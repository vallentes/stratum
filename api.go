package main

import (
	"crypto/subtle"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4<<20)).Decode(v)
}

func idOf(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}

func qInt(r *http.Request, k string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(k)); err == nil {
		return v
	}
	return def
}

func qInt64(r *http.Request, k string) int64 {
	v, _ := strconv.ParseInt(r.URL.Query().Get(k), 10, 64)
	return v
}

type h func(w http.ResponseWriter, r *http.Request)

// ---------- auth ----------

const sessionCookie = "stratum_session"

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.st.db.Exec(`DELETE FROM sessions WHERE token=?`, c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, map[string]any{"ok": true})
}

// ---------- routes ----------

func (a *App) routes(m *http.ServeMux) {
	m.HandleFunc("POST /api/login", a.login)
	m.HandleFunc("POST /api/logout", a.logout)
	m.HandleFunc("GET /api/me", func(w http.ResponseWriter, r *http.Request) {
		u := a.sessionUser(r)
		out := map[string]any{"authed": u != nil, "version": version, "user": u}
		if u == nil {
			out["default_password"] = a.defaultPasswordInUse()
		}
		writeJSON(w, out)
	})
	m.HandleFunc("POST /api/audit/ingest", a.auditIngest)
	g := func(p string, fn h) { m.HandleFunc(p, a.guardFor(p, fn)) }

	g("POST /api/password", a.changePassword)
	g("GET /api/users", a.listUsers)
	g("POST /api/users", a.createUser)
	g("PUT /api/users/{id}", a.updateUser)
	g("DELETE /api/users/{id}", a.deleteUser)
	g("GET /api/scope", a.scopeTree)
	g("GET /api/devices", a.listDevices)
	g("POST /api/devices", a.saveDevice)
	g("PUT /api/devices/{id}", a.saveDevice)
	g("DELETE /api/devices/{id}", a.deleteDevice)
	g("POST /api/devices/{id}/discover", a.discover)
	g("POST /api/devices/{id}/inventory", func(w http.ResponseWriter, r *http.Request) {
		a.refreshInventory(idOf(r))
		writeJSON(w, map[string]any{"ok": true})
	})
	g("POST /api/shares", a.saveShare)
	g("PUT /api/shares/{id}", a.saveShare)
	g("DELETE /api/shares/{id}", a.deleteShare)
	g("POST /api/shares/{id}/scan", func(w http.ResponseWriter, r *http.Request) {
		id, err := a.startScan(idOf(r))
		if err != nil {
			httpErr(w, 409, err.Error())
			return
		}
		writeJSON(w, map[string]any{"scan_id": id})
	})
	g("GET /api/scans", a.listScans)
	g("POST /api/scans/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		p := a.running[idOf(r)]
		a.mu.Unlock()
		if p == nil {
			httpErr(w, 404, "scan is not running")
			return
		}
		p.mu.Lock()
		p.Cancel = true
		p.mu.Unlock()
		if p.cancel != nil {
			p.cancel()
		}
		writeJSON(w, map[string]any{"ok": true})
	})

	g("GET /api/summary", a.summary)
	g("GET /api/hotcold", a.hotcold)
	g("GET /api/topfolders", a.topFolders)
	g("GET /api/growth", a.growth)
	g("GET /api/filetypes", a.fileTypes)
	g("GET /api/owners", a.owners)
	g("GET /api/search", a.search)
	g("GET /api/search.csv", a.searchCSV)
	g("GET /api/duplicates", a.duplicates)
	g("GET /api/duplicates/set", a.duplicateSet)
	g("GET /api/issues", a.issues)
	g("GET /api/issues.csv", a.issuesCSV)
	g("POST /api/issues/triage", a.triage)
	g("GET /api/audit/summary", a.auditSummary)
	g("GET /api/audit/events", a.auditEvents)
	g("GET /api/inventory", a.inventory)

	g("GET /api/tags", a.listTags)
	g("GET /api/tagrules", a.listTagRules)
	g("POST /api/tagrules", a.saveTagRule)
	g("PUT /api/tagrules/{id}", a.saveTagRule)
	g("DELETE /api/tagrules/{id}", a.deleteTagRule)
	g("POST /api/tagrules/{id}/apply", a.applyTagRuleNow)
	g("POST /api/tagrules/preview", a.previewFilter)

	g("GET /api/automations", a.listAutomations)
	g("POST /api/automations", a.saveAutomation)
	g("PUT /api/automations/{id}", a.saveAutomation)
	g("DELETE /api/automations/{id}", a.deleteAutomation)
	g("POST /api/automations/{id}/run", a.runAutomationHTTP)
	g("GET /api/automations/{id}/runs", a.listRuns)
	g("GET /api/runs/{id}/ledger", a.ledger)
	g("GET /api/runs/{id}/ledger.csv", a.ledgerCSV)

	a.collectorRoutes(m)
	a.smartRoutes(m)
	g("POST /api/devices/{id}/enable-audit", a.enableAudit)
	g("PUT /api/settings/costs", a.saveCosts)
	g("GET /api/ads", a.adsReport)
	g("GET /api/jobs", a.jobsReport)
	g("PUT /api/shares/{id}/exclude", a.setExclusions)
	g("GET /api/exclude/presets", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, excludePresets) })
	g("GET /api/liveindex", a.liveIndexStatus)
	g("GET /api/view", a.viewFile)
	g("GET /api/viewlog", a.viewLog)
	g("GET /api/export/dashboard.xlsx", a.exportDashboard)
	g("GET /api/search.xlsx", a.searchXLSX)
	g("GET /api/iops", a.iopsReport)
	a.directoryRoutes(m)
	g("GET /api/settings", a.settings)
	g("GET /download/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if name != "stratum.exe" && name != "stratum-linux" {
			http.NotFound(w, r)
			return
		}
		exe, _ := os.Executable()
		p := filepath.Join(filepath.Dir(exe), "dist", name)
		if _, err := os.Stat(p); err != nil {
			httpErr(w, 404, "collector binary not published on this server (expected "+p+")")
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		http.ServeFile(w, r, p)
	})
	g("POST /api/settings/ingest-token", func(w http.ResponseWriter, r *http.Request) {
		t := randHex(20)
		a.st.setSetting("ingest_token", t)
		writeJSON(w, map[string]any{"token": t})
	})
}

// ---------- devices & shares ----------

func (a *App) scopeTree(w http.ResponseWriter, r *http.Request) {
	type sh struct {
		ID        int64  `json:"id"`
		Name      string `json:"name"`
		Path      string `json:"path"`
		Published bool   `json:"published"`
	}
	type dv struct {
		ID     int64  `json:"id"`
		Name   string `json:"name"`
		Kind   string `json:"kind"`
		Shares []sh   `json:"shares"`
	}
	out := []*dv{}
	idx := map[int64]*dv{}
	rows, _ := a.st.db.Query(`SELECT id,name,kind FROM devices ORDER BY name`)
	for rows.Next() {
		d := &dv{Shares: []sh{}}
		rows.Scan(&d.ID, &d.Name, &d.Kind)
		out = append(out, d)
		idx[d.ID] = d
	}
	rows.Close()
	rows, _ = a.st.db.Query(`SELECT id,device_id,name,path,current_scan FROM shares ORDER BY name`)
	for rows.Next() {
		var s sh
		var did, cur int64
		rows.Scan(&s.ID, &did, &s.Name, &s.Path, &cur)
		s.Published = cur > 0
		if d := idx[did]; d != nil {
			d.Shares = append(d.Shares, s)
		}
	}
	rows.Close()
	writeJSON(w, out)
}

func (a *App) listDevices(w http.ResponseWriter, r *http.Request) {
	type shareOut struct {
		Share
		Files   int64  `json:"files"`
		Bytes   int64  `json:"bytes"`
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	type devOut struct {
		Device
		HasSecret     bool       `json:"has_secret"`
		Collector     string     `json:"collector"`
		CollectorSeen int64      `json:"collector_seen"`
		Shares        []shareOut `json:"shares"`
	}
	var out []*devOut
	rows, _ := a.st.db.Query(`SELECT d.id,d.name,d.kind,d.host,d.port,d.username,d.secret<>'',d.insecure,d.collector_id,COALESCE(c.name,''),COALESCE(c.last_seen,0),COALESCE(d.options,'') FROM devices d LEFT JOIN collectors c ON c.id=d.collector_id ORDER BY d.name`)
	idx := map[int64]*devOut{}
	for rows.Next() {
		d := &devOut{Shares: []shareOut{}}
		var ins int
		rows.Scan(&d.ID, &d.Name, &d.Kind, &d.Host, &d.Port, &d.Username, &d.HasSecret, &ins, &d.CollectorID, &d.Collector, &d.CollectorSeen, &d.Options)
		d.Insecure = ins == 1
		out = append(out, d)
		idx[d.ID] = d
	}
	rows.Close()
	rows, _ = a.st.db.Query(`SELECT s.id,s.device_id,s.name,s.path,s.schedule_hours,s.current_scan,s.failed_scan,s.last_scan_at,COALESCE(s.options,''),
	  COALESCE(c.files,0),COALESCE(c.bytes,0),
	  COALESCE((SELECT status FROM scans WHERE share_id=s.id ORDER BY id DESC LIMIT 1),''),
	  COALESCE((SELECT message FROM scans WHERE share_id=s.id ORDER BY id DESC LIMIT 1),'')
	  FROM shares s LEFT JOIN scans c ON c.id=s.current_scan ORDER BY s.name`)
	for rows.Next() {
		var s shareOut
		rows.Scan(&s.ID, &s.DeviceID, &s.Name, &s.Path, &s.ScheduleHours, &s.CurrentScan, &s.FailedScan, &s.LastScanAt, &s.Options, &s.Files, &s.Bytes, &s.Status, &s.Message)
		if d := idx[s.DeviceID]; d != nil {
			d.Shares = append(d.Shares, s)
		}
	}
	rows.Close()
	if out == nil {
		out = []*devOut{}
	}
	writeJSON(w, out)
}

func (a *App) saveDevice(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name, Kind, Host, Username, Password string
		Port                                 int
		Insecure                             bool
		CollectorID                          int64  `json:"collector_id"`
		Options                              string `json:"options"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	in.Name, in.Host = strings.TrimSpace(in.Name), strings.TrimSpace(in.Host)
	if in.Name == "" || (in.Kind != "windows" && in.Kind != "powerscale" && in.Kind != "s3") {
		httpErr(w, 400, "name and a kind of windows, powerscale or s3 are required")
		return
	}
	if in.Kind == "powerscale" && (in.Host == "" || in.Username == "") {
		httpErr(w, 400, "PowerScale needs a cluster address and a service account")
		return
	}
	if in.Kind == "s3" && (in.Host == "" || in.Username == "") {
		httpErr(w, 400, "S3 needs an endpoint URL and an access key")
		return
	}
	id := idOf(r)
	if id == 0 {
		res, err := a.st.db.Exec(`INSERT INTO devices(name,kind,host,port,username,secret,insecure,created,collector_id) VALUES(?,?,?,?,?,?,?,?,?)`,
			in.Name, in.Kind, in.Host, in.Port, in.Username, sealIf(a, in.Password), b2i(in.Insecure), now(), in.CollectorID)
		if err != nil {
			httpErr(w, 400, "a device with that name already exists")
			return
		}
		id, _ = res.LastInsertId()
	} else {
		a.st.db.Exec(`UPDATE devices SET name=?,kind=?,host=?,port=?,username=?,insecure=?,collector_id=? WHERE id=?`,
			in.Name, in.Kind, in.Host, in.Port, in.Username, b2i(in.Insecure), in.CollectorID, id)
		if in.Password != "" {
			a.st.db.Exec(`UPDATE devices SET secret=? WHERE id=?`, a.seal(in.Password), id)
		}
	}
	a.mu.Lock()
	a.ipCache = nil
	a.mu.Unlock()
	a.st.db.Exec(`UPDATE devices SET options=? WHERE id=?`, in.Options, id)
	go a.refreshInventory(id)
	writeJSON(w, map[string]any{"id": id})
}

func sealIf(a *App, pw string) string {
	if pw == "" {
		return ""
	}
	return a.seal(pw)
}

func (a *App) dropShareIndex(shareID int64) {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	var cur, failed int64
	a.st.db.QueryRow(`SELECT current_scan,failed_scan FROM shares WHERE id=?`, shareID).Scan(&cur, &failed)
	ids := map[int64]bool{cur: true, failed: true}
	for _, s := range a.ids(`SELECT id FROM scans WHERE share_id=?`, shareID) {
		ids[s] = true
	}
	for s := range ids {
		a.clearScanStorage(s)
	}
	a.st.db.Exec(`DELETE FROM file_tags WHERE share_id=?`, shareID)
	a.st.db.Exec(`DELETE FROM issue_triage WHERE share_id=?`, shareID)
	a.st.db.Exec(`DELETE FROM history WHERE share_id=?`, shareID)
	a.st.db.Exec(`DELETE FROM scans WHERE share_id=?`, shareID)
	a.st.db.Exec(`DELETE FROM dir_history WHERE share_id=?`, shareID)
	a.st.db.Exec(`DELETE FROM shares WHERE id=?`, shareID)
}

func (a *App) deleteDevice(w http.ResponseWriter, r *http.Request) {
	id := idOf(r)
	rows, _ := a.st.db.Query(`SELECT id FROM shares WHERE device_id=?`, id)
	var ids []int64
	for rows.Next() {
		var s int64
		rows.Scan(&s)
		ids = append(ids, s)
	}
	rows.Close()
	for _, s := range ids {
		a.dropShareIndex(s)
	}
	a.st.db.Exec(`DELETE FROM devices WHERE id=?`, id)
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) discover(w http.ResponseWriter, r *http.Request) {
	d, err := a.device(idOf(r))
	if err != nil {
		httpErr(w, 404, "device not found")
		return
	}
	var out []DiscoveredShare
	if d.CollectorID > 0 {
		var raw json.RawMessage
		if raw, err = a.runTask(d.CollectorID, "discover", map[string]any{"device": d.wire()}, 45*time.Second); err == nil {
			err = json.Unmarshal(raw, &out)
		}
	} else {
		out, err = discoverDevice(d)
	}
	if err != nil {
		httpErr(w, 502, err.Error())
		return
	}
	if out == nil {
		out = []DiscoveredShare{}
	}
	writeJSON(w, out)
}

func (a *App) saveShare(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DeviceID      int64 `json:"device_id"`
		Name, Path    string
		ScheduleHours int     `json:"schedule_hours"`
		Options       *string `json:"options"`
	}
	if err := readJSON(r, &in); err != nil || strings.TrimSpace(in.Path) == "" {
		httpErr(w, 400, "path is required")
		return
	}
	if in.Name == "" {
		in.Name = in.Path
	}
	id := idOf(r)
	if id == 0 {
		if _, err := a.device(in.DeviceID); err != nil {
			httpErr(w, 400, "unknown device")
			return
		}
		opts := ""
		if in.Options != nil {
			opts = *in.Options
		}
		if dv, err := a.device(in.DeviceID); err == nil && opts == "" && !isWindows && dv.CollectorID == 0 && dv.Kind == "windows" && strings.TrimSpace(in.Path) == "/" {
			b, _ := json.Marshal(map[string]any{"exclude": excludePresets["linux"]})
			opts = string(b)
		}
		res, err := a.st.db.Exec(`INSERT INTO shares(device_id,name,path,schedule_hours,created,options) VALUES(?,?,?,?,?,?)`,
			in.DeviceID, in.Name, strings.TrimSpace(in.Path), in.ScheduleHours, now(), opts)
		if err != nil {
			httpErr(w, 500, err.Error())
			return
		}
		id, _ = res.LastInsertId()
	} else {
		a.st.db.Exec(`UPDATE shares SET name=?, schedule_hours=? WHERE id=?`, in.Name, in.ScheduleHours, id)
		if in.Options != nil {
			// Merge: a checkbox sending {"ads":true} must not wipe the exclusion list.
			var cur, upd map[string]any
			var old string
			a.st.db.QueryRow(`SELECT COALESCE(options,'') FROM shares WHERE id=?`, id).Scan(&old)
			json.Unmarshal([]byte(old), &cur)
			json.Unmarshal([]byte(*in.Options), &upd)
			if cur == nil {
				cur = map[string]any{}
			}
			for k, v := range upd {
				cur[k] = v
			}
			b, _ := json.Marshal(cur)
			a.st.db.Exec(`UPDATE shares SET options=? WHERE id=?`, string(b), id)
		}
	}
	writeJSON(w, map[string]any{"id": id})
}

func (a *App) deleteShare(w http.ResponseWriter, r *http.Request) {
	a.dropShareIndex(idOf(r))
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) listScans(w http.ResponseWriter, r *http.Request) {
	type scanOut struct {
		ID       int64  `json:"id"`
		ShareID  int64  `json:"share_id"`
		Share    string `json:"share"`
		Device   string `json:"device"`
		Started  int64  `json:"started"`
		Finished int64  `json:"finished"`
		Status   string `json:"status"`
		Files    int64  `json:"files"`
		Dirs     int64  `json:"dirs"`
		Bytes    int64  `json:"bytes"`
		Errors   int64  `json:"errors"`
		Message  string `json:"message"`
	}
	rows, _ := a.st.db.Query(`SELECT c.id,c.share_id,COALESCE(s.name,'(removed)'),COALESCE(d.name,''),c.started,c.finished,c.status,c.files,c.dirs,c.bytes,c.errors,c.message
	  FROM scans c LEFT JOIN shares s ON s.id=c.share_id LEFT JOIN devices d ON d.id=s.device_id ORDER BY c.id DESC LIMIT ?`, qInt(r, "limit", 50))
	hist := []scanOut{}
	for rows.Next() {
		var s scanOut
		rows.Scan(&s.ID, &s.ShareID, &s.Share, &s.Device, &s.Started, &s.Finished, &s.Status, &s.Files, &s.Dirs, &s.Bytes, &s.Errors, &s.Message)
		hist = append(hist, s)
	}
	rows.Close()
	a.mu.Lock()
	active := []scanProgress{}
	for _, p := range a.running {
		active = append(active, p.snapshot())
	}
	a.mu.Unlock()
	sort.Slice(active, func(i, j int) bool { return active[i].ScanID < active[j].ScanID })
	writeJSON(w, map[string]any{"active": active, "history": hist})
}

// ---------- dashboard ----------

func (a *App) summary(w http.ResponseWriter, r *http.Request) {
	sc := scopeFrom(r)
	wh, args := sc.where()
	var files, bytes, dirs, sources, oldest, newest sql.NullInt64
	a.st.db.QueryRow(`SELECT SUM(c.files),SUM(c.bytes),SUM(c.dirs),COUNT(DISTINCT s.device_id),MIN(c.finished),MAX(c.finished)
	  FROM (SELECT * FROM shares`+wh+`) s JOIN scans c ON c.id=s.current_scan`, args...).
		Scan(&files, &bytes, &dirs, &sources, &oldest, &newest)
	var shares int64
	a.st.db.QueryRow(`SELECT COUNT(*) FROM shares`+wh, args...).Scan(&shares)
	a.mu.Lock()
	running := len(a.running)
	a.mu.Unlock()
	writeJSON(w, map[string]any{"files": files.Int64, "bytes": bytes.Int64, "folders": dirs.Int64,
		"devices": sources.Int64, "shares": shares, "oldest": oldest.Int64, "newest": newest.Int64, "running": running})
}

var bands = []struct {
	Key  string
	Days int64
}{{"<1mo", 30}, {"1-3mo", 91}, {"3-6mo", 182}, {"6-12mo", 365}, {"1-2y", 730}, {">2y", math.MaxInt32}}

func (a *App) hotcold(w http.ResponseWriter, r *http.Request) {
	months := qInt(r, "months", 12)
	cut := now() - int64(float64(months)*30.44*86400)
	sc := scopeFrom(r)
	type band struct {
		Key   string `json:"key"`
		Bytes int64  `json:"bytes"`
	}
	toBands := func(rows []aggBucket) []band {
		out := make([]band, len(bands))
		for i, b := range bands {
			out[i].Key = b.Key
		}
		for _, rw := range rows {
			age := (now() - dayUnix(rw.Key)) / 86400
			for i, b := range bands {
				if age < b.Days || i == len(bands)-1 {
					out[i].Bytes += rw.Bytes
					break
				}
			}
		}
		return out
	}
	mrows := a.aggFor(sc, "m")
	var hotB, coldB, hotF, coldF int64
	for _, rw := range mrows {
		if dayUnix(rw.Key)+86400 > cut {
			hotB, hotF = hotB+rw.Bytes, hotF+rw.Files
		} else {
			coldB, coldF = coldB+rw.Bytes, coldF+rw.Files
		}
	}
	writeJSON(w, map[string]any{"months": months, "cutoff": cut, "hot_bytes": hotB, "cold_bytes": coldB,
		"hot_files": hotF, "cold_files": coldF, "by_access": toBands(a.aggFor(sc, "a")), "by_modified": toBands(mrows)})
}

func (a *App) topFolders(w http.ResponseWriter, r *http.Request) {
	sc := scopeFrom(r)
	cond, args := sc.scans("d.scan_id")
	rows, err := a.st.db.Query(`SELECT d.path, d.bytes, d.files, d.owner, s.id, s.name, dv.name FROM dirs d
	  JOIN shares s ON s.current_scan=d.scan_id JOIN devices dv ON dv.id=s.device_id
	  WHERE d.depth=? AND `+cond+` ORDER BY d.bytes DESC LIMIT ?`, append([]any{qInt(r, "depth", 1)}, append(args, qInt(r, "limit", 10))...)...)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var p, owner, share, dev string
		var b, f, sid int64
		rows.Scan(&p, &b, &f, &owner, &sid, &share, &dev)
		out = append(out, map[string]any{"path": p, "bytes": b, "files": f, "owner": owner, "share_id": sid, "share": share, "device": dev})
	}
	writeJSON(w, out)
}

func (a *App) growth(w http.ResponseWriter, r *http.Request) {
	sc := scopeFrom(r)
	cond, args := sc.scans("scan_id")
	span := qInt(r, "months", 24)
	t := time.Now()
	start := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -(span - 1), 0)
	_, _ = cond, args
	var base sql.NullInt64
	per := map[string]int64{}
	for _, rw := range a.aggFor(sc, "c") {
		if dayUnix(rw.Key) < start.Unix() {
			base.Int64 += rw.Bytes
		} else if len(rw.Key) >= 7 {
			per[rw.Key[:7]] += rw.Bytes
		}
	}
	type pt struct {
		Month string `json:"month"`
		Bytes int64  `json:"bytes"`
	}
	var series []pt
	cum := base.Int64
	for i := 0; i < span; i++ {
		m := start.AddDate(0, i, 0).Format("2006-01")
		cum += per[m]
		series = append(series, pt{m, cum})
	}
	// Least-squares line over the last 6 months, projected 6 months forward.
	n := 6
	if len(series) < n {
		n = len(series)
	}
	var sx, sy, sxy, sxx float64
	for i := 0; i < n; i++ {
		x, y := float64(i), float64(series[len(series)-n+i].Bytes)
		sx, sy, sxy, sxx = sx+x, sy+y, sxy+x*y, sxx+x*x
	}
	slope := 0.0
	if d := float64(n)*sxx - sx*sx; d != 0 {
		slope = (float64(n)*sxy - sx*sy) / d
	}
	if slope < 0 {
		slope = 0 // deletions happen, but projecting shrinkage is misleading
	}
	last := float64(series[len(series)-1].Bytes)
	var proj []pt
	for i := 1; i <= 6; i++ {
		proj = append(proj, pt{start.AddDate(0, span-1+i, 0).Format("2006-01"), int64(last + slope*float64(i))})
	}
	// Indexed-over-time from scan history (what the index actually held).
	w2, a2 := sc.where()
	hrows, _ := a.st.db.Query(`SELECT strftime('%Y-%m-%d', ts, 'unixepoch') d, share_id, MAX(bytes) FROM history WHERE share_id IN (SELECT id FROM shares`+w2+`) GROUP BY d, share_id ORDER BY d`, a2...)
	daily := map[string]map[int64]int64{}
	var days []string
	for hrows != nil && hrows.Next() {
		var d string
		var sid, b int64
		hrows.Scan(&d, &sid, &b)
		if daily[d] == nil {
			daily[d] = map[int64]int64{}
			days = append(days, d)
		}
		daily[d][sid] = b
	}
	if hrows != nil {
		hrows.Close()
	}
	lastBy := map[int64]int64{}
	var hist []pt
	for _, d := range days {
		for sid, b := range daily[d] {
			lastBy[sid] = b
		}
		var tot int64
		for _, b := range lastBy {
			tot += b
		}
		hist = append(hist, pt{d, tot})
	}
	writeJSON(w, map[string]any{"series": series, "projection": proj, "monthly_growth": int64(slope), "history": hist})
}

func (a *App) fileTypes(w http.ResponseWriter, r *http.Request) {
	rows := a.aggFor(scopeFrom(r), "e")
	sort.Slice(rows, func(i, j int) bool { return rows[i].Bytes > rows[j].Bytes })
	limit := qInt(r, "limit", 15)
	out := []map[string]any{}
	for i, rw := range rows {
		if i >= limit {
			break
		}
		out = append(out, map[string]any{"ext": rw.Key, "bytes": rw.Bytes, "files": rw.Files})
	}
	writeJSON(w, out)
}

func (a *App) owners(w http.ResponseWriter, r *http.Request) {
	sc := scopeFrom(r)
	cond, args := sc.scans("scan_id")
	rows, err := a.st.db.Query(`SELECT COALESCE(NULLIF(owner,''),'(unknown)') o, SUM(own_bytes) b, SUM(own_files), COUNT(*) FROM dirs WHERE `+cond+` GROUP BY o ORDER BY b DESC LIMIT ?`,
		append(args, qInt(r, "limit", 25))...)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	out := []map[string]any{}
	for rows.Next() {
		var o string
		var b, f, d int64
		rows.Scan(&o, &b, &f, &d)
		out = append(out, map[string]any{"owner": o, "bytes": b, "files": f, "folders": d})
	}
	rows.Close()
	// Activity per user in the last 30 days from the audit stream.
	act := map[string]int64{}
	arows, _ := a.st.db.Query(`SELECT username, SUM(count) FROM audit WHERE ts >= ? GROUP BY username`, now()-30*86400)
	for arows != nil && arows.Next() {
		var u string
		var c int64
		arows.Scan(&u, &c)
		act[strings.ToLower(u)] = c
	}
	if arows != nil {
		arows.Close()
	}
	for _, o := range out {
		o["activity_30d"] = act[strings.ToLower(o["owner"].(string))]
	}
	writeJSON(w, out)
}

// ---------- search ----------

func filterFrom(r *http.Request) Filter {
	q := r.URL.Query()
	fl := Filter{Q: strings.TrimSpace(q.Get("q")), PathPrefix: q.Get("path"), PathContains: q.Get("path_contains"),
		Owner: q.Get("owner"), Tag: q.Get("tag"), DeviceID: qInt64(r, "device"), ShareID: qInt64(r, "share"),
		ModifiedAfter: qInt64(r, "after"), ModifiedBefore: qInt64(r, "before"),
		OlderThanDays: qInt(r, "older_days", 0), NewerThanDays: qInt(r, "newer_days", 0), NotAccessedDay: qInt(r, "not_accessed_days", 0),
		MinSize: qInt64(r, "min_size"), MaxSize: qInt64(r, "max_size")}
	if e := q.Get("ext"); e != "" {
		fl.Ext = strings.Split(e, ",")
	}
	return fl
}

const searchCols = `SELECT d.name, s.id, s.name, f.path, f.name, f.ext, f.size, f.mtime, f.atime, f.ctime, f.owner, f.flags`

func (a *App) search(w http.ResponseWriter, r *http.Request) {
	t := time.Now()
	fl := filterFrom(r)
	from, args := a.fileSelect(fl)
	var total, bytes sql.NullInt64
	if fl.empty() {
		// Listing every file in the estate sorted by name is a full scan of millions of
		// rows; the page asks for a name or a filter first.
		writeJSON(w, map[string]any{"total": 0, "bytes": 0, "ms": 0, "rows": []any{}, "needs_filter": true})
		return
	}
	ctx := r.Context() // a newer keystroke cancels this request; stop the query with it
	if err := a.st.db.QueryRowContext(ctx, `SELECT COUNT(*), SUM(f.size)`+from, args...).Scan(&total, &bytes); err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	order := "f.name"
	switch r.URL.Query().Get("sort") {
	case "size":
		order = "f.size DESC"
	case "mtime":
		order = "f.mtime DESC"
	case "path":
		order = "f.path"
	}
	limit := qInt(r, "limit", 1000)
	if limit > 1000 {
		limit = 1000
	}
	rows, err := a.st.db.QueryContext(ctx, searchCols+from+` ORDER BY `+order+` LIMIT ? OFFSET ?`, append(args, limit, qInt(r, "offset", 0))...)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var dev, share, p, name, ext, owner string
		var sid, size, mt, at, ct, flags int64
		rows.Scan(&dev, &sid, &share, &p, &name, &ext, &size, &mt, &at, &ct, &owner, &flags)
		out = append(out, map[string]any{"device": dev, "share_id": sid, "share": share, "path": p, "name": name, "ext": ext,
			"size": size, "mtime": mt, "atime": at, "ctime": ct, "owner": owner, "stub": flags&1 == 1})
	}
	writeJSON(w, map[string]any{"total": total.Int64, "bytes": bytes.Int64, "ms": time.Since(t).Milliseconds(), "rows": out})
}

func csvStart(w http.ResponseWriter, name string) *csv.Writer {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Write([]byte{0xEF, 0xBB, 0xBF}) // Excel-friendly UTF-8
	return csv.NewWriter(w)
}

func ts(u int64) string {
	if u == 0 {
		return ""
	}
	return time.Unix(u, 0).UTC().Format("2006-01-02 15:04:05")
}

func (a *App) searchCSV(w http.ResponseWriter, r *http.Request) {
	fl := filterFrom(r)
	from, args := a.fileSelect(fl)
	rows, err := a.st.db.Query(searchCols+from+` ORDER BY s.id, f.path`, args...)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	cw := csvStart(w, "search.csv")
	cw.Write([]string{"device", "share", "path", "name", "extension", "size_bytes", "modified_utc", "accessed_utc", "created_utc", "folder_owner"})
	for rows.Next() {
		var dev, share, p, name, ext, owner string
		var sid, size, mt, at, ct, flags int64
		rows.Scan(&dev, &sid, &share, &p, &name, &ext, &size, &mt, &at, &ct, &owner, &flags)
		cw.Write([]string{dev, share, p, name, ext, strconv.FormatInt(size, 10), ts(mt), ts(at), ts(ct), owner})
	}
	cw.Flush()
}

// ---------- duplicates ----------

func (a *App) duplicates(w http.ResponseWriter, r *http.Request) {
	sc := scopeFrom(r)
	cond, args := sc.scans("x.scan_id")
	minSize := qInt64(r, "min_size")
	bargs := append([]any{minSize}, args...)
	var sets, reclaim, largest sql.NullInt64
	a.st.db.QueryRow(`SELECT COUNT(*), SUM(size*(copies-1)), MAX(size*(copies-1)) FROM dup_sets x WHERE size > ? AND `+cond, bargs...).Scan(&sets, &reclaim, &largest)
	rows, err := a.st.db.Query(`SELECT x.name, x.size, x.mtime, x.copies, s.id, s.name, d.name, COALESCE(x.etag,'') FROM dup_sets x
	  JOIN shares s ON s.current_scan=x.scan_id JOIN devices d ON d.id=s.device_id WHERE x.size > ? AND `+cond+` ORDER BY x.size*(x.copies-1) DESC LIMIT ?`,
		append(bargs, qInt(r, "top", 50))...)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var name, share, dev, etag string
		var size, mt, c, sid int64
		rows.Scan(&name, &size, &mt, &c, &sid, &share, &dev, &etag)
		out = append(out, map[string]any{"name": name, "size": size, "mtime": mt, "copies": c, "reclaim": size * (c - 1),
			"share_id": sid, "share": share, "device": dev, "etag": etag})
	}
	writeJSON(w, map[string]any{"sets": sets.Int64, "reclaimable": reclaim.Int64, "largest": largest.Int64, "rows": out})
}

func (a *App) duplicateSet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	sh, err := a.share(qInt64(r, "share"))
	if err != nil {
		httpErr(w, 404, "share not found")
		return
	}
	t := a.fileRowsFor(sh.CurrentScan)
	var rows *sql.Rows
	if et := q.Get("etag"); et != "" {
		rows, _ = a.st.db.Query(`SELECT path, owner, atime FROM `+t+` WHERE etag=? AND size=? ORDER BY path LIMIT 1000`, et, qInt64(r, "size"))
	} else {
		rows, _ = a.st.db.Query(`SELECT path, owner, atime FROM `+t+` WHERE ext=? AND name=? AND size=? AND mtime=? ORDER BY path`,
			extOf(q.Get("name")), q.Get("name"), qInt64(r, "size"), qInt64(r, "mtime"))
	}
	if rows == nil {
		writeJSON(w, []any{})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var p, o string
		var at int64
		rows.Scan(&p, &o, &at)
		out = append(out, map[string]any{"path": p, "owner": o, "atime": at})
	}
	writeJSON(w, out)
}

// ---------- path & scan issues ----------

var issueFamilies = map[string][]string{
	"errors":      {"error"},
	"interrupted": {"interrupted"},
	"links":       {"link"},
	"long":        {"long_path", "long_name"},
	"illegal":     {"illegal", "reserved"},
	"unpublished": {"not_published"},
}

func (a *App) issues(w http.ResponseWriter, r *http.Request) {
	sc := scopeFrom(r)
	cond, args := sc.scansWithFailed("i.scan_id")
	counts := map[string]int64{}
	rows, _ := a.st.db.Query(`SELECT kind, COUNT(*) FROM issues i WHERE `+cond+` GROUP BY kind`, args...)
	for rows.Next() {
		var k string
		var n int64
		rows.Scan(&k, &n)
		for fam, kinds := range issueFamilies {
			for _, kk := range kinds {
				if kk == k {
					counts[fam] += n
				}
			}
		}
	}
	rows.Close()
	var devs, shares int64
	a.st.db.QueryRow(`SELECT COUNT(DISTINCT s.device_id), COUNT(DISTINCT i.share_id) FROM issues i JOIN shares s ON s.id=i.share_id WHERE `+cond, args...).Scan(&devs, &shares)

	c := []string{cond}
	qa := append([]any{}, args...)
	if fam := r.URL.Query().Get("family"); fam != "" && issueFamilies[fam] != nil {
		ph := strings.TrimSuffix(strings.Repeat("?,", len(issueFamilies[fam])), ",")
		c = append(c, "i.kind IN ("+ph+")")
		for _, k := range issueFamilies[fam] {
			qa = append(qa, k)
		}
	}
	if p := r.URL.Query().Get("q"); p != "" {
		c = append(c, `i.path LIKE ? ESCAPE '\'`)
		qa = append(qa, "%"+likeEscape(p)+"%")
	}
	if ml := qInt(r, "min_len", 0); ml > 0 {
		c = append(c, "i.len >= ?")
		qa = append(qa, ml)
	}
	switch st := r.URL.Query().Get("state"); st {
	case "open":
		c = append(c, "COALESCE(t.state,'')=''")
	case "acknowledged", "ignored":
		c = append(c, "t.state=?")
		qa = append(qa, st)
	}
	order := "i.len DESC"
	if r.URL.Query().Get("sort") == "newest" {
		order = "i.detected DESC"
	}
	q := `SELECT i.share_id, s.name, d.name, d.kind, i.path, i.kind, i.detail, i.len, i.scan_id, i.detected, COALESCE(t.state,'')
	  FROM issues i JOIN shares s ON s.id=i.share_id JOIN devices d ON d.id=s.device_id
	  LEFT JOIN issue_triage t ON t.share_id=i.share_id AND t.path=i.path AND t.kind=i.kind
	  WHERE ` + strings.Join(c, " AND ") + ` ORDER BY ` + order
	var matched int64
	a.st.db.QueryRow(`SELECT COUNT(*) FROM (`+q+`)`, qa...).Scan(&matched)
	rows, err := a.st.db.Query(q+` LIMIT ?`, append(qa, qInt(r, "limit", 500))...)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var sid, ln, scan, det int64
		var share, dev, kind, p, k, detail, state string
		rows.Scan(&sid, &share, &dev, &kind, &p, &k, &detail, &ln, &scan, &det, &state)
		out = append(out, map[string]any{"share_id": sid, "share": share, "device": dev, "platform": kind, "path": p, "kind": k,
			"detail": detail, "len": ln, "scan_id": scan, "detected": det, "state": state})
	}
	writeJSON(w, map[string]any{"counts": counts, "devices": devs, "shares": shares, "matched": matched, "rows": out})
}

func (a *App) issuesCSV(w http.ResponseWriter, r *http.Request) {
	sc := scopeFrom(r)
	cond, args := sc.scansWithFailed("i.scan_id")
	rows, err := a.st.db.Query(`SELECT d.name, s.name, i.path, i.kind, i.detail, i.len, i.scan_id, i.detected, COALESCE(t.state,'')
	  FROM issues i JOIN shares s ON s.id=i.share_id JOIN devices d ON d.id=s.device_id
	  LEFT JOIN issue_triage t ON t.share_id=i.share_id AND t.path=i.path AND t.kind=i.kind WHERE `+cond+` ORDER BY i.kind, i.len DESC`, args...)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	cw := csvStart(w, "path-issues.csv")
	cw.Write([]string{"device", "share", "path", "issue", "detail", "client_path_length", "scan", "detected_utc", "triage"})
	for rows.Next() {
		var dev, share, p, k, d, st string
		var ln, scan, det int64
		rows.Scan(&dev, &share, &p, &k, &d, &ln, &scan, &det, &st)
		cw.Write([]string{dev, share, p, k, d, strconv.FormatInt(ln, 10), strconv.FormatInt(scan, 10), ts(det), st})
	}
	cw.Flush()
}

func (a *App) triage(w http.ResponseWriter, r *http.Request) {
	var in []struct {
		ShareID int64 `json:"share_id"`
		Path    string
		Kind    string
		State   string
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	for _, t := range in {
		if t.State == "" {
			a.st.db.Exec(`DELETE FROM issue_triage WHERE share_id=? AND path=? AND kind=?`, t.ShareID, t.Path, t.Kind)
		} else if t.State == "acknowledged" || t.State == "ignored" {
			a.st.db.Exec(`INSERT INTO issue_triage VALUES(?,?,?,?) ON CONFLICT DO UPDATE SET state=excluded.state`, t.ShareID, t.Path, t.Kind, t.State)
		}
	}
	writeJSON(w, map[string]any{"ok": true})
}

// ---------- audit ----------

func (a *App) auditIngest(w http.ResponseWriter, r *http.Request) {
	tok := a.st.setting("ingest_token")
	got := r.Header.Get("X-Ingest-Token")
	if !a.authed(r) && (tok == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(got)) != 1) {
		httpErr(w, 401, "ingest token required")
		return
	}
	var evs []AuditEvent
	if err := readJSON(r, &evs); err != nil {
		httpErr(w, 400, "expected a JSON array of events")
		return
	}
	for _, e := range evs {
		e.Op = normOp(e.Op, "")
		a.audit.add(e)
	}
	writeJSON(w, map[string]any{"accepted": len(evs)})
}

func (a *App) auditSummary(w http.ResponseWriter, r *http.Request) {
	a.audit.flush(false)
	type devSum struct {
		ID        int64            `json:"id"`
		Name      string           `json:"name"`
		Kind      string           `json:"kind"`
		Events    int64            `json:"events"`
		Rows      int64            `json:"rows"`
		LastEvent int64            `json:"last_event"`
		Ops       map[string]int64 `json:"ops"`
	}
	out := []*devSum{}
	idx := map[int64]*devSum{}
	rows, _ := a.st.db.Query(`SELECT id,name,kind FROM devices ORDER BY name`)
	for rows.Next() {
		d := &devSum{Ops: map[string]int64{}}
		rows.Scan(&d.ID, &d.Name, &d.Kind)
		out = append(out, d)
		idx[d.ID] = d
	}
	rows.Close()
	rows, _ = a.st.db.Query(`SELECT device_id, op, SUM(count), COUNT(*), MAX(ts) FROM audit GROUP BY device_id, op`)
	for rows.Next() {
		var id, ev, n, last int64
		var op string
		rows.Scan(&id, &op, &ev, &n, &last)
		d := idx[id]
		if d == nil {
			d = &devSum{ID: 0, Name: "Unmatched sender", Ops: map[string]int64{}}
			idx[id] = d
			out = append(out, d)
		}
		d.Ops[op] += ev
		d.Events += ev
		d.Rows += n
		if last > d.LastEvent {
			d.LastEvent = last
		}
	}
	rows.Close()
	writeJSON(w, map[string]any{"devices": out, "windows_audit": winAudit, "dropped_lines": a.auditDropped.Load()})
}

func (a *App) auditEvents(w http.ResponseWriter, r *http.Request) {
	c := []string{"1=1"}
	var args []any
	if d := qInt64(r, "device"); d > 0 {
		c = append(c, "device_id=?")
		args = append(args, d)
	}
	for _, k := range []string{"op", "username"} {
		if v := r.URL.Query().Get(k); v != "" {
			c = append(c, k+"=?")
			args = append(args, v)
		}
	}
	if v := r.URL.Query().Get("q"); v != "" {
		c = append(c, `path LIKE ? ESCAPE '\'`)
		args = append(args, "%"+likeEscape(v)+"%")
	}
	rows, err := a.st.db.Query(`SELECT ts,device_id,username,op,path,proto,client,bytes,count FROM audit WHERE `+strings.Join(c, " AND ")+` ORDER BY ts DESC LIMIT ?`,
		append(args, qInt(r, "limit", 200))...)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []AuditRow{}
	for rows.Next() {
		var e AuditRow
		rows.Scan(&e.TS, &e.DeviceID, &e.User, &e.Op, &e.Path, &e.Proto, &e.Client, &e.Bytes, &e.Count)
		out = append(out, e)
	}
	writeJSON(w, out)
}

type AuditRow struct {
	AuditEvent
	Count int64 `json:"count"`
}

func (a *App) inventory(w http.ResponseWriter, r *http.Request) {
	rows, _ := a.st.db.Query(`SELECT id,name,kind,host,inventory,inventory_at FROM devices ORDER BY name`)
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, at int64
		var name, kind, host, inv string
		rows.Scan(&id, &name, &kind, &host, &inv, &at)
		var m map[string]any
		json.Unmarshal([]byte(inv), &m)
		out = append(out, map[string]any{"id": id, "name": name, "kind": kind, "host": host, "inventory": m, "collected": at})
	}
	writeJSON(w, out)
}

// ---------- tags ----------

func (a *App) listTags(w http.ResponseWriter, r *http.Request) {
	rows, _ := a.st.db.Query(`SELECT t.tag, COUNT(*) FROM file_tags t GROUP BY t.tag ORDER BY t.tag`)
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var t string
		var n int64
		rows.Scan(&t, &n)
		out = append(out, map[string]any{"tag": t, "files": n})
	}
	writeJSON(w, out)
}

func (a *App) listTagRules(w http.ResponseWriter, r *http.Request) {
	rows, _ := a.st.db.Query(`SELECT r.id,r.name,r.tag,r.match,r.enabled,(SELECT COUNT(*) FROM file_tags t WHERE t.rule_id=r.id) FROM tag_rules r ORDER BY r.name`)
	defer rows.Close()
	out := []TagRule{}
	for rows.Next() {
		var t TagRule
		var m string
		var en int
		rows.Scan(&t.ID, &t.Name, &t.Tag, &m, &en, &t.Tagged)
		json.Unmarshal([]byte(m), &t.Match)
		t.Enabled = en == 1
		out = append(out, t)
	}
	writeJSON(w, out)
}

func (a *App) saveTagRule(w http.ResponseWriter, r *http.Request) {
	var in TagRule
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	in.Tag = strings.TrimSpace(in.Tag)
	if in.Name == "" || in.Tag == "" {
		httpErr(w, 400, "name and tag are required")
		return
	}
	in.Match.Tag = ""
	if in.Match.empty() {
		httpErr(w, 400, "add at least one condition")
		return
	}
	m, _ := json.Marshal(in.Match)
	id := idOf(r)
	if id == 0 {
		res, _ := a.st.db.Exec(`INSERT INTO tag_rules(name,tag,match,enabled,created) VALUES(?,?,?,?,?)`, in.Name, in.Tag, string(m), b2i(in.Enabled), now())
		id, _ = res.LastInsertId()
	} else {
		a.st.db.Exec(`UPDATE tag_rules SET name=?,tag=?,match=?,enabled=? WHERE id=?`, in.Name, in.Tag, string(m), b2i(in.Enabled), id)
	}
	a.st.db.Exec(`DELETE FROM file_tags WHERE rule_id=?`, id)
	if in.Enabled {
		a.applyRule(id, in.Tag, string(m), 0)
	}
	writeJSON(w, map[string]any{"id": id})
}

func (a *App) deleteTagRule(w http.ResponseWriter, r *http.Request) {
	a.st.db.Exec(`DELETE FROM file_tags WHERE rule_id=?`, idOf(r))
	a.st.db.Exec(`DELETE FROM tag_rules WHERE id=?`, idOf(r))
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) applyTagRuleNow(w http.ResponseWriter, r *http.Request) {
	var tag, m string
	if err := a.st.db.QueryRow(`SELECT tag,match FROM tag_rules WHERE id=?`, idOf(r)).Scan(&tag, &m); err != nil {
		httpErr(w, 404, "rule not found")
		return
	}
	if err := a.applyRule(idOf(r), tag, m, 0); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) previewFilter(w http.ResponseWriter, r *http.Request) {
	var fl Filter
	readJSON(r, &fl)
	from, args := a.fileSelect(fl)
	var n, b sql.NullInt64
	a.st.db.QueryRow(`SELECT COUNT(*), SUM(f.size)`+from, args...).Scan(&n, &b)
	writeJSON(w, map[string]any{"files": n.Int64, "bytes": b.Int64})
}

// ---------- automations ----------

func (a *App) listAutomations(w http.ResponseWriter, r *http.Request) {
	rows, _ := a.st.db.Query(`SELECT id FROM automations ORDER BY name`)
	var ids []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	out := []Automation{}
	for _, id := range ids {
		if au, err := a.automation(id); err == nil {
			out = append(out, au)
		}
	}
	writeJSON(w, map[string]any{"automations": out})
}

func (a *App) saveAutomation(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Automation
		Confirm string `json:"confirm"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	au := in.Automation
	if au.InputKind == "tag" {
		au.Input = Filter{Tag: au.Input.Tag, DeviceID: au.Input.DeviceID, ShareID: au.Input.ShareID}
	}
	if err := validateAutomation(&au); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	// A schedule means unattended real runs: destructive pipelines must be armed by typing the name.
	if au.Schedule != "" && isDestructive(au.Actions) && in.Confirm != au.Name {
		httpErr(w, 400, "scheduling a destructive automation requires typing its name to confirm")
		return
	}
	inJ, _ := json.Marshal(au.Input)
	acJ, _ := json.Marshal(au.Actions)
	id := idOf(r)
	if id == 0 {
		res, err := a.st.db.Exec(`INSERT INTO automations(name,description,enabled,input_kind,input,actions,schedule,created) VALUES(?,?,?,?,?,?,?,?)`,
			au.Name, au.Desc, b2i(au.Enabled), au.InputKind, string(inJ), string(acJ), au.Schedule, now())
		if err != nil {
			httpErr(w, 500, err.Error())
			return
		}
		id, _ = res.LastInsertId()
	} else {
		a.st.db.Exec(`UPDATE automations SET name=?,description=?,enabled=?,input_kind=?,input=?,actions=?,schedule=? WHERE id=?`,
			au.Name, au.Desc, b2i(au.Enabled), au.InputKind, string(inJ), string(acJ), au.Schedule, id)
	}
	writeJSON(w, map[string]any{"id": id})
}

func (a *App) deleteAutomation(w http.ResponseWriter, r *http.Request) {
	a.st.db.Exec(`DELETE FROM automations WHERE id=?`, idOf(r))
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) runAutomationHTTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Dry     bool   `json:"dry"`
		Confirm string `json:"confirm"`
	}
	readJSON(r, &in)
	au, err := a.automation(idOf(r))
	if err != nil {
		httpErr(w, 404, "automation not found")
		return
	}
	if !au.Enabled {
		httpErr(w, 400, "automation is disabled")
		return
	}
	if au.LastStatus == "running" {
		httpErr(w, 409, "a run is already in progress")
		return
	}
	if !in.Dry && isDestructive(au.Actions) && in.Confirm != au.Name {
		httpErr(w, 400, "type the automation name to confirm a real run")
		return
	}
	id, err := a.startAutomationRun(au, in.Dry)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"run_id": id})
}

func (a *App) listRuns(w http.ResponseWriter, r *http.Request) {
	rows, _ := a.st.db.Query(`SELECT id,dry_run,started,finished,status,items,ok,failed,message FROM automation_runs WHERE automation_id=? ORDER BY id DESC LIMIT 50`, idOf(r))
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, dry, st, fin, items, ok, failed int64
		var status, msg string
		rows.Scan(&id, &dry, &st, &fin, &status, &items, &ok, &failed, &msg)
		out = append(out, map[string]any{"id": id, "dry_run": dry == 1, "started": st, "finished": fin, "status": status,
			"items": items, "ok": ok, "failed": failed, "message": msg})
	}
	writeJSON(w, out)
}

func (a *App) ledger(w http.ResponseWriter, r *http.Request) {
	rows, _ := a.st.db.Query(`SELECT l.ts, COALESCE(s.name,''), l.path, l.action, l.target, l.result, l.detail FROM automation_ledger l
	  LEFT JOIN shares s ON s.id=l.share_id WHERE l.run_id=? ORDER BY l.rowid LIMIT ?`, idOf(r), qInt(r, "limit", 500))
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var t int64
		var sh, p, ac, tg, res, det string
		rows.Scan(&t, &sh, &p, &ac, &tg, &res, &det)
		out = append(out, map[string]any{"ts": t, "share": sh, "path": p, "action": ac, "target": tg, "result": res, "detail": det})
	}
	writeJSON(w, out)
}

func (a *App) ledgerCSV(w http.ResponseWriter, r *http.Request) {
	rows, _ := a.st.db.Query(`SELECT l.ts, COALESCE(s.name,''), l.path, l.action, l.target, l.result, l.detail FROM automation_ledger l
	  LEFT JOIN shares s ON s.id=l.share_id WHERE l.run_id=? ORDER BY l.rowid`, idOf(r))
	defer rows.Close()
	cw := csvStart(w, fmt.Sprintf("run-%d-ledger.csv", idOf(r)))
	cw.Write([]string{"time_utc", "share", "path", "action", "target", "result", "detail"})
	for rows.Next() {
		var t int64
		var sh, p, ac, tg, res, det string
		rows.Scan(&t, &sh, &p, &ac, &tg, &res, &det)
		cw.Write([]string{ts(t), sh, p, ac, tg, res, det})
	}
	cw.Flush()
}

func (a *App) settings(w http.ResponseWriter, r *http.Request) {
	primary, archive := a.costs()
	writeJSON(w, map[string]any{"version": version, "ingest_token_set": a.st.setting("ingest_token") != "", "cost_primary": primary, "cost_archive": archive,
		"windows_audit": winAudit, "dropped_audit_lines": a.auditDropped.Load()})
}
