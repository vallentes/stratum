package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// A collector is this same binary running on-site ("stratum collector ..."). It polls
// the central server for work over HTTPS, walks storage the server cannot reach, and
// streams index rows, audit events and task results back. The collector never
// listens on the network except for the optional local syslog receiver.

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// ================= server side =================

func (a *App) collectorFrom(r *http.Request) (int64, bool) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		return 0, false
	}
	var id int64
	if a.st.db.QueryRow(`SELECT id FROM collectors WHERE token_hash=?`, hashToken(tok)).Scan(&id) != nil {
		return 0, false
	}
	return id, true
}

func (a *App) cguard(fn func(w http.ResponseWriter, r *http.Request, cid int64)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cid, ok := a.collectorFrom(r)
		if !ok {
			httpErr(w, 401, "unknown collector token")
			return
		}
		fn(w, r, cid)
	}
}

// readBody accepts gzip-compressed bodies from collectors.
func readBody(r *http.Request, v any) error {
	defer r.Body.Close()
	var rd io.Reader = http.MaxBytesReader(nil, r.Body, 256<<20)
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(rd)
		if err != nil {
			return err
		}
		defer gz.Close()
		rd = gz
	}
	dec := json.NewDecoder(rd)
	dec.UseNumber()
	return dec.Decode(v)
}

func (a *App) collectorRoutes(m *http.ServeMux) {
	g := func(p string, fn h) { m.HandleFunc(p, a.guardFor(p, fn)) }
	g("GET /api/collectors", a.listCollectors)
	g("POST /api/collectors", a.createCollector)
	g("POST /api/collectors/{id}/token", a.rotateCollector)
	g("DELETE /api/collectors/{id}", a.deleteCollector)
	g("POST /api/collectors/{id}/installer", a.collectorInstaller)

	m.HandleFunc("POST /api/c/poll", a.cguard(a.cPoll))
	m.HandleFunc("POST /api/c/tasks/{id}/result", a.cguard(a.cTaskResult))
	m.HandleFunc("POST /api/c/scans/{id}/rows", a.cguard(a.cScanRows))
	m.HandleFunc("POST /api/c/scans/{id}/finish", a.cguard(a.cScanFinish))
	m.HandleFunc("POST /api/c/audit", a.cguard(a.cAudit))
	m.HandleFunc("GET /api/c/binary", a.cguard(a.collectorBinary))
}

type collectorOut struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
	OS       string `json:"os"`
	LastSeen int64  `json:"last_seen"`
	Online   bool   `json:"online"`
	Devices  int64  `json:"devices"`
	Info     any    `json:"info"`
}

func (a *App) listCollectors(w http.ResponseWriter, r *http.Request) {
	rows, _ := a.st.db.Query(`SELECT c.id,c.name,c.hostname,c.version,c.os,c.last_seen,c.info,(SELECT COUNT(*) FROM devices d WHERE d.collector_id=c.id) FROM collectors c ORDER BY c.name`)
	defer rows.Close()
	out := []collectorOut{}
	for rows.Next() {
		var c collectorOut
		var info string
		rows.Scan(&c.ID, &c.Name, &c.Hostname, &c.Version, &c.OS, &c.LastSeen, &info, &c.Devices)
		json.Unmarshal([]byte(info), &c.Info)
		if ts, live := a.collectorSeen(c.ID); ts > 0 {
			c.LastSeen, c.Info = ts, live
			c.Hostname, c.Version, c.OS = fmt.Sprint(live["hostname"]), fmt.Sprint(live["version"]), fmt.Sprint(live["os"])
		}
		c.Online = now()-c.LastSeen < 30
		out = append(out, c)
	}
	writeJSON(w, out)
}

func (a *App) createCollector(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name string }
	readJSON(r, &in)
	if strings.TrimSpace(in.Name) == "" {
		httpErr(w, 400, "name is required")
		return
	}
	tok := "stc_" + randHex(24)
	res, err := a.st.db.Exec(`INSERT INTO collectors(name,token_hash,created) VALUES(?,?,?)`, strings.TrimSpace(in.Name), hashToken(tok), now())
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	id, _ := res.LastInsertId()
	writeJSON(w, map[string]any{"id": id, "token": tok})
}

func (a *App) rotateCollector(w http.ResponseWriter, r *http.Request) {
	tok := "stc_" + randHex(24)
	a.st.db.Exec(`UPDATE collectors SET token_hash=? WHERE id=?`, hashToken(tok), idOf(r))
	writeJSON(w, map[string]any{"token": tok})
}

func (a *App) deleteCollector(w http.ResponseWriter, r *http.Request) {
	var n int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE collector_id=?`, idOf(r)).Scan(&n)
	if n > 0 {
		httpErr(w, 409, "move or remove the devices on this collector first")
		return
	}
	a.st.db.Exec(`DELETE FROM collectors WHERE id=?`, idOf(r))
	a.st.db.Exec(`DELETE FROM tasks WHERE collector_id=?`, idOf(r))
	writeJSON(w, map[string]any{"ok": true})
}

type wireTask struct {
	ID      int64           `json:"id"`
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

type pollReply struct {
	Tasks         []wireTask       `json:"tasks"`
	Cancel        []int64          `json:"cancel"`
	Devices       []map[string]any `json:"devices"`
	WindowsDevice int64            `json:"windows_device"`
	Version       string           `json:"version"`
	SHAWindows    string           `json:"sha_windows"`
	SHALinux      string           `json:"sha_linux"`
}

func (a *App) cPoll(w http.ResponseWriter, r *http.Request, cid int64) {
	var info map[string]any
	readBody(r, &info)
	quick.seen(cid)
	a.notePoll(cid, info)
	// Interactive reads first, and on their own: everything below writes to
	// SQLite, which a publishing scan can hold for 15s. The collector polls
	// again half a second after it gets tasks, so nothing else waits long.
	if qt := quick.take(cid); len(qt) > 0 {
		go a.st.db.Exec(`UPDATE collectors SET last_seen=? WHERE id=?`, now(), cid)
		writeJSON(w, pollReply{Tasks: qt, Version: version, SHAWindows: distSHA("stratum.exe"), SHALinux: distSHA("stratum-linux")})
		return
	}
	// Check-ins are kept in memory (flushed once a minute): a publishing scan can
	// hold the SQLite writer for a long time and polls must never wait on it.
	if raw, has := info["running_scan_ids"]; has {
		run := map[int64]bool{}
		ids, _ := raw.([]any) // null when the collector is running nothing
		for _, v := range ids {
			if n, ok := v.(json.Number); ok {
				x, _ := n.Int64()
				run[x] = true
			}
		}
		go a.requeueLostRemote(cid, run)
	}
	var rep pollReply
	rep.Version, rep.SHAWindows, rep.SHALinux = version, distSHA("stratum.exe"), distSHA("stratum-linux")
	// Claim only when something is pending: the read never waits for the writer.
	var pending int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM tasks WHERE collector_id=? AND status='pending'`, cid).Scan(&pending)
	var rows *sql.Rows
	err := sql.ErrNoRows
	if pending > 0 {
		rows, err = a.st.db.Query(`UPDATE tasks SET status='claimed', claimed_at=? WHERE collector_id=? AND status='pending' RETURNING id, kind, payload`, now(), cid)
	}
	if err == nil {
		for rows.Next() {
			var t wireTask
			var p string
			rows.Scan(&t.ID, &t.Kind, &p)
			t.Payload = json.RawMessage(p)
			rep.Tasks = append(rep.Tasks, t)
		}
		rows.Close()
	}
	a.mu.Lock()
	for _, t := range rep.Tasks {
		if t.Kind == "scan" {
			var pl struct {
				ScanID int64 `json:"scan_id"`
			}
			json.Unmarshal(t.Payload, &pl)
			if p := a.running[pl.ScanID]; p != nil {
				p.mu.Lock()
				p.Claimed, p.Updated = true, now()
				p.mu.Unlock()
			}
		}
	}
	for _, p := range a.running {
		if p.Remote && p.Cancel {
			rep.Cancel = append(rep.Cancel, p.ScanID)
		}
	}
	a.mu.Unlock()
	drows, _ := a.st.db.Query(`SELECT id,kind,host FROM devices WHERE collector_id=?`, cid)
	for drows != nil && drows.Next() {
		var id int64
		var k, h string
		drows.Scan(&id, &k, &h)
		rep.Devices = append(rep.Devices, map[string]any{"id": id, "kind": k, "host": h})
		if k == "windows" && isLocalHost(h) && rep.WindowsDevice == 0 {
			rep.WindowsDevice = id
		}
	}
	if drows != nil {
		drows.Close()
	}
	writeJSON(w, rep)
}

func (a *App) cTaskResult(w http.ResponseWriter, r *http.Request, cid int64) {
	var in struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err := readBody(r, &in); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	if quick.deliver(idOf(r), quickResult{ok: in.OK, result: in.Result, err: in.Error}) {
		writeJSON(w, map[string]any{"ok": true})
		return
	}
	st := "done"
	if !in.OK {
		st = "failed"
	}
	a.st.db.Exec(`UPDATE tasks SET status=?, result=?, error=?, finished=? WHERE id=? AND collector_id=?`, st, string(in.Result), in.Error, now(), idOf(r), cid)
	var kind string
	a.st.db.QueryRow(`SELECT kind FROM tasks WHERE id=?`, idOf(r)).Scan(&kind)
	if in.OK && (kind == "enable_audit" || kind == "disable_audit") {
		var out map[string]string
		json.Unmarshal(in.Result, &out)
		for _, dev := range a.ids(`SELECT id FROM devices WHERE collector_id=?`, cid) {
			a.markAudited(dev, out)
		}
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) remoteScan(w http.ResponseWriter, r *http.Request, cid int64) *scanProgress {
	a.mu.Lock()
	p := a.running[idOf(r)]
	a.mu.Unlock()
	if p == nil || !p.Remote || (r.URL.Query().Get("attempt") != "" && attemptOf(r.URL.Query().Get("attempt")) != p.Attempt) {
		httpErr(w, 410, "scan is no longer running on the server")
		return nil
	}
	return p
}

type wireRow struct {
	K string `json:"k"`
	V []any  `json:"v"`
}

type wireProgress struct {
	Files, Dirs, Bytes, Errors int64
	Current                    string
}

func (a *App) cScanRows(w http.ResponseWriter, r *http.Request, cid int64) {
	p := a.remoteScan(w, r, cid)
	if p == nil {
		return
	}
	var in struct {
		Rows     []wireRow    `json:"rows"`
		Progress wireProgress `json:"progress"`
	}
	if err := readBody(r, &in); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	rows := make([]row, 0, len(in.Rows))
	for _, wr := range in.Rows {
		vals := make([]any, len(wr.V))
		for i, v := range wr.V {
			if n, ok := v.(json.Number); ok {
				iv, err := n.Int64()
				if err != nil {
					f, _ := n.Float64()
					iv = int64(f)
				}
				vals[i] = iv
			} else {
				vals[i] = v
			}
		}
		// Scan and share ids are authoritative from the server, never from the collector.
		if len(vals) > 0 {
			vals[0] = p.ScanID
		}
		if (wr.K == "i" || wr.K == "a") && len(vals) > 1 {
			vals[1] = p.ShareID
		}
		if _, ok := insertSQL[wr.K]; ok {
			rows = append(rows, row{wr.K, vals})
		}
	}
	if err := a.insertRows(rows); err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	p.mu.Lock()
	p.Files, p.Dirs, p.Bytes, p.Errors = in.Progress.Files, in.Progress.Dirs, in.Progress.Bytes, in.Progress.Errors
	p.Current, p.Updated, p.Claimed = in.Progress.Current, now(), true
	cancel := p.Cancel
	p.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true, "cancel": cancel})
}

func (a *App) cScanFinish(w http.ResponseWriter, r *http.Request, cid int64) {
	p := a.remoteScan(w, r, cid)
	if p == nil {
		return
	}
	var res scanResult
	if err := readBody(r, &res); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	if p.Cancel {
		res.Cancelled = true
	}
	a.st.db.Exec(`UPDATE tasks SET status='done', finished=? WHERE kind='scan' AND collector_id=? AND json_extract(payload,'$.scan_id')=?`, now(), cid, p.ScanID)
	go a.finishScan(p.ShareID, p.ScanID, p, res)
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) cAudit(w http.ResponseWriter, r *http.Request, cid int64) {
	var evs []AuditEvent
	if err := readBody(r, &evs); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	mine := map[int64]bool{}
	for _, id := range a.ids(`SELECT id FROM devices WHERE collector_id=?`, cid) {
		mine[id] = true
	}
	n := 0
	for _, e := range evs {
		if !mine[e.DeviceID] {
			continue // a collector may only report for its own devices
		}
		a.audit.add(e)
		n++
	}
	writeJSON(w, map[string]any{"accepted": n})
}

// runTask queues work for a collector and waits for its answer.
func (a *App) runTask(cid int64, kind string, payload any, timeout time.Duration) (json.RawMessage, error) {
	if isQuickKind(kind) {
		return quick.run(cid, kind, payload, timeout)
	}
	b, _ := json.Marshal(payload)
	res, err := a.st.db.Exec(`INSERT INTO tasks(collector_id,kind,payload,status,created) VALUES(?,?,?,'pending',?)`, cid, kind, string(b), now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		var st, result, errMsg string
		a.st.db.QueryRow(`SELECT status,result,error FROM tasks WHERE id=?`, id).Scan(&st, &result, &errMsg)
		switch st {
		case "done":
			a.st.db.Exec(`DELETE FROM tasks WHERE id=?`, id)
			return json.RawMessage(result), nil
		case "failed":
			a.st.db.Exec(`DELETE FROM tasks WHERE id=?`, id)
			return nil, errors.New(errMsg)
		}
	}
	a.st.db.Exec(`UPDATE tasks SET status='expired' WHERE id=? AND status IN ('pending','claimed')`, id)
	var seen int64
	a.st.db.QueryRow(`SELECT last_seen FROM collectors WHERE id=?`, cid).Scan(&seen)
	if now()-seen > 30 {
		return nil, fmt.Errorf("the collector for this device is offline (last seen %s)", agoText(seen))
	}
	return nil, errors.New("the collector did not answer in time")
}

func agoText(u int64) string {
	if u == 0 {
		return "never"
	}
	return time.Since(time.Unix(u, 0)).Round(time.Second).String() + " ago"
}

// ================= collector side =================

type collectorClient struct {
	server  string
	token   string
	dataDir string
	hc      *http.Client

	mu       sync.Mutex
	scans    map[int64]context.CancelFunc
	devices  []map[string]any
	winDev   atomic.Int64
	auditCh  chan AuditEvent
	inflight atomic.Int64 // tasks being worked on; self-update waits for zero
	ipMap    map[string]int64
	ipAt     time.Time
}

func (c *collectorClient) post(p string, in, out any) (int, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	json.NewEncoder(gz).Encode(in)
	gz.Close()
	req, _ := http.NewRequest("POST", c.server+p, &buf)
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return resp.StatusCode, fmt.Errorf("%s: HTTP %d %s", p, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode, nil
}

// postRetry retries transient failures with backoff; 4xx answers are final.
func (c *collectorClient) postRetry(p string, in, out any, tries int) (int, error) {
	var code int
	var err error
	for i := 0; i < tries; i++ {
		code, err = c.post(p, in, out)
		if err == nil || (code >= 400 && code < 500) {
			return code, err
		}
		time.Sleep(time.Duration(1<<i) * time.Second)
	}
	return code, err
}

func runCollector(server, token, dataDir string, insecure bool, syslogAddr string) {
	server = strings.TrimRight(server, "/")
	os.MkdirAll(dataDir, 0o700)
	c := &collectorClient{server: server, token: token, dataDir: dataDir, scans: map[int64]context.CancelFunc{},
		auditCh: make(chan AuditEvent, 50000),
		hc: &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment, TLSClientConfig: collectorTLS(insecure)}}}
	host, _ := os.Hostname()
	log.Printf("stratum collector %s on %s reporting to %s", version, host, server)

	go c.auditPump()
	lastFile := filepath.Join(dataDir, "winaudit-last-id")
	startWindowsAudit(func() int64 { return c.winDev.Load() }, func(e AuditEvent) { c.queueAudit(e) },
		func() uint64 {
			b, _ := os.ReadFile(lastFile)
			n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
			return n
		},
		func(n uint64) { os.WriteFile(lastFile, []byte(strconv.FormatUint(n, 10)), 0o600) })
	syslogListen(syslogAddr, func(line, ip string) {
		if e, ok := parseAuditLine(line); ok {
			if e.DeviceID = c.deviceForIP(ip); e.DeviceID > 0 {
				c.queueAudit(e)
			}
		}
	})

	failures := 0
	for {
		c.mu.Lock()
		running := len(c.scans)
		var runIDs []int64
		for id := range c.scans {
			runIDs = append(runIDs, id)
		}
		c.mu.Unlock()
		var rep pollReply
		_, err := c.post("/api/c/poll", map[string]any{"hostname": host, "version": version, "os": runtime.GOOS + "/" + runtime.GOARCH,
			"running_scans": running, "running_scan_ids": runIDs, "jobs": jobs.snapshot(), "windows_audit": winAudit}, &rep)
		if err != nil {
			failures++
			if failures == 1 || failures%20 == 0 {
				log.Printf("poll failed (%d in a row): %v", failures, err)
			}
			time.Sleep(time.Duration(min(failures, 10)) * 3 * time.Second)
			continue
		}
		if failures > 0 {
			log.Printf("connected to %s again", server)
		}
		failures = 0
		c.mu.Lock()
		c.devices = rep.Devices
		c.ipMap = nil
		for _, id := range rep.Cancel {
			if cancel := c.scans[id]; cancel != nil {
				cancel()
			}
		}
		c.mu.Unlock()
		c.winDev.Store(rep.WindowsDevice)
		sha := rep.SHAWindows
		if runtime.GOOS != "windows" {
			sha = rep.SHALinux
		}
		if c.selfUpdate(rep.Version, sha) {
			os.Exit(3) // the service manager restarts us on the new binary
		}
		for _, t := range rep.Tasks {
			go c.handle(t)
		}
		if len(rep.Tasks) > 0 {
			time.Sleep(500 * time.Millisecond)
		} else {
			time.Sleep(3 * time.Second)
		}
	}
}

func (c *collectorClient) handle(t wireTask) {
	c.inflight.Add(1)
	defer c.inflight.Add(-1)
	var result any
	var err error
	switch t.Kind {
	case "scan":
		c.doScan(t.Payload)
		return
	case "discover":
		var pl struct {
			Device deviceWire `json:"device"`
		}
		json.Unmarshal(t.Payload, &pl)
		result, err = discoverDevice(pl.Device.dev())
	case "inventory":
		var pl struct {
			Device deviceWire `json:"device"`
			Shares []Share    `json:"shares"`
		}
		json.Unmarshal(t.Payload, &pl)
		result = collectInventory(pl.Device.dev(), pl.Shares)
	case "exec":
		var pl execPayload
		json.Unmarshal(t.Payload, &pl)
		result = execBatch(pl)
	case "enable_audit":
		var pl struct {
			Paths []string `json:"paths"`
		}
		json.Unmarshal(t.Payload, &pl)
		result, err = enableFileAuditing(pl.Paths)
	case "disable_audit":
		var pl struct {
			Paths []string `json:"paths"`
		}
		json.Unmarshal(t.Payload, &pl)
		result, err = disableFileAuditing(pl.Paths)
	case "stat":
		var pl statPayload
		json.Unmarshal(t.Payload, &pl)
		result = statItems(pl)
	case "read":
		var pl readPayload
		json.Unmarshal(t.Payload, &pl)
		result, err = readRange(pl)
	case "ldap":
		var pl struct {
			Config ldapCfg  `json:"config"`
			Owners []string `json:"owners"`
		}
		json.Unmarshal(t.Payload, &pl)
		result, err = ldapResolve(pl.Config, pl.Owners)
	case "perf":
		var pl struct {
			Device deviceWire `json:"device"`
		}
		json.Unmarshal(t.Payload, &pl)
		d := pl.Device.dev()
		if d.Kind == "windows" && isLocalHost(d.Host) {
			result, err = collectPerf(d)
		} else if d.Kind == "powerscale" {
			result, err = perfPowerScale(d)
		} else {
			err = fmt.Errorf("IOPS for this device must be collected on the machine itself")
		}
	default:
		err = fmt.Errorf("this collector does not support %q; upgrade it", t.Kind)
	}
	body := map[string]any{"ok": err == nil, "result": result}
	if err != nil {
		body["error"] = err.Error()
	}
	if _, perr := c.postRetry(fmt.Sprintf("/api/c/tasks/%d/result", t.ID), body, nil, 5); perr != nil {
		log.Printf("task %d (%s): could not report result: %v", t.ID, t.Kind, perr)
	}
}

func (c *collectorClient) doScan(payload json.RawMessage) {
	var pl struct {
		ScanID  int64               `json:"scan_id"`
		Attempt int64               `json:"attempt"`
		Device  deviceWire          `json:"device"`
		Share   Share               `json:"share"`
		Done    map[string][2]int64 `json:"done"`
	}
	json.Unmarshal(payload, &pl)
	d := pl.Device.dev()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.mu.Lock()
	c.scans[pl.ScanID] = cancel
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.scans, pl.ScanID); c.mu.Unlock() }()
	log.Printf("scan %d: %s %s started", pl.ScanID, d.Name, pl.Share.Path)

	p := newProgress(pl.ScanID, pl.Share, d)
	res := scanResult{}
	l, err := listerFor(d, pl.Share)
	if err != nil {
		res.WriteErr = err.Error()
	} else {
		out := make(chan row, 20000)
		done := make(chan error, 1)
		go c.sender(ctx, cancel, pl.ScanID, pl.Attempt, out, p, done) // heartbeats even while queued
		release, ok := acquireScanSlot(ctx, d, pl.Share, p)
		defer release()
		if !ok {
			res.WriteErr = "cancelled while queued"
		}
		res.RootOK, res.Interrupted = walkShare(ctx, d, pl.Share, pl.ScanID, l, p, out, pl.Done)
		close(out)
		if werr := <-done; werr != nil {
			res.WriteErr = "upload to server failed: " + werr.Error()
		}
	}
	snap := p.snapshot()
	res.Cancelled = ctx.Err() != nil && res.WriteErr == ""
	res.Files, res.Dirs, res.Bytes, res.Errors = snap.Files, snap.Dirs, snap.Bytes, snap.Errors
	if _, err := c.postRetry(fmt.Sprintf("/api/c/scans/%d/finish?attempt=%d", pl.ScanID, pl.Attempt), res, nil, 8); err != nil {
		log.Printf("scan %d: could not report finish: %v", pl.ScanID, err)
	}
	log.Printf("scan %d: done, %d files, %d bytes, root_ok=%v interrupted=%d", pl.ScanID, res.Files, res.Bytes, res.RootOK, res.Interrupted)
}

// sender streams rows to the server in compressed batches along with live progress.
func (c *collectorClient) sender(ctx context.Context, cancel context.CancelFunc, scanID, attempt int64, in <-chan row, p *scanProgress, done chan<- error) {
	const batch = 2000
	buf := make([]wireRow, 0, batch)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var failed error
	flush := func() {
		if failed != nil {
			buf = buf[:0]
			return
		}
		snap := p.snapshot()
		var rep struct {
			Cancel bool `json:"cancel"`
		}
		code, err := c.postRetry(fmt.Sprintf("/api/c/scans/%d/rows?attempt=%d", scanID, attempt), map[string]any{"rows": buf,
			"progress": wireProgress{snap.Files, snap.Dirs, snap.Bytes, snap.Errors, snap.Current}}, &rep, 6)
		buf = buf[:0]
		if err != nil {
			failed = err
			if code == 410 {
				failed = errors.New("server no longer tracks this scan")
			}
			cancel()
		} else if rep.Cancel {
			cancel()
		}
	}
	for {
		select {
		case r, ok := <-in:
			if !ok {
				flush()
				done <- failed
				return
			}
			buf = append(buf, wireRow{r.kind, r.vals})
			if len(buf) >= batch {
				flush()
			}
		case <-tick.C:
			flush() // also carries progress when the walk is slow
		}
	}
}

func (c *collectorClient) queueAudit(e AuditEvent) {
	select {
	case c.auditCh <- e:
	default: // server unreachable for a long time: drop rather than grow without bound
	}
}

func (c *collectorClient) auditPump() {
	var buf []AuditEvent
	t := time.NewTicker(5 * time.Second)
	for {
		select {
		case e := <-c.auditCh:
			buf = append(buf, e)
			if len(buf) < 5000 {
				continue
			}
		case <-t.C:
		}
		if len(buf) == 0 {
			continue
		}
		if _, err := c.postRetry("/api/c/audit", buf, nil, 3); err == nil {
			buf = buf[:0]
		} else if len(buf) > 200000 {
			buf = buf[len(buf)-100000:]
		}
	}
}

func (c *collectorClient) deviceForIP(ip string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ipMap == nil || time.Since(c.ipAt) > 5*time.Minute {
		c.ipMap, c.ipAt = map[string]int64{}, time.Now()
		for _, d := range c.devices {
			h := fmt.Sprint(d["host"])
			h = strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
			h, _, _ = strings.Cut(h, ":")
			id, _ := d["id"].(float64)
			if addrs, err := net.LookupHost(h); err == nil {
				for _, ad := range addrs {
					c.ipMap[ad] = int64(id)
				}
			}
		}
	}
	return c.ipMap[ip]
}

// notePoll records a collector check-in in memory; flushCollectorSeen persists it.
func (a *App) notePoll(cid int64, info map[string]any) {
	if info == nil {
		info = map[string]any{}
	}
	info["_ts"] = now()
	a.mu.Lock()
	if a.seen == nil {
		a.seen = map[int64]map[string]any{}
	}
	a.seen[cid] = info
	a.mu.Unlock()
}

func (a *App) collectorSeen(cid int64) (int64, map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if i, ok := a.seen[cid]; ok {
		ts, _ := i["_ts"].(int64)
		return ts, i
	}
	return 0, nil
}

func (a *App) flushCollectorSeen() {
	a.mu.Lock()
	snap := map[int64]map[string]any{}
	for k, v := range a.seen {
		snap[k] = v
	}
	a.mu.Unlock()
	for cid, info := range snap {
		ts, _ := info["_ts"].(int64)
		ib, _ := json.Marshal(info)
		a.st.db.Exec(`UPDATE collectors SET last_seen=?, hostname=?, version=?, os=?, info=? WHERE id=?`,
			ts, fmt.Sprint(info["hostname"]), fmt.Sprint(info["version"]), fmt.Sprint(info["os"]), string(ib), cid)
	}
}

// collectorPin, when set, makes the collector trust exactly one server certificate.
var collectorPin string

func collectorTLS(insecure bool) *tls.Config {
	if collectorPin != "" {
		return pinnedTLS(collectorPin)
	}
	return &tls.Config{InsecureSkipVerify: insecure}
}
