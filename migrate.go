package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Migration planner and copier. A migration copies one indexed share to a folder,
// PowerScale path or S3 bucket on a registered device. The plan comes from the index:
// totals, an estimate, everything that will fail at the target, and waves (groups of
// top-level folders) that can be copied, checked and re-run one at a time.

type migOptions struct {
	Conflict  string  `json:"conflict"` // skip | newer | overwrite
	Verify    string  `json:"verify"`   // checksum | size
	WaveGB    float64 `json:"wave_gb"`  // target wave size
	MBps      float64 `json:"mbps"`     // assumed throughput for the estimate
	FilesPerS float64 `json:"files_per_s"`
}

func (o *migOptions) defaults() {
	if o.Conflict == "" {
		o.Conflict = "skip"
	}
	if o.Verify == "" {
		o.Verify = "checksum"
	}
	if o.WaveGB <= 0 {
		o.WaveGB = 500
	}
	if o.MBps <= 0 {
		o.MBps = 100
	}
	if o.FilesPerS <= 0 {
		o.FilesPerS = 100
	}
}

type migCheck struct {
	Key      string   `json:"key"`
	Severity string   `json:"severity"` // blocker | warning | info
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Files    int64    `json:"files"`
	Bytes    int64    `json:"bytes"`
	Sample   []string `json:"sample"`
}

type migWave struct {
	ID       int64    `json:"id"`
	Idx      int      `json:"idx"`
	Label    string   `json:"label"`
	Tops     []string `json:"tops"`
	Files    int64    `json:"files"`
	Bytes    int64    `json:"bytes"`
	Status   string   `json:"status"`
	Dry      bool     `json:"dry"`
	Started  int64    `json:"started"`
	Finished int64    `json:"finished"`
	Done     int64    `json:"done"`
	Copied   int64    `json:"copied"`
	Skipped  int64    `json:"skipped"`
	Conflict int64    `json:"conflicts"`
	Failed   int64    `json:"failed"`
	BytesOK  int64    `json:"bytes_done"`
	Message  string   `json:"message"`
}

type migPlan struct {
	Built      int64      `json:"built"`
	ScanAt     int64      `json:"scan_at"`
	Files      int64      `json:"files"`
	Bytes      int64      `json:"bytes"`
	EstSeconds int64      `json:"est_seconds"`
	Free       int64      `json:"free"`
	FreeNote   string     `json:"free_note"`
	Runner     string     `json:"runner"`
	Checks     []migCheck `json:"checks"`
	Blockers   int        `json:"blockers"`
}

type migration struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	SourceShare int64      `json:"source_share"`
	TargetDev   int64      `json:"target_device"`
	TargetRoot  string     `json:"target_root"`
	Options     migOptions `json:"options"`
	Plan        *migPlan   `json:"plan"`
	Created     int64      `json:"created"`
	Source      string     `json:"source"`
	Target      string     `json:"target"`
	Waves       []migWave  `json:"waves"`
}

func (a *App) migration(id int64) (migration, error) {
	var m migration
	var opts, plan string
	err := a.st.db.QueryRow(`SELECT id,name,source_share,target_device,target_root,options,COALESCE(plan,''),created FROM migrations WHERE id=?`, id).
		Scan(&m.ID, &m.Name, &m.SourceShare, &m.TargetDev, &m.TargetRoot, &opts, &plan, &m.Created)
	if err != nil {
		return m, errors.New("migration not found")
	}
	json.Unmarshal([]byte(opts), &m.Options)
	m.Options.defaults()
	if plan != "" {
		m.Plan = &migPlan{}
		json.Unmarshal([]byte(plan), m.Plan)
	}
	if s, err := a.share(m.SourceShare); err == nil {
		d, _ := a.device(s.DeviceID)
		m.Source = d.Name + " › " + s.Name
	} else {
		m.Source = "(share removed)"
	}
	if d, err := a.device(m.TargetDev); err == nil {
		m.Target = d.Name + " › " + m.TargetRoot
	}
	m.Waves = a.migWaves(id)
	return m, nil
}

func (a *App) migWaves(id int64) []migWave {
	out := []migWave{}
	rows, err := a.st.db.Query(`SELECT id,idx,label,tops,files,bytes,status,dry,started,finished,done,copied,skipped,conflicts,failed,bytes_done,message FROM migration_waves WHERE migration_id=? ORDER BY idx`, id)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var w migWave
		var tops string
		var dry int
		rows.Scan(&w.ID, &w.Idx, &w.Label, &tops, &w.Files, &w.Bytes, &w.Status, &dry, &w.Started, &w.Finished, &w.Done, &w.Copied, &w.Skipped, &w.Conflict, &w.Failed, &w.BytesOK, &w.Message)
		json.Unmarshal([]byte(tops), &w.Tops)
		w.Dry = dry == 1
		out = append(out, w)
	}
	return out
}

// targetIsWindowsLike: SMB names rules apply (Windows folders, UNC, PowerScale over SMB).
func targetIsWindowsLike(d Device, root string) bool {
	if d.Kind == "powerscale" {
		return true
	}
	return d.Kind == "windows" && !strings.HasPrefix(root, "/")
}

func sourceCaseSensitive(d Device, s Share) bool {
	return d.Kind == "s3" || (d.Kind == "windows" && strings.HasPrefix(s.Path, "/"))
}

func normDevPath(p string) string {
	return strings.TrimSuffix(strings.ToLower(strings.ReplaceAll(p, `\`, "/")), "/")
}

// runnerFor decides where the copy runs: on the collector next to the storage, or on
// the server. Empty runner + error means it cannot run anywhere.
func runnerFor(src, dst Device) (cid int64, label string, err error) {
	local := func(d Device) bool { return d.Kind == "windows" && d.CollectorID == 0 }
	switch {
	case src.CollectorID > 0 && dst.CollectorID > 0 && src.CollectorID != dst.CollectorID:
		return 0, "", errors.New("source and target sit behind different collectors; register both on the same collector")
	case src.CollectorID > 0 && local(dst):
		return 0, "", errors.New("the target is a folder on the Stratum server itself, which the source's collector cannot reach")
	case dst.CollectorID > 0 && local(src):
		return 0, "", errors.New("the source is a folder on the Stratum server itself, which the target's collector cannot reach")
	case src.CollectorID > 0:
		return src.CollectorID, "", nil
	case dst.CollectorID > 0:
		return dst.CollectorID, "", nil
	}
	return 0, "this server", nil
}

// buildPlan computes totals, checks and waves from the published index.
func (a *App) buildPlan(m migration) (*migPlan, []migWave, error) {
	s, err := a.share(m.SourceShare)
	if err != nil {
		return nil, nil, errors.New("the source share no longer exists")
	}
	if s.CurrentScan == 0 {
		return nil, nil, errors.New("the source share has no finished scan yet; scan it first")
	}
	src, _ := a.device(s.DeviceID)
	dst, err := a.device(m.TargetDev)
	if err != nil {
		return nil, nil, errors.New("the target device no longer exists")
	}
	o := m.Options
	o.defaults()
	t := a.tableFor(s.CurrentScan)
	p := &migPlan{Built: now(), Free: -1, Checks: []migCheck{}}
	a.st.db.QueryRow(`SELECT finished FROM scans WHERE id=?`, s.CurrentScan).Scan(&p.ScanAt)
	a.st.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size),0) FROM `+t+` WHERE scan_id=?`, s.CurrentScan).Scan(&p.Files, &p.Bytes)
	p.EstSeconds = int64(float64(p.Bytes)/(o.MBps*1e6) + float64(p.Files)/o.FilesPerS)
	add := func(c migCheck) {
		if c.Sample == nil {
			c.Sample = []string{}
		}
		p.Checks = append(p.Checks, c)
		if c.Severity == "blocker" {
			p.Blockers++
		}
	}
	sample := func(q string, args ...any) []string {
		var out []string
		rows, err := a.st.db.Query(q+` LIMIT 20`, args...)
		if err != nil {
			return out
		}
		defer rows.Close()
		for rows.Next() {
			var x string
			rows.Scan(&x)
			out = append(out, x)
		}
		return out
	}

	// Where it runs.
	cid, label, rerr := runnerFor(src, dst)
	if rerr != nil {
		add(migCheck{Key: "runner", Severity: "blocker", Title: "No machine can reach both sides", Detail: rerr.Error()})
	} else if cid > 0 {
		var name string
		a.st.db.QueryRow(`SELECT name FROM collectors WHERE id=?`, cid).Scan(&name)
		label = "collector " + name
	}
	p.Runner = label

	// Never copy into the source, or the source into its own copy.
	if src.ID == dst.ID {
		sp, tp := normDevPath(s.Path), normDevPath(m.TargetRoot)
		if tp == sp || strings.HasPrefix(tp, sp+"/") || strings.HasPrefix(sp, tp+"/") {
			add(migCheck{Key: "overlap", Severity: "blocker", Title: "Target overlaps the source", Detail: "The target folder is inside the source share (or the other way round). Pick a folder outside it."})
		}
	}

	if p.ScanAt > 0 && now()-p.ScanAt > 7*86400 {
		add(migCheck{Key: "stale", Severity: "warning", Title: "The index is more than a week old",
			Detail: "The plan reflects the share as it was at the last scan. Rescan it for exact numbers; the copy itself always reads the live files."})
	}

	cond := "scan_id IN (?,?)"
	var n int64
	a.st.db.QueryRow(`SELECT COUNT(*) FROM issues WHERE `+cond+` AND kind IN ('error','interrupted')`, s.CurrentScan, s.CurrentScan).Scan(&n)
	if n > 0 {
		add(migCheck{Key: "unreadable", Severity: "warning", Title: count(n, "folder could not be read", "folders could not be read"), Files: n,
			Detail: "The scan could not open them, so their files are not in the plan and will not be copied. Usually the copy account lacks read access.",
			Sample: sample(`SELECT path FROM issues WHERE scan_id=? AND kind IN ('error','interrupted') ORDER BY path`, s.CurrentScan)})
	}
	a.st.db.QueryRow(`SELECT COUNT(*) FROM issues WHERE scan_id=? AND kind='link'`, s.CurrentScan).Scan(&n)
	if n > 0 {
		add(migCheck{Key: "links", Severity: "info", Title: count(n, "link, junction or stub is not copied", "links, junctions and stubs are not copied"), Files: n,
			Detail: "Symbolic links, junctions and cloud or archive stubs are not followed. Recreate links at the target if you need them.",
			Sample: sample(`SELECT path FROM issues WHERE scan_id=? AND kind='link' ORDER BY path`, s.CurrentScan)})
	}

	if targetIsWindowsLike(dst, m.TargetRoot) {
		// Names Windows and SMB clients cannot use.
		if sourceCaseSensitive(src, s) {
			a.namesPass(s, t, add)
		} else {
			kinds := `'illegal','reserved','long_name'`
			if dst.Kind == "powerscale" {
				kinds = `'long_name'`
			}
			var nf int64
			a.st.db.QueryRow(`SELECT COUNT(*) FROM issues WHERE scan_id=? AND kind IN (`+kinds+`)`, s.CurrentScan).Scan(&nf)
			if nf > 0 {
				add(migCheck{Key: "names", Severity: "blocker", Title: count(nf, "name the target will refuse", "names the target will refuse"), Files: nf,
					Detail: "Reserved names (CON, AUX…), trailing dots or spaces, illegal characters or names over 255 characters. Rename them at the source before copying.",
					Sample: sample(`SELECT path FROM issues WHERE scan_id=? AND kind IN (`+kinds+`) ORDER BY path`, s.CurrentScan)})
			}
		}
		if dst.Kind == "windows" {
			limit := 260 - len(strings.TrimRight(m.TargetRoot, `\/`))
			var nl, bl int64
			a.st.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size),0) FROM `+t+` WHERE scan_id=? AND length(path) > ?`, s.CurrentScan, limit).Scan(&nl, &bl)
			if nl > 0 {
				add(migCheck{Key: "long_path", Severity: "warning", Title: count(nl, "file will have a path over 260 characters", "files will have paths over 260 characters"), Files: nl, Bytes: bl,
					Detail: fmt.Sprintf("Under %s these paths pass Windows' classic limit. Stratum copies them, but Explorer and many applications cannot open them. A shorter target folder helps.", m.TargetRoot),
					Sample: sample(`SELECT path FROM `+t+` WHERE scan_id=? AND length(path) > ? ORDER BY length(path) DESC`, s.CurrentScan, limit)})
			}
		}
	}
	if dst.Kind == "s3" {
		base := strings.Trim(m.TargetRoot, "/")
		_, prefix, _ := strings.Cut(base, "/")
		limit := 1024 - len(prefix)
		var nk, nb int64
		a.st.db.QueryRow(`SELECT COUNT(*) FROM `+t+` WHERE scan_id=? AND length(path) > ?`, s.CurrentScan, limit).Scan(&nk)
		if nk > 0 {
			add(migCheck{Key: "key_len", Severity: "blocker", Title: count(nk, "object key would pass 1024 bytes", "object keys would pass 1024 bytes"), Files: nk,
				Detail: "S3 limits keys to 1024 bytes. Shorten these paths or pick a shorter prefix.",
				Sample: sample(`SELECT path FROM `+t+` WHERE scan_id=? AND length(path) > ? ORDER BY length(path) DESC`, s.CurrentScan, limit)})
		}
		a.st.db.QueryRow(`SELECT COUNT(*) FROM `+t+` WHERE scan_id=? AND size > ?`, s.CurrentScan, int64(5)<<40).Scan(&nb)
		if nb > 0 {
			add(migCheck{Key: "huge", Severity: "blocker", Title: count(nb, "file is larger than 5 TB", "files are larger than 5 TB"), Files: nb, Detail: "S3 objects cannot exceed 5 TB."})
		}
	}

	// Capacity at the target.
	if rerr == nil {
		var free int64
		var note string
		if cid > 0 && dst.CollectorID > 0 {
			raw, err := a.runTask(cid, "mfree", map[string]any{"device": dst.wire(), "root": m.TargetRoot}, 45*time.Second)
			var r struct {
				Free int64  `json:"free"`
				Note string `json:"note"`
			}
			if err == nil && json.Unmarshal(raw, &r) == nil {
				free, note = r.Free, r.Note
			} else {
				free, note = -1, "the collector did not report free space"
				if err != nil {
					note = err.Error()
				}
			}
		} else if dst.Kind == "windows" && !isWindows && !strings.HasPrefix(m.TargetRoot, "/") {
			free, note = -1, "free space of a Windows target is only known through its collector"
		} else {
			free, note = freeSpace(dst, m.TargetRoot)
		}
		p.Free, p.FreeNote = free, note
		switch {
		case free >= 0 && free < p.Bytes:
			add(migCheck{Key: "capacity", Severity: "blocker", Title: "Not enough free space at the target",
				Detail: fmt.Sprintf("The share holds %s; the target has %s free.", fmtB(p.Bytes), fmtB(free))})
		case free >= 0 && float64(free) < float64(p.Bytes)*1.15:
			add(migCheck{Key: "capacity", Severity: "warning", Title: "Free space at the target is tight",
				Detail: fmt.Sprintf("The share holds %s; the target has %s free, under 15%% headroom.", fmtB(p.Bytes), fmtB(free))})
		}
	}

	// Waves: top-level folders packed in name order up to the wave size.
	type top struct {
		name         string
		files, bytes int64
	}
	var tops []top
	rows, err := a.st.db.Query(`SELECT CASE WHEN dir='/' THEN '' ELSE substr(path, 2, instr(substr(path, 2), '/') - 1) END AS t, COUNT(*), COALESCE(SUM(size),0)
	  FROM `+t+` WHERE scan_id=? GROUP BY t ORDER BY t`, s.CurrentScan)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var x top
		rows.Scan(&x.name, &x.files, &x.bytes)
		tops = append(tops, x)
	}
	rows.Close()
	limit := int64(o.WaveGB * 1e9)
	var waves []migWave
	var cur *migWave
	for _, x := range tops {
		if cur == nil || (cur.Bytes > 0 && cur.Bytes+x.bytes > limit) || cur.Files+x.files > 2_000_000 {
			waves = append(waves, migWave{Idx: len(waves) + 1})
			cur = &waves[len(waves)-1]
		}
		cur.Tops = append(cur.Tops, x.name)
		cur.Files += x.files
		cur.Bytes += x.bytes
	}
	for i := range waves {
		w := &waves[i]
		name := func(t string) string {
			if t == "" {
				return "(files in the share root)"
			}
			return t
		}
		if len(w.Tops) == 1 {
			w.Label = name(w.Tops[0])
		} else {
			w.Label = fmt.Sprintf("%s to %s (%d folders)", name(w.Tops[0]), name(w.Tops[len(w.Tops)-1]), len(w.Tops))
		}
	}
	return p, waves, nil
}

// namesPass checks every name of a case-sensitive source against Windows rules and
// finds paths that differ only by letter case.
func (a *App) namesPass(s Share, t string, add func(migCheck)) {
	rows, err := a.st.db.Query(`SELECT path, name FROM `+t+` WHERE scan_id=?`, s.CurrentScan)
	if err != nil {
		return
	}
	defer rows.Close()
	seen := map[string]string{}
	var bad, dupes []string
	var nb, nd int64
	for rows.Next() {
		var p, n string
		rows.Scan(&p, &n)
		for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
			if k, _ := hygiene(seg); k != "" {
				nb++
				if len(bad) < 20 {
					bad = append(bad, p)
				}
				break
			}
		}
		lp := strings.ToLower(p)
		if prev, ok := seen[lp]; ok {
			nd++
			if len(dupes) < 20 {
				dupes = append(dupes, prev+"  /  "+p)
			}
		} else {
			seen[lp] = p
		}
	}
	if nb > 0 {
		add(migCheck{Key: "names", Severity: "blocker", Title: count(nb, "path the target will refuse", "paths the target will refuse"), Files: nb,
			Detail: "Characters such as : * ? \" < > |, trailing dots or spaces, or reserved names are fine on the source but not on Windows or SMB. Rename them first.", Sample: bad})
	}
	if nd > 0 {
		add(migCheck{Key: "case", Severity: "blocker", Title: count(nd, "file differs from another only by letter case", "files differ from another only by letter case"), Files: nd,
			Detail: "The source tells Report.pdf and report.pdf apart; the target does not, so one would overwrite the other. Rename one of each pair.", Sample: dupes})
	}
}

func (a *App) savePlan(m migration) (migration, error) {
	p, waves, err := a.buildPlan(m)
	if err != nil {
		return m, err
	}
	b, _ := json.Marshal(p)
	a.st.db.Exec(`UPDATE migrations SET plan=? WHERE id=?`, string(b), m.ID)
	// Waves are rebuilt only while none has run; afterwards the plan refreshes the checks only.
	var ran int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM migration_waves WHERE migration_id=? AND status<>'pending'`, m.ID).Scan(&ran)
	if ran == 0 {
		a.st.db.Exec(`DELETE FROM migration_waves WHERE migration_id=?`, m.ID)
		for _, w := range waves {
			tb, _ := json.Marshal(w.Tops)
			a.st.db.Exec(`INSERT INTO migration_waves(migration_id,idx,label,tops,files,bytes,status) VALUES(?,?,?,?,?,?,'pending')`, m.ID, w.Idx, w.Label, string(tb), w.Files, w.Bytes)
		}
	}
	return a.migration(m.ID)
}

// count writes "1 file is" / "3 files are" style phrases.
func count(n int64, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmtN(n) + " " + many
}

// ---------- running a wave ----------

var migRunning sync.Map // wave id -> true

func (a *App) startWave(m migration, waveID int64, dry bool) error {
	if m.Plan == nil {
		return errors.New("build the plan first")
	}
	if m.Plan.Blockers > 0 && !dry {
		return fmt.Errorf("the plan has %d blocking problems; fix them and rebuild the plan, or run a dry run", m.Plan.Blockers)
	}
	var running int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM migration_waves WHERE migration_id=? AND status IN ('running','cancelling')`, m.ID).Scan(&running)
	if running > 0 {
		return errors.New("a wave of this migration is already running")
	}
	if _, loaded := migRunning.LoadOrStore(waveID, true); loaded {
		return errors.New("this wave is already running")
	}
	a.st.db.Exec(`UPDATE migration_waves SET status='running', dry=?, started=?, finished=0, done=0, copied=0, skipped=0, conflicts=0, failed=0, bytes_done=0, message='' WHERE id=?`,
		b2i(dry), now(), waveID)
	a.st.db.Exec(`DELETE FROM migration_ledger WHERE wave_id=?`, waveID)
	go func() {
		defer migRunning.Delete(waveID)
		a.runWave(m, waveID, dry)
	}()
	return nil
}

func (a *App) runWave(m migration, waveID int64, dry bool) {
	finish := func(status, msg string) {
		a.st.db.Exec(`UPDATE migration_waves SET status=?, finished=?, message=? WHERE id=?`, status, now(), msg, waveID)
	}
	var w migWave
	for _, x := range a.migWaves(m.ID) {
		if x.ID == waveID {
			w = x
		}
	}
	s, err1 := a.share(m.SourceShare)
	src, err2 := a.device(s.DeviceID)
	dst, err3 := a.device(m.TargetDev)
	if err1 != nil || err2 != nil || err3 != nil {
		finish("failed", "source or target no longer exists")
		return
	}
	cid, _, err := runnerFor(src, dst)
	if err != nil {
		finish("failed", err.Error())
		return
	}
	t := a.tableFor(s.CurrentScan)
	var rels []string
	var sizes []int64
	for _, top := range w.Tops {
		q, args := `SELECT path, size FROM `+t+` WHERE scan_id=? AND dir='/'`, []any{s.CurrentScan}
		if top != "" {
			q, args = `SELECT path, size FROM `+t+` WHERE scan_id=? AND path >= ? AND path < ?`, []any{s.CurrentScan, "/" + top + "/", "/" + top + "0"}
		}
		rows, err := a.st.db.Query(q+` ORDER BY path`, args...)
		if err != nil {
			finish("failed", err.Error())
			return
		}
		for rows.Next() {
			var p string
			var sz int64
			rows.Scan(&p, &sz)
			rels = append(rels, p)
			sizes = append(sizes, sz)
		}
		rows.Close()
	}
	opts := mOpts{Conflict: m.Options.Conflict, Verify: m.Options.Verify, Dry: dry}
	var done, copied, skipped, conflicts, failed, bytesOK int64
	var lastErr string
	for i := 0; i < len(rels); {
		var st string
		a.st.db.QueryRow(`SELECT status FROM migration_waves WHERE id=?`, waveID).Scan(&st)
		if st == "cancelling" {
			finish("cancelled", fmt.Sprintf("stopped after %d of %d files", done, len(rels)))
			return
		}
		// Chunks of at most 200 files or 4 GB.
		j, chunkBytes := i, int64(0)
		for j < len(rels) && j-i < 200 && (j == i || chunkBytes+sizes[j] <= 4<<30) {
			chunkBytes += sizes[j]
			j++
		}
		pl := mPayload{Src: src.wire(), SrcRoot: s.Path, Dst: dst.wire(), DstRoot: m.TargetRoot, Rels: rels[i:j], Opts: opts}
		var res []mResult
		if cid > 0 {
			raw, err := a.runTask(cid, "migrate", pl, 6*time.Hour)
			if err == nil {
				err = json.Unmarshal(raw, &res)
			}
			if err != nil {
				res = nil
				lastErr = err.Error()
			}
		} else {
			var err error
			if res, err = migrateBatch(pl); err != nil {
				lastErr = err.Error()
			}
		}
		if res == nil { // the whole chunk failed (unreachable side): record it and stop
			for _, r := range rels[i:j] {
				res = append(res, mResult{Rel: r, Result: "failed", Detail: lastErr})
			}
		}
		a.wmu.Lock()
		tx, err := a.st.db.Begin()
		if err == nil {
			ins, _ := tx.Prepare(`INSERT INTO migration_ledger(wave_id,ts,path,result,bytes,detail) VALUES(?,?,?,?,?,?)`)
			for _, r := range res {
				switch r.Result {
				case "copied", "would-copy", "would-overwrite":
					copied++
					bytesOK += r.Bytes
				case "skipped":
					skipped++
				case "conflict":
					conflicts++
				default:
					failed++
					lastErr = r.Detail
				}
				if r.Result != "skipped" {
					ins.Exec(waveID, now(), r.Rel, r.Result, r.Bytes, r.Detail)
				}
			}
			tx.Commit()
		}
		a.wmu.Unlock()
		done += int64(j - i)
		a.st.db.Exec(`UPDATE migration_waves SET done=?, copied=?, skipped=?, conflicts=?, failed=?, bytes_done=? WHERE id=?`, done, copied, skipped, conflicts, failed, bytesOK, waveID)
		i = j
		if failed == done && done >= 200 { // nothing works: do not grind through a million failures
			finish("failed", "every file failed so far: "+lastErr)
			return
		}
	}
	status := "done"
	msg := ""
	switch {
	case failed > 0:
		status, msg = "done with errors", fmt.Sprintf("%d files failed; see the list and run the wave again to retry them", failed)
	case conflicts > 0:
		msg = fmt.Sprintf("%d files were left alone because a different file is at the target", conflicts)
	}
	if dry {
		msg = strings.TrimSpace("Dry run: nothing was written. " + msg)
	}
	finish(status, msg)
	log.Printf("migration %q wave %d (dry=%v): %d files, %d copied, %d skipped, %d conflicts, %d failed", m.Name, w.Idx, dry, done, copied, skipped, conflicts, failed)
}

// ---------- API ----------

func (a *App) listMigrations(w http.ResponseWriter, r *http.Request) {
	out := []migration{}
	for _, id := range a.ids(`SELECT id FROM migrations ORDER BY id DESC`) {
		if m, err := a.migration(id); err == nil {
			out = append(out, m)
		}
	}
	writeJSON(w, out)
}

func (a *App) createMigration(w http.ResponseWriter, r *http.Request) {
	var in migration
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.TargetRoot = strings.TrimSpace(in.TargetRoot)
	if in.Name == "" || in.SourceShare == 0 || in.TargetDev == 0 || in.TargetRoot == "" {
		httpErr(w, 400, "name, source share, target device and target folder are required")
		return
	}
	if d, err := a.device(in.TargetDev); err == nil && d.Kind == "powerscale" && !strings.HasPrefix(in.TargetRoot, "/ifs") {
		httpErr(w, 400, "a PowerScale target is a path under /ifs")
		return
	}
	in.Options.defaults()
	ob, _ := json.Marshal(in.Options)
	res, err := a.st.db.Exec(`INSERT INTO migrations(name,source_share,target_device,target_root,options,created) VALUES(?,?,?,?,?,?)`,
		in.Name, in.SourceShare, in.TargetDev, in.TargetRoot, string(ob), now())
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	id, _ := res.LastInsertId()
	m, _ := a.migration(id)
	m, err = a.savePlan(m)
	if err != nil {
		writeJSON(w, map[string]any{"id": id, "plan_error": err.Error()})
		return
	}
	writeJSON(w, m)
}

func (a *App) getMigration(w http.ResponseWriter, r *http.Request) {
	m, err := a.migration(idOf(r))
	if err != nil {
		httpErr(w, 404, err.Error())
		return
	}
	writeJSON(w, m)
}

func (a *App) replanMigration(w http.ResponseWriter, r *http.Request) {
	m, err := a.migration(idOf(r))
	if err != nil {
		httpErr(w, 404, err.Error())
		return
	}
	var in struct {
		Options *migOptions `json:"options"`
	}
	readJSON(r, &in)
	if in.Options != nil {
		in.Options.defaults()
		ob, _ := json.Marshal(in.Options)
		a.st.db.Exec(`UPDATE migrations SET options=? WHERE id=?`, string(ob), m.ID)
		m.Options = *in.Options
	}
	if m, err = a.savePlan(m); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	writeJSON(w, m)
}

func (a *App) deleteMigration(w http.ResponseWriter, r *http.Request) {
	id := idOf(r)
	var running int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM migration_waves WHERE migration_id=? AND status IN ('running','cancelling')`, id).Scan(&running)
	if running > 0 {
		httpErr(w, 400, "stop the running wave first")
		return
	}
	a.st.db.Exec(`DELETE FROM migration_ledger WHERE wave_id IN (SELECT id FROM migration_waves WHERE migration_id=?)`, id)
	a.st.db.Exec(`DELETE FROM migration_waves WHERE migration_id=?`, id)
	a.st.db.Exec(`DELETE FROM migrations WHERE id=?`, id)
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) waveAction(w http.ResponseWriter, r *http.Request) {
	m, err := a.migration(idOf(r))
	if err != nil {
		httpErr(w, 404, err.Error())
		return
	}
	wid, _ := strconv.ParseInt(r.PathValue("wid"), 10, 64)
	found := false
	for _, x := range m.Waves {
		found = found || x.ID == wid
	}
	if !found {
		httpErr(w, 404, "wave not found")
		return
	}
	switch r.PathValue("action") {
	case "run", "dry-run":
		if err := a.startWave(m, wid, r.PathValue("action") == "dry-run"); err != nil {
			httpErr(w, 400, err.Error())
			return
		}
	case "cancel":
		a.st.db.Exec(`UPDATE migration_waves SET status='cancelling' WHERE id=? AND status='running'`, wid)
	default:
		httpErr(w, 404, "unknown action")
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) waveLedger(w http.ResponseWriter, r *http.Request) {
	wid, _ := strconv.ParseInt(r.PathValue("wid"), 10, 64)
	q := `SELECT ts, path, result, bytes, detail FROM migration_ledger WHERE wave_id=? AND wave_id IN (SELECT id FROM migration_waves WHERE migration_id=?)`
	args := []any{wid, idOf(r)}
	if res := r.URL.Query().Get("result"); res != "" {
		q += ` AND result=?`
		args = append(args, res)
	}
	rows, err := a.st.db.Query(q+` ORDER BY rowid LIMIT ?`, append(args, qInt(r, "limit", 500))...)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	if r.URL.Query().Get("format") == "csv" {
		cw := csvStart(w, "migration-wave-"+r.PathValue("wid")+".csv")
		cw.Write([]string{"time_utc", "path", "result", "bytes", "detail"})
		for rows.Next() {
			var t, b int64
			var p, res, d string
			rows.Scan(&t, &p, &res, &b, &d)
			cw.Write([]string{ts(t), p, res, strconv.FormatInt(b, 10), d})
		}
		cw.Flush()
		return
	}
	out := []map[string]any{}
	for rows.Next() {
		var t, b int64
		var p, res, d string
		rows.Scan(&t, &p, &res, &b, &d)
		out = append(out, map[string]any{"ts": t, "path": p, "result": res, "bytes": b, "detail": d})
	}
	writeJSON(w, out)
}

// mfreeExec answers a collector's "free space at this target" task.
func mfreeExec(d Device, root string) map[string]any {
	f, note := freeSpace(d, root)
	return map[string]any{"free": f, "note": note}
}
