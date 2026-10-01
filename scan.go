package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type DiscoveredShare struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Comment string `json:"comment,omitempty"`
	Zone    string `json:"zone,omitempty"`
}

type Device struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"` // windows | powerscale
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Secret      string `json:"-"`
	Insecure    bool   `json:"insecure"`
	CollectorID int64  `json:"collector_id"`
	Options     string `json:"options"` // JSON, e.g. S3 {"region":"us-east-1","path_style":true}
}

// deviceWire carries credentials to a collector (over the authenticated HTTPS channel only).
type deviceWire struct {
	Device
	Secret string `json:"secret"`
}

func (d Device) wire() deviceWire { return deviceWire{Device: d, Secret: d.Secret} }
func (w deviceWire) dev() Device  { d := w.Device; d.Secret = w.Secret; return d }

type Share struct {
	ID            int64  `json:"id"`
	DeviceID      int64  `json:"device_id"`
	Name          string `json:"name"`
	Path          string `json:"path"`
	ScheduleHours int    `json:"schedule_hours"`
	CurrentScan   int64  `json:"current_scan"`
	FailedScan    int64  `json:"failed_scan"`
	LastScanAt    int64  `json:"last_scan_at"`
	Options       string `json:"options"` // JSON, e.g. {"ads":true}
}

// opt reads a boolean option from a JSON options string.
func opt(options, key string) bool {
	var m map[string]any
	json.Unmarshal([]byte(options), &m)
	b, _ := m[key].(bool)
	return b
}

func optStr(options, key string) string {
	var m map[string]any
	json.Unmarshal([]byte(options), &m)
	s, _ := m[key].(string)
	return s
}

func (a *App) device(id int64) (Device, error) {
	var d Device
	var ins int
	err := a.st.db.QueryRow(`SELECT id,name,kind,host,port,username,secret,insecure,collector_id,COALESCE(options,'') FROM devices WHERE id=?`, id).
		Scan(&d.ID, &d.Name, &d.Kind, &d.Host, &d.Port, &d.Username, &d.Secret, &ins, &d.CollectorID, &d.Options)
	d.Insecure = ins == 1
	if d.Secret != "" {
		d.Secret, _ = a.unseal(d.Secret)
	}
	return d, err
}

func (a *App) share(id int64) (Share, error) {
	var s Share
	err := a.st.db.QueryRow(`SELECT id,device_id,name,path,schedule_hours,current_scan,failed_scan,last_scan_at,COALESCE(options,'') FROM shares WHERE id=?`, id).
		Scan(&s.ID, &s.DeviceID, &s.Name, &s.Path, &s.ScheduleHours, &s.CurrentScan, &s.FailedScan, &s.LastScanAt, &s.Options)
	return s, err
}

func (a *App) sharesOf(deviceID int64) []Share {
	rows, err := a.st.db.Query(`SELECT id FROM shares WHERE device_id=?`, deviceID)
	if err != nil {
		return nil
	}
	var ids []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	var out []Share
	for _, id := range ids {
		if s, err := a.share(id); err == nil {
			out = append(out, s)
		}
	}
	return out
}

func isLocalHost(h string) bool {
	h = strings.ToLower(strings.TrimSpace(h))
	return h == "" || h == "localhost" || h == "." || h == "127.0.0.1"
}

func psClientFor(d Device) *psClient {
	return newPSClient(d.Host, d.Port, d.Username, d.Secret, d.Insecure)
}

func (a *App) psClientFor(d Device) *psClient { return psClientFor(d) }

func listerFor(d Device, s Share) (Lister, error) {
	switch d.Kind {
	case "windows":
		if strings.HasPrefix(s.Path, `\\`) {
			if err := connectSMB(s.Path, d.Username, d.Secret); err != nil {
				return nil, err
			}
		}
		return newLocalLister(s.Path, opt(s.Options, "ads")), nil
	case "powerscale":
		return &psLister{c: psClientFor(d), root: s.Path}, nil
	case "s3":
		return newS3Lister(d, s.Path)
	}
	return nil, fmt.Errorf("unknown device kind %q", d.Kind)
}

// discoverDevice lists the shares a device publishes. Runs wherever the storage is reachable.
func discoverDevice(d Device) ([]DiscoveredShare, error) {
	switch d.Kind {
	case "powerscale":
		return psClientFor(d).psShares()
	case "windows":
		if isLocalHost(d.Host) {
			out := localDrives()
			if sh, e := enumWindowsShares("localhost"); e == nil {
				out = append(out, sh...)
			}
			return out, nil
		}
		if d.Username != "" {
			_ = connectSMB(`\\`+strings.TrimPrefix(d.Host, `\\`)+`\IPC$`, d.Username, d.Secret) // best effort; discovery reports the real error
		}
		return enumWindowsShares(d.Host)
	case "s3":
		c, err := newS3Client(d)
		if err != nil {
			return nil, err
		}
		return c.buckets()
	}
	return nil, fmt.Errorf("unknown device kind %q", d.Kind)
}

// collectInventory gathers hardware/capacity facts. Runs wherever the storage is reachable.
func collectInventory(d Device, shares []Share) map[string]any {
	switch d.Kind {
	case "powerscale":
		inv, err := psClientFor(d).psInventory()
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		return inv
	case "windows":
		var inv map[string]any
		if isLocalHost(d.Host) {
			inv = hostInventory()
		} else {
			inv = map[string]any{"hostname": d.Host}
		}
		var vols []map[string]any
		var rawTotal, used uint64
		for _, s := range shares {
			if t, f, err := diskSpace(s.Path); err == nil {
				vols = append(vols, map[string]any{"share": s.Name, "total": t, "free": f})
				rawTotal += t
				used += t - f
			}
		}
		inv["volumes"] = vols
		inv["raw_bytes"] = rawTotal
		inv["used_bytes"] = used
		inv["model"] = "Windows file server"
		if !isWindows {
			inv["model"] = "Linux server"
		}
		return inv
	case "s3":
		return s3Inventory(d)
	}
	return map[string]any{"error": "unknown device kind"}
}

// clientPathLen is the length a Windows/SMB client would see for this entry.
func clientPathLen(d Device, s Share, rel string) int {
	if d.Kind == "powerscale" {
		return len(`\\`+d.Host+`\`+s.Name) + len(rel)
	}
	return len(strings.TrimRight(s.Path, `\/`)) + len(rel)
}

// ---- running scan state ----

type scanProgress struct {
	ScanID      int64  `json:"scan_id"`
	ShareID     int64  `json:"share_id"`
	Share       string `json:"share"`
	Device      string `json:"device"`
	Started     int64  `json:"started"`
	Files       int64  `json:"files"`
	Dirs        int64  `json:"dirs"`
	Bytes       int64  `json:"bytes"`
	Errors      int64  `json:"errors"`
	Current     string `json:"current"`
	PrevFiles   int64  `json:"prev_files"` // files in the last published index, for a % estimate
	Remote      bool   `json:"remote"`
	Collector   string `json:"collector,omitempty"`
	Claimed     bool   `json:"claimed"` // remote: a collector picked the job up
	Updated     int64  `json:"updated"`
	Cancel      bool   `json:"cancel_requested"`
	Publishing  bool   `json:"publishing"` // walk finished; indexes and reports are being built
	finishing   *atomic.Bool
	Attempt     int64 `json:"attempt"`
	CollectorID int64 `json:"-"`
	mu          *sync.Mutex
	cancel      context.CancelFunc
}

func (p *scanProgress) setCurrent(s string) {
	p.mu.Lock()
	p.Current = s
	p.Updated = now()
	p.mu.Unlock()
}

func (p *scanProgress) snapshot() scanProgress {
	p.mu.Lock()
	defer p.mu.Unlock()
	cp := *p
	cp.Files, cp.Dirs = atomic.LoadInt64(&p.Files), atomic.LoadInt64(&p.Dirs)
	cp.Bytes, cp.Errors = atomic.LoadInt64(&p.Bytes), atomic.LoadInt64(&p.Errors)
	cp.Publishing = p.finishing != nil && p.finishing.Load()
	return cp
}

type row struct {
	kind string // f d i
	vals []any
}

type scanJob struct {
	ctx    context.Context
	dev    Device
	share  Share
	scanID int64
	l      Lister
	out    chan<- row
	sem    chan struct{}
	p      *scanProgress
	interr atomic.Int64
	rootOK atomic.Bool
	done   map[string][2]int64
	excl   *excluder
	pl     permsLister // nil when folder permissions are not collected
	fps    sync.Map    // folder -> permissions fingerprint, to spot changes from the parent
}

var reservedNames = map[string]bool{"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true}

// hygiene returns path-hygiene findings for one name: things that break Windows
// clients, backup agents or migrations even though the entry itself was indexed.
func hygiene(name string) (kind, detail string) {
	if len(name) > 255 {
		return "long_name", fmt.Sprintf("name is %d chars (limit 255)", len(name))
	}
	for _, r := range name {
		if r < 32 || strings.ContainsRune(`<>:"|?*\`, r) {
			return "illegal", fmt.Sprintf("illegal character %q", r)
		}
	}
	if strings.HasSuffix(name, " ") || strings.HasSuffix(name, ".") {
		return "illegal", "trailing space or dot"
	}
	stem := strings.ToUpper(name)
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	if reservedNames[stem] {
		return "reserved", "reserved device name " + stem
	}
	return "", ""
}

func classifyErr(err error) string {
	if errors.Is(err, fs.ErrPermission) {
		return "error"
	}
	s := strings.ToLower(err.Error())
	for _, k := range []string{"network", "timeout", "connection", "eof", "reset", "semaphore", "unreachable", "no route", "broken pipe", "i/o timeout"} {
		if strings.Contains(s, k) {
			return "interrupted"
		}
	}
	return "error"
}

func (j *scanJob) issue(rel, kind, detail string, ln int) {
	j.out <- row{"i", []any{j.scanID, j.share.ID, rel, kind, detail, ln, now()}}
}

func (j *scanJob) walk(rel string, depth int) (files, bytes int64) {
	if j.ctx.Err() != nil {
		return
	}
	// Resume: a folder finished before the interruption keeps its recorded totals.
	if t, ok := j.done[rel]; ok {
		if rel == "/" {
			j.rootOK.Store(true)
		}
		return t[0], t[1]
	}
	j.p.setCurrent(rel)
	ents, err := j.l.List(rel)
	if err != nil {
		k := classifyErr(err)
		if k == "interrupted" {
			j.interr.Add(1)
		}
		atomic.AddInt64(&j.p.Errors, 1)
		j.issue(rel, k, err.Error(), 0)
		if len(ents) == 0 {
			return
		}
	}
	if rel == "/" {
		j.rootOK.Store(true)
	}
	owner := ""
	if j.pl != nil {
		if dp, err := j.pl.DirPerms(rel); err == nil {
			owner = dp.Owner
			j.permsRow(rel, dp)
		}
	}
	if owner == "" {
		owner = j.l.DirOwner(rel)
	}
	object := j.dev.Kind == "s3"
	myLen := clientPathLen(j.dev, j.share, rel)
	var ownFiles, ownBytes int64
	var subdirs []string
	for _, e := range ents {
		child := path.Join(rel, e.Name)
		if j.excl.match(child, e.Name) {
			continue // excluded by the share's rules: not indexed, not reported
		}
		ln := 0
		if !object { // object keys are not name-checked; Windows rules do not apply
			ln = clientPathLen(j.dev, j.share, child)
			if k, d := hygiene(e.Name); k != "" {
				j.issue(child, k, d, ln)
			}
			if ln > 260 && myLen <= 260 {
				j.issue(child, "long_path", fmt.Sprintf("path is %d chars (Windows MAX_PATH 260)", ln), ln)
			}
		}
		if e.Link != "" {
			j.issue(child, "link", e.Link+" not followed", ln)
			continue
		}
		if e.Flags&flagStub != 0 {
			j.issue(child, "link", "offline or cloud stub, indexed at its logical size", ln)
		}
		if e.IsDir {
			subdirs = append(subdirs, child)
			continue
		}
		fo := owner
		if e.Owner != "" {
			fo = e.Owner
		}
		j.out <- row{"f", []any{j.scanID, child, rel, e.Name, extOf(e.Name), e.Size, e.Mtime, e.Atime, e.Ctime, fo, e.Flags, e.ETag}}
		for _, st := range e.Streams {
			j.out <- row{"a", []any{j.scanID, j.share.ID, child, st.Name, st.Size, adsClass(st.Name, st.Size), fo}}
		}
		ownFiles++
		if e.Flags&flagHardlinkDup == 0 {
			ownBytes += e.Size
		}
	}
	atomic.AddInt64(&j.p.Files, ownFiles)
	atomic.AddInt64(&j.p.Bytes, ownBytes)
	atomic.AddInt64(&j.p.Dirs, 1)
	files, bytes = ownFiles, ownBytes

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, sd := range subdirs {
		select {
		case j.sem <- struct{}{}: // spare worker: go wide
			wg.Add(1)
			go func(sd string) {
				defer func() { <-j.sem; wg.Done() }()
				f, b := j.walk(sd, depth+1)
				mu.Lock()
				files, bytes = files+f, bytes+b
				mu.Unlock()
			}(sd)
		default: // all busy: go deep inline, never blocks
			f, b := j.walk(sd, depth+1)
			mu.Lock()
			files, bytes = files+f, bytes+b
			mu.Unlock()
		}
	}
	wg.Wait()
	if j.ctx.Err() != nil {
		return // an incomplete folder must not be recorded as done
	}
	j.out <- row{"d", []any{j.scanID, rel, depth, owner, files, bytes, ownFiles, ownBytes}}
	return
}

// walkShare runs one metadata walk, emitting rows to out. The caller closes out.
// done holds folders completed by an earlier, interrupted attempt of the same scan.

type scanResult struct {
	Cancelled   bool   `json:"cancelled"`
	WriteErr    string `json:"write_err"`
	RootOK      bool   `json:"root_ok"`
	Interrupted int64  `json:"interrupted"`
	Files       int64  `json:"files"`
	Dirs        int64  `json:"dirs"`
	Bytes       int64  `json:"bytes"`
	Errors      int64  `json:"errors"`
}

// walkShare runs one metadata walk, emitting rows to out. The caller closes out.
func walkShare(ctx context.Context, d Device, s Share, scanID int64, l Lister, p *scanProgress, out chan<- row, done map[string][2]int64) (rootOK bool, interrupted int64) {
	par := l.Parallelism()
	j := &scanJob{ctx: ctx, dev: d, share: s, scanID: scanID, l: l, out: out, sem: make(chan struct{}, par-1), p: p, done: done, excl: newExcluder(s.Options)}
	if pl, ok := l.(permsLister); ok && permsOn(s) {
		j.pl = pl
	}
	j.walk("/", 0)
	return j.rootOK.Load(), j.interr.Load()
}

var insertSQL = map[string]string{
	"f": "", // per-scan table, see insertRows
	"a": `INSERT INTO ads(scan_id,share_id,path,stream,size,class,owner) VALUES(?,?,?,?,?,?,?)`,
	"d": `INSERT INTO dirs(scan_id,path,depth,owner,files,bytes,own_files,own_bytes) VALUES(?,?,?,?,?,?,?,?)`,
	"i": `INSERT INTO issues(scan_id,share_id,path,kind,detail,len,detected) VALUES(?,?,?,?,?,?,?)`,
	"p": `INSERT INTO perms(scan_id,share_id,path,owner,protected,aces,open,orphan,deny) VALUES(?,?,?,?,?,?,?,?,?)`,
}

// writer batches rows into SQLite transactions.
func (a *App) writer(in <-chan row, done chan<- error) {
	const batch = 20000
	buf := make([]row, 0, batch)
	var firstErr error
	for r := range in {
		if firstErr != nil {
			continue // drain
		}
		buf = append(buf, r)
		if len(buf) >= batch {
			firstErr = a.insertRows(buf)
			buf = buf[:0]
		}
	}
	if firstErr == nil && len(buf) > 0 {
		firstErr = a.insertRows(buf)
	}
	done <- firstErr
}

func (a *App) insertRows(rows []row) error {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	tx, err := a.st.db.Begin()
	if err != nil {
		return err
	}
	stmts := map[string]*sql.Stmt{}
	stmt := func(r row) (*sql.Stmt, error) {
		q, key := insertSQL[r.kind], r.kind
		if r.kind == "f" {
			// File rows go to the scan's own table.
			id, _ := r.vals[0].(int64)
			key = "f" + strconv.FormatInt(id, 10)
			q = `INSERT INTO ` + a.tableFor(id) + `(` + colList + `) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`
		}
		if s := stmts[key]; s != nil {
			return s, nil
		}
		if q == "" {
			return nil, nil
		}
		s, err := tx.Prepare(q)
		stmts[key] = s
		return s, err
	}
	for _, r := range rows {
		st, err := stmt(r)
		if err != nil {
			tx.Rollback()
			return err
		}
		if st == nil {
			continue
		}
		if r.kind == "f" && len(r.vals) == 11 {
			r.vals = append(r.vals, "") // rows from older collectors carry no etag
		}
		if _, err := st.Exec(r.vals...); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func newProgress(scanID int64, s Share, d Device) *scanProgress {
	return &scanProgress{ScanID: scanID, ShareID: s.ID, Share: s.Name, Device: d.Name, Started: now(), Updated: now(), mu: &sync.Mutex{}, finishing: &atomic.Bool{}}
}

func (a *App) startScan(shareID int64) (int64, error) {
	s, err := a.share(shareID)
	if err != nil {
		return 0, fmt.Errorf("share %d not found", shareID)
	}
	d, err := a.device(s.DeviceID)
	if err != nil {
		return 0, err
	}
	a.mu.Lock()
	for _, p := range a.running {
		if p.ShareID == shareID {
			a.mu.Unlock()
			return p.ScanID, fmt.Errorf("a scan of %s is already running", s.Name)
		}
	}
	a.mu.Unlock()
	res, err := a.st.db.Exec(`INSERT INTO scans(share_id,started,status) VALUES(?,?,'running')`, shareID, now())
	if err != nil {
		return 0, err
	}
	scanID, _ := res.LastInsertId()
	p := newProgress(scanID, s, d)
	a.st.db.QueryRow(`SELECT files FROM scans WHERE id=?`, s.CurrentScan).Scan(&p.PrevFiles)
	a.mu.Lock()
	a.running[scanID] = p
	a.mu.Unlock()

	a.createScanTable(scanID)
	if d.CollectorID > 0 {
		a.queueRemoteScan(p, d, s, nil)
		return scanID, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go a.runScanResume(ctx, d, s, scanID, p, nil)
	go a.refreshInventory(d.ID)
	return scanID, nil
}

// finishScan decides whether a finished walk becomes the share's published index.
// Only a clean walk replaces the previous index; anything else keeps it.
func (a *App) finishScan(shareID, scanID int64, p *scanProgress, r scanResult) {
	if p != nil && p.finishing != nil && !p.finishing.CompareAndSwap(false, true) {
		log.Printf("scan %d: already finishing, second finish ignored", scanID)
		return
	}
	defer func() {
		a.mu.Lock()
		delete(a.running, scanID)
		a.mu.Unlock()
	}()
	s, err := a.share(shareID)
	if err != nil {
		return
	}
	msg := ""
	switch {
	case r.Cancelled:
		msg = "scan cancelled"
	case r.WriteErr != "":
		msg = r.WriteErr
	case !r.RootOK:
		msg = "share root could not be read"
	case r.Interrupted > 0:
		msg = fmt.Sprintf("%d folders interrupted (connection dropped), index incomplete", r.Interrupted)
	}
	if msg != "" && s.CurrentScan == scanID {
		// Never fail (and purge) a scan that is already the share's live index.
		log.Printf("scan %d (%s): %s, but it is already the published index; kept", scanID, s.Name, msg)
		return
	}
	if msg != "" {
		log.Printf("scan %d (%s) not published: %s", scanID, s.Name, msg)
		a.wmu.Lock()
		if s.FailedScan > 0 && s.FailedScan != scanID {
			a.st.db.Exec(`DELETE FROM issues WHERE scan_id=?`, s.FailedScan)
		}
		a.st.db.Exec(`INSERT INTO issues(scan_id,share_id,path,kind,detail,len,detected) VALUES(?,?,'/','not_published',?,0,?)`,
			scanID, s.ID, msg+"; share kept its previous index", now())
		a.st.db.Exec(`UPDATE shares SET failed_scan=? WHERE id=?`, scanID, s.ID)
		a.st.db.Exec(`UPDATE scans SET finished=?,status='failed',files=?,dirs=?,bytes=?,errors=?,message=? WHERE id=?`,
			now(), r.Files, r.Dirs, r.Bytes, r.Errors, msg, scanID)
		a.wmu.Unlock()
		a.purgeScan(scanID, false)
		return
	}
	// A resumed attempt only counts what it walked itself; the share totals live in the
	// root folder's row, which covers every attempt.
	a.scanTotals(scanID, &r)
	// Publish: a quick swap under the write lock, then the aggregates.
	a.wmu.Lock()
	a.st.db.Exec(`UPDATE shares SET current_scan=?, failed_scan=0, last_scan_at=? WHERE id=?`, scanID, now(), s.ID)
	a.st.db.Exec(`INSERT INTO history(share_id,ts,files,bytes) VALUES(?,?,?,?)`, s.ID, now(), r.Files, r.Bytes)
	a.indexScanTable(scanID)
	a.snapshotDirs(s.ID, scanID)
	a.buildAggregates(scanID)
	a.st.db.Exec(`UPDATE scans SET finished=?,status='done',files=?,dirs=?,bytes=?,errors=? WHERE id=?`,
		now(), r.Files, r.Dirs, r.Bytes, r.Errors, scanID)
	a.wmu.Unlock()
	started := int64(0)
	if p != nil {
		started = p.Started
	}
	log.Printf("scan %d (%s) published: %d files, %d dirs, %d bytes, %d errors in %s", scanID, s.Name,
		r.Files, r.Dirs, r.Bytes, r.Errors, time.Since(time.Unix(started, 0)).Round(time.Second))
	a.applyTagRules(s.ID)
	// The replaced index goes last, in small chunks, so running scans keep writing.
	for _, old := range []int64{s.CurrentScan, s.FailedScan} {
		if old > 0 && old != scanID {
			a.purgeScan(old, true)
		}
	}
}

// purgeScan deletes one scan's rows in chunks, releasing the write lock between
// chunks so other scans are never stalled behind a multi-million-row delete.

func (a *App) snapshotDirs(shareID, scanID int64) {
	a.copyRows(`INSERT INTO dir_history(share_id,scan_id,ts,path,depth,bytes,files) VALUES(?,?,?,?,?,?,?)`,
		`SELECT ?,?,?,path,depth,bytes,files FROM dirs WHERE scan_id=? AND depth<=3`, shareID, scanID, now(), scanID)
	a.st.db.Exec(`DELETE FROM dir_history WHERE share_id=? AND scan_id NOT IN (SELECT DISTINCT scan_id FROM dir_history WHERE share_id=? ORDER BY scan_id DESC LIMIT 30)`, shareID, shareID)
}

func (a *App) refreshInventory(deviceID int64) {
	d, err := a.device(deviceID)
	if err != nil {
		return
	}
	var inv map[string]any
	if d.CollectorID > 0 {
		raw, err := a.runTask(d.CollectorID, "inventory", map[string]any{"device": d.wire(), "shares": a.sharesOf(d.ID)}, 60*time.Second)
		if err != nil {
			inv = map[string]any{"error": err.Error()}
		} else {
			json.Unmarshal(raw, &inv)
		}
	} else {
		inv = collectInventory(d, a.sharesOf(d.ID))
	}
	b, _ := json.Marshal(inv)
	a.st.db.Exec(`UPDATE devices SET inventory=?, inventory_at=? WHERE id=?`, string(b), now(), d.ID)
}

// scheduler kicks off due scans, scheduled automations, daily inventory and watchdogs.
func (a *App) scheduler() {
	t := time.NewTicker(time.Minute)
	for range t.C {
		for _, id := range a.ids(`SELECT id FROM shares WHERE schedule_hours>0 AND COALESCE((SELECT MAX(started) FROM scans WHERE share_id=shares.id), 0) + schedule_hours*3600 <= ?`, now()) {
			a.startScan(id)
		}
		for _, id := range a.ids(`SELECT id FROM devices WHERE inventory_at < ?`, now()-86400) {
			go a.refreshInventory(id)
		}
		a.runScheduledAutomations()
		a.remoteWatchdog()
		a.flushCollectorSeen()
		if a.ldapConfig().URL != "" {
			var last int64
			fmt.Sscan(a.st.setting("ldap_last_sync"), &last)
			if now()-last > 86400 {
				a.st.setSetting("ldap_last_sync", fmt.Sprint(now()))
				go a.syncDirectory()
			}
		}
	}
}

func (a *App) ids(q string, args ...any) []int64 {
	rows, err := a.st.db.Query(q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		out = append(out, id)
	}
	return out
}

// remoteWatchdog fails collector scans that stopped reporting, so the share can be rescanned.
func (a *App) remoteWatchdog() {
	a.mu.Lock()
	var stale []*scanProgress
	for _, p := range a.running {
		snap := p.snapshot()
		if !snap.Remote || snap.Publishing {
			continue // publishing runs on the server: the collector has nothing left to report
		}
		if (snap.Claimed && now()-snap.Updated > 600) || (!snap.Claimed && now()-snap.Started > 6*3600) {
			stale = append(stale, p)
		}
	}
	a.mu.Unlock()
	for _, p := range stale {
		msg := "collector stopped reporting"
		if !p.Claimed {
			msg = "no collector picked the scan up within 6 hours"
		}
		a.st.db.Exec(`UPDATE tasks SET status='expired' WHERE kind='scan' AND status IN ('pending','claimed') AND json_extract(payload,'$.scan_id')=?`, p.ScanID)
		a.finishScan(p.ShareID, p.ScanID, p, scanResult{WriteErr: msg})
	}
}

// extOf is the lower-case extension of a file name or path, as stored in files.ext.
func extOf(name string) string {
	name = path.Base(name)
	if i := strings.LastIndexByte(name, '.'); i > 0 && i < len(name)-1 {
		return strings.ToLower(name[i+1:])
	}
	return ""
}

func (a *App) purgeScan(scanID int64, withIssues bool) {
	if withIssues {
		a.wmu.Lock()
		a.dropAggregates(scanID)
		a.wmu.Unlock()
		a.chunkDelete("issues", scanID)
	}
	a.dropScanFiles(scanID)
	a.chunkDelete("dirs", scanID)
	a.chunkDelete("ads", scanID)
	a.chunkDelete("perms", scanID)
}

// scanTotals raises a result's counts to what the scan's folder rows record.
func (a *App) scanTotals(scanID int64, r *scanResult) {
	var files, bytes, dirs int64
	a.st.db.QueryRow(`SELECT files, bytes FROM dirs WHERE scan_id=? AND path='/'`, scanID).Scan(&files, &bytes)
	a.st.db.QueryRow(`SELECT COUNT(*) FROM dirs WHERE scan_id=?`, scanID).Scan(&dirs)
	r.Files, r.Bytes, r.Dirs = max(r.Files, files), max(r.Bytes, bytes), max(r.Dirs, dirs)
}

// repairScanTotals fixes published scans recorded with zero files by a resumed
// attempt before scanTotals existed.
func (a *App) repairScanTotals() {
	for _, id := range a.ids(`SELECT id FROM scans WHERE status='done' AND files=0 AND id IN (SELECT current_scan FROM shares)`) {
		var r scanResult
		a.scanTotals(id, &r)
		if r.Files > 0 {
			a.st.db.Exec(`UPDATE scans SET files=?, dirs=?, bytes=? WHERE id=?`, r.Files, r.Dirs, r.Bytes, id)
			log.Printf("scan %d: totals repaired to %d files", id, r.Files)
		}
	}
}
