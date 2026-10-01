package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path"
	"strconv"
	"time"
)

// Crash-resume. A folder's dirs row is written only after its whole subtree is done
// (the walk is bottom-up), so the dirs rows of an interrupted scan are an exact list
// of finished folders. Resuming drops the rows of unfinished folders and walks again,
// skipping every finished folder with its recorded totals.

type resumeState struct {
	Done                       map[string][2]int64
	Files, Dirs, Bytes, Errors int64
}

// prepareResume cleans partial rows of an interrupted scan and returns what is done.
func (a *App) prepareResume(scanID int64) (*resumeState, error) {
	t := a.tableFor(scanID)
	if t == "files_legacy" {
		return nil, fmt.Errorf("scan %d predates resumable scans", scanID)
	}
	st := &resumeState{Done: map[string][2]int64{}}
	rows, err := a.st.db.Query(`SELECT path, files, bytes FROM dirs WHERE scan_id=?`, scanID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p string
		var f, b int64
		rows.Scan(&p, &f, &b)
		st.Done[p] = [2]int64{f, b}
	}
	rows.Close()

	a.wmu.Lock()
	defer a.wmu.Unlock()
	// Files listed by folders that never finished would be written twice.
	a.st.db.Exec(`DELETE FROM `+t+` WHERE dir NOT IN (SELECT path FROM dirs WHERE scan_id=?)`, scanID)
	a.st.db.Exec(`DELETE FROM ads WHERE scan_id=? AND path NOT IN (SELECT path FROM `+t+`)`, scanID)
	irows, _ := a.st.db.Query(`SELECT rowid, path, kind FROM issues WHERE scan_id=?`, scanID)
	var drop []int64
	for irows != nil && irows.Next() {
		var id int64
		var p, k string
		irows.Scan(&id, &p, &k)
		if _, ok := st.Done[path.Dir(p)]; !ok || k == "error" || k == "interrupted" || k == "not_published" {
			drop = append(drop, id)
		}
	}
	if irows != nil {
		irows.Close()
	}
	for _, id := range drop {
		a.st.db.Exec(`DELETE FROM issues WHERE rowid=?`, id)
	}
	a.st.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN flags & 4 = 0 THEN size ELSE 0 END),0) FROM `+t).Scan(&st.Files, &st.Bytes)
	st.Dirs = int64(len(st.Done))
	return st, nil
}

// resumeInterrupted picks up scans that were running when the service stopped.
func (a *App) resumeInterrupted() {
	for _, scanID := range a.ids(`SELECT id FROM scans WHERE status='running'`) {
		var shareID int64
		a.st.db.QueryRow(`SELECT share_id FROM scans WHERE id=?`, scanID).Scan(&shareID)
		if err := a.resumeScan(scanID, shareID); err != nil {
			log.Printf("scan %d cannot resume: %v", scanID, err)
			a.st.db.Exec(`UPDATE scans SET status='failed', message=?, finished=? WHERE id=?`, "service restarted mid-scan; "+err.Error(), now(), scanID)
			a.dropScanFiles(scanID)
			a.chunkDelete("dirs", scanID)
		}
	}
}

func (a *App) resumeScan(scanID, shareID int64) error {
	s, err := a.share(shareID)
	if err != nil {
		return fmt.Errorf("share removed")
	}
	d, err := a.device(s.DeviceID)
	if err != nil {
		return fmt.Errorf("device removed")
	}
	st, err := a.prepareResume(scanID)
	if err != nil {
		return err
	}
	p := newProgress(scanID, s, d)
	p.Files, p.Dirs, p.Bytes = st.Files, st.Dirs, st.Bytes
	a.st.db.QueryRow(`SELECT started FROM scans WHERE id=?`, scanID).Scan(&p.Started)
	a.st.db.QueryRow(`SELECT files FROM scans WHERE id=?`, s.CurrentScan).Scan(&p.PrevFiles)
	a.mu.Lock()
	a.running[scanID] = p
	a.mu.Unlock()
	log.Printf("scan %d (%s) resuming: %d folders and %d files already done", scanID, s.Name, st.Dirs, st.Files)
	if d.CollectorID > 0 {
		a.queueRemoteScan(p, d, s, st.Done)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go a.runScanResume(ctx, d, s, scanID, p, st.Done)
	return nil
}

// queueRemoteScan hands a (possibly resumed) scan to the device's collector. Each
// hand-off gets a new attempt number so rows from an abandoned attempt are refused.
func (a *App) queueRemoteScan(p *scanProgress, d Device, s Share, done map[string][2]int64) {
	p.mu.Lock()
	p.Remote, p.Claimed, p.CollectorID = true, false, d.CollectorID
	p.Attempt++
	attempt := p.Attempt
	p.mu.Unlock()
	a.st.db.QueryRow(`SELECT name FROM collectors WHERE id=?`, d.CollectorID).Scan(&p.Collector)
	a.st.db.Exec(`UPDATE tasks SET status='expired' WHERE kind='scan' AND status IN ('pending','claimed') AND json_extract(payload,'$.scan_id')=?`, p.ScanID)
	payload, _ := json.Marshal(map[string]any{"scan_id": p.ScanID, "attempt": attempt, "device": d.wire(), "share": s, "done": done})
	a.st.db.Exec(`INSERT INTO tasks(collector_id,kind,payload,status,created) VALUES(?,'scan',?,'pending',?)`, d.CollectorID, string(payload), now())
}

// requeueLostRemote resumes remote scans whose collector restarted and forgot them.
func (a *App) requeueLostRemote(cid int64, runningOnCollector map[int64]bool) {
	a.mu.Lock()
	var lost []*scanProgress
	for _, p := range a.running {
		p.mu.Lock()
		stale := p.Remote && p.CollectorID == cid && p.Claimed && !runningOnCollector[p.ScanID] && now()-p.Updated > 30 && !p.Cancel
		p.mu.Unlock()
		if stale {
			lost = append(lost, p)
		}
	}
	a.mu.Unlock()
	for _, p := range lost {
		var status string
		a.st.db.QueryRow(`SELECT status FROM scans WHERE id=?`, p.ScanID).Scan(&status)
		if status != "running" || (p.finishing != nil && p.finishing.Load()) {
			continue // already publishing or finished
		}
		s, err1 := a.share(p.ShareID)
		d, err2 := a.device(s.DeviceID)
		if err1 != nil || err2 != nil {
			continue
		}
		st, err := a.prepareResume(p.ScanID)
		if err != nil {
			continue
		}
		p.mu.Lock()
		p.Files, p.Dirs, p.Bytes = st.Files, st.Dirs, st.Bytes
		p.Updated = now()
		p.mu.Unlock()
		log.Printf("scan %d: collector restarted, resuming with %d folders done", p.ScanID, st.Dirs)
		a.queueRemoteScan(p, d, s, st.Done)
	}
}

func (a *App) runScanResume(ctx context.Context, d Device, s Share, scanID int64, p *scanProgress, done map[string][2]int64) {
	l, err := listerFor(d, s)
	if err != nil {
		a.finishScan(s.ID, scanID, p, scanResult{WriteErr: err.Error()})
		return
	}
	release, ok := acquireScanSlot(ctx, d, s, p)
	defer release()
	if !ok {
		a.finishScan(s.ID, scanID, p, scanResult{Cancelled: true})
		return
	}
	out := make(chan row, 20000)
	wdone := make(chan error, 1)
	go a.writer(out, wdone)
	rootOK, intr := walkShare(ctx, d, s, scanID, l, p, out, done)
	close(out)
	werr := <-wdone
	snap := p.snapshot()
	r := scanResult{Cancelled: ctx.Err() != nil, RootOK: rootOK, Interrupted: intr, Files: snap.Files, Dirs: snap.Dirs, Bytes: snap.Bytes, Errors: snap.Errors}
	if werr != nil {
		r.WriteErr = "index write failed: " + werr.Error()
	}
	a.finishScan(s.ID, scanID, p, r)
}

func attemptOf(v string) int64 {
	n, _ := strconv.ParseInt(v, 10, 64)
	return n
}

var _ = time.Second
