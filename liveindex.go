package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Audit-driven index updates. Between full walks, every create/modify/delete/rename
// event is turned into a targeted re-read of just that path (stat, no content), and
// the published index is patched in place. A full walk is still the source of truth
// for folder totals; aggregates are refreshed after each batch of changes.

type statResult struct {
	Rel    string `json:"rel"`
	Exists bool   `json:"exists"`
	IsDir  bool   `json:"is_dir"`
	Size   int64  `json:"size"`
	Mtime  int64  `json:"mtime"`
	Atime  int64  `json:"atime"`
	Ctime  int64  `json:"ctime"`
	ETag   string `json:"etag,omitempty"`
}

type statPayload struct {
	Device deviceWire `json:"device"`
	Share  Share      `json:"share"`
	Rels   []string   `json:"rels"`
}

// statItems re-reads metadata for specific paths. Runs where the storage is reachable.
func statItems(pl statPayload) []statResult {
	d := pl.Device.dev()
	out := make([]statResult, 0, len(pl.Rels))
	var ps *psClient
	var s3l *s3Lister
	switch d.Kind {
	case "powerscale":
		ps = psClientFor(d)
	case "s3":
		if l, err := newS3Lister(d, pl.Share.Path); err == nil {
			s3l = l.(*s3Lister)
		}
	}
	for _, rel := range pl.Rels {
		r := statResult{Rel: rel}
		switch d.Kind {
		case "windows":
			full := filepath.Join(pl.Share.Path, filepath.FromSlash(strings.TrimPrefix(rel, "/")))
			if info, err := os.Lstat(longPath(full)); err == nil {
				e := Entry{Mtime: info.ModTime().Unix(), Size: info.Size()}
				fillPlatform(&e, info)
				r = statResult{Rel: rel, Exists: true, IsDir: info.IsDir(), Size: info.Size(), Mtime: e.Mtime, Atime: e.Atime, Ctime: e.Ctime}
			}
		case "powerscale":
			var md struct {
				Attrs []struct {
					Name  string `json:"name"`
					Value any    `json:"value"`
				} `json:"attrs"`
			}
			if err := ps.getJSON(nsPath(path.Join(pl.Share.Path, rel))+"?metadata", &md); err == nil {
				r.Exists = true
				for _, a := range md.Attrs {
					switch a.Name {
					case "size":
						if f, ok := a.Value.(float64); ok {
							r.Size = int64(f)
						}
					case "last_modified":
						r.Mtime = parseHTTPTime(fmt.Sprint(a.Value))
					case "access_time":
						r.Atime = parseHTTPTime(fmt.Sprint(a.Value))
					case "create_time":
						r.Ctime = parseHTTPTime(fmt.Sprint(a.Value))
					case "type":
						r.IsDir = fmt.Sprint(a.Value) == "container"
					}
				}
				if r.Atime == 0 {
					r.Atime = r.Mtime
				}
				if r.Ctime == 0 {
					r.Ctime = r.Mtime
				}
			}
		case "s3":
			if s3l != nil {
				if resp, err := s3l.c.do("HEAD", s3l.bucket, s3l.key(rel), nil, nil); err == nil {
					resp.Body.Close()
					if resp.StatusCode == 200 {
						t, _ := http.ParseTime(resp.Header.Get("Last-Modified"))
						r = statResult{Rel: rel, Exists: true, Size: resp.ContentLength, Mtime: t.Unix(), Atime: t.Unix(), Ctime: t.Unix(),
							ETag: strings.Trim(resp.Header.Get("ETag"), `"`)}
					}
				}
			}
		}
		out = append(out, r)
	}
	return out
}

// auditRel maps an audit event path onto a share, returning the share-relative path.
func auditRel(kind, sharePath, eventPath string) (string, bool) {
	norm := func(p string) string {
		p = strings.ReplaceAll(p, `\`, "/")
		p = strings.TrimRight(p, "/")
		if kind == "windows" {
			p = strings.ToLower(p)
		}
		return p
	}
	sp, ep := norm(sharePath), norm(eventPath)
	if kind == "windows" && strings.HasPrefix(sp, "//") {
		return "", false // UNC share: events carry the server's local path, not mappable here
	}
	if ep == sp {
		return "/", true
	}
	if !strings.HasPrefix(ep, sp+"/") {
		return "", false
	}
	// Keep the original case of the event path for the stored row.
	orig := strings.ReplaceAll(eventPath, `\`, "/")
	return "/" + strings.TrimLeft(orig[len(strings.TrimRight(strings.ReplaceAll(sharePath, `\`, "/"), "/")):], "/"), true
}

var aggRefresh sync.Map // shareID -> last aggregate rebuild (unix)

func (a *App) liveIndexer() {
	for range time.Tick(3 * time.Minute) {
		for _, sid := range a.ids(`SELECT id FROM shares WHERE current_scan>0`) {
			a.liveUpdateShare(sid)
		}
	}
}

func (a *App) liveUpdateShare(shareID int64) {
	s, err := a.share(shareID)
	if err != nil || s.CurrentScan == 0 {
		return
	}
	a.mu.Lock()
	for _, p := range a.running {
		if p.ShareID == shareID {
			a.mu.Unlock()
			return // a full walk is running; it will supersede these events
		}
	}
	a.mu.Unlock()
	d, err := a.device(s.DeviceID)
	if err != nil {
		return
	}
	wmKey := fmt.Sprintf("live_wm_%d", shareID)
	var wm int64
	fmt.Sscan(a.st.setting(wmKey), &wm)
	if wm < s.LastScanAt {
		wm = s.LastScanAt
	}
	rows, err := a.st.db.Query(`SELECT path, MAX(ts), SUM(count) FROM audit WHERE device_id=? AND ts > ? AND op IN ('create','modify','delete','rename') GROUP BY path ORDER BY 2 LIMIT 20000`, d.ID, wm)
	if err != nil {
		return
	}
	var rels []string
	seen := map[string]bool{}
	maxTS, events := wm, int64(0)
	for rows.Next() {
		var p string
		var ts, c int64
		rows.Scan(&p, &ts, &c)
		if ts > maxTS {
			maxTS = ts
		}
		if rel, ok := auditRel(d.Kind, s.Path, p); ok && rel != "/" && !seen[rel] {
			seen[rel] = true
			rels = append(rels, rel)
			events += c
		}
	}
	rows.Close()
	if len(rels) == 0 {
		if maxTS > wm {
			a.st.setSetting(wmKey, fmt.Sprint(maxTS))
		}
		return
	}
	var results []statResult
	for i := 0; i < len(rels); i += 500 {
		pl := statPayload{Device: d.wire(), Share: s, Rels: rels[i:min(i+500, len(rels))]}
		if d.CollectorID > 0 {
			raw, err := a.runTask(d.CollectorID, "stat", pl, 3*time.Minute)
			if err != nil {
				a.st.db.Exec(`INSERT INTO index_updates(share_id,ts,events,upserted,removed,message) VALUES(?,?,?,?,?,?)`, shareID, now(), events, 0, 0, err.Error())
				return // watermark stays put: the same events are retried next round
			}
			var part []statResult
			json.Unmarshal(raw, &part)
			results = append(results, part...)
		} else {
			results = append(results, statItems(pl)...)
		}
	}
	up, rm := a.applyStat(s, results)
	a.st.setSetting(wmKey, fmt.Sprint(maxTS))
	a.st.db.Exec(`INSERT INTO index_updates(share_id,ts,events,upserted,removed) VALUES(?,?,?,?,?)`, shareID, now(), events, up, rm)
	if up+rm > 0 {
		last, _ := aggRefresh.Load(shareID)
		if l, _ := last.(int64); now()-l > 600 {
			aggRefresh.Store(shareID, now())
			a.wmu.Lock()
			a.buildAggregates(s.CurrentScan)
			t := a.fileRowsFor(s.CurrentScan)
			a.st.db.Exec(`UPDATE scans SET files=(SELECT COUNT(*) FROM `+t+`), bytes=(SELECT COALESCE(SUM(CASE WHEN flags & 4 = 0 THEN size ELSE 0 END),0) FROM `+t+`) WHERE id=?`, s.CurrentScan)
			a.wmu.Unlock()
		}
		log.Printf("live index %s: %d events, %d upserted, %d removed", s.Name, events, up, rm)
	}
}

// applyStat patches the published index with fresh metadata for changed paths.
func (a *App) applyStat(s Share, results []statResult) (up, rm int) {
	t := a.tableFor(s.CurrentScan)
	a.wmu.Lock()
	defer a.wmu.Unlock()
	tx, err := a.st.db.Begin()
	if err != nil {
		return
	}
	defer tx.Commit()
	owners := map[string]string{}
	ownerOf := func(dir string) string {
		if o, ok := owners[dir]; ok {
			return o
		}
		var o string
		tx.QueryRow(`SELECT owner FROM dirs WHERE scan_id=? AND path=?`, s.CurrentScan, dir).Scan(&o)
		owners[dir] = o
		return o
	}
	for _, r := range results {
		switch {
		case !r.Exists:
			res, _ := tx.Exec(`DELETE FROM `+t+` WHERE scan_id=? AND ext=? AND path=?`, s.CurrentScan, extOf(r.Rel), r.Rel)
			if n, _ := res.RowsAffected(); n > 0 {
				rm += int(n)
			} else {
				// Maybe a folder: drop everything beneath it.
				res, _ = tx.Exec(`DELETE FROM `+t+` WHERE scan_id=? AND path LIKE ? ESCAPE '\'`, s.CurrentScan, likeEscape(r.Rel)+"/%")
				n, _ := res.RowsAffected()
				rm += int(n)
			}
		case r.IsDir:
			// New folders are indexed through the events for the files inside them.
		default:
			tx.Exec(`DELETE FROM `+t+` WHERE scan_id=? AND ext=? AND path=?`, s.CurrentScan, extOf(r.Rel), r.Rel)
			dir := path.Dir(r.Rel)
			tx.Exec(`INSERT INTO `+t+`(`+colList+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, s.CurrentScan, r.Rel, dir, path.Base(r.Rel), extOf(r.Rel),
				r.Size, r.Mtime, r.Atime, r.Ctime, ownerOf(dir), 0, r.ETag)
			up++
		}
	}
	return
}

func (a *App) liveIndexStatus(w http.ResponseWriter, r *http.Request) {
	rows, _ := a.st.db.Query(`SELECT u.ts, COALESCE(s.name,''), u.events, u.upserted, u.removed, u.message FROM index_updates u LEFT JOIN shares s ON s.id=u.share_id ORDER BY u.ts DESC LIMIT 30`)
	out := []map[string]any{}
	for rows != nil && rows.Next() {
		var ts, ev, up, rm int64
		var sh, msg string
		rows.Scan(&ts, &sh, &ev, &up, &rm, &msg)
		out = append(out, map[string]any{"ts": ts, "share": sh, "events": ev, "upserted": up, "removed": rm, "message": msg})
	}
	if rows != nil {
		rows.Close()
	}
	writeJSON(w, out)
}
