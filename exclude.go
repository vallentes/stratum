package main

import (
	"encoding/json"
	"net/http"
	"path"
	"strings"
)

// Per-share exclusions, stored in share options as {"exclude": [...]}. Each rule is:
//   /Some/Folder   a share-relative path: that folder (or file) and everything below it
//   *.iso, ~$*     a wildcard on the file or folder name, anywhere in the share
//   node_modules   a plain name: any folder or file with exactly that name
// Matching is case-insensitive (Windows and SMB semantics).

type excluder struct {
	prefixes []string
	globs    []string
	names    map[string]bool
}

func newExcluder(options string) *excluder {
	var o struct {
		Exclude []string `json:"exclude"`
	}
	json.Unmarshal([]byte(options), &o)
	if len(o.Exclude) == 0 {
		return nil
	}
	x := &excluder{names: map[string]bool{}}
	for _, r := range o.Exclude {
		r = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(r, `\`, "/")))
		switch {
		case r == "" || r == "/":
		case strings.HasPrefix(r, "/"):
			x.prefixes = append(x.prefixes, strings.TrimRight(r, "/"))
		case strings.ContainsAny(r, "*?["):
			x.globs = append(x.globs, r)
		default:
			x.names[r] = true
		}
	}
	return x
}

func (x *excluder) match(rel, name string) bool {
	if x == nil {
		return false
	}
	lr, ln := strings.ToLower(rel), strings.ToLower(name)
	if x.names[ln] {
		return true
	}
	for _, p := range x.prefixes {
		if lr == p || strings.HasPrefix(lr, p+"/") {
			return true
		}
	}
	for _, g := range x.globs {
		if ok, _ := path.Match(g, ln); ok {
			return true
		}
	}
	return false
}

// Suggested rules for common noise; offered in the UI, never applied silently.
var excludePresets = map[string][]string{
	"system":   {"$RECYCLE.BIN", "System Volume Information", "pagefile.sys", "hiberfil.sys", "swapfile.sys", "$WinREAgent", "Config.Msi"},
	"dev":      {"node_modules", ".git", ".svn", "__pycache__", ".venv", "Library", "obj", ".gradle"},
	"temp":     {"*.tmp", "~$*", "Thumbs.db", ".DS_Store", "desktop.ini"},
	"snapshot": {".snapshot", "~snapshot", ".isi-snapshots"},
	"mac":      {"__MACOSX", "._*", ".DS_Store", ".AppleDouble", ".Spotlight-V100", ".fseventsd", ".Trashes"},
	"linux":    {"/var/lib/docker", "/var/lib/containerd", "/var/lib/kubelet", "/var/lib/lxcfs", "/snap", "/var/cache", "/var/log/journal", "/swap.img", "/swapfile", "/lost+found"},
}

// pruneExcluded removes rows now excluded from a share's published index so the
// change shows immediately instead of after the next scan.
func (a *App) pruneExcluded(s Share) (int64, error) {
	x := newExcluder(s.Options)
	if x == nil || s.CurrentScan == 0 {
		return 0, nil
	}
	t := a.tableFor(s.CurrentScan)
	rows, err := a.st.db.Query(`SELECT rowid, path FROM `+t+` WHERE scan_id=?`, s.CurrentScan)
	if err != nil {
		return 0, err
	}
	var drop []int64
	for rows.Next() {
		var id int64
		var p string
		rows.Scan(&id, &p)
		// Excluded when the file or any folder on its path matches.
		parts := strings.Split(strings.Trim(p, "/"), "/")
		cur := ""
		for _, seg := range parts {
			cur += "/" + seg
			if x.match(cur, seg) {
				drop = append(drop, id)
				break
			}
		}
	}
	rows.Close()
	a.wmu.Lock()
	defer a.wmu.Unlock()
	tx, err := a.st.db.Begin()
	if err != nil {
		return 0, err
	}
	for _, id := range drop {
		tx.Exec(`DELETE FROM `+t+` WHERE rowid=?`, id)
	}
	// Folder rows: drop excluded folders; totals of their parents are corrected on the next scan.
	drows, _ := tx.Query(`SELECT rowid, path FROM dirs WHERE scan_id=?`, s.CurrentScan)
	var ddrop []int64
	for drows != nil && drows.Next() {
		var id int64
		var p string
		drows.Scan(&id, &p)
		cur := ""
		for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
			if seg == "" {
				break
			}
			cur += "/" + seg
			if x.match(cur, seg) {
				ddrop = append(ddrop, id)
				break
			}
		}
	}
	if drows != nil {
		drows.Close()
	}
	for _, id := range ddrop {
		tx.Exec(`DELETE FROM dirs WHERE rowid=?`, id)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if len(drop) > 0 {
		a.buildAggregates(s.CurrentScan)
		ft := a.fileRowsFor(s.CurrentScan)
		a.st.db.Exec(`UPDATE scans SET files=(SELECT COUNT(*) FROM `+ft+`), bytes=(SELECT COALESCE(SUM(CASE WHEN flags & 4 = 0 THEN size ELSE 0 END),0) FROM `+ft+`) WHERE id=?`, s.CurrentScan)
	}
	return int64(len(drop)), nil
}

func (a *App) setExclusions(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Exclude []string `json:"exclude"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	s, err := a.share(idOf(r))
	if err != nil {
		httpErr(w, 404, "share not found")
		return
	}
	var opts map[string]any
	json.Unmarshal([]byte(s.Options), &opts)
	if opts == nil {
		opts = map[string]any{}
	}
	var clean []string
	for _, e := range in.Exclude {
		if e = strings.TrimSpace(e); e != "" && e != "/" {
			clean = append(clean, e)
		}
	}
	opts["exclude"] = clean
	b, _ := json.Marshal(opts)
	s.Options = string(b)
	a.st.db.Exec(`UPDATE shares SET options=? WHERE id=?`, s.Options, s.ID)
	n, err := a.pruneExcluded(s)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "removed": n, "rules": clean})
}
