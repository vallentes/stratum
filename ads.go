package main

import (
	"net/http"
	"strings"
)

// NTFS alternate data streams. Collected when a share has {"ads":true} (one extra
// call per file, so it is opt-in). Classified by stream name:
//   internet-origin  Zone.Identifier (Mark of the Web: downloaded or from email)
//   cloud-sync       sync-client metadata (Dropbox, Box, Google, OneDrive)
//   mac-client       resource forks written by macOS SMB clients
//   app-metadata     Office property sets, Explorer/SmartScreen tags
//   hidden-payload   unknown stream larger than 64 KB: data a normal listing never shows
//   unknown          anything else

func adsClass(name string, size int64) string {
	n := strings.ToLower(strings.Trim(name, "\x05"))
	switch {
	case n == "zone.identifier":
		return "internet-origin"
	case strings.HasPrefix(n, "com.dropbox"), strings.HasPrefix(n, "com.box"), strings.HasPrefix(n, "com.google"),
		strings.Contains(n, "onedrive"), strings.HasPrefix(n, "ms-properties"), n == "syncflag":
		return "cloud-sync"
	case strings.HasPrefix(n, "afp_"), strings.HasPrefix(n, "com.apple"), n == "os2.ea":
		return "mac-client"
	case n == "summaryinformation", n == "documentsummaryinformation", strings.HasPrefix(n, "{4c8cc155-"),
		n == "smartscreen", n == "encryptable", strings.HasPrefix(n, "ocustomproperty"), n == "favicon", n == "win32app_1":
		return "app-metadata"
	case size > 64<<10:
		return "hidden-payload"
	}
	return "unknown"
}

func (a *App) adsReport(w http.ResponseWriter, r *http.Request) {
	sc := scopeFrom(r)
	cond, args := sc.scans("x.scan_id")
	join := ` FROM ads x JOIN shares s ON s.current_scan=x.scan_id JOIN devices d ON d.id=s.device_id WHERE ` + cond
	type grp struct {
		Key     string `json:"key"`
		Streams int64  `json:"streams"`
		Files   int64  `json:"files"`
		Bytes   int64  `json:"bytes"`
	}
	group := func(col string, limit int) []grp {
		out := []grp{}
		rows, err := a.st.db.Query(`SELECT `+col+` k, COUNT(*), COUNT(DISTINCT x.path), SUM(x.size)`+join+` GROUP BY k ORDER BY 2 DESC LIMIT ?`, append(args, limit)...)
		if err != nil {
			return out
		}
		defer rows.Close()
		for rows.Next() {
			var g grp
			rows.Scan(&g.Key, &g.Streams, &g.Files, &g.Bytes)
			out = append(out, g)
		}
		return out
	}
	type item struct {
		Device string `json:"device"`
		Share  string `json:"share"`
		Path   string `json:"path"`
		Stream string `json:"stream"`
		Size   int64  `json:"size"`
		Class  string `json:"class"`
		Owner  string `json:"owner"`
	}
	list := func(extra string, order string, limit int) []item {
		out := []item{}
		rows, err := a.st.db.Query(`SELECT d.name, s.name, x.path, x.stream, x.size, x.class, x.owner`+join+extra+` ORDER BY `+order+` LIMIT ?`, append(args, limit)...)
		if err != nil {
			return out
		}
		defer rows.Close()
		for rows.Next() {
			var it item
			rows.Scan(&it.Device, &it.Share, &it.Path, &it.Stream, &it.Size, &it.Class, &it.Owner)
			out = append(out, it)
		}
		return out
	}
	var enabled int
	w2, a2 := sc.where()
	if w2 == "" {
		w2 = " WHERE 1=1"
	}
	a.st.db.QueryRow(`SELECT COUNT(*) FROM shares`+w2+` AND options LIKE '%"ads":true%'`, a2...).Scan(&enabled)
	writeJSON(w, map[string]any{
		"shares_enabled": enabled,
		"by_class":       group("x.class", 20),
		"by_device":      group("d.name", 20),
		"by_owner":       group("x.owner", 15),
		"by_stream":      group("x.stream", 25),
		"hidden":         list(" AND x.class IN ('hidden-payload','unknown')", "x.size DESC", 50),
		"internet":       list(" AND x.class='internet-origin'", "x.size DESC", 20),
	})
}
