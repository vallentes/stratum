package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// In-app file viewer. Only paths that exist in a published index can be opened, so
// the viewer can never be pointed at arbitrary files on the server or storage.
// Responses are sandboxed (CSP) and active content (HTML, SVG, XML) is served as
// plain text, so a malicious file cannot run script in this origin.

var textExts = map[string]bool{"txt": true, "log": true, "csv": true, "tsv": true, "md": true, "json": true, "xml": true, "yaml": true, "yml": true,
	"ini": true, "conf": true, "cfg": true, "ps1": true, "psm1": true, "bat": true, "cmd": true, "sh": true, "py": true, "go": true, "js": true, "ts": true,
	"java": true, "cs": true, "c": true, "h": true, "cpp": true, "sql": true, "html": true, "htm": true, "css": true, "svg": true, "properties": true, "reg": true, "inf": true}

var activeExts = map[string]bool{"html": true, "htm": true, "svg": true, "xml": true, "xhtml": true, "js": true, "mjs": true}

func viewContentType(name string) string {
	ext := extOf(name)
	if activeExts[ext] || textExts[ext] {
		return "text/plain; charset=utf-8"
	}
	if t := mime.TypeByExtension("." + ext); t != "" {
		return t
	}
	return "application/octet-stream"
}

type readPayload struct {
	Device deviceWire `json:"device"`
	Share  Share      `json:"share"`
	Rel    string     `json:"rel"`
	Offset int64      `json:"offset"`
	Length int64      `json:"length"`
}

type readResult struct {
	Data string `json:"data"` // base64
	Size int64  `json:"size"`
}

const readChunk = 8 << 20

// readRange reads part of a file. Runs where the storage is reachable (server or collector).
func readRange(pl readPayload) (readResult, error) {
	d := pl.Device.dev()
	if pl.Length <= 0 || pl.Length > readChunk {
		pl.Length = readChunk
	}
	var rc io.ReadCloser
	var size int64
	switch d.Kind {
	case "windows":
		f, err := os.Open(longPath(filepath.Join(pl.Share.Path, filepath.FromSlash(strings.TrimPrefix(pl.Rel, "/")))))
		if err != nil {
			return readResult{}, err
		}
		st, _ := f.Stat()
		size = st.Size()
		f.Seek(pl.Offset, io.SeekStart)
		rc = f
	case "powerscale":
		c := psClientFor(d)
		resp, err := c.do("GET", nsPath(path.Join(pl.Share.Path, pl.Rel)), map[string]string{"Range": fmt.Sprintf("bytes=%d-%d", pl.Offset, pl.Offset+pl.Length-1)}, nil)
		if err != nil {
			return readResult{}, err
		}
		if resp.StatusCode >= 300 {
			resp.Body.Close()
			return readResult{}, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		size = totalFromRange(resp)
		rc = resp.Body
	case "s3":
		l, err := newS3Lister(d, pl.Share.Path)
		if err != nil {
			return readResult{}, err
		}
		resp, err := l.(*s3Lister).get(pl.Rel, fmt.Sprintf("bytes=%d-%d", pl.Offset, pl.Offset+pl.Length-1))
		if err != nil {
			return readResult{}, err
		}
		if resp.StatusCode >= 300 {
			defer resp.Body.Close()
			return readResult{}, s3Err(resp)
		}
		size = totalFromRange(resp)
		rc = resp.Body
	default:
		return readResult{}, errors.New("unsupported device kind")
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, pl.Length))
	if err != nil {
		return readResult{}, err
	}
	return readResult{Data: base64.StdEncoding.EncodeToString(b), Size: size}, nil
}

func totalFromRange(resp *http.Response) int64 {
	if cr := resp.Header.Get("Content-Range"); cr != "" {
		if i := strings.LastIndexByte(cr, '/'); i >= 0 {
			n, _ := strconv.ParseInt(cr[i+1:], 10, 64)
			return n
		}
	}
	return resp.ContentLength
}

func parseRange(h string, size int64) (start, end int64, ok bool) {
	if !strings.HasPrefix(h, "bytes=") {
		return 0, size - 1, false
	}
	a, b, _ := strings.Cut(strings.TrimPrefix(h, "bytes="), "-")
	if a == "" { // suffix range
		n, _ := strconv.ParseInt(b, 10, 64)
		return max(size-n, 0), size - 1, true
	}
	start, _ = strconv.ParseInt(a, 10, 64)
	end = size - 1
	if b != "" {
		end, _ = strconv.ParseInt(b, 10, 64)
	}
	if end >= size {
		end = size - 1
	}
	return start, end, start <= end
}

func (a *App) viewFile(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rel := q.Get("path")
	sh, err := a.share(qInt64(r, "share"))
	if err != nil || sh.CurrentScan == 0 {
		httpErr(w, 404, "share not indexed")
		return
	}
	if rel == "" || !strings.HasPrefix(rel, "/") || strings.Contains(rel, "..") || path.Clean(rel) != rel {
		httpErr(w, 400, "bad path")
		return
	}
	var size int64
	if a.st.db.QueryRow(`SELECT size FROM `+a.tableFor(sh.CurrentScan)+` WHERE scan_id=? AND ext=? AND path=?`, sh.CurrentScan, extOf(rel), rel).Scan(&size) != nil {
		httpErr(w, 404, "not in the index (only indexed files can be opened)")
		return
	}
	if looksSecret(rel) {
		httpErr(w, 403, "blocked: this file looks like a credential, key or secret store; open it on the server if you really need to")
		return
	}
	d, err := a.device(sh.DeviceID)
	if err != nil {
		httpErr(w, 404, "device not found")
		return
	}
	// Logged in the background: a publishing scan can hold the writer lock for
	// 15s, and opening a file should not wait for the audit row.
	go a.st.db.Exec(`INSERT INTO view_log(ts,share_id,path,bytes,client) VALUES(?,?,?,?,?)`, now(), sh.ID, rel, size, viewerName(r))

	name := path.Base(rel)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, no-store")
	disp := "inline"
	if q.Get("download") == "1" {
		disp = "attachment"
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`%s; filename="%s"`, disp, strings.ReplaceAll(name, `"`, "")))
	ct := viewContentType(name)
	if disp == "attachment" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	if ct != "application/pdf" {
		// PDFs render in the browser's sandboxed PDF viewer; everything else gets a script-free sandbox.
		w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'")
	}

	// Direct access from this server: stream with range support.
	if d.CollectorID == 0 && d.Kind == "windows" {
		f, err := os.Open(longPath(filepath.Join(sh.Path, filepath.FromSlash(strings.TrimPrefix(rel, "/")))))
		if err != nil {
			httpErr(w, 502, err.Error())
			return
		}
		defer f.Close()
		st, _ := f.Stat()
		http.ServeContent(w, r, "", st.ModTime(), f)
		return
	}
	// Remote (collector) or API-backed storage: pull ranges in chunks.
	start, end, partial := parseRange(r.Header.Get("Range"), size)
	if size == 0 {
		w.WriteHeader(200)
		return
	}
	fetch := func(off int64) ([]byte, error) {
		pl := readPayload{Device: d.wire(), Share: sh, Rel: rel, Offset: off, Length: min(readChunk, end-off+1)}
		var res readResult
		if d.CollectorID > 0 {
			raw, err := a.runTask(d.CollectorID, "read", pl, 2*time.Minute)
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal(raw, &res); err != nil {
				return nil, err
			}
		} else if res, err = readRange(pl); err != nil {
			return nil, err
		}
		return base64.StdEncoding.DecodeString(res.Data)
	}
	// The first chunk before any status goes out. Once 200 and a length are
	// sent there is no way left to report a failure, and a stream cut short is
	// what browsers show as ERR_HTTP2_PROTOCOL_ERROR.
	first, err := fetch(start)
	if err != nil || len(first) == 0 {
		w.Header().Del("Content-Disposition")
		w.Header().Del("Content-Security-Policy")
		msg := "the file could not be read"
		if err != nil {
			msg = "could not read the file: " + err.Error()
		}
		httpErr(w, 502, msg)
		return
	}
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	if partial {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
		w.WriteHeader(206)
	} else {
		w.WriteHeader(200)
	}
	b := first
	for off := start; ; {
		if _, err := w.Write(b); err != nil || len(b) == 0 {
			return
		}
		if off += int64(len(b)); off > end {
			return
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if b, err = fetch(off); err != nil {
			return
		}
	}
}

func (a *App) viewLog(w http.ResponseWriter, r *http.Request) {
	rows, _ := a.st.db.Query(`SELECT v.ts, COALESCE(s.name,''), v.path, v.bytes, v.client FROM view_log v LEFT JOIN shares s ON s.id=v.share_id ORDER BY v.ts DESC LIMIT 100`)
	out := []map[string]any{}
	for rows != nil && rows.Next() {
		var ts, b int64
		var sh, p, c string
		rows.Scan(&ts, &sh, &p, &b, &c)
		out = append(out, map[string]any{"ts": ts, "share": sh, "path": p, "bytes": b, "client": c})
	}
	if rows != nil {
		rows.Close()
	}
	writeJSON(w, out)
}

// looksSecret matches the credential and key categories used by the Risk page, plus
// well-known Unix secret locations. The viewer refuses these outright.
func looksSecret(rel string) bool {
	low := strings.ToLower(rel)
	name := path.Base(low)
	for _, p := range []string{"/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/.ssh/", "/.gnupg/", "/.aws/", "/.kube/", "/.docker/config.json", "/secrets/", "/private/"} {
		if strings.Contains(low, p) || strings.HasSuffix(low, strings.TrimSuffix(p, "/")) {
			return true
		}
	}
	ext := extOf(name)
	for _, c := range sensitiveCats[:2] { // credentials, keys
		for _, e := range c.Exts {
			if ext == e {
				return true
			}
		}
		for _, n := range c.Names {
			if ok, _ := path.Match(strings.ReplaceAll(n, "%", "*"), name); ok {
				return true
			}
		}
	}
	return strings.HasPrefix(name, ".env") || strings.HasSuffix(name, ".env")
}

// viewerName is "user@address" for the file viewer log.
func viewerName(r *http.Request) string {
	if u := userFrom(r); u != nil {
		return u.Username + "@" + clientIP(r)
	}
	return clientIP(r)
}
