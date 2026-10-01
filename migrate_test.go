package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// memS3 is a small in-memory S3: path-style buckets, list v2 with delimiter, HEAD,
// GET, PUT, and multipart uploads.
type memS3 struct {
	mu       sync.Mutex
	objs     map[string][]byte // "bucket/key"
	meta     map[string]string // "bucket/key" -> x-amz-meta-mtime
	uploads  map[string]map[int][]byte
	unsigned int // uploads that used UNSIGNED-PAYLOAD
	parts    int
}

func newMemS3(t *testing.T) (*memS3, *httptest.Server) {
	m := &memS3{objs: map[string][]byte{}, meta: map[string]string{}, uploads: map[string]map[int][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(srv.Close)
	return m, srv
}

func (m *memS3) serve(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
		w.WriteHeader(403)
		return
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	id := bucket + "/" + key
	q := r.URL.Query()
	switch {
	case r.Method == "GET" && key == "": // list
		prefix := q.Get("prefix")
		var keys []string
		for k := range m.objs {
			if b, kk, _ := strings.Cut(k, "/"); b == bucket && strings.HasPrefix(kk, prefix) {
				keys = append(keys, kk)
			}
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteString("<ListBucketResult><IsTruncated>false</IsTruncated>")
		seen := map[string]bool{}
		for _, k := range keys {
			rest := strings.TrimPrefix(k, prefix)
			if i := strings.IndexByte(rest, '/'); i >= 0 && q.Get("delimiter") == "/" {
				cp := prefix + rest[:i+1]
				if !seen[cp] {
					seen[cp] = true
					fmt.Fprintf(&b, "<CommonPrefixes><Prefix>%s</Prefix></CommonPrefixes>", s3XMLEsc(cp))
				}
				continue
			}
			fmt.Fprintf(&b, `<Contents><Key>%s</Key><LastModified>2025-05-01T10:00:00.000Z</LastModified><ETag>"x"</ETag><Size>%d</Size></Contents>`, s3XMLEsc(k), len(m.objs[bucket+"/"+k]))
		}
		b.WriteString("</ListBucketResult>")
		w.Write([]byte(b.String()))
	case r.Method == "HEAD":
		o, ok := m.objs[id]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(o)))
		w.Header().Set("Last-Modified", "Thu, 01 May 2025 10:00:00 GMT")
		if v := m.meta[id]; v != "" {
			w.Header().Set("x-amz-meta-mtime", v)
		}
	case r.Method == "GET":
		o, ok := m.objs[id]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Write(o)
	case r.Method == "POST" && q.Has("uploads"):
		up := fmt.Sprintf("up%d", len(m.uploads)+1)
		m.uploads[up] = map[int][]byte{}
		m.meta[id] = r.Header.Get("x-amz-meta-mtime")
		fmt.Fprintf(w, "<InitiateMultipartUploadResult><UploadId>%s</UploadId></InitiateMultipartUploadResult>", up)
	case r.Method == "PUT" && q.Get("uploadId") != "":
		b, _ := io.ReadAll(r.Body)
		var n int
		fmt.Sscan(q.Get("partNumber"), &n)
		m.uploads[q.Get("uploadId")][n] = b
		m.parts++
		w.Header().Set("ETag", fmt.Sprintf(`"p%d"`, n))
	case r.Method == "POST" && q.Get("uploadId") != "":
		var done struct {
			Parts []struct {
				N int `xml:"PartNumber"`
			} `xml:"Part"`
		}
		xml.NewDecoder(r.Body).Decode(&done)
		var all []byte
		for _, p := range done.Parts {
			all = append(all, m.uploads[q.Get("uploadId")][p.N]...)
		}
		m.objs[id] = all
		w.Write([]byte("<CompleteMultipartUploadResult/>"))
	case r.Method == "DELETE" && q.Get("uploadId") != "":
		delete(m.uploads, q.Get("uploadId"))
	case r.Method == "PUT":
		if r.Header.Get("x-amz-content-sha256") == "UNSIGNED-PAYLOAD" {
			m.unsigned++
		}
		b, _ := io.ReadAll(r.Body)
		m.objs[id] = b
		m.meta[id] = r.Header.Get("x-amz-meta-mtime")
	default:
		w.WriteHeader(400)
	}
}

func migCreate(t *testing.T, a *App, body string) migration {
	rec := httptest.NewRecorder()
	a.createMigration(rec, httptest.NewRequest("POST", "/api/migrations", strings.NewReader(body)))
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "plan_error") {
		t.Fatalf("create migration: %d %s", rec.Code, rec.Body.String())
	}
	var id struct {
		ID int64 `json:"id"`
	}
	jsonUnmarshal(rec.Body.String(), &id)
	m, err := a.migration(id.ID)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func runWaveWait(t *testing.T, a *App, m migration, w migWave, dry bool) migWave {
	t.Helper()
	m, _ = a.migration(m.ID)
	if err := a.startWave(m, w.ID, dry); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2400; i++ {
		for _, x := range a.migWaves(m.ID) {
			if x.ID == w.ID && x.Status != "running" {
				return x
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("wave did not finish")
	return w
}

func checkKeys(p *migPlan) map[string]string {
	out := map[string]string{}
	for _, c := range p.Checks {
		out[c.Key] = c.Severity
	}
	return out
}

func TestMigrationLocal(t *testing.T) {
	_, a := localFixture(t, "Finance/q1.xlsx", "Finance/2024/q2.xlsx", "HR/policy.docx", "readme.txt")
	id, _ := a.startScan(1)
	waitScanLong(t, a, id, 20*time.Second)
	target := filepath.Join(t.TempDir(), "migrated")
	s, _ := a.share(1)

	// A target inside the source is refused.
	bad := migCreate(t, a, fmt.Sprintf(`{"name":"bad","source_share":1,"target_device":1,"target_root":%q}`, filepath.Join(s.Path, "Finance", "copy")))
	if checkKeys(bad.Plan)["overlap"] != "blocker" {
		t.Fatalf("overlap not caught: %+v", bad.Plan.Checks)
	}
	if err := a.startWave(bad, bad.Waves[0].ID, false); err == nil {
		t.Fatal("a plan with blockers must not run for real")
	}

	m := migCreate(t, a, fmt.Sprintf(`{"name":"to new disk","source_share":1,"target_device":1,"target_root":%q,"options":{"wave_gb":0.000000250}}`, target))
	if m.Plan.Files != 4 || m.Plan.Blockers != 0 {
		t.Fatalf("plan: %+v", m.Plan)
	}
	// 100-byte files, 250-byte waves: root files + Finance (2 files) do not fit together.
	if len(m.Waves) < 2 {
		t.Fatalf("waves: %+v", m.Waves)
	}
	var total int64
	for _, w := range m.Waves {
		total += w.Files
	}
	if total != 4 {
		t.Fatalf("waves cover %d files", total)
	}

	// Dry run writes nothing.
	w := runWaveWait(t, a, m, m.Waves[0], true)
	if w.Status != "done" || w.Copied != w.Files {
		t.Fatalf("dry run: %+v", w)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("dry run wrote to the target")
	}
	// Real runs of every wave.
	for _, w := range m.Waves {
		got := runWaveWait(t, a, m, w, false)
		if got.Status != "done" || got.Copied != w.Files || got.Failed != 0 {
			t.Fatalf("wave %d: %+v", w.Idx, got)
		}
	}
	srcFile := filepath.Join(s.Path, "Finance", "2024", "q2.xlsx")
	dstFile := filepath.Join(target, "Finance", "2024", "q2.xlsx")
	sb, _ := os.ReadFile(srcFile)
	db, err := os.ReadFile(dstFile)
	if err != nil || string(sb) != string(db) {
		t.Fatalf("copied content differs: %v", err)
	}
	si, _ := os.Stat(srcFile)
	di, _ := os.Stat(dstFile)
	if !si.ModTime().Truncate(time.Second).Equal(di.ModTime().Truncate(time.Second)) {
		t.Fatalf("modified time not kept: %v vs %v", si.ModTime(), di.ModTime())
	}
	if _, err := os.Stat(dstFile + ".stratum-partial"); err == nil {
		t.Fatal("partial file left behind")
	}
	var detail string
	a.st.db.QueryRow(`SELECT detail FROM migration_ledger WHERE path='/Finance/2024/q2.xlsx' AND result='copied'`).Scan(&detail)
	if !strings.HasPrefix(detail, "verified sha256") {
		t.Fatalf("ledger detail %q", detail)
	}

	// Running again copies nothing: everything is already there.
	fin := m.Waves[len(m.Waves)-1]
	for _, w := range m.Waves {
		for _, tp := range w.Tops {
			if tp == "Finance" {
				fin = w
			}
		}
	}
	again := runWaveWait(t, a, m, fin, false)
	if again.Copied != 0 || again.Skipped != fin.Files {
		t.Fatalf("rerun: %+v", again)
	}
	// A different file at the target is left alone by default...
	os.WriteFile(dstFile, []byte("someone else's newer edit"), 0o644)
	again = runWaveWait(t, a, m, fin, false)
	if again.Conflict != 1 || again.Copied != 0 {
		t.Fatalf("conflict: %+v", again)
	}
	if b, _ := os.ReadFile(dstFile); string(b) != "someone else's newer edit" {
		t.Fatal("conflicting target file was overwritten")
	}
	// ...and replaced when the policy says so.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"options":{"conflict":"overwrite","wave_gb":0.000000250}}`))
	req.SetPathValue("id", fmt.Sprint(m.ID))
	a.replanMigration(rec, req)
	m, _ = a.migration(m.ID)
	again = runWaveWait(t, a, m, fin, false)
	if again.Copied != 1 {
		t.Fatalf("overwrite: %+v", again)
	}
	if b, _ := os.ReadFile(dstFile); string(b) != string(sb) {
		t.Fatal("overwrite did not restore the source content")
	}
	// The source is never touched.
	if b, _ := os.ReadFile(srcFile); string(b) != string(sb) {
		t.Fatal("source changed")
	}
}

func TestMigrationS3(t *testing.T) {
	store, srv := newMemS3(t)
	_, a := localFixture(t, "Docs/a.txt", "Docs/b.txt")
	dir, _ := a.share(1)
	big := strings.Repeat("0123456789", 600) // 6000 bytes: multipart with 2 KB parts
	os.WriteFile(filepath.Join(dir.Path, "Docs", "big.bin"), []byte(big), 0o644)
	old := s3PartSize
	s3PartSize = 2048
	defer func() { s3PartSize = old }()
	a.st.db.Exec(`INSERT INTO devices(id,name,kind,host,username,secret,created,options) VALUES(2,'obj','s3',?, 'AK', ?, 0, '{"region":"us-east-1"}')`, srv.URL, a.seal("SK"))
	id, _ := a.startScan(1)
	waitScanLong(t, a, id, 20*time.Second)

	// Folder to bucket.
	m := migCreate(t, a, `{"name":"to object","source_share":1,"target_device":2,"target_root":"archive/fs01"}`)
	if m.Plan.Blockers != 0 {
		t.Fatalf("plan: %+v", m.Plan.Checks)
	}
	for _, w := range m.Waves {
		if got := runWaveWait(t, a, m, w, false); got.Failed != 0 || got.Status != "done" {
			t.Fatalf("wave to S3: %+v", got)
		}
	}
	if string(store.objs["archive/fs01/Docs/big.bin"]) != big || store.parts != 3 {
		t.Fatalf("multipart upload: %d parts, %d bytes", store.parts, len(store.objs["archive/fs01/Docs/big.bin"]))
	}
	if store.unsigned == 0 || store.meta["archive/fs01/Docs/a.txt"] == "" {
		t.Fatal("uploads must stream unsigned and keep the modified time")
	}

	// Bucket back to a folder, and the checks a case-sensitive source needs.
	store.objs["archive/fs01/Docs/A.TXT"] = []byte("same name as a.txt on Windows")
	store.objs["archive/fs01/Docs/bad:name.txt"] = []byte("colon")
	a.st.db.Exec(`INSERT INTO shares(id,device_id,name,path,created) VALUES(2,2,'archive','archive/fs01',0)`)
	id2, _ := a.startScan(2)
	waitScanLong(t, a, id2, 20*time.Second)
	back := filepath.Join(t.TempDir(), "back")
	if isWindows {
		m2 := migCreate(t, a, fmt.Sprintf(`{"name":"back","source_share":2,"target_device":1,"target_root":%q}`, back))
		k := checkKeys(m2.Plan)
		if k["case"] != "blocker" || k["names"] != "blocker" {
			t.Fatalf("S3 to Windows checks: %+v", m2.Plan.Checks)
		}
		store.mu.Lock()
		delete(store.objs, "archive/fs01/Docs/A.TXT")
		delete(store.objs, "archive/fs01/Docs/bad:name.txt")
		store.mu.Unlock()
		id3, _ := a.startScan(2)
		waitScanLong(t, a, id3, 20*time.Second)
	} else {
		store.mu.Lock()
		delete(store.objs, "archive/fs01/Docs/A.TXT")
		delete(store.objs, "archive/fs01/Docs/bad:name.txt")
		store.mu.Unlock()
		id3, _ := a.startScan(2)
		waitScanLong(t, a, id3, 20*time.Second)
	}
	m3 := migCreate(t, a, fmt.Sprintf(`{"name":"back2","source_share":2,"target_device":1,"target_root":%q}`, back))
	if m3.Plan.Blockers != 0 {
		t.Fatalf("clean plan expected: %+v", m3.Plan.Checks)
	}
	for _, w := range m3.Waves {
		if got := runWaveWait(t, a, m3, w, false); got.Failed != 0 {
			t.Fatalf("wave from S3: %+v", got)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(back, "Docs", "big.bin")); string(b) != big {
		t.Fatal("round trip through S3 changed the content")
	}
	fi, _ := os.Stat(filepath.Join(back, "Docs", "a.txt"))
	si, _ := os.Stat(filepath.Join(dir.Path, "Docs", "a.txt"))
	if fi.ModTime().Unix() != si.ModTime().Unix() {
		t.Fatalf("modified time lost through S3: %v vs %v", fi.ModTime(), si.ModTime())
	}
}

func TestMigrationRunner(t *testing.T) {
	local := Device{Kind: "windows"}
	coll := Device{Kind: "windows", CollectorID: 3}
	other := Device{Kind: "windows", CollectorID: 4}
	s3 := Device{Kind: "s3"}
	if _, _, err := runnerFor(coll, other); err == nil {
		t.Error("different collectors must be refused")
	}
	if _, _, err := runnerFor(coll, local); err == nil {
		t.Error("collector cannot reach the server's own disk")
	}
	if cid, _, err := runnerFor(coll, s3); err != nil || cid != 3 {
		t.Error("collector source to S3 runs on the collector")
	}
	if cid, label, err := runnerFor(local, s3); err != nil || cid != 0 || label == "" {
		t.Error("server source runs on the server")
	}
}

func s3XMLEsc(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

func jsonUnmarshal(s string, v any) { json.Unmarshal([]byte(s), v) }
