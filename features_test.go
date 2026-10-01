package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func localFixture(t *testing.T, files ...string) (string, *App) {
	dir := t.TempDir()
	for _, p := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		mustMkdir(t, filepath.Dir(full))
		mustWrite(t, full, strings.Repeat("x", 100))
	}
	a := newTestApp(t)
	a.st.db.Exec(`INSERT INTO devices(id,name,kind,host,created) VALUES(1,'local','windows','',0)`)
	a.st.db.Exec(`INSERT INTO shares(id,device_id,name,path,created) VALUES(1,1,'t',?,0)`, dir)
	return dir, a
}

func countRows(a *App, scanID int64) (n int) {
	a.st.db.QueryRow(`SELECT COUNT(*) FROM `+a.fileRowsFor(scanID)+` WHERE scan_id=?`, scanID).Scan(&n)
	return
}

// TestResume simulates a crash mid-walk: folders without a dirs row are unfinished.
// Resuming must neither lose nor duplicate files.
func TestResume(t *testing.T) {
	_, a := localFixture(t, "a/1.txt", "a/2.txt", "b/3.txt", "b/c/4.txt", "5.txt")
	res, _ := a.st.db.Exec(`INSERT INTO scans(share_id,started,status) VALUES(1,?, 'running')`, now())
	id, _ := res.LastInsertId()
	a.createScanTable(id)
	s, _ := a.share(1)
	d, _ := a.device(1)
	l, _ := listerFor(d, s)
	out := make(chan row, 1000)
	done := make(chan error, 1)
	go a.writer(out, done)
	walkShare(context.Background(), d, s, id, l, newProgress(id, s, d), out, nil)
	close(out)
	<-done
	if n := countRows(a, id); n != 5 {
		t.Fatalf("walk wrote %d files", n)
	}
	// Crash: "/" and "/b" never finished (their dirs rows are missing), "/b/c" did.
	a.st.db.Exec(`DELETE FROM dirs WHERE scan_id=? AND path IN ('/','/b')`, id)
	if err := a.resumeScan(id, 1); err != nil {
		t.Fatal(err)
	}
	if st, msg := waitScanLong(t, a, id, 20*time.Second); st != "done" {
		t.Fatalf("resumed scan %s: %s", st, msg)
	}
	if n := countRows(a, id); n != 5 {
		t.Fatalf("after resume %d files, want 5 (no loss, no duplicates)", n)
	}
	var dirs int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM dirs WHERE scan_id=?`, id).Scan(&dirs)
	if dirs != 4 {
		t.Fatalf("dirs %d, want 4", dirs)
	}
}

// TestS3Scan walks a fake S3 bucket (prefix folders, paging) and finds ETag duplicates.
func TestS3Scan(t *testing.T) {
	sawAuth := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AK/") {
			sawAuth = true
		}
		q := r.URL.Query()
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<ListAllMyBucketsResult><Buckets><Bucket><Name>data</Name><CreationDate>2026-01-01T00:00:00Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>`)
			return
		}
		obj := func(k, etag string, size int) string {
			return fmt.Sprintf(`<Contents><Key>%s</Key><LastModified>2025-05-01T10:00:00.000Z</LastModified><ETag>"%s"</ETag><Size>%d</Size><Owner><DisplayName>svc</DisplayName></Owner></Contents>`, k, etag, size)
		}
		switch q.Get("prefix") {
		case "":
			if q.Get("continuation-token") == "" {
				fmt.Fprint(w, `<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>p2</NextContinuationToken>`+obj("a.bin", "e1", 50)+`<CommonPrefixes><Prefix>logs/</Prefix></CommonPrefixes></ListBucketResult>`)
			} else {
				fmt.Fprint(w, `<ListBucketResult><IsTruncated>false</IsTruncated>`+obj("b.bin", "e2", 70)+`</ListBucketResult>`)
			}
		case "logs/":
			fmt.Fprint(w, `<ListBucketResult><IsTruncated>false</IsTruncated>`+obj("logs/", "x", 0)+obj("logs/copy-of-a.bin", "e1", 50)+`</ListBucketResult>`)
		}
	}))
	defer srv.Close()
	a := newTestApp(t)
	a.st.db.Exec(`INSERT INTO devices(id,name,kind,host,username,secret,created,options) VALUES(1,'obj','s3',?, 'AK', ?, 0, '{"region":"us-east-1"}')`, srv.URL, a.seal("SK"))
	d, _ := a.device(1)
	b, err := discoverDevice(d)
	if err != nil || len(b) != 1 || b[0].Name != "data" {
		t.Fatalf("bucket discovery %v %+v", err, b)
	}
	a.st.db.Exec(`INSERT INTO shares(id,device_id,name,path,created) VALUES(1,1,'data','data',0)`)
	id, _ := a.startScan(1)
	if st, msg := waitScanLong(t, a, id, 20*time.Second); st != "done" {
		t.Fatalf("s3 scan %s: %s", st, msg)
	}
	if n := countRows(a, id); n != 3 || !sawAuth {
		t.Fatalf("indexed %d objects (want 3), signed=%v", n, sawAuth)
	}
	var sets, copies int
	a.st.db.QueryRow(`SELECT COUNT(*), MAX(copies) FROM dup_sets WHERE scan_id=? AND etag='e1'`, id).Scan(&sets, &copies)
	if sets != 1 || copies != 2 {
		t.Fatalf("etag duplicates: sets=%d copies=%d", sets, copies)
	}
	var owner string
	a.st.db.QueryRow(`SELECT owner FROM ` + a.fileRowsFor(id) + ` WHERE name='a.bin'`).Scan(&owner)
	if owner != "svc" {
		t.Fatalf("object owner %q", owner)
	}
}

func TestAuditRel(t *testing.T) {
	cases := []struct{ kind, share, ev, want string }{
		{"windows", `D:\Shares\Fin`, `d:/shares/fin/Q3/Budget.xlsx`, "/Q3/Budget.xlsx"},
		{"windows", `D:\Shares\Fin`, `D:\Shares\Finance\x`, ""},
		{"powerscale", "/ifs/data/dfs", `\ifs\data\dfs\mydata\a.inc`, "/mydata/a.inc"},
		{"powerscale", "/ifs/data/dfs", "/ifs/data/other/a", ""},
	}
	for _, c := range cases {
		got, ok := auditRel(c.kind, c.share, c.ev)
		if (c.want == "") == ok || got != c.want {
			t.Errorf("auditRel(%s,%s,%s)=%q,%v want %q", c.kind, c.share, c.ev, got, ok, c.want)
		}
	}
}

// TestLiveUpdate: audit events after a scan patch the index without a rewalk.
func TestLiveUpdate(t *testing.T) {
	dir, a := localFixture(t, "keep.txt", "gone.txt")
	id, _ := a.startScan(1)
	waitScanLong(t, a, id, 20*time.Second)
	mustWrite(t, filepath.Join(dir, "new.txt"), "hello")
	os.Remove(filepath.Join(dir, "gone.txt"))
	ts := now() + 5
	for _, p := range []string{"new.txt", "gone.txt"} {
		a.st.db.Exec(`INSERT INTO audit(ts,device_id,username,op,path,proto,client,bytes,count) VALUES(?,1,'u','modify',?,'','',0,1)`, ts,
			strings.ReplaceAll(filepath.Join(dir, p), `\`, "/"))
	}
	a.liveUpdateShare(1)
	var names []string
	rows, _ := a.st.db.Query(`SELECT name FROM ` + a.fileRowsFor(id) + ` ORDER BY name`)
	for rows.Next() {
		var n string
		rows.Scan(&n)
		names = append(names, n)
	}
	rows.Close()
	if strings.Join(names, ",") != "keep.txt,new.txt" {
		t.Fatalf("index after live update: %v", names)
	}
}

// TestViewerGuard: only indexed paths can be opened, and active content is neutered.
func TestViewerGuard(t *testing.T) {
	dir, a := localFixture(t, "doc.txt", "x.html")
	mustWrite(t, filepath.Join(dir, "secret-not-indexed.txt"), "nope")
	id, _ := a.startScan(1)
	waitScanLong(t, a, id, 20*time.Second)
	a.st.db.Exec(`DELETE FROM ` + a.tableFor(id) + ` WHERE name='secret-not-indexed.txt'`)
	get := func(p string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		a.viewFile(rec, httptest.NewRequest("GET", "/api/view?share=1&path="+p, nil))
		return rec
	}
	if r := get("/doc.txt"); r.Code != 200 || !strings.Contains(r.Body.String(), "xxx") {
		t.Fatalf("indexed file: %d", r.Code)
	}
	if r := get("/secret-not-indexed.txt"); r.Code != 404 {
		t.Fatalf("unindexed file served: %d", r.Code)
	}
	if r := get("/../../windows/win.ini"); r.Code != 400 {
		t.Fatalf("traversal: %d", r.Code)
	}
	if r := get("/x.html"); !strings.HasPrefix(r.Header().Get("Content-Type"), "text/plain") || !strings.Contains(r.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("html not neutered: %q %q", r.Header().Get("Content-Type"), r.Header().Get("Content-Security-Policy"))
	}
}

func TestXLSX(t *testing.T) {
	var buf bytes.Buffer
	err := writeXLSX(&buf, []sheet{{name: "A & B", header: []string{"n", "t"}, rows: [][]any{{int64(5), "<x>"}, {1.5, tsTime(1790000000)}}}})
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range z.File {
		rc, _ := f.Open()
		dec := xml.NewDecoder(rc)
		for {
			if _, err := dec.Token(); err != nil {
				if err != io.EOF {
					t.Fatalf("%s is not well-formed XML: %v", f.Name, err)
				}
				break
			}
		}
		rc.Close()
	}
}

func TestADSClass(t *testing.T) {
	for name, want := range map[string]string{"Zone.Identifier": "internet-origin", "com.dropbox.attrs": "cloud-sync", "AFP_AfpInfo": "mac-client",
		"\x05SummaryInformation": "app-metadata", "payload": "unknown"} {
		if got := adsClass(name, 100); got != want {
			t.Errorf("adsClass(%q)=%s want %s", name, got, want)
		}
	}
	if adsClass("payload", 5<<20) != "hidden-payload" {
		t.Error("large unknown stream should be hidden-payload")
	}
}

func TestExclusions(t *testing.T) {
	x := newExcluder(`{"exclude":["/Archive","node_modules","*.ISO"]}`)
	for _, c := range []struct {
		rel, name string
		want      bool
	}{{"/archive/2019", "2019", true}, {"/Archive", "Archive", true}, {"/Archived", "Archived", false},
		{"/src/node_modules", "node_modules", true}, {"/a/disk.iso", "disk.iso", true}, {"/a/b.txt", "b.txt", false}} {
		if got := x.match(c.rel, c.name); got != c.want {
			t.Errorf("match(%s)=%v want %v", c.rel, got, c.want)
		}
	}
	_, a := localFixture(t, "keep/a.txt", "Archive/old.txt", "src/node_modules/m.js", "src/app.js", "img.iso")
	id, _ := a.startScan(1)
	waitScanLong(t, a, id, 20*time.Second)
	if n := countRows(a, id); n != 5 {
		t.Fatalf("before exclusions %d files", n)
	}
	// Apply rules to the published index, then confirm a rescan honours them too.
	a.st.db.Exec(`UPDATE shares SET options='{"ads":false}' WHERE id=1`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/shares/1/exclude", strings.NewReader(`{"exclude":["/Archive","node_modules","*.iso"]}`))
	req.SetPathValue("id", "1")
	a.setExclusions(rec, req)
	if n := countRows(a, id); n != 2 || !strings.Contains(rec.Body.String(), `"removed":3`) {
		t.Fatalf("after prune %d files, %s", n, rec.Body.String())
	}
	s, _ := a.share(1)
	if !strings.Contains(s.Options, `"ads":false`) {
		t.Fatalf("exclusions wiped other options: %s", s.Options)
	}
	id2, _ := a.startScan(1)
	waitScanLong(t, a, id2, 20*time.Second)
	if n := countRows(a, id2); n != 2 {
		t.Fatalf("rescan with exclusions indexed %d files, want 2", n)
	}
}

func TestLooksSecret(t *testing.T) {
	for p, want := range map[string]bool{"/etc/shadow": true, "/home/u/.ssh/id_rsa": true, "/app/.env": true, "/app/.env.production": true,
		"/certs/server.key": true, "/x/passwords.xlsx": true, "/vault.kdbx": true, "/docs/report.pdf": false, "/src/main.go": false} {
		if got := looksSecret(p); got != want {
			t.Errorf("looksSecret(%s)=%v want %v", p, got, want)
		}
	}
}

func TestInstallerTrailer(t *testing.T) {
	a := newTestApp(t)
	exe, _ := os.Executable()
	dist := filepath.Join(filepath.Dir(exe), "dist")
	mustMkdir(t, dist)
	mustWrite(t, filepath.Join(dist, "stratum.exe"), "MZ-fake-binary")
	t.Cleanup(func() { os.RemoveAll(dist) })
	a.st.db.Exec(`INSERT INTO collectors(id,name,token_hash,created) VALUES(3,'My PC',?,0)`, hashToken("stc_good"))
	call := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/collectors/3/installer", strings.NewReader(body))
		req.SetPathValue("id", "3")
		a.collectorInstaller(rec, req)
		return rec
	}
	if r := call(`{"token":"stc_wrong"}`); r.Code != 403 {
		t.Fatalf("wrong token got %d", r.Code)
	}
	r := call(`{"token":"stc_good","server":"https://srv.example:9443/"}`)
	if r.Code != 200 || !strings.Contains(r.Header().Get("Content-Disposition"), "stratum-collector-My-PC.exe") {
		t.Fatalf("installer: %d %s", r.Code, r.Header().Get("Content-Disposition"))
	}
	out := filepath.Join(t.TempDir(), "setup.exe")
	os.WriteFile(out, r.Body.Bytes(), 0o755)
	cfg := readConfigFrom(out)
	if cfg == nil || cfg.Server != "https://srv.example:9443" || cfg.Token != "stc_good" || cfg.Name != "My PC" {
		t.Fatalf("embedded config: %+v", cfg)
	}
	if !bytes.HasPrefix(r.Body.Bytes(), []byte("MZ-fake-binary")) {
		t.Fatal("binary not preserved in front of the trailer")
	}
	if readConfigFrom(filepath.Join(dist, "stratum.exe")) != nil {
		t.Fatal("stock binary must not carry a config")
	}
}

func TestJobsReport(t *testing.T) {
	a := newTestApp(t)
	a.st.db.Exec(`INSERT INTO collectors(id,name,token_hash,created) VALUES(7,'My PC','h',0)`)
	a.st.db.Exec(`INSERT INTO devices(id,name,kind,host,created,collector_id) VALUES(1,'drives','windows','',0,7)`)
	a.st.db.Exec(`INSERT INTO scans(id,share_id,started,status,files,dirs) VALUES(9,1,0,'done',900,100)`)
	a.st.db.Exec(`INSERT INTO shares(id,device_id,name,path,current_scan,created) VALUES(1,1,'D:','D:\',9,0)`)
	// A collector reports one audit step: 2,500 ops on a drive of 1,000 items = 50%.
	a.notePoll(7, map[string]any{"jobs": []any{map[string]any{"id": 1.0, "kind": "enable_audit", "started": float64(now() - 100),
		"step": 1.0, "steps": 4.0, "path": `d:\`, "step_started": float64(now() - 60), "ops": 2500.0}}})
	rec := httptest.NewRecorder()
	a.jobsReport(rec, httptest.NewRequest("GET", "/api/jobs", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `"pct":27.7`) || !strings.Contains(body, `"items":1000`) || !strings.Contains(body, `"where":"My PC"`) {
		t.Fatalf("jobs report: %s", body)
	}
}

func TestProcessOps(t *testing.T) {
	if !isWindows {
		t.Skip("I/O counters are read on Windows only")
	}
	if n := processOps(os.Getpid()); n <= 0 {
		t.Fatalf("own process I/O ops = %d", n)
	}
}

func TestSelfSignedPin(t *testing.T) {
	dir := t.TempDir()
	cert, err := loadOrCreateCert(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := loadOrCreateCert(dir, "127.0.0.1:0")
	if certPin(cert) != certPin(again) {
		t.Fatal("certificate must be reused across restarts (collectors pin it)")
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()
	get := func(pin string) error {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: pinnedTLS(pin)}}
		resp, err := c.Get(srv.URL)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := get(certPin(cert)); err != nil {
		t.Fatalf("correct pin refused: %v", err)
	}
	if err := get(strings.Repeat("ab", 32)); err == nil {
		t.Fatal("wrong pin accepted")
	}
}

func TestScanLockKey(t *testing.T) {
	if !isWindows {
		t.Skip("physical disk mapping is Windows-only")
	}
	d := Device{ID: 1, Kind: "windows"}
	c := scanLockKey(d, Share{Path: `C:\`})
	if !strings.HasPrefix(c, "disk:") {
		t.Fatalf("C: should map to a physical disk, got %q", c)
	}
	if k := scanLockKey(d, Share{Path: `\\srv\share`}); k != "device:1" {
		t.Fatalf("UNC share key %q", k)
	}
	t.Logf("C: -> %s", c)
}

func TestSearchNeedsFilter(t *testing.T) {
	_, a := localFixture(t, "report.pdf", "notes.txt")
	id, _ := a.startScan(1)
	waitScanLong(t, a, id, 20*time.Second)
	get := func(q string) string {
		rec := httptest.NewRecorder()
		a.search(rec, httptest.NewRequest("GET", "/api/search?"+q, nil))
		return rec.Body.String()
	}
	if b := get("sort=name"); !strings.Contains(b, `"needs_filter":true`) {
		t.Fatalf("unfiltered search should not scan everything: %s", b)
	}
	if b := get("ext=pdf"); !strings.Contains(b, `"total":1`) || !strings.Contains(b, "report.pdf") {
		t.Fatalf("ext search: %s", b)
	}
	if b := get("q=note"); !strings.Contains(b, "notes.txt") {
		t.Fatalf("name search: %s", b)
	}
}

// The dashboard workbook must be a valid .xlsx with every sheet, built from a real scan.
func TestDashboardExport(t *testing.T) {
	_, a := localFixture(t, "a/report.pdf", "a/report-copy/report.pdf", "b/notes.txt")
	id, _ := a.startScan(1)
	waitScanLong(t, a, id, 20*time.Second)
	rec := httptest.NewRecorder()
	a.exportDashboard(rec, httptest.NewRequest("GET", "/api/export/dashboard.xlsx", nil))
	z, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	sheets := 0
	for _, f := range z.File {
		if strings.HasPrefix(f.Name, "xl/worksheets/sheet") {
			sheets++
		}
		rc, _ := f.Open()
		dec := xml.NewDecoder(rc)
		for {
			if _, err := dec.Token(); err != nil {
				if err != io.EOF {
					t.Fatalf("%s: %v", f.Name, err)
				}
				break
			}
		}
		rc.Close()
	}
	if sheets != 7 {
		t.Fatalf("workbook has %d sheets, want 7", sheets)
	}
}
