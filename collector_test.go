package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCollectorEndToEnd runs a real collector loop against an in-process server:
// discover through the task queue, then a scan streamed back and published.
func TestCollectorEndToEnd(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"a/x.pdf", "a/y.locky", "b/passwords.xlsx", "b/deep/z.tmp"} {
		full := filepath.Join(dir, filepath.FromSlash(p))
		mustMkdir(t, filepath.Dir(full))
		mustWrite(t, full, strings.Repeat("x", 100))
	}
	a := newTestApp(t)
	mux := http.NewServeMux()
	a.routes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tok := "stc_test"
	a.st.db.Exec(`INSERT INTO collectors(id,name,token_hash,created) VALUES(7,'site-a',?,0)`, hashToken(tok))
	a.st.db.Exec(`INSERT INTO devices(id,name,kind,host,created,collector_id) VALUES(1,'fs01','windows','',0,7)`)
	a.st.db.Exec(`INSERT INTO shares(id,device_id,name,path,created) VALUES(1,1,'data',?,0)`, dir)
	go runCollector(srv.URL, tok, t.TempDir(), false, "")

	d, _ := a.device(1)
	raw, err := a.runTask(7, "discover", map[string]any{"device": d.wire()}, 20*time.Second)
	if err != nil || !strings.Contains(string(raw), `"path"`) {
		t.Fatalf("discover via collector: %v %s", err, raw)
	}
	id, err := a.startScan(1)
	if err != nil {
		t.Fatal(err)
	}
	if st, msg := waitScanLong(t, a, id, 30*time.Second); st != "done" {
		t.Fatalf("remote scan %s: %s", st, msg)
	}
	var n int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM `+a.fileRowsFor(id)+` WHERE scan_id=?`, id).Scan(&n)
	if n != 4 {
		t.Fatalf("remote scan indexed %d files", n)
	}
	// Folder permissions travel through the collector too.
	var perms, shareOK int
	a.st.db.QueryRow(`SELECT COUNT(*), SUM(share_id=1) FROM perms WHERE scan_id=?`, id).Scan(&perms, &shareOK)
	if perms == 0 || shareOK != perms {
		t.Fatalf("permission rows via collector: %d (share id right on %d)", perms, shareOK)
	}
	// A migration from a collector device runs on that collector.
	target := t.TempDir()
	rec := httptest.NewRecorder()
	a.createMigration(rec, httptest.NewRequest("POST", "/api/migrations", strings.NewReader(`{"name":"m","source_share":1,"target_device":1,"target_root":`+jsonQuote(filepath.Join(target, "copy"))+`}`)))
	var mm struct {
		ID   int64 `json:"id"`
		Plan struct {
			Runner   string `json:"runner"`
			Blockers int    `json:"blockers"`
		} `json:"plan"`
	}
	jsonUnmarshal(rec.Body.String(), &mm)
	if mm.Plan.Runner != "collector site-a" || mm.Plan.Blockers != 0 {
		t.Fatalf("migration plan via collector: %s", rec.Body.String())
	}
	m, _ := a.migration(mm.ID)
	for _, w := range m.Waves {
		if got := runWaveWait(t, a, m, w, false); got.Status != "done" || got.Copied != w.Files {
			t.Fatalf("wave via collector: %+v", got)
		}
	}
	if b, err := os.ReadFile(filepath.Join(target, "copy", "b", "deep", "z.tmp")); err != nil || len(b) != 100 {
		t.Fatalf("file copied by the collector: %v", err)
	}
	// Decoys are planted by the collector on its own machine.
	if isWindows {
		res, err := a.plantDecoys(1)
		if err != nil || len(res) == 0 || res[0].Result != "planted" {
			t.Fatalf("decoys via collector: %v %+v", err, res)
		}
		if _, err := os.Stat(filepath.Join(dir, decoyNames[0])); err != nil {
			t.Fatal("decoy not on disk")
		}
		if res, err = a.removeDecoys(1); err != nil || res[0].Result != "removed" {
			t.Fatalf("decoy removal via collector: %v %+v", err, res)
		}
	}
	// Audit from a collector is only accepted for its own devices.
	a.st.db.Exec(`INSERT INTO devices(id,name,kind,host,created,collector_id) VALUES(2,'other','windows','x',0,0)`)
	req, _ := http.NewRequest("POST", srv.URL+"/api/c/audit", strings.NewReader(`[{"device_id":1,"user":"u","op":"delete","path":"/a"},{"device_id":2,"user":"u","op":"delete","path":"/b"}]`))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, _ := http.DefaultClient.Do(req)
	var out struct{ Accepted int }
	jsonDecode(resp, &out)
	if out.Accepted != 1 {
		t.Fatalf("accepted %d audit events, want 1", out.Accepted)
	}
	// Wrong token is refused.
	req, _ = http.NewRequest("POST", srv.URL+"/api/c/poll", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer nope")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("bad token got %d", resp.StatusCode)
	}
}

func waitScanLong(t *testing.T, a *App, id int64, d time.Duration) (status, msg string) {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		a.st.db.QueryRow(`SELECT status,message FROM scans WHERE id=?`, id).Scan(&status, &msg)
		a.mu.Lock()
		_, busy := a.running[id]
		a.mu.Unlock()
		if status != "running" && !busy {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("timeout waiting for scan")
	return
}

func TestAskParser(t *testing.T) {
	a := newTestApp(t)
	a.st.db.Exec(`INSERT INTO shares(id,device_id,name,path) VALUES(3,1,'Finance','x')`)
	r := a.parseAsk("videos over 1 GB not touched in 2 years in finance")
	f := r.Filter
	if f.MinSize != 1<<30 || f.OlderThanDays != 730 || f.ShareID != 3 || len(f.Ext) == 0 {
		t.Fatalf("parse: %+v %v", f, r.Understood)
	}
	r = a.parseAsk("pdf files owned by jdoe modified in the last 3 weeks")
	if r.Filter.Owner != "jdoe" || r.Filter.NewerThanDays != 21 || r.Filter.Ext[0] != "pdf" {
		t.Fatalf("parse2: %+v", r.Filter)
	}
	if a.parseAsk("show me duplicates").Route != "#/duplicates" {
		t.Fatal("duplicate intent")
	}
	if a.parseAsk("biggest files not accessed in a year").Filter.NotAccessedDay != 365 {
		t.Fatal("not accessed")
	}
}

// A collector that restarted reports running_scan_ids as null; its orphaned scans
// must be handed out again as a resumed attempt.
func TestRequeueAfterCollectorRestart(t *testing.T) {
	_, a := localFixture(t, "a.txt")
	a.st.db.Exec(`INSERT INTO collectors(id,name,token_hash,created) VALUES(7,'c',?,0)`, hashToken("stc_x"))
	a.st.db.Exec(`UPDATE devices SET collector_id=7 WHERE id=1`)
	id, err := a.startScan(1)
	if err != nil {
		t.Fatal(err)
	}
	poll := func(body string) {
		rec := httptest.NewRecorder()
		a.cPoll(rec, httptest.NewRequest("POST", "/api/c/poll", strings.NewReader(body)), 7)
	}
	poll(`{"hostname":"h"}`) // claims attempt 1
	a.mu.Lock()
	p := a.running[id]
	a.mu.Unlock()
	p.mu.Lock()
	p.Updated = now() - 120 // silent for two minutes
	p.mu.Unlock()
	poll(`{"hostname":"h","running_scan_ids":null}`)
	time.Sleep(300 * time.Millisecond) // requeue runs in the background
	var attempts int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM tasks WHERE kind='scan' AND status IN ('pending','claimed') AND json_extract(payload,'$.attempt')=2`).Scan(&attempts)
	if attempts != 1 {
		t.Fatalf("orphaned scan was not requeued (pending attempt-2 tasks: %d)", attempts)
	}
}

func jsonQuote(s string) string { b, _ := json.Marshal(s); return string(b) }
