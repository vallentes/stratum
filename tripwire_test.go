package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type hookSink struct {
	mu  sync.Mutex
	got map[string][]string
	srv *httptest.Server
}

func newHookSink(t *testing.T) *hookSink {
	h := &hookSink{got: map[string][]string{}}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.got[r.URL.Path] = append(h.got[r.URL.Path], string(b))
		h.mu.Unlock()
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hookSink) count(p string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.got[p])
}

func (h *hookSink) last(p string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if l := h.got[p]; len(l) > 0 {
		return l[len(l)-1]
	}
	return ""
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func alertsOf(a *App, rule string) (n int, count int) {
	a.st.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(count),0) FROM tw_alerts WHERE rule=?`, rule).Scan(&n, &count)
	return
}

func TestTripwireRules(t *testing.T) {
	_, a := localFixture(t, "x.txt")
	hooks := newHookSink(t)
	cfg := twDefaults()
	cfg.BurstPerMin, cfg.ExtPerMin = 50, 10
	cfg.SlackURL, cfg.TeamsURL, cfg.WebhookURL = hooks.srv.URL+"/slack", hooks.srv.URL+"/teams", hooks.srv.URL+"/hook"
	a.twSave(cfg)
	a.tw = newTripwire(a)

	// Saved secrets are sealed in the database and never returned to the browser.
	if raw := a.st.setting("tripwire"); strings.Contains(raw, "/slack") {
		t.Fatal("webhook address stored in clear text")
	}
	rec := httptest.NewRecorder()
	a.twStatus(rec, httptest.NewRequest("GET", "/api/tripwire", nil))
	if strings.Contains(rec.Body.String(), "/slack") || !strings.Contains(rec.Body.String(), `"slack_url_set":true`) {
		t.Fatalf("status leaks or misreports secrets: %s", rec.Body.String())
	}

	ts := now() - now()%60 + 5
	ev := func(user, op, p string, at int64) {
		a.audit.add(AuditEvent{TS: at, DeviceID: 1, User: user, Op: op, Path: p, Client: "10.0.0.9"})
	}
	// 1. Mass change by one account.
	for i := 0; i < 60; i++ {
		ev(`CORP\bob`, "modify", "D:/share/f"+itoa(i)+".docx", ts)
	}
	waitFor(t, "burst alert", func() bool { n, _ := alertsOf(a, "burst"); return n == 1 })
	waitFor(t, "notifications", func() bool {
		return hooks.count("/slack") == 1 && hooks.count("/teams") == 1 && hooks.count("/hook") == 1
	})
	if !strings.Contains(hooks.last("/slack"), "Mass change") || !strings.Contains(hooks.last("/teams"), "AdaptiveCard") || !strings.Contains(hooks.last("/hook"), `"rule":"burst"`) {
		t.Fatalf("notification bodies: %v", hooks.got)
	}
	// Other accounts below the threshold do not alert.
	for i := 0; i < 20; i++ {
		ev(`CORP\ann`, "modify", "D:/share/a"+itoa(i), ts)
	}
	// The same account crossing the threshold again in the next minute adds to the open alert.
	for i := 0; i < 55; i++ {
		ev(`CORP\bob`, "modify", "D:/share/g"+itoa(i), ts+60)
	}
	waitFor(t, "the second minute added to the open alert", func() bool { _, c := alertsOf(a, "burst"); return c >= 100 })
	if n, c := alertsOf(a, "burst"); n != 1 || c < 100 {
		t.Fatalf("burst alerts %d with count %d; want one open alert carrying both minutes", n, c)
	}
	if hooks.count("/slack") != 1 {
		t.Fatal("a repeat inside the cool-down must not notify again")
	}

	// 2. Ransomware endings.
	for i := 0; i < 12; i++ {
		ev(`CORP\eve`, "rename", "D:/share/report"+itoa(i)+".docx.lockbit", ts)
	}
	waitFor(t, "ransomware ending alert", func() bool { n, _ := alertsOf(a, "ransom_ext"); return n == 1 })

	// 3. Ransom note.
	ev(`CORP\eve`, "create", "D:/share/HOW_TO_DECRYPT.txt", ts)
	waitFor(t, "ransom note alert", func() bool { n, _ := alertsOf(a, "ransom_note"); return n == 1 })

	// Reads never count.
	for i := 0; i < 100; i++ {
		ev(`CORP\reader`, "read", "D:/share/r"+itoa(i), ts)
	}
	time.Sleep(200 * time.Millisecond)
	var reader int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM tw_alerts WHERE username='CORP\reader'`).Scan(&reader)
	if reader != 0 {
		t.Fatal("reads raised an alert")
	}

	// Switched off: nothing fires.
	cfg.Enabled = false
	a.twSave(cfg)
	for i := 0; i < 80; i++ {
		ev(`CORP\zed`, "delete", "D:/share/z"+itoa(i), ts)
	}
	time.Sleep(200 * time.Millisecond)
	var zed int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM tw_alerts WHERE username='CORP\zed'`).Scan(&zed)
	if zed != 0 {
		t.Fatal("alert raised while the tripwire is off")
	}
}

func TestTripwireDecoys(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("decoys on a local share need a Windows audit source")
	}
	dir, a := localFixture(t, "Finance/a.xlsx", "HR/b.docx")
	a.tw = newTripwire(a)
	id, _ := a.startScan(1)
	waitScanLong(t, a, id, 20*time.Second)
	res, err := a.plantDecoys(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 6 {
		t.Fatalf("want 2 decoys in the root and in each of 2 folders, got %+v", res)
	}
	p := filepath.Join(dir, "Finance", decoyNames[0])
	fi, err := os.Stat(p)
	if err != nil || fi.Size() != 48*1024 {
		t.Fatalf("decoy not written: %v", err)
	}
	s, _ := a.share(1)
	if !strings.Contains(s.Options, decoyNames[0]) {
		t.Fatal("decoys must be excluded from the index")
	}
	if _, err := a.plantDecoys(1); err == nil {
		t.Fatal("planting twice must be refused")
	}
	// Our own writes are quiet; once that passes, touching a decoy is critical.
	a.tw.mu.Lock()
	a.tw.quiet = map[string]int64{}
	a.tw.mu.Unlock()
	a.audit.add(AuditEvent{DeviceID: 1, User: `CORP\mallory`, Op: "create", Path: strings.ReplaceAll(p, `\`, "/")})
	time.Sleep(100 * time.Millisecond)
	if n, _ := alertsOf(a, "decoy"); n != 0 {
		t.Fatal("creating (never possible for an attacker) must not fire")
	}
	a.audit.add(AuditEvent{DeviceID: 1, User: `CORP\mallory`, Op: "modify", Path: strings.ToUpper(strings.ReplaceAll(p, `\`, "/"))})
	waitFor(t, "decoy alert", func() bool { n, _ := alertsOf(a, "decoy"); return n == 1 })
	var shareID int64
	a.st.db.QueryRow(`SELECT share_id FROM tw_alerts WHERE rule='decoy'`).Scan(&shareID)
	if shareID != 1 {
		t.Fatalf("decoy alert share %d", shareID)
	}
	// A decoy that was changed is left as evidence; the others are removed.
	os.WriteFile(p, []byte("encrypted!"), 0o644)
	res, err = a.removeDecoys(1)
	if err != nil {
		t.Fatal(err)
	}
	removed, kept := 0, 0
	for _, r := range res {
		if r.Result == "removed" {
			removed++
		} else if strings.HasPrefix(r.Result, "left in place") {
			kept++
		}
	}
	if removed != 5 || kept != 1 {
		t.Fatalf("removal results %+v", res)
	}
	s, _ = a.share(1)
	if strings.Contains(s.Options, decoyNames[0]) {
		t.Fatal("exclusions not cleaned up")
	}
}

func TestTripwireBlockWindows(t *testing.T) {
	_, a := localFixture(t, "x.txt")
	a.tw = newTripwire(a)
	var calls []string
	old := twPowerShell
	twPowerShell = func(script string, env []string) (string, error) {
		calls = append(calls, strings.Join(env, ";"))
		if strings.Contains(strings.Join(env, ";"), "MODE=block") {
			return "Projects|Finance", nil
		}
		return "Projects|Finance", nil
	}
	defer func() { twPowerShell = old }()
	if !isWindows {
		t.Skip("blocking on the local Windows device needs a Windows server")
	}
	cfg := twDefaults()
	cfg.AutoBlock = true
	id := a.twRaise(twAlert{DeviceID: 1, User: `CORP\bob`, Rule: "ransom_ext", Severity: "critical", Detail: "x", Count: 30}, cfg)
	var blocked int
	var note string
	a.st.db.QueryRow(`SELECT blocked, block_note FROM tw_alerts WHERE id=?`, id).Scan(&blocked, &note)
	if blocked != 1 || !strings.Contains(note, "Finance") || !strings.Contains(note, "automatic") {
		t.Fatalf("automatic block: %d %s", blocked, note)
	}
	if _, err := a.twBlock(id, false, "admin"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !strings.Contains(calls[1], "STRATUM_TW_SHARES=Projects|Finance") || !strings.Contains(calls[1], "MODE=unblock") {
		t.Fatalf("unblock must undo exactly the blocked shares: %v", calls)
	}
	// Protected accounts are never blocked automatically.
	id2 := a.twRaise(twAlert{DeviceID: 1, User: `CORP\Administrator`, Rule: "ransom_ext", Severity: "critical", Detail: "x"}, cfg)
	a.st.db.QueryRow(`SELECT blocked, block_note FROM tw_alerts WHERE id=?`, id2).Scan(&blocked, &note)
	if blocked != 0 || !strings.Contains(note, "never-block") {
		t.Fatalf("protected account: %d %s", blocked, note)
	}
	for _, u := range []string{"", `CORP\PC01$`, `NT AUTHORITY\SYSTEM`} {
		if twProtected(cfg, u) == "" {
			t.Errorf("%q must be protected", u)
		}
	}
}

func TestTripwireBlockPowerScale(t *testing.T) {
	var mu sync.Mutex
	shares := map[string][]map[string]any{
		"System": {{"name": "finance", "permissions": []any{map[string]any{"permission": "change", "permission_type": "allow", "trustee": map[string]any{"name": "Everyone", "type": "wellknown"}}}}},
		"zone2":  {{"name": "eng", "permissions": []any{}}},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /session/1/session", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) })
	mux.HandleFunc("GET /platform/1/zones", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"zones":[{"name":"System"},{"name":"zone2"}]}`))
	})
	mux.HandleFunc("GET /platform/1/protocols/smb/shares", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"shares": shares[r.URL.Query().Get("zone")]})
	})
	mux.HandleFunc("PUT /platform/1/protocols/smb/shares/{name}", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Permissions []any `json:"permissions"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		defer mu.Unlock()
		for _, s := range shares[r.URL.Query().Get("zone")] {
			if s["name"] == r.PathValue("name") {
				s["permissions"] = body.Permissions
			}
		}
		w.WriteHeader(204)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	c := newPSClient(srv.URL, 0, "svc", "pw", true)

	res, err := psBlock(c, `CORP\bob`, true, nil)
	if err != nil || len(res.Shares) != 2 {
		t.Fatalf("block: %v %+v", err, res)
	}
	fin := shares["System"][0]["permissions"].([]any)
	if len(fin) != 2 || fin[0].(map[string]any)["permission_type"] != "deny" {
		t.Fatalf("deny entry must come first and existing entries stay: %+v", fin)
	}
	// Blocking twice adds nothing.
	psBlock(c, `CORP\bob`, true, nil)
	if len(shares["System"][0]["permissions"].([]any)) != 2 {
		t.Fatal("second block duplicated the deny entry")
	}
	if _, err := psBlock(c, `corp\BOB`, false, res.Shares); err != nil {
		t.Fatal(err)
	}
	fin = shares["System"][0]["permissions"].([]any)
	if len(fin) != 1 || fin[0].(map[string]any)["permission_type"] != "allow" || len(shares["zone2"][0]["permissions"].([]any)) != 0 {
		t.Fatalf("unblock must remove only the deny entries: %+v / %+v", fin, shares["zone2"])
	}
}

// fakeSMTP accepts one message on localhost and returns what it received.
func fakeSMTP(t *testing.T) (port int, got chan string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		rw := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
		say := func(s string) { rw.WriteString(s + "\r\n"); rw.Flush() }
		say("220 fake ESMTP")
		var data strings.Builder
		inData := false
		for {
			line, err := rw.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					say("250 queued")
					got <- data.String()
					continue
				}
				data.WriteString(line)
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250 fake")
			case strings.HasPrefix(cmd, "DATA"):
				inData = true
				say("354 go ahead")
			case strings.HasPrefix(cmd, "QUIT"):
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, got
}

func TestTripwireEmail(t *testing.T) {
	port, got := fakeSMTP(t)
	cfg := twDefaults()
	cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPTLS, cfg.MailFrom, cfg.MailTo = "127.0.0.1", port, "none", "stratum@example.com", "soc@example.com"
	cfg.LinkURL = "https://stratum.example.com"
	res := twNotify(cfg, twAlert{Rule: "decoy", Severity: "critical", Device: "FS01", User: `CORP\mallory`, Detail: "A decoy file nobody should ever open was changed.", Sample: []string{"D:/x/!000.xlsx"}})
	if len(res) != 1 || res[0] != "Email: sent" {
		t.Fatalf("email result %v", res)
	}
	select {
	case m := <-got:
		if !strings.Contains(m, "Subject: Stratum tripwire: Decoy file touched") || !strings.Contains(m, `CORP\mallory`) || !strings.Contains(m, "https://stratum.example.com/#/tripwire") {
			t.Fatalf("message: %s", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no mail received")
	}
	// STARTTLS required but not offered: a clear error, not a silent clear-text send.
	port2, _ := fakeSMTP(t)
	cfg.SMTPPort, cfg.SMTPTLS = port2, "starttls"
	if r := twNotify(cfg, twAlert{Rule: "test"}); !strings.Contains(r[0], "STARTTLS") {
		t.Fatalf("starttls check: %v", r)
	}
}

// Stratum's own operation names must survive the ingest API's normalization.
func TestNormOpOwnNames(t *testing.T) {
	for in, want := range map[string]string{"modify": "modify", "create": "create", "delete": "delete", "rename": "rename", "read": "read", "write": "modify", "changed": "modify"} {
		if got := normOp(in, ""); got != want {
			t.Errorf("normOp(%q) = %q, want %q", in, got, want)
		}
	}
}
