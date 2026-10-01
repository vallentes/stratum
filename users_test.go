package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type client struct {
	t      *testing.T
	srv    *httptest.Server
	cookie *http.Cookie
}

func (c *client) do(method, path, body string) (int, string) {
	req, _ := http.NewRequest(method, c.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie {
			c.cookie = ck
		}
	}
	b := new(strings.Builder)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp.StatusCode, b.String()
}

func TestUsersAndRoles(t *testing.T) {
	a := newTestApp(t)
	a.ensureUsers()
	mux := http.NewServeMux()
	a.routes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	admin := &client{t: t, srv: srv}

	// Fresh install: admin/admin works but must change the password before anything else.
	if code, body := admin.do("POST", "/api/login", `{"username":"admin","password":"admin"}`); code != 200 || !strings.Contains(body, `"must_change":true`) {
		t.Fatalf("default login: %d %s", code, body)
	}
	if code, _ := admin.do("GET", "/api/devices", ""); code != 403 {
		t.Fatalf("must_change should block other calls, got %d", code)
	}
	if code, body := admin.do("POST", "/api/password", `{"current":"admin","new":"admin"}`); code != 400 || !strings.Contains(body, "least 10") {
		t.Fatalf("weak password accepted: %d %s", code, body)
	}
	if code, _ := admin.do("POST", "/api/password", `{"current":"admin","new":"a-much-better-one"}`); code != 200 {
		t.Fatal("password change failed")
	}
	if code, _ := admin.do("GET", "/api/devices", ""); code != 200 {
		t.Fatal("admin blocked after changing password")
	}

	// Admin creates a viewer; the viewer must change its temporary password, then can read but not change or open files.
	if code, body := admin.do("POST", "/api/users", `{"username":"ana","password":"temporary-pass","role":"viewer"}`); code != 200 {
		t.Fatalf("create user: %d %s", code, body)
	}
	viewer := &client{t: t, srv: srv}
	viewer.do("POST", "/api/login", `{"username":"ANA","password":"temporary-pass"}`) // usernames are case-insensitive
	viewer.do("POST", "/api/password", `{"current":"temporary-pass","new":"ana-own-password"}`)
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/api/devices", 200},
		{"POST", "/api/devices", 403},
		{"GET", "/api/view?share=1&path=/x", 403},
		{"GET", "/api/users", 403},
		{"POST", "/api/collectors", 403},
	} {
		if code, _ := viewer.do(c.method, c.path, `{}`); code != c.want {
			t.Errorf("viewer %s %s = %d, want %d", c.method, c.path, code, c.want)
		}
	}

	// The last admin cannot be demoted, disabled or deleted.
	var adminID int64
	a.st.db.QueryRow(`SELECT id FROM users WHERE username='admin'`).Scan(&adminID)
	if code, body := admin.do("PUT", "/api/users/"+itoa(int(adminID)), `{"role":"viewer"}`); code != 400 || !strings.Contains(body, "at least one active admin") {
		t.Fatalf("demoting last admin: %d %s", code, body)
	}
	// Disabling a user ends its sessions immediately.
	var anaID int64
	a.st.db.QueryRow(`SELECT id FROM users WHERE username='ana'`).Scan(&anaID)
	admin.do("PUT", "/api/users/"+itoa(int(anaID)), `{"disabled":true}`)
	if code, _ := viewer.do("GET", "/api/devices", ""); code != 401 {
		t.Fatalf("disabled user still signed in: %d", code)
	}
	// Repeated wrong passwords are throttled.
	bad := &client{t: t, srv: srv}
	var last int
	for i := 0; i < 6; i++ {
		last, _ = bad.do("POST", "/api/login", `{"username":"admin","password":"nope"}`)
	}
	if last != 429 {
		t.Fatalf("no throttling after repeated failures, last status %d", last)
	}
}

func TestUpgradeKeepsAdminPassword(t *testing.T) {
	a := newTestApp(t)
	h := "$2a$10$abcdefghijklmnopqrstuuJ6wq3mSXo8vAvhvd0jjfR.lmBy4ZB1W" // any existing bcrypt hash
	a.st.setSetting("admin_hash", h)
	a.ensureUsers()
	var got string
	var mc int
	a.st.db.QueryRow(`SELECT pass_hash, must_change FROM users WHERE username='admin'`).Scan(&got, &mc)
	if got != h || mc != 0 {
		t.Fatalf("upgrade did not keep the old admin password (must_change=%d)", mc)
	}
}
