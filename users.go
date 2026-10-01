package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Users and roles.
//
//	viewer  read-only reports and search; cannot open file contents
//	editor  + manage sources, scans, tags, automations, view and download files
//	admin   + users, settings, collectors, turning file auditing on or off
//
// A fresh install has one user, admin / admin, that must change its password at the
// first sign-in. Installs from before users existed keep their admin password.

const (
	roleViewer = 1
	roleEditor = 2
	roleAdmin  = 3
)

var roleNames = map[int]string{roleViewer: "viewer", roleEditor: "editor", roleAdmin: "admin"}

func roleLevel(name string) int {
	for k, v := range roleNames {
		if v == name {
			return k
		}
	}
	return 0
}

const usersSchema = `
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE, pass_hash TEXT, role TEXT,
  must_change INTEGER DEFAULT 0, disabled INTEGER DEFAULT 0, created INTEGER, last_login INTEGER DEFAULT 0);
`

const defaultAdminPassword = "admin"

type User struct {
	ID         int64  `json:"id"`
	Username   string `json:"username"`
	Role       string `json:"role"`
	MustChange bool   `json:"must_change"`
	Disabled   bool   `json:"disabled"`
	Created    int64  `json:"created"`
	LastLogin  int64  `json:"last_login"`
}

// ensureUsers creates the users table and the first admin.
func (a *App) ensureUsers() {
	a.st.db.Exec(usersSchema)
	a.st.db.Exec(`ALTER TABLE sessions ADD COLUMN user_id INTEGER DEFAULT 0`)
	var n int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	if n > 0 {
		return
	}
	if old := a.st.setting("admin_hash"); old != "" {
		// Upgrade: keep the password the single admin already had.
		a.st.db.Exec(`INSERT INTO users(username,pass_hash,role,must_change,created) VALUES('admin',?,'admin',0,?)`, old, now())
		a.st.db.Exec(`DELETE FROM sessions`) // old sessions had no user attached
		return
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(defaultAdminPassword), bcrypt.DefaultCost)
	a.st.db.Exec(`INSERT INTO users(username,pass_hash,role,must_change,created) VALUES('admin',?,'admin',1,?)`, string(h), now())
}

func (a *App) setUserPassword(id int64, pw string, mustChange bool) {
	h, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	a.st.db.Exec(`UPDATE users SET pass_hash=?, must_change=? WHERE id=?`, string(h), b2i(mustChange), id)
}

func validPassword(pw string) string {
	if len(pw) < 10 {
		return "use at least 10 characters"
	}
	if strings.TrimSpace(pw) != pw {
		return "a password cannot start or end with a space"
	}
	if strings.EqualFold(pw, defaultAdminPassword) {
		return "choose something other than the default password"
	}
	return ""
}

// ---- sessions carry the user ----

type ctxKey int

const userKey ctxKey = 1

func userFrom(r *http.Request) *User {
	u, _ := r.Context().Value(userKey).(*User)
	return u
}

func (a *App) sessionUser(r *http.Request) *User {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	var exp, uid int64
	if a.st.db.QueryRow(`SELECT expires, COALESCE(user_id,0) FROM sessions WHERE token=?`, c.Value).Scan(&exp, &uid) != nil || exp < now() || uid == 0 {
		return nil
	}
	u := &User{}
	var mc, dis int
	if a.st.db.QueryRow(`SELECT id, username, role, must_change, disabled FROM users WHERE id=?`, uid).Scan(&u.ID, &u.Username, &u.Role, &mc, &dis) != nil || dis == 1 {
		return nil
	}
	u.MustChange = mc == 1
	if exp-now() < 11*3600 { // sliding, written at most every hour
		a.st.db.Exec(`UPDATE sessions SET expires=? WHERE token=?`, now()+12*3600, c.Value)
	}
	return u
}

func (a *App) authed(r *http.Request) bool { return a.sessionUser(r) != nil }

// Route permissions: reads need viewer, changes need editor, these need more.
var routeRoles = map[string]int{
	"GET /api/view":                       roleEditor, // file contents
	"GET /api/viewlog":                    roleAdmin,
	"GET /download/{name}":                roleEditor,
	"GET /api/collectors":                 roleViewer,
	"POST /api/collectors":                roleAdmin,
	"POST /api/collectors/{id}/token":     roleAdmin,
	"POST /api/collectors/{id}/installer": roleAdmin,
	"DELETE /api/collectors/{id}":         roleAdmin,
	"POST /api/devices/{id}/enable-audit": roleAdmin, // changes Windows security settings
	"POST /api/settings/ingest-token":     roleAdmin,
	"PUT /api/settings/costs":             roleAdmin,
	"GET /api/directory/config":           roleAdmin,
	"PUT /api/directory/config":           roleAdmin,
	"POST /api/directory/sync":            roleAdmin,
	"GET /api/users":                      roleAdmin,
	"POST /api/users":                     roleAdmin,
	"PUT /api/users/{id}":                 roleAdmin,
	"DELETE /api/users/{id}":              roleAdmin,
	"POST /api/password":                  roleViewer, // everyone can change their own
}

func requiredRole(pattern string) int {
	if r, ok := routeRoles[pattern]; ok {
		return r
	}
	if strings.HasPrefix(pattern, "GET ") {
		return roleViewer
	}
	return roleEditor
}

// guardFor wraps a handler with sign-in, forced password change and role checks.
func (a *App) guardFor(pattern string, fn h) http.HandlerFunc {
	need := requiredRole(pattern)
	return func(w http.ResponseWriter, r *http.Request) {
		u := a.sessionUser(r)
		if u == nil {
			httpErr(w, 401, "sign in required")
			return
		}
		if u.MustChange && pattern != "POST /api/password" {
			httpErr(w, 403, "change your password first")
			return
		}
		if roleLevel(u.Role) < need {
			httpErr(w, 403, "your role ("+u.Role+") cannot do this; ask an admin")
			return
		}
		fn(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	}
}

// ---- login with throttling ----

type loginGuard struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

var logins = &loginGuard{fails: map[string][]time.Time{}}

const (
	loginWindow   = 15 * time.Minute
	loginMaxFails = 10
	loginPause    = time.Minute
)

// blocked allows 10 failures per username+address in 15 minutes, then pauses sign-in for
// that pair for one minute after the latest failure. It returns the time left.
func (g *loginGuard) blocked(key string) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	var keep []time.Time
	for _, t := range g.fails[key] {
		if time.Since(t) < loginWindow {
			keep = append(keep, t)
		}
	}
	g.fails[key] = keep
	if len(keep) < loginMaxFails {
		return 0
	}
	return loginPause - time.Since(keep[len(keep)-1])
}

// failures returns the number of recent failures for the pair.
func (g *loginGuard) failures(key string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.fails[key])
}

func (g *loginGuard) fail(key string) {
	g.mu.Lock()
	g.fails[key] = append(g.fails[key], time.Now())
	g.mu.Unlock()
}

func (g *loginGuard) clear(key string) {
	g.mu.Lock()
	delete(g.fails, key)
	g.mu.Unlock()
}

func clientIP(r *http.Request) string {
	h := r.RemoteAddr
	if i := strings.LastIndexByte(h, ':'); i > 0 {
		h = h[:i]
	}
	return h
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	readJSON(r, &in)
	if strings.TrimSpace(in.Username) == "" {
		in.Username = "admin"
	}
	in.Username = strings.TrimSpace(in.Username)
	ip := clientIP(r)
	key := strings.ToLower(in.Username) + "|" + ip
	if left := logins.blocked(key); left > 0 {
		httpErr(w, 429, fmt.Sprintf("too many failed attempts; try again in %d seconds", int(left.Seconds())+1))
		return
	}
	var id int64
	var hash string
	var mc, dis int
	err := a.st.db.QueryRow(`SELECT id, pass_hash, must_change, disabled FROM users WHERE username=?`, in.Username).Scan(&id, &hash, &mc, &dis)
	reason := ""
	switch {
	case err != nil:
		reason = "no such user"
	case dis == 1:
		reason = "user is disabled"
	case !passwordMatches(hash, in.Password):
		reason = fmt.Sprintf("wrong password (%d characters received)", len(in.Password))
	}
	if reason != "" {
		logins.fail(key)
		log.Printf("sign-in failed for %q from %s: %s", in.Username, ip, reason)
		time.Sleep(700 * time.Millisecond)
		msg := "wrong username or password"
		if n := logins.failures(key); n >= loginMaxFails-3 && n < loginMaxFails {
			msg += fmt.Sprintf(" (%d tries left before a one-minute pause)", loginMaxFails-n)
		}
		if dis == 1 && err == nil {
			msg = "this account is disabled; ask an admin"
		}
		httpErr(w, 401, msg)
		return
	}
	logins.clear(key)
	tok := randHex(24)
	a.st.db.Exec(`DELETE FROM sessions WHERE expires < ?`, now())
	a.st.db.Exec(`INSERT INTO sessions(token,expires,user_id) VALUES(?,?,?)`, tok, now()+12*3600, id)
	a.st.db.Exec(`UPDATE users SET last_login=? WHERE id=?`, now(), id)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https", SameSite: http.SameSiteStrictMode})
	writeJSON(w, map[string]any{"ok": true, "must_change": mc == 1})
}

// passwordMatches also accepts the password without surrounding spaces, which password
// managers and copy-paste add by accident. New passwords cannot start or end with a space.
func passwordMatches(hash, pw string) bool {
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil {
		return true
	}
	t := strings.TrimSpace(pw)
	return t != pw && t != "" && bcrypt.CompareHashAndPassword([]byte(hash), []byte(t)) == nil
}

// defaultPasswordInUse reports whether the admin account still has the install password,
// so the sign-in page only mentions admin / admin when it would work.
func (a *App) defaultPasswordInUse() bool {
	var hash string
	var mc int
	if a.st.db.QueryRow(`SELECT pass_hash, must_change FROM users WHERE username='admin' AND disabled=0`).Scan(&hash, &mc) != nil || mc == 0 {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(defaultAdminPassword)) == nil
}

func (a *App) changePassword(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var in struct{ Current, New string }
	readJSON(r, &in)
	var hash string
	a.st.db.QueryRow(`SELECT pass_hash FROM users WHERE id=?`, u.ID).Scan(&hash)
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Current)) != nil {
		httpErr(w, 400, "current password is wrong")
		return
	}
	if msg := validPassword(in.New); msg != "" {
		httpErr(w, 400, msg)
		return
	}
	a.setUserPassword(u.ID, in.New, false)
	// Sign out every other session of this user.
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.st.db.Exec(`DELETE FROM sessions WHERE user_id=? AND token<>?`, u.ID, c.Value)
	}
	writeJSON(w, map[string]any{"ok": true})
}

// ---- user management (admin) ----

func (a *App) listUsers(w http.ResponseWriter, r *http.Request) {
	rows, _ := a.st.db.Query(`SELECT id, username, role, must_change, disabled, created, last_login FROM users ORDER BY username`)
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		var mc, dis int
		rows.Scan(&u.ID, &u.Username, &u.Role, &mc, &dis, &u.Created, &u.LastLogin)
		u.MustChange, u.Disabled = mc == 1, dis == 1
		out = append(out, u)
	}
	writeJSON(w, out)
}

func (a *App) activeAdmins(except int64) int {
	var n int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0 AND id<>?`, except).Scan(&n)
	return n
}

func (a *App) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password, Role string }
	readJSON(r, &in)
	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" || strings.ContainsAny(in.Username, " \t/\\") {
		httpErr(w, 400, "username is required and cannot contain spaces or slashes")
		return
	}
	if roleLevel(in.Role) == 0 {
		httpErr(w, 400, "role must be viewer, editor or admin")
		return
	}
	if len(in.Password) < 10 {
		httpErr(w, 400, "temporary password needs at least 10 characters")
		return
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	res, err := a.st.db.Exec(`INSERT INTO users(username,pass_hash,role,must_change,created) VALUES(?,?,?,1,?)`, in.Username, string(h), in.Role, now())
	if err != nil {
		httpErr(w, 409, "that username is taken")
		return
	}
	id, _ := res.LastInsertId()
	writeJSON(w, map[string]any{"id": id})
}

func (a *App) updateUser(w http.ResponseWriter, r *http.Request) {
	me := userFrom(r)
	id := idOf(r)
	var in struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
		Password string  `json:"password"` // admin reset: user must change it at next sign-in
	}
	readJSON(r, &in)
	var role string
	if a.st.db.QueryRow(`SELECT role FROM users WHERE id=?`, id).Scan(&role) != nil {
		httpErr(w, 404, "user not found")
		return
	}
	losingAdmin := role == "admin" && ((in.Role != nil && *in.Role != "admin") || (in.Disabled != nil && *in.Disabled))
	if losingAdmin && a.activeAdmins(id) == 0 {
		httpErr(w, 400, "keep at least one active admin")
		return
	}
	if id == me.ID && in.Disabled != nil && *in.Disabled {
		httpErr(w, 400, "you cannot disable yourself")
		return
	}
	if in.Role != nil {
		if roleLevel(*in.Role) == 0 {
			httpErr(w, 400, "role must be viewer, editor or admin")
			return
		}
		a.st.db.Exec(`UPDATE users SET role=? WHERE id=?`, *in.Role, id)
	}
	if in.Disabled != nil {
		a.st.db.Exec(`UPDATE users SET disabled=? WHERE id=?`, b2i(*in.Disabled), id)
		if *in.Disabled {
			a.st.db.Exec(`DELETE FROM sessions WHERE user_id=?`, id)
		}
	}
	if in.Password != "" {
		if len(in.Password) < 10 {
			httpErr(w, 400, "temporary password needs at least 10 characters")
			return
		}
		a.setUserPassword(id, in.Password, true)
		a.st.db.Exec(`DELETE FROM sessions WHERE user_id=?`, id)
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) deleteUser(w http.ResponseWriter, r *http.Request) {
	me := userFrom(r)
	id := idOf(r)
	if id == me.ID {
		httpErr(w, 400, "you cannot delete yourself")
		return
	}
	var role string
	a.st.db.QueryRow(`SELECT role FROM users WHERE id=?`, id).Scan(&role)
	if role == "admin" && a.activeAdmins(id) == 0 {
		httpErr(w, 400, "keep at least one active admin")
		return
	}
	a.st.db.Exec(`DELETE FROM sessions WHERE user_id=?`, id)
	a.st.db.Exec(`DELETE FROM users WHERE id=?`, id)
	writeJSON(w, map[string]any{"ok": true})
}
