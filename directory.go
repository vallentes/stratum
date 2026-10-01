package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Active Directory org view. Folder owners (DOMAIN\user) are looked up over LDAP for
// department, title, OU and enabled state, then capacity is rolled up by department
// and by the OU tree. Lookups run on the server or on a collector inside the domain.

type ldapCfg struct {
	URL         string `json:"url"` // ldaps://dc01.corp.local:636 or ldap://dc01:389
	BindUser    string `json:"bind_user"`
	Password    string `json:"password,omitempty"`
	BaseDN      string `json:"base_dn"`
	Insecure    bool   `json:"insecure"`
	CollectorID int64  `json:"collector_id"`
}

type dirEntry struct {
	Owner      string `json:"owner"`
	Display    string `json:"display"`
	DN         string `json:"dn"`
	OU         string `json:"ou"`
	Department string `json:"department"`
	Title      string `json:"title"`
	Disabled   bool   `json:"disabled"`
	Error      string `json:"error,omitempty"`
}

func (a *App) ldapConfig() ldapCfg {
	var c ldapCfg
	json.Unmarshal([]byte(a.st.setting("ldap")), &c)
	if c.Password != "" {
		c.Password, _ = a.unseal(c.Password)
	}
	return c
}

// ouPath turns "CN=Ann,OU=Finance,OU=Staff,DC=corp,DC=local" into "corp.local/Staff/Finance".
func ouPath(dn string) string {
	parts := strings.Split(dn, ",")
	var dc, ou []string
	for _, p := range parts {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok {
			continue
		}
		switch strings.ToUpper(k) {
		case "DC":
			dc = append(dc, v)
		case "OU":
			ou = append([]string{v}, ou...)
		}
	}
	return strings.Join(append([]string{strings.Join(dc, ".")}, ou...), "/")
}

func skipOwner(o string) bool {
	u := strings.ToUpper(o)
	return o == "" || strings.HasPrefix(u, "BUILTIN\\") || strings.HasPrefix(u, "NT AUTHORITY\\") || strings.HasPrefix(u, "NT SERVICE\\") ||
		strings.HasPrefix(u, "S-1-") || strings.HasPrefix(u, "CREATOR ") || u == "EVERYONE"
}

// ldapResolve looks owners up in the directory. Runs wherever the DCs are reachable.
func ldapResolve(c ldapCfg, owners []string) ([]dirEntry, error) {
	if c.URL == "" || c.BaseDN == "" {
		return nil, errors.New("directory is not configured")
	}
	conn, err := ldap.DialURL(c.URL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: c.Insecure}))
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", c.URL, err)
	}
	defer conn.Close()
	conn.SetTimeout(30 * time.Second)
	if err := conn.Bind(c.BindUser, c.Password); err != nil {
		return nil, fmt.Errorf("bind as %s: %w", c.BindUser, err)
	}
	var out []dirEntry
	for _, o := range owners {
		e := dirEntry{Owner: o}
		if strings.HasPrefix(strings.ToUpper(o), "S-1-5-21-") {
			e.Error = "unresolved SID (account deleted)"
			out = append(out, e)
			continue
		}
		sam := o
		if i := strings.LastIndexByte(o, '\\'); i >= 0 {
			sam = o[i+1:]
		}
		req := ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 20, false,
			fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(sam)),
			[]string{"distinguishedName", "displayName", "department", "title", "userAccountControl"}, nil)
		res, err := conn.Search(req)
		if err != nil || len(res.Entries) == 0 {
			e.Error = "not found in directory"
			if err != nil {
				e.Error = err.Error()
			}
			out = append(out, e)
			continue
		}
		en := res.Entries[0]
		e.DN = en.DN
		e.OU = ouPath(en.DN)
		e.Display = en.GetAttributeValue("displayName")
		e.Department = en.GetAttributeValue("department")
		e.Title = en.GetAttributeValue("title")
		var uac int
		fmt.Sscan(en.GetAttributeValue("userAccountControl"), &uac)
		e.Disabled = uac&2 != 0
		out = append(out, e)
	}
	return out, nil
}

// syncDirectory resolves every folder owner in the published indexes.
func (a *App) syncDirectory() (int, error) {
	c := a.ldapConfig()
	rows, err := a.st.db.Query(`SELECT DISTINCT owner FROM dirs WHERE scan_id IN (SELECT current_scan FROM shares)`)
	if err != nil {
		return 0, err
	}
	var owners []string
	for rows.Next() {
		var o string
		rows.Scan(&o)
		if !skipOwner(o) || strings.HasPrefix(strings.ToUpper(o), "S-1-5-21-") {
			owners = append(owners, o)
		}
	}
	rows.Close()
	var res []dirEntry
	if c.CollectorID > 0 {
		raw, err := a.runTask(c.CollectorID, "ldap", map[string]any{"config": c, "owners": owners}, 5*time.Minute)
		if err != nil {
			return 0, err
		}
		if err := json.Unmarshal(raw, &res); err != nil {
			return 0, err
		}
	} else if res, err = ldapResolve(c, owners); err != nil {
		return 0, err
	}
	for _, e := range res {
		a.st.db.Exec(`INSERT INTO owner_directory(owner,display,dn,ou,department,title,disabled,resolved_at,error) VALUES(?,?,?,?,?,?,?,?,?)
		  ON CONFLICT(owner) DO UPDATE SET display=excluded.display, dn=excluded.dn, ou=excluded.ou, department=excluded.department,
		  title=excluded.title, disabled=excluded.disabled, resolved_at=excluded.resolved_at, error=excluded.error`,
			e.Owner, e.Display, e.DN, e.OU, e.Department, e.Title, b2i(e.Disabled), now(), e.Error)
	}
	return len(res), nil
}

func (a *App) directoryRoutes(m *http.ServeMux) {
	g := func(p string, fn h) { m.HandleFunc(p, a.guardFor(p, fn)) }
	g("GET /api/directory/config", func(w http.ResponseWriter, r *http.Request) {
		c := a.ldapConfig()
		has := c.Password != ""
		c.Password = ""
		var n, resolved int64
		a.st.db.QueryRow(`SELECT COUNT(*), SUM(CASE WHEN error='' THEN 1 ELSE 0 END) FROM owner_directory`).Scan(&n, &resolved)
		writeJSON(w, map[string]any{"config": c, "has_password": has, "owners": n, "resolved": resolved, "last_sync": a.st.setting("ldap_last_sync")})
	})
	g("PUT /api/directory/config", func(w http.ResponseWriter, r *http.Request) {
		var in ldapCfg
		if err := readJSON(r, &in); err != nil {
			httpErr(w, 400, "bad request")
			return
		}
		old := a.ldapConfig()
		if in.Password == "" {
			in.Password = old.Password
		}
		if in.Password != "" {
			in.Password = a.seal(in.Password)
		}
		b, _ := json.Marshal(in)
		a.st.setSetting("ldap", string(b))
		writeJSON(w, map[string]any{"ok": true})
	})
	g("POST /api/directory/sync", func(w http.ResponseWriter, r *http.Request) {
		n, err := a.syncDirectory()
		if err != nil {
			httpErr(w, 502, err.Error())
			return
		}
		a.st.setSetting("ldap_last_sync", fmt.Sprint(now()))
		writeJSON(w, map[string]any{"resolved": n})
	})
	g("GET /api/owners/org", a.ownersOrg)
}

type orgNode struct {
	Name     string     `json:"name"`
	Path     string     `json:"path"`
	Bytes    int64      `json:"bytes"`
	Files    int64      `json:"files"`
	Owners   int64      `json:"owners"`
	Activity int64      `json:"activity_30d"`
	Children []*orgNode `json:"children,omitempty"`
}

func (a *App) ownersOrg(w http.ResponseWriter, r *http.Request) {
	sc := scopeFrom(r)
	cond, args := sc.scans("d.scan_id")
	type row struct {
		owner, dept, ou string
		disabled        bool
		err             string
		bytes, files    int64
	}
	rows, err := a.st.db.Query(`SELECT d.owner, COALESCE(o.department,''), COALESCE(o.ou,''), COALESCE(o.disabled,0), COALESCE(o.error,'?'), SUM(d.own_bytes), SUM(d.own_files)
	  FROM dirs d LEFT JOIN owner_directory o ON o.owner=d.owner WHERE `+cond+` GROUP BY d.owner`, args...)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	var list []row
	for rows.Next() {
		var x row
		var dis int
		rows.Scan(&x.owner, &x.dept, &x.ou, &dis, &x.err, &x.bytes, &x.files)
		x.disabled = dis == 1
		list = append(list, x)
	}
	rows.Close()
	// Audit activity per account (matched on the user part, case-insensitive).
	act := map[string]int64{}
	arows, _ := a.st.db.Query(`SELECT username, SUM(count) FROM audit WHERE ts >= ? GROUP BY username`, now()-30*86400)
	for arows != nil && arows.Next() {
		var u string
		var c int64
		arows.Scan(&u, &c)
		if i := strings.LastIndexByte(u, '\\'); i >= 0 {
			u = u[i+1:]
		}
		act[strings.ToLower(u)] += c
	}
	if arows != nil {
		arows.Close()
	}
	actOf := func(owner string) int64 {
		if i := strings.LastIndexByte(owner, '\\'); i >= 0 {
			owner = owner[i+1:]
		}
		return act[strings.ToLower(owner)]
	}
	depts := map[string]*orgNode{}
	root := &orgNode{Name: "All", Path: ""}
	var disabledBytes, unresolvedBytes, systemBytes int64
	for _, x := range list {
		label := x.dept
		switch {
		case skipOwner(x.owner) && !strings.HasPrefix(strings.ToUpper(x.owner), "S-1-5-21-"):
			label = "(system and built-in accounts)"
			systemBytes += x.bytes
		case x.err != "" && x.err != "?":
			label = "(not in directory)"
			unresolvedBytes += x.bytes
		case x.err == "?":
			label = "(not looked up yet)"
		case label == "":
			label = "(no department set)"
		}
		if x.disabled {
			disabledBytes += x.bytes
		}
		dn := depts[label]
		if dn == nil {
			dn = &orgNode{Name: label, Path: label}
			depts[label] = dn
		}
		dn.Bytes, dn.Files, dn.Owners, dn.Activity = dn.Bytes+x.bytes, dn.Files+x.files, dn.Owners+1, dn.Activity+actOf(x.owner)
		// OU tree
		ou := x.ou
		if ou == "" {
			ou = label
		}
		node := root
		node.Bytes, node.Files, node.Owners = node.Bytes+x.bytes, node.Files+x.files, node.Owners+1
		p := ""
		for _, part := range strings.Split(ou, "/") {
			p += "/" + part
			var next *orgNode
			for _, c := range node.Children {
				if c.Name == part {
					next = c
				}
			}
			if next == nil {
				next = &orgNode{Name: part, Path: p}
				node.Children = append(node.Children, next)
			}
			next.Bytes, next.Files, next.Owners, next.Activity = next.Bytes+x.bytes, next.Files+x.files, next.Owners+1, next.Activity+actOf(x.owner)
			node = next
		}
	}
	var dl []*orgNode
	for _, d := range depts {
		dl = append(dl, d)
	}
	sort.Slice(dl, func(i, j int) bool { return dl[i].Bytes > dl[j].Bytes })
	var sortTree func(n *orgNode)
	sortTree = func(n *orgNode) {
		sort.Slice(n.Children, func(i, j int) bool { return n.Children[i].Bytes > n.Children[j].Bytes })
		for _, c := range n.Children {
			sortTree(c)
		}
	}
	sortTree(root)
	c := a.ldapConfig()
	writeJSON(w, map[string]any{"configured": c.URL != "", "departments": dl, "tree": root,
		"disabled_bytes": disabledBytes, "unresolved_bytes": unresolvedBytes, "system_bytes": systemBytes})
}
