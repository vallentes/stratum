package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Permissions explorer. During a scan every folder's access list is read (one call
// per folder, files are not read) and stored only where it differs from what the
// folder inherits: the share root, folders with inheritance switched off, and folders
// with entries of their own. Everything below such a folder has the same access, so
// "who can reach what" is answered from a few thousand rows, not millions.

// ACE is one access entry in a normalized, storage-independent form.
type ACE struct {
	Trustee   string `json:"t"`
	SID       string `json:"s,omitempty"`
	Deny      bool   `json:"d,omitempty"`
	Rights    string `json:"r"` // full | modify | write | read | list | special
	Inherited bool   `json:"i,omitempty"`
	Orphan    bool   `json:"o,omitempty"` // a SID that no longer resolves: a deleted account
	Kind      string `json:"k,omitempty"` // user | group | wellknown
}

// DirPerms is the security of one folder.
type DirPerms struct {
	Owner     string
	Protected bool // inheritance from the parent is switched off
	ACEs      []ACE
	// Inheritance is true where the storage marks inherited entries (NTFS, OneFS ACLs).
	// Elsewhere (POSIX mode bits) a folder counts as explicit when it differs from its parent.
	Inheritance bool
}

// permsLister is implemented by listers that can read folder security.
type permsLister interface {
	DirPerms(rel string) (DirPerms, error)
}

// permsOn: folder permissions are collected unless the share switches them off.
func permsOn(s Share) bool {
	var m map[string]any
	json.Unmarshal([]byte(s.Options), &m)
	v, ok := m["perms"]
	return !ok || v == true
}

func (p DirPerms) fingerprint() string {
	var b strings.Builder
	b.WriteString(p.Owner)
	for _, e := range p.ACEs {
		fmt.Fprintf(&b, "|%s %v %s", e.Trustee, e.Deny, e.Rights)
	}
	return b.String()
}

func (p DirPerms) explicit(parentFP string, isRoot bool) bool {
	if isRoot || p.Protected {
		return true
	}
	if p.Inheritance {
		for _, e := range p.ACEs {
			if !e.Inherited {
				return true
			}
		}
		return false
	}
	return p.fingerprint() != parentFP
}

// Well-known groups that mean "practically everybody".
var openSIDs = map[string]bool{"S-1-1-0": true, "S-1-5-11": true, "S-1-5-32-545": true, "S-1-5-7": true, "S-1-5-4": true, "S-1-5-32-546": true}
var openNames = map[string]bool{"everyone": true, "authenticated users": true, "users": true, "domain users": true, "anonymous logon": true,
	"interactive": true, "guests": true, "domain guests": true, "nt authority\\authenticated users": true, "builtin\\users": true, "builtin\\guests": true}

func isOpenTrustee(e ACE) bool {
	if openSIDs[e.SID] || strings.HasSuffix(e.SID, "-513") || strings.HasSuffix(e.SID, "-514") {
		return true
	}
	n := strings.ToLower(e.Trustee)
	if openNames[n] {
		return true
	}
	if i := strings.LastIndexByte(n, '\\'); i >= 0 && openNames[n[i+1:]] {
		return true
	}
	return false
}

// grantsAccess is an allow entry that lets the trustee see file contents.
func grantsAccess(e ACE) bool {
	return !e.Deny && e.Rights != "list" && e.Rights != ""
}

func (p DirPerms) flags() (open, orphan, deny bool) {
	for _, e := range p.ACEs {
		if isOpenTrustee(e) && grantsAccess(e) {
			open = true
		}
		if e.Orphan {
			orphan = true
		}
		if e.Deny {
			deny = true
		}
	}
	return
}

// permsRow records one folder's security when it is explicit.
func (j *scanJob) permsRow(rel string, p DirPerms) {
	fp := p.fingerprint()
	j.fps.Store(rel, fp)
	parent := ""
	if rel != "/" {
		if v, ok := j.fps.Load(path.Dir(rel)); ok {
			parent = v.(string)
		}
	}
	if !p.explicit(parent, rel == "/") {
		return
	}
	open, orphan, deny := p.flags()
	b, _ := json.Marshal(p.ACEs)
	j.out <- row{"p", []any{j.scanID, j.share.ID, rel, p.Owner, b2i(p.Protected), string(b), b2i(open), b2i(orphan), b2i(deny)}}
}

// rightsRank orders rights for "highest access" summaries.
var rightsRank = map[string]int{"list": 1, "special": 2, "read": 3, "write": 4, "modify": 5, "full": 6}

// ---------- API ----------

type permFolder struct {
	ShareID   int64    `json:"share_id"`
	Share     string   `json:"share"`
	Device    string   `json:"device"`
	Path      string   `json:"path"`
	Owner     string   `json:"owner"`
	Protected bool     `json:"protected"`
	Open      bool     `json:"open"`
	Orphan    bool     `json:"orphan"`
	Deny      bool     `json:"deny"`
	ACEs      []ACE    `json:"aces"`
	Files     int64    `json:"files"`
	Bytes     int64    `json:"bytes"`
	Disabled  []string `json:"disabled,omitempty"` // trustees whose directory account is disabled
}

const permSelect = `SELECT p.share_id, s.name, d.name, p.path, p.owner, p.protected, p.aces, p.open, p.orphan, p.deny,
  COALESCE(r.files,0), COALESCE(r.bytes,0)
  FROM perms p JOIN shares s ON s.id=p.share_id AND s.current_scan=p.scan_id JOIN devices d ON d.id=s.device_id
  LEFT JOIN dirs r ON r.scan_id=p.scan_id AND r.path=p.path`

func (a *App) disabledAccounts() map[string]bool {
	out := map[string]bool{}
	rows, err := a.st.db.Query(`SELECT lower(owner) FROM owner_directory WHERE disabled=1`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var o string
		rows.Scan(&o)
		out[o] = true
	}
	return out
}

func (a *App) permFolders(sc Scope, where string, args []any, limit int) ([]permFolder, error) {
	cond, cargs := sc.scans("p.scan_id")
	q := permSelect + ` WHERE ` + cond
	if where != "" {
		q += " AND " + where
	}
	q += ` ORDER BY COALESCE(r.bytes,0) DESC, p.path LIMIT ?`
	rows, err := a.st.db.Query(q, append(append(cargs, args...), limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	dis := a.disabledAccounts()
	out := []permFolder{}
	for rows.Next() {
		var f permFolder
		var prot, open, orph, deny int
		var aces string
		rows.Scan(&f.ShareID, &f.Share, &f.Device, &f.Path, &f.Owner, &prot, &aces, &open, &orph, &deny, &f.Files, &f.Bytes)
		f.Protected, f.Open, f.Orphan, f.Deny = prot == 1, open == 1, orph == 1, deny == 1
		json.Unmarshal([]byte(aces), &f.ACEs)
		for _, e := range f.ACEs {
			if dis[strings.ToLower(e.Trustee)] {
				f.Disabled = append(f.Disabled, e.Trustee)
			}
		}
		out = append(out, f)
	}
	return out, nil
}

var permKinds = map[string]string{
	"open":      "p.open=1",
	"orphan":    "p.orphan=1",
	"protected": "p.protected=1",
	"deny":      "p.deny=1",
	"all":       "",
}

func (a *App) permsSummary(w http.ResponseWriter, r *http.Request) {
	sc := scopeFrom(r)
	cond, args := sc.scans("scan_id")
	var total, open, orphan, prot, deny, shares int64
	a.st.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(open),0), COALESCE(SUM(orphan),0), COALESCE(SUM(protected),0), COALESCE(SUM(deny),0), COUNT(DISTINCT share_id)
	  FROM perms WHERE `+cond, args...).Scan(&total, &open, &orphan, &prot, &deny, &shares)
	var openBytes, openFiles int64
	// Exposed data: open folders that are not inside another open folder (no double counting).
	if ofs, err := a.permFolders(sc, "p.open=1", nil, 5000); err == nil {
		sort.Slice(ofs, func(i, j int) bool { return len(ofs[i].Path) < len(ofs[j].Path) })
		var tops []permFolder
		for _, f := range ofs {
			inside := false
			for _, t := range tops {
				if t.ShareID == f.ShareID && (t.Path == "/" || strings.HasPrefix(f.Path, t.Path+"/")) {
					inside = true
					break
				}
			}
			if !inside {
				tops = append(tops, f)
				openBytes += f.Bytes
				openFiles += f.Files
			}
		}
	}
	// Disabled directory accounts that still hold access somewhere.
	dis := a.disabledAccounts()
	disabled := map[string]int{}
	trustees := map[string]bool{}
	if all, err := a.permFolders(sc, "", nil, 20000); err == nil {
		for _, f := range all {
			for _, e := range f.ACEs {
				trustees[strings.ToLower(e.Trustee)] = true
				if dis[strings.ToLower(e.Trustee)] {
					disabled[e.Trustee]++
				}
			}
		}
	}
	var noPerms int64
	w2, a2 := sc.where()
	a.st.db.QueryRow(`SELECT COUNT(*) FROM shares`+w2+andOr(w2)+`current_scan>0 AND current_scan NOT IN (SELECT DISTINCT scan_id FROM perms)`, a2...).Scan(&noPerms)
	writeJSON(w, map[string]any{"folders": total, "open": open, "orphan": orphan, "protected": prot, "deny": deny, "shares": shares,
		"open_bytes": openBytes, "open_files": openFiles, "disabled": disabled, "trustees": len(trustees), "shares_without": noPerms})
}

func andOr(w string) string {
	if w == "" {
		return " WHERE "
	}
	return " AND "
}

func (a *App) permsList(w http.ResponseWriter, r *http.Request) {
	sc := scopeFrom(r)
	kind := r.URL.Query().Get("kind")
	where, ok := permKinds[kind]
	if !ok {
		where = ""
	}
	var args []any
	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" {
		if where != "" {
			where += " AND "
		}
		where += "(p.path LIKE ? OR p.aces LIKE ? OR p.owner LIKE ?)"
		like := "%" + q + "%"
		args = append(args, like, like, like)
	}
	list, err := a.permFolders(sc, where, args, qInt(r, "limit", 300))
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	if kind == "disabled" {
		var keep []permFolder
		for _, f := range list {
			if len(f.Disabled) > 0 {
				keep = append(keep, f)
			}
		}
		list = keep
		if list == nil {
			list = []permFolder{}
		}
	}
	writeJSON(w, list)
}

type reachRow struct {
	permFolder
	Via    string `json:"via"`
	Rights string `json:"rights"`
	Denied bool   `json:"denied"`
}

// trusteeMatches compares "DOMAIN\name", "name" and SIDs without case.
func trusteeMatches(e ACE, want string) bool {
	w := strings.ToLower(strings.TrimSpace(want))
	t := strings.ToLower(e.Trustee)
	if w == "" {
		return false
	}
	if t == w || strings.EqualFold(e.SID, want) {
		return true
	}
	short := func(s string) string {
		if i := strings.LastIndexByte(s, '\\'); i >= 0 {
			return s[i+1:]
		}
		return s
	}
	return !strings.Contains(w, `\`) && short(t) == w
}

// permsWho answers "what can this account reach": folders whose own entries name the
// account (or one of the extra groups typed in), plus folders open to everybody.
func (a *App) permsWho(w http.ResponseWriter, r *http.Request) {
	sc := scopeFrom(r)
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		httpErr(w, 400, "type an account or group name")
		return
	}
	names := []string{name}
	for _, g := range strings.Split(r.URL.Query().Get("groups"), ",") {
		if g = strings.TrimSpace(g); g != "" {
			names = append(names, g)
		}
	}
	withOpen := r.URL.Query().Get("open") != "0"
	all, err := a.permFolders(sc, "", nil, 50000)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	out := []reachRow{}
	for _, f := range all {
		best, via, denied := "", "", false
		for _, e := range f.ACEs {
			hit := ""
			for _, n := range names {
				if trusteeMatches(e, n) {
					hit = e.Trustee
				}
			}
			if hit == "" && withOpen && isOpenTrustee(e) {
				hit = e.Trustee
			}
			if hit == "" {
				continue
			}
			if e.Deny {
				denied, via = true, hit
				continue
			}
			if rightsRank[e.Rights] > rightsRank[best] {
				best, via = e.Rights, hit
			}
		}
		if best == "" && !denied {
			continue
		}
		out = append(out, reachRow{permFolder: f, Via: via, Rights: best, Denied: denied})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if len(out) > 500 {
		out = out[:500]
	}
	writeJSON(w, map[string]any{"name": name, "rows": out})
}

// permsFolder returns the access that applies to any folder: its own entry, or the
// nearest parent with explicit permissions.
func (a *App) permsFolder(w http.ResponseWriter, r *http.Request) {
	shareID := qInt64(r, "share")
	p := path.Clean("/" + strings.TrimPrefix(r.URL.Query().Get("path"), "/"))
	sh, err := a.share(shareID)
	if err != nil || sh.CurrentScan == 0 {
		httpErr(w, 404, "share not indexed")
		return
	}
	for cur := p; ; cur = path.Dir(cur) {
		var owner, aces string
		var prot int
		if a.st.db.QueryRow(`SELECT owner, aces, protected FROM perms WHERE scan_id=? AND path=?`, sh.CurrentScan, cur).Scan(&owner, &aces, &prot) == nil {
			var list []ACE
			json.Unmarshal([]byte(aces), &list)
			writeJSON(w, map[string]any{"path": p, "from": cur, "owner": owner, "protected": prot == 1, "aces": list})
			return
		}
		if cur == "/" {
			break
		}
	}
	writeJSON(w, map[string]any{"path": p, "from": "", "aces": []ACE{}})
}

func (a *App) permsCSV(w http.ResponseWriter, r *http.Request) {
	sc := scopeFrom(r)
	where := permKinds[r.URL.Query().Get("kind")]
	list, err := a.permFolders(sc, where, nil, 200000)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	cw := csvStart(w, "permissions.csv")
	cw.Write([]string{"device", "share", "folder", "owner", "inheritance_off", "open_to_everyone", "deleted_account", "has_deny", "files_below", "bytes_below", "trustee", "allow_or_deny", "rights", "inherited"})
	for _, f := range list {
		for _, e := range f.ACEs {
			ad := "allow"
			if e.Deny {
				ad = "deny"
			}
			cw.Write([]string{f.Device, f.Share, f.Path, f.Owner, yn(f.Protected), yn(f.Open), yn(e.Orphan), yn(f.Deny),
				strconv.FormatInt(f.Files, 10), strconv.FormatInt(f.Bytes, 10), e.Trustee, ad, e.Rights, yn(e.Inherited)})
		}
	}
	cw.Flush()
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// trusteesForDirectory lists account names found in access entries, so the directory
// sync can tell which of them are disabled.
func (a *App) trusteesForDirectory() []string {
	rows, err := a.st.db.Query(`SELECT aces FROM perms WHERE scan_id IN (SELECT current_scan FROM shares)`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var s string
		rows.Scan(&s)
		var list []ACE
		json.Unmarshal([]byte(s), &list)
		for _, e := range list {
			if e.Kind == "user" && strings.Contains(e.Trustee, `\`) && !seen[e.Trustee] && !isOpenTrustee(e) {
				seen[e.Trustee] = true
				out = append(out, e.Trustee)
			}
		}
	}
	return out
}

// windowsRights turns an NTFS access mask into a plain label.
func windowsRights(mask uint32) string {
	const (
		genericAll   = 0x10000000
		genericWrite = 0x40000000
		genericRead  = 0x80000000
		genericExec  = 0x20000000
		writeDAC     = 0x40000
		writeOwner   = 0x80000
		del          = 0x10000
		delChild     = 0x40
		writeData    = 0x2
		appendData   = 0x4
		readData     = 0x1
		traverse     = 0x20
		readAttrs    = 0x80
		readEA       = 0x8
	)
	switch {
	case mask&genericAll != 0, mask&0x1F01FF == 0x1F01FF, mask&(writeDAC|writeOwner) != 0:
		return "full"
	}
	wr := mask&(writeData|appendData|genericWrite) != 0
	if wr && mask&(del|delChild) != 0 {
		return "modify"
	}
	if wr {
		return "write"
	}
	if mask&(readData|genericRead) != 0 {
		return "read"
	}
	if mask&(traverse|readAttrs|readEA|genericExec) != 0 {
		return "list"
	}
	return "special"
}

// posixPerms models mode bits as three entries: owner, group, everyone else.
func posixPerms(owner, group string, mode uint32) DirPerms {
	label := func(bits uint32, isOwner bool) string {
		r, w, x := bits&4 != 0, bits&2 != 0, bits&1 != 0
		switch {
		case isOwner:
			return "full" // the owner can always change the mode
		case r && w && x:
			return "modify"
		case r:
			return "read"
		case x:
			return "list"
		}
		return ""
	}
	p := DirPerms{Owner: owner}
	add := func(t, kind string, bits uint32, isOwner bool) {
		if l := label(bits, isOwner); l != "" {
			p.ACEs = append(p.ACEs, ACE{Trustee: t, Rights: l, Kind: kind})
		}
	}
	add(owner, "user", (mode>>6)&7, true)
	add(group, "group", (mode>>3)&7, false)
	add("Everyone", "wellknown", mode&7, false)
	return p
}

// oneFSRights maps OneFS access rights names to a plain label.
func oneFSRights(rights []string) string {
	best := ""
	set := func(l string) {
		if rightsRank[l] > rightsRank[best] {
			best = l
		}
	}
	has := map[string]bool{}
	for _, r := range rights {
		has[r] = true
	}
	for _, r := range rights {
		switch {
		case strings.HasSuffix(r, "_gen_all"), r == "full_control", r == "std_write_dac", r == "std_write_owner":
			set("full")
		case r == "modify":
			set("modify")
		case strings.HasSuffix(r, "_gen_write"), r == "add_file", r == "add_subdir", r == "file_write", r == "append":
			if has["std_delete"] || has["delete_child"] {
				set("modify")
			} else {
				set("write")
			}
		case strings.HasSuffix(r, "_gen_read"), r == "list", r == "file_read":
			set("read")
		case r == "traverse", strings.HasSuffix(r, "_gen_execute"), r == "std_read_dac", r == "file_read_attr":
			set("list")
		}
	}
	if best == "" {
		return "special"
	}
	return best
}
