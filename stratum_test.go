package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeOneFS serves a tiny /ifs tree over RAN plus the PAPI endpoints we call.
// Field names follow the OneFS 9.x API reference; this is not a live cluster.
func fakeOneFS(t *testing.T) *httptest.Server {
	type node struct {
		kind string
		size int64
		kids []string
	}
	tree := map[string]node{
		"/ifs/data/dfs":                          {kind: "container", kids: []string{"mydata", "locky_test2", "link1"}},
		"/ifs/data/dfs/mydata":                   {kind: "container", kids: []string{"adovbs.inc", "adovbs - Copy.inc", "CON.txt"}},
		"/ifs/data/dfs/mydata/adovbs.inc":        {kind: "object", size: 14800},
		"/ifs/data/dfs/mydata/adovbs - Copy.inc": {kind: "object", size: 14800},
		"/ifs/data/dfs/mydata/CON.txt":           {kind: "object", size: 1},
		"/ifs/data/dfs/locky_test2":              {kind: "container"},
		"/ifs/data/dfs/link1":                    {kind: "symbolic_link"},
	}
	// 2500 files in one folder to exercise RAN resume paging.
	var many []string
	for i := 0; i < 2500; i++ {
		n := "enc_" + itoa(i) + ".locky"
		many = append(many, n)
		tree["/ifs/data/dfs/locky_test2/"+n] = node{kind: "object", size: 22}
	}
	lt := tree["/ifs/data/dfs/locky_test2"]
	lt.kids = many
	tree["/ifs/data/dfs/locky_test2"] = lt
	mod := time.Date(2026, 7, 21, 12, 13, 0, 0, time.UTC).Format(http.TimeFormat)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /session/1/session", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "isisessid", Value: "s1", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "isicsrf", Value: "c1", Path: "/"})
		w.WriteHeader(201)
	})
	auth := func(r *http.Request) bool {
		c, err := r.Cookie("isisessid")
		return err == nil && c.Value == "s1" && r.Header.Get("X-CSRF-Token") == "c1"
	}
	mux.HandleFunc("GET /namespace/", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			w.WriteHeader(401)
			return
		}
		p := "/" + strings.TrimPrefix(r.URL.Path, "/namespace/")
		n, ok := tree[p]
		if !ok {
			w.WriteHeader(404)
			return
		}
		if _, isACL := r.URL.Query()["acl"]; isACL {
			admins := map[string]any{"accessrights": []string{"dir_gen_all"}, "accesstype": "allow", "inherit_flags": []string{"object_inherit", "container_inherit"},
				"trustee": map[string]any{"id": "SID:S-1-5-32-544", "name": "Administrators", "type": "group"}}
			inherited := map[string]any{"accessrights": []string{"dir_gen_all"}, "accesstype": "allow", "inherit_flags": []string{"inherited_ace"},
				"trustee": map[string]any{"id": "SID:S-1-5-32-544", "name": "Administrators", "type": "group"}}
			acl := []any{admins}
			switch p {
			case "/ifs/data/dfs/mydata": // opened up to everybody, plus an account that was deleted
				acl = []any{inherited,
					map[string]any{"accessrights": []string{"dir_gen_read", "dir_gen_execute"}, "accesstype": "allow", "inherit_flags": []string{"container_inherit"},
						"trustee": map[string]any{"id": "SID:S-1-1-0", "name": "Everyone", "type": "wellknown"}},
					map[string]any{"accessrights": []string{"modify"}, "accesstype": "allow", "inherit_flags": []string{},
						"trustee": map[string]any{"id": "SID:S-1-5-21-111-222-333-1999", "type": "user"}}}
			case "/ifs/data/dfs/locky_test2": // inherits only: no row of its own
				acl = []any{inherited}
			}
			json.NewEncoder(w).Encode(map[string]any{"owner": map[string]any{"name": "demouser", "type": "user"}, "authoritative": "acl", "acl": acl})
			return
		}
		start := 0
		if res := r.URL.Query().Get("resume"); res != "" {
			start = atoi(res)
		}
		end := start + 1000
		if end > len(n.kids) {
			end = len(n.kids)
		}
		var kids []map[string]any
		for _, k := range n.kids[start:end] {
			c := tree[p+"/"+k]
			kids = append(kids, map[string]any{"name": k, "type": c.kind, "size": c.size, "last_modified": mod, "access_time": mod, "create_time": mod, "owner": "demouser"})
		}
		out := map[string]any{"children": kids}
		if end < len(n.kids) {
			out["resume"] = itoa(end)
		}
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /platform/1/zones", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"zones":[{"name":"System"},{"name":"zone2"}]}`))
	})
	mux.HandleFunc("GET /platform/1/protocols/smb/shares", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("zone") == "zone2" {
			w.Write([]byte(`{"shares":[{"name":"eng","path":"/ifs/zone2/eng"}]}`))
			return
		}
		w.Write([]byte(`{"shares":[{"name":"dfsprod","path":"/ifs/data/dfs","description":"DFS root"},{"name":"ifs","path":"/ifs"}]}`))
	})
	mux.HandleFunc("GET /platform/1/cluster/identity", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"name":"PS-Test-160","description":""}`))
	})
	mux.HandleFunc("GET /platform/1/cluster/config", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"guid":"000c29f3a1","name":"PS-Test-160","onefs_version":{"release":"9.7.0.0","build":"B_9_7_0_0"}}`))
	})
	mux.HandleFunc("GET /platform/3/cluster/nodes", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodes":[{"id":1,"lnn":1,"hardware":{"product":"PowerScale F200","serial_number":"SX1"}},{"id":2,"lnn":2,"hardware":{"product":"PowerScale F200","serial_number":"SX2"}},{"id":3,"lnn":3,"hardware":{"product":"PowerScale F200","serial_number":"SX3"}}]}`))
	})
	mux.HandleFunc("GET /platform/1/statistics/current", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"stats":[{"key":"ifs.bytes.total","value":1.2e13},{"key":"ifs.bytes.used","value":4.2e12}]}`))
	})
	return httptest.NewTLSServer(mux)
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }
func atoi(s string) int { var i int; json.Unmarshal([]byte(s), &i); return i }

func newTestApp(t *testing.T) *App {
	st, err := openStore(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.db.Close() })
	a := &App{st: st, running: map[int64]*scanProgress{}, sessions: map[string]int64{}, key: make([]byte, 32)}
	a.audit = newAuditAgg(a)
	return a
}

func waitScan(t *testing.T, a *App, id int64) (status, msg string) {
	for i := 0; i < 200; i++ {
		a.st.db.QueryRow(`SELECT status,message FROM scans WHERE id=?`, id).Scan(&status, &msg)
		a.mu.Lock()
		_, busy := a.running[id]
		a.mu.Unlock()
		if status != "running" && !busy {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("scan did not finish")
	return
}

func TestPowerScaleScan(t *testing.T) {
	srv := fakeOneFS(t)
	defer srv.Close()
	a := newTestApp(t)
	res, _ := a.st.db.Exec(`INSERT INTO devices(name,kind,host,username,secret,insecure,created) VALUES('PS-Test-160','powerscale',?, 'svc', ?, 1, 0)`, srv.URL, a.seal("pw"))
	devID, _ := res.LastInsertId()
	d, _ := a.device(devID)

	shares, err := a.psClientFor(d).psShares()
	if err != nil || len(shares) != 3 || shares[2].Zone != "zone2" {
		t.Fatalf("share discovery: %v %+v", err, shares)
	}
	inv, err := a.psClientFor(d).psInventory()
	if err != nil || inv["node_count"] != 3 || inv["os"] != "OneFS 9.7.0.0" {
		t.Fatalf("inventory: %v %+v", err, inv)
	}

	res, _ = a.st.db.Exec(`INSERT INTO shares(device_id,name,path,created) VALUES(?,'dfsprod','/ifs/data/dfs',0)`, devID)
	shID, _ := res.LastInsertId()
	scanID, err := a.startScan(shID)
	if err != nil {
		t.Fatal(err)
	}
	if st, msg := waitScan(t, a, scanID); st != "done" {
		t.Fatalf("scan %s: %s", st, msg)
	}
	var files, bytes int64
	a.st.db.QueryRow(`SELECT COUNT(*), SUM(size) FROM `+a.fileRowsFor(scanID)+` WHERE scan_id=?`, scanID).Scan(&files, &bytes)
	if files != 2503 || bytes != 14800*2+1+2500*22 {
		t.Fatalf("indexed %d files / %d bytes", files, bytes)
	}
	var owner string
	a.st.db.QueryRow(`SELECT owner FROM `+a.fileRowsFor(scanID)+` WHERE scan_id=? AND name='adovbs.inc'`, scanID).Scan(&owner)
	if owner != "demouser" {
		t.Fatalf("owner %q", owner)
	}
	kinds := map[string]int{}
	rows, _ := a.st.db.Query(`SELECT kind FROM issues WHERE scan_id=?`, scanID)
	for rows.Next() {
		var k string
		rows.Scan(&k)
		kinds[k]++
	}
	rows.Close()
	if kinds["reserved"] != 1 || kinds["link"] != 1 {
		t.Fatalf("issues %+v", kinds)
	}
	var rootBytes int64
	a.st.db.QueryRow(`SELECT bytes FROM dirs WHERE scan_id=? AND path='/'`, scanID).Scan(&rootBytes)
	if rootBytes != bytes {
		t.Fatalf("root rollup %d != %d", rootBytes, bytes)
	}
	// Folder permissions: root and the opened-up folder are explicit, the inheriting one is not.
	perm := map[string][3]int{}
	prows, _ := a.st.db.Query(`SELECT path, open, orphan, protected FROM perms WHERE scan_id=?`, scanID)
	for prows.Next() {
		var p string
		var o, orph, prot int
		prows.Scan(&p, &o, &orph, &prot)
		perm[p] = [3]int{o, orph, prot}
	}
	prows.Close()
	if len(perm) != 2 || perm["/mydata"] != [3]int{1, 1, 0} || perm["/"][0] != 0 {
		t.Fatalf("PowerScale permissions %+v", perm)
	}

	// A failed rescan must keep the published index.
	srv.Close()
	scan2, _ := a.startScan(shID)
	if st, _ := waitScan(t, a, scan2); st != "failed" {
		t.Fatalf("expected failed rescan, got %s", st)
	}
	var cur int64
	a.st.db.QueryRow(`SELECT current_scan FROM shares WHERE id=?`, shID).Scan(&cur)
	if cur != scanID {
		t.Fatalf("current_scan moved to %d", cur)
	}
}

func TestLocalScanAndAutomation(t *testing.T) {
	dir := t.TempDir()
	mk := func(p string, n int) {
		full := filepath.Join(dir, filepath.FromSlash(p))
		mustMkdir(t, filepath.Dir(full))
		mustWrite(t, full, strings.Repeat("x", n))
	}
	mk("a/one.pdf", 100)
	mk("a/two.tmp", 50)
	mk("b/one.pdf", 100)
	mk("b/deep/three.tmp", 10)
	a := newTestApp(t)
	a.st.db.Exec(`INSERT INTO devices(id,name,kind,host,created) VALUES(1,'local','windows','',0)`)
	a.st.db.Exec(`INSERT INTO shares(id,device_id,name,path,created) VALUES(1,1,'t',?,0)`, dir)
	id, _ := a.startScan(1)
	if st, msg := waitScan(t, a, id); st != "done" {
		t.Fatalf("%s %s", st, msg)
	}

	// Tag rule then automation over the tag: dry-run changes nothing, real run deletes.
	a.st.db.Exec(`INSERT INTO tag_rules(id,name,tag,match,enabled) VALUES(1,'tmp','junk','{"ext":["tmp"]}',1)`)
	a.applyTagRules(1)
	var tagged int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM file_tags WHERE tag='junk'`).Scan(&tagged)
	if tagged != 2 {
		t.Fatalf("tagged %d", tagged)
	}
	au := Automation{ID: 1, Name: "purge", Enabled: true, InputKind: "tag", Input: Filter{Tag: "junk"}, Actions: []Action{{Type: "delete"}}}
	if err := validateAutomation(&au); err != nil {
		t.Fatal(err)
	}
	a.st.db.Exec(`INSERT INTO automations(id,name,enabled,input_kind,input,actions) VALUES(1,'purge',1,'tag','{"tag":"junk"}','[{"type":"delete"}]')`)
	a.runAutomation(au, 1, true)
	if !exists(filepath.Join(dir, "a", "two.tmp")) {
		t.Fatal("dry-run deleted a file")
	}
	var dryRows int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM automation_ledger WHERE run_id=1 AND result='dry-run'`).Scan(&dryRows)
	if dryRows != 2 {
		t.Fatalf("dry-run ledger rows %d", dryRows)
	}
	a.runAutomation(au, 2, false)
	if exists(filepath.Join(dir, "a", "two.tmp")) || exists(filepath.Join(dir, "b", "deep", "three.tmp")) {
		t.Fatal("real run did not delete")
	}
	var left int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM ` + a.fileRowsFor(id) + ` WHERE ext='tmp'`).Scan(&left)
	if left != 0 {
		t.Fatal("index still lists deleted files")
	}
	// Copy never overwrites.
	x := &executor{dev: Device{Kind: "windows"}, share: Share{Name: "t", Path: dir}}
	dst := t.TempDir()
	if _, _, err := x.apply(Action{Type: "copy", Target: dst}, "/a/one.pdf", false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := x.apply(Action{Type: "copy", Target: dst}, "/a/one.pdf", false); err == nil {
		t.Fatal("copy overwrote an existing target")
	}
}

func TestHygiene(t *testing.T) {
	cases := map[string]string{"ok.txt": "", "CON": "reserved", "aux.log": "reserved", "trail.": "illegal", "sp ": "illegal",
		"a:b": "illegal", "q?": "illegal", strings.Repeat("n", 256): "long_name"}
	for in, want := range cases {
		if got, _ := hygiene(in); got != want {
			t.Errorf("hygiene(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAuditParse(t *testing.T) {
	json1 := `<14>1 2026-07-21T12:13:01Z ps-1 audit_protocol - - {"protocol":"SMB2","zoneName":"System","eventType":"delete","isDirectory":false,"clientIP":"10.0.0.5","fileName":"\\ifs\\data\\dfs\\x.txt","userName":"CORP\\jdoe"}`
	e, ok := parseAuditLine(json1)
	if !ok || e.Op != "delete" || e.Path != "/ifs/data/dfs/x.txt" || e.User != `CORP\jdoe` || e.Client != "10.0.0.5" {
		t.Fatalf("json form: %v %+v", ok, e)
	}
	kv := `Jul 21 12:13:01 ps-1 audit_protocol[123]: protocol: SMB2, eventType: rename, fileName: /ifs/data/a.doc, userName: bob`
	e, ok = parseAuditLine(kv)
	if !ok || e.Op != "rename" || e.User != "bob" {
		t.Fatalf("kv form: %v %+v", ok, e)
	}
	if _, ok := parseAuditLine("random noise"); ok {
		t.Fatal("noise parsed")
	}
	if normOp("create", "open-file") != "read" || normOp("create", "create-file") != "create" || normOp("write", "") != "modify" {
		t.Fatal("normOp mapping")
	}
}
