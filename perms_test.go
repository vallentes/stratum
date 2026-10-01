package main

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if b, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v %s", name, args, err, b)
	}
}

// TestPermissionsScan gives real folders different access and checks what the
// scan records and what the reports answer.
func TestPermissionsScan(t *testing.T) {
	dir, a := localFixture(t, "open/a.txt", "open/sub/b.txt", "locked/c.txt", "ghost/d.txt", "plain/e.txt")
	ghost := "S-1-5-21-1111111111-2222222222-3333333333-4444"
	switch runtime.GOOS {
	case "windows":
		run(t, "icacls", filepath.Join(dir, "open"), "/grant", "*S-1-1-0:(OI)(CI)R")
		run(t, "icacls", filepath.Join(dir, "locked"), "/inheritance:d")
		// icacls refuses SIDs that do not resolve, which is exactly the deleted-account case.
		run(t, "powershell", "-NoProfile", "-Command", `$p='`+filepath.Join(dir, "ghost")+`'; $acl=Get-Acl -LiteralPath $p;
$sid=New-Object System.Security.Principal.SecurityIdentifier('`+ghost+`');
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'Modify','ContainerInherit,ObjectInherit','None','Allow')));
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'WriteData','ContainerInherit,ObjectInherit','None','Deny')));
Set-Acl -LiteralPath $p -AclObject $acl`)
	default:
		// Mode bits have no inheritance: a folder gets a row when it differs from its parent.
		for _, d := range []string{"", "plain", "ghost", "open/sub"} {
			os.Chmod(filepath.Join(dir, d), 0o750) // not world-readable
		}
		os.Chmod(filepath.Join(dir, "open"), 0o757)
		os.Chmod(filepath.Join(dir, "open", "sub"), 0o757)
		os.Chmod(filepath.Join(dir, "locked"), 0o700)
	}
	id, _ := a.startScan(1)
	waitScanLong(t, a, id, 20*time.Second)

	got := map[string]permFolder{}
	list, err := a.permFolders(Scope{}, "", nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range list {
		got[f.Path] = f
	}
	if _, ok := got["/"]; !ok {
		t.Fatalf("the share root always gets a row: %+v", got)
	}
	if !got["/open"].Open {
		t.Fatalf("/open should be open to everybody: %+v", got["/open"])
	}
	if _, ok := got["/open/sub"]; ok {
		t.Fatal("/open/sub only inherits and must not get its own row")
	}
	if _, ok := got["/plain"]; ok {
		t.Fatal("/plain only inherits and must not get its own row")
	}
	if runtime.GOOS == "windows" {
		if !got["/locked"].Protected {
			t.Fatalf("/locked has inheritance switched off: %+v", got["/locked"])
		}
		g := got["/ghost"]
		if !g.Orphan || !g.Deny {
			t.Fatalf("/ghost names a deleted account with an allow and a deny entry: %+v", g)
		}
	} else if _, ok := got["/locked"]; !ok {
		t.Fatal("/locked differs from its parent and needs a row")
	}
	if got["/open"].Files != 2 {
		t.Fatalf("files below /open: %d", got["/open"].Files)
	}

	// The reports.
	get := func(fn func(w2 *httptest.ResponseRecorder, q string), q string) string {
		rec := httptest.NewRecorder()
		fn(rec, q)
		return rec.Body.String()
	}
	sum := get(func(w2 *httptest.ResponseRecorder, q string) {
		a.permsSummary(w2, httptest.NewRequest("GET", "/api/perms/summary"+q, nil))
	}, "")
	if !strings.Contains(sum, `"open":1`) || !strings.Contains(sum, `"open_files":2`) {
		t.Fatalf("summary: %s", sum)
	}
	who := get(func(w2 *httptest.ResponseRecorder, q string) {
		a.permsWho(w2, httptest.NewRequest("GET", "/api/perms/who"+q, nil))
	}, "?name=nobody-in-particular")
	if !strings.Contains(who, `"path":"/open"`) {
		t.Fatalf("anyone reaches /open through Everyone: %s", who)
	}
	eff := get(func(w2 *httptest.ResponseRecorder, q string) {
		a.permsFolder(w2, httptest.NewRequest("GET", "/api/perms/folder"+q, nil))
	}, "?share=1&path=/open/sub/deeper")
	if !strings.Contains(eff, `"from":"/open"`) {
		t.Fatalf("effective access of a folder comes from its nearest explicit parent: %s", eff)
	}
	csv := get(func(w2 *httptest.ResponseRecorder, q string) {
		a.permsCSV(w2, httptest.NewRequest("GET", "/api/perms/export.csv"+q, nil))
	}, "?kind=open")
	if !strings.Contains(csv, "/open") || strings.Contains(csv, "/locked") {
		t.Fatalf("csv export of open folders: %s", csv)
	}

	// Switching the option off stops collection on the next scan.
	a.st.db.Exec(`UPDATE shares SET options='{"perms":false}' WHERE id=1`)
	id2, _ := a.startScan(1)
	waitScanLong(t, a, id2, 20*time.Second)
	var n int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM perms WHERE scan_id=?`, id2).Scan(&n)
	if n != 0 {
		t.Fatalf("permissions collected although switched off: %d rows", n)
	}
}

func TestRightsLabels(t *testing.T) {
	for mask, want := range map[uint32]string{0x1F01FF: "full", 0x1301BF: "modify", 0x1200A9: "read", 0x120089: "read", 0x100020: "list", 0x116: "write", 0x10000000: "full"} {
		if got := windowsRights(mask); got != want {
			t.Errorf("mask %#x: %s, want %s", mask, got, want)
		}
	}
	if oneFSRights([]string{"dir_gen_read", "dir_gen_execute"}) != "read" || oneFSRights([]string{"dir_gen_write", "std_delete"}) != "modify" {
		t.Error("OneFS rights")
	}
	p := posixPerms("ana", "staff", 0o750)
	if len(p.ACEs) != 2 || p.ACEs[1].Rights != "read" {
		t.Fatalf("posix 0750: %+v", p.ACEs)
	}
	if f, _, _ := posixPerms("ana", "staff", 0o755).flags(); !f {
		t.Fatal("0755 lets everybody read")
	}
}
