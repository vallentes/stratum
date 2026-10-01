//go:build windows

package main

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows file-server audit: polls the local Security log for object-access events
// (4663 access, 4660 delete). Needs "Audit File System" enabled plus a SACL on the
// audited folders, and the service must run as an account that can read the Security log.

var (
	wevtapi       = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery  = wevtapi.NewProc("EvtQuery")
	procEvtNext   = wevtapi.NewProc("EvtNext")
	procEvtRender = wevtapi.NewProc("EvtRender")
	procEvtClose  = wevtapi.NewProc("EvtClose")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryForwardDirection = 0x100
	evtRenderEventXml        = 1
)

type evtXML struct {
	System struct {
		EventID       int    `xml:"EventID"`
		EventRecordID uint64 `xml:"EventRecordID"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

type WinAuditStatus struct {
	Enabled bool   `json:"enabled"`
	Error   string `json:"error,omitempty"`
	LastID  uint64 `json:"last_record_id"`
	Events  int64  `json:"events"`
}

var winAudit WinAuditStatus

// startWindowsAudit polls the local Security log. getDev says which device the events
// belong to (0 = not registered yet, skip); load/save persist the last record id.
func startWindowsAudit(getDev func() int64, emit func(AuditEvent), load func() uint64, save func(uint64)) {
	go func() {
		last := load()
		winAudit.LastID = last
		for {
			if dev := getDev(); dev > 0 {
				n, id, err := pollSecurityLog(last, func(e AuditEvent) { e.DeviceID = dev; emit(e) })
				if err != nil {
					winAudit.Enabled, winAudit.Error = false, err.Error()
				} else {
					winAudit.Enabled, winAudit.Error = true, ""
					winAudit.Events += int64(n)
					if id > last {
						last = id
						winAudit.LastID = id
						save(id)
					}
				}
			} else {
				winAudit.Enabled, winAudit.Error = false, "no Windows device for this machine is registered"
			}
			time.Sleep(15 * time.Second)
		}
	}()
}

const auditPolicyGUID = "{0CCE921D-69AE-11D9-BED3-505054503030}" // "File System" subcategory, any display language

func auditMarker() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "Stratum", "audit-policy-enabled-by-stratum")
}

// auditPolicyOn reports whether File System success auditing is already enabled.
func auditPolicyOn() bool {
	b, err := exec.Command("auditpol", "/get", "/subcategory:"+auditPolicyGUID, "/r").CombinedOutput()
	if err != nil {
		return false
	}
	// CSV: ...,Inclusion Setting,... ; value contains "Success" when enabled.
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return len(lines) > 1 && strings.Contains(lines[len(lines)-1], "Success")
}

func isSystemDriveRoot(p string) bool {
	sd := strings.ToUpper(strings.TrimRight(os.Getenv("SystemDrive"), `\`))
	if sd == "" {
		sd = "C:"
	}
	return strings.EqualFold(strings.TrimRight(filepath.Clean(p), `\`), sd)
}

const auditRuleScript = `$ErrorActionPreference='Stop'
$p=$env:STRATUM_AUDIT_PATH
$item=Get-Item -LiteralPath $p
$acl=$item.GetAccessControl('Audit')
$sid=New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$rights=[System.Security.AccessControl.FileSystemRights]'WriteData,AppendData,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions'
$rule=New-Object System.Security.AccessControl.FileSystemAuditRule($sid,$rights,'ContainerInherit,ObjectInherit','None','Success')
if ($env:STRATUM_AUDIT_MODE -eq 'remove') { [void]$acl.RemoveAuditRuleSpecific($rule) } else { $acl.AddAuditRule($rule) }
$item.SetAccessControl($acl)
'ok'`

func runAuditRule(p, mode string, j *jobState) error {
	c := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", auditRuleScript)
	c.Env = append(os.Environ(), "STRATUM_AUDIT_PATH="+p, "STRATUM_AUDIT_MODE="+mode)
	var buf strings.Builder
	c.Stdout, c.Stderr = &buf, &buf
	if err := c.Start(); err != nil {
		return err
	}
	jobs.setPID(j, c.Process.Pid) // the Index page follows this process's I/O
	if err := c.Wait(); err != nil {
		return errors.New(strings.TrimSpace(buf.String()))
	}
	return nil
}

// enableFileAuditing turns on the "File System" success audit policy (remembering
// whether Stratum was the one to turn it on) and adds one audit rule (write, delete,
// permission changes by Everyone) to each chosen folder. Existing rules are kept.
func enableFileAuditing(paths []string) (map[string]string, error) {
	out := map[string]string{}
	j := jobs.start("enable_audit", len(paths))
	defer jobs.end(j)
	if !auditPolicyOn() {
		if b, err := exec.Command("auditpol", "/set", "/subcategory:"+auditPolicyGUID, "/success:enable").CombinedOutput(); err != nil {
			return nil, fmt.Errorf("auditpol: %s (needs administrator rights; install the collector as a service)", strings.TrimSpace(string(b)))
		}
		os.MkdirAll(filepath.Dir(auditMarker()), 0o755)
		os.WriteFile(auditMarker(), []byte(time.Now().Format(time.RFC3339)), 0o644)
		out["policy"] = "File System success auditing enabled"
	} else {
		out["policy"] = "File System auditing was already enabled"
	}
	for i, p := range paths {
		jobs.stepTo(j, i+1, p)
		switch {
		case strings.HasPrefix(p, `\\`):
			out[p] = "skipped: remote share, enable auditing on that server"
		case isSystemDriveRoot(p):
			out[p] = "skipped: the whole system drive would log every Windows write; audit specific folders instead"
		default:
			if err := runAuditRule(p, "add", j); err != nil {
				out[p] = "failed: " + err.Error()
			} else {
				out[p] = "audit rule added"
			}
		}
	}
	return out, nil
}

// disableFileAuditing removes exactly the rule Stratum added, and turns the policy
// back off only if Stratum was the one that turned it on.
func disableFileAuditing(paths []string) (map[string]string, error) {
	out := map[string]string{}
	j := jobs.start("disable_audit", len(paths))
	defer jobs.end(j)
	for i, p := range paths {
		jobs.stepTo(j, i+1, p)
		if strings.HasPrefix(p, `\\`) || isSystemDriveRoot(p) {
			continue
		}
		if err := runAuditRule(p, "remove", j); err != nil {
			out[p] = "failed: " + err.Error()
		} else {
			out[p] = "audit rule removed"
		}
	}
	if _, err := os.Stat(auditMarker()); err == nil {
		if b, err := exec.Command("auditpol", "/set", "/subcategory:"+auditPolicyGUID, "/success:disable").CombinedOutput(); err != nil {
			out["policy"] = "could not turn the policy off: " + strings.TrimSpace(string(b))
		} else {
			os.Remove(auditMarker())
			out["policy"] = "File System auditing turned off (Stratum had turned it on)"
		}
	} else {
		out["policy"] = "left as it was (it was enabled before Stratum)"
	}
	return out, nil
}

func pollSecurityLog(afterID uint64, emit func(AuditEvent)) (int, uint64, error) {
	q := "*[System[(EventID=4663 or EventID=4660)"
	if afterID > 0 {
		q += fmt.Sprintf(" and (EventRecordID > %d)", afterID)
	} else {
		q += " and TimeCreated[timediff(@SystemTime) <= 3600000]"
	}
	q += "]]"
	ch, _ := windows.UTF16PtrFromString("Security")
	qq, _ := windows.UTF16PtrFromString(q)
	h, _, err := procEvtQuery.Call(0, uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(qq)), evtQueryChannelPath|evtQueryForwardDirection)
	if h == 0 {
		return 0, afterID, fmt.Errorf("cannot read the Security log (run as an administrator or Event Log Readers member): %v", err)
	}
	defer procEvtClose.Call(h)
	maxID := afterID
	n := 0
	events := make([]uintptr, 64)
	buf := make([]uint16, 16384)
	for {
		var got uint32
		r, _, _ := procEvtNext.Call(h, uintptr(len(events)), uintptr(unsafe.Pointer(&events[0])), 2000, 0, uintptr(unsafe.Pointer(&got)))
		if r == 0 || got == 0 {
			break
		}
		for i := 0; i < int(got); i++ {
			var used, props uint32
			for {
				r, _, e := procEvtRender.Call(0, events[i], evtRenderEventXml, uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
				if r == 0 && e == syscall.ERROR_INSUFFICIENT_BUFFER {
					buf = make([]uint16, used/2+1)
					continue
				}
				break
			}
			procEvtClose.Call(events[i])
			var ev evtXML
			if xml.Unmarshal([]byte(windows.UTF16ToString(buf)), &ev) != nil {
				continue
			}
			if ev.System.EventRecordID > maxID {
				maxID = ev.System.EventRecordID
			}
			if e, ok := winEventToAudit(ev); ok {
				emit(e)
				n++
			}
		}
	}
	return n, maxID, nil
}

func winEventToAudit(ev evtXML) (AuditEvent, bool) {
	d := map[string]string{}
	for _, x := range ev.Data {
		d[x.Name] = strings.TrimSpace(x.Value)
	}
	e := AuditEvent{Proto: "SMB/local"}
	if t, err := time.Parse(time.RFC3339Nano, ev.System.TimeCreated.SystemTime); err == nil {
		e.TS = t.Unix()
	}
	e.User = d["SubjectUserName"]
	if dom := d["SubjectDomainName"]; dom != "" {
		e.User = dom + `\` + e.User
	}
	if strings.HasSuffix(d["SubjectUserName"], "$") {
		return e, false // machine accounts: backup/AV noise
	}
	if ev.System.EventID == 4660 {
		e.Op = "delete"
		e.Path = d["ObjectName"]
		return e, true // 4660 has no ObjectName on older builds; kept for counts
	}
	if d["ObjectType"] != "" && d["ObjectType"] != "File" {
		return e, false
	}
	e.Path = strings.ReplaceAll(d["ObjectName"], `\`, "/")
	mask, _ := strconv.ParseUint(strings.TrimPrefix(d["AccessMask"], "0x"), 16, 64)
	switch {
	case mask&0x10000 != 0:
		e.Op = "delete"
	case mask&0x6 != 0:
		e.Op = "modify"
	case mask&0x40000 != 0 || mask&0x80000 != 0:
		e.Op = "modify"
	case mask&0x1 != 0:
		e.Op = "read"
	default:
		e.Op = "other"
	}
	return e, e.Path != ""
}
