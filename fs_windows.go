//go:build windows

package main

import (
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const isWindows = true

const (
	attrReparse          = 0x400
	attrOffline          = 0x1000
	attrRecallOnOpen     = 0x40000
	attrRecallOnDataRead = 0x400000
)

func ftUnix(ft syscall.Filetime) int64 {
	if ft.HighDateTime == 0 && ft.LowDateTime == 0 {
		return 0
	}
	return ft.Nanoseconds() / 1e9
}

// fillPlatform pulls access/creation time and reparse/stub flags from the
// find-data Go already fetched, so no extra syscall per file.
func fillPlatform(e *Entry, info fs.FileInfo) {
	d, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		e.Atime, e.Ctime = e.Mtime, e.Mtime
		return
	}
	e.Atime = ftUnix(d.LastAccessTime)
	e.Ctime = ftUnix(d.CreationTime)
	a := d.FileAttributes
	switch {
	case a&attrReparse != 0 && (e.IsDir || a&0x10 != 0):
		e.Link = "junction"
	case a&attrReparse != 0 && info.Mode()&fs.ModeSymlink != 0:
		e.Link = "symlink"
	case a&(attrOffline|attrRecallOnOpen|attrRecallOnDataRead) != 0:
		e.Flags |= flagStub
	case a&attrReparse != 0:
		e.Link = "reparse"
	}
	if info.Mode()&fs.ModeSymlink != 0 && e.Link == "" {
		e.Link = "symlink"
	}
}

type ownerCache struct {
	mu   sync.Mutex
	sids map[string]string
}

func newOwnerCache() *ownerCache { return &ownerCache{sids: map[string]string{}} }

func (c *ownerCache) owner(path string) string {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return ""
	}
	sid, _, err := sd.Owner()
	if err != nil || sid == nil {
		return ""
	}
	key := sid.String()
	c.mu.Lock()
	name, ok := c.sids[key]
	c.mu.Unlock()
	if ok {
		return name
	}
	acct, dom, _, err := sid.LookupAccount("")
	name = key
	if err == nil {
		name = acct
		if dom != "" {
			name = dom + `\` + acct
		}
	}
	c.mu.Lock()
	c.sids[key] = name
	c.mu.Unlock()
	return name
}

var (
	netapi32             = windows.NewLazySystemDLL("netapi32.dll")
	procNetShareEnum     = netapi32.NewProc("NetShareEnum")
	procNetApiBufferFree = netapi32.NewProc("NetApiBufferFree")
	mpr                  = windows.NewLazySystemDLL("mpr.dll")
	procWNetAddConn2     = mpr.NewProc("WNetAddConnection2W")
)

type shareInfo1 struct {
	netname *uint16
	typ     uint32
	remark  *uint16
}

// enumWindowsShares lists the disk shares a Windows (or any SMB) server publishes.
func enumWindowsShares(server string) ([]DiscoveredShare, error) {
	srv, _ := windows.UTF16PtrFromString(`\\` + strings.TrimPrefix(server, `\\`))
	var buf *byte
	var read, total, resume uint32
	r, _, _ := procNetShareEnum.Call(uintptr(unsafe.Pointer(srv)), 1, uintptr(unsafe.Pointer(&buf)),
		0xFFFFFFFF, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
	if r != 0 {
		return nil, fmt.Errorf("NetShareEnum %s: %w", server, syscall.Errno(r))
	}
	defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(buf)))
	items := unsafe.Slice((*shareInfo1)(unsafe.Pointer(buf)), read)
	var out []DiscoveredShare
	for _, it := range items {
		if it.typ&0xFF != 0 || it.typ&0x80000000 != 0 { // disk shares only, skip ADMIN$/C$
			continue
		}
		name := windows.UTF16PtrToString(it.netname)
		out = append(out, DiscoveredShare{Name: name, Path: `\\` + strings.TrimPrefix(server, `\\`) + `\` + name,
			Comment: windows.UTF16PtrToString(it.remark)})
	}
	return out, nil
}

type netResource struct {
	scope, typ, displayType, usage uint32
	local, remote, comment, prov   *uint16
}

// connectSMB authenticates to \\server\share with explicit credentials. Without a
// username the service account's own identity is used.
func connectSMB(unc, user, pass string) error {
	if user == "" {
		return nil
	}
	remote, _ := windows.UTF16PtrFromString(unc)
	u, _ := windows.UTF16PtrFromString(user)
	p, _ := windows.UTF16PtrFromString(pass)
	nr := netResource{typ: 1, remote: remote}
	r, _, _ := procWNetAddConn2.Call(uintptr(unsafe.Pointer(&nr)), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(u)), 0)
	if r != 0 && r != 1219 { // 1219: already connected with other credentials, reuse it
		return fmt.Errorf("connect %s: %w", unc, syscall.Errno(r))
	}
	return nil
}

func diskSpace(path string) (total, free uint64, err error) {
	p, _ := windows.UTF16PtrFromString(path)
	var avail uint64
	err = windows.GetDiskFreeSpaceEx(p, &avail, &total, &free)
	return
}

func localDrives() []DiscoveredShare {
	var out []DiscoveredShare
	mask, _ := windows.GetLogicalDrives()
	for i := 0; i < 26; i++ {
		if mask&(1<<i) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		p, _ := windows.UTF16PtrFromString(root)
		if windows.GetDriveType(p) != windows.DRIVE_FIXED {
			continue
		}
		out = append(out, DiscoveredShare{Name: root[:2], Path: root})
	}
	return out
}

func hostInventory() map[string]any {
	h, _ := os.Hostname()
	v := windows.RtlGetVersion()
	return map[string]any{
		"hostname": h,
		"os":       fmt.Sprintf("Windows %d.%d build %d", v.MajorVersion, v.MinorVersion, v.BuildNumber),
		"arch":     runtime.GOARCH,
		"cpus":     runtime.NumCPU(),
	}
}

func devOf(p string) (uint64, error) { return 0, nil }

// Windows shares do not span filesystems the way a Linux root does; reparse
// points (junctions, mount folders) are already reported as links.
func mountBoundary(p string, rootDev uint64, info fs.FileInfo) string { return "" }

// Hard links are rare on file shares and need a handle per file to detect.
func inodeKey(info fs.FileInfo) (string, bool) { return "", false }

var (
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procFindFirstStreamW = kernel32.NewProc("FindFirstStreamW")
	procFindNextStreamW  = kernel32.NewProc("FindNextStreamW")
)

type win32FindStreamData struct {
	StreamSize int64
	StreamName [296]uint16 // MAX_PATH + 36
}

// listStreams returns the alternate data streams of a file (everything but ::$DATA).
func listStreams(p string) []Stream {
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return nil
	}
	var fd win32FindStreamData
	h, _, _ := procFindFirstStreamW.Call(uintptr(unsafe.Pointer(name)), 0, uintptr(unsafe.Pointer(&fd)), 0)
	if windows.Handle(h) == windows.InvalidHandle {
		return nil
	}
	defer windows.FindClose(windows.Handle(h))
	var out []Stream
	for {
		n := windows.UTF16ToString(fd.StreamName[:])
		if n != "::$DATA" {
			n = strings.TrimSuffix(strings.TrimPrefix(n, ":"), ":$DATA")
			out = append(out, Stream{Name: n, Size: fd.StreamSize})
		}
		r, _, _ := procFindNextStreamW.Call(h, uintptr(unsafe.Pointer(&fd)))
		if r == 0 {
			break
		}
	}
	return out
}
