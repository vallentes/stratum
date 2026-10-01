//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"syscall"
)

const isWindows = false

func fillPlatform(e *Entry, info fs.FileInfo) {
	e.Atime, e.Ctime = e.Mtime, e.Mtime
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		e.Atime = st.Atim.Sec
		// Sparse files (VM disks, databases) report a logical size far above what they use.
		if !info.IsDir() && e.Size > 1<<20 && st.Blocks*512 < e.Size/2 {
			e.Flags |= flagSparse
		}
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		e.Link = "symlink"
	} else if !info.Mode().IsRegular() && !info.IsDir() {
		e.Link = "special" // sockets, fifos, devices
	}
}

func devOf(p string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		return 0, err
	}
	return uint64(st.Dev), nil
}

var bindMounts = map[string]bool{}

var mountTypes struct {
	once sync.Once
	m    map[string]string // mount point -> fstype
}

func mountInfo() map[string]string {
	mountTypes.once.Do(func() {
		mountTypes.m = map[string]string{}
		f, err := os.Open("/proc/self/mountinfo")
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			// id parent major:minor root mountpoint opts ... - fstype source superopts
			parts := strings.SplitN(sc.Text(), " - ", 2)
			left := strings.Fields(parts[0])
			if len(left) < 5 || len(parts) < 2 {
				continue
			}
			fstype := strings.Fields(parts[1])[0]
			mp := unescapeMount(left[4])
			mountTypes.m[mp] = fstype
			// Field 4 is the root inside the filesystem; anything but "/" is a bind mount of a
			// sub-folder (systemd sandboxing, containers) and would duplicate the real disk.
			if left[3] != "/" {
				bindMounts[mp] = true
			}
		}
	})
	return mountTypes.m
}

func unescapeMount(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\134`, `\`).Replace(s)
}

// mountBoundary reports a directory on a different filesystem than the share root.
func mountBoundary(p string, rootDev uint64, info fs.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(st.Dev) == rootDev {
		return ""
	}
	if t := mountInfo()[p]; t != "" {
		return "mount (" + t + ")"
	}
	return "mount"
}

func inodeKey(info fs.FileInfo) (string, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink <= 1 {
		return "", false
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino), true
}

func listStreams(p string) []Stream { return nil }

type ownerCache struct {
	mu    sync.Mutex
	names map[uint32]string
}

func newOwnerCache() *ownerCache { return &ownerCache{names: map[uint32]string{}} }

func (c *ownerCache) owner(path string) string {
	var st syscall.Stat_t
	if syscall.Stat(path, &st) != nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if n, ok := c.names[st.Uid]; ok {
		return n
	}
	n := fmt.Sprint(st.Uid)
	if u, err := user.LookupId(n); err == nil {
		n = u.Username
	}
	c.names[st.Uid] = n
	return n
}

func setHidden(p string) {} // dot-files are the Unix way; decoy names stay as they are

// DirPerms models POSIX owner, group and mode bits as three access entries.
func (l *localLister) DirPerms(rel string) (DirPerms, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(l.abs(rel), &st); err != nil {
		return DirPerms{}, err
	}
	owner := l.owners.owner(l.abs(rel))
	group := fmt.Sprint(st.Gid)
	if g, err := user.LookupGroupId(group); err == nil {
		group = g.Name
	}
	return posixPerms(owner, group, uint32(st.Mode)&0o777), nil
}

func enumWindowsShares(server string) ([]DiscoveredShare, error) {
	return nil, errors.New("share discovery for Windows servers runs in a Windows collector; add this device through a collector")
}

func connectSMB(unc, user, pass string) error {
	if strings.HasPrefix(unc, `\`) {
		return errors.New("unc paths need a Windows collector; the Linux server cannot open SMB shares directly")
	}
	return nil
}

func diskSpace(path string) (total, free uint64, err error) {
	var s syscall.Statfs_t
	if err = syscall.Statfs(path, &s); err != nil {
		return
	}
	return s.Blocks * uint64(s.Bsize), s.Bavail * uint64(s.Bsize), nil
}

var realFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "nfs": true, "nfs4": true,
	"cifs": true, "smb3": true, "ntfs": true, "ntfs3": true, "vfat": true, "exfat": true, "fuseblk": true, "f2fs": true, "jfs": true, "reiserfs": true, "ceph": true, "glusterfs": true, "lustre": true}

// localDrives lists real mounted filesystems (not /proc, /sys, tmpfs, overlay, snaps, container layers).
func localDrives() []DiscoveredShare {
	var out []DiscoveredShare
	seen := map[string]bool{}
	for mp, t := range mountInfo() {
		if !realFS[t] || seen[mp] || bindMounts[mp] || strings.HasPrefix(mp, "/snap/") || strings.HasPrefix(mp, "/var/lib/docker") ||
			strings.HasPrefix(mp, "/var/lib/containerd") || strings.HasPrefix(mp, "/var/lib/kubelet") || strings.HasPrefix(mp, "/run/") || strings.HasPrefix(mp, "/boot") {
			continue
		}
		seen[mp] = true
		d := DiscoveredShare{Name: mp, Path: mp, Comment: t}
		if tot, free, err := diskSpace(mp); err == nil {
			d.Comment = fmt.Sprintf("%s, %.0f GB used of %.0f GB", t, float64(tot-free)/(1<<30), float64(tot)/(1<<30))
		}
		out = append(out, d)
	}
	return out
}

func hostInventory() map[string]any {
	h, _ := os.Hostname()
	osName := runtime.GOOS
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "PRETTY_NAME=") {
				osName = strings.Trim(strings.TrimPrefix(l, "PRETTY_NAME="), `"`)
			}
		}
	}
	return map[string]any{"hostname": h, "os": osName, "arch": runtime.GOARCH, "cpus": runtime.NumCPU()}
}
