package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Entry is one directory child as reported by the storage, metadata only.
type Entry struct {
	Name    string
	IsDir   bool
	Size    int64
	Mtime   int64
	Atime   int64
	Ctime   int64
	Link    string // non-empty for reparse points / symlinks / stubs / mount points: not followed
	Owner   string // object owner when the storage reports one per item (S3)
	ETag    string // object ETag (S3)
	Flags   int    // flagStub | flagSparse | flagHardlinkDup
	Streams []Stream
}

// Stream is an NTFS alternate data stream on a file.
type Stream struct {
	Name string
	Size int64
}

const (
	flagStub        = 1 // offline / cloud placeholder: size is logical, data is elsewhere
	flagSparse      = 2 // allocated space well below the logical size
	flagHardlinkDup = 4 // another path to an inode already counted: excluded from totals
)

// Lister abstracts one storage protocol. Paths passed in are share-relative, "/"-separated,
// starting with "/" ("/" is the share root).
type Lister interface {
	List(rel string) ([]Entry, error)
	DirOwner(rel string) string
	Parallelism() int
}

// localLister reads a local volume, a Linux path, or a UNC path (\\server\share).
type localLister struct {
	root    string
	owners  *ownerCache
	ads     bool
	rootDev uint64
	seen    sync.Map // "dev:ino" of multi-link files already counted
}

func newLocalLister(root string, ads bool) *localLister {
	l := &localLister{root: filepath.Clean(root), owners: newOwnerCache(), ads: ads}
	l.rootDev, _ = devOf(l.root)
	return l
}

func (l *localLister) abs(rel string) string {
	if rel == "/" || rel == "" {
		return l.root
	}
	return filepath.Join(l.root, filepath.FromSlash(strings.TrimPrefix(rel, "/")))
}

func (l *localLister) Parallelism() int {
	if strings.HasPrefix(l.root, `\\`) {
		return 16 // SMB: latency bound, more in flight helps
	}
	return 8
}

func (l *localLister) List(rel string) ([]Entry, error) {
	dir := longPath(l.abs(rel))
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(ents))
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return out, err
		}
		en := Entry{Name: e.Name(), IsDir: e.IsDir(), Size: info.Size(), Mtime: info.ModTime().Unix()}
		fillPlatform(&en, info)
		if en.IsDir {
			en.Size = 0
			// Never leave the share's filesystem: pseudo filesystems (/proc, /sys) report
			// fake sizes and other mounts belong to other shares.
			if kind := mountBoundary(filepath.Join(l.abs(rel), e.Name()), l.rootDev, info); kind != "" {
				en.Link = kind
			}
		} else if key, multi := inodeKey(info); multi {
			if _, dup := l.seen.LoadOrStore(key, true); dup {
				en.Flags |= flagHardlinkDup
			}
		}
		if l.ads && !en.IsDir && en.Link == "" {
			en.Streams = listStreams(filepath.Join(dir, e.Name()))
		}
		out = append(out, en)
	}
	return out, nil
}

func (l *localLister) DirOwner(rel string) string { return l.owners.owner(longPath(l.abs(rel))) }

// longPath lets Win32 calls go past MAX_PATH. No-op elsewhere.
func longPath(p string) string {
	if !isWindows || strings.HasPrefix(p, `\\?\`) {
		return p
	}
	if strings.HasPrefix(p, `\\`) {
		return `\\?\UNC\` + p[2:]
	}
	if len(p) >= 2 && p[1] == ':' {
		return `\\?\` + p
	}
	return p
}
