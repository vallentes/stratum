package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

// One walk per physical disk at a time. Partitions of one spinning disk (D: and E:
// on the same drive) seek back and forth when walked in parallel until both crawl,
// while separate disks should run side by side. Local Windows drive letters are
// mapped to their physical disk; anything else (UNC shares, PowerScale, S3, Linux
// paths) is serialised per device. Extra scans wait in line and show as queued.

var scanLocks sync.Map // key -> chan struct{} (capacity 1)

func lockSlot(key string) chan struct{} {
	v, _ := scanLocks.LoadOrStore(key, make(chan struct{}, 1))
	return v.(chan struct{})
}

// scanLockKey names the resource a walk of this share competes for.
func scanLockKey(d Device, s Share) string {
	if d.Kind == "windows" && isWindows && !strings.HasPrefix(s.Path, `\\`) {
		if vol := filepath.VolumeName(s.Path); len(vol) == 2 && vol[1] == ':' {
			if disks := physicalDisks(vol); len(disks) > 0 {
				return fmt.Sprintf("disk:%v", disks)
			}
			return "vol:" + strings.ToUpper(vol)
		}
	}
	return fmt.Sprintf("device:%d", d.ID)
}

// acquireScanSlot blocks until the disk (or device) is free or ctx ends.
func acquireScanSlot(ctx context.Context, d Device, s Share, p *scanProgress) (release func(), ok bool) {
	slot := lockSlot(scanLockKey(d, s))
	select {
	case slot <- struct{}{}:
		return func() { <-slot }, true
	default:
	}
	p.setCurrent("queued: another scan is reading the same disk")
	select {
	case slot <- struct{}{}:
		return func() { <-slot }, true
	case <-ctx.Done():
		return func() {}, false
	}
}
