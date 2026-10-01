//go:build linux

package main

import "errors"

func runService(fn func()) bool { return false }

func installService(args []string) error {
	return errors.New("on Linux, run the collector under systemd (see README)")
}

func uninstallService() error { return errors.New("on Linux, remove the systemd unit") }

func startedByDoubleClick() bool { return false }

func processOps(pid int) int64 { return 0 }

func physicalDisks(vol string) []uint32 { return nil }
