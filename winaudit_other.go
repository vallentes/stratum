//go:build linux

package main

import "errors"

type WinAuditStatus struct {
	Enabled bool   `json:"enabled"`
	Error   string `json:"error,omitempty"`
	LastID  uint64 `json:"last_record_id"`
	Events  int64  `json:"events"`
}

var winAudit = WinAuditStatus{Error: "Windows audit collection runs in the Windows collector"}

func startWindowsAudit(getDev func() int64, emit func(AuditEvent), load func() uint64, save func(uint64)) {
}

func enableFileAuditing(paths []string) (map[string]string, error) {
	return nil, errors.New("file auditing can only be enabled by a Windows collector")
}

func disableFileAuditing(paths []string) (map[string]string, error) {
	return nil, errors.New("file auditing can only be changed by a Windows collector")
}
