package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Collector self-update. Every poll reply carries the server version; when it differs
// and no scan is running, the collector downloads the matching binary (authenticated
// with its own token), checks the SHA-256 the server announced, swaps the executable
// and exits so the service manager restarts it on the new version. Windows allows
// renaming a running executable, which is what makes the swap possible.

func (a *App) collectorBinary(w http.ResponseWriter, r *http.Request, cid int64) {
	name := "stratum.exe"
	if r.URL.Query().Get("os") == "linux" {
		name = "stratum-linux"
	}
	exe, _ := os.Executable()
	http.ServeFile(w, r, filepath.Join(filepath.Dir(exe), "dist", name))
}

// distSHA returns the checksum of a published binary (cached by modification time).
var distSums = map[string][2]string{}

func distSHA(name string) string {
	exe, _ := os.Executable()
	p := filepath.Join(filepath.Dir(exe), "dist", name)
	st, err := os.Stat(p)
	if err != nil {
		return ""
	}
	key := st.ModTime().String()
	if v, ok := distSums[name]; ok && v[0] == key {
		return v[1]
	}
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	sum := hex.EncodeToString(h.Sum(nil))
	distSums[name] = [2]string{key, sum}
	return sum
}

// selfUpdate replaces the running collector binary. Returns true when the process
// should exit so the service restarts it.
func (c *collectorClient) selfUpdate(serverVersion, wantSHA string) bool {
	if serverVersion == "" || serverVersion == version || wantSHA == "" || !runningAsService() {
		return false
	}
	c.mu.Lock()
	busy := len(c.scans) > 0 || c.inflight.Load() > 0
	c.mu.Unlock()
	if busy {
		return false // never interrupt a scan or a running job; try again on a later poll
	}
	// Never apply the same binary twice: if the server publishes a build whose version
	// string does not change, this stops a restart loop.
	marker := filepath.Join(c.dataDir, "last-update-sha")
	if b, _ := os.ReadFile(marker); strings.TrimSpace(string(b)) == wantSHA {
		return false
	}
	osName := "windows"
	if runtime.GOOS != "windows" {
		osName = "linux"
	}
	req, _ := http.NewRequest("GET", c.server+"/api/c/binary?os="+osName, nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.hc.Do(req)
	if err != nil {
		log.Printf("update to %s: %v", serverVersion, err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Printf("update to %s: HTTP %d", serverVersion, resp.StatusCode)
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	newPath := exe + ".new"
	f, err := os.Create(newPath)
	if err != nil {
		log.Printf("update: %v", err)
		return false
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	f.Close()
	if err != nil || !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), wantSHA) {
		os.Remove(newPath)
		log.Printf("update to %s: download incomplete or checksum mismatch, skipped", serverVersion)
		return false
	}
	old := exe + ".old"
	os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		os.Remove(newPath)
		log.Printf("update: cannot move the running binary aside: %v", err)
		return false
	}
	if err := os.Rename(newPath, exe); err != nil {
		os.Rename(old, exe) // put the working binary back
		log.Printf("update: %v", err)
		return false
	}
	os.Chmod(exe, 0o755)
	os.WriteFile(marker, []byte(wantSHA), 0o600)
	log.Printf("updated %s -> %s; restarting", version, serverVersion)
	return true
}

func runningAsService() bool { return serviceMode }

var serviceMode bool

var _ = fmt.Sprintf
