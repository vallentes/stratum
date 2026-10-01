package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Pre-configured collector installers. The server appends a small config trailer
// (server URL + collector token) to the stock binary; Windows and Linux both ignore
// bytes after the executable image. On double-click the collector finds the trailer
// and installs itself without asking for anything but administrator approval.
//
// Trailer layout: <json> <uint64 little-endian json length> "STRATCFG"

const cfgMagic = "STRATCFG"

type embeddedConfig struct {
	Server   string `json:"server"`
	Token    string `json:"token"`
	Name     string `json:"name"`
	Insecure bool   `json:"insecure,omitempty"`
	Pin      string `json:"pin,omitempty"` // server certificate SHA-256 when it is self-signed
}

func readEmbeddedConfig() *embeddedConfig {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	return readConfigFrom(exe)
}

func readConfigFrom(file string) *embeddedConfig {
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() < 16 {
		return nil
	}
	tail := make([]byte, 16)
	if _, err := f.ReadAt(tail, st.Size()-16); err != nil || string(tail[8:]) != cfgMagic {
		return nil
	}
	n := int64(binary.LittleEndian.Uint64(tail[:8]))
	if n <= 0 || n > 64<<10 || n > st.Size()-16 {
		return nil
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, st.Size()-16-n); err != nil {
		return nil
	}
	var c embeddedConfig
	if json.Unmarshal(buf, &c) != nil || c.Server == "" || !strings.HasPrefix(c.Token, "stc_") {
		return nil
	}
	return &c
}

var safeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// collectorInstaller streams a binary with this collector's config appended. The token
// travels in the POST body (never in a URL, so it cannot land in proxy logs) and must
// match the collector: only someone holding the token can build its installer.
func (a *App) collectorInstaller(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token  string `json:"token"`
		OS     string `json:"os"`
		Server string `json:"server"`
	}
	if err := readJSON(r, &in); err != nil || in.Token == "" {
		httpErr(w, 400, "token required")
		return
	}
	var name, hash string
	if a.st.db.QueryRow(`SELECT name, token_hash FROM collectors WHERE id=?`, idOf(r)).Scan(&name, &hash) != nil || hashToken(in.Token) != hash {
		httpErr(w, 403, "that token does not belong to this collector; rotate it to get a new one")
		return
	}
	src, out := "stratum.exe", "stratum-collector-"+safeName.ReplaceAllString(name, "-")+".exe"
	if in.OS == "linux" {
		src, out = "stratum-linux", "stratum-collector-"+safeName.ReplaceAllString(name, "-")
	}
	exe, _ := os.Executable()
	f, err := os.Open(filepath.Join(filepath.Dir(exe), "dist", src))
	if err != nil {
		httpErr(w, 404, "collector binaries are not published on this server (dist/"+src+")")
		return
	}
	defer f.Close()
	server := strings.TrimRight(in.Server, "/")
	if server == "" {
		server = "https://" + r.Host
	}
	ec := embeddedConfig{Server: server, Token: in.Token, Name: name}
	// Reached by IP over the server's own self-signed certificate: pin it.
	if u, err := url.Parse(server); err == nil && tlsPin != "" && net.ParseIP(u.Hostname()) != nil {
		ec.Pin = tlsPin
	}
	cfg, _ := json.Marshal(ec)
	var trailer bytes.Buffer
	trailer.Write(cfg)
	binary.Write(&trailer, binary.LittleEndian, uint64(len(cfg)))
	trailer.WriteString(cfgMagic)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+out+`"`)
	w.Header().Set("Cache-Control", "no-store")
	io.Copy(w, f)
	w.Write(trailer.Bytes())
}
