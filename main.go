package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed web
var webFS embed.FS

const version = "0.5.0"

type App struct {
	st           *Store
	key          []byte
	mu           sync.Mutex
	running      map[int64]*scanProgress
	sessions     map[string]int64
	audit        *auditAgg
	tw           *tripwire
	auditDropped atomic.Int64
	ipCache      map[string]int64
	ipCacheAt    time.Time
	seen         map[int64]map[string]any // live collector check-ins
	wmu          sync.Mutex               // serialises bulk index writes: SQLite has one writer at a time
}

func main() {
	if len(os.Args) == 1 {
		if cfg := readEmbeddedConfig(); cfg != nil {
			autoInstall(cfg) // pre-configured installer downloaded from the server
			return
		}
		if startedByDoubleClick() {
			interactiveSetup()
			return
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "collector" {
		collectorMain(os.Args[2:])
		return
	}
	addr := flag.String("addr", ":8470", "HTTP listen address")
	dataDir := flag.String("data", "data", "data directory (index database, key)")
	syslogAddr := flag.String("syslog", ":5514", "audit syslog listen address (udp+tcp), empty to disable")
	resetPw := flag.String("reset-password", "", "set a temporary password for -user (they choose a new one at sign-in) and exit")
	resetUser := flag.String("user", "admin", "user for -reset-password")
	pprofAddr := flag.String("pprof", "", "serve Go profiling on this address (keep it on 127.0.0.1)")
	tlsAddr := flag.String("tls-addr", "", "also serve HTTPS with a self-signed certificate on this address, e.g. 203.0.113.10:8443")
	listShares := flag.Bool("list-shares", false, "print devices and shares and exit")
	deleteShare := flag.Int64("delete-share", 0, "remove a share and its index (not the data) and exit")
	installSrv := flag.Bool("install-server", false, "Windows: install the server as the StratumServer service on port 8470 and exit")
	uninstallSrv := flag.Bool("uninstall-server", false, "Windows: remove the StratumServer service (the index is kept) and exit")
	flag.Parse()

	if *installSrv || *uninstallSrv {
		do := installServer
		if *uninstallSrv {
			do = uninstallServer
		}
		if err := do(); err != nil && err != errAsyncInstall {
			log.Fatal(err)
		}
		return
	}
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatal(err)
	}
	if isWindowsService() {
		// No console under the service manager: keep the log next to the index.
		lp := filepath.Join(*dataDir, "stratum.log")
		if fi, err := os.Stat(lp); err == nil && fi.Size() > 20<<20 {
			os.Rename(lp, lp+".1")
		}
		if f, err := os.OpenFile(lp, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			log.SetOutput(f)
		}
	}
	st, err := openStore(filepath.Join(*dataDir, "stratum.db"))
	if err != nil {
		log.Fatal(err)
	}
	a := &App{st: st, running: map[int64]*scanProgress{}, sessions: map[string]int64{}}
	a.key, err = loadKey(filepath.Join(*dataDir, "secret.key"))
	if err != nil {
		log.Fatal(err)
	}
	a.ensureUsers()
	if *resetPw != "" {
		// Recovery: set a temporary password for -user (default admin), re-enable it and
		// require a new password at the next sign-in.
		res, _ := st.db.Exec(`UPDATE users SET disabled=0 WHERE username=?`, *resetUser)
		if n, _ := res.RowsAffected(); n == 0 {
			log.Fatalf("no user %q", *resetUser)
		}
		var id int64
		st.db.QueryRow(`SELECT id FROM users WHERE username=?`, *resetUser).Scan(&id)
		a.setUserPassword(id, *resetPw, true)
		fmt.Printf("temporary password set for %s; a new one is required at the next sign-in\n", *resetUser)
		return
	}
	// Admin commands for when the UI is not reachable (stop the service first).
	if *listShares {
		for _, id := range a.ids(`SELECT id FROM shares ORDER BY id`) {
			s, _ := a.share(id)
			d, _ := a.device(s.DeviceID)
			var files, bytes int64
			a.st.db.QueryRow(`SELECT files, bytes FROM scans WHERE id=?`, s.CurrentScan).Scan(&files, &bytes)
			fmt.Printf("share %d\tdevice %d %q\t%q\t%s\t%d files\t%s\n", s.ID, d.ID, d.Name, s.Name, s.Path, files, fmtB(bytes))
		}
		return
	}
	if *deleteShare > 0 {
		s, err := a.share(*deleteShare)
		if err != nil {
			log.Fatalf("share %d not found", *deleteShare)
		}
		for _, id := range []int64{s.CurrentScan, s.FailedScan} {
			if id > 0 {
				a.purgeScan(id, true)
			}
		}
		for _, id := range a.ids(`SELECT id FROM scans WHERE share_id=?`, s.ID) {
			a.purgeScan(id, true)
		}
		a.dropShareIndex(s.ID)
		fmt.Printf("share %d (%s) and its index removed; nothing on the storage was touched\n", s.ID, s.Path)
		return
	}
	var mustChange int
	st.db.QueryRow(`SELECT must_change FROM users WHERE username='admin'`).Scan(&mustChange)
	if mustChange == 1 {
		log.Printf("sign in as admin / %s; you will be asked to choose a new password", defaultAdminPassword)
	}
	// Scans that were running when the process stopped never published; mark them.
	st.db.Exec(`UPDATE automation_runs SET status='failed', message='service restarted mid-run', finished=? WHERE status='running'`, now())
	st.db.Exec(`UPDATE automations SET last_status='failed' WHERE last_status='running'`)
	// Rows left by scans that never published (cut off by a restart); purged in chunks in the background.
	go func() {
		for _, id := range a.ids(`SELECT id FROM scans WHERE status<>'running' AND id NOT IN (SELECT current_scan FROM shares) AND finished >= ?`, now()-30*86400) {
			a.purgeScan(id, false)
		}
		a.backfillAggregates()
	}()

	a.audit = newAuditAgg(a)
	a.tw = newTripwire(a)
	syslogListen(*syslogAddr, a.ingestLine)
	startWindowsAudit(a.localWindowsDevice, a.audit.add,
		func() uint64 { n, _ := strconv.ParseUint(st.setting("winaudit_last_id"), 10, 64); return n },
		func(n uint64) { st.setSetting("winaudit_last_id", strconv.FormatUint(n, 10)) })
	go a.resumeInterrupted()
	go a.recoverAuditResults()
	go a.liveIndexer()
	go a.perfCollector()
	go a.scheduler()
	go a.checkpointer()
	if *pprofAddr != "" {
		go http.ListenAndServe(*pprofAddr, http.DefaultServeMux) // net/http/pprof registers on the default mux
	}

	mux := http.NewServeMux()
	a.routes(mux)
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	srv := &http.Server{Addr: *addr, Handler: logRequests(mux), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
		a.audit.flush(true)
		os.Exit(0)
	}()
	if *tlsAddr != "" {
		cert, err := loadOrCreateCert(*dataDir, *tlsAddr)
		if err != nil {
			log.Fatalf("tls: %v", err)
		}
		tlsPin = certPin(cert)
		ts := &http.Server{Addr: *tlsAddr, Handler: logRequests(mux), ReadHeaderTimeout: 10 * time.Second,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
		go func() { log.Fatal(ts.ListenAndServeTLS("", "")) }()
		log.Printf("stratum %s also on https://%s (self-signed, SHA-256 %s)", version, *tlsAddr, tlsPin)
	}
	log.Printf("stratum %s listening on http://%s", version, *addr)
	serve := func() { log.Fatal(srv.ListenAndServe()) }
	if runService(serve) { // started by the Windows service manager; returns on stop
		a.audit.flush(true)
		return
	}
	serve()
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		h.ServeHTTP(w, r)
		if d := time.Since(t); d > 2*time.Second {
			log.Printf("slow %s %s %s", r.Method, r.URL.Path, d.Round(time.Millisecond))
		}
	})
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- secrets at rest: device passwords are sealed with a local AES-GCM key ----

func loadKey(p string) ([]byte, error) {
	if b, err := os.ReadFile(p); err == nil && len(b) == 32 {
		return b, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, os.WriteFile(p, k, 0o600)
}

func (a *App) seal(plain string) string {
	blk, _ := aes.NewCipher(a.key)
	g, _ := cipher.NewGCM(blk)
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce)
	return base64.StdEncoding.EncodeToString(g.Seal(nonce, nonce, []byte(plain), nil))
}

func (a *App) unseal(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	blk, _ := aes.NewCipher(a.key)
	g, _ := cipher.NewGCM(blk)
	if len(raw) < g.NonceSize() {
		return "", errors.New("bad secret")
	}
	out, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
	return string(out), err
}

// checkpointer keeps the write-ahead log small. Automatic checkpoints are passive and
// never shrink the WAL while scans write continuously, and a large WAL makes every
// page read slower: that is what throttled multi-million-file scans.
func (a *App) checkpointer() {
	for range time.Tick(20 * time.Second) {
		a.wmu.Lock()
		a.st.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		a.wmu.Unlock()
	}
}
