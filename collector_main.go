package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

var errAsyncInstall = errors.New("continuing in the elevated window")

// collectorMain handles "stratum collector ...".
func collectorMain(args []string) {
	fs := flag.NewFlagSet("collector", flag.ExitOnError)
	server := fs.String("server", "", "central Stratum URL, e.g. https://stratum.example.com")
	token := fs.String("token", "", "collector token from Sources > Collectors")
	exe, _ := os.Executable()
	dataDir := fs.String("data", filepath.Join(filepath.Dir(exe), "collector-data"), "local state directory")
	insecure := fs.Bool("insecure", false, "accept a self-signed server certificate")
	pin := fs.String("pin", "", "trust only the server certificate with this SHA-256 fingerprint")
	syslogAddr := fs.String("syslog", ":5514", "receive PowerScale audit syslog on this address (empty to disable)")
	install := fs.Bool("install", false, "install as a Windows service (administrator prompt) and start it")
	uninstall := fs.Bool("uninstall", false, "stop and remove the Windows service")
	fs.Parse(args)

	if *uninstall {
		if err := uninstallService(); err != nil {
			fmt.Println("uninstall failed:", err)
			os.Exit(1)
		}
		fmt.Println("collector service removed")
		return
	}
	if *server == "" || *token == "" {
		fmt.Println("usage: stratum collector -server https://your-server -token stc_... [-install]")
		os.Exit(2)
	}
	abs, _ := filepath.Abs(*dataDir)
	if *install {
		svcArgs := []string{"-server", *server, "-token", *token, "-data", abs, "-syslog", *syslogAddr}
		if *insecure {
			svcArgs = append(svcArgs, "-insecure")
		}
		if *pin != "" {
			svcArgs = append(svcArgs, "-pin", *pin)
		}
		if err := installService(svcArgs); err == errAsyncInstall {
			return
		} else if err != nil {
			fmt.Println("install failed:", err)
			os.Exit(1)
		}
		fmt.Println("collector installed as service StratumCollector and started")
		return
	}
	os.MkdirAll(abs, 0o700)
	collectorPin = *pin
	run := func() { runCollector(*server, *token, abs, *insecure, *syslogAddr) }
	serviceMode = os.Getenv("INVOCATION_ID") != "" // systemd
	if runService(func() {
		serviceMode = true
		logTo(filepath.Join(abs, "collector.log"))
		run()
	}) {
		return
	}
	run()
}

// logTo sends the log to a file (services have no console), starting fresh past 20 MB.
func logTo(p string) {
	if st, err := os.Stat(p); err == nil && st.Size() > 20<<20 {
		os.Rename(p, p+".1")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err == nil {
		log.SetOutput(io.MultiWriter(f))
	}
}
