package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// interactiveSetup runs when the exe is double-clicked: install the server on this
// machine, or a collector that reports to an existing server.
func interactiveSetup() {
	in := bufio.NewReader(os.Stdin)
	ask := func(q string) string {
		fmt.Print(q)
		s, _ := in.ReadString('\n')
		return strings.TrimSpace(s)
	}
	pause := func() { ask("\nPress Enter to close this window.") }
	fmt.Println("Stratum " + version + " setup")
	fmt.Println("==================")
	fmt.Println()
	fmt.Println("  1  Install the Stratum server on this PC (web UI on port 8470). Start here.")
	fmt.Println("  2  Install a collector that reports to a Stratum server you already run.")
	fmt.Println()
	if c := ask("Choose 1 or 2 [1]: "); c != "2" {
		fmt.Println("\nInstalling the StratumServer service. Approve the Windows administrator prompt;")
		fmt.Println("your browser opens on http://localhost:8470 when it is ready (sign in as admin / admin).")
		if err := installServer(); err != nil && err != errAsyncInstall {
			fmt.Println("Install failed:", err)
		}
		pause()
		return
	}
	fmt.Println()
	fmt.Println("Stratum collector setup")
	fmt.Println("=======================")
	fmt.Println("This installs the collector as a Windows service on this machine. It connects out to")
	fmt.Println("your Stratum server over HTTPS; nothing is opened inbound.")
	fmt.Println()
	fmt.Println("Find both values in Stratum: Sources > Collectors > New collector.")
	fmt.Println()
	server := strings.TrimRight(ask("Stratum server URL (e.g. https://stratum.example.com:9443): "), "/")
	if server == "" {
		fmt.Println("No server entered, nothing changed.")
		pause()
		return
	}
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	token := ask("Collector token (starts with stc_): ")
	if !strings.HasPrefix(token, "stc_") {
		fmt.Println("That does not look like a collector token (it starts with stc_). Nothing changed.")
		pause()
		return
	}
	fmt.Print("Checking the server and token... ")
	req, _ := http.NewRequest("POST", server+"/api/c/poll", strings.NewReader(`{"hostname":"setup-check"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	insecure := false
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil && strings.Contains(err.Error(), "certificate") {
		fmt.Println("\nThe server's certificate is not trusted by this machine.")
		if strings.EqualFold(ask("Continue anyway, accepting it (y/N)? "), "y") {
			insecure = true
			c := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
			req, _ = http.NewRequest("POST", server+"/api/c/poll", strings.NewReader(`{"hostname":"setup-check"}`))
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err = c.Do(req)
		}
	}
	if err != nil {
		fmt.Printf("\nCould not reach %s: %v\n", server, err)
		pause()
		return
	}
	resp.Body.Close()
	if resp.StatusCode == 401 {
		fmt.Println("\nThe server rejected this token. Copy it again from the New collector dialog (or rotate it).")
		pause()
		return
	}
	if resp.StatusCode >= 300 {
		fmt.Printf("\nUnexpected answer from the server: HTTP %d\n", resp.StatusCode)
		pause()
		return
	}
	fmt.Println("OK")
	args := []string{"-server", server, "-token", token, "-syslog", ":5514"}
	if insecure {
		args = append(args, "-insecure")
	}
	fmt.Println("Installing. Approve the Windows administrator prompt; a message confirms the result.")
	if err := installService(args); err != nil && err != errAsyncInstall {
		fmt.Println("Install failed:", err)
	}
	pause()
}

// autoInstall runs a pre-configured installer: nothing to type, one admin approval.
func autoInstall(cfg *embeddedConfig) {
	args := []string{"-server", cfg.Server, "-token", cfg.Token, "-syslog", ":5514"}
	if cfg.Insecure {
		args = append(args, "-insecure")
	}
	if cfg.Pin != "" {
		args = append(args, "-pin", cfg.Pin)
	}
	if !isWindows {
		// Linux: run in the foreground; a systemd unit can call "collector -server ... -token ...".
		fmt.Printf("Stratum collector %q reporting to %s (Ctrl+C to stop)\n", cfg.Name, cfg.Server)
		collectorMain(args)
		return
	}
	fmt.Printf("Stratum collector %q\nServer: %s\n\n", cfg.Name, cfg.Server)
	fmt.Println("Installing as a Windows service. Approve the administrator prompt;")
	fmt.Println("a message box confirms the result. This window closes by itself.")
	err := installService(args)
	if err != nil && err != errAsyncInstall {
		fmt.Println("\nInstall failed:", err)
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	time.Sleep(6 * time.Second)
}
