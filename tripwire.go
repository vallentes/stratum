package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Tripwire: ransomware early warning on top of the audit stream. Every audit event
// (Windows Security log, OneFS syslog, ingest API) passes through observe, which keeps
// per-account counters for the current minute in memory and fires on:
//   burst       one account changes more files in a minute than the threshold
//   ransom_ext  files with known ransomware endings appear
//   ransom_note a ransom note is written
//   decoy       a decoy file planted by Stratum is changed, renamed or deleted
// Alerts are stored, sent to email / Teams / Slack / a webhook, and can block the
// account's access to the file server's shares (manually, or automatically when on).

type twConfig struct {
	Enabled     bool     `json:"enabled"`
	BurstPerMin int      `json:"burst_per_min"`
	ExtPerMin   int      `json:"ext_per_min"`
	CooldownMin int      `json:"cooldown_min"`
	AutoBlock   bool     `json:"auto_block"`
	NeverBlock  []string `json:"never_block"`
	LinkURL     string   `json:"link_url"`
	SMTPHost    string   `json:"smtp_host"`
	SMTPPort    int      `json:"smtp_port"`
	SMTPUser    string   `json:"smtp_user"`
	SMTPPass    string   `json:"smtp_pass"`
	SMTPTLS     string   `json:"smtp_tls"` // starttls | tls | none
	MailFrom    string   `json:"mail_from"`
	MailTo      string   `json:"mail_to"`
	TeamsURL    string   `json:"teams_url"`
	SlackURL    string   `json:"slack_url"`
	WebhookURL  string   `json:"webhook_url"`
}

// Secret fields are sealed at rest and never sent back to the browser.
var twSecrets = []string{"smtp_pass", "teams_url", "slack_url", "webhook_url"}

func twDefaults() twConfig {
	return twConfig{Enabled: true, BurstPerMin: 300, ExtPerMin: 20, CooldownMin: 15, NeverBlock: []string{"Administrator"}, SMTPPort: 587, SMTPTLS: "starttls"}
}

func (c twConfig) toMap() map[string]any {
	b, _ := json.Marshal(c)
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

func twFromMap(m map[string]any) twConfig {
	b, _ := json.Marshal(m)
	c := twDefaults()
	json.Unmarshal(b, &c)
	return c
}

func (a *App) twLoad() twConfig {
	raw := a.st.setting("tripwire")
	if raw == "" {
		return twDefaults()
	}
	var m map[string]any
	json.Unmarshal([]byte(raw), &m)
	for _, k := range twSecrets {
		if s, _ := m[k].(string); s != "" {
			m[k], _ = a.unseal(s)
		}
	}
	return twFromMap(m)
}

func (a *App) twSave(c twConfig) {
	m := c.toMap()
	for _, k := range twSecrets {
		if s, _ := m[k].(string); s != "" {
			m[k] = a.seal(s)
		}
	}
	b, _ := json.Marshal(m)
	a.st.setSetting("tripwire", string(b))
	if a.tw != nil {
		a.tw.setConfig(c)
	}
}

type twWin struct {
	min     int64
	changes int
	ext     int
	sample  []string
	extHits []string // files with ransomware endings, for that alert's sample
	fired   map[string]bool
	client  string
}

type twDecoy struct {
	ID       int64
	DeviceID int64
	ShareID  int64
	Path     string
}

type tripwire struct {
	a      *App
	mu     sync.Mutex
	cfg    twConfig
	wins   map[string]*twWin
	decoys map[string]twDecoy
	quiet  map[string]int64 // normalized path -> ignore events until (planting and removal by Stratum)
	exts   map[string]bool
	notes  []string
	pruned int64
}

func newTripwire(a *App) *tripwire {
	t := &tripwire{a: a, cfg: a.twLoad(), wins: map[string]*twWin{}, quiet: map[string]int64{}, exts: map[string]bool{}}
	for _, e := range ransomExts {
		t.exts[e] = true
	}
	for _, p := range ransomNotePatterns { // SQL LIKE patterns -> globs
		t.notes = append(t.notes, strings.NewReplacer("%", "*", "_", "?").Replace(p))
	}
	t.loadDecoys()
	return t
}

func (t *tripwire) setConfig(c twConfig) {
	t.mu.Lock()
	t.cfg = c
	t.mu.Unlock()
}

func (t *tripwire) loadDecoys() {
	m := map[string]twDecoy{}
	rows, err := t.a.st.db.Query(`SELECT id, device_id, share_id, path FROM tw_decoys`)
	if err == nil {
		for rows.Next() {
			var d twDecoy
			rows.Scan(&d.ID, &d.DeviceID, &d.ShareID, &d.Path)
			m[twNorm(d.Path)] = d
		}
		rows.Close()
	}
	t.mu.Lock()
	t.decoys = m
	t.mu.Unlock()
}

// twNorm makes Windows, UNC-less and OneFS paths comparable: forward slashes, lower case,
// and OneFS's optional drive prefix ("C:\ifs\...") dropped.
func twNorm(p string) string {
	p = strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if len(p) > 2 && p[1] == ':' && strings.HasPrefix(p[2:], "/ifs/") {
		p = p[2:]
	}
	return strings.TrimSuffix(p, "/")
}

func (t *tripwire) isNote(name string) bool {
	for _, g := range t.notes {
		if ok, _ := path.Match(g, name); ok {
			return true
		}
	}
	return false
}

// observe is called for every audit event; it must stay cheap.
func (t *tripwire) observe(e AuditEvent) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.cfg.Enabled {
		return
	}
	if e.TS == 0 {
		e.TS = now()
	}
	np := twNorm(e.Path)
	if until, ok := t.quiet[np]; ok {
		if now() < until {
			return
		}
		delete(t.quiet, np)
	}
	if d, ok := t.decoys[np]; ok && (e.Op == "modify" || e.Op == "delete" || e.Op == "rename") {
		t.fireLocked(e, "decoy", d.ShareID, 1, []string{e.Path})
		return
	}
	switch e.Op {
	case "modify", "delete", "rename", "create":
	default:
		return
	}
	key := strconv.FormatInt(e.DeviceID, 10) + "|" + strings.ToLower(e.User)
	m := e.TS / 60
	w := t.wins[key]
	if w == nil || w.min != m {
		w = &twWin{min: m, fired: map[string]bool{}}
		t.wins[key] = w
	}
	w.changes++
	if e.Client != "" {
		w.client = e.Client
	}
	if len(w.sample) < 8 {
		w.sample = append(w.sample, e.Path)
	}
	name := path.Base(np)
	if i := strings.LastIndexByte(name, '.'); i >= 0 && t.exts[name[i+1:]] {
		w.ext++
		if len(w.extHits) < 8 {
			w.extHits = append(w.extHits, e.Path)
		}
	}
	if (e.Op == "create" || e.Op == "modify") && !w.fired["ransom_note"] && t.isNote(name) {
		w.fired["ransom_note"] = true
		t.fireLocked(e, "ransom_note", 0, 1, []string{e.Path})
	}
	if t.cfg.ExtPerMin > 0 && w.ext >= t.cfg.ExtPerMin && !w.fired["ransom_ext"] {
		w.fired["ransom_ext"] = true
		t.fireLocked(e, "ransom_ext", 0, w.ext, w.extHits)
	}
	if t.cfg.BurstPerMin > 0 && w.changes >= t.cfg.BurstPerMin && !w.fired["burst"] {
		w.fired["burst"] = true
		t.fireLocked(e, "burst", 0, w.changes, w.sample)
	}
	if now()-t.pruned > 60 {
		t.pruned = now()
		cut := now()/60 - 5
		for k, x := range t.wins {
			if x.min < cut {
				delete(t.wins, k)
			}
		}
	}
}

type twAlert struct {
	ID       int64    `json:"id"`
	TS       int64    `json:"ts"`
	LastTS   int64    `json:"last_ts"`
	DeviceID int64    `json:"device_id"`
	Device   string   `json:"device"`
	ShareID  int64    `json:"share_id"`
	Share    string   `json:"share"`
	User     string   `json:"user"`
	Client   string   `json:"client"`
	Rule     string   `json:"rule"`
	Severity string   `json:"severity"`
	Detail   string   `json:"detail"`
	Sample   []string `json:"sample"`
	Count    int      `json:"count"`
	Status   string   `json:"status"`
	Blocked  bool     `json:"blocked"`
	Block    string   `json:"block_note"`
	Notified string   `json:"notified"`
}

var twRuleLabel = map[string]string{
	"decoy":       "Decoy file touched",
	"ransom_note": "Ransom note written",
	"ransom_ext":  "Files with ransomware endings",
	"burst":       "Mass change by one account",
	"test":        "Test alert",
}

func (t *tripwire) fireLocked(e AuditEvent, rule string, shareID int64, count int, sample []string) {
	sev := "critical"
	detail := ""
	switch rule {
	case "decoy":
		detail = "A decoy file nobody should ever open was " + map[string]string{"modify": "changed", "delete": "deleted", "rename": "renamed"}[e.Op] + "."
	case "ransom_note":
		detail = "A file named like a ransom note appeared: " + path.Base(e.Path)
	case "ransom_ext":
		detail = fmt.Sprintf("%d files with known ransomware endings in one minute (threshold %d).", count, t.cfg.ExtPerMin)
	case "burst":
		sev = "warning"
		detail = fmt.Sprintf("%d files changed in one minute (threshold %d).", count, t.cfg.BurstPerMin)
	}
	al := twAlert{TS: e.TS, DeviceID: e.DeviceID, ShareID: shareID, User: e.User, Client: e.Client, Rule: rule, Severity: sev,
		Detail: detail, Sample: append([]string{}, sample...), Count: count}
	cfg := t.cfg
	go t.a.twRaise(al, cfg)
}

var twRaiseMu sync.Mutex

// twRaise stores an alert (or adds to an open one for the same account and rule),
// notifies, and blocks when automatic response is on.
func (a *App) twRaise(al twAlert, cfg twConfig) int64 {
	if al.ShareID == 0 {
		al.ShareID = a.shareForPath(al.DeviceID, al.Path0())
	}
	dedupe := fmt.Sprintf("%d|%s|%s", al.DeviceID, strings.ToLower(al.User), al.Rule)
	cool := int64(cfg.CooldownMin) * 60
	if cool <= 0 {
		cool = 900
	}
	var id int64
	// Check-then-insert must be atomic, or two alerts raised at the same moment for the
	// same account and rule would both be stored.
	twRaiseMu.Lock()
	if al.Rule != "test" && a.st.db.QueryRow(`SELECT id FROM tw_alerts WHERE dedupe=? AND status='open' AND last_ts >= ?`, dedupe, now()-cool).Scan(&id) == nil {
		a.st.db.Exec(`UPDATE tw_alerts SET count=count+?, last_ts=? WHERE id=?`, max(al.Count, 1), now(), id)
		twRaiseMu.Unlock()
		return id
	}
	sample, _ := json.Marshal(al.Sample)
	res, err := a.st.db.Exec(`INSERT INTO tw_alerts(ts,last_ts,device_id,share_id,username,client,rule,severity,detail,sample,count,status,dedupe)
	  VALUES(?,?,?,?,?,?,?,?,?,?,?,'open',?)`, now(), now(), al.DeviceID, al.ShareID, al.User, al.Client, al.Rule, al.Severity, al.Detail, string(sample), al.Count, dedupe)
	twRaiseMu.Unlock()
	if err != nil {
		log.Printf("tripwire: store alert: %v", err)
		return 0
	}
	id, _ = res.LastInsertId()
	al.ID = id
	if d, err := a.device(al.DeviceID); err == nil {
		al.Device = d.Name
	}
	log.Printf("tripwire: %s on device %d by %q: %s", al.Rule, al.DeviceID, al.User, al.Detail)
	notes := twNotify(cfg, al)
	a.st.db.Exec(`UPDATE tw_alerts SET notified=? WHERE id=?`, strings.Join(notes, "; "), id)
	if cfg.AutoBlock && al.Rule != "test" {
		if why := twProtected(cfg, al.User); why != "" {
			a.st.db.Exec(`UPDATE tw_alerts SET block_note=? WHERE id=?`, "not blocked automatically: "+why, id)
		} else if _, err := a.twBlock(id, true, "automatic"); err != nil {
			a.st.db.Exec(`UPDATE tw_alerts SET block_note=? WHERE id=?`, "automatic block failed: "+err.Error(), id)
		}
	}
	return id
}

func (al twAlert) Path0() string {
	if len(al.Sample) > 0 {
		return al.Sample[0]
	}
	return ""
}

// shareForPath finds the indexed share an event path falls under.
func (a *App) shareForPath(deviceID int64, p string) int64 {
	np := twNorm(p)
	best, bestLen := int64(0), -1
	for _, s := range a.sharesOf(deviceID) {
		sp := twNorm(s.Path)
		if (np == sp || strings.HasPrefix(np, sp+"/")) && len(sp) > bestLen {
			best, bestLen = s.ID, len(sp)
		}
	}
	return best
}

// twProtected says why an account must never be blocked automatically.
func twProtected(cfg twConfig, user string) string {
	u := strings.ToLower(strings.TrimSpace(user))
	short := u
	if i := strings.LastIndexByte(u, '\\'); i >= 0 {
		short = u[i+1:]
	}
	switch {
	case u == "":
		return "the event carries no account name"
	case strings.HasSuffix(u, "$"), short == "system", short == "local service", short == "network service":
		return "machine and system accounts are never blocked"
	}
	for _, n := range cfg.NeverBlock {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" && (n == u || n == short) {
			return "the account is on the never-block list"
		}
	}
	return ""
}

// ---------- notifications ----------

var twHTTP = &http.Client{Timeout: 10 * time.Second}

func twMessage(cfg twConfig, al twAlert) (title, text string) {
	label := twRuleLabel[al.Rule]
	if label == "" {
		label = al.Rule
	}
	title = fmt.Sprintf("Stratum tripwire: %s", label)
	var b strings.Builder
	if al.Device != "" {
		fmt.Fprintf(&b, "Device: %s\n", al.Device)
	}
	if al.User != "" {
		fmt.Fprintf(&b, "Account: %s\n", al.User)
	}
	if al.Client != "" {
		fmt.Fprintf(&b, "Client: %s\n", al.Client)
	}
	b.WriteString(al.Detail + "\n")
	for i, p := range al.Sample {
		if i == 5 {
			break
		}
		fmt.Fprintf(&b, "  %s\n", p)
	}
	if cfg.LinkURL != "" {
		fmt.Fprintf(&b, "Open: %s/#/tripwire\n", strings.TrimRight(cfg.LinkURL, "/"))
	}
	return title, strings.TrimSpace(b.String())
}

func twPost(u string, body any) error {
	b, _ := json.Marshal(body)
	resp, err := twHTTP.Post(u, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// twNotify sends to every configured channel and reports what happened per channel.
func twNotify(cfg twConfig, al twAlert) []string {
	title, text := twMessage(cfg, al)
	var out []string
	note := func(ch string, err error) {
		if err != nil {
			out = append(out, ch+": failed ("+err.Error()+")")
		} else {
			out = append(out, ch+": sent")
		}
	}
	if cfg.SlackURL != "" {
		note("Slack", twPost(cfg.SlackURL, map[string]any{"text": "*" + title + "*\n" + text}))
	}
	if cfg.TeamsURL != "" {
		// Adaptive card, the format Teams workflows ("post to a channel when a webhook
		// request is received") expect.
		card := map[string]any{"type": "message", "attachments": []any{map[string]any{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content": map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
				"body": []any{
					map[string]any{"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": title, "wrap": true, "color": map[bool]string{true: "Attention", false: "Warning"}[al.Severity == "critical"]},
					map[string]any{"type": "TextBlock", "text": strings.ReplaceAll(text, "\n", "\n\n"), "wrap": true},
				}}}}}
		note("Teams", twPost(cfg.TeamsURL, card))
	}
	if cfg.WebhookURL != "" {
		note("Webhook", twPost(cfg.WebhookURL, map[string]any{"source": "stratum", "title": title, "alert": al}))
	}
	if cfg.SMTPHost != "" && cfg.MailTo != "" {
		note("Email", sendMail(cfg, title, text))
	}
	if len(out) == 0 {
		out = append(out, "no notification channel configured")
	}
	return out
}

func sendMail(cfg twConfig, subject, body string) error {
	port := cfg.SMTPPort
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(cfg.SMTPHost, strconv.Itoa(port))
	tcfg := &tls.Config{ServerName: cfg.SMTPHost}
	var c *smtp.Client
	if cfg.SMTPTLS == "tls" {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, tcfg)
		if err != nil {
			return err
		}
		if c, err = smtp.NewClient(conn, cfg.SMTPHost); err != nil {
			return err
		}
	} else {
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return err
		}
		if c, err = smtp.NewClient(conn, cfg.SMTPHost); err != nil {
			return err
		}
		if cfg.SMTPTLS != "none" {
			if ok, _ := c.Extension("STARTTLS"); !ok {
				c.Close()
				return errors.New("the mail server does not offer STARTTLS; choose TLS or none")
			}
			if err := c.StartTLS(tcfg); err != nil {
				c.Close()
				return err
			}
		}
	}
	defer c.Close()
	if cfg.SMTPUser != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)); err != nil {
			return err
		}
	}
	from := cfg.MailFrom
	if from == "" {
		from = cfg.SMTPUser
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	var to []string
	for _, r := range strings.FieldsFunc(cfg.MailTo, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		if err := c.Rcpt(r); err != nil {
			return err
		}
		to = append(to, r)
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	fmt.Fprintf(wc, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		from, strings.Join(to, ", "), subject, time.Now().Format(time.RFC1123Z), strings.ReplaceAll(body, "\n", "\r\n"))
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// ---------- blocking ----------

type twBlockPayload struct {
	Device deviceWire `json:"device"`
	User   string     `json:"user"`
	Block  bool       `json:"block"`
	Shares []string   `json:"shares"` // unblock: exactly the shares the block touched
}

type twBlockResult struct {
	Shares []string `json:"shares"`
}

// twPowerShell runs a script; replaced in tests so no real share is touched.
var twPowerShell = func(script string, env []string) (string, error) {
	c := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	c.Env = append(os.Environ(), env...)
	b, err := c.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(b)))
	}
	return strings.TrimSpace(string(b)), nil
}

// Deny on every non-administrative SMB share, then close the account's open files and
// sessions so the deny takes effect at once. Unblock removes exactly those denies.
const twSMBScript = `$ErrorActionPreference='Stop'
$u=$env:STRATUM_TW_USER
$names=@()
if ($env:STRATUM_TW_MODE -eq 'block') {
  foreach ($s in (Get-SmbShare -Special $false)) { Block-SmbShareAccess -Name $s.Name -ScopeName $s.ScopeName -AccountName $u -Force | Out-Null; $names += $s.Name }
  Get-SmbOpenFile | Where-Object { $_.ClientUserName -eq $u } | Close-SmbOpenFile -Force
  Get-SmbSession | Where-Object { $_.ClientUserName -eq $u } | Close-SmbSession -Force
} else {
  foreach ($n in ($env:STRATUM_TW_SHARES -split '\|')) { if ($n) { Unblock-SmbShareAccess -Name $n -AccountName $u -Force | Out-Null; $names += $n } }
}
$names -join '|'`

// twBlockExec does the storage work; it runs on the server or on a collector.
func twBlockExec(pl twBlockPayload) (twBlockResult, error) {
	d := pl.Device.dev()
	switch d.Kind {
	case "windows":
		if !isLocalHost(d.Host) {
			return twBlockResult{}, errors.New("blocking on a Windows file server runs on that server: install a collector there")
		}
		mode := "unblock"
		if pl.Block {
			mode = "block"
		}
		out, err := twPowerShell(twSMBScript, []string{"STRATUM_TW_USER=" + pl.User, "STRATUM_TW_MODE=" + mode, "STRATUM_TW_SHARES=" + strings.Join(pl.Shares, "|")})
		if err != nil {
			return twBlockResult{}, err
		}
		res := twBlockResult{Shares: []string{}}
		for _, n := range strings.Split(out, "|") {
			if n = strings.TrimSpace(n); n != "" {
				res.Shares = append(res.Shares, n)
			}
		}
		return res, nil
	case "powerscale":
		return psBlock(psClientFor(d), pl.User, pl.Block, pl.Shares)
	}
	return twBlockResult{}, errors.New("blocking is available for Windows file servers and PowerScale clusters")
}

// psBlock adds (or removes) a deny-everything entry for the account on every SMB
// share of every access zone.
func psBlock(c *psClient, user string, block bool, only []string) (twBlockResult, error) {
	var zones struct {
		Zones []struct {
			Name string `json:"name"`
		} `json:"zones"`
	}
	if err := c.getJSON("/platform/1/zones", &zones); err != nil || len(zones.Zones) == 0 {
		zones.Zones = []struct {
			Name string `json:"name"`
		}{{Name: "System"}}
	}
	want := map[string]bool{}
	for _, s := range only {
		want[s] = true
	}
	res := twBlockResult{Shares: []string{}}
	var firstErr error
	for _, z := range zones.Zones {
		var list struct {
			Shares []map[string]any `json:"shares"`
		}
		if err := c.getJSON("/platform/1/protocols/smb/shares?zone="+url.QueryEscape(z.Name), &list); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, s := range list.Shares {
			name, _ := s["name"].(string)
			id := z.Name + "/" + name
			if !block && !want[id] {
				continue
			}
			perms, _ := s["permissions"].([]any)
			isDeny := func(p any) bool {
				m, _ := p.(map[string]any)
				tr, _ := m["trustee"].(map[string]any)
				n, _ := tr["name"].(string)
				return m["permission_type"] == "deny" && strings.EqualFold(n, user)
			}
			var next []any
			if block {
				already := false
				for _, p := range perms {
					already = already || isDeny(p)
				}
				if already {
					res.Shares = append(res.Shares, id)
					continue
				}
				next = append([]any{map[string]any{"permission": "full", "permission_type": "deny", "trustee": map[string]any{"name": user, "type": "user"}}}, perms...)
			} else {
				next = []any{}
				for _, p := range perms {
					if !isDeny(p) {
						next = append(next, p)
					}
				}
			}
			body, _ := json.Marshal(map[string]any{"permissions": next})
			err := c.expect(c.do("PUT", "/platform/1/protocols/smb/shares/"+url.PathEscape(name)+"?zone="+url.QueryEscape(z.Name),
				map[string]string{"Content-Type": "application/json"}, bytes.NewReader(body)))
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("%s: %w", id, err)
				}
				continue
			}
			res.Shares = append(res.Shares, id)
		}
	}
	if len(res.Shares) == 0 && firstErr != nil {
		return res, firstErr
	}
	return res, nil
}

// twBlock blocks (or unblocks) the account of an alert on that alert's device.
func (a *App) twBlock(alertID int64, block bool, by string) (twBlockResult, error) {
	var devID int64
	var user, note string
	var blocked int
	if err := a.st.db.QueryRow(`SELECT device_id, username, COALESCE(block_note,''), blocked FROM tw_alerts WHERE id=?`, alertID).Scan(&devID, &user, &note, &blocked); err != nil {
		return twBlockResult{}, errors.New("alert not found")
	}
	if strings.TrimSpace(user) == "" {
		return twBlockResult{}, errors.New("this alert has no account to block")
	}
	if block && blocked == 1 {
		return twBlockResult{}, errors.New("already blocked")
	}
	d, err := a.device(devID)
	if err != nil {
		return twBlockResult{}, errors.New("device not found")
	}
	pl := twBlockPayload{Device: d.wire(), User: user, Block: block}
	if !block {
		var prev struct {
			Shares []string `json:"shares"`
		}
		json.Unmarshal([]byte(note), &prev)
		pl.Shares = prev.Shares
	}
	var res twBlockResult
	if d.CollectorID > 0 {
		raw, err := a.runTask(d.CollectorID, "tw_block", pl, 3*time.Minute)
		if err == nil {
			err = json.Unmarshal(raw, &res)
		}
		if err != nil {
			return res, err
		}
	} else if d.Kind == "windows" && !isWindows {
		return res, errors.New("this server is not that Windows machine: install a collector on it to block accounts")
	} else if res, err = twBlockExec(pl); err != nil {
		return res, err
	}
	b, _ := json.Marshal(map[string]any{"shares": res.Shares, "at": now(), "by": by, "blocked": block})
	a.st.db.Exec(`UPDATE tw_alerts SET blocked=?, block_note=? WHERE id=?`, b2i(block), string(b), alertID)
	log.Printf("tripwire: %s %q on %s (%s): %v", map[bool]string{true: "blocked", false: "unblocked"}[block], user, d.Name, by, res.Shares)
	return res, nil
}

// ---------- decoys ----------

// Names sort first and last, where ransomware that walks folders in order starts.
var decoyNames = []string{"!000_Payroll_backup_2019.xlsx", "zzz_Accounting_archive_2018.docx"}

type twDecoyPayload struct {
	Device deviceWire `json:"device"`
	Share  Share      `json:"share"`
	Plant  bool       `json:"plant"`
	Rels   []string   `json:"rels"`
	Hashes []string   `json:"hashes"` // remove: what was planted, so changed files are left alone
}

type twDecoyResult struct {
	Rel    string `json:"rel"`
	Hash   string `json:"hash"`
	Result string `json:"result"`
}

func decoyAbs(d Device, s Share, rel string) string {
	if d.Kind == "powerscale" {
		return path.Join(s.Path, rel)
	}
	return filepath.Join(s.Path, filepath.FromSlash(strings.TrimPrefix(rel, "/")))
}

// twDecoyExec writes or removes decoy files. Runs on the server or a collector.
func twDecoyExec(pl twDecoyPayload) []twDecoyResult {
	d := pl.Device.dev()
	var ps *psClient
	if d.Kind == "powerscale" {
		ps = psClientFor(d)
	}
	out := make([]twDecoyResult, len(pl.Rels))
	for i, rel := range pl.Rels {
		out[i].Rel = rel
		abs := decoyAbs(d, pl.Share, rel)
		if pl.Plant {
			body := make([]byte, 48*1024)
			rand.Read(body)
			copy(body, "PK\x03\x04") // looks like an Office file to anything that peeks
			h := sha256.Sum256(body)
			out[i].Hash = hex.EncodeToString(h[:])
			var err error
			if ps != nil {
				if resp, e := ps.do("HEAD", nsPath(abs), nil, nil); e == nil {
					resp.Body.Close()
					if resp.StatusCode == 200 {
						err = errors.New("a file with this name already exists")
					}
				}
				if err == nil {
					err = ps.expect(ps.do("PUT", nsPath(abs), map[string]string{"x-isi-ifs-target-type": "object", "Content-Type": "application/octet-stream"}, bytes.NewReader(body)))
				}
			} else {
				var f *os.File
				if f, err = os.OpenFile(longPath(abs), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644); err == nil {
					_, err = f.Write(body)
					f.Close()
					setHidden(longPath(abs))
				} else if os.IsExist(err) {
					// A decoy from an earlier request whose answer never reached the server:
					// adopt it. Anything else with this name is someone's file; leave it.
					if old, rerr := os.ReadFile(longPath(abs)); rerr == nil && isOurDecoy(old) {
						h := sha256.Sum256(old)
						out[i].Hash = hex.EncodeToString(h[:])
						out[i].Result = "planted"
						continue
					}
					err = errors.New("a file with this name already exists and is not a Stratum decoy; left alone")
				}
			}
			out[i].Result = "planted"
			if err != nil {
				out[i].Result, out[i].Hash = "failed: "+err.Error(), ""
			}
			continue
		}
		var cur []byte
		var err error
		if ps != nil {
			var resp *http.Response
			if resp, err = ps.do("GET", nsPath(abs), nil, nil); err == nil {
				cur, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				resp.Body.Close()
				if resp.StatusCode == 404 {
					err = os.ErrNotExist
				}
			}
		} else {
			cur, err = os.ReadFile(longPath(abs))
		}
		if err != nil {
			out[i].Result = "already gone"
			continue
		}
		h := sha256.Sum256(cur)
		if i < len(pl.Hashes) && pl.Hashes[i] != "" && hex.EncodeToString(h[:]) != pl.Hashes[i] {
			out[i].Result = "left in place: changed since it was planted (keep it as evidence)"
			continue
		}
		if ps != nil {
			err = ps.ranDelete(abs, false)
		} else {
			err = os.Remove(longPath(abs))
		}
		out[i].Result = "removed"
		if err != nil {
			out[i].Result = "failed: " + err.Error()
		}
	}
	return out
}

func (a *App) runDecoys(d Device, pl twDecoyPayload) ([]twDecoyResult, error) {
	if d.CollectorID > 0 {
		raw, err := a.runTask(d.CollectorID, "tw_decoys", pl, 3*time.Minute)
		if err != nil {
			return nil, err
		}
		var res []twDecoyResult
		return res, json.Unmarshal(raw, &res)
	}
	if d.Kind == "windows" && !isWindows {
		return nil, errors.New("this server is not that Windows machine: install a collector on it")
	}
	return twDecoyExec(pl), nil
}

// setShareExcludes adds or removes the decoy names from a share's exclusion rules, so
// decoys never show up in reports.
func (a *App) setDecoyExcludes(s Share, add bool) {
	var o map[string]any
	json.Unmarshal([]byte(s.Options), &o)
	if o == nil {
		o = map[string]any{}
	}
	var list []string
	if raw, ok := o["exclude"].([]any); ok {
		for _, v := range raw {
			if str, ok := v.(string); ok {
				list = append(list, str)
			}
		}
	}
	keep := []string{}
	for _, r := range list {
		isDecoy := false
		for _, n := range decoyNames {
			isDecoy = isDecoy || strings.EqualFold(r, n)
		}
		if !isDecoy {
			keep = append(keep, r)
		}
	}
	if add {
		keep = append(keep, decoyNames...)
	}
	o["exclude"] = keep
	b, _ := json.Marshal(o)
	a.st.db.Exec(`UPDATE shares SET options=? WHERE id=?`, string(b), s.ID)
}

func (a *App) plantDecoys(shareID int64) ([]twDecoyResult, error) {
	s, err := a.share(shareID)
	if err != nil {
		return nil, errors.New("share not found")
	}
	d, err := a.device(s.DeviceID)
	if err != nil {
		return nil, err
	}
	switch {
	case d.Kind == "powerscale":
	case d.Kind == "windows" && strings.HasPrefix(s.Path, `\\`):
		return nil, errors.New("plant decoys through the file server's own path (a collector on that server), not a UNC path: its audit log reports local paths")
	case d.Kind == "windows" && isWindows, d.Kind == "windows" && d.CollectorID > 0:
		if strings.HasPrefix(s.Path, "/") {
			return nil, errors.New("decoys need an audit source; Linux servers have none in Stratum yet")
		}
	default:
		return nil, errors.New("decoys need an audit source: a Windows file server or a PowerScale cluster")
	}
	var have int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM tw_decoys WHERE share_id=?`, s.ID).Scan(&have)
	if have > 0 {
		return nil, errors.New("this share already has decoys; remove them first")
	}
	// The share root plus its ten biggest top-level folders.
	folders := []string{"/"}
	rows, err := a.st.db.Query(`SELECT path FROM dirs WHERE scan_id=? AND depth=1 ORDER BY bytes DESC LIMIT 10`, s.CurrentScan)
	if err == nil {
		for rows.Next() {
			var p string
			rows.Scan(&p)
			folders = append(folders, p)
		}
		rows.Close()
	}
	var rels []string
	for _, f := range folders {
		for _, n := range decoyNames {
			rels = append(rels, path.Join(f, n))
		}
	}
	pl := twDecoyPayload{Device: d.wire(), Share: s, Plant: true, Rels: rels}
	a.twQuiet(d, s, rels, 3*time.Minute) // our own writes are not an attack
	res, err := a.runDecoys(d, pl)
	if err != nil {
		return nil, err
	}
	for _, r := range res {
		if r.Result == "planted" {
			a.st.db.Exec(`INSERT INTO tw_decoys(device_id,share_id,rel,path,hash,created) VALUES(?,?,?,?,?,?)`, d.ID, s.ID, r.Rel, decoyAbs(d, s, r.Rel), r.Hash, now())
		}
	}
	a.setDecoyExcludes(s, true)
	if a.tw != nil {
		a.tw.loadDecoys()
	}
	return res, nil
}

func (a *App) removeDecoys(shareID int64) ([]twDecoyResult, error) {
	s, err := a.share(shareID)
	if err != nil {
		return nil, errors.New("share not found")
	}
	d, err := a.device(s.DeviceID)
	if err != nil {
		return nil, err
	}
	rows, err := a.st.db.Query(`SELECT rel, hash FROM tw_decoys WHERE share_id=?`, s.ID)
	if err != nil {
		return nil, err
	}
	pl := twDecoyPayload{Device: d.wire(), Share: s}
	for rows.Next() {
		var r, h string
		rows.Scan(&r, &h)
		pl.Rels = append(pl.Rels, r)
		pl.Hashes = append(pl.Hashes, h)
	}
	rows.Close()
	if len(pl.Rels) == 0 {
		return []twDecoyResult{}, nil
	}
	a.twQuiet(d, s, pl.Rels, 10*time.Minute)
	res, err := a.runDecoys(d, pl)
	if err != nil {
		return nil, err
	}
	a.st.db.Exec(`DELETE FROM tw_decoys WHERE share_id=?`, s.ID)
	a.setDecoyExcludes(s, false)
	if a.tw != nil {
		a.tw.loadDecoys()
	}
	return res, nil
}

func (a *App) twQuiet(d Device, s Share, rels []string, dur time.Duration) {
	if a.tw == nil {
		return
	}
	a.tw.mu.Lock()
	defer a.tw.mu.Unlock()
	for _, r := range rels {
		a.tw.quiet[twNorm(decoyAbs(d, s, r))] = time.Now().Add(dur).Unix()
	}
}

// ---------- API ----------

func (a *App) twStatus(w http.ResponseWriter, r *http.Request) {
	cfg := a.twLoad()
	m := cfg.toMap()
	for _, k := range twSecrets {
		s, _ := m[k].(string)
		m[k+"_set"] = s != ""
		m[k] = ""
	}
	alerts := []twAlert{}
	rows, err := a.st.db.Query(`SELECT t.id,t.ts,t.last_ts,t.device_id,COALESCE(d.name,''),t.share_id,COALESCE(s.name,''),t.username,t.client,t.rule,t.severity,t.detail,t.sample,t.count,t.status,t.blocked,COALESCE(t.block_note,''),COALESCE(t.notified,'')
	  FROM tw_alerts t LEFT JOIN devices d ON d.id=t.device_id LEFT JOIN shares s ON s.id=t.share_id ORDER BY t.id DESC LIMIT 200`)
	if err == nil {
		for rows.Next() {
			var al twAlert
			var sample string
			var blocked int
			rows.Scan(&al.ID, &al.TS, &al.LastTS, &al.DeviceID, &al.Device, &al.ShareID, &al.Share, &al.User, &al.Client, &al.Rule, &al.Severity, &al.Detail, &sample, &al.Count, &al.Status, &blocked, &al.Block, &al.Notified)
			json.Unmarshal([]byte(sample), &al.Sample)
			al.Blocked = blocked == 1
			alerts = append(alerts, al)
		}
		rows.Close()
	}
	type shareState struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		Path     string `json:"path"`
		Device   string `json:"device"`
		Kind     string `json:"kind"`
		Audited  bool   `json:"audited"`
		Decoys   int    `json:"decoys"`
		Eligible string `json:"eligible"` // "" or why decoys cannot be planted
	}
	shares := []shareState{}
	srows, err := a.st.db.Query(`SELECT s.id, s.name, s.path, d.name, d.kind, COALESCE(s.options,''), d.collector_id, (SELECT COUNT(*) FROM tw_decoys x WHERE x.share_id=s.id)
	  FROM shares s JOIN devices d ON d.id=s.device_id ORDER BY d.name, s.name`)
	if err == nil {
		for srows.Next() {
			var st shareState
			var opts string
			var cid int64
			srows.Scan(&st.ID, &st.Name, &st.Path, &st.Device, &st.Kind, &opts, &cid, &st.Decoys)
			st.Audited = opt(opts, "audited") || st.Kind == "powerscale"
			switch {
			case st.Kind == "s3":
				st.Eligible = "object storage has no file audit"
			case st.Kind == "windows" && strings.HasPrefix(st.Path, "/"):
				st.Eligible = "Linux servers have no audit source yet"
			case st.Kind == "windows" && strings.HasPrefix(st.Path, `\\`):
				st.Eligible = "UNC path: use a collector on that file server"
			case st.Kind == "windows" && cid == 0 && !isWindows:
				st.Eligible = "needs a collector on that machine"
			}
			shares = append(shares, st)
		}
		srows.Close()
	}
	var open, blocked, last24 int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM tw_alerts WHERE status='open' AND rule<>'test'`).Scan(&open)
	a.st.db.QueryRow(`SELECT COUNT(*) FROM tw_alerts WHERE blocked=1`).Scan(&blocked)
	a.st.db.QueryRow(`SELECT COUNT(*) FROM tw_alerts WHERE ts>=? AND rule<>'test'`, now()-86400).Scan(&last24)
	var events int64
	a.st.db.QueryRow(`SELECT COALESCE(SUM(count),0) FROM audit WHERE ts>=?`, now()-86400).Scan(&events)
	writeJSON(w, map[string]any{"config": m, "alerts": alerts, "shares": shares, "open": open, "blocked": blocked, "last24": last24, "events24": events})
}

func (a *App) twPutConfig(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	cur := a.twLoad().toMap()
	for k, v := range in {
		if strings.HasSuffix(k, "_set") {
			continue
		}
		isSecret := false
		for _, s := range twSecrets {
			isSecret = isSecret || s == k
		}
		if s, _ := v.(string); isSecret && s == "" {
			if in[k+"_clear"] != true {
				continue // empty secret field means "keep what is stored"
			}
		}
		cur[k] = v
	}
	c := twFromMap(cur)
	if c.BurstPerMin < 0 || c.ExtPerMin < 0 {
		httpErr(w, 400, "thresholds cannot be negative")
		return
	}
	for _, u := range []string{c.TeamsURL, c.SlackURL, c.WebhookURL} {
		if u != "" && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
			httpErr(w, 400, "webhook addresses start with https://")
			return
		}
	}
	a.twSave(c)
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) twTest(w http.ResponseWriter, r *http.Request) {
	cfg := a.twLoad()
	al := twAlert{Rule: "test", Severity: "warning", Device: "Stratum", User: userFrom(r).Username,
		Detail: "This is a test of the tripwire notifications. Nothing happened on your storage.", Sample: []string{}}
	writeJSON(w, map[string]any{"results": twNotify(cfg, al)})
}

func (a *App) twAlertAction(w http.ResponseWriter, r *http.Request) {
	id := idOf(r)
	who := userFrom(r).Username
	switch r.PathValue("action") {
	case "ack":
		a.st.db.Exec(`UPDATE tw_alerts SET status='acknowledged' WHERE id=?`, id)
	case "resolve":
		a.st.db.Exec(`UPDATE tw_alerts SET status='resolved' WHERE id=?`, id)
	case "block", "unblock":
		res, err := a.twBlock(id, r.PathValue("action") == "block", who)
		if err != nil {
			httpErr(w, 400, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true, "shares": res.Shares})
		return
	default:
		httpErr(w, 404, "unknown action")
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) twDecoysPlant(w http.ResponseWriter, r *http.Request) {
	res, err := a.plantDecoys(idOf(r))
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]any{"results": res})
}

func (a *App) twDecoysRemove(w http.ResponseWriter, r *http.Request) {
	res, err := a.removeDecoys(idOf(r))
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]any{"results": res})
}

// isOurDecoy recognises a file Stratum planted: exactly the decoy size with the header it writes.
func isOurDecoy(b []byte) bool {
	return len(b) == 48*1024 && string(b[:4]) == "PK\x03\x04"
}
