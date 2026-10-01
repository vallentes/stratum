package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (a *App) smartRoutes(m *http.ServeMux) {
	g := func(p string, fn h) { m.HandleFunc(p, a.guardFor(p, fn)) }
	g("GET /api/insights", a.insights)
	g("GET /api/risk", a.risk)
	g("POST /api/ask", a.ask)
	g("GET /api/changes", a.changes)
}

func (a *App) costs() (primary, archive float64) {
	primary, _ = strconv.ParseFloat(a.st.setting("cost_primary_tb"), 64)
	archive, _ = strconv.ParseFloat(a.st.setting("cost_archive_tb"), 64)
	if primary <= 0 {
		primary = 25
	}
	if archive <= 0 {
		archive = 4
	}
	return
}

func (a *App) saveCosts(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Primary float64 `json:"primary"`
		Archive float64 `json:"archive"`
	}
	readJSON(r, &in)
	if in.Primary <= 0 || in.Archive < 0 {
		httpErr(w, 400, "costs must be positive")
		return
	}
	a.st.setSetting("cost_primary_tb", strconv.FormatFloat(in.Primary, 'f', -1, 64))
	a.st.setSetting("cost_archive_tb", strconv.FormatFloat(in.Archive, 'f', -1, 64))
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) enableAudit(w http.ResponseWriter, r *http.Request) {
	d, err := a.device(idOf(r))
	if err != nil || d.Kind != "windows" {
		httpErr(w, 400, "file auditing can be changed on Windows devices only")
		return
	}
	var in struct {
		Enable   *bool   `json:"enable"`
		ShareIDs []int64 `json:"share_ids"`
	}
	readJSON(r, &in)
	enable := in.Enable == nil || *in.Enable
	pick := map[int64]bool{}
	for _, id := range in.ShareIDs {
		pick[id] = true
	}
	var paths []string
	var chosen []Share
	for _, s := range a.sharesOf(d.ID) {
		if len(pick) == 0 || pick[s.ID] {
			paths = append(paths, s.Path)
			chosen = append(chosen, s)
		}
	}
	if len(paths) == 0 {
		httpErr(w, 400, "pick at least one share")
		return
	}
	kind := "enable_audit"
	if !enable {
		kind = "disable_audit"
	}
	var out map[string]string
	if d.CollectorID > 0 {
		var raw json.RawMessage
		// Applying an inherited audit rule touches every file below the folder: allow time.
		if raw, err = a.runTask(d.CollectorID, kind, map[string]any{"paths": paths}, 15*time.Minute); err == nil {
			err = json.Unmarshal(raw, &out)
		}
	} else if enable {
		out, err = enableFileAuditing(paths)
	} else {
		out, err = disableFileAuditing(paths)
	}
	if err != nil && d.CollectorID > 0 && strings.Contains(err.Error(), "did not answer in time") {
		// Big drives take a while: Windows rewrites the security settings of every file.
		// The collector keeps going and the result is recorded when it reports back.
		writeJSON(w, map[string]string{"status": "still applying on the collector; the Now column updates when it finishes (large drives can take 10 to 30 minutes)"})
		return
	}
	if err != nil {
		httpErr(w, 502, err.Error())
		return
	}
	_ = chosen
	a.markAudited(d.ID, out)
	a.st.db.Exec(`INSERT INTO audit_changes(ts,device_id,action,result) VALUES(?,?,?,?)`, now(), d.ID, kind, mustJSON(out))
	writeJSON(w, out)
}

const tb = 1 << 40

// ---------- insights ----------

type Insight struct {
	ID       string  `json:"id"`
	Severity string  `json:"severity"` // info | warn | crit | good
	Title    string  `json:"title"`
	Detail   string  `json:"detail"`
	Bytes    int64   `json:"bytes,omitempty"`
	Count    int64   `json:"count,omitempty"`
	Savings  float64 `json:"savings_month,omitempty"`
	Action   string  `json:"action,omitempty"`
	Href     string  `json:"href,omitempty"`
	Score    float64 `json:"-"`
}

var junkExts = []string{"tmp", "temp", "bak", "old", "dmp", "chk", "gid", "~tmp", "crdownload", "part"}
var mediaExts = []string{"mp4", "mov", "avi", "mkv", "wmv", "m4v", "mpg", "mpeg", "iso", "vob"}
var mailExts = []string{"pst", "ost"}

func inList(col string, list []string) (string, []any) {
	ph := strings.TrimSuffix(strings.Repeat("?,", len(list)), ",")
	args := make([]any, len(list))
	for i, v := range list {
		args[i] = v
	}
	return col + " IN (" + ph + ")", args
}

func (a *App) insights(w http.ResponseWriter, r *http.Request) {
	sc := scopeFrom(r)
	cond, sargs := sc.scans("scan_id")
	primary, archive := a.costs()
	perTBSaving := primary - archive
	var out []Insight
	_, _ = cond, sargs
	ext := map[string]aggBucket{}
	var total int64
	for _, e := range a.aggFor(sc, "e") {
		ext[e.Key] = e
		total += e.Bytes
	}
	sumExts := func(list []string) (n, b int64) {
		for _, x := range list {
			n, b = n+ext[x].Files, b+ext[x].Bytes
		}
		return
	}
	tot := float64(max(total, 1))
	qs := func() string {
		v := []string{}
		if sc.DeviceID > 0 {
			v = append(v, fmt.Sprintf("device=%d", sc.DeviceID))
		}
		if sc.ShareID > 0 {
			v = append(v, fmt.Sprintf("share=%d", sc.ShareID))
		}
		if len(v) == 0 {
			return ""
		}
		return "&" + strings.Join(v, "&")
	}()

	// Cold data that could move to a cheaper tier.
	cut := now() - 365*86400
	var n, b int64
	for _, m := range a.aggFor(sc, "m") {
		if dayUnix(m.Key)+86400 <= cut {
			n, b = n+m.Files, b+m.Bytes
		}
	}
	if b > 0 {
		sev := "info"
		if float64(b)/tot > 0.5 {
			sev = "warn"
		}
		save := float64(b) / tb * perTBSaving
		out = append(out, Insight{ID: "cold", Severity: sev, Title: fmt.Sprintf("%s of cold data could move to a cheaper tier", fmtB(b)),
			Detail: fmt.Sprintf("%s files (%.0f%% of capacity) have not been modified in over a year. At $%.0f/TB primary vs $%.0f/TB archive that is about $%s a month.",
				fmtN(n), float64(b)/tot*100, primary, archive, fmtN(int64(save))),
			Bytes: b, Count: n, Savings: save, Action: "Review cold files", Href: "#/search/older_days=365" + qs, Score: save + 1})
	}

	// Duplicates.
	var sets, reclaim sql.NullInt64
	dcond, dargs := sc.scans("scan_id")
	a.st.db.QueryRow(`SELECT COUNT(*), SUM(size*(copies-1)) FROM dup_sets WHERE `+dcond, dargs...).Scan(&sets, &reclaim)
	if reclaim.Int64 > 0 {
		save := float64(reclaim.Int64) / tb * primary
		out = append(out, Insight{ID: "dupes", Severity: "info", Title: fmt.Sprintf("%s reclaimable from duplicate files", fmtB(reclaim.Int64)),
			Detail: fmt.Sprintf("%s sets of candidate duplicates (same name, size and modified time). Removing the extra copies frees about $%s a month of primary storage.", fmtN(sets.Int64), fmtN(int64(save))),
			Bytes:  reclaim.Int64, Count: sets.Int64, Savings: save, Action: "Open duplicates", Href: "#/duplicates", Score: save})
	}

	// Junk and temporary files.
	n, b = sumExts(junkExts)
	if n > 0 {
		out = append(out, Insight{ID: "junk", Severity: "info", Title: fmt.Sprintf("%s of temporary and junk files", fmtB(b)),
			Detail: fmt.Sprintf("%s files such as .tmp, .bak, .old and .dmp. Safe candidates for an Auto Tag rule plus a delete automation after review.", fmtN(n)),
			Bytes:  b, Count: n, Savings: float64(b) / tb * primary, Action: "Find them", Href: "#/search/ext=" + strings.Join(junkExts[:6], ",") + qs, Score: float64(b) / tb * primary})
	}

	// Mail archives.
	n, b = sumExts(mailExts)
	if n > 0 {
		out = append(out, Insight{ID: "pst", Severity: "warn", Title: fmt.Sprintf("%s Outlook data files (%s)", fmtN(n), fmtB(b)),
			Detail: "PST/OST files on shares are a compliance blind spot (mail outside retention and eDiscovery) and corrupt easily over SMB. Candidates for migration into the mail platform.",
			Bytes:  b, Count: n, Action: "List PST files", Href: "#/search/ext=pst,ost" + qs, Score: float64(b) / tb * 10})
	}

	// Large media.
	n, b = sumExts(mediaExts)
	if b > 0 && float64(b)/tot > 0.1 {
		out = append(out, Insight{ID: "media", Severity: "info", Title: fmt.Sprintf("Video and disk images take %.0f%% of capacity", float64(b)/tot*100),
			Detail: fmt.Sprintf("%s media files, %s. Usually a small number of owners; worth a conversation or an archive tier.", fmtN(n), fmtB(b)),
			Bytes:  b, Count: n, Action: "Show media", Href: "#/search/ext=" + strings.Join(mediaExts, ",") + "&sort=size" + qs, Score: float64(b) / tb})
	}

	// Very large single files.
	n, b = 0, 0
	for _, szc := range a.aggFor(sc, "s") {
		if szc.Key == "5:10GB+" {
			n, b = szc.Files, szc.Bytes
		}
	}
	if n > 0 {
		out = append(out, Insight{ID: "huge", Severity: "info", Title: fmt.Sprintf("%s files over 10 GB hold %s", fmtN(n), fmtB(b)),
			Detail: "A handful of giant files often explain a share's growth: VM disks, database dumps, backups copied onto a file share.",
			Bytes:  b, Count: n, Action: "Show them", Href: "#/search/min_size=10737418240&sort=size" + qs, Score: float64(b) / tb})
	}

	// Orphaned owners (SIDs that no longer resolve).
	var ob, of sql.NullInt64
	var owners sql.NullInt64
	ocond, oargs := sc.scans("scan_id")
	a.st.db.QueryRow(`SELECT COUNT(DISTINCT owner), SUM(own_bytes), SUM(own_files) FROM dirs WHERE owner LIKE 'S-1-5-21-%' AND `+ocond, oargs...).Scan(&owners, &ob, &of)
	if owners.Int64 > 0 {
		out = append(out, Insight{ID: "orphans", Severity: "warn", Title: fmt.Sprintf("%s owned by %d deleted accounts", fmtB(ob.Int64), owners.Int64),
			Detail: fmt.Sprintf("Folders whose owner SID no longer resolves in the directory (%s files). Typical after staff leave: nobody is accountable for this data.", fmtN(of.Int64)),
			Bytes:  ob.Int64, Count: owners.Int64, Action: "See owners", Href: "#/owners", Score: float64(ob.Int64) / tb * 20})
	}

	// Empty folders.
	var empty sql.NullInt64
	a.st.db.QueryRow(`SELECT COUNT(*) FROM dirs WHERE files=0 AND depth>0 AND `+ocond, oargs...).Scan(&empty)
	if empty.Int64 > 50 {
		out = append(out, Insight{ID: "empty", Severity: "info", Title: fmt.Sprintf("%s empty folder trees", fmtN(empty.Int64)),
			Detail: "Folders with no files anywhere beneath them. Harmless for capacity, but they clutter navigation and slow migrations.", Count: empty.Int64, Score: 0.1})
	}

	// Shares that are almost entirely cold.
	w2, a2 := sc.where()
	rows, _ := a.st.db.Query(`SELECT s.id, s.name, SUM(g.bytes), SUM(CASE WHEN g.key < ? THEN g.bytes ELSE 0 END) FROM scan_agg g JOIN (SELECT * FROM shares`+w2+`) s ON s.current_scan=g.scan_id WHERE g.dim='m' GROUP BY s.id`,
		append([]any{time.Now().AddDate(-2, 0, 0).Format("2006-01-02")}, a2...)...)
	for rows != nil && rows.Next() {
		var id int64
		var name string
		var sb, cb int64
		rows.Scan(&id, &name, &sb, &cb)
		if sb > 1<<30 && float64(cb)/float64(sb) > 0.9 {
			out = append(out, Insight{ID: fmt.Sprintf("stale-%d", id), Severity: "warn", Title: fmt.Sprintf("Share %s is %.0f%% untouched for 2+ years", name, float64(cb)/float64(sb)*100),
				Detail: fmt.Sprintf("%s of %s has not changed in two years. A whole-share archive or read-only candidate.", fmtB(cb), fmtB(sb)),
				Bytes:  cb, Savings: float64(cb) / tb * perTBSaving, Action: "Scope to share", Href: fmt.Sprintf("#/search/share=%d&older_days=730", id), Score: float64(cb) / tb * perTBSaving})
		}
	}
	if rows != nil {
		rows.Close()
	}

	// Ownership concentration.
	var topOwner string
	var topBytes sql.NullInt64
	a.st.db.QueryRow(`SELECT owner, SUM(own_bytes) b FROM dirs WHERE `+ocond+` GROUP BY owner ORDER BY b DESC LIMIT 1`, oargs...).Scan(&topOwner, &topBytes)
	if topBytes.Int64 > 0 && float64(topBytes.Int64)/tot > 0.4 && tot > float64(10<<30) {
		out = append(out, Insight{ID: "concentration", Severity: "info", Title: fmt.Sprintf("%s owns %.0f%% of the data", topOwner, float64(topBytes.Int64)/tot*100),
			Detail: "Often a service or admin account created during a migration, which hides the real business owners. Consider resetting ownership to the teams that use the data.",
			Bytes:  topBytes.Int64, Action: "Owner files", Href: "#/search/owner=" + topOwner, Score: 0.5})
	}

	// Capacity forecast from inventory + growth trend.
	out = append(out, a.capacityForecast(sc)...)
	// Growth since the previous scan.
	if ch := a.changeSummary(sc); ch != nil && ch.Delta != 0 {
		sev := "info"
		if ch.Delta > 0 && float64(ch.Delta)/tot > 0.05 {
			sev = "warn"
		}
		verb := "grew"
		if ch.Delta < 0 {
			verb = "shrank"
		}
		d := ch.Delta
		if d < 0 {
			d = -d
		}
		title := fmt.Sprintf("Data %s by %s since the previous scan", verb, fmtB(d))
		detail := ""
		if len(ch.Leaders) > 0 {
			detail = fmt.Sprintf("Biggest change: %s in %s (+%s).", ch.Leaders[0].Path, ch.Leaders[0].Share, fmtB(ch.Leaders[0].Delta))
		}
		out = append(out, Insight{ID: "growth", Severity: sev, Title: title, Detail: detail, Bytes: ch.Delta, Action: "See what changed", Href: "#/insights", Score: math.Abs(float64(ch.Delta)) / tb * 5})
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	var saving float64
	for _, i := range out {
		saving += i.Savings
	}
	if out == nil {
		out = []Insight{}
	}
	writeJSON(w, map[string]any{"insights": out, "savings_month": saving, "cost_primary": primary, "cost_archive": archive})
}

func (a *App) capacityForecast(sc Scope) []Insight {
	var out []Insight
	w, args := sc.where()
	devs := a.ids(`SELECT DISTINCT device_id FROM shares`+w, args...)
	for _, id := range devs {
		var name, inv string
		a.st.db.QueryRow(`SELECT name, inventory FROM devices WHERE id=?`, id).Scan(&name, &inv)
		var m map[string]any
		json.Unmarshal([]byte(inv), &m)
		raw, _ := m["raw_bytes"].(float64)
		used, _ := m["used_bytes"].(float64)
		if raw <= 0 || used <= 0 {
			continue
		}
		// Growth per day from this device's index history over the last 90 days.
		rows, _ := a.st.db.Query(`SELECT h.ts, h.bytes, h.share_id FROM history h JOIN shares s ON s.id=h.share_id WHERE s.device_id=? AND h.ts >= ? ORDER BY h.ts`, id, now()-90*86400)
		first, last := map[int64][2]int64{}, map[int64][2]int64{}
		for rows != nil && rows.Next() {
			var ts, b, sid int64
			rows.Scan(&ts, &b, &sid)
			if _, ok := first[sid]; !ok {
				first[sid] = [2]int64{ts, b}
			}
			last[sid] = [2]int64{ts, b}
		}
		if rows != nil {
			rows.Close()
		}
		var perDay float64
		for sid, f := range first {
			l := last[sid]
			if days := float64(l[0]-f[0]) / 86400; days >= 1 {
				perDay += float64(l[1]-f[1]) / days
			}
		}
		pct := used / raw * 100
		if perDay <= 0 {
			if pct > 85 {
				out = append(out, Insight{ID: fmt.Sprintf("cap-%d", id), Severity: "warn", Title: fmt.Sprintf("%s is %.0f%% full", name, pct),
					Detail: "Not growing in the indexed shares right now, but headroom is thin.", Href: "#/inventory", Action: "Inventory", Score: pct / 10})
			}
			continue
		}
		days := (raw*0.95 - used) / perDay
		sev := "info"
		switch {
		case days < 30:
			sev = "crit"
		case days < 120:
			sev = "warn"
		}
		if days < 365 {
			out = append(out, Insight{ID: fmt.Sprintf("cap-%d", id), Severity: sev,
				Title:  fmt.Sprintf("%s reaches 95%% full in about %.0f days", name, math.Max(days, 0)),
				Detail: fmt.Sprintf("%.0f%% used today, growing %s per day across the indexed shares.", pct, fmtB(int64(perDay))),
				Action: "Inventory", Href: "#/inventory", Score: 1000 / math.Max(days, 1)})
		}
	}
	return out
}

// ---------- change tracking ----------

type dirChange struct {
	Share string `json:"share"`
	Path  string `json:"path"`
	Depth int    `json:"depth"`
	Now   int64  `json:"bytes"`
	Prev  int64  `json:"prev_bytes"`
	Delta int64  `json:"delta"`
	Files int64  `json:"file_delta"`
}

type changeOut struct {
	Delta   int64       `json:"delta"`
	From    int64       `json:"from"`
	To      int64       `json:"to"`
	Leaders []dirChange `json:"leaders"`
	Shrink  []dirChange `json:"shrinkers"`
	Shares  int         `json:"shares_compared"`
}

func (a *App) changeSummary(sc Scope) *changeOut {
	w, args := sc.where()
	rows, err := a.st.db.Query(`SELECT id, name, current_scan FROM shares`+w, args...)
	if err != nil {
		return nil
	}
	type sh struct {
		id, cur int64
		name    string
	}
	var list []sh
	for rows.Next() {
		var s sh
		rows.Scan(&s.id, &s.name, &s.cur)
		list = append(list, s)
	}
	rows.Close()
	out := &changeOut{}
	var all []dirChange
	for _, s := range list {
		var prev, prevTs, curTs int64
		a.st.db.QueryRow(`SELECT MAX(scan_id) FROM dir_history WHERE share_id=? AND scan_id < ?`, s.id, s.cur).Scan(&prev)
		if prev == 0 {
			continue
		}
		a.st.db.QueryRow(`SELECT MIN(ts) FROM dir_history WHERE scan_id=?`, prev).Scan(&prevTs)
		a.st.db.QueryRow(`SELECT MIN(ts) FROM dir_history WHERE scan_id=?`, s.cur).Scan(&curTs)
		out.Shares++
		if out.From == 0 || prevTs < out.From {
			out.From = prevTs
		}
		if curTs > out.To {
			out.To = curTs
		}
		q := `SELECT path, depth, SUM(CASE WHEN scan_id=? THEN bytes ELSE 0 END), SUM(CASE WHEN scan_id=? THEN bytes ELSE 0 END),
		  SUM(CASE WHEN scan_id=? THEN files ELSE 0 END) - SUM(CASE WHEN scan_id=? THEN files ELSE 0 END)
		  FROM dir_history WHERE share_id=? AND scan_id IN (?,?) GROUP BY path, depth`
		r2, err := a.st.db.Query(q, s.cur, prev, s.cur, prev, s.id, s.cur, prev)
		if err != nil {
			continue
		}
		for r2.Next() {
			var c dirChange
			r2.Scan(&c.Path, &c.Depth, &c.Now, &c.Prev, &c.Files)
			c.Share, c.Delta = s.name, c.Now-c.Prev
			if c.Depth == 0 {
				out.Delta += c.Delta
				continue
			}
			if c.Delta != 0 {
				all = append(all, c)
			}
		}
		r2.Close()
	}
	if out.Shares == 0 {
		return nil
	}
	// Prefer the deepest folder that explains a change: skip a parent when a child carries most of its delta.
	sort.Slice(all, func(i, j int) bool { return all[i].Delta > all[j].Delta })
	for _, c := range all {
		if c.Delta > 0 && len(out.Leaders) < 10 {
			out.Leaders = append(out.Leaders, c)
		}
	}
	for i := len(all) - 1; i >= 0 && len(out.Shrink) < 10; i-- {
		if all[i].Delta < 0 {
			out.Shrink = append(out.Shrink, all[i])
		}
	}
	return out
}

func (a *App) changes(w http.ResponseWriter, r *http.Request) {
	ch := a.changeSummary(scopeFrom(r))
	if ch == nil {
		writeJSON(w, map[string]any{"available": false})
		return
	}
	writeJSON(w, map[string]any{"available": true, "summary": ch})
}

// ---------- risk ----------

var ransomExts = []string{"locky", "zepto", "odin", "thor", "aesir", "osiris", "cerber", "cerber2", "cerber3", "crypt", "crypted", "cryptolocker",
	"encrypted", "enc", "crinf", "r5a", "xrnt", "xtbl", "crypz", "cryp1", "wncry", "wnry", "wcry", "wncryt", "onion", "ryk", "ryuk", "conti",
	"lockbit", "lockbit3", "hive", "akira", "blackcat", "royal", "play", "phobos", "eking", "devos", "makop", "stop", "djvu", "maas",
	"globeimposter", "dharma", "wallet", "arena", "java", "combo", "adobe", "gdcb", "krab", "sodinokibi", "revil", "clop", "cl0p", "medusa",
	"basta", "blackbasta", "rhysida", "8base", "bianlian", "babuk", "avos", "avoslocker", "mallox", "hydra", "kraken", "lock", "locked",
	"crab", "kkk", "zzzzz", "micro", "ecc", "ezz", "exx", "vvv", "ccc", "abc", "xyz", "aaa", "ttt", "rrk", "fun", "gws", "btc"}

var ransomNotePatterns = []string{"%decrypt%instruction%", "how_to_decrypt%", "how-to-decrypt%", "how_to_recover%", "how_to_restore%",
	"%_readme_%.txt", "_readme.txt", "restore_files%", "restore-my-files%", "!!!_read_me%", "readme_for_decrypt%", "recover-files%",
	"decrypt-files%", "@please_read_me@%", "#decrypt_my_files#%", "%ransom%note%", "help_decrypt%", "help_restore%", "read_me_to_decrypt%",
	"%-decrypt.txt", "%-readme.txt", "files_encrypted%", "your_files_are_encrypted%"}

type sensitiveCat struct {
	Key, Label, Why string
	Exts            []string
	Names           []string
}

var sensitiveCats = []sensitiveCat{
	{"credentials", "Credentials and password stores", "Password lists and vaults readable on a share are a direct path to account takeover.",
		[]string{"kdbx", "kdb", "psafe3", "1pif", "agilekeychain", "keychain"},
		[]string{"%password%", "%passwd%", "%credential%", "%logins%", "%secrets%", ".env", "%.env", "wallet.dat", "%.htpasswd"}},
	{"keys", "Private keys and certificates", "Private keys let anyone impersonate the server, user or code signer they belong to.",
		[]string{"pem", "key", "pfx", "p12", "ppk", "jks", "keystore", "ovpn", "asc", "gpg"},
		[]string{"id_rsa%", "id_ed25519%", "id_ecdsa%", "id_dsa%"}},
	{"finance_hr", "Payroll, HR and financial records by name", "Names that suggest personal or financial data. Check who can read these folders.",
		nil, []string{"%payroll%", "%salary%", "%salaries%", "%ssn%", "%social_security%", "%passport%", "%tax_return%", "%w-2%", "%w2_%", "%bank_statement%", "%credit_card%", "%iban%", "%medical%", "%employee_record%"}},
	{"databases", "Database files and dumps", "Copies of databases on file shares escape the database's own access controls and backups.",
		[]string{"mdf", "ldf", "ndf", "bak", "sql", "dump", "db", "sqlite", "sqlite3", "accdb", "mdb", "dmp"}, nil},
	{"mail", "Mailbox archives", "PST/OST/MBOX files hold whole mailboxes outside retention and eDiscovery.",
		[]string{"pst", "ost", "mbox", "nsf"}, nil},
	{"vm", "Virtual machine disks and backups", "A VM disk on a share contains a full copy of that machine, including its credentials.",
		[]string{"vmdk", "vhd", "vhdx", "qcow2", "ova", "ovf", "vbk", "vib", "vrb", "tib"}, nil},
}

func (a *App) risk(w http.ResponseWriter, r *http.Request) {
	sc := scopeFrom(r)
	cond, sargs := sc.scans("h.scan_id")
	type sample struct {
		Device string `json:"device"`
		Share  string `json:"share"`
		Path   string `json:"path"`
		Owner  string `json:"owner"`
		Size   int64  `json:"size"`
		Mtime  int64  `json:"mtime"`
	}
	// All reads come from risk_hits, precomputed when each scan was published.
	samples := func(cat string, limit int) []sample {
		out := []sample{}
		rows, err := a.st.db.Query(`SELECT d.name, s.name, h.path, h.owner, h.size, h.mtime FROM risk_hits h JOIN shares s ON s.current_scan=h.scan_id
		  JOIN devices d ON d.id=s.device_id WHERE h.cat=? AND `+cond+` ORDER BY h.mtime DESC LIMIT ?`, append(append([]any{cat}, sargs...), limit)...)
		if err != nil {
			return out
		}
		defer rows.Close()
		for rows.Next() {
			var s sample
			rows.Scan(&s.Device, &s.Share, &s.Path, &s.Owner, &s.Size, &s.Mtime)
			out = append(out, s)
		}
		return out
	}
	count := func(cat string) (n, b, first, last, folders int64) {
		var nn, bb, ff, ll, dd sql.NullInt64
		a.st.db.QueryRow(`SELECT COUNT(*), SUM(h.size), MIN(h.mtime), MAX(h.mtime), COUNT(DISTINCT h.scan_id || h.dir) FROM risk_hits h WHERE h.cat=? AND `+cond,
			append([]any{cat}, sargs...)...).Scan(&nn, &bb, &ff, &ll, &dd)
		return nn.Int64, bb.Int64, ff.Int64, ll.Int64, dd.Int64
	}

	encN, encB, encFirst, encLast, encDirs := count("ransom_ext")
	noteN, _, _, _, noteDirs := count("ransom_note")
	type folderHit struct {
		Device string `json:"device"`
		Share  string `json:"share"`
		Dir    string `json:"dir"`
		Files  int64  `json:"files"`
		Last   int64  `json:"last"`
	}
	hotFolders := []folderHit{}
	if encN > 0 {
		rows, _ := a.st.db.Query(`SELECT d.name, s.name, h.dir, COUNT(*) c, MAX(h.mtime) FROM risk_hits h JOIN shares s ON s.current_scan=h.scan_id
		  JOIN devices d ON d.id=s.device_id WHERE h.cat='ransom_ext' AND `+cond+` GROUP BY s.id, h.dir ORDER BY c DESC LIMIT 15`, sargs...)
		for rows != nil && rows.Next() {
			var fh folderHit
			rows.Scan(&fh.Device, &fh.Share, &fh.Dir, &fh.Files, &fh.Last)
			hotFolders = append(hotFolders, fh)
		}
		if rows != nil {
			rows.Close()
		}
	}

	type catOut struct {
		Key     string   `json:"key"`
		Label   string   `json:"label"`
		Why     string   `json:"why"`
		Files   int64    `json:"files"`
		Bytes   int64    `json:"bytes"`
		Folders int64    `json:"folders"`
		Samples []sample `json:"samples"`
		Search  string   `json:"search"`
	}
	var cats []catOut
	for _, c := range sensitiveCats {
		n, b, _, _, folders := count(c.Key)
		co := catOut{Key: c.Key, Label: c.Label, Why: c.Why, Files: n, Bytes: b, Folders: folders, Samples: []sample{}}
		if len(c.Exts) > 0 {
			co.Search = "ext=" + strings.Join(c.Exts, ",")
		}
		if n > 0 {
			co.Samples = samples(c.Key, 8)
		}
		cats = append(cats, co)
	}
	noteSamples := samples("ransom_note", 10)

	// Audit anomalies: 10-minute windows where one account changed far more than its norm.
	type burst struct {
		User    string           `json:"user"`
		Device  string           `json:"device"`
		Window  int64            `json:"window"`
		Changes int64            `json:"changes"`
		Norm    float64          `json:"norm"`
		Ops     map[string]int64 `json:"ops"`
		Ransom  int64            `json:"ransom_ext_hits"`
	}
	since := now() - 7*86400
	type key struct {
		user string
		dev  int64
		win  int64
	}
	agg := map[key]map[string]int64{}
	rex := map[string]bool{}
	for _, e := range ransomExts {
		rex[e] = true
	}
	ransomHits := map[key]int64{}
	rows, _ := a.st.db.Query(`SELECT username, device_id, (ts/600)*600, op, SUM(count), path FROM audit WHERE ts >= ? AND op IN ('create','modify','delete','rename') GROUP BY username, device_id, ts/600, op, path`, since)
	for rows != nil && rows.Next() {
		var u, op, p string
		var dev, win, c int64
		rows.Scan(&u, &dev, &win, &op, &c, &p)
		k := key{u, dev, win}
		if agg[k] == nil {
			agg[k] = map[string]int64{}
		}
		agg[k][op] += c
		if i := strings.LastIndexByte(p, '.'); i >= 0 && rex[strings.ToLower(p[i+1:])] {
			ransomHits[k] += c
		}
	}
	if rows != nil {
		rows.Close()
	}
	perUser := map[string][]int64{}
	for k, ops := range agg {
		var t int64
		for _, v := range ops {
			t += v
		}
		perUser[k.user] = append(perUser[k.user], t)
	}
	median := func(v []int64) float64 {
		s := append([]int64{}, v...)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		if len(s) == 0 {
			return 0
		}
		return float64(s[len(s)/2])
	}
	devNames := map[int64]string{}
	drows, _ := a.st.db.Query(`SELECT id,name FROM devices`)
	for drows != nil && drows.Next() {
		var id int64
		var n string
		drows.Scan(&id, &n)
		devNames[id] = n
	}
	if drows != nil {
		drows.Close()
	}
	var bursts []burst
	for k, ops := range agg {
		var t int64
		for _, v := range ops {
			t += v
		}
		norm := median(perUser[k.user])
		if (t >= 300 && float64(t) >= 10*math.Max(norm, 1)) || ransomHits[k] >= 20 {
			bursts = append(bursts, burst{User: k.user, Device: devNames[k.dev], Window: k.win, Changes: t, Norm: norm, Ops: ops, Ransom: ransomHits[k]})
		}
	}
	sort.Slice(bursts, func(i, j int) bool { return bursts[i].Changes > bursts[j].Changes })
	if len(bursts) > 25 {
		bursts = bursts[:25]
	}

	// A simple 0-100 score so the page can lead with one number.
	score := 0.0
	if encN > 0 {
		score += 40 + math.Min(20, math.Log10(float64(encN))*5)
	}
	if noteN > 0 {
		score += 20
	}
	if len(bursts) > 0 {
		score += 15
	}
	for _, c := range cats {
		if c.Files > 0 && (c.Key == "credentials" || c.Key == "keys") {
			score += 8
		} else if c.Files > 0 {
			score += 2
		}
	}
	score = math.Min(100, score)
	if bursts == nil {
		bursts = []burst{}
	}
	writeJSON(w, map[string]any{
		"score": math.Round(score),
		"ransomware": map[string]any{"encrypted_files": encN, "encrypted_bytes": encB, "first": encFirst, "last": encLast, "folders": encDirs,
			"notes": noteN, "note_folders": noteDirs, "top_folders": hotFolders, "note_samples": noteSamples,
			"search": "ext=" + strings.Join(ransomExts[:12], ",")},
		"sensitive": cats,
		"bursts":    bursts,
	})
}

// ---------- ask (plain-English search) ----------

var typeWords = map[string][]string{
	"video":        mediaExts[:9],
	"movie":        mediaExts[:9],
	"image":        {"jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "heic", "raw", "cr2", "nef", "webp", "svg"},
	"photo":        {"jpg", "jpeg", "png", "heic", "raw", "cr2", "nef", "tif", "tiff"},
	"picture":      {"jpg", "jpeg", "png", "gif", "bmp", "heic"},
	"document":     {"doc", "docx", "pdf", "txt", "rtf", "odt", "pages"},
	"word":         {"doc", "docx", "rtf"},
	"spreadsheet":  {"xls", "xlsx", "xlsm", "csv", "ods", "numbers"},
	"excel":        {"xls", "xlsx", "xlsm"},
	"presentation": {"ppt", "pptx", "odp", "key"},
	"powerpoint":   {"ppt", "pptx"},
	"slide":        {"ppt", "pptx"},
	"archive":      {"zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "xz", "cab"},
	"zip":          {"zip", "7z", "rar"},
	"audio":        {"mp3", "wav", "flac", "aac", "m4a", "ogg", "wma"},
	"music":        {"mp3", "wav", "flac", "aac", "m4a", "ogg", "wma"},
	"email":        {"pst", "ost", "msg", "eml", "mbox"},
	"mail":         {"pst", "ost", "msg", "eml", "mbox"},
	"pst":          {"pst", "ost"},
	"disk image":   {"iso", "vhd", "vhdx", "vmdk", "qcow2", "img"},
	"iso":          {"iso", "img"},
	"vm":           {"vmdk", "vhd", "vhdx", "qcow2", "ova"},
	"virtual":      {"vmdk", "vhd", "vhdx", "qcow2", "ova"},
	"database":     {"mdf", "ldf", "bak", "sql", "db", "sqlite", "accdb", "mdb"},
	"backup":       {"bak", "vbk", "vib", "tib", "old", "backup"},
	"log":          {"log", "evtx", "etl"},
	"temp":         junkExts,
	"temporary":    junkExts,
	"junk":         junkExts,
	"code":         {"py", "js", "ts", "go", "java", "cs", "cpp", "c", "h", "rb", "php", "ps1", "sh"},
	"script":       {"ps1", "bat", "cmd", "sh", "vbs", "py"},
	"cad":          {"dwg", "dxf", "step", "stp", "iges", "sldprt", "sldasm", "ipt", "iam", "rvt"},
	"pdf":          {"pdf"},
	"installer":    {"exe", "msi", "msp", "pkg", "dmg"},
	"executable":   {"exe", "dll", "msi", "bat", "cmd", "ps1"},
	"key":          sensitiveCats[1].Exts,
	"certificate":  {"pem", "pfx", "p12", "cer", "crt"},
}

var (
	reSize    = regexp.MustCompile(`(?i)(over|above|bigger than|larger than|more than|greater than|>|at least|under|below|smaller than|less than|<)\s*(\d+(?:\.\d+)?)\s*(kb|mb|gb|tb|k|m|g|t)\b`)
	reAgeOld  = regexp.MustCompile(`(?i)(?:not (?:been )?(?:modified|changed|touched|edited|updated|written)|untouched|unchanged|older than|stale for|cold for)\s*(?:in|for|since)?\s*(?:the\s+)?(?:last|past)?\s*(\d+|a|an|one|two|three|four|five|six|ten)?\s*(day|week|month|year)s?`)
	reAgeAcc  = regexp.MustCompile(`(?i)not (?:been )?(?:accessed|opened|read|used)\s*(?:in|for|since)?\s*(?:the\s+)?(?:last|past)?\s*(\d+|a|an|one|two|three|four|five|six|ten)?\s*(day|week|month|year)s?`)
	reAgeNew  = regexp.MustCompile(`(?i)(?:modified|changed|created|added|edited|written|updated)\s*(?:in|within)\s*(?:the\s+)?(?:last|past)\s*(\d+|a|an|one|two|three|four|five|six|ten)?\s*(day|week|month|year)s?`)
	reOwner   = regexp.MustCompile(`(?i)(?:owned by|belonging to|owner(?: is)?|from user|by user)\s+([\w.\\@-]+)`)
	reNamed   = regexp.MustCompile(`(?i)(?:named|called|name contains|containing|with name)\s+"?([^"\s]+)"?`)
	reQuoted  = regexp.MustCompile(`"([^"]+)"`)
	reIn      = regexp.MustCompile(`(?i)\b(?:in|under|inside|within)\s+(?:the\s+)?(?:folder|directory|path|share)?\s*([\w\\/.$-]+?)(?:\s+(?:folder|share|directory))?(?:\s|$)`)
	reTagged  = regexp.MustCompile(`(?i)tagged\s+(?:as\s+)?"?([\w.-]+)"?`)
	reExtList = regexp.MustCompile(`(?i)\.([a-z0-9]{1,6})\b`)
)

var numWords = map[string]int{"a": 1, "an": 1, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "ten": 10}

func ageDays(n, unit string) int {
	v := 1
	if n != "" {
		if x, err := strconv.Atoi(n); err == nil {
			v = x
		} else if x, ok := numWords[strings.ToLower(n)]; ok {
			v = x
		}
	}
	switch strings.ToLower(unit) {
	case "week":
		return v * 7
	case "month":
		return v * 30
	case "year":
		return v * 365
	}
	return v
}

type askReply struct {
	Filter     Filter   `json:"filter"`
	Understood []string `json:"understood"`
	Route      string   `json:"route,omitempty"`
	Sort       string   `json:"sort,omitempty"`
}

// parseAsk turns a plain-English question into a search filter. Deterministic and
// local: no data leaves the server. Unrecognised words are ignored rather than guessed.
func (a *App) parseAsk(q string) askReply {
	var rep askReply
	lq := strings.ToLower(q)
	f := &rep.Filter
	say := func(s string, args ...any) { rep.Understood = append(rep.Understood, fmt.Sprintf(s, args...)) }

	switch {
	case strings.Contains(lq, "duplicate"):
		rep.Route = "#/duplicates"
		say("duplicate files")
		return rep
	case strings.Contains(lq, "ransomware") || strings.Contains(lq, "encrypted") || strings.Contains(lq, "sensitive") || strings.Contains(lq, "risk"):
		rep.Route = "#/risk"
		say("risk and ransomware traces")
		return rep
	case strings.Contains(lq, "long path") || strings.Contains(lq, "illegal") || strings.Contains(lq, "scan error"):
		rep.Route = "#/issues"
		say("path and scan issues")
		return rep
	case strings.Contains(lq, "save money") || strings.Contains(lq, "reclaim") || strings.Contains(lq, "recommend") || strings.Contains(lq, "insight"):
		rep.Route = "#/insights"
		say("insights and savings")
		return rep
	}

	for _, m := range reSize.FindAllStringSubmatch(q, -1) {
		v, _ := strconv.ParseFloat(m[2], 64)
		mult := map[string]float64{"k": 1 << 10, "kb": 1 << 10, "m": 1 << 20, "mb": 1 << 20, "g": 1 << 30, "gb": 1 << 30, "t": 1 << 40, "tb": 1 << 40}[strings.ToLower(m[3])]
		b := int64(v * mult)
		switch strings.ToLower(m[1]) {
		case "under", "below", "smaller than", "less than", "<":
			f.MaxSize = b
			say("smaller than %s", fmtB(b))
		default:
			f.MinSize = b
			say("at least %s", fmtB(b))
		}
	}
	if m := reAgeAcc.FindStringSubmatch(q); m != nil {
		f.NotAccessedDay = ageDays(m[1], m[2])
		say("not accessed for %d days", f.NotAccessedDay)
	} else if m := reAgeOld.FindStringSubmatch(q); m != nil {
		f.OlderThanDays = ageDays(m[1], m[2])
		say("not modified for %d days", f.OlderThanDays)
	}
	if m := reAgeNew.FindStringSubmatch(q); m != nil {
		f.NewerThanDays = ageDays(m[1], m[2])
		say("modified in the last %d days", f.NewerThanDays)
	}
	switch {
	case strings.Contains(lq, "today"):
		f.NewerThanDays = 1
		say("modified today")
	case strings.Contains(lq, "this week"):
		f.NewerThanDays = 7
		say("modified this week")
	case strings.Contains(lq, "this month"):
		f.NewerThanDays = 30
		say("modified this month")
	case f.OlderThanDays == 0 && f.NotAccessedDay == 0 && (strings.Contains(lq, "cold") || strings.Contains(lq, "stale") || strings.Contains(lq, "old files")):
		f.OlderThanDays = 365
		say("cold: not modified for a year")
	case f.NewerThanDays == 0 && (strings.Contains(lq, "hot") || strings.Contains(lq, "recent")):
		f.NewerThanDays = 30
		say("recently modified")
	}
	if strings.Contains(lq, "biggest") || strings.Contains(lq, "largest") || strings.Contains(lq, "big files") || strings.Contains(lq, "large files") {
		rep.Sort = "size"
		say("largest first")
	}
	if strings.Contains(lq, "newest") || strings.Contains(lq, "latest") {
		rep.Sort = "mtime"
	}

	extSet := map[string]bool{}
	for word, exts := range typeWords {
		if strings.Contains(lq, word) {
			for _, e := range exts {
				extSet[e] = true
			}
			say("%s files", word)
		}
	}
	for _, m := range reExtList.FindAllStringSubmatch(q, -1) {
		if _, isNum := strconv.Atoi(m[1]); isNum == nil {
			continue
		}
		extSet[strings.ToLower(m[1])] = true
		say(".%s files", strings.ToLower(m[1]))
	}
	for e := range extSet {
		f.Ext = append(f.Ext, e)
	}
	sort.Strings(f.Ext)

	if m := reOwner.FindStringSubmatch(q); m != nil {
		f.Owner = m[1]
		say("owner like %s", m[1])
	}
	if m := reTagged.FindStringSubmatch(q); m != nil {
		f.Tag = m[1]
		say("tagged %s", m[1])
	}
	if m := reQuoted.FindStringSubmatch(q); m != nil {
		f.Q = m[1]
		say("name contains %q", m[1])
	} else if m := reNamed.FindStringSubmatch(q); m != nil {
		f.Q = m[1]
		say("name contains %q", m[1])
	}
	// "in Finance" / "under /Projects/2021": a share name wins, otherwise a path fragment.
	for _, m := range reIn.FindAllStringSubmatch(q, -1) {
		w := strings.Trim(m[1], ".,")
		lw := strings.ToLower(w)
		if w == "" || numWords[lw] > 0 || lw == "the" || lw == "last" || lw == "past" || lw == "a" {
			continue
		}
		if _, err := strconv.Atoi(w); err == nil {
			continue
		}
		var sid int64
		var sname string
		if a.st.db.QueryRow(`SELECT id, name FROM shares WHERE lower(name)=? LIMIT 1`, lw).Scan(&sid, &sname) == nil {
			f.ShareID = sid
			say("share %s", sname)
		} else {
			f.PathContains = strings.ReplaceAll(w, `\`, "/")
			say("path contains %s", f.PathContains)
		}
		break
	}
	if len(rep.Understood) == 0 {
		// Nothing recognised: fall back to a plain name search on the longest word.
		words := strings.Fields(q)
		best := ""
		for _, wd := range words {
			if len(wd) > len(best) {
				best = wd
			}
		}
		f.Q = strings.Trim(best, `"'.,?`)
		say("name contains %q", f.Q)
	}
	return rep
}

func (a *App) ask(w http.ResponseWriter, r *http.Request) {
	var in struct{ Q string }
	readJSON(r, &in)
	if strings.TrimSpace(in.Q) == "" {
		httpErr(w, 400, "ask something, e.g. videos over 1 GB not touched in 2 years")
		return
	}
	writeJSON(w, a.parseAsk(in.Q))
}

// ---------- formatting helpers ----------

func fmtB(n int64) string {
	f := float64(n)
	u := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	i := 0
	for f >= 1024 && i < len(u)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	if f >= 100 {
		return fmt.Sprintf("%.0f %s", f, u[i])
	}
	return fmt.Sprintf("%.1f %s", f, u[i])
}

func fmtN(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// markAudited stores, per share, whether Stratum's audit rule is on (for the Auditing dialog).
func (a *App) markAudited(deviceID int64, out map[string]string) {
	for _, s := range a.sharesOf(deviceID) {
		res, ok := out[s.Path]
		if !ok {
			continue
		}
		var o map[string]any
		json.Unmarshal([]byte(s.Options), &o)
		if o == nil {
			o = map[string]any{}
		}
		switch {
		case strings.HasPrefix(res, "audit rule added"):
			o["audited"] = true
		case strings.HasPrefix(res, "audit rule removed"):
			o["audited"] = false
		default:
			continue
		}
		b, _ := json.Marshal(o)
		a.st.db.Exec(`UPDATE shares SET options=? WHERE id=?`, string(b), s.ID)
	}
}

// recoverAuditResults applies audit results that arrived after the request that
// started them had timed out (recorded in the tasks table by the collector).
func (a *App) recoverAuditResults() {
	rows, err := a.st.db.Query(`SELECT collector_id, result FROM tasks WHERE kind IN ('enable_audit','disable_audit') AND status='done' AND result<>'' ORDER BY id`)
	if err != nil {
		return
	}
	type res struct {
		cid int64
		out map[string]string
	}
	var list []res
	for rows.Next() {
		var r res
		var raw string
		rows.Scan(&r.cid, &raw)
		json.Unmarshal([]byte(raw), &r.out)
		list = append(list, r)
	}
	rows.Close()
	for _, r := range list {
		for _, dev := range a.ids(`SELECT id FROM devices WHERE collector_id=?`, r.cid) {
			a.markAudited(dev, r.out)
		}
	}
}
