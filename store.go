package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, expires INTEGER);
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY, name TEXT UNIQUE, kind TEXT, host TEXT, port INTEGER DEFAULT 0,
  username TEXT DEFAULT '', secret TEXT DEFAULT '', insecure INTEGER DEFAULT 0,
  created INTEGER, inventory TEXT DEFAULT '', inventory_at INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS shares(
  id INTEGER PRIMARY KEY, device_id INTEGER, name TEXT, path TEXT,
  schedule_hours INTEGER DEFAULT 0, current_scan INTEGER DEFAULT 0, failed_scan INTEGER DEFAULT 0,
  last_scan_at INTEGER DEFAULT 0, created INTEGER);
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY, share_id INTEGER, started INTEGER, finished INTEGER DEFAULT 0,
  status TEXT, files INTEGER DEFAULT 0, dirs INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0,
  errors INTEGER DEFAULT 0, message TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS dirs(
  scan_id INTEGER, path TEXT, depth INTEGER, owner TEXT,
  files INTEGER, bytes INTEGER, own_files INTEGER, own_bytes INTEGER);
CREATE INDEX IF NOT EXISTS dirs_scan_depth ON dirs(scan_id, depth, bytes);
CREATE TABLE IF NOT EXISTS issues(
  scan_id INTEGER, share_id INTEGER, path TEXT, kind TEXT, detail TEXT, len INTEGER, detected INTEGER);
CREATE INDEX IF NOT EXISTS issues_scan ON issues(scan_id, kind);
CREATE TABLE IF NOT EXISTS issue_triage(share_id INTEGER, path TEXT, kind TEXT, state TEXT, PRIMARY KEY(share_id, path, kind));
CREATE TABLE IF NOT EXISTS history(share_id INTEGER, ts INTEGER, files INTEGER, bytes INTEGER);
CREATE TABLE IF NOT EXISTS audit(
  ts INTEGER, device_id INTEGER, username TEXT, op TEXT, path TEXT, proto TEXT,
  client TEXT, bytes INTEGER, count INTEGER);
CREATE INDEX IF NOT EXISTS audit_dev_ts ON audit(device_id, ts);
CREATE TABLE IF NOT EXISTS tag_rules(
  id INTEGER PRIMARY KEY, name TEXT, tag TEXT, match TEXT, enabled INTEGER DEFAULT 1, created INTEGER);
CREATE TABLE IF NOT EXISTS file_tags(share_id INTEGER, path TEXT, tag TEXT, rule_id INTEGER, PRIMARY KEY(share_id, path, tag));
CREATE INDEX IF NOT EXISTS file_tags_tag ON file_tags(tag);
CREATE TABLE IF NOT EXISTS automations(
  id INTEGER PRIMARY KEY, name TEXT, description TEXT DEFAULT '', enabled INTEGER DEFAULT 1,
  input_kind TEXT, input TEXT, actions TEXT, schedule TEXT DEFAULT '', last_status TEXT DEFAULT '',
  last_run_at INTEGER DEFAULT 0, created INTEGER);
CREATE TABLE IF NOT EXISTS automation_runs(
  id INTEGER PRIMARY KEY, automation_id INTEGER, dry_run INTEGER, started INTEGER, finished INTEGER DEFAULT 0,
  status TEXT, items INTEGER DEFAULT 0, ok INTEGER DEFAULT 0, failed INTEGER DEFAULT 0, message TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS automation_ledger(
  run_id INTEGER, ts INTEGER, share_id INTEGER, path TEXT, action TEXT, target TEXT, result TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS ledger_run ON automation_ledger(run_id);
CREATE TABLE IF NOT EXISTS collectors(
  id INTEGER PRIMARY KEY, name TEXT, token_hash TEXT UNIQUE, created INTEGER, last_seen INTEGER DEFAULT 0,
  hostname TEXT DEFAULT '', version TEXT DEFAULT '', os TEXT DEFAULT '', info TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS tasks(
  id INTEGER PRIMARY KEY, collector_id INTEGER, kind TEXT, payload TEXT, status TEXT, result TEXT DEFAULT '',
  error TEXT DEFAULT '', created INTEGER, claimed_at INTEGER DEFAULT 0, finished INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS tasks_pending ON tasks(collector_id, status);
CREATE TABLE IF NOT EXISTS dir_history(share_id INTEGER, scan_id INTEGER, ts INTEGER, path TEXT, depth INTEGER, bytes INTEGER, files INTEGER);
CREATE INDEX IF NOT EXISTS dir_history_share ON dir_history(share_id, scan_id, path);
`

type Store struct{ db *sql.DB }

func openStore(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(15000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(0)&_pragma=cache_size(-262144)&_pragma=temp_store(MEMORY)&_pragma=mmap_size(2147483648)&_pragma=wal_autocheckpoint(0)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	if _, err := db.Exec(aggSchema); err != nil {
		return nil, fmt.Errorf("agg schema: %w", err)
	}
	// Additive migrations; "duplicate column" errors mean already applied.
	s := &Store{db: db}
	s.migrateEngine()
	for _, m := range []string{
		`ALTER TABLE devices ADD COLUMN collector_id INTEGER DEFAULT 0`,
		// Random-order secondary indexes made big scans crawl; lookups go through (scan_id, ext) instead.
		`ALTER TABLE shares ADD COLUMN options TEXT DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN options TEXT DEFAULT ''`,
		`ALTER TABLE dup_sets ADD COLUMN etag TEXT DEFAULT ''`,
		`DROP INDEX IF EXISTS files_scan_name`,
		`DROP INDEX IF EXISTS files_scan_path`,
	} {
		db.Exec(m)
	}
	if _, err := db.Exec(extraSchema); err != nil {
		return nil, fmt.Errorf("extra schema: %w", err)
	}
	return s, nil
}

func (s *Store) setting(k string) string {
	var v string
	s.db.QueryRow(`SELECT v FROM settings WHERE k=?`, k).Scan(&v)
	return v
}

func (s *Store) setSetting(k, v string) error {
	_, err := s.db.Exec(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

// Scope is the device/share selection from the scope bar. It resolves to the
// set of published scan ids, so every report only ever reads finished indexes.
type Scope struct {
	DeviceID int64
	ShareID  int64
}

func scopeFrom(r *http.Request) Scope {
	d, _ := strconv.ParseInt(r.URL.Query().Get("device"), 10, 64)
	sh, _ := strconv.ParseInt(r.URL.Query().Get("share"), 10, 64)
	return Scope{DeviceID: d, ShareID: sh}
}

func (sc Scope) where() (string, []any) {
	var conds []string
	var args []any
	if sc.DeviceID > 0 {
		conds = append(conds, "device_id=?")
		args = append(args, sc.DeviceID)
	}
	if sc.ShareID > 0 {
		conds = append(conds, "id=?")
		args = append(args, sc.ShareID)
	}
	w := ""
	if len(conds) > 0 {
		w = " WHERE " + strings.Join(conds, " AND ")
	}
	return w, args
}

// scans returns "scan_id IN (...)" for the published index of every share in scope.
func (sc Scope) scans(col string) (string, []any) {
	w, args := sc.where()
	return col + " IN (SELECT current_scan FROM shares" + w + ")", args
}

// scansWithFailed also includes the most recent unpublished scan, for issue reporting.
func (sc Scope) scansWithFailed(col string) (string, []any) {
	w, args := sc.where()
	all := append(append([]any{}, args...), args...)
	return col + " IN (SELECT current_scan FROM shares" + w + " UNION SELECT failed_scan FROM shares" + w + ")", all
}

func now() int64 { return time.Now().Unix() }

const extraSchema = `
CREATE TABLE IF NOT EXISTS ads(scan_id INTEGER, share_id INTEGER, path TEXT, stream TEXT, size INTEGER, class TEXT, owner TEXT);
CREATE INDEX IF NOT EXISTS ads_scan ON ads(scan_id, class);
CREATE TABLE IF NOT EXISTS index_updates(share_id INTEGER, ts INTEGER, events INTEGER, upserted INTEGER, removed INTEGER, message TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS audit_changes(ts INTEGER, device_id INTEGER, action TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS view_log(ts INTEGER, share_id INTEGER, path TEXT, bytes INTEGER, client TEXT);
CREATE TABLE IF NOT EXISTS owner_directory(owner TEXT PRIMARY KEY, display TEXT, dn TEXT, ou TEXT, department TEXT, title TEXT,
  disabled INTEGER DEFAULT 0, resolved_at INTEGER, error TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS perf_samples(ts INTEGER, device_id INTEGER, scope TEXT, key TEXT, metric TEXT, value REAL);
CREATE INDEX IF NOT EXISTS perf_idx ON perf_samples(device_id, scope, key, metric, ts);
`
