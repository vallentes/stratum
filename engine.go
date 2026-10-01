package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// Index engine: every scan writes its file rows into its own table, f_<scanID>, with
// no secondary indexes while it runs (append-only, so ingest speed stays flat). On
// publish the table gets its indexes in one bulk build; replacing an index is a
// DROP TABLE instead of deleting millions of rows. Rows from before this engine
// live in files_legacy until those shares are rescanned.

const fileCols = `scan_id INTEGER, path TEXT, dir TEXT, name TEXT, ext TEXT, size INTEGER, mtime INTEGER, atime INTEGER, ctime INTEGER, owner TEXT, flags INTEGER, etag TEXT`

const colList = `scan_id,path,dir,name,ext,size,mtime,atime,ctime,owner,flags,etag`

var tableCache sync.Map // scanID -> table name

func scanTable(id int64) string { return "f_" + strconv.FormatInt(id, 10) }

// migrateEngine renames the pre-engine files table and makes sure the helper tables exist.
func (s *Store) migrateEngine() {
	var typ string
	s.db.QueryRow(`SELECT type FROM sqlite_master WHERE name='files'`).Scan(&typ)
	if typ == "table" {
		s.db.Exec(`ALTER TABLE files RENAME TO files_legacy`)
	}
	s.db.Exec(`CREATE TABLE IF NOT EXISTS files_legacy(` + fileCols + `)`)
	s.db.Exec(`ALTER TABLE files_legacy ADD COLUMN etag TEXT`)
	s.db.Exec(`CREATE INDEX IF NOT EXISTS files_legacy_scan ON files_legacy(scan_id, ext)`)
	s.db.Exec(`CREATE TABLE IF NOT EXISTS files_empty(` + fileCols + `)`)
}

// tableFor names the table holding a scan's rows.
func (a *App) tableFor(scanID int64) string {
	if v, ok := tableCache.Load(scanID); ok {
		return v.(string)
	}
	t := scanTable(scanID)
	var n int
	a.st.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, t).Scan(&n)
	if n == 0 {
		t = "files_legacy"
	}
	tableCache.Store(scanID, t)
	return t
}

// createScanTable starts a new scan with empty storage. SQLite can hand out a deleted
// scan's id again, so anything left under that id is cleared first.
func (a *App) createScanTable(scanID int64) {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	a.clearScanStorage(scanID)
	a.st.db.Exec(`CREATE TABLE ` + scanTable(scanID) + `(` + fileCols + `)`)
	tableCache.Store(scanID, scanTable(scanID))
}

// clearScanStorage removes every row and table kept for a scan id. Caller holds a.wmu.
func (a *App) clearScanStorage(scanID int64) {
	if scanID <= 0 {
		return
	}
	a.dropAggregates(scanID)
	a.st.db.Exec(`DROP TABLE IF EXISTS ` + scanTable(scanID))
	tableCache.Delete(scanID)
	a.st.db.Exec(`DELETE FROM files_legacy WHERE scan_id=?`, scanID)
	a.st.db.Exec(`DELETE FROM dirs WHERE scan_id=?`, scanID)
	a.st.db.Exec(`DELETE FROM issues WHERE scan_id=?`, scanID)
}

// indexScanTable builds the lookup indexes once, after the walk. Caller holds a.wmu.
func (a *App) indexScanTable(scanID int64) {
	t := a.tableFor(scanID)
	if t == "files_legacy" {
		return
	}
	a.st.db.Exec(`CREATE INDEX IF NOT EXISTS ` + t + `_ext ON ` + t + `(ext)`)
	a.st.db.Exec(`CREATE INDEX IF NOT EXISTS ` + t + `_path ON ` + t + `(path)`)
	a.st.db.Exec(`ANALYZE ` + t)
}

// dropScanFiles removes a scan's file rows: a table drop, or chunked deletes for legacy rows.
func (a *App) dropScanFiles(scanID int64) {
	t := a.tableFor(scanID)
	if t != "files_legacy" {
		a.wmu.Lock()
		a.st.db.Exec(`DROP TABLE IF EXISTS ` + t)
		a.wmu.Unlock()
		tableCache.Delete(scanID)
		return
	}
	a.chunkDelete("files_legacy", scanID)
}

func (a *App) chunkDelete(table string, scanID int64) {
	for {
		a.wmu.Lock()
		res, err := a.st.db.Exec(`DELETE FROM `+table+` WHERE rowid IN (SELECT rowid FROM `+table+` WHERE scan_id=? LIMIT 20000)`, scanID)
		a.wmu.Unlock()
		if err != nil {
			return
		}
		if n, _ := res.RowsAffected(); n < 20000 {
			return
		}
	}
}

// scopeScans lists the published scan ids for a scope.
func (a *App) scopeScans(sc Scope) []int64 {
	w, args := sc.where()
	if w == "" {
		w = " WHERE current_scan>0"
	} else {
		w += " AND current_scan>0"
	}
	return a.ids(`SELECT current_scan FROM shares`+w, args...)
}

// fileSelect builds " FROM <files> f JOIN shares s ... WHERE ..." for a filter,
// reading only the tables of the shares in the filter's scope.
func (a *App) fileSelect(fl Filter) (string, []any) {
	sc := Scope{DeviceID: fl.DeviceID, ShareID: fl.ShareID}
	cond, cargs := fl.conditions()
	// Filter inside each scan's own table (so its ext/path indexes are used and only
	// matches are combined), then join the small result back to shares/devices.
	// Filtering a UNION of every table instead made SQLite materialise millions of
	// rows first: over a minute per search on spinning disks.
	var parts []string
	var args []any
	for _, id := range a.scopeScans(sc) {
		parts = append(parts, `SELECT `+prefixed("f.", colList)+` FROM `+a.fileRowsFor(id)+` f JOIN shares s ON s.current_scan=f.scan_id JOIN devices d ON d.id=s.device_id WHERE f.scan_id=`+strconv.FormatInt(id, 10)+` AND `+cond)
		args = append(args, cargs...)
	}
	from := `(SELECT ` + colList + ` FROM files_empty)`
	if len(parts) > 0 {
		from = "(" + strings.Join(parts, " UNION ALL ") + ")"
	}
	return " FROM " + from + " f JOIN shares s ON s.current_scan=f.scan_id JOIN devices d ON d.id=s.device_id WHERE 1=1", args
}

// prefixed turns "a,b,c" into "f.a,f.b,f.c".

func (a *App) fileRowsFor(scanID int64) string {
	t := a.tableFor(scanID)
	if t == "files_legacy" {
		return fmt.Sprintf("(SELECT %s FROM files_legacy WHERE scan_id=%d)", colList, scanID)
	}
	return t
}

func prefixed(p, cols string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = p + c
	}
	return strings.Join(parts, ",")
}
