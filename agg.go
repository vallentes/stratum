package main

import (
	"log"
	"strings"
	"time"
)

// Publish-time aggregates. Reports read these small tables instead of scanning
// every file row, so the dashboard stays fast at tens of millions of files.
//
//   scan_agg  (scan_id, dim, key, bytes, files)
//     dim m/a/c: key = day (YYYY-MM-DD) of modified / accessed / created time
//     dim e:     key = extension
//     dim s:     key = size class
//   dup_sets  (scan_id, name, size, mtime, copies)
//   risk_hits (scan_id, cat, path, dir, name, size, mtime, owner)

const aggSchema = `
CREATE TABLE IF NOT EXISTS scan_agg(scan_id INTEGER, dim TEXT, key TEXT, bytes INTEGER, files INTEGER);
CREATE INDEX IF NOT EXISTS scan_agg_idx ON scan_agg(scan_id, dim);
CREATE TABLE IF NOT EXISTS dup_sets(scan_id INTEGER, name TEXT, size INTEGER, mtime INTEGER, copies INTEGER);
CREATE INDEX IF NOT EXISTS dup_sets_idx ON dup_sets(scan_id, size);
CREATE TABLE IF NOT EXISTS risk_hits(scan_id INTEGER, cat TEXT, path TEXT, dir TEXT, name TEXT, size INTEGER, mtime INTEGER, owner TEXT);
CREATE INDEX IF NOT EXISTS risk_hits_idx ON risk_hits(scan_id, cat);
CREATE TABLE IF NOT EXISTS agg_done(scan_id INTEGER PRIMARY KEY, built INTEGER);
`

const sizeClassSQL = `CASE WHEN size < 1048576 THEN '1:<1MB' WHEN size < 104857600 THEN '2:1-100MB' WHEN size < 1073741824 THEN '3:100MB-1GB'
  WHEN size < 10737418240 THEN '4:1-10GB' ELSE '5:10GB+' END`

// riskCats lists every category precomputed into risk_hits: SQL condition + args.
func riskCats() []struct {
	cat  string
	cond string
	args []any
} {
	var out []struct {
		cat  string
		cond string
		args []any
	}
	add := func(cat string, exts, names []string) {
		var parts []string
		var args []any
		if len(exts) > 0 {
			q, aa := inList("ext", exts)
			parts = append(parts, q)
			args = append(args, aa...)
		}
		for _, n := range names {
			parts = append(parts, "lower(name) LIKE ?")
			args = append(args, n)
		}
		out = append(out, struct {
			cat  string
			cond string
			args []any
		}{cat, "(" + strings.Join(parts, " OR ") + ")", args})
	}
	add("ransom_ext", ransomExts, nil)
	add("ransom_note", nil, ransomNotePatterns)
	for _, c := range sensitiveCats {
		add(c.Key, c.Exts, c.Names)
	}
	return out
}

// buildAggregates computes all aggregates for one published scan. Caller holds a.wmu.
func (a *App) buildAggregates(scanID int64) {
	t := time.Now()
	db := a.st.db
	for _, tbl := range []string{"scan_agg", "dup_sets", "risk_hits", "agg_done"} {
		db.Exec(`DELETE FROM `+tbl+` WHERE scan_id=?`, scanID)
	}
	ft := a.fileRowsFor(scanID)
	// Hard-link duplicates (flag 4) are listed but never counted twice in capacity.
	sz := "CASE WHEN flags & 4 = 0 THEN size ELSE 0 END"
	aggIns := `INSERT INTO scan_agg VALUES(?,?,?,?,?)`
	for dim, col := range map[string]string{"m": "mtime", "a": "atime", "c": "ctime"} {
		a.copyRows(aggIns, `SELECT ?, ?, date(`+col+`,'unixepoch'), SUM(`+sz+`), COUNT(*) FROM `+ft+` GROUP BY 3`, scanID, dim)
	}
	a.copyRows(aggIns, `SELECT ?, 'e', ext, SUM(`+sz+`), COUNT(*) FROM `+ft+` GROUP BY ext`, scanID)
	a.copyRows(aggIns, `SELECT ?, 's', `+sizeClassSQL+`, SUM(`+sz+`), COUNT(*) FROM `+ft+` GROUP BY 3`, scanID)
	// Files: same name + size + modified time. Objects: same ETag + size (content hash for single-part uploads).
	dupIns := `INSERT INTO dup_sets(scan_id,name,size,mtime,copies,etag) VALUES(?,?,?,?,?,?)`
	a.copyRows(dupIns, `SELECT ?, name, size, mtime, COUNT(*) c, '' FROM `+ft+` WHERE size>0 AND COALESCE(etag,'')='' AND flags & 4 = 0 GROUP BY name, size, mtime HAVING c>1`, scanID)
	a.copyRows(dupIns, `SELECT ?, MIN(name), size, 0, COUNT(*) c, etag FROM `+ft+` WHERE size>0 AND COALESCE(etag,'')<>'' GROUP BY etag, size HAVING c>1`, scanID)
	for _, rc := range riskCats() {
		a.copyRows(`INSERT INTO risk_hits VALUES(?,?,?,?,?,?,?,?)`, `SELECT ?, ?, path, dir, name, size, mtime, owner FROM `+ft+` WHERE `+rc.cond+` LIMIT 200000`,
			append([]any{scanID, rc.cat}, rc.args...)...)
	}
	db.Exec(`INSERT INTO agg_done VALUES(?,?)`, scanID, now())
	log.Printf("aggregates for scan %d built in %s", scanID, time.Since(t).Round(time.Millisecond))
}

// copyRows runs a SELECT, which in WAL mode holds no write lock however long it
// takes, then inserts the (small) result in one short transaction. INSERT ... SELECT
// over millions of rows held the database's write lock for minutes on slow disks,
// and every other write in the app timed out meanwhile.
func (a *App) copyRows(insert, sel string, args ...any) {
	rows, err := a.st.db.Query(sel, args...)
	if err != nil {
		log.Printf("aggregate query: %v", err)
		return
	}
	cols, _ := rows.Columns()
	var buf [][]any
	for rows.Next() {
		v := make([]any, len(cols))
		ptr := make([]any, len(cols))
		for i := range v {
			ptr[i] = &v[i]
		}
		if rows.Scan(ptr...) == nil {
			buf = append(buf, v)
		}
	}
	rows.Close()
	tx, err := a.st.db.Begin()
	if err != nil {
		log.Printf("aggregate insert: %v", err)
		return
	}
	st, err := tx.Prepare(insert)
	if err != nil {
		tx.Rollback()
		log.Printf("aggregate insert: %v", err)
		return
	}
	for _, v := range buf {
		st.Exec(v...)
	}
	tx.Commit()
}

func (a *App) dropAggregates(scanID int64) {
	for _, tbl := range []string{"scan_agg", "dup_sets", "risk_hits", "agg_done"} {
		a.st.db.Exec(`DELETE FROM `+tbl+` WHERE scan_id=?`, scanID)
	}
}

// backfillAggregates builds aggregates for published scans that predate them.
func (a *App) backfillAggregates() {
	for _, id := range a.ids(`SELECT current_scan FROM shares WHERE current_scan>0 AND current_scan NOT IN (SELECT scan_id FROM agg_done)`) {
		a.wmu.Lock()
		a.buildAggregates(id)
		a.wmu.Unlock()
	}
}

type aggBucket struct {
	Key   string
	Bytes int64
	Files int64
}

// aggFor sums one dimension across the published scans in scope.
func (a *App) aggFor(sc Scope, dim string) []aggBucket {
	cond, args := sc.scans("scan_id")
	rows, err := a.st.db.Query(`SELECT key, SUM(bytes), SUM(files) FROM scan_agg WHERE dim=? AND `+cond+` GROUP BY key`, append([]any{dim}, args...)...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []aggBucket
	for rows.Next() {
		var r aggBucket
		var k *string
		rows.Scan(&k, &r.Bytes, &r.Files)
		if k != nil {
			r.Key = *k
		}
		out = append(out, r)
	}
	return out
}

func dayUnix(key string) int64 {
	t, err := time.Parse("2006-01-02", key)
	if err != nil {
		return 0
	}
	return t.Unix()
}
