package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// ---------- tag rules ----------

type TagRule struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Tag     string `json:"tag"`
	Match   Filter `json:"match"`
	Enabled bool   `json:"enabled"`
	Tagged  int64  `json:"tagged"`
}

// applyTagRules re-evaluates every enabled rule against a share's published index.
// Tags are derived state: rerunning is idempotent and removing a rule removes its tags.
func (a *App) applyTagRules(shareID int64) {
	rows, err := a.st.db.Query(`SELECT id,tag,match FROM tag_rules WHERE enabled=1`)
	if err != nil {
		return
	}
	type rr struct {
		id    int64
		tag   string
		match string
	}
	var rules []rr
	for rows.Next() {
		var r rr
		rows.Scan(&r.id, &r.tag, &r.match)
		rules = append(rules, r)
	}
	rows.Close()
	for _, r := range rules {
		a.applyRule(r.id, r.tag, r.match, shareID)
	}
}

func (a *App) applyRule(id int64, tag, match string, shareID int64) error {
	var fl Filter
	json.Unmarshal([]byte(match), &fl)
	if fl.empty() {
		return errors.New("rule has no conditions")
	}
	fl.Tag = "" // a rule never selects on tags (avoids feedback loops)
	if shareID > 0 {
		if fl.ShareID > 0 && fl.ShareID != shareID {
			return nil
		}
		fl.ShareID = shareID
		a.st.db.Exec(`DELETE FROM file_tags WHERE rule_id=? AND share_id=?`, id, shareID)
	} else {
		a.st.db.Exec(`DELETE FROM file_tags WHERE rule_id=?`, id)
	}
	from, args := a.fileSelect(fl)
	_, err := a.st.db.Exec(`INSERT OR IGNORE INTO file_tags(share_id,path,tag,rule_id) SELECT s.id, f.path, ?, ?`+from,
		append([]any{tag, id}, args...)...)
	return err
}

// ---------- Automations ----------

type Action struct {
	Type     string `json:"type"`               // copy move delete rename tag untag
	Target   string `json:"target,omitempty"`   // copy/move destination root
	Template string `json:"template,omitempty"` // rename: {stem} {ext} {name} {date}
	Tag      string `json:"tag,omitempty"`
}

type Automation struct {
	ID         int64    `json:"id"`
	Name       string   `json:"name"`
	Desc       string   `json:"description"`
	Enabled    bool     `json:"enabled"`
	InputKind  string   `json:"input_kind"` // search | tag
	Input      Filter   `json:"input"`
	Actions    []Action `json:"actions"`
	Schedule   string   `json:"schedule"` // "" = manual, "HH:MM" = daily
	LastStatus string   `json:"last_status"`
	LastRunAt  int64    `json:"last_run_at"`
}

func isDestructive(acts []Action) bool {
	for _, a := range acts {
		switch a.Type {
		case "move", "delete", "rename":
			return true
		}
	}
	return false
}

func validateAutomation(au *Automation) error {
	if strings.TrimSpace(au.Name) == "" {
		return errors.New("name is required")
	}
	if len(au.Actions) == 0 {
		return errors.New("add at least one action")
	}
	if au.InputKind == "tag" && au.Input.Tag == "" {
		return errors.New("tag input needs a tag")
	}
	if au.Input.empty() {
		return errors.New("input selects every file; add at least one condition")
	}
	for _, ac := range au.Actions {
		switch ac.Type {
		case "copy", "move":
			if ac.Target == "" {
				return fmt.Errorf("%s needs a target folder", ac.Type)
			}
		case "rename":
			if !strings.Contains(ac.Template, "{") {
				return errors.New("rename needs a template such as {stem}_old{ext}")
			}
		case "tag", "untag":
			if ac.Tag == "" {
				return fmt.Errorf("%s needs a tag", ac.Type)
			}
		case "delete":
		default:
			return fmt.Errorf("unknown action %q", ac.Type)
		}
	}
	if au.Schedule != "" {
		if _, err := time.Parse("15:04", au.Schedule); err != nil {
			return errors.New("schedule must be HH:MM (daily)")
		}
	}
	return nil
}

func (a *App) automation(id int64) (Automation, error) {
	var au Automation
	var en int
	var in, acts string
	err := a.st.db.QueryRow(`SELECT id,name,description,enabled,input_kind,input,actions,schedule,last_status,last_run_at FROM automations WHERE id=?`, id).
		Scan(&au.ID, &au.Name, &au.Desc, &en, &au.InputKind, &in, &acts, &au.Schedule, &au.LastStatus, &au.LastRunAt)
	au.Enabled = en == 1
	json.Unmarshal([]byte(in), &au.Input)
	json.Unmarshal([]byte(acts), &au.Actions)
	return au, err
}

const maxRunItems = 100000

func renderName(tpl, name string) string {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	return strings.NewReplacer("{stem}", stem, "{ext}", ext, "{name}", name, "{date}", time.Now().Format("20060102")).Replace(tpl)
}

// executor performs one action on one item for one device kind.
type executor struct {
	dev   Device
	share Share
	ps    *psClient
	s3    *s3Lister
}

func (x *executor) full(rel string) string {
	if x.dev.Kind == "powerscale" {
		return path.Join(x.share.Path, rel)
	}
	return filepath.Join(x.share.Path, filepath.FromSlash(strings.TrimPrefix(rel, "/")))
}

func (x *executor) dest(root, rel string) string {
	if x.dev.Kind == "powerscale" {
		return path.Join(root, x.share.Name, rel)
	}
	return filepath.Join(root, x.share.Name, filepath.FromSlash(strings.TrimPrefix(rel, "/")))
}

func (x *executor) exists(p string) bool {
	if x.dev.Kind == "powerscale" {
		resp, err := x.ps.do("HEAD", nsPath(p), nil, nil)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	}
	_, err := os.Lstat(p)
	return err == nil
}

func copyLocal(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chtimes(dst, st.ModTime(), st.ModTime())
}

// apply runs one action. It returns the item's new rel path (after move/rename,
// "" once the item has left the share) and the target it acted on.
func (x *executor) apply(ac Action, rel string, dry bool) (newRel, target string, err error) {
	if x.dev.Kind == "s3" {
		return x.applyS3(ac, rel, dry)
	}
	src := x.full(rel)
	if ac.Type != "tag" && ac.Type != "untag" && !x.exists(src) {
		return rel, "", errors.New("source no longer exists (index is older than the file system)")
	}
	switch ac.Type {
	case "copy", "move":
		target = x.dest(ac.Target, rel)
		if x.exists(target) {
			return rel, target, errors.New("target already exists, not overwritten")
		}
		if dry {
			break
		}
		if x.dev.Kind == "powerscale" {
			if err = x.ps.ranMkdir(path.Dir(target)); err != nil {
				return rel, target, err
			}
			if ac.Type == "copy" {
				err = x.ps.ranCopy(src, target)
			} else {
				err = x.ps.ranMove(src, target)
			}
		} else if ac.Type == "copy" {
			err = copyLocal(src, target)
		} else {
			os.MkdirAll(filepath.Dir(target), 0o755)
			if err = os.Rename(src, target); err != nil { // cross-volume: copy then remove
				if err = copyLocal(src, target); err == nil {
					err = os.Remove(src)
				}
			}
		}
		if ac.Type == "move" {
			newRel = ""
		} else {
			newRel = rel
		}
		return newRel, target, err
	case "delete":
		target = src
		if !dry {
			if x.dev.Kind == "powerscale" {
				err = x.ps.ranDelete(src, false)
			} else {
				err = os.Remove(src)
			}
		}
		return "", target, err
	case "rename":
		nn := renderName(ac.Template, path.Base(rel))
		if nn == "" || strings.ContainsAny(nn, `/\`) {
			return rel, "", errors.New("template produced an invalid name")
		}
		newRel = path.Join(path.Dir(rel), nn)
		target = x.full(newRel)
		if x.exists(target) {
			return rel, target, errors.New("a file with the new name already exists")
		}
		if !dry {
			if x.dev.Kind == "powerscale" {
				err = x.ps.ranMove(src, target)
			} else {
				err = os.Rename(src, target)
			}
		}
		return newRel, target, err
	case "tag", "untag":
		return rel, ac.Tag, nil
	}
	return rel, "", fmt.Errorf("unknown action %s", ac.Type)
}

func (a *App) startAutomationRun(au Automation, dry bool) (int64, error) {
	res, err := a.st.db.Exec(`INSERT INTO automation_runs(automation_id,dry_run,started,status) VALUES(?,?,?,'running')`, au.ID, b2i(dry), now())
	if err != nil {
		return 0, err
	}
	runID, _ := res.LastInsertId()
	a.st.db.Exec(`UPDATE automations SET last_status='running', last_run_at=? WHERE id=?`, now(), au.ID)
	go a.runAutomation(au, runID, dry)
	return runID, nil
}

// ledgerEntry is one action applied (or simulated) on one item.
type ledgerEntry struct {
	Rel    string `json:"rel"`
	Action string `json:"action"`
	Target string `json:"target"`
	Result string `json:"result"` // ok | dry-run | failed
	Detail string `json:"detail"`
	NewRel string `json:"new_rel"`
}

// execItem runs the whole pipeline for one item. Pure storage work, no database,
// so it can run on the server or on a collector.
func execItem(x *executor, actions []Action, rel string, dry bool) (entries []ledgerEntry, ok bool) {
	ok = true
	for _, ac := range actions {
		if rel == "" {
			break // moved or deleted by an earlier step
		}
		newRel, target, err := x.apply(ac, rel, dry)
		e := ledgerEntry{Rel: rel, Action: ac.Type, Target: target, Result: "ok", NewRel: newRel}
		if err != nil {
			e.Result, e.Detail, ok = "failed", err.Error(), false
		} else if dry {
			e.Result = "dry-run"
		}
		entries = append(entries, e)
		if err != nil {
			break
		}
		rel = newRel
	}
	return
}

type execPayload struct {
	Device  deviceWire `json:"device"`
	Share   Share      `json:"share"`
	Actions []Action   `json:"actions"`
	Rels    []string   `json:"rels"`
	Dry     bool       `json:"dry"`
}

func execBatch(pl execPayload) [][]ledgerEntry {
	d := pl.Device.dev()
	x := &executor{dev: d, share: pl.Share}
	if d.Kind == "powerscale" {
		x.ps = psClientFor(d)
	}
	if d.Kind == "s3" {
		if l, err := newS3Lister(d, pl.Share.Path); err == nil {
			x.s3 = l.(*s3Lister)
		}
	}
	out := make([][]ledgerEntry, len(pl.Rels))
	for i, rel := range pl.Rels {
		out[i], _ = execItem(x, pl.Actions, rel, pl.Dry)
	}
	return out
}

func (a *App) runAutomation(au Automation, runID int64, dry bool) {
	from, args := a.fileSelect(au.Input)
	rows, err := a.st.db.Query(`SELECT s.id, f.path`+from+` ORDER BY s.id, f.path LIMIT ?`, append(args, maxRunItems+1)...)
	finish := func(status, msg string, items, ok, failed int) {
		a.st.db.Exec(`UPDATE automation_runs SET finished=?,status=?,items=?,ok=?,failed=?,message=? WHERE id=?`,
			now(), status, items, ok, failed, msg, runID)
		label := status
		if dry && status == "completed" {
			label = "completed (dry-run)"
		}
		a.st.db.Exec(`UPDATE automations SET last_status=? WHERE id=?`, label, au.ID)
	}
	if err != nil {
		finish("failed", err.Error(), 0, 0, 0)
		return
	}
	byShare := map[int64][]string{}
	var order []int64
	total := 0
	for rows.Next() {
		var sid int64
		var rel string
		rows.Scan(&sid, &rel)
		if byShare[sid] == nil {
			order = append(order, sid)
		}
		byShare[sid] = append(byShare[sid], rel)
		total++
	}
	rows.Close()
	if total > maxRunItems {
		finish("failed", fmt.Sprintf("input matches more than %d items; narrow the search", maxRunItems), 0, 0, 0)
		return
	}
	ok, failed, done := 0, 0, 0
	var notes []string
	for _, sid := range order {
		sh, err1 := a.share(sid)
		dv, err2 := a.device(sh.DeviceID)
		rels := byShare[sid]
		if err1 != nil || err2 != nil {
			failed += len(rels)
			continue
		}
		chunk := 500
		if dv.CollectorID > 0 {
			chunk = 250
		}
		for i := 0; i < len(rels); i += chunk {
			part := rels[i:min(i+chunk, len(rels))]
			pl := execPayload{Device: dv.wire(), Share: sh, Actions: au.Actions, Rels: part, Dry: dry}
			var results [][]ledgerEntry
			if dv.CollectorID > 0 {
				raw, err := a.runTask(dv.CollectorID, "exec", pl, 15*time.Minute)
				if err == nil {
					err = json.Unmarshal(raw, &results)
				}
				if err != nil || len(results) != len(part) {
					msg := "collector did not return results"
					if err != nil {
						msg = err.Error()
					}
					results = make([][]ledgerEntry, len(part))
					for k, rel := range part {
						results[k] = []ledgerEntry{{Rel: rel, Action: au.Actions[0].Type, Result: "failed", Detail: msg}}
					}
					notes = append(notes, msg)
				}
			} else {
				results = execBatch(pl)
			}
			// Short transaction per chunk: ledger + index reflect, never held across storage I/O.
			a.wmu.Lock()
			tx, err := a.st.db.Begin()
			if err != nil {
				a.wmu.Unlock()
				finish("failed", err.Error(), total, ok, failed)
				return
			}
			led, _ := tx.Prepare(`INSERT INTO automation_ledger(run_id,ts,share_id,path,action,target,result,detail) VALUES(?,?,?,?,?,?,?,?)`)
			acts := map[string]Action{}
			for _, ac := range au.Actions {
				acts[ac.Type] = ac
			}
			for _, entries := range results {
				itemOK := len(entries) > 0
				for _, e := range entries {
					led.Exec(runID, now(), sid, e.Rel, e.Action, e.Target, e.Result, e.Detail)
					if e.Result == "failed" {
						itemOK = false
					} else if e.Result == "ok" {
						a.reflectInIndex(tx, sh, acts[e.Action], e.Rel, e.NewRel)
					}
				}
				if itemOK {
					ok++
				} else {
					failed++
				}
			}
			tx.Commit()
			a.wmu.Unlock()
			done += len(part)
			a.st.db.Exec(`UPDATE automation_runs SET items=?,ok=?,failed=? WHERE id=?`, done, ok, failed, runID)
		}
	}
	status := "completed"
	if failed > 0 && ok == 0 {
		status = "failed"
	} else if failed > 0 {
		status = "completed with errors"
	}
	msg := ""
	if len(notes) > 0 {
		msg = notes[0]
	}
	finish(status, msg, total, ok, failed)
	log.Printf("automation %q run %d (dry=%v): %d items, %d ok, %d failed", au.Name, runID, dry, total, ok, failed)
}

// reflectInIndex keeps the published index truthful after a real action, so
// reports don't show deleted/moved files until the next scan.
func (a *App) reflectInIndex(db interface {
	Exec(string, ...any) (sql.Result, error)
}, sh Share, ac Action, rel, newRel string) {
	switch ac.Type {
	case "delete", "move":
		db.Exec(`DELETE FROM `+a.tableFor(sh.CurrentScan)+` WHERE path=? AND scan_id=?`, rel, sh.CurrentScan)
		db.Exec(`DELETE FROM file_tags WHERE share_id=? AND path=?`, sh.ID, rel)
	case "rename":
		db.Exec(`UPDATE `+a.tableFor(sh.CurrentScan)+` SET path=?, name=?, ext=? WHERE path=? AND scan_id=?`, newRel, path.Base(newRel), extOf(newRel), rel, sh.CurrentScan)
		db.Exec(`UPDATE file_tags SET path=? WHERE share_id=? AND path=?`, newRel, sh.ID, rel)
	case "tag":
		db.Exec(`INSERT OR IGNORE INTO file_tags(share_id,path,tag,rule_id) VALUES(?,?,?,0)`, sh.ID, rel, ac.Tag)
	case "untag":
		db.Exec(`DELETE FROM file_tags WHERE share_id=? AND path=? AND tag=?`, sh.ID, rel, ac.Tag)
	}
}

func (a *App) runScheduledAutomations() {
	rows, err := a.st.db.Query(`SELECT id FROM automations WHERE enabled=1 AND schedule<>''`)
	if err != nil {
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	t := time.Now()
	for _, id := range ids {
		au, err := a.automation(id)
		if err != nil {
			continue
		}
		at, _ := time.ParseInLocation("15:04", au.Schedule, time.Local)
		due := time.Date(t.Year(), t.Month(), t.Day(), at.Hour(), at.Minute(), 0, 0, time.Local)
		if t.Before(due) || au.LastRunAt >= due.Unix() || au.LastStatus == "running" {
			continue
		}
		a.startAutomationRun(au, false)
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// applyS3 runs one action on one object. Copy and move are server-side copies;
// rename is copy then delete (S3 has no rename).
func (x *executor) applyS3(ac Action, rel string, dry bool) (newRel, target string, err error) {
	l := x.s3
	if l == nil {
		return rel, "", errors.New("S3 endpoint not reachable")
	}
	if ac.Type == "tag" || ac.Type == "untag" {
		return rel, ac.Tag, nil
	}
	if !l.exists(rel) {
		return rel, "", errors.New("object no longer exists (index is older than the bucket)")
	}
	switch ac.Type {
	case "copy", "move":
		if dry {
			tb, tp, _ := strings.Cut(strings.Trim(ac.Target, "/"), "/")
			return rel, tb + "/" + strings.Trim(tp+"/"+strings.TrimPrefix(rel, "/"), "/"), nil
		}
		target, err = l.copyTo(rel, ac.Target)
		if err != nil || ac.Type == "copy" {
			return rel, target, err
		}
		return "", target, l.remove(rel)
	case "delete":
		if !dry {
			err = l.remove(rel)
		}
		return "", l.bucket + "/" + l.key(rel), err
	case "rename":
		nn := renderName(ac.Template, path.Base(rel))
		if nn == "" || strings.Contains(nn, "/") {
			return rel, "", errors.New("template produced an invalid name")
		}
		newRel = path.Join(path.Dir(rel), nn)
		if l.exists(newRel) {
			return rel, newRel, errors.New("an object with the new name already exists")
		}
		if dry {
			return newRel, l.bucket + "/" + l.key(newRel), nil
		}
		target = l.bucket + "/" + l.key(newRel)
		if err = l.copyKey(rel, l.bucket, l.key(newRel)); err != nil {
			return rel, target, err
		}
		return newRel, target, l.remove(rel)
	}
	return rel, "", fmt.Errorf("unknown action %s", ac.Type)
}
