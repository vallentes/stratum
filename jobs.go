package main

import (
	"net/http"
	"sort"
	"sync"
)

// Long-running jobs other than scans (today: turning file auditing on or off, which
// makes Windows rewrite the security settings of every file below a folder). The
// worker records what it is doing; collectors send the list on every poll and the
// Index page shows it with an estimate.

type jobState struct {
	ID      int64  `json:"id"`
	Kind    string `json:"kind"` // enable_audit | disable_audit
	Started int64  `json:"started"`
	Step    int    `json:"step"` // 1-based
	Steps   int    `json:"steps"`
	Path    string `json:"path"`
	StepAt  int64  `json:"step_started"`
	Ops     int64  `json:"ops"` // I/O operations of the current step's worker process
	pid     int
}

type jobTracker struct {
	mu   sync.Mutex
	next int64
	jobs map[int64]*jobState
}

var jobs = &jobTracker{jobs: map[int64]*jobState{}}

func (t *jobTracker) start(kind string, steps int) *jobState {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.next++
	j := &jobState{ID: t.next, Kind: kind, Started: now(), Steps: steps}
	t.jobs[j.ID] = j
	return j
}

func (t *jobTracker) end(j *jobState) {
	t.mu.Lock()
	delete(t.jobs, j.ID)
	t.mu.Unlock()
}

func (t *jobTracker) stepTo(j *jobState, step int, path string) {
	if j == nil {
		return
	}
	t.mu.Lock()
	j.Step, j.Path, j.StepAt, j.Ops, j.pid = step, path, now(), 0, 0
	t.mu.Unlock()
}

func (t *jobTracker) setPID(j *jobState, pid int) {
	if j == nil {
		return
	}
	t.mu.Lock()
	j.pid = pid
	t.mu.Unlock()
}

// snapshot returns copies with fresh I/O counters.
func (t *jobTracker) snapshot() []jobState {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]jobState, 0, len(t.jobs))
	for _, j := range t.jobs {
		if j.pid > 0 {
			if ops := processOps(j.pid); ops > 0 {
				j.Ops = ops
			}
		}
		out = append(out, *j)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out
}

type jobOut struct {
	jobState
	Where     string  `json:"where"`  // collector name or "this server"
	Device    string  `json:"device"` // device the path belongs to
	Share     string  `json:"share"`
	Items     int64   `json:"items"`      // files + folders indexed under the path
	Pct       float64 `json:"pct"`        // estimated, -1 when unknown
	RemainSec int64   `json:"remain_sec"` // estimate for the current step, -1 when unknown
}

// opsPerItem: applying an inherited audit rule costs about nine I/O operations per
// file or folder on NTFS (measured: 1.9M items on D: took ~17M operations).
const opsPerItem = 9.0

func (a *App) jobsReport(w http.ResponseWriter, r *http.Request) {
	var out []jobOut
	add := func(where string, collectorID int64, list []jobState) {
		for _, j := range list {
			o := jobOut{jobState: j, Where: where, Pct: -1, RemainSec: -1}
			// Match the path to an indexed share to know how many items the step touches.
			q := `SELECT d.name, s.name, COALESCE(c.files,0)+COALESCE(c.dirs,0) FROM shares s JOIN devices d ON d.id=s.device_id
			  LEFT JOIN scans c ON c.id=s.current_scan WHERE d.collector_id=? AND lower(s.path)=lower(?) LIMIT 1`
			a.st.db.QueryRow(q, collectorID, j.Path).Scan(&o.Device, &o.Share, &o.Items)
			if o.Items > 0 && j.Ops > 0 {
				o.Pct = min(99, float64(j.Ops)/(float64(o.Items)*opsPerItem)*100)
				if el := now() - j.StepAt; el > 30 && o.Pct > 1 {
					o.RemainSec = int64(float64(el) * (100 - o.Pct) / o.Pct)
				}
			}
			out = append(out, o)
		}
	}
	add("this server", 0, jobs.snapshot())
	rows, _ := a.st.db.Query(`SELECT id, name FROM collectors`)
	type col struct {
		id   int64
		name string
	}
	var cols []col
	for rows != nil && rows.Next() {
		var c col
		rows.Scan(&c.id, &c.name)
		cols = append(cols, c)
	}
	if rows != nil {
		rows.Close()
	}
	for _, c := range cols {
		ts, info := a.collectorSeen(c.id)
		if info == nil || now()-ts > 60 {
			continue
		}
		raw, _ := info["jobs"].([]any)
		var list []jobState
		for _, x := range raw {
			m, _ := x.(map[string]any)
			num := func(k string) int64 {
				switch v := m[k].(type) {
				case float64:
					return int64(v)
				case interface{ Int64() (int64, error) }:
					n, _ := v.Int64()
					return n
				}
				return 0
			}
			k, _ := m["kind"].(string)
			p, _ := m["path"].(string)
			list = append(list, jobState{ID: num("id"), Kind: k, Started: num("started"), Step: int(num("step")), Steps: int(num("steps")),
				Path: p, StepAt: num("step_started"), Ops: num("ops")})
		}
		add(c.name, c.id, list)
	}
	if out == nil {
		out = []jobOut{}
	}
	writeJSON(w, out)
}
