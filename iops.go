package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// IOPS diagnostics. One sample per minute per device:
//   Windows    typeperf: PhysicalDisk, LogicalDisk and SMB Server Shares transfer rates
//   Linux      /proc/diskstats deltas (completed reads+writes per second)
//   PowerScale PAPI statistics: per-node disk transfer rate, protocol ops (key names
//              can differ between OneFS releases; unknown keys are skipped)
// Analysis compares each series with its own history: robust baseline (median/MAD of
// the same hour over the last 7 days), anomalies (|z| > 4) and level shifts.

type perfSample struct {
	Scope  string  `json:"scope"`
	Key    string  `json:"key"`
	Metric string  `json:"metric"`
	Value  float64 `json:"value"`
}

func collectPerf(d Device) ([]perfSample, error) {
	switch d.Kind {
	case "windows":
		if !isLocalHost(d.Host) {
			return nil, fmt.Errorf("IOPS for a remote Windows server needs a collector on that server")
		}
		if runtime.GOOS == "windows" {
			return perfWindows()
		}
		return perfLinux()
	case "powerscale":
		return perfPowerScale(d)
	}
	return nil, nil
}

func perfWindows() ([]perfSample, error) {
	counters := []string{`\PhysicalDisk(*)\Disk Transfers/sec`, `\LogicalDisk(*)\Disk Transfers/sec`, `\SMB Server Shares(*)\Data Requests/sec`}
	args := append(counters, "-sc", "2", "-si", "1")
	out, err := exec.Command("typeperf", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("typeperf: %w", err)
	}
	r := csv.NewReader(strings.NewReader(string(out)))
	r.FieldsPerRecord = -1
	recs, _ := r.ReadAll()
	var header, last []string
	for _, rec := range recs {
		if len(rec) < 2 {
			continue
		}
		if strings.Contains(rec[0], "PDH-CSV") {
			header = rec
		} else if header != nil {
			last = rec // second sample: rates need two readings
		}
	}
	var s []perfSample
	for i := 1; i < len(header) && i < len(last); i++ {
		v, err := strconv.ParseFloat(strings.TrimSpace(last[i]), 64)
		if err != nil {
			continue
		}
		// \\HOST\PhysicalDisk(0 C:)\Disk Transfers/sec
		h := header[i]
		obj, inst := "", ""
		if a := strings.IndexByte(h, '('); a >= 0 {
			if b := strings.IndexByte(h[a:], ')'); b >= 0 {
				inst = h[a+1 : a+b]
				objStart := strings.LastIndexByte(h[:a], '\\')
				obj = h[objStart+1 : a]
			}
		}
		scope := map[string]string{"PhysicalDisk": "disk", "LogicalDisk": "volume", "SMB Server Shares": "share"}[obj]
		if scope == "" {
			continue
		}
		if inst == "_Total" {
			scope, inst = "host", obj+" total"
		}
		s = append(s, perfSample{scope, inst, "iops", v})
	}
	return s, nil
}

func readDiskstats() map[string]float64 {
	f, err := os.Open("/proc/diskstats")
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]float64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) < 8 || strings.HasPrefix(p[2], "loop") || strings.HasPrefix(p[2], "ram") {
			continue
		}
		r, _ := strconv.ParseFloat(p[3], 64)
		w, _ := strconv.ParseFloat(p[7], 64)
		out[p[2]] = r + w
	}
	return out
}

func perfLinux() ([]perfSample, error) {
	a := readDiskstats()
	time.Sleep(time.Second)
	b := readDiskstats()
	var s []perfSample
	var total float64
	for dev, v := range b {
		d := v - a[dev]
		if d < 0 {
			continue
		}
		s = append(s, perfSample{"disk", dev, "iops", d})
		if !strings.ContainsAny(dev[len(dev)-1:], "0123456789") || strings.HasPrefix(dev, "md") || strings.HasPrefix(dev, "nvme") && !strings.Contains(dev, "p") {
			total += d
		}
	}
	s = append(s, perfSample{"host", "all disks", "iops", total})
	return s, nil
}

func perfPowerScale(d Device) ([]perfSample, error) {
	c := psClientFor(d)
	var s []perfSample
	keys := map[string][2]string{
		"node.disk.xfers.rate.sum":    {"node", "iops"},
		"node.protostats.smb2.total":  {"node", "smb_ops"},
		"node.protostats.nfs3.total":  {"node", "nfs_ops"},
		"cluster.disk.xfers.rate.sum": {"cluster", "iops"},
	}
	var lastErr error
	for key, sm := range keys {
		var res struct {
			Stats []struct {
				Devid int     `json:"devid"`
				Key   string  `json:"key"`
				Value any     `json:"value"`
				Error *string `json:"error"`
			} `json:"stats"`
		}
		if err := c.getJSON("/platform/1/statistics/current?key="+key+"&devid=all", &res); err != nil {
			lastErr = err
			continue
		}
		for _, st := range res.Stats {
			v, ok := st.Value.(float64)
			if !ok || st.Error != nil {
				continue
			}
			k := "cluster"
			if sm[0] == "node" {
				k = "node " + strconv.Itoa(st.Devid)
			}
			s = append(s, perfSample{sm[0], k, sm[1], v})
		}
	}
	if len(s) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return s, nil
}

// perfCollector samples every device once a minute.
func (a *App) perfCollector() {
	for range time.Tick(time.Minute) {
		for _, id := range a.ids(`SELECT id FROM devices WHERE kind IN ('windows','powerscale')`) {
			go func(id int64) {
				d, err := a.device(id)
				if err != nil {
					return
				}
				var s []perfSample
				if d.CollectorID > 0 {
					raw, err := a.runTask(d.CollectorID, "perf", map[string]any{"device": d.wire()}, 50*time.Second)
					if err != nil {
						return
					}
					json.Unmarshal(raw, &s)
				} else if s, err = collectPerf(d); err != nil {
					return
				}
				ts := now() - now()%60
				a.wmu.Lock()
				tx, err := a.st.db.Begin()
				if err == nil {
					for _, x := range s {
						tx.Exec(`INSERT INTO perf_samples(ts,device_id,scope,key,metric,value) VALUES(?,?,?,?,?,?)`, ts, id, x.Scope, x.Key, x.Metric, x.Value)
					}
					tx.Commit()
				}
				a.wmu.Unlock()
			}(id)
		}
		if time.Now().Minute() == 0 {
			a.st.db.Exec(`DELETE FROM perf_samples WHERE ts < ?`, now()-14*86400)
		}
	}
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64{}, v...)
	sort.Float64s(s)
	return s[len(s)/2]
}

type seriesOut struct {
	Scope     string       `json:"scope"`
	Key       string       `json:"key"`
	Metric    string       `json:"metric"`
	Points    [][2]float64 `json:"points"` // [ts, value], last 24h
	Current   float64      `json:"current"`
	Baseline  float64      `json:"baseline"`
	Peak      float64      `json:"peak"`
	Anomalies []int64      `json:"anomalies"`
	Shift     *levelShift  `json:"shift,omitempty"`
}

type levelShift struct {
	At     int64   `json:"at"`
	Before float64 `json:"before"`
	After  float64 `json:"after"`
}

func (a *App) iopsReport(w http.ResponseWriter, r *http.Request) {
	dev := qInt64(r, "device")
	if dev == 0 {
		dev = func() int64 {
			ids := a.ids(`SELECT device_id FROM perf_samples GROUP BY device_id ORDER BY COUNT(*) DESC LIMIT 1`)
			if len(ids) > 0 {
				return ids[0]
			}
			return 0
		}()
	}
	since := now() - 7*86400
	rows, err := a.st.db.Query(`SELECT ts, scope, key, metric, value FROM perf_samples WHERE device_id=? AND ts >= ? ORDER BY ts`, dev, since)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	type k3 struct{ scope, key, metric string }
	hist := map[k3][][2]float64{}
	for rows.Next() {
		var ts int64
		var s, k, m string
		var v float64
		rows.Scan(&ts, &s, &k, &m, &v)
		hist[k3{s, k, m}] = append(hist[k3{s, k, m}], [2]float64{float64(ts), v})
	}
	rows.Close()
	cut := float64(now() - 86400)
	var out []seriesOut
	for key, pts := range hist {
		so := seriesOut{Scope: key.scope, Key: key.key, Metric: key.metric}
		// Baseline per hour-of-day from the whole week, robust to spikes.
		byHour := map[int][]float64{}
		for _, p := range pts {
			byHour[time.Unix(int64(p[0]), 0).Hour()] = append(byHour[time.Unix(int64(p[0]), 0).Hour()], p[1])
		}
		type hb struct{ med, mad float64 }
		base := map[int]hb{}
		for h, v := range byHour {
			m := median(v)
			dev := make([]float64, len(v))
			for i, x := range v {
				dev[i] = math.Abs(x - m)
			}
			base[h] = hb{m, median(dev)}
		}
		var recent []float64
		for _, p := range pts {
			if p[0] < cut {
				continue
			}
			so.Points = append(so.Points, p)
			recent = append(recent, p[1])
			if p[1] > so.Peak {
				so.Peak = p[1]
			}
			b := base[time.Unix(int64(p[0]), 0).Hour()]
			scale := math.Max(1.4826*b.mad, math.Max(1, b.med*0.1))
			if (p[1]-b.med)/scale > 4 && len(pts) > 120 {
				so.Anomalies = append(so.Anomalies, int64(p[0]))
			}
		}
		if len(so.Points) == 0 {
			continue
		}
		so.Current = so.Points[len(so.Points)-1][1]
		so.Baseline = base[time.Now().Hour()].med
		// Level shift: best split of the last 6 hours by difference of means.
		n := len(recent)
		if n > 60 {
			win := recent[max(0, n-360):]
			bestD, bestI := 0.0, -1
			for i := 15; i < len(win)-15; i++ {
				l, rr := mean(win[:i]), mean(win[i:])
				if d := math.Abs(rr - l); d > bestD {
					bestD, bestI = d, i
				}
			}
			if bestI > 0 {
				l, rr := mean(win[:bestI]), mean(win[bestI:])
				if (rr > 2*l || rr < l/2) && bestD > 20 {
					so.Shift = &levelShift{At: int64(so.Points[len(so.Points)-len(win)+bestI][0]), Before: l, After: rr}
				}
			}
		}
		out = append(out, so)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return out[i].Peak > out[j].Peak
	})
	// Most-contended files and busiest clients from the audit stream (last hour).
	files := a.queryRows(`SELECT path, SUM(count) c, COUNT(DISTINCT username), MAX(ts) FROM audit WHERE device_id=? AND ts >= ? GROUP BY path ORDER BY c DESC LIMIT 25`, dev, now()-3600)
	clients := a.queryRows(`SELECT CASE WHEN client='' THEN username ELSE client END k, SUM(count) c, COUNT(DISTINCT path) FROM audit WHERE device_id=? AND ts >= ? GROUP BY k ORDER BY c DESC LIMIT 15`, dev, now()-3600)
	devs := a.queryRows(`SELECT d.id, d.name, d.kind, COUNT(p.ts) FROM devices d LEFT JOIN perf_samples p ON p.device_id=d.id AND p.ts >= ? GROUP BY d.id ORDER BY d.name`, now()-3600)
	if out == nil {
		out = []seriesOut{}
	}
	writeJSON(w, map[string]any{"device": dev, "series": out, "files": files, "clients": clients, "devices": devs})
}

func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	var s float64
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}
