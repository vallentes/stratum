package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AuditEvent is one normalized file operation from any audit source.
type AuditEvent struct {
	TS       int64  `json:"ts"`
	DeviceID int64  `json:"device_id"`
	User     string `json:"user"`
	Op       string `json:"op"` // create modify delete rename read other
	Path     string `json:"path"`
	Proto    string `json:"proto"`
	Client   string `json:"client"`
	Bytes    int64  `json:"bytes"`
}

// auditAgg collapses repeating I/O into 60-second windows before it reaches the
// database, so counts are real operations rather than raw log lines.
type auditAgg struct {
	mu  sync.Mutex
	app *App
	m   map[string]*aggRow
}

type aggRow struct {
	AuditEvent
	count int64
}

func newAuditAgg(a *App) *auditAgg {
	g := &auditAgg{app: a, m: map[string]*aggRow{}}
	go func() {
		for range time.Tick(15 * time.Second) {
			g.flush(false)
		}
	}()
	return g
}

func (g *auditAgg) add(e AuditEvent) {
	if e.TS == 0 {
		e.TS = now()
	}
	g.app.tw.observe(e) // ransomware early warning sees every event before aggregation
	win := e.TS - e.TS%60
	key := strconv.FormatInt(win, 10) + "|" + strconv.FormatInt(e.DeviceID, 10) + "|" + e.User + "|" + e.Op + "|" + e.Path
	g.mu.Lock()
	if r, ok := g.m[key]; ok {
		r.count++
		r.Bytes += e.Bytes
	} else {
		e.TS = win
		g.m[key] = &aggRow{AuditEvent: e, count: 1}
	}
	g.mu.Unlock()
}

// flush writes closed windows (or everything when all is true).
func (g *auditAgg) flush(all bool) {
	cut := now() - now()%60
	g.mu.Lock()
	var out []*aggRow
	for k, r := range g.m {
		if all || r.TS < cut {
			out = append(out, r)
			delete(g.m, k)
		}
	}
	g.mu.Unlock()
	if len(out) == 0 {
		return
	}
	tx, err := g.app.st.db.Begin()
	if err != nil {
		return
	}
	st, _ := tx.Prepare(`INSERT INTO audit(ts,device_id,username,op,path,proto,client,bytes,count) VALUES(?,?,?,?,?,?,?,?,?)`)
	for _, r := range out {
		st.Exec(r.TS, r.DeviceID, r.User, r.Op, r.Path, r.Proto, r.Client, r.Bytes, r.count)
	}
	tx.Commit()
}

func normOp(eventType, detail string) string {
	e := strings.ToLower(eventType + " " + detail)
	switch {
	case strings.Contains(e, "rename"):
		return "rename"
	case strings.Contains(e, "delete"), strings.Contains(e, "unlink"), strings.Contains(e, "rmdir"):
		return "delete"
	case strings.Contains(e, "write"), strings.Contains(e, "modif"), strings.Contains(e, "change"), strings.Contains(e, "set-security"), strings.Contains(e, "setattr"), strings.Contains(e, "truncate"):
		return "modify"
	case strings.Contains(e, "open"), strings.Contains(e, "read"), strings.Contains(e, "get-security"):
		return "read"
	case strings.Contains(e, "create"), strings.Contains(e, "mkdir"):
		return "create"
	}
	return "other"
}

var kvRe = regexp.MustCompile(`(\w+)\s*[:=]\s*("[^"]*"|[^,|]+)`)

// parseAuditLine accepts a OneFS protocol-audit syslog line. OneFS emits either a
// JSON payload (CEE-style fields) or "key: value" pairs depending on version, so
// both shapes are handled; unknown lines return ok=false.
func parseAuditLine(line string) (AuditEvent, bool) {
	var e AuditEvent
	f := map[string]string{}
	if i := strings.IndexByte(line, '{'); i >= 0 {
		var m map[string]any
		if json.Unmarshal([]byte(line[i:]), &m) == nil {
			for k, v := range m {
				switch x := v.(type) {
				case string:
					f[strings.ToLower(k)] = x
				case float64:
					f[strings.ToLower(k)] = strconv.FormatFloat(x, 'f', -1, 64)
				case bool:
					f[strings.ToLower(k)] = strconv.FormatBool(x)
				}
			}
		}
	}
	if len(f) == 0 {
		for _, m := range kvRe.FindAllStringSubmatch(line, -1) {
			f[strings.ToLower(m[1])] = strings.Trim(strings.TrimSpace(m[2]), `"`)
		}
	}
	pick := func(keys ...string) string {
		for _, k := range keys {
			if v := f[k]; v != "" {
				return v
			}
		}
		return ""
	}
	e.Path = strings.ReplaceAll(pick("filename", "path", "objectname", "file"), `\`, "/")
	et := pick("eventtype", "event", "operation", "op")
	if e.Path == "" || et == "" {
		return e, false
	}
	e.Op = normOp(et, pick("detailtype", "detail", "createresult"))
	e.User = pick("username", "user", "usersid", "userid", "uid")
	e.Proto = pick("protocol", "proto")
	e.Client = pick("clientip", "client", "clientaddress")
	b, _ := strconv.ParseInt(pick("byteswritten", "bytesread", "bytes"), 10, 64)
	e.Bytes = b
	if t := pick("timestamp", "time"); t != "" {
		if ts, err := time.Parse(time.RFC3339, t); err == nil {
			e.TS = ts.Unix()
		} else if n, err := strconv.ParseInt(t, 10, 64); err == nil && n > 1e9 {
			if n > 1e12 {
				n /= 1000
			}
			e.TS = n
		}
	}
	return e, true
}

// deviceForIP maps a syslog sender to a registered device by resolving device hosts.
func (a *App) deviceForIP(ip string) int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ipCache == nil || time.Since(a.ipCacheAt) > 5*time.Minute {
		a.ipCache = map[string]int64{}
		a.ipCacheAt = time.Now()
		rows, err := a.st.db.Query(`SELECT id,host FROM devices`)
		if err == nil {
			for rows.Next() {
				var id int64
				var h string
				rows.Scan(&id, &h)
				h = strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
				h, _, _ = strings.Cut(h, ":")
				if addrs, err := net.LookupHost(h); err == nil {
					for _, ad := range addrs {
						a.ipCache[ad] = id
					}
				}
			}
			rows.Close()
		}
	}
	return a.ipCache[ip]
}

// syslogListen receives OneFS audit forwarding on UDP and TCP.
func syslogListen(addr string, handle func(line, ip string)) {
	if addr == "" {
		return
	}
	go func() {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			log.Printf("audit syslog udp %s: %v", addr, err)
			return
		}
		log.Printf("audit syslog listening on udp %s", addr)
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				continue
			}
			ip, _, _ := net.SplitHostPort(from.String())
			handle(string(buf[:n]), ip)
		}
	}()
	go func() {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("audit syslog tcp %s: %v", addr, err)
			return
		}
		log.Printf("audit syslog listening on tcp %s", addr)
		for {
			c, err := ln.Accept()
			if err != nil {
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
				sc := bufio.NewScanner(c)
				sc.Buffer(make([]byte, 64*1024), 1024*1024)
				for sc.Scan() {
					handle(sc.Text(), ip)
				}
			}(c)
		}
	}()
}

func (a *App) ingestLine(line, ip string) {
	e, ok := parseAuditLine(line)
	if !ok {
		a.auditDropped.Add(1)
		return
	}
	e.DeviceID = a.deviceForIP(ip)
	a.audit.add(e)
}

// localWindowsDevice is the Windows device that is this server itself (not behind a collector).
func (a *App) localWindowsDevice() int64 {
	var id int64
	a.st.db.QueryRow(`SELECT id FROM devices WHERE kind='windows' AND collector_id=0 AND (host='' OR lower(host) IN ('localhost','.','127.0.0.1')) ORDER BY id LIMIT 1`).Scan(&id)
	return id
}
