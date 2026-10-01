package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

// psClient talks to a PowerScale (OneFS) cluster: PAPI (/platform) for inventory and
// share discovery, RAN (/namespace) for the metadata walk. Session auth with CSRF,
// falling back to HTTP basic auth when sessions are disabled.
type psClient struct {
	base      string
	user      string
	pass      string
	hc        *http.Client
	bulk      *http.Client // file transfers: no short timeout
	mu        sync.Mutex
	csrf      string
	session   bool
	triedSess bool
}

func newPSClient(host string, port int, user, pass string, insecure bool) *psClient {
	if port == 0 {
		port = 8080
	}
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure},
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
	}
	base := host
	if !strings.Contains(host, "://") {
		base = fmt.Sprintf("https://%s:%d", host, port)
	}
	return &psClient{base: strings.TrimRight(base, "/"), user: user, pass: pass,
		hc:   &http.Client{Transport: tr, Jar: jar, Timeout: 120 * time.Second},
		bulk: &http.Client{Transport: tr, Jar: jar, Timeout: 6 * time.Hour}}
}

func (c *psClient) login() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.triedSess {
		return
	}
	c.triedSess = true
	body, _ := json.Marshal(map[string]any{"username": c.user, "password": c.pass, "services": []string{"platform", "namespace"}})
	resp, err := c.hc.Post(c.base+"/session/1/session", "application/json", bytes.NewReader(body))
	if err != nil {
		return
	}
	resp.Body.Close()
	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		return
	}
	u, _ := url.Parse(c.base)
	for _, ck := range c.hc.Jar.Cookies(u) {
		if ck.Name == "isicsrf" {
			c.csrf = ck.Value
		}
	}
	c.session = true
}

func (c *psClient) do(method, p string, hdr map[string]string, body io.Reader) (*http.Response, error) {
	c.login()
	req, err := http.NewRequest(method, c.base+p, body)
	if err != nil {
		return nil, err
	}
	if c.session {
		if c.csrf != "" {
			req.Header.Set("X-CSRF-Token", c.csrf)
		}
		req.Header.Set("Referer", c.base)
	} else {
		req.SetBasicAuth(c.user, c.pass)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return c.hc.Do(req)
}

// doSized is do with a streamed body of known length (RAN uploads need Content-Length).
func (c *psClient) doSized(method, p string, hdr map[string]string, body io.Reader, size int64) (*http.Response, error) {
	c.login()
	req, err := http.NewRequest(method, c.base+p, body)
	if err != nil {
		return nil, err
	}
	req.ContentLength = size
	if size == 0 {
		req.Body = http.NoBody
	}
	if c.session {
		if c.csrf != "" {
			req.Header.Set("X-CSRF-Token", c.csrf)
		}
		req.Header.Set("Referer", c.base)
	} else {
		req.SetBasicAuth(c.user, c.pass)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return c.bulk.Do(req)
}

func (c *psClient) getJSON(p string, out any) error {
	resp, err := c.do("GET", p, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("%s: HTTP %d %s", p, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// nsPath converts an /ifs path into the RAN URL path, escaping each segment.
func nsPath(ifsPath string) string {
	parts := strings.Split(strings.Trim(ifsPath, "/"), "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return "/namespace/" + strings.Join(parts, "/")
}

type ranChild struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Size         int64  `json:"size"`
	LastModified string `json:"last_modified"`
	AccessTime   string `json:"access_time"`
	CreateTime   string `json:"create_time"`
	Owner        string `json:"owner"`
}

func parseHTTPTime(s string) int64 {
	if s == "" {
		return 0
	}
	for _, f := range []string{http.TimeFormat, time.RFC1123, time.RFC1123Z, time.RFC3339} {
		if t, err := time.Parse(f, s); err == nil {
			return t.Unix()
		}
	}
	return 0
}

// listDir returns every child of an /ifs directory, following RAN's resume token.
func (c *psClient) listDir(ifsPath string) ([]ranChild, error) {
	var all []ranChild
	resume := ""
	for {
		q := url.Values{}
		q.Set("detail", "name,type,size,last_modified,access_time,create_time,owner")
		q.Set("max-keys", "1000")
		if resume != "" {
			q.Set("resume", resume)
		}
		var page struct {
			Children []ranChild `json:"children"`
			Resume   string     `json:"resume"`
		}
		if err := c.getJSON(nsPath(ifsPath)+"?"+q.Encode(), &page); err != nil {
			return all, err
		}
		all = append(all, page.Children...)
		if page.Resume == "" {
			return all, nil
		}
		resume = page.Resume
	}
}

// psLister walks one share (an /ifs path) through RAN.
type psLister struct {
	c    *psClient
	root string // e.g. /ifs/data/dfs
}

func (l *psLister) abs(rel string) string { return path.Join(l.root, rel) }
func (l *psLister) Parallelism() int      { return 16 }

func (l *psLister) List(rel string) ([]Entry, error) {
	kids, err := l.c.listDir(l.abs(rel))
	out := make([]Entry, 0, len(kids))
	for _, k := range kids {
		e := Entry{Name: k.Name, Size: k.Size, Mtime: parseHTTPTime(k.LastModified),
			Atime: parseHTTPTime(k.AccessTime), Ctime: parseHTTPTime(k.CreateTime)}
		switch k.Type {
		case "container":
			e.IsDir, e.Size = true, 0
		case "object":
		default: // symbolic_link, pipe, socket, ...
			e.Link = k.Type
		}
		if e.Atime == 0 {
			e.Atime = e.Mtime
		}
		if e.Ctime == 0 {
			e.Ctime = e.Mtime
		}
		out = append(out, e)
	}
	return out, err
}

func (l *psLister) DirOwner(rel string) string {
	p, err := l.DirPerms(rel)
	if err != nil {
		return ""
	}
	return p.Owner
}

type psPersona struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

func (p psPersona) label() string {
	if p.Name != "" {
		return p.Name
	}
	return p.ID
}

// DirPerms reads a folder's ACL through RAN (?acl). Folders whose authority is the
// POSIX mode are modelled from the mode bits instead.
func (l *psLister) DirPerms(rel string) (DirPerms, error) {
	var acl struct {
		ACL []struct {
			AccessRights []string  `json:"accessrights"`
			AccessType   string    `json:"accesstype"`
			InheritFlags []string  `json:"inherit_flags"`
			Trustee      psPersona `json:"trustee"`
		} `json:"acl"`
		Authoritative string    `json:"authoritative"`
		Mode          string    `json:"mode"`
		Owner         psPersona `json:"owner"`
		Group         psPersona `json:"group"`
	}
	if err := l.c.getJSON(nsPath(l.abs(rel))+"?acl", &acl); err != nil {
		return DirPerms{}, err
	}
	if acl.Authoritative == "mode" || len(acl.ACL) == 0 {
		var m uint32
		fmt.Sscanf(acl.Mode, "%o", &m)
		return posixPerms(acl.Owner.label(), acl.Group.label(), m&0o777), nil
	}
	out := DirPerms{Owner: acl.Owner.label(), Inheritance: true}
	for _, e := range acl.ACL {
		inherited, inheritOnly := false, false
		for _, f := range e.InheritFlags {
			switch f {
			case "inherited_ace":
				inherited = true
			case "inherit_only":
				inheritOnly = true
			}
		}
		if inheritOnly {
			continue
		}
		sid := strings.TrimPrefix(e.Trustee.ID, "SID:")
		kind := e.Trustee.Type
		if kind == "" {
			kind = "user"
		}
		out.ACEs = append(out.ACEs, ACE{Trustee: e.Trustee.label(), SID: sid, Deny: e.AccessType == "deny", Rights: oneFSRights(e.AccessRights),
			Inherited: inherited, Kind: kind, Orphan: e.Trustee.Name == "" && strings.HasPrefix(sid, "S-1-5-21-")})
	}
	return out, nil
}

// psShares lists SMB shares across every access zone.
func (c *psClient) psShares() ([]DiscoveredShare, error) {
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
	var out []DiscoveredShare
	for _, z := range zones.Zones {
		var sh struct {
			Shares []struct {
				Name        string `json:"name"`
				Path        string `json:"path"`
				Description string `json:"description"`
			} `json:"shares"`
		}
		if err := c.getJSON("/platform/1/protocols/smb/shares?zone="+url.QueryEscape(z.Name), &sh); err != nil {
			if len(out) == 0 && z.Name == "System" {
				return nil, err
			}
			continue
		}
		for _, s := range sh.Shares {
			out = append(out, DiscoveredShare{Name: s.Name, Path: s.Path, Comment: s.Description, Zone: z.Name})
		}
	}
	return out, nil
}

// psInventory is the hardware/config snapshot shown in Device Inventory.
func (c *psClient) psInventory() (map[string]any, error) {
	inv := map[string]any{}
	var id map[string]any
	if err := c.getJSON("/platform/1/cluster/identity", &id); err != nil {
		return nil, err
	}
	inv["name"] = id["name"]
	var cfg struct {
		GUID         string `json:"guid"`
		Name         string `json:"name"`
		OnefsVersion struct {
			Release string `json:"release"`
			Build   string `json:"build"`
		} `json:"onefs_version"`
	}
	if c.getJSON("/platform/1/cluster/config", &cfg) == nil {
		inv["guid"] = cfg.GUID
		inv["os"] = "OneFS " + cfg.OnefsVersion.Release
	}
	var nodes struct {
		Nodes []struct {
			ID       int `json:"id"`
			LNN      int `json:"lnn"`
			Hardware struct {
				Product      string `json:"product"`
				SerialNumber string `json:"serial_number"`
				Model        string `json:"model"`
			} `json:"hardware"`
		} `json:"nodes"`
	}
	if c.getJSON("/platform/3/cluster/nodes", &nodes) == nil {
		var list []map[string]any
		for _, n := range nodes.Nodes {
			list = append(list, map[string]any{"lnn": n.LNN, "model": n.Hardware.Product, "serial": n.Hardware.SerialNumber})
		}
		inv["nodes"] = list
		inv["node_count"] = len(list)
		if len(list) > 0 {
			inv["model"] = list[0]["model"]
		}
	}
	var stats struct {
		Stats []struct {
			Key   string  `json:"key"`
			Value float64 `json:"value"`
		} `json:"stats"`
	}
	if c.getJSON("/platform/1/statistics/current?key=ifs.bytes.total&key=ifs.bytes.used&devid=all", &stats) == nil {
		for _, s := range stats.Stats {
			switch s.Key {
			case "ifs.bytes.total":
				inv["raw_bytes"] = int64(s.Value)
			case "ifs.bytes.used":
				inv["used_bytes"] = int64(s.Value)
			}
		}
	}
	return inv, nil
}

// RAN file operations used by automations.
func (c *psClient) ranDelete(ifsPath string, dir bool) error {
	p := nsPath(ifsPath)
	if dir {
		p += "?recursive=true"
	}
	return c.expect(c.do("DELETE", p, nil, nil))
}

func (c *psClient) ranMove(src, dst string) error {
	return c.expect(c.do("POST", nsPath(src), map[string]string{"x-isi-ifs-set-location": nsPath(dst)}, nil))
}

func (c *psClient) ranCopy(src, dst string) error {
	return c.expect(c.do("PUT", nsPath(dst)+"?merge=false&continue=false", map[string]string{"x-isi-ifs-copy-source": nsPath(src)}, nil))
}

func (c *psClient) ranMkdir(ifsPath string) error {
	return c.expect(c.do("PUT", nsPath(ifsPath)+"?recursive=true", map[string]string{"x-isi-ifs-target-type": "container"}, nil))
}

func (c *psClient) expect(resp *http.Response, err error) error {
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}
