package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Minimal S3 client (AWS Signature V4) for Dell ObjectScale/ECS, AWS S3, MinIO and
// other S3-compatible stores. Device: Host = endpoint URL, Username = access key,
// Secret = secret key, Options = {"region":"us-east-1","path_style":true}.

type s3Client struct {
	endpoint  *url.URL
	access    string
	secret    string
	region    string
	pathStyle bool
	hc        *http.Client
	bulk      *http.Client // transfers: no short timeout
}

func newS3Client(d Device) (*s3Client, error) {
	ep := d.Host
	if !strings.Contains(ep, "://") {
		ep = "https://" + ep
	}
	u, err := url.Parse(strings.TrimRight(ep, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("S3 endpoint %q is not a URL", d.Host)
	}
	region := optStr(d.Options, "region")
	if region == "" {
		region = "us-east-1"
	}
	// ObjectScale/ECS and most on-prem stores want path-style; default to it unless told otherwise.
	pathStyle := true
	if strings.Contains(d.Options, `"path_style":false`) {
		pathStyle = false
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: d.Insecure}, MaxIdleConnsPerHost: 32}
	return &s3Client{endpoint: u, access: d.Username, secret: d.Secret, region: region, pathStyle: pathStyle,
		hc: &http.Client{Timeout: 2 * time.Minute, Transport: tr}, bulk: &http.Client{Timeout: 6 * time.Hour, Transport: tr}}, nil
}

func hmacSHA(key []byte, s string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return m.Sum(nil)
}

func sha256hex(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// s3Escape encodes per the SigV4 rules (RFC 3986 unreserved kept).
func s3Escape(s string, keepSlash bool) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' || (keepSlash && c == '/') {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// do signs and sends one request. bucket may be empty (service-level calls).
func (c *s3Client) do(method, bucket, key string, query url.Values, hdr map[string]string) (*http.Response, error) {
	req, err := c.signed(method, bucket, key, query, hdr, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	return c.hc.Do(req)
}

// signed builds a SigV4-signed request for the given instant (separate from do so the
// signature can be checked against AWS's published examples).
func (c *s3Client) signed(method, bucket, key string, query url.Values, hdr map[string]string, t time.Time) (*http.Request, error) {
	host := c.endpoint.Host
	p := "/"
	if bucket != "" {
		if c.pathStyle {
			p = "/" + bucket + "/" + key
		} else {
			host = bucket + "." + host
			p = "/" + key
		}
	}
	canonPath := s3Escape(p, true)
	// Canonical query: sorted keys, each key/value escaped.
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var qs []string
	for _, k := range keys {
		for _, v := range query[k] {
			qs = append(qs, s3Escape(k, false)+"="+s3Escape(v, false))
		}
	}
	canonQuery := strings.Join(qs, "&")
	amzDate := t.Format("20060102T150405Z")
	day := t.Format("20060102")
	payloadHash := sha256hex(nil)
	headers := map[string]string{"host": host, "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash}
	for k, v := range hdr {
		headers[strings.ToLower(k)] = v
	}
	payloadHash = headers["x-amz-content-sha256"] // uploads sign as UNSIGNED-PAYLOAD
	hk := make([]string, 0, len(headers))
	for k := range headers {
		hk = append(hk, k)
	}
	sort.Strings(hk)
	var ch strings.Builder
	for _, k := range hk {
		ch.WriteString(k + ":" + strings.TrimSpace(headers[k]) + "\n")
	}
	signed := strings.Join(hk, ";")
	creq := strings.Join([]string{method, canonPath, canonQuery, ch.String(), signed, payloadHash}, "\n")
	scope := day + "/" + c.region + "/s3/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256hex([]byte(creq))
	k := hmacSHA([]byte("AWS4"+c.secret), day)
	k = hmacSHA(k, c.region)
	k = hmacSHA(k, "s3")
	k = hmacSHA(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA(k, sts))

	u := c.endpoint.Scheme + "://" + host + canonPath
	if canonQuery != "" {
		u += "?" + canonQuery
	}
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		if k != "host" {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", c.access, scope, signed, sig))
	return req, nil
}

// doBody sends a request with a streamed body. The payload is not hashed into the
// signature (UNSIGNED-PAYLOAD), which S3 accepts over HTTPS and which keeps uploads streaming.
func (c *s3Client) doBody(method, bucket, key string, query url.Values, hdr map[string]string, body io.Reader, size int64) (*http.Response, error) {
	h := map[string]string{"x-amz-content-sha256": "UNSIGNED-PAYLOAD"}
	for k, v := range hdr {
		h[k] = v
	}
	req, err := c.signed(method, bucket, key, query, h, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Body = io.NopCloser(body)
		req.ContentLength = size
		if size == 0 {
			req.Body = http.NoBody
		}
	}
	return c.bulk.Do(req)
}

func s3Err(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	var e struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	xml.Unmarshal(b, &e)
	if e.Code != "" {
		return fmt.Errorf("S3 %s: %s", e.Code, e.Message)
	}
	return fmt.Errorf("S3 HTTP %d", resp.StatusCode)
}

func (c *s3Client) buckets() ([]DiscoveredShare, error) {
	resp, err := c.do("GET", "", "", nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, s3Err(resp)
	}
	var out struct {
		Buckets []struct {
			Name         string `xml:"Name"`
			CreationDate string `xml:"CreationDate"`
		} `xml:"Buckets>Bucket"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	var list []DiscoveredShare
	for _, b := range out.Buckets {
		list = append(list, DiscoveredShare{Name: b.Name, Path: b.Name, Comment: "bucket created " + strings.SplitN(b.CreationDate, "T", 2)[0]})
	}
	return list, nil
}

type s3ListPage struct {
	Contents []struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int64  `xml:"Size"`
		Owner        struct {
			DisplayName string `xml:"DisplayName"`
			ID          string `xml:"ID"`
		} `xml:"Owner"`
	} `xml:"Contents"`
	CommonPrefixes []struct {
		Prefix string `xml:"Prefix"`
	} `xml:"CommonPrefixes"`
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
}

// s3Lister walks one bucket (optionally under a prefix) with delimiter "/", so
// prefixes appear as folders exactly like a file share.
type s3Lister struct {
	c      *s3Client
	bucket string
	base   string // prefix inside the bucket, "" or "a/b/"
}

func newS3Lister(d Device, sharePath string) (Lister, error) {
	c, err := newS3Client(d)
	if err != nil {
		return nil, err
	}
	bucket, prefix, _ := strings.Cut(strings.Trim(sharePath, "/"), "/")
	if prefix != "" {
		prefix += "/"
	}
	return &s3Lister{c: c, bucket: bucket, base: prefix}, nil
}

func (l *s3Lister) Parallelism() int       { return 16 }
func (l *s3Lister) DirOwner(string) string { return "" }

func (l *s3Lister) prefixFor(rel string) string {
	p := l.base + strings.TrimPrefix(rel, "/")
	if p != "" && !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}

func (l *s3Lister) List(rel string) ([]Entry, error) {
	prefix := l.prefixFor(rel)
	var out []Entry
	token := ""
	for {
		q := url.Values{"list-type": {"2"}, "delimiter": {"/"}, "prefix": {prefix}, "fetch-owner": {"true"}, "max-keys": {"1000"}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := l.c.do("GET", l.bucket, "", q, nil)
		if err != nil {
			return out, err
		}
		if resp.StatusCode >= 300 {
			err := s3Err(resp)
			resp.Body.Close()
			return out, err
		}
		var page s3ListPage
		err = xml.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return out, err
		}
		for _, cp := range page.CommonPrefixes {
			name := strings.TrimSuffix(strings.TrimPrefix(cp.Prefix, prefix), "/")
			if name != "" {
				out = append(out, Entry{Name: name, IsDir: true})
			}
		}
		for _, o := range page.Contents {
			name := strings.TrimPrefix(o.Key, prefix)
			if name == "" || strings.HasSuffix(name, "/") {
				continue // folder marker object
			}
			t, _ := time.Parse(time.RFC3339, o.LastModified)
			owner := o.Owner.DisplayName
			if owner == "" {
				owner = o.Owner.ID
			}
			out = append(out, Entry{Name: name, Size: o.Size, Mtime: t.Unix(), Atime: t.Unix(), Ctime: t.Unix(),
				ETag: strings.Trim(o.ETag, `"`), Owner: owner})
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			return out, nil
		}
		token = page.NextContinuationToken
	}
}

func (l *s3Lister) key(rel string) string { return l.base + strings.TrimPrefix(rel, "/") }

func (l *s3Lister) exists(rel string) bool {
	resp, err := l.c.do("HEAD", l.bucket, l.key(rel), nil, nil)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

func (l *s3Lister) remove(rel string) error {
	resp, err := l.c.do("DELETE", l.bucket, l.key(rel), nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return s3Err(resp)
	}
	return nil
}

// copyTo copies an object server-side to "bucket/prefix/..." (target root) + rel.
func (l *s3Lister) copyTo(rel, target string) (string, error) {
	tb, tp, _ := strings.Cut(strings.Trim(target, "/"), "/")
	if tb == "" {
		return "", fmt.Errorf("S3 target must be bucket/prefix")
	}
	dstKey := strings.Trim(tp+"/"+strings.TrimPrefix(rel, "/"), "/")
	return tb + "/" + dstKey, l.copyKey(rel, tb, dstKey)
}

// copyKey server-side copies one object to an exact bucket/key. Never overwrites.
func (l *s3Lister) copyKey(rel, bucket, dstKey string) error {
	if head, err := l.c.do("HEAD", bucket, dstKey, nil, nil); err == nil {
		head.Body.Close()
		if head.StatusCode == 200 {
			return fmt.Errorf("target %s/%s already exists, not overwritten", bucket, dstKey)
		}
	}
	src := "/" + l.bucket + "/" + s3Escape(l.key(rel), true)
	resp, err := l.c.do("PUT", bucket, dstKey, nil, map[string]string{"x-amz-copy-source": src})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return s3Err(resp)
	}
	return nil
}

// get streams an object (optionally a byte range) for the file viewer.
func (l *s3Lister) get(rel, rng string) (*http.Response, error) {
	h := map[string]string{}
	if rng != "" {
		h["range"] = rng
	}
	return l.c.do("GET", l.bucket, l.key(rel), nil, h)
}

func s3Inventory(d Device) map[string]any {
	c, err := newS3Client(d)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	b, err := c.buckets()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return map[string]any{"model": "S3 object storage", "os": c.endpoint.Host, "buckets": len(b), "node_count": 0}
}
