package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Migration copy engine. A source and a target are each one of: a local or UNC
// folder (Windows, Linux), a PowerScale path (RAN), or an S3 bucket/prefix. Copying
// never deletes anything and never touches the source; the target is only
// overwritten when the migration's conflict policy says so.

type mStat struct {
	Exists bool
	Size   int64
	Mtime  int64
}

type mEnd interface {
	Stat(rel string) (mStat, error)
	Open(rel string) (io.ReadCloser, error)
	Put(rel string, r io.Reader, size, mtime int64) error
	KeepsMtime() bool
}

func openEnd(d Device, root string) (mEnd, error) {
	switch d.Kind {
	case "powerscale":
		return &psEnd{c: psClientFor(d), root: "/" + strings.Trim(root, "/")}, nil
	case "s3":
		l, err := newS3Lister(d, root)
		if err != nil {
			return nil, err
		}
		sl := l.(*s3Lister)
		if sl.bucket == "" {
			return nil, errors.New("an S3 target is bucket or bucket/prefix")
		}
		return &s3End{l: sl}, nil
	case "windows":
		if strings.HasPrefix(root, `\\`) {
			if err := connectSMB(root, d.Username, d.Secret); err != nil {
				return nil, err
			}
		}
		if strings.TrimSpace(root) == "" {
			return nil, errors.New("no folder given")
		}
		return &fsEnd{root: filepath.Clean(root)}, nil
	}
	return nil, fmt.Errorf("unknown device kind %q", d.Kind)
}

// ---- local and UNC folders ----

type fsEnd struct{ root string }

func (e *fsEnd) abs(rel string) string {
	return longPath(filepath.Join(e.root, filepath.FromSlash(strings.TrimPrefix(rel, "/"))))
}
func (e *fsEnd) KeepsMtime() bool { return true }

func (e *fsEnd) Stat(rel string) (mStat, error) {
	fi, err := os.Lstat(e.abs(rel))
	if errors.Is(err, os.ErrNotExist) {
		return mStat{}, nil
	}
	if err != nil {
		return mStat{}, err
	}
	if fi.IsDir() {
		return mStat{}, errors.New("a folder with this name exists at the target")
	}
	return mStat{Exists: true, Size: fi.Size(), Mtime: fi.ModTime().Unix()}, nil
}

func (e *fsEnd) Open(rel string) (io.ReadCloser, error) { return os.Open(e.abs(rel)) }

func (e *fsEnd) Put(rel string, r io.Reader, size, mtime int64) error {
	dst := e.abs(rel)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	// Write next to the target and rename into place, so a failed copy never leaves a
	// half-written file under the real name.
	tmp := dst + ".stratum-partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	t := time.Unix(mtime, 0)
	return os.Chtimes(dst, t, t)
}

// ---- PowerScale (RAN) ----

type psEnd struct {
	c    *psClient
	root string
}

func (e *psEnd) abs(rel string) string { return path.Join(e.root, rel) }
func (e *psEnd) KeepsMtime() bool      { return false } // RAN cannot set the modified time

func (e *psEnd) Stat(rel string) (mStat, error) {
	resp, err := e.c.do("HEAD", nsPath(e.abs(rel)), nil, nil)
	if err != nil {
		return mStat{}, err
	}
	resp.Body.Close()
	if resp.StatusCode == 404 {
		return mStat{}, nil
	}
	if resp.StatusCode >= 300 {
		return mStat{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.Header.Get("x-isi-ifs-target-type") == "container" {
		return mStat{}, errors.New("a folder with this name exists at the target")
	}
	return mStat{Exists: true, Size: resp.ContentLength, Mtime: parseHTTPTime(resp.Header.Get("Last-Modified"))}, nil
}

func (e *psEnd) Open(rel string) (io.ReadCloser, error) {
	resp, err := e.c.doSized("GET", nsPath(e.abs(rel)), nil, nil, 0)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp.Body, nil
}

func (e *psEnd) Put(rel string, r io.Reader, size, mtime int64) error {
	if err := e.c.ranMkdir(path.Dir(e.abs(rel))); err != nil {
		return err
	}
	return e.c.expect(e.c.doSized("PUT", nsPath(e.abs(rel))+"?overwrite=true", map[string]string{"x-isi-ifs-target-type": "object", "Content-Type": "application/octet-stream"}, r, size))
}

// ---- S3 and ObjectScale ----

type s3End struct{ l *s3Lister }

func (e *s3End) KeepsMtime() bool { return true } // kept as x-amz-meta-mtime

func (e *s3End) Stat(rel string) (mStat, error) {
	resp, err := e.l.c.do("HEAD", e.l.bucket, e.l.key(rel), nil, nil)
	if err != nil {
		return mStat{}, err
	}
	resp.Body.Close()
	if resp.StatusCode == 404 {
		return mStat{}, nil
	}
	if resp.StatusCode >= 300 {
		return mStat{}, fmt.Errorf("S3 HTTP %d", resp.StatusCode)
	}
	st := mStat{Exists: true, Size: resp.ContentLength, Mtime: parseHTTPTime(resp.Header.Get("Last-Modified"))}
	if m, err := strconv.ParseInt(resp.Header.Get("x-amz-meta-mtime"), 10, 64); err == nil {
		st.Mtime = m
	}
	return st, nil
}

func (e *s3End) Open(rel string) (io.ReadCloser, error) {
	resp, err := e.l.c.doBody("GET", e.l.bucket, e.l.key(rel), nil, nil, nil, 0)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		return nil, s3Err(resp)
	}
	return resp.Body, nil
}

// s3PartSize is the multipart chunk; anything larger goes in parts (S3 caps a single PUT at 5 GB).
var s3PartSize int64 = 64 << 20

func (e *s3End) Put(rel string, r io.Reader, size, mtime int64) error {
	key := e.l.key(rel)
	meta := map[string]string{"x-amz-meta-mtime": strconv.FormatInt(mtime, 10)}
	if size <= s3PartSize {
		resp, err := e.l.c.doBody("PUT", e.l.bucket, key, nil, meta, r, size)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return s3Err(resp)
		}
		return nil
	}
	part := s3PartSize
	if size/part > 9000 { // S3 allows 10,000 parts
		part = size/9000 + 1
	}
	resp, err := e.l.c.doBody("POST", e.l.bucket, key, url.Values{"uploads": {""}}, meta, bytes.NewReader(nil), 0)
	if err != nil {
		return err
	}
	var init struct {
		UploadID string `xml:"UploadId"`
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		return s3Err(resp)
	}
	xml.NewDecoder(resp.Body).Decode(&init)
	resp.Body.Close()
	if init.UploadID == "" {
		return errors.New("S3 did not start a multipart upload")
	}
	abort := func() {
		if r, err := e.l.c.doBody("DELETE", e.l.bucket, key, url.Values{"uploadId": {init.UploadID}}, nil, nil, 0); err == nil {
			r.Body.Close()
		}
	}
	type done struct {
		XMLName xml.Name `xml:"Part"`
		N       int      `xml:"PartNumber"`
		ETag    string   `xml:"ETag"`
	}
	var parts []done
	buf := make([]byte, part)
	for n, left := 1, size; left > 0; n++ {
		chunk := min(part, left)
		if _, err := io.ReadFull(r, buf[:chunk]); err != nil {
			abort()
			return err
		}
		q := url.Values{"partNumber": {strconv.Itoa(n)}, "uploadId": {init.UploadID}}
		resp, err := e.l.c.doBody("PUT", e.l.bucket, key, q, nil, bytes.NewReader(buf[:chunk]), chunk)
		if err != nil {
			abort()
			return err
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			abort()
			return fmt.Errorf("S3 part %d: HTTP %d", n, resp.StatusCode)
		}
		parts = append(parts, done{N: n, ETag: resp.Header.Get("ETag")})
		left -= chunk
	}
	body, _ := xml.Marshal(struct {
		XMLName xml.Name `xml:"CompleteMultipartUpload"`
		Parts   []done
	}{Parts: parts})
	resp, err = e.l.c.doBody("POST", e.l.bucket, key, url.Values{"uploadId": {init.UploadID}}, nil, bytes.NewReader(body), int64(len(body)))
	if err != nil {
		abort()
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 || bytes.Contains(b, []byte("<Error>")) { // S3 can report errors inside a 200
		abort()
		return fmt.Errorf("S3 could not complete the upload: %s", strings.TrimSpace(string(b)))
	}
	return nil
}

// ---- copying ----

type mOpts struct {
	Conflict string `json:"conflict"` // skip | newer | overwrite
	Verify   string `json:"verify"`   // checksum | size
	Dry      bool   `json:"dry"`
}

type mResult struct {
	Rel    string `json:"rel"`
	Result string `json:"result"` // copied | skipped | conflict | failed | would-copy | would-overwrite
	Bytes  int64  `json:"bytes"`
	Detail string `json:"detail,omitempty"`
}

type countingHash struct {
	n int64
	h hashWriter
}

type hashWriter interface {
	io.Writer
	Sum([]byte) []byte
}

func (c *countingHash) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return c.h.Write(p)
}

func hashOf(e mEnd, rel string) (string, int64, error) {
	r, err := e.Open(rel)
	if err != nil {
		return "", 0, err
	}
	defer r.Close()
	h := sha256.New()
	n, err := io.Copy(h, r)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

// copyOne copies one file. It reports what it did; it never returns an error.
func copyOne(src, dst mEnd, rel string, o mOpts) mResult {
	res := mResult{Rel: rel}
	fail := func(format string, a ...any) mResult {
		res.Result, res.Detail = "failed", fmt.Sprintf(format, a...)
		return res
	}
	ss, err := src.Stat(rel)
	if err != nil {
		return fail("reading the source: %v", err)
	}
	if !ss.Exists {
		return fail("the source file no longer exists (the index is older than the storage)")
	}
	ds, err := dst.Stat(rel)
	if err != nil {
		return fail("checking the target: %v", err)
	}
	overwrite := false
	if ds.Exists {
		sameTime := !dst.KeepsMtime() || !src.KeepsMtime() || abs64(ds.Mtime-ss.Mtime) <= 2
		if ds.Size == ss.Size && sameTime {
			res.Result, res.Detail = "skipped", "already at the target, same size and date"
			return res
		}
		switch o.Conflict {
		case "overwrite":
			overwrite = true
		case "newer":
			if ss.Mtime > ds.Mtime {
				overwrite = true
			}
		}
		if !overwrite {
			res.Result = "conflict"
			res.Detail = fmt.Sprintf("a different file is at the target (%s, %s); left as it is", fmtB(ds.Size), time.Unix(ds.Mtime, 0).UTC().Format("2006-01-02"))
			return res
		}
	}
	if o.Dry {
		res.Result, res.Bytes = "would-copy", ss.Size
		if overwrite {
			res.Result = "would-overwrite"
		}
		return res
	}
	r, err := src.Open(rel)
	if err != nil {
		return fail("opening the source: %v", err)
	}
	ch := &countingHash{h: sha256.New()}
	err = dst.Put(rel, io.TeeReader(r, ch), ss.Size, ss.Mtime)
	r.Close()
	if err != nil {
		return fail("writing the target: %v", err)
	}
	if ch.n != ss.Size {
		return fail("the source changed while it was copied (%d of %d bytes read); copy it again", ch.n, ss.Size)
	}
	srcHash := hex.EncodeToString(ch.h.Sum(nil))
	if o.Verify == "size" {
		ds, err := dst.Stat(rel)
		if err != nil || ds.Size != ss.Size {
			return fail("verification: the target has %d bytes, the source %d", ds.Size, ss.Size)
		}
		res.Detail = "verified by size"
	} else {
		got, n, err := hashOf(dst, rel)
		if err != nil {
			return fail("verification: reading the target back: %v", err)
		}
		if got != srcHash || n != ss.Size {
			return fail("verification failed: the target's checksum differs from the source")
		}
		res.Detail = "verified sha256 " + srcHash[:16]
	}
	res.Result, res.Bytes = "copied", ss.Size
	if overwrite {
		res.Detail = "replaced an older or different target file; " + res.Detail
	}
	return res
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

type mPayload struct {
	Src     deviceWire `json:"src"`
	SrcRoot string     `json:"src_root"`
	Dst     deviceWire `json:"dst"`
	DstRoot string     `json:"dst_root"`
	Rels    []string   `json:"rels"`
	Opts    mOpts      `json:"opts"`
}

// migrateBatch copies a list of files with a few in flight at once. It runs on the
// server or on a collector.
func migrateBatch(pl mPayload) ([]mResult, error) {
	src, err := openEnd(pl.Src.dev(), pl.SrcRoot)
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	dst, err := openEnd(pl.Dst.dev(), pl.DstRoot)
	if err != nil {
		return nil, fmt.Errorf("target: %w", err)
	}
	out := make([]mResult, len(pl.Rels))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				out[i] = copyOne(src, dst, pl.Rels[i], pl.Opts)
			}
		}()
	}
	for i := range pl.Rels {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out, nil
}

// freeSpace reports free bytes at a target root, or -1 when the storage cannot say.
func freeSpace(d Device, root string) (int64, string) {
	switch d.Kind {
	case "windows":
		p := filepath.Clean(root)
		for {
			if _, err := os.Stat(p); err == nil {
				break
			}
			parent := filepath.Dir(p)
			if parent == p {
				break
			}
			p = parent
		}
		_, free, err := diskSpace(p)
		if err != nil {
			return -1, err.Error()
		}
		return int64(free), ""
	case "powerscale":
		inv, err := psClientFor(d).psInventory()
		if err != nil {
			return -1, err.Error()
		}
		raw, _ := inv["raw_bytes"].(int64)
		used, _ := inv["used_bytes"].(int64)
		if raw == 0 {
			return -1, "the cluster did not report capacity"
		}
		return raw - used, "raw cluster capacity before protection overhead"
	}
	return -1, "object storage has no fixed capacity"
}
