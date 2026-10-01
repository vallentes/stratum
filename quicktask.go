package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Interactive collector work (opening a file in the viewer, downloading it)
// never touches SQLite. A remote read used to be queued and answered through
// the tasks table, and while a large scan was publishing its index the writer
// lock held both of those writes for the full 15s busy timeout: every 8 MB
// chunk took 30s or more, the browser gave up mid-stream and the download
// failed with a protocol error.
//
// Quick tasks live in memory instead, carry negative IDs so they can never be
// confused with a row in the tasks table, and go out on the collector's next
// poll ahead of anything else. The collector needs no change: it runs the task
// and posts the result to the same URL as always.

type quickResult struct {
	ok     bool
	result json.RawMessage
	err    string
}

type quickQueue struct {
	mu       sync.Mutex
	next     int64
	pending  map[int64][]wireTask // collector id -> tasks not yet handed out
	waiters  map[int64]chan quickResult
	lastSeen map[int64]time.Time // collector id -> last poll, kept in memory
}

var quick = &quickQueue{pending: map[int64][]wireTask{}, waiters: map[int64]chan quickResult{}, lastSeen: map[int64]time.Time{}}

func isQuickKind(kind string) bool { return kind == "read" }

func (q *quickQueue) seen(cid int64) {
	q.mu.Lock()
	q.lastSeen[cid] = time.Now()
	q.mu.Unlock()
}

// take hands a collector its queued quick tasks.
func (q *quickQueue) take(cid int64) []wireTask {
	q.mu.Lock()
	defer q.mu.Unlock()
	t := q.pending[cid]
	delete(q.pending, cid)
	return t
}

// deliver passes a collector's answer to whoever is waiting. False when the
// ID is not a quick task.
func (q *quickQueue) deliver(id int64, r quickResult) bool {
	if id >= 0 {
		return false
	}
	q.mu.Lock()
	ch := q.waiters[id]
	delete(q.waiters, id)
	q.mu.Unlock()
	if ch != nil {
		ch <- r // buffered: never blocks
	}
	return true
}

func (q *quickQueue) run(cid int64, kind string, payload any, timeout time.Duration) (json.RawMessage, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	ch := make(chan quickResult, 1)
	q.mu.Lock()
	q.next--
	id := q.next
	q.waiters[id] = ch
	q.pending[cid] = append(q.pending[cid], wireTask{ID: id, Kind: kind, Payload: b})
	seen := q.lastSeen[cid]
	q.mu.Unlock()

	select {
	case r := <-ch:
		if !r.ok {
			return nil, errors.New(r.err)
		}
		return r.result, nil
	case <-time.After(timeout):
	}
	q.mu.Lock()
	delete(q.waiters, id)
	list := q.pending[cid]
	for i, t := range list {
		if t.ID == id {
			q.pending[cid] = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	q.mu.Unlock()
	if seen.IsZero() || time.Since(seen) > 30*time.Second {
		return nil, fmt.Errorf("the collector for this device is offline or not polling")
	}
	return nil, errors.New("the collector did not answer in time")
}
