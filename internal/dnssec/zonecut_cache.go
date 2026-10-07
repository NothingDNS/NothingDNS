package dnssec

import (
	"container/list"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// maxZoneCutCacheEntries bounds the cross-response zone-cut cache (F477).
// A variable only so tests can measure the uncached per-response cost; 0
// disables the cache for validators created afterwards.
var maxZoneCutCacheEntries = 4096

// zoneCutCache remembers authenticated answers to "is name a zone cut below
// signer?" (F472's noZoneCutBelowSigner) across responses, so repeated answers
// for deep names under the same signer do not repeat one DS lookup per
// intermediate name (F477). Only results proven by an authenticated DS
// RRset or DS denial are stored, each for the remaining lifetime of the proof
// that established it: the minimum TTL / original TTL of the records in that
// DS response and the earliest RRSIG expiration. Entries are evicted least
// recently used beyond cap. It is safe for concurrent use; a nil cache is a
// disabled cache.
type zoneCutCache struct {
	mu      sync.Mutex
	cap     int
	order   *list.List // front = most recently used; values are *zoneCutEntry
	entries map[string]*list.Element
}

type zoneCutEntry struct {
	key     string
	isCut   bool
	expires time.Time
}

func newZoneCutCache(capacity int) *zoneCutCache {
	return &zoneCutCache{cap: capacity, order: list.New(), entries: make(map[string]*list.Element)}
}

func zoneCutKey(signer, name string) string { return signer + "|" + name }

// get returns the cached result for (signer, name) if it is still live at now.
func (c *zoneCutCache) get(signer, name string, now time.Time) (isCut, ok bool) {
	if c == nil {
		return false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, found := c.entries[zoneCutKey(signer, name)]
	if !found {
		return false, false
	}
	e := el.Value.(*zoneCutEntry)
	if !now.Before(e.expires) {
		c.order.Remove(el)
		delete(c.entries, e.key)
		return false, false
	}
	c.order.MoveToFront(el)
	return e.isCut, true
}

// put stores a proven result for ttl (ignored unless positive).
func (c *zoneCutCache) put(signer, name string, isCut bool, now time.Time, ttl time.Duration) {
	if c == nil || ttl <= 0 || c.cap <= 0 {
		return
	}
	key := zoneCutKey(signer, name)
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, found := c.entries[key]; found {
		e := el.Value.(*zoneCutEntry)
		e.isCut, e.expires = isCut, now.Add(ttl)
		c.order.MoveToFront(el)
		return
	}
	for c.order.Len() >= c.cap {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*zoneCutEntry).key)
	}
	c.entries[key] = c.order.PushFront(&zoneCutEntry{key: key, isCut: isCut, expires: now.Add(ttl)})
}

func (c *zoneCutCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// proofLifetime is how long the proof carried by msg (a DS response) may be
// reused at now: the minimum of every Answer/Authority record's TTL, every
// RRSIG's original TTL and every RRSIG's remaining validity. Considering all
// records rather than just the ones that proved the result can only shorten
// the lifetime. A message without records, or with an expired signature,
// yields 0 (do not cache).
func proofLifetime(msg *protocol.Message, now time.Time) time.Duration {
	if msg == nil {
		return 0
	}
	nowSec := uint32(now.Unix())
	minSec := int64(-1)
	lower := func(s int64) {
		if minSec < 0 || s < minSec {
			minSec = s
		}
	}
	for _, sec := range [][]*protocol.ResourceRecord{msg.Answers, msg.Authorities} {
		for _, rr := range sec {
			if rr == nil {
				continue
			}
			lower(int64(rr.TTL))
			if sig, ok := rr.Data.(*protocol.RDataRRSIG); ok {
				lower(int64(sig.OriginalTTL))
				remaining := int64(int32(sig.Expiration - nowSec)) // RFC 4034 §3.1.5 serial arithmetic
				if remaining < 0 {
					remaining = 0
				}
				lower(remaining)
			}
		}
	}
	if minSec <= 0 {
		return 0
	}
	return time.Duration(minSec) * time.Second
}

// clock returns the validator's current time (injectable for tests).
func (v *Validator) clock() time.Time {
	if v.now != nil {
		return v.now()
	}
	return time.Now()
}
