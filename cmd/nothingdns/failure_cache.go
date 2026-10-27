// NothingDNS - resolution failure cache (RFC 9520)
//
// "Resolvers MUST implement a cache for resolution failures" and, while an
// entry lasts, "MUST NOT send any corresponding outgoing queries" (RFC 9520
// §3.2). Without it every client retry of a name whose upstream or authority
// fails went out again, so a broken zone or a dead upstream turned client
// retries into a query storm (F750). A failure is an upstream or resolver
// that does not answer, an unusable answer, a SERVFAIL/REFUSED-class answer,
// or a DNSSEC validation failure (§3.4).

package main

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// failureCacheTTL is how long a failure is remembered: within RFC 9520's
// 1 s - 5 min bounds, the 5 s its §3.2 suggests to start a backoff with.
const failureCacheTTL = 5 * time.Second

// maxFailureCacheEntries bounds the cache (RFC 9520 §3.2: mitigate resource
// exhaustion); when full, expired entries are dropped, then the oldest half.
const maxFailureCacheEntries = 10000

// failureCache remembers failed (name, type, class, CD) lookups until a
// deadline. The zero value is ready to use.
type failureCache struct {
	mu    sync.Mutex
	until map[string]time.Time
	now   func() time.Time // for tests; nil = time.Now
}

func (c *failureCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// failureKey identifies a query for the failure cache. CD is part of it: a
// validation failure must not stop a CD=1 client, which validates itself.
func failureKey(q *query) string {
	if q == nil || q.q == nil {
		return ""
	}
	cd := "0"
	if q.msg != nil && q.msg.Header.Flags.CD {
		cd = "1"
	}
	return strings.ToLower(canonicalize(q.qname)) + "|" + strconv.Itoa(int(q.q.QType)) + "|" + strconv.Itoa(int(q.q.QClass)) + "|" + cd
}

// active reports whether key failed within failureCacheTTL.
func (c *failureCache) active(key string) bool {
	if key == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	deadline, ok := c.until[key]
	if !ok {
		return false
	}
	if !c.clock().Before(deadline) {
		delete(c.until, key)
		return false
	}
	return true
}

// add records a failure for key.
func (c *failureCache) add(key string) {
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	if c.until == nil {
		c.until = make(map[string]time.Time)
	}
	if len(c.until) >= maxFailureCacheEntries {
		for k, d := range c.until {
			if !now.Before(d) {
				delete(c.until, k)
			}
		}
		if len(c.until) >= maxFailureCacheEntries {
			// Still full of live entries: drop about half. They are at most
			// failureCacheTTL old, so this only shortens some failure windows.
			n := 0
			for k := range c.until {
				delete(c.until, k)
				if n++; n >= maxFailureCacheEntries/2 {
					break
				}
			}
		}
	}
	c.until[key] = now.Add(failureCacheTTL)
}

// answerCachedFailure answers q from the failure cache: stale data when serve
// stale has it, else SERVFAIL with EDE 13 (Cached Error). It reports whether
// q was answered.
func (h *integratedHandler) answerCachedFailure(q *query) bool {
	if !h.failures.active(failureKey(q)) {
		return false
	}
	if h.serveStaleOnFailedRefresh(q, "cached resolution failure") {
		return true
	}
	if h.metrics != nil {
		h.metrics.RecordResponse(protocol.RcodeServerFailure)
	}
	sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDECachedError, "cached resolution failure")
	return true
}
