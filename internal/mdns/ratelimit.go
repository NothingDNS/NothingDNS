package mdns

import (
	"sync"
	"time"
)

// mdnsResponseRateLimiter throttles responses per source IP so the responder
// cannot be abused as a reflector/amplifier by a spoofed query source. mDNS is
// link-local, so the number of distinct sources is naturally small; the map is
// still capped as a backstop against a spoofer forging many source addresses.
type mdnsResponseRateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*tokenBucket
	rate     float64 // tokens per second
	burst    float64 // max tokens
	maxHosts int
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func newMDNSResponseRateLimiter(rate, burst float64, maxHosts int) *mdnsResponseRateLimiter {
	return &mdnsResponseRateLimiter{
		buckets:  make(map[string]*tokenBucket),
		rate:     rate,
		burst:    burst,
		maxHosts: maxHosts,
	}
}

// allow reports whether a response to ip is permitted now, consuming a token.
func (l *mdnsResponseRateLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.buckets[ip]
	if b == nil {
		// Backstop against unbounded growth from spoofed sources: if the table
		// is full, evict only the least-recently-used source. Clearing the whole
		// map reset every active throttle, so one new spoofed address gave a
		// previously exhausted victim a fresh burst.
		if len(l.buckets) >= l.maxHosts {
			l.evictOldest()
		}
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
	} else {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * l.rate
			if b.tokens > l.burst {
				b.tokens = l.burst
			}
			b.last = now
		}
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *mdnsResponseRateLimiter) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	for key, bucket := range l.buckets {
		if oldestKey == "" || bucket.last.Before(oldestTime) {
			oldestKey = key
			oldestTime = bucket.last
		}
	}
	if oldestKey != "" {
		delete(l.buckets, oldestKey)
	}
}
