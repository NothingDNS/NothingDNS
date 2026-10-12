package filter

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
)

// RateLimiter implements per-client rate limiting using token buckets.
//
// enabled is an atomic.Bool because Allow() reads it on the hot
// request path without taking rl.mu, while Reload/SetEnabled write
// it. Mixing locked writes with unlocked reads on a plain bool would
// be a data race; atomic.Bool gives us a wait-free fast path plus
// safe visibility on writes.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens per second
	burst    int
	enabled  atomic.Bool
	stopCh   chan struct{}
	stopOnce sync.Once // guards Stop from panicking on a second call

	// Memory protection: max buckets to prevent unbounded growth during attacks
	maxBuckets int
}

// bucket holds token bucket state for a single client.
type bucket struct {
	tokens   float64
	lastTime time.Time // also drives LRU eviction when maxBuckets exceeded
}

// NewRateLimiter creates a rate limiter from config.
func NewRateLimiter(cfg config.RRLConfig) *RateLimiter {
	rate := float64(cfg.Rate)
	if rate <= 0 {
		rate = 5 // default: 5 qps
	}
	burst := cfg.Burst
	if burst <= 0 {
		burst = 20 // default burst
	}
	maxBuckets := cfg.MaxBuckets
	if maxBuckets <= 0 {
		maxBuckets = 10000 // default: protect against unbounded growth
	}

	rl := &RateLimiter{
		buckets:    make(map[string]*bucket),
		rate:       rate,
		burst:      burst,
		stopCh:     make(chan struct{}),
		maxBuckets: maxBuckets,
	}
	rl.enabled.Store(true)

	// Start background cleanup goroutine
	go rl.cleanup()

	return rl
}

// Allow checks if a client IP is allowed to make a request.
func (rl *RateLimiter) Allow(clientIP net.IP) bool {
	if !rl.enabled.Load() {
		return true
	}

	key := limiterKey(clientIP)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		// Check if we need to evict old buckets before creating new one
		if len(rl.buckets) >= rl.maxBuckets {
			rl.evictOldest(100) // evict 1% of max to make room
		}

		b = &bucket{
			tokens:   float64(rl.burst) - 1, // consume one token for this request
			lastTime: now,
		}
		rl.buckets[key] = b
		return true
	}

	// Refill tokens based on elapsed time
	elapsed := elapsedSecondsSince(b.lastTime, now)
	b.tokens += rl.rate * elapsed
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastTime = now

	if b.tokens < 1 {
		return false
	}

	b.tokens--
	return true
}

// limiterKey is the bucket key for a client: the address for IPv4, the /64
// for IPv6 (F707) — one IPv6 subscriber line holds 2^64 addresses, so a
// per-address bucket never limited it.
func limiterKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	if v6 := ip.To16(); v6 != nil {
		return v6.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return ip.String()
}

func elapsedSecondsSince(lastTime, now time.Time) float64 {
	if now.Before(lastTime) {
		return 0
	}
	return now.Sub(lastTime).Seconds()
}

// Stop terminates the background cleanup goroutine.
// Idempotent: a second call is a no-op. Without the sync.Once
// guard, the second close(rl.stopCh) panicked with "close of
// closed channel" — easy to trigger from a daemon shutdown path
// that runs Stop twice (e.g. defer in tests plus an explicit Stop
// in the production cleanup).
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.stopCh)
	})
}

// SetRate updates the rate limit (tokens per second) at runtime.
func (rl *RateLimiter) SetRate(rate float64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rate > 0 {
		rl.rate = rate
	}
}

// SetBurst updates the burst capacity at runtime.
func (rl *RateLimiter) SetBurst(burst int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if burst > 0 {
		rl.burst = burst
	}
}

// SetEnabled toggles rate limiting at runtime. Wait-free for readers.
func (rl *RateLimiter) SetEnabled(enabled bool) {
	rl.enabled.Store(enabled)
}

// Reload updates rate limiter settings from config.
func (rl *RateLimiter) Reload(cfg config.RRLConfig) {
	rl.mu.Lock()
	if cfg.Rate > 0 {
		rl.rate = float64(cfg.Rate)
	}
	if cfg.Burst > 0 {
		rl.burst = cfg.Burst
	}
	if cfg.MaxBuckets > 0 {
		rl.maxBuckets = cfg.MaxBuckets
	}
	rl.mu.Unlock()
	rl.enabled.Store(cfg.Enabled)
}

// cleanup periodically removes stale buckets.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			rl.pruneStale()
		}
	}
}

// pruneStale removes buckets not accessed in the last 5 minutes.
func (rl *RateLimiter) pruneStale() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	staleThreshold := time.Now().Add(-5 * time.Minute)
	for key, b := range rl.buckets {
		if b.lastTime.Before(staleThreshold) {
			delete(rl.buckets, key)
		}
	}
}

// evictOldest removes n least-recently-used buckets.
//
// Originally keyed on bucket.createdAt (creation time), which let an
// attacker spraying source IPs bypass the limit (M-5): fresh attacker
// buckets started with burst-1 tokens, and the longest-tenured
// legitimate clients — who were quietly under-limit — became the
// eviction targets. When those legitimate clients next showed up
// they got a brand-new bucket with full burst, so the per-IP cap
// effectively reset cluster-wide under churn.
//
// Switching the sort key to lastTime makes this true LRU: a steady
// legitimate client who keeps the bucket warm via recent traffic
// outlives the cold attacker buckets whose first burst was minutes
// ago, and the burst-reset trick stops working.
//
// The sampling approach (peek up to 2*n entries, drop the n with the
// oldest lastTime) is unchanged.
func (rl *RateLimiter) evictOldest(n int) {
	if n <= 0 || len(rl.buckets) == 0 {
		return
	}

	type entry struct {
		key      string
		lastTime time.Time
	}

	samples := make([]entry, 0, n*2)
	for key, b := range rl.buckets {
		samples = append(samples, entry{key: key, lastTime: b.lastTime})
		if len(samples) >= n*2 {
			break
		}
	}

	deleted := 0
	for deleted < n && len(samples) > 0 {
		oldestIdx := 0
		for i := 1; i < len(samples); i++ {
			if samples[i].lastTime.Before(samples[oldestIdx].lastTime) {
				oldestIdx = i
			}
		}
		delete(rl.buckets, samples[oldestIdx].key)
		samples[oldestIdx] = samples[len(samples)-1]
		samples = samples[:len(samples)-1]
		deleted++
	}
}
