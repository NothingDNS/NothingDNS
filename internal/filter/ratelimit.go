package filter

import (
	"net"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
)

// RateLimiter implements per-client rate limiting using token buckets.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   int
	enabled bool
	stopCh  chan struct{}

	// Memory protection: max buckets to prevent unbounded growth during attacks
	maxBuckets int
}

// bucket holds token bucket state for a single client.
type bucket struct {
	tokens      float64
	lastTime    time.Time
	createdAt   time.Time // for LRU eviction when maxBuckets exceeded
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
		enabled:    true,
		stopCh:     make(chan struct{}),
		maxBuckets: maxBuckets,
	}

	// Start background cleanup goroutine
	go rl.cleanup()

	return rl
}

// Allow checks if a client IP is allowed to make a request.
func (rl *RateLimiter) Allow(clientIP net.IP) bool {
	if !rl.enabled {
		return true
	}

	key := clientIP.String()

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
			tokens:    float64(rl.burst) - 1, // consume one token for this request
			lastTime:  now,
			createdAt: now,
		}
		rl.buckets[key] = b
		return true
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastTime).Seconds()
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

// Stop terminates the background cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
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

// SetEnabled toggles rate limiting at runtime.
func (rl *RateLimiter) SetEnabled(enabled bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.enabled = enabled
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

// evictOldest removes the oldest n buckets by creation time.
// Called when bucket count approaches maxBuckets during attacks.
func (rl *RateLimiter) evictOldest(n int) {
	if n <= 0 || len(rl.buckets) == 0 {
		return
	}

	// Simple eviction: remove n oldest by creation time
	// For efficiency with large maps, we use a sampling approach
	// rather than sorting all entries
	type entry struct {
		key       string
		createdAt time.Time
	}

	// Sample up to 2*n entries and remove the oldest n
	// This is O(n) instead of O(n log n) for full sort
	samples := make([]entry, 0, n*2)
	for key, b := range rl.buckets {
		samples = append(samples, entry{key: key, createdAt: b.createdAt})
		if len(samples) >= n*2 {
			break
		}
	}

	// Find and delete n oldest from sample
	deleted := 0
	for deleted < n && len(samples) > 0 {
		// Find oldest in sample
		oldestIdx := 0
		for i := 1; i < len(samples); i++ {
			if samples[i].createdAt.Before(samples[oldestIdx].createdAt) {
				oldestIdx = i
			}
		}
		// Delete it
		delete(rl.buckets, samples[oldestIdx].key)
		// Remove from sample slice
		samples[oldestIdx] = samples[len(samples)-1]
		samples = samples[:len(samples)-1]
		deleted++
	}
}
