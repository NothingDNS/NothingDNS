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
}

// bucket holds token bucket state for a single client.
type bucket struct {
	tokens   float64
	lastTime time.Time
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

	rl := &RateLimiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
		enabled: true,
		stopCh:  make(chan struct{}),
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
		b = &bucket{
			tokens:   float64(rl.burst) - 1, // consume one token for this request
			lastTime: now,
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
