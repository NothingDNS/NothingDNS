package filter

import (
	"net"
	"sync"
	"time"
)

// RRLConfig configures DNS Response Rate Limiting (RFC 8231).
type RRLConfig struct {
	Enabled       bool `yaml:"enabled"`
	Rate          int  `yaml:"rate"`           // responses per second per bucket
	Burst         int  `yaml:"burst"`          // burst capacity
	Window        int  `yaml:"window"`         // suppression window in seconds
	MaxBuckets    int  `yaml:"max_buckets"`    // memory limit
	ResponsesOnly bool `yaml:"responses_only"` // RRL applies only to responses, not queries
}

// rrlBucket tracks response rate for a single (clientIP, qtype, rcode) triple.
// Tracking by qtype+rcode prevents a flood of TYPE=ANY from hiding legitimate
// A record responses behind the same client IP.
type rrlBucket struct {
	tokens    float64 // remaining token capacity
	lastTime  time.Time
	createdAt time.Time
	suppressed time.Time // when suppression window started; zero = not suppressed
}

// RRL implements DNS Response Rate Limiting per RFC 8231.
// Unlike the token-bucket client limiter (which tracks queries), RRL tracks
// responses to detect when a client is receiving disproportionate answers
// relative to the configured rate. This catches reflected amplification floods
// where the attacker spoofs the victim's source IP.
type RRL struct {
	mu       sync.Mutex
	buckets  map[string]*rrlBucket
	rate     float64
	burst    int
	window   time.Duration
	enabled  bool
	stopCh   chan struct{}

	maxBuckets int
}

// rrlKey builds a unique key for a response bucket.
func rrlKey(clientIP net.IP, qtype uint16, rcode uint8) string {
	return clientIP.String() + ":" + itoa16(qtype) + ":" + itoa8(rcode)
}

// itoa16 formats a uint16 as a decimal string (no allocation).
func itoa16(v uint16) string {
	return u16toa(v)
}

func u16toa(v uint16) string {
	if v < 10 {
		return string(rune('0' + v))
	}
	var buf [5]byte
	i := len(buf)
	for v >= 10 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	i--
	buf[i] = byte('0' + v)
	return string(buf[i:])
}

func itoa8(v uint8) string {
	return u8toa(v)
}

func u8toa(v uint8) string {
	if v < 10 {
		return string(rune('0' + v))
	}
	var buf [3]byte
	i := len(buf)
	for v >= 10 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	i--
	buf[i] = byte('0' + v)
	return string(buf[i:])
}

// NewRRL creates a new RRL from config.
func NewRRL(cfg RRLConfig) *RRL {
	if cfg.Rate <= 0 {
		cfg.Rate = 5
	}
	if cfg.Burst <= 0 {
		cfg.Burst = 20
	}
	if cfg.Window <= 0 {
		cfg.Window = 10
	}
	if cfg.MaxBuckets <= 0 {
		cfg.MaxBuckets = 10000
	}

	rrl := &RRL{
		buckets:    make(map[string]*rrlBucket),
		rate:       float64(cfg.Rate),
		burst:      cfg.Burst,
		window:     time.Duration(cfg.Window) * time.Second,
		enabled:    cfg.Enabled,
		stopCh:     make(chan struct{}),
		maxBuckets: cfg.MaxBuckets,
	}

	if rrl.enabled {
		go rrl.cleanup()
	}

	return rrl
}

// Allow logs a response and returns whether it should be allowed.
// Returns (allowed, isSuppressed). When isSuppressed is true, the caller
// should return REFUSED without sending a real response.
func (rrl *RRL) Allow(clientIP net.IP, qtype uint16, rcode uint8) (allowed, suppressed bool) {
	if !rrl.enabled {
		return true, false
	}

	key := rrlKey(clientIP, qtype, rcode)

	rrl.mu.Lock()
	defer rrl.mu.Unlock()

	now := time.Now()
	b, ok := rrl.buckets[key]
	if !ok {
		if len(rrl.buckets) >= rrl.maxBuckets {
			rrl.evictOldest(100)
		}
		b = &rrlBucket{
			tokens:     float64(rrl.burst) - 1,
			lastTime:   now,
			createdAt:  now,
		}
		rrl.buckets[key] = b
		return true, false
	}

	// If suppressed, check if the window has elapsed.
	if !b.suppressed.IsZero() {
		if now.Sub(b.suppressed) < rrl.window {
			return false, true
		}
		// Window expired — clear suppression.
		b.suppressed = time.Time{}
	}

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += rrl.rate * elapsed
	if b.tokens > float64(rrl.burst) {
		b.tokens = float64(rrl.burst)
	}
	b.lastTime = now

	if b.tokens < 1 {
		// Enter suppression window.
		b.suppressed = now
		return false, true
	}

	b.tokens--
	return true, false
}

// LogSuperlative records a response that is disproportionately large relative
// to the query (amplification detection). If the ratio (response bytes /
// query bytes) exceeds ratio, the bucket is immediately suppressed.
// This is a best-effort signal; RRL Allow still governs rate.
func (rrl *RRL) LogSuperlative(clientIP net.IP, qtype uint16, rcode uint8, queryLen, responseLen int) {
	if !rrl.enabled || queryLen == 0 {
		return
	}
	// Amplification is measured per (qtype, rcode) so a multi-qtype flood
	// doesn't aggregate into a single bucket.
	ratio := float64(responseLen) / float64(queryLen)
	if ratio < 50 {
		return // not an amplification concern
	}

	key := rrlKey(clientIP, qtype, rcode)
	rrl.mu.Lock()
	defer rrl.mu.Unlock()

	b, ok := rrl.buckets[key]
	if !ok {
		if len(rrl.buckets) >= rrl.maxBuckets {
			rrl.evictOldest(100)
		}
		b = &rrlBucket{
			tokens:      float64(rrl.burst) - 1,
			lastTime:    time.Now(),
			createdAt:   time.Now(),
		}
		rrl.buckets[key] = b
		return
	}

	// Superlative response: accelerate token drain by the ratio factor.
	// A 50x amplification burns tokens 50x faster.
	b.tokens -= ratio
	if b.tokens < 0 {
		b.tokens = 0
		b.suppressed = time.Now()
	}
}

// Stop terminates the background cleanup goroutine.
func (rrl *RRL) Stop() {
	close(rrl.stopCh)
}

// SetEnabled toggles RRL at runtime.
func (rrl *RRL) SetEnabled(enabled bool) {
	rrl.mu.Lock()
	defer rrl.mu.Unlock()
	rrl.enabled = enabled
}

// cleanup periodically removes stale buckets.
func (rrl *RRL) cleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-rrl.stopCh:
			return
		case <-ticker.C:
			rrl.pruneStale()
		}
	}
}

// pruneStale removes buckets idle for more than 5 minutes.
func (rrl *RRL) pruneStale() {
	rrl.mu.Lock()
	defer rrl.mu.Unlock()

	threshold := time.Now().Add(-5 * time.Minute)
	for key, b := range rrl.buckets {
		if b.lastTime.Before(threshold) {
			delete(rrl.buckets, key)
		}
	}
}

// evictOldest removes n oldest buckets by creation time.
func (rrl *RRL) evictOldest(n int) {
	if n <= 0 || len(rrl.buckets) == 0 {
		return
	}

	type entry struct {
		key       string
		createdAt time.Time
	}

	samples := make([]entry, 0, n*2)
	for key, b := range rrl.buckets {
		samples = append(samples, entry{key: key, createdAt: b.createdAt})
		if len(samples) >= n*2 {
			break
		}
	}

	deleted := 0
	for deleted < n && len(samples) > 0 {
		oldestIdx := 0
		for i := 1; i < len(samples); i++ {
			if samples[i].createdAt.Before(samples[oldestIdx].createdAt) {
				oldestIdx = i
			}
		}
		delete(rrl.buckets, samples[oldestIdx].key)
		samples[oldestIdx] = samples[len(samples)-1]
		samples = samples[:len(samples)-1]
		deleted++
	}
}
