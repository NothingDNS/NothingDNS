package filter

import (
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
)

func TestRateLimiter_BasicAllow(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 5, Burst: 20})
	defer rl.Stop()

	ip := net.ParseIP("10.0.0.1")
	if !rl.Allow(ip) {
		t.Error("first request should be allowed")
	}
}

func TestRateLimiter_BurstExhaustion(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 3})
	defer rl.Stop()

	ip := net.ParseIP("10.0.0.1")

	// Should allow burst size requests
	for i := 0; i < 3; i++ {
		if !rl.Allow(ip) {
			t.Fatalf("request %d should be allowed within burst", i+1)
		}
	}

	// Next request should be denied
	if rl.Allow(ip) {
		t.Error("request beyond burst should be denied")
	}
}

func TestRateLimiter_TokenRefill(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 1000, Burst: 2})
	defer rl.Stop()

	ip := net.ParseIP("10.0.0.1")

	// Exhaust the burst
	rl.Allow(ip)
	rl.Allow(ip)

	// Denied immediately
	if rl.Allow(ip) {
		t.Error("should be denied after burst exhaustion")
	}

	// Manually advance the bucket's lastTime to simulate time passing
	rl.mu.Lock()
	b := rl.buckets[ip.String()]
	b.lastTime = time.Now().Add(-10 * time.Millisecond) // 10ms ago, should refill ~10 tokens at 1000/s
	rl.mu.Unlock()

	// Should be allowed again after refill
	if !rl.Allow(ip) {
		t.Error("should be allowed after token refill")
	}
}

func TestRateLimiter_DifferentClients(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 1})
	defer rl.Stop()

	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")

	if !rl.Allow(ip1) {
		t.Error("ip1 first request should be allowed")
	}
	if !rl.Allow(ip2) {
		t.Error("ip2 first request should be allowed (separate bucket)")
	}

	// Both should be denied now (burst=1)
	if rl.Allow(ip1) {
		t.Error("ip1 should be denied after burst")
	}
	if rl.Allow(ip2) {
		t.Error("ip2 should be denied after burst")
	}
}

func TestRateLimiter_Defaults(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{}) // empty config
	defer rl.Stop()

	if rl.rate != 5 {
		t.Errorf("expected default rate 5, got %f", rl.rate)
	}
	if rl.burst != 20 {
		t.Errorf("expected default burst 20, got %d", rl.burst)
	}
}

func TestRateLimiter_IPv6(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 2})
	defer rl.Stop()

	ip := net.ParseIP("::1")
	if !rl.Allow(ip) {
		t.Error("IPv6 first request should be allowed")
	}
	if !rl.Allow(ip) {
		t.Error("IPv6 second request should be allowed")
	}
	if rl.Allow(ip) {
		t.Error("IPv6 request beyond burst should be denied")
	}
}

func TestRateLimiter_PruneStale(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 10})
	defer rl.Stop()

	ip := net.ParseIP("10.0.0.1")
	rl.Allow(ip)

	// Manually make the bucket stale
	rl.mu.Lock()
	rl.buckets[ip.String()].lastTime = time.Now().Add(-10 * time.Minute)
	rl.mu.Unlock()

	rl.pruneStale()

	rl.mu.Lock()
	count := len(rl.buckets)
	rl.mu.Unlock()

	if count != 0 {
		t.Errorf("expected 0 buckets after prune, got %d", count)
	}
}

func TestRateLimiter_PruneKeepsActive(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 10})
	defer rl.Stop()

	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")

	rl.Allow(ip1)
	rl.Allow(ip2)

	// Make ip1 stale
	rl.mu.Lock()
	rl.buckets[ip1.String()].lastTime = time.Now().Add(-10 * time.Minute)
	rl.mu.Unlock()

	rl.pruneStale()

	rl.mu.Lock()
	count := len(rl.buckets)
	_, hasActive := rl.buckets[ip2.String()]
	rl.mu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 bucket after prune, got %d", count)
	}
	if !hasActive {
		t.Error("active bucket should still exist")
	}
}

func TestRateLimiter_CapNotExceedBurst(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 10000, Burst: 3})
	defer rl.Stop()

	ip := net.ParseIP("10.0.0.1")

	// Use 1 token
	rl.Allow(ip)

	// Simulate a lot of time passing - tokens should cap at burst
	rl.mu.Lock()
	rl.buckets[ip.String()].lastTime = time.Now().Add(-1 * time.Hour)
	rl.mu.Unlock()

	// Should only get burst-size requests
	allowed := 0
	for i := 0; i < 10; i++ {
		if rl.Allow(ip) {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("expected 3 allowed (burst cap), got %d", allowed)
	}
}
