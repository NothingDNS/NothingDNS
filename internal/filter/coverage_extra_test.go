package filter

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
)

// ---------------------------------------------------------------------------
// RateLimiter.SetRate
// ---------------------------------------------------------------------------

func TestRateLimiter_SetRate_Positive(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 10, Burst: 5})
	defer rl.Stop()

	rl.SetRate(100)

	rl.mu.Lock()
	got := rl.rate
	rl.mu.Unlock()

	if got != 100 {
		t.Errorf("rate = %v, want 100", got)
	}
}

func TestRateLimiter_SetRate_Zero(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 10, Burst: 5})
	defer rl.Stop()

	rl.SetRate(0)

	rl.mu.Lock()
	got := rl.rate
	rl.mu.Unlock()

	if got != 10 {
		t.Errorf("rate should remain 10 when SetRate(0), got %v", got)
	}
}

func TestRateLimiter_SetRate_Negative(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 10, Burst: 5})
	defer rl.Stop()

	rl.SetRate(-5)

	rl.mu.Lock()
	got := rl.rate
	rl.mu.Unlock()

	if got != 10 {
		t.Errorf("rate should remain 10 when SetRate(-5), got %v", got)
	}
}

// ---------------------------------------------------------------------------
// RateLimiter.SetBurst
// ---------------------------------------------------------------------------

func TestRateLimiter_SetBurst_Positive(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 10, Burst: 5})
	defer rl.Stop()

	rl.SetBurst(50)

	rl.mu.Lock()
	got := rl.burst
	rl.mu.Unlock()

	if got != 50 {
		t.Errorf("burst = %d, want 50", got)
	}
}

func TestRateLimiter_SetBurst_Zero(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 10, Burst: 5})
	defer rl.Stop()

	rl.SetBurst(0)

	rl.mu.Lock()
	got := rl.burst
	rl.mu.Unlock()

	if got != 5 {
		t.Errorf("burst should remain 5 when SetBurst(0), got %d", got)
	}
}

func TestRateLimiter_SetBurst_Negative(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 10, Burst: 5})
	defer rl.Stop()

	rl.SetBurst(-10)

	rl.mu.Lock()
	got := rl.burst
	rl.mu.Unlock()

	if got != 5 {
		t.Errorf("burst should remain 5 when SetBurst(-10), got %d", got)
	}
}

// ---------------------------------------------------------------------------
// RateLimiter.SetEnabled
// ---------------------------------------------------------------------------

func TestRateLimiter_SetEnabled_False(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 1})
	defer rl.Stop()

	// Exhaust the burst
	ip := net.ParseIP("192.168.1.1")
	if !rl.Allow(ip) {
		t.Fatal("first request should be allowed")
	}
	if rl.Allow(ip) {
		t.Fatal("second request should be rate-limited (burst=1)")
	}

	// Disable rate limiting
	rl.SetEnabled(false)

	if !rl.Allow(ip) {
		t.Error("should always allow when disabled")
	}
}

func TestRateLimiter_SetEnabled_True(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 1})
	defer rl.Stop()

	// Disable then re-enable
	rl.SetEnabled(false)
	rl.SetEnabled(true)

	rl.mu.Lock()
	enabled := rl.enabled
	rl.mu.Unlock()

	if !enabled {
		t.Error("expected enabled=true after SetEnabled(true)")
	}
}

func TestRateLimiter_SetEnabled_AllowAlwaysWhenDisabled(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 1})
	defer rl.Stop()

	rl.SetEnabled(false)

	// Even with burst=1 and rate=1, should always allow when disabled
	for i := 0; i < 100; i++ {
		if !rl.Allow(net.ParseIP("10.0.0.1")) {
			t.Fatalf("request %d should be allowed when disabled", i)
		}
	}
}
