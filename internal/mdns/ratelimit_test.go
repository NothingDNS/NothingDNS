package mdns

import (
	"testing"
	"time"
)

func TestMDNSResponseRateLimiter(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	l := newMDNSResponseRateLimiter(20, 40, 4096)

	// Burst of 40 allowed immediately, then throttled.
	allowed := 0
	for i := 0; i < 60; i++ {
		if l.allow("192.0.2.9", base) {
			allowed++
		}
	}
	if allowed != 40 {
		t.Errorf("burst allowed %d, want 40", allowed)
	}
	if l.allow("192.0.2.9", base) {
		t.Error("expected throttling after burst exhausted")
	}

	// After 1s, ~20 tokens refill.
	if !l.allow("192.0.2.9", base.Add(time.Second)) {
		t.Error("expected refill after 1s")
	}

	// A different source has its own independent bucket.
	if !l.allow("192.0.2.10", base) {
		t.Error("independent source should be allowed")
	}
}

func TestMDNSResponseRateLimiter_MapBounded(t *testing.T) {
	l := newMDNSResponseRateLimiter(20, 40, 16)
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 1000; i++ {
		l.allow(string(rune(i))+".src", base)
	}
	l.mu.Lock()
	n := len(l.buckets)
	l.mu.Unlock()
	if n > 16 {
		t.Errorf("bucket map grew to %d, want <= 16 (bounded)", n)
	}
}

func TestMDNSResponseRateLimiter_CapacityDoesNotResetActiveThrottle(t *testing.T) {
	l := newMDNSResponseRateLimiter(1, 1, 2)
	base := time.Unix(1_700_000_000, 0)
	if !l.allow("victim", base) || l.allow("victim", base.Add(900*time.Millisecond)) {
		t.Fatal("victim did not enter throttled state")
	}
	if !l.allow("attacker-1", base) || !l.allow("attacker-2", base.Add(900*time.Millisecond)) {
		t.Fatal("new source unexpectedly denied")
	}
	if l.allow("victim", base.Add(900*time.Millisecond)) {
		t.Fatal("capacity churn reset active victim throttle")
	}
}
