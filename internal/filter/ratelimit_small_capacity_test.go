package filter

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
)

func TestRateLimiterSmallMaxBucketsPreservesActiveClient(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 1, MaxBuckets: 2})
	defer rl.Stop()
	legit := net.ParseIP("192.0.2.1")
	attacker1 := net.ParseIP("192.0.2.2")
	attacker2 := net.ParseIP("192.0.2.3")

	if !rl.Allow(legit) || !rl.Allow(attacker1) {
		t.Fatal("initial requests should be allowed")
	}
	if rl.Allow(legit) {
		t.Fatal("second immediate request should be rate limited")
	}
	if !rl.Allow(attacker2) {
		t.Fatal("new client should be allowed after capacity eviction")
	}
	if rl.Allow(legit) {
		t.Fatal("one-entry churn reset an active client's token bucket")
	}
}
