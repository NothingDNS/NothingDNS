package filter

import (
	"net"
	"testing"
)

func TestRRLSmallMaxBucketsPreservesActiveSuppression(t *testing.T) {
	rrl := NewRRL(RRLConfig{Enabled: true, Rate: 1, Burst: 1, Window: 60, MaxBuckets: 2})
	defer rrl.Stop()
	legit := net.ParseIP("192.0.2.10")
	attacker1 := net.ParseIP("192.0.2.11")
	attacker2 := net.ParseIP("192.0.2.12")

	if allowed, _ := rrl.Allow(legit, 1, 0); !allowed {
		t.Fatal("initial legitimate response should be allowed")
	}
	if allowed, _ := rrl.Allow(attacker1, 1, 0); !allowed {
		t.Fatal("initial attacker response should be allowed")
	}
	if allowed, suppressed := rrl.Allow(legit, 1, 0); allowed || !suppressed {
		t.Fatal("second immediate legitimate response should enter suppression")
	}
	if allowed, _ := rrl.Allow(attacker2, 1, 0); !allowed {
		t.Fatal("new client should be allowed after capacity eviction")
	}
	if allowed, suppressed := rrl.Allow(legit, 1, 0); allowed || !suppressed {
		t.Fatal("one-entry churn cleared an active RRL suppression")
	}
}
