//go:build proof_round009

// Round-009 proof: boundedTTL(0) must not produce a zero-duration entry
// when MinTTL is also zero. The current implementation returns 0 for
// ttl=0 (since 0 is not < MinTTL=0), so a caller passing ttl=0 stores
// an immediately-expired entry — effectively disabling positive caching.
//
// This is the positive-caching analog of the round-008 fix in
// clampNegativeTTL. The fix: when ttl=0, return the MaxTTL ceiling
// (or 0 only if MaxTTL is also 0 and MinTTL is 0 — i.e., no caching
// configured at all).
//
// Pre-fix expected: boundedTTL(0) with MinTTL=0 returns 0 (immediate
// expiry).
// Post-fix expected: boundedTTL(0) with MinTTL=0 and MaxTTL>0 returns
// MaxTTL (or at minimum the entry has a non-zero lifetime).
//
// Build tag `proof_round009` keeps this proof as durable regression
// evidence without dirtying the default suite. Run with:
//   go test -tags proof_round009 ./internal/cache/ -run TestProofRound009 -v
//
// A correct fix cannot naively fall back to MaxTTL: stale-serving tests
// in internal/cache/stale_test.go rely on ttl=0 producing immediate
// expiry when ServeStale+StaleGrace are set. The right fix needs a
// separate API or sentinel value to distinguish "no TTL" from
// "immediately expired."
package cache

import (
	"testing"
	"time"
)

func TestProofRound009_BoundedTTLZero(t *testing.T) {
	// MinTTL=0, MaxTTL=3600s. boundedTTL(0) should return at least
	// something non-zero — not 0 — so the entry lives for MaxTTL.
	c := New(Config{
		Capacity: 100,
		MinTTL:   0,
		MaxTTL:   3600 * time.Second,
	})

	d := c.boundedTTL(0)
	if d == 0 {
		t.Fatalf("FAIL: boundedTTL(0) with MinTTL=0, MaxTTL=3600s returned %v (immediate expiry). "+
			"Pre-fix: 0 < 0 is false, so MinTTL is not applied; the entry expires immediately. "+
			"Post-fix: ttl=0 should fall back to MaxTTL so the entry is cached for the full window.",
			d)
	}
	// The fix should produce a boundedTTL of MaxTTL (3600s) for ttl=0.
	want := 3600 * time.Second
	if d != want {
		t.Fatalf("FAIL: boundedTTL(0) returned %v, want %v (MaxTTL)", d, want)
	}

	t.Logf("PROOF PASS: boundedTTL(0) returned %v (falls back to MaxTTL)", d)
}
