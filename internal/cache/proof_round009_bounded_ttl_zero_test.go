// Round-009 proof: boundedTTL(0) must not produce a MaxTTL entry.
// ttl=0 means "immediate expiry" (the caller wants the entry to expire
// right away). The UnboundedTTL sentinel means "no TTL from upstream,
// apply MaxTTL." These are distinct semantics that were previously
// both expressed as ttl=0.
//
// This is the positive-caching analog of the round-008 fix in
// clampNegativeTTL.
//
// Pre-fix (naive): boundedTTL(0) with MinTTL=0, MaxTTL>0 returned MaxTTL
// (wrong: conflates "no upstream TTL" with "immediate expiry").
// Post-fix (sentinel): boundedTTL(0) returns 0 (immediate expiry);
// boundedTTL(UnboundedTTL) returns MaxTTL (positive-caching window).
//
// Build tag `proof_round009` keeps this proof as durable regression
// evidence without dirtying the default suite. Run with:
//   go test -tags proof_round009 ./internal/cache/ -run TestProofRound009 -v
package cache

import (
	"testing"
	"time"
)

func TestProofRound009_BoundedTTLZero(t *testing.T) {
	// MinTTL=0, MaxTTL=3600s.
	c := New(Config{
		Capacity: 100,
		MinTTL:   0,
		MaxTTL:   3600 * time.Second,
	})

	// boundedTTL(0) means "immediate expiry" — the entry should NOT be
	// cached for the MaxTTL window.
	d := c.boundedTTL(0)
	if d != 0 {
		t.Fatalf("FAIL: boundedTTL(0) returned %v, want 0 (immediate expiry). "+
			"The sentinel UnboundedTTL is for 'no upstream TTL → apply MaxTTL'.", d)
	}

	// boundedTTL(UnboundedTTL) means "no TTL from upstream → apply MaxTTL".
	d = c.boundedTTL(UnboundedTTL)
	want := 3600 * time.Second
	if d != want {
		t.Fatalf("FAIL: boundedTTL(UnboundedTTL) returned %v, want %v (MaxTTL)", d, want)
	}

	t.Logf("PROOF PASS: boundedTTL(0)=0 (immediate expiry), boundedTTL(UnboundedTTL)=MaxTTL=%v", d)
}
