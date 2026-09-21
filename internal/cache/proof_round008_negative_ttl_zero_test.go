// Round-008 proof: SetNegativeWithTTL(key, rcode, 0) must fall back to
// the configured NegativeTTL, not store an entry that expires immediately.
// The current implementation calls clampNegativeTTL(ttl) which returns
// 0 for ttl=0 (since 0 is not > NegativeTTL), so the entry has
// ExpireTime == now and is immediately expired.
//
// By contrast, SetNegativeMessage(key, rcode, msg, 0) explicitly handles
// ttl <= 0 by falling back to c.config().NegativeTTL (see line 689).
//
// Pre-fix expected: SetNegativeWithTTL(key, "", 0) stores an entry with
// ExpireTime equal to now (zero duration = immediate expiry).
// Post-fix expected: SetNegativeWithTTL(key, "", 0) stores an entry with
// ExpireTime equal to now + NegativeTTL (falls back to configured value).
package cache

import (
	"testing"
	"time"
)

func TestProofRound008_NegativeTTLZero(t *testing.T) {
	c := New(Config{Capacity: 100, NegativeTTL: 30 * time.Second})

	now := c.now()

	// SetNegativeWithTTL with ttl=0: should fall back to NegativeTTL.
	c.SetNegativeWithTTL("test.zero", 3 /* NXDOMAIN */, 0)

	e := c.Get("test.zero")
	if e == nil {
		// Pre-fix: the entry is immediately expired, so Get returns nil.
		// Post-fix: the entry has ExpireTime = now + 30s, so Get returns it.
		t.Fatalf("FAIL: SetNegativeWithTTL(key, 3, 0) stored an immediately-expired entry (Get returned nil). " +
			"Pre-fix clampNegativeTTL returns 0 for ttl=0, so ExpireTime == now. " +
			"Post-fix should fall back to NegativeTTL (30s) like SetNegativeMessage does.")
	}

	// Verify the entry has a meaningful remaining TTL (close to NegativeTTL).
	remaining := time.Duration(e.RemainingTTL(now)) * time.Second
	if remaining < 25*time.Second {
		t.Fatalf("FAIL: SetNegativeWithTTL(key, 3, 0) stored an entry with remaining TTL %v, want ~30s. "+
			"Pre-fix clampNegativeTTL returns 0 for ttl=0; post-fix should fall back to NegativeTTL.",
			remaining)
	}

	t.Logf("PROOF PASS: SetNegativeWithTTL(key, 3, 0) stored an entry with remaining TTL %v (falls back to NegativeTTL)", remaining)
}
