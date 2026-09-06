package cache

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestCacheLoadZeroTTLLeak verifies that Cache.Load releases the pooled
// *protocol.Message when it encounters an already-expired entry (remainingTTL == 0).
//
// Bug: Cache.Load calls protocol.UnpackMessage, which returns a pooled *Message.
// When remainingTTL == 0 the code did "continue" without calling msg.Release(),
// permanently leaking the pooled struct. The fix adds msg.Release() before continue.
func TestCacheLoadZeroTTLLeak(t *testing.T) {
	c := New(DefaultConfig())

	// Build a valid wire-format message using the same pattern as validWireMessage.
	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{{Name: mustName("test.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}
	buf := make([]byte, msg.WireLength())
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatal(err)
	}
	wire := buf[:n]

	// An expired entry: ExpireTime is in the past, so remainingTTL == 0 inside Load.
	entries := []CacheEntryJSON{
		{
			Key:        "test.com:1",
			WireBytes:  wire,
			TTL:        60,
			ExpireTime: time.Now().Add(-1 * time.Hour), // remainingTTL == 0
		},
	}

	// First Load: unpacks wire → gets pooled *Message → hits zero-TTL → skip.
	c.Load(entries)

	// Second Load: the same zero-TTL path.
	// With the bug: pooled msg was leaked, pool is empty, must allocate → ≥1 alloc.
	// With the fix: pooled msg was returned via Release(), pool has one → 0 allocs.
	allocs := testing.AllocsPerRun(100, func() {
		c.Load(entries)
	})

	if allocs > 0 {
		t.Errorf("BUG: Cache.Load leaked pooled *protocol.Message on zero-TTL path: "+
			"expected 0 allocs, got %.0f", allocs)
	}
}
