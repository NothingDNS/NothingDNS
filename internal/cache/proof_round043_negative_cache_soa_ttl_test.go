// Round-043 proof: a cached negative answer must go out with the negative TTL,
// not the upstream SOA's own TTL.
//
// CONTRACT. RFC 2308 §5: the SOA in a negative response carries the negative
// TTL — "The TTL of this record is set from the minimum of the MINIMUM field of
// the SOA record and the TTL of the SOA itself, and indicates how long a
// resolver may cache the negative answer." The server derives exactly that
// value (`negativeCacheTTL` = min(SOA.TTL, SOA.MINIMUM)) and stores the entry
// with it as its lifetime.
//
// DEFECT. `setNegativeEntry` bounded the ENTRY lifetime but never bounded the
// TTLs inside the stored message, unlike `setInternal`, which clamps a positive
// entry's records to the entry lifetime. The cache-hit path then serves
// `entry.AgeAdjustedMessage(...)`, which subtracts only the entry's age — with
// the comment "so downstream negative caching honors the remaining TTL", which
// is precisely what it does not do. For the common zone shape where the SOA TTL
// is much larger than its MINIMUM (e.g. SOA TTL 86400, MINIMUM 60), the cached
// NXDOMAIN goes out with an SOA TTL of ~86400 instead of 60: a downstream
// resolver caches the denial for a day while this server's own entry expires in
// a minute, so a name that appears stays unresolvable downstream.
//
// FIX. Clamp the stored negative message's TTLs to the entry lifetime in
// `setNegativeEntry`, mirroring the clamp `setInternal` already applies to
// positive entries. The clamp only lowers TTLs, so an upstream that already
// publishes the negative TTL (or a smaller one) is unaffected.
package cache

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// rr043NegativeResponse builds an NXDOMAIN response carrying an SOA whose own
// TTL differs from its MINIMUM, which is what decides the negative TTL.
func rr043NegativeResponse(t *testing.T, soaTTL, minimum uint32) *protocol.Message {
	t.Helper()

	name, err := protocol.ParseName("gone.example.com.")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	mname, _ := protocol.ParseName("ns1.example.com.")
	rname, _ := protocol.ParseName("hostmaster.example.com.")
	origin, _ := protocol.ParseName("example.com.")

	msg := &protocol.Message{
		Header: protocol.Header{ID: 1, QDCount: 1, NSCount: 1},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
		Authorities: []*protocol.ResourceRecord{{
			Name:  origin,
			Type:  protocol.TypeSOA,
			Class: protocol.ClassIN,
			TTL:   soaTTL,
			Data: &protocol.RDataSOA{
				MName: mname, RName: rname, Serial: 2026010101,
				Refresh: 3600, Retry: 600, Expire: 604800, Minimum: minimum,
			},
		}},
	}
	msg.Header.Flags.RCODE = protocol.RcodeNameError
	return msg
}

// rr043SOATTL returns the SOA TTL of the authority section, which is the value
// a downstream resolver uses as the negative TTL (RFC 2308 §5).
func rr043SOATTL(t *testing.T, msg *protocol.Message) uint32 {
	t.Helper()
	if msg == nil {
		t.Fatal("served message is nil")
	}
	for _, rr := range msg.Authorities {
		if rr != nil && rr.Type == protocol.TypeSOA {
			return rr.TTL
		}
	}
	t.Fatal("served negative response carries no SOA in the authority section")
	return 0
}

// TestRound043NegativeCacheHitHonoursNegativeTTL is the defect case: SOA TTL
// 86400, MINIMUM 60 — the served SOA TTL must be 60 (the negative TTL the cache
// derived and stored as the entry lifetime), not 86400.
func TestRound043NegativeCacheHitHonoursNegativeTTL(t *testing.T) {
	c := New(DefaultConfig())

	const negativeTTL = 60
	c.SetNegativeMessage("k", protocol.RcodeNameError, rr043NegativeResponse(t, 86400, negativeTTL), negativeTTL)

	entry := c.Get("k")
	if entry == nil {
		t.Fatal("negative entry was not cached")
	}
	if !entry.IsNegative {
		t.Fatal("entry is not marked negative")
	}

	served := entry.AgeAdjustedMessage(time.Now())
	got := rr043SOATTL(t, served)
	if got > negativeTTL {
		t.Fatalf("cached negative answer served with SOA TTL %d, want <= %d (the negative TTL): "+
			"RFC 2308 §5 sets the SOA TTL in a negative response to "+
			"min(SOA.TTL, SOA.MINIMUM), and this cache derived and stored exactly that "+
			"value as the entry lifetime. Serving %d makes every downstream resolver cache "+
			"the denial for %d seconds while this entry expires after %d — a name that "+
			"appears stays unresolvable downstream for %ds.",
			got, negativeTTL, got, got, negativeTTL, got)
	}
}

// TestRound043NegativeCacheTTLControls pins the neighbouring cases.
func TestRound043NegativeCacheTTLControls(t *testing.T) {
	t.Run("upstream already publishes the negative TTL", func(t *testing.T) {
		c := New(DefaultConfig())

		// SOA TTL == MINIMUM == 60: the clamp must not change anything.
		c.SetNegativeMessage("k", protocol.RcodeNameError, rr043NegativeResponse(t, 60, 60), 60)
		entry := c.Get("k")
		if entry == nil {
			t.Fatal("negative entry was not cached")
		}
		if got := rr043SOATTL(t, entry.AgeAdjustedMessage(time.Now())); got != 60 {
			t.Errorf("SOA TTL = %d, want 60 (an already-correct upstream value must pass through)", got)
		}
	})

	t.Run("smaller SOA TTL is not inflated", func(t *testing.T) {
		c := New(DefaultConfig())

		// SOA TTL 30 with MINIMUM 60 -> negative TTL 30; a smaller published
		// TTL must not be raised to the entry lifetime.
		c.SetNegativeMessage("k", protocol.RcodeNameError, rr043NegativeResponse(t, 30, 60), 30)
		entry := c.Get("k")
		if entry == nil {
			t.Fatal("negative entry was not cached")
		}
		if got := rr043SOATTL(t, entry.AgeAdjustedMessage(time.Now())); got != 30 {
			t.Errorf("SOA TTL = %d, want 30 (clamping must only lower TTLs)", got)
		}
	})

	t.Run("positive entries still clamp to their lifetime", func(t *testing.T) {
		c := New(DefaultConfig())

		name, _ := protocol.ParseName("www.example.com.")
		msg := &protocol.Message{
			Header:    protocol.Header{ID: 1, QDCount: 1, ANCount: 1},
			Questions: []*protocol.Question{{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN}},
			Answers: []*protocol.ResourceRecord{{
				Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 86400,
				Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
			}},
		}
		c.Set("p", msg, 30)

		entry := c.Get("p")
		if entry == nil {
			t.Fatal("positive entry was not cached")
		}
		served := entry.AgeAdjustedMessage(time.Now())
		if len(served.Answers) != 1 {
			t.Fatalf("served %d answers, want 1", len(served.Answers))
		}
		if got := served.Answers[0].TTL; got > 30 {
			t.Errorf("positive answer TTL = %d, want <= 30 (the existing positive clamp)", got)
		}
	})
}
