package cache

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func ttlPolicyCache(min, max time.Duration) *Cache {
	return New(Config{
		Capacity:   100,
		DefaultTTL: 60 * time.Second,
		MinTTL:     min,
		MaxTTL:     max,
	})
}

func msgWithTTL(ttl uint32) *protocol.Message {
	m := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{{Name: protocol.NewName([]string{"www", "example", "com"}, true), QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}
	m.AddAnswer(&protocol.ResourceRecord{
		Name:  protocol.NewName([]string{"www", "example", "com"}, true),
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   ttl,
		Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
	})
	return m
}

// TestApplyTTLPolicy_CapsAtMaxTTL is the regression for max_ttl never reaching
// the wire. The configured ceiling bounded only how long this cache treated an
// answer as fresh; the record TTLs inside the message went out untouched, so
// under max_ttl=1h an upstream TTL of 999999 was still handed to the client as
// 999999 and every downstream cache held for 11 days what this server
// refreshes hourly.
func TestApplyTTLPolicy_CapsAtMaxTTL(t *testing.T) {
	c := ttlPolicyCache(5*time.Second, time.Hour)
	msg := msgWithTTL(999999)

	got := c.ApplyTTLPolicy(msg, 999999)

	if got != 3600 {
		t.Errorf("effective TTL = %d, want 3600", got)
	}
	if msg.Answers[0].TTL != 3600 {
		t.Errorf("record TTL = %d, want 3600 (the ceiling must reach the wire)", msg.Answers[0].TTL)
	}
}

// TestApplyTTLPolicy_NeverInflates: min_ttl extends how long this cache holds
// an entry, but it must not make the server claim more freshness than the
// authority published.
func TestApplyTTLPolicy_NeverInflates(t *testing.T) {
	c := ttlPolicyCache(300*time.Second, time.Hour)
	msg := msgWithTTL(60)

	got := c.ApplyTTLPolicy(msg, 60)

	if got != 300 {
		t.Errorf("effective entry lifetime = %d, want 300 (min_ttl floor)", got)
	}
	if msg.Answers[0].TTL != 60 {
		t.Errorf("record TTL = %d, want 60 — min_ttl must not inflate the authority's TTL",
			msg.Answers[0].TTL)
	}
}

func TestApplyTTLPolicy_UnboundedMaxLeavesTTLAlone(t *testing.T) {
	c := ttlPolicyCache(0, 0) // no ceiling configured
	msg := msgWithTTL(86400)

	if got := c.ApplyTTLPolicy(msg, 86400); got != 86400 {
		t.Errorf("effective TTL = %d, want 86400", got)
	}
	if msg.Answers[0].TTL != 86400 {
		t.Errorf("record TTL = %d, want 86400", msg.Answers[0].TTL)
	}
}

func TestApplyTTLPolicy_NilMessage(t *testing.T) {
	c := ttlPolicyCache(5*time.Second, time.Hour)
	if got := c.ApplyTTLPolicy(nil, 999999); got != 3600 {
		t.Errorf("effective TTL = %d, want 3600", got)
	}
}

// TestApplyTTLPolicy_SkipsOPT: the OPT pseudo-record's TTL field carries EDNS
// state, not a lifetime.
func TestApplyTTLPolicy_SkipsOPT(t *testing.T) {
	c := ttlPolicyCache(5*time.Second, time.Hour)
	msg := msgWithTTL(999999)
	optTTL := protocol.BuildEDNSTTL(0, 0, true, 0)
	msg.AddAdditional(&protocol.ResourceRecord{
		Name:  protocol.NewName(nil, true),
		Type:  protocol.TypeOPT,
		Class: 1232,
		TTL:   optTTL,
		Data:  &protocol.RDataOPT{},
	})

	c.ApplyTTLPolicy(msg, 999999)

	if got := msg.GetOPT().TTL; got != optTTL {
		t.Errorf("OPT TTL field = 0x%08X, want 0x%08X (it is EDNS state, not a TTL)", got, optTTL)
	}
}

// TestSet_StoredMessageCarriesTheCeiling checks the same bound on the cached
// copy, which is what later hits are served from.
func TestSet_StoredMessageCarriesTheCeiling(t *testing.T) {
	c := ttlPolicyCache(5*time.Second, time.Hour)
	c.Set("k", msgWithTTL(999999), 999999)

	entry := c.Get("k")
	if entry == nil || entry.Message == nil {
		t.Fatal("entry not cached")
	}
	if entry.Message.Answers[0].TTL != 3600 {
		t.Errorf("cached record TTL = %d, want 3600", entry.Message.Answers[0].TTL)
	}
}

func TestSet_NilMessageDoesNotPanic(t *testing.T) {
	c := ttlPolicyCache(5*time.Second, time.Hour)
	c.Set("k", nil, 60) // must not panic
}
