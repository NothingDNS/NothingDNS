package resolver

import (
	"context"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// RFC 5452 section 6 requires a resolver to reject data outside the domain
// for which a response was requested. Glueless NS address resolution must not
// turn an unrelated Answer record into an upstream nameserver address.
func TestLookupNSAddressesRejectsOffChainAnswers_F899(t *testing.T) {
	transport := newMockTransport()
	transport.setAllRootHandlers(func(query *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: query.Header.ID, Flags: protocol.Flags{QR: true, AA: true}},
			Questions: query.Questions,
		}
		if query.Questions[0].QType == protocol.TypeA {
			resp.AddAnswer(makeARR("ns.provider.test.", "192.0.2.53"))
			resp.AddAnswer(makeARR("poison.attacker.test.", "203.0.113.66"))
			return resp
		}
		resp.AddAuthority(makeSOARR("provider.test."))
		return resp
	})

	cfg := DefaultConfig()
	cfg.AllowPrivateUpstream = true
	cfg.QnameMinimization = false
	r := NewResolver(cfg, nil, transport)
	got := r.lookupNSAddresses(context.Background(), "ns.provider.test.")

	if !containsString(got, "192.0.2.53:53") {
		t.Fatalf("CONTROL FAILED: queried nameserver address missing from %v", got)
	}
	t.Log("CONTROL OK: the A record owned by the queried nameserver was accepted")
	if containsString(got, "203.0.113.66:53") {
		t.Log("EXPECTED: poison.attacker.test. is outside the ns.provider.test. answer chain and is rejected")
		t.Logf("ACTUAL: lookupNSAddresses returned %v", got)
		t.Fatal("PROBLEM CONFIRMED: an off-chain Answer record became an upstream nameserver address")
	}
	t.Log("PROBLEM NOT REPRODUCED: off-chain Answer record was rejected")
}

func TestLookupNSAddressesKeepsCNAMEChainAndRejectsCachedOffChainAnswer_F899(t *testing.T) {
	cache := newMockCache()
	msg := &protocol.Message{Header: protocol.Header{Flags: protocol.Flags{QR: true}}}
	msg.AddAnswer(makeCNAMERR("ns.provider.test.", "actual.provider.test."))
	msg.AddAnswer(makeARR("actual.provider.test.", "192.0.2.54"))
	msg.AddAnswer(makeARR("unrelated.attacker.test.", "203.0.113.67"))
	cache.Set(cacheKey("ns.provider.test.", protocol.TypeA), msg, 300)

	cfg := DefaultConfig()
	cfg.AllowPrivateUpstream = true
	r := NewResolver(cfg, cache, newMockTransport())
	got := r.lookupNSAddresses(context.Background(), "ns.provider.test.")
	if len(got) != 1 || got[0] != "192.0.2.54:53" {
		t.Fatalf("FIX NOT VERIFIED: CNAME-chain lookup returned %v", got)
	}
	t.Log("FIX VERIFIED: cached CNAME target was accepted and unrelated A record was rejected")
}
