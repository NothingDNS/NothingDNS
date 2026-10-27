package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

// An ACL denial carries EDE 18 (Prohibited) and a per-client rate-limit
// refusal EDE 0 "rate limited", like the RRL and recursion refusals; a query
// without EDNS gets no OPT (RFC 8914) (F748).
func TestRefusalsCarryExtendedError(t *testing.T) {
	ede := func(m *protocol.Message) (uint16, bool) {
		opt := m.GetOPT()
		if opt == nil {
			return 0, false
		}
		o := opt.Data.(*protocol.RDataOPT).GetOption(protocol.OptionCodeExtendedError)
		if o == nil || len(o.Data) < 2 {
			return 0, false
		}
		return uint16(o.Data[0])<<8 | uint16(o.Data[1]), true
	}
	ask := func(h *integratedHandler, ip string, edns bool) *protocol.Message {
		q := newTestQuery(t, "www.example.com.", protocol.TypeA)
		if edns {
			q.SetEDNS0(1232, false)
		}
		w := newCaptureWriter(ip, "udp")
		h.ServeDNS(w, q)
		return w.msg
	}

	h := newTestHandler()
	acl := filter.NewEmptyACLChecker()
	if err := acl.UpdateRules([]config.ACLRule{{Name: "lan", Action: "allow", Networks: []string{"192.0.2.0/24"}}}); err != nil {
		t.Fatal(err)
	}
	h.security.ACLChecker = acl
	if code, ok := ede(ask(h, "198.51.100.7", true)); !ok || code != protocol.EDEProhibited {
		t.Fatalf("ACL denial EDE = %d/%v, want 18", code, ok)
	}
	if m := ask(h, "198.51.100.7", false); m.Header.Flags.RCODE != protocol.RcodeRefused || m.GetOPT() != nil {
		t.Fatal("ACL denial without EDNS must be a plain REFUSED")
	}

	h = newTestHandler()
	h.security.RateLimiter = filter.NewRateLimiter(config.RRLConfig{Enabled: true, Rate: 1, Burst: 1})
	ask(h, "192.0.2.9", true)
	if m := ask(h, "192.0.2.9", true); m.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Fatalf("rate limit rcode %d", m.Header.Flags.RCODE)
	} else if code, ok := ede(m); !ok || code != protocol.EDEOtherError {
		t.Fatalf("rate limit EDE = %d/%v", code, ok)
	}
}
