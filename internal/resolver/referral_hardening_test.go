package resolver

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// Regression tests for F257 (NXNS glueless fan-out), F258 (lame upward
// referral SERVFAIL) and F259 (non-descending referral loop).

func rhName(s string) *protocol.Name { n, _ := protocol.ParseName(s); return n }

func rhReply(msg *protocol.Message) *protocol.Message {
	return &protocol.Message{
		Header:    protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true}},
		Questions: msg.Questions,
	}
}

func rhNS(owner, target string) *protocol.ResourceRecord {
	return &protocol.ResourceRecord{Name: rhName(owner), Type: protocol.TypeNS, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNS{NSDName: rhName(target)}}
}

func rhA(owner string, ip [4]byte) *protocol.ResourceRecord {
	return &protocol.ResourceRecord{Name: rhName(owner), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataA{Address: ip}}
}

func rhResolver(mt *mockTransport) *Resolver {
	cfg := DefaultConfig()
	cfg.Hints = []RootHint{{Name: "a.root.test.", IPv4: []string{"1.1.1.1"}}}
	return NewResolver(cfg, nil, mt)
}

func TestResolve_GluelessNSFanoutIsCapped(t *testing.T) {
	mt := newMockTransport()
	var victim atomic.Int64
	mt.setHandler("1.1.1.1:53", func(msg *protocol.Message) *protocol.Message {
		r := rhReply(msg)
		if strings.HasSuffix(strings.ToLower(msg.Questions[0].Name.String()), "victim.test.") {
			r.Authorities = append(r.Authorities, rhNS("victim.test.", "ns.victim.test."))
			r.Additionals = append(r.Additionals, rhA("ns.victim.test.", [4]byte{3, 3, 3, 3}))
		} else {
			r.Authorities = append(r.Authorities, rhNS("attacker.test.", "ns.attacker.test."))
			r.Additionals = append(r.Additionals, rhA("ns.attacker.test.", [4]byte{2, 2, 2, 2}))
		}
		return r
	})
	mt.setHandler("2.2.2.2:53", func(msg *protocol.Message) *protocol.Message {
		r := rhReply(msg)
		for i := 0; i < 100; i++ {
			r.Authorities = append(r.Authorities, rhNS("x.attacker.test.", fmt.Sprintf("ns%d.victim.test.", i)))
		}
		return r
	})
	mt.setHandler("3.3.3.3:53", func(msg *protocol.Message) *protocol.Message {
		victim.Add(1)
		r := rhReply(msg)
		r.Header.Flags.RCODE = protocol.RcodeNameError
		return r
	})

	_, _ = rhResolver(mt).Resolve(context.Background(), "x.attacker.test.", protocol.TypeA)
	if got, max := victim.Load(), int64(64); got > max {
		t.Fatalf("one client query sent %d queries to the victim zone, want <= %d", got, max)
	}
}

func lameDelegation(mt *mockTransport, lameOwner string) {
	mt.setHandler("1.1.1.1:53", func(msg *protocol.Message) *protocol.Message {
		r := rhReply(msg)
		r.Authorities = append(r.Authorities, rhNS("example.test.", "ns1.example.test."), rhNS("example.test.", "ns2.example.test."))
		r.Additionals = append(r.Additionals, rhA("ns1.example.test.", [4]byte{4, 4, 4, 4}), rhA("ns2.example.test.", [4]byte{5, 5, 5, 5}))
		return r
	})
	mt.setHandler("4.4.4.4:53", func(msg *protocol.Message) *protocol.Message {
		r := rhReply(msg)
		r.Authorities = append(r.Authorities, rhNS(lameOwner, "ns1.example.test."))
		return r
	})
	mt.setHandler("5.5.5.5:53", func(msg *protocol.Message) *protocol.Message {
		r := rhReply(msg)
		r.Header.Flags.AA = true
		r.Answers = append(r.Answers, rhA(msg.Questions[0].Name.String(), [4]byte{9, 9, 9, 9}))
		return r
	})
}

func TestResolve_LameReferralTriesNextServer(t *testing.T) {
	// "." is an upward referral (F258); "example.test." is a self referral (F259).
	for _, owner := range []string{".", "example.test."} {
		mt := newMockTransport()
		lameDelegation(mt, owner)
		resp, err := rhResolver(mt).Resolve(context.Background(), "www.example.test.", protocol.TypeA)
		if err != nil || resp == nil || resp.Header.Flags.RCODE != protocol.RcodeSuccess || len(resp.Answers) != 1 {
			t.Fatalf("lame owner %q: got resp=%v err=%v, want NOERROR from the healthy server", owner, resp, err)
		}
	}
}

func TestResolve_SelfReferralDoesNotLoop(t *testing.T) {
	mt := newMockTransport()
	lameDelegation(mt, "example.test.")
	mt.setHandler("5.5.5.5:53", mt.handler["4.4.4.4:53"]) // both servers loop
	resp, err := rhResolver(mt).Resolve(context.Background(), "www.example.test.", protocol.TypeA)
	if err != nil || resp == nil || resp.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Fatalf("got resp=%v err=%v, want SERVFAIL", resp, err)
	}
	if n := len(mt.getCalls()); n > 3 {
		t.Fatalf("self-referral loop sent %d queries, want <= 3 (root + each server once)", n)
	}
}
