package resolver

import (
	"context"
	"errors"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// Regression tests for F422 (error-rcode / empty replies not treated as
// lame), F423 (non-AA negative answers accepted and cached) and F424
// (context cancellation reported as a synthesized SERVFAIL).

type lameHandler func(msg *protocol.Message) *protocol.Message

// twoServerDelegation wires root 1.1.1.1 to refer example.test to ns1
// (4.4.4.4) and ns2 (5.5.5.5), listing ns1 first when ns1First is set.
func twoServerDelegation(mt *mockTransport, ns1First bool, ns1, ns2 lameHandler) {
	mt.setHandler("1.1.1.1:53", func(msg *protocol.Message) *protocol.Message {
		r := rhReply(msg)
		recs := [][2]*protocol.ResourceRecord{
			{rhNS("example.test.", "ns1.example.test."), rhA("ns1.example.test.", [4]byte{4, 4, 4, 4})},
			{rhNS("example.test.", "ns2.example.test."), rhA("ns2.example.test.", [4]byte{5, 5, 5, 5})},
		}
		if !ns1First {
			recs[0], recs[1] = recs[1], recs[0]
		}
		for _, rr := range recs {
			r.Authorities = append(r.Authorities, rr[0])
			r.Additionals = append(r.Additionals, rr[1])
		}
		return r
	})
	mt.setHandler("4.4.4.4:53", ns1)
	mt.setHandler("5.5.5.5:53", ns2)
}

func healthyServer(msg *protocol.Message) *protocol.Message {
	r := rhReply(msg)
	r.Header.Flags.AA = true
	r.Answers = append(r.Answers, rhA(msg.Questions[0].Name.String(), [4]byte{9, 9, 9, 9}))
	return r
}

func rcodeServer(rc uint8, aa bool, withSOA bool) lameHandler {
	return func(msg *protocol.Message) *protocol.Message {
		r := rhReply(msg)
		r.Header.Flags.RCODE = rc
		r.Header.Flags.AA = aa
		if withSOA {
			r.Authorities = append(r.Authorities, makeSOARR("example.test."))
		}
		return r
	}
}

// refusedWithReferral answers REFUSED but carries an in-bailiwick child
// referral; it must not be followed.
func refusedWithReferral(msg *protocol.Message) *protocol.Message {
	r := rhReply(msg)
	r.Header.Flags.RCODE = protocol.RcodeRefused
	r.Authorities = append(r.Authorities, rhNS("www.example.test.", "ns.www.example.test."))
	r.Additionals = append(r.Additionals, rhA("ns.www.example.test.", [4]byte{6, 6, 6, 6}))
	return r
}

func lameTestResolver(mt *mockTransport, cache Cache) *Resolver {
	cfg := DefaultConfig()
	cfg.Hints = []RootHint{{Name: "a.root.test.", IPv4: []string{"1.1.1.1"}}}
	return NewResolver(cfg, cache, mt)
}

func countCalls(mt *mockTransport, addr string) int {
	n := 0
	for _, a := range mt.getCalls() {
		if a == addr {
			n++
		}
	}
	return n
}

func TestResolve_ErrorRcodeServerIsLame(t *testing.T) {
	bad := map[string]lameHandler{
		"SERVFAIL":        rcodeServer(protocol.RcodeServerFailure, false, false),
		"REFUSED":         rcodeServer(protocol.RcodeRefused, false, false),
		"empty NOERROR":   rcodeServer(protocol.RcodeSuccess, false, false),
		"REFUSED with NS": refusedWithReferral,
	}
	for label, h := range bad {
		for _, ns1First := range []bool{true, false} {
			mt := newMockTransport()
			mt.setHandler("6.6.6.6:53", healthyServer) // reachable only via the refused "referral"
			twoServerDelegation(mt, ns1First, h, healthyServer)
			resp, err := lameTestResolver(mt, nil).Resolve(context.Background(), "www.example.test.", protocol.TypeA)
			if err != nil || resp == nil || resp.Header.Flags.RCODE != protocol.RcodeSuccess || len(resp.Answers) != 1 {
				t.Fatalf("%s (ns1First=%v): resp=%v err=%v, want NOERROR from the healthy server", label, ns1First, resp, err)
			}
			if n := countCalls(mt, "6.6.6.6:53"); n != 0 {
				t.Fatalf("%s: followed NS records of an error-rcode reply (%d queries)", label, n)
			}
			if n := countCalls(mt, "4.4.4.4:53"); n > 1 {
				t.Fatalf("%s: lame server queried %d times, want <= 1", label, n)
			}
		}

		// Every server broken: SERVFAIL after one query per server, not a
		// MaxDepth-long retry loop.
		mt := newMockTransport()
		twoServerDelegation(mt, true, h, h)
		resp, err := lameTestResolver(mt, nil).Resolve(context.Background(), "www.example.test.", protocol.TypeA)
		if err != nil || resp == nil || resp.Header.Flags.RCODE != protocol.RcodeServerFailure {
			t.Fatalf("%s on all servers: resp=%v err=%v, want SERVFAIL", label, resp, err)
		}
		if n := countCalls(mt, "4.4.4.4:53") + countCalls(mt, "5.5.5.5:53"); n != 2 {
			t.Fatalf("%s on all servers: %d delegation queries, want 2", label, n)
		}
	}
}

func TestResolve_NonAuthoritativeNegativeIsLame(t *testing.T) {
	bad := map[string]lameHandler{
		"non-AA NXDOMAIN":     rcodeServer(protocol.RcodeNameError, false, false),
		"non-AA NXDOMAIN+SOA": rcodeServer(protocol.RcodeNameError, false, true),
		"non-AA NODATA":       rcodeServer(protocol.RcodeSuccess, false, true),
	}
	for label, h := range bad {
		for _, ns1First := range []bool{true, false} {
			mt := newMockTransport()
			twoServerDelegation(mt, ns1First, h, healthyServer)
			cache := newMockCache()
			resp, err := lameTestResolver(mt, cache).Resolve(context.Background(), "www.example.test.", protocol.TypeA)
			if err != nil || resp == nil || resp.Header.Flags.RCODE != protocol.RcodeSuccess || len(resp.Answers) != 1 {
				t.Fatalf("%s (ns1First=%v): resp=%v err=%v, want NOERROR from the healthy server", label, ns1First, resp, err)
			}
			if len(cache.negatives) != 0 {
				t.Fatalf("%s (ns1First=%v): cached non-authoritative negative %v", label, ns1First, cache.negatives)
			}
		}
		mt := newMockTransport()
		twoServerDelegation(mt, true, h, h)
		cache := newMockCache()
		resp, err := lameTestResolver(mt, cache).Resolve(context.Background(), "www.example.test.", protocol.TypeA)
		if err != nil || resp == nil || resp.Header.Flags.RCODE != protocol.RcodeServerFailure || len(cache.negatives) != 0 {
			t.Fatalf("%s on all servers: resp=%v err=%v negatives=%v, want uncached SERVFAIL", label, resp, err, cache.negatives)
		}
	}

	// Control: an authoritative NXDOMAIN is still final and cached.
	mt := newMockTransport()
	twoServerDelegation(mt, true, rcodeServer(protocol.RcodeNameError, true, true), healthyServer)
	cache := newMockCache()
	resp, err := lameTestResolver(mt, cache).Resolve(context.Background(), "www.example.test.", protocol.TypeA)
	if err != nil || resp == nil || resp.Header.Flags.RCODE != protocol.RcodeNameError || len(cache.negatives) != 1 {
		t.Fatalf("AA NXDOMAIN: resp=%v err=%v negatives=%v, want cached NXDOMAIN", resp, err, cache.negatives)
	}
}

func TestResolve_ContextCancelReturnsCtxErr(t *testing.T) {
	mt := newMockTransport()
	twoServerDelegation(mt, true, healthyServer, healthyServer)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, err := lameTestResolver(mt, nil).Resolve(ctx, "www.example.test.", protocol.TypeA)
	if !errors.Is(err, context.Canceled) || resp != nil {
		t.Fatalf("pre-cancelled: resp=%v err=%v, want nil, context.Canceled", resp, err)
	}

	// Gated: the delegation server cancels the caller's context when the
	// query reaches it.
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	mt = newMockTransport()
	twoServerDelegation(mt, true, func(msg *protocol.Message) *protocol.Message {
		cancel()
		return nil
	}, func(msg *protocol.Message) *protocol.Message {
		cancel()
		return nil
	})
	resp, err = lameTestResolver(mt, nil).Resolve(ctx, "www.example.test.", protocol.TypeA)
	if !errors.Is(err, context.Canceled) || resp != nil {
		t.Fatalf("cancelled mid-resolution: resp=%v err=%v, want nil, context.Canceled", resp, err)
	}

	// Control: upstream failure with a live context is still SERVFAIL, nil.
	mt = newMockTransport()
	twoServerDelegation(mt, true, rcodeServer(protocol.RcodeServerFailure, false, false), rcodeServer(protocol.RcodeServerFailure, false, false))
	resp, err = lameTestResolver(mt, nil).Resolve(context.Background(), "www.example.test.", protocol.TypeA)
	if err != nil || resp == nil || resp.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Fatalf("live ctx: resp=%v err=%v, want SERVFAIL, nil", resp, err)
	}
}
