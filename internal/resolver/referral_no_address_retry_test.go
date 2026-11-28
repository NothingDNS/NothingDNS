package resolver

import (
	"context"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func resolveThroughReferral(t *testing.T, broken, backup, qmin bool) (uint8, int) {
	t.Helper()
	mt := newMockTransport()
	const primary = "192.0.2.1:53"
	const secondary = "192.0.2.2:53"
	const nameserver = "192.0.2.3:53"
	mt.setHandler(primary, func(q *protocol.Message) *protocol.Message {
		if q.Questions[0].Name.String() == "ns.outside." || q.Questions[0].Name.String() == "outside." {
			return rcodeServer(protocol.RcodeNameError, true, false)(q)
		}
		r := rhReply(q)
		if broken {
			r.Authorities = append(r.Authorities, rhNS("example.", "ns.outside."))
		} else {
			r.Authorities = append(r.Authorities, rhNS("example.", "ns.example."))
			r.Additionals = append(r.Additionals, rhA("ns.example.", [4]byte{192, 0, 2, 3}))
		}
		return r
	})
	mt.setHandler(secondary, func(q *protocol.Message) *protocol.Message {
		if q.Questions[0].Name.String() == "ns.outside." || q.Questions[0].Name.String() == "outside." {
			return rcodeServer(protocol.RcodeNameError, true, false)(q)
		}
		r := rhReply(q)
		r.Authorities = append(r.Authorities, rhNS("example.", "ns.example."))
		r.Additionals = append(r.Additionals, rhA("ns.example.", [4]byte{192, 0, 2, 3}))
		return r
	})
	mt.setHandler(nameserver, healthyServer)
	cfg := DefaultConfig()
	cfg.MaxDepth = 4
	cfg.QnameMinimization = qmin
	cfg.AllowPrivateUpstream = true
	cfg.Hints = []RootHint{{Name: "primary.example.", IPv4: []string{"192.0.2.1"}}}
	if backup {
		// The initial two-way rotation starts at index one.
		cfg.Hints = append([]RootHint{{Name: "secondary.example.", IPv4: []string{"192.0.2.2"}}}, cfg.Hints...)
	}
	resp, err := NewResolver(cfg, nil, mt).Resolve(context.Background(), "www.example.", protocol.TypeA)
	if err != nil || resp == nil {
		t.Fatalf("resolve: response=%v err=%v", resp, err)
	}
	return resp.Header.Flags.RCODE, countCalls(mt, nameserver)
}

func TestResolveRetriesReferralWithoutNameserverAddress_F897(t *testing.T) {
	if code, n := resolveThroughReferral(t, true, true, false); code != protocol.RcodeSuccess || n != 1 {
		t.Fatalf("REGRESSION: RCODE=%d child queries=%d, want NOERROR and one child query", code, n)
	}
}
