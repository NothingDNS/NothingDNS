package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/resolver"
)

// With only the iterative resolver, a local CNAME to an outside name is
// chased like a direct query (RFC 1034 §4.3.2 step 3a), not answered with
// the bare CNAME unless the target happened to be cached (F889).
func TestCNAMEOutsideTargetUsesIterativeResolver(t *testing.T) {
	h := newTestHandler()
	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Answers: []*protocol.ResourceRecord{
			{Name: mustParseName(t, "ext.example.net."), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{5, 6, 7, 8}}},
		},
	}
	resp.Header.Flags.AA = true
	h.resolver = resolver.NewResolver(resolver.Config{}, nil, &mockResolverTransport{resp: resp})
	h.zones["local.test."] = loadTestZoneFile(t, "local.test.", `$ORIGIN local.test.
$TTL 300
@   IN SOA ns1.local.test. admin.local.test. ( 1 3600 600 86400 120 )
@   IN NS  ns1.local.test.
ns1 IN A   192.0.2.53
alias IN CNAME ext.example.net.
`)
	h.RebuildZoneTree()
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "alias.local.test.", protocol.TypeA))
	if w.msg == nil || len(w.msg.Answers) != 2 || w.msg.Answers[1].Type != protocol.TypeA {
		t.Fatalf("alias.local.test. A: %v, want the CNAME and the target's A", w.msg)
	}
}
