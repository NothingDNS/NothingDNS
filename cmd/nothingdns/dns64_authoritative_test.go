package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/dns64"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

// RFC 6147 §5.1: a DNS64 that is authoritative examines "its own results"
// for the AAAA RRset and, finding none, synthesizes from the A RRset — names
// in zones this server hosts are reachable from IPv6-only clients too (F875).
func TestDNS64SynthesizesFromLocalZone(t *testing.T) {
	h := newTestHandler()
	synth, err := dns64.NewSynthesizer("", 0) // 64:ff9b::/96
	if err != nil {
		t.Fatal(err)
	}
	h.security.DNS64Synth = synth
	h.zones["local.test."] = loadTestZoneFile(t, "local.test.", `$ORIGIN local.test.
$TTL 300
@   IN SOA ns1.local.test. admin.local.test. ( 1 3600 600 86400 120 )
@   IN NS  ns1.local.test.
ns1 IN A   192.0.2.53
www IN A   192.0.2.10
v6  IN A   192.0.2.11
v6  IN AAAA 2001:db8::11
alias IN CNAME www
`)
	h.RebuildZoneTree()
	ask := func(name string) *protocol.Message {
		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, newTestQuery(t, name, protocol.TypeAAAA))
		if w.msg == nil {
			t.Fatalf("%s: no response", name)
		}
		return w.msg
	}
	for i := 0; i < 2; i++ { // the second answer comes from the authoritative cache
		m := ask("www.local.test.")
		if len(m.Answers) != 1 {
			t.Fatalf("pass %d: www.local.test. AAAA answers %d, want 1 synthesized", i, len(m.Answers))
		}
		a, ok := m.Answers[0].Data.(*protocol.RDataAAAA)
		if !ok || a.String() != "64:ff9b::c000:20a" || m.Answers[0].TTL > 120 {
			t.Fatalf("pass %d: answer %v (TTL %d), want 64:ff9b::c000:20a with TTL <= 120", i, m.Answers[0], m.Answers[0].TTL)
		}
	}
	// Through an in-zone CNAME the chain is kept (RFC 6147 §5.3.1).
	if m := ask("alias.local.test."); len(m.Answers) != 2 || m.Answers[0].Type != protocol.TypeCNAME ||
		m.Answers[1].Data.(*protocol.RDataAAAA).String() != "64:ff9b::c000:20a" {
		t.Fatalf("alias.local.test.: %v", m.Answers)
	}
	// A real AAAA is served as is.
	if m := ask("v6.local.test."); len(m.Answers) != 1 || m.Answers[0].Data.(*protocol.RDataAAAA).String() != "2001:db8::11" {
		t.Fatalf("v6.local.test.: %v", m.Answers)
	}
	// A name that does not exist stays NXDOMAIN.
	if m := ask("nope.local.test."); m.Header.Flags.RCODE != protocol.RcodeNameError || len(m.Answers) != 0 {
		t.Fatalf("nope.local.test.: rcode %d answers %d", m.Header.Flags.RCODE, len(m.Answers))
	}
}
