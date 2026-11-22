package main

import (
	"os"
	"testing"

	"github.com/nothingdns/nothingdns/internal/dns64"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/rpz"
	"github.com/nothingdns/nothingdns/internal/zone"
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

// Split-horizon views answer from their own zones (splitHorizonStage,
// answerViewCNAME), and DNS64 applies there too, from the view's A RRset
// (F876).
func TestDNS64SynthesizesFromViewZone(t *testing.T) {
	h := newTestHandler()
	h.config.Resolution.AuthoritativeOnly = true
	synth, err := dns64.NewSynthesizer("", 0) // 64:ff9b::/96
	if err != nil {
		t.Fatal(err)
	}
	h.security.DNS64Synth = synth
	sh, err := filter.NewSplitHorizon([]filter.ViewConfig{
		{Name: "internal", MatchClients: []string{"127.0.0.0/8"}},
		{Name: "external", MatchClients: []string{"0.0.0.0/0"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.splitHorizon = sh
	viewZone := func(addr string) string {
		return `$ORIGIN split.test.
$TTL 300
@   IN SOA ns1.split.test. admin.split.test. ( 1 3600 600 86400 120 )
@   IN NS  ns1.split.test.
ns1 IN A   ` + addr + `
www IN A   ` + addr + `
alias IN CNAME www
`
	}
	h.viewZones = map[string]map[string]*zone.Zone{
		"internal": {"split.test.": loadTestZoneFile(t, "internal.split.test.", viewZone("192.0.2.10"))},
		"external": {"split.test.": loadTestZoneFile(t, "external.split.test.", viewZone("198.51.100.10"))},
	}
	for _, tc := range []struct{ client, name, want string }{
		{"127.0.0.1", "www.split.test.", "64:ff9b::c000:20a"},
		{"127.0.0.1", "alias.split.test.", "64:ff9b::c000:20a"},
		{"10.9.9.9", "www.split.test.", "64:ff9b::c633:640a"},
		{"10.9.9.9", "alias.split.test.", "64:ff9b::c633:640a"},
	} {
		m := askFrom(t, h, tc.client, tc.name, protocol.TypeAAAA)
		if len(m.Answers) == 0 {
			t.Fatalf("%s from %s: no answer, want %s", tc.name, tc.client, tc.want)
		}
		last, ok := m.Answers[len(m.Answers)-1].Data.(*protocol.RDataAAAA)
		if !ok || last.String() != tc.want {
			t.Fatalf("%s from %s: %v, want AAAA %s", tc.name, tc.client, m.Answers, tc.want)
		}
	}
}

// An RPZ rule decides a local answer whether or not DNS64 is on (F879): a
// rule triggered by the A answer behind a synthesis answers the AAAA query
// (NXDOMAIN, DROP), as on the forwarding path, and a rule that answered the
// AAAA query itself is not replaced by a synthesis.
func TestDNS64HonoursRPZOnLocalAnswers(t *testing.T) {
	h := newTestHandler()
	synth, err := dns64.NewSynthesizer("", 0)
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
dropme IN A 192.0.2.30
v6bad IN A 192.0.2.20
v6bad IN AAAA 2001:db8::bad
`)
	h.RebuildZoneTree()
	f := t.TempDir() + "/p.rpz"
	body := "$TTL 60\n@ IN SOA ns.rpz. admin.rpz. 1 3600 600 86400 60\n@ IN NS ns.rpz.\n" +
		"32.10.2.0.192.rpz-ip CNAME .\n" +
		"32.30.2.0.192.rpz-ip CNAME rpz-drop.\n" +
		"128.bad.zz.db8.2001.rpz-ip CNAME *.\n"
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	eng := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{f}})
	if err := eng.Load(); err != nil {
		t.Fatal(err)
	}
	h.security.RPZEngine = eng
	ask := func(name string) *protocol.Message {
		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, newTestQuery(t, name, protocol.TypeAAAA))
		return w.msg
	}
	if m := ask("www.local.test."); m == nil || m.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("www.local.test. AAAA: %v, want the RPZ NXDOMAIN", m)
	}
	if m := ask("dropme.local.test."); m != nil {
		t.Errorf("dropme.local.test. AAAA: %v, want no response (rpz-drop)", m)
	}
	if m := ask("v6bad.local.test."); m == nil || len(m.Answers) != 0 {
		t.Errorf("v6bad.local.test. AAAA: %v, want the RPZ NODATA", m)
	}
}
