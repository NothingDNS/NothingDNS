package main

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const internalViewZone = `$ORIGIN view.test.
$TTL 3600
@        IN  SOA ns1.view.test. admin.view.test. ( 1 3600 600 86400 300 )
@        IN  NS  ns1.view.test.
ns1      IN  A   10.0.0.1
www      IN  A   10.0.0.10
secret   IN  A   10.0.0.99
alias    IN  CNAME secret.view.test.
chain1   IN  CNAME chain2.view.test.
chain2   IN  CNAME www.view.test.
loopa    IN  CNAME loopb.view.test.
loopb    IN  CNAME loopa.view.test.
`

const externalViewZone = `$ORIGIN view.test.
$TTL 3600
@        IN  SOA ns1.view.test. admin.view.test. ( 1 3600 600 86400 300 )
@        IN  NS  ns1.view.test.
ns1      IN  A   192.0.2.1
www      IN  A   192.0.2.10
alias    IN  CNAME www.view.test.
`

// viewTestHandler wires two horizons over the same zone name: loopback is
// "internal", everything else is "external".
func viewTestHandler(t *testing.T) *integratedHandler {
	t.Helper()
	h := newTestHandler()
	h.config.Resolution.AuthoritativeOnly = true

	views := []filter.ViewConfig{
		{Name: "internal", MatchClients: []string{"127.0.0.0/8"}},
		{Name: "external", MatchClients: []string{"0.0.0.0/0"}},
	}
	sh, err := filter.NewSplitHorizon(views)
	if err != nil {
		t.Fatalf("NewSplitHorizon: %v", err)
	}
	h.splitHorizon = sh
	h.viewZones = map[string]map[string]*zone.Zone{
		"internal": {"view.test.": loadTestZoneFile(t, "internal.view.test.", internalViewZone)},
		"external": {"view.test.": loadTestZoneFile(t, "external.view.test.", externalViewZone)},
	}
	return h
}

func askFrom(t *testing.T, h *integratedHandler, clientIP, qname string, qtype uint16) *protocol.Message {
	t.Helper()
	w := newCaptureWriter(clientIP, "tcp")
	h.ServeDNS(w, newTestQuery(t, qname, qtype))
	if w.msg == nil {
		t.Fatal("no response")
	}
	return w.msg
}

func addressesIn(resp *protocol.Message) []string {
	var out []string
	for _, rr := range resp.Answers {
		if a, ok := rr.Data.(*protocol.RDataA); ok {
			out = append(out, net.IP(a.Address[:]).String())
		}
	}
	return out
}

// TestViewCNAME_IsResolvedInsideTheView is the regression for every CNAME in a
// split-horizon view being unresolvable. handleAuthoritative returns false on
// a CNAME as a signal to chase it; the split-horizon stage passed that signal
// on, and the chase then ran against the global zones, which never contain
// view zones. On an authoritative-only server the query fell all the way
// through to REFUSED — "name is outside all configured zones" — for an alias
// the server was authoritative for.
func TestViewCNAME_IsResolvedInsideTheView(t *testing.T) {
	h := viewTestHandler(t)

	resp := askFrom(t, h, "127.0.0.1", "alias.view.test.", protocol.TypeA)
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", resp.Header.Flags.RCODE)
	}

	var sawCNAME bool
	for _, rr := range resp.Answers {
		if rr.Type == protocol.TypeCNAME {
			sawCNAME = true
		}
	}
	if !sawCNAME {
		t.Error("response carries no CNAME record")
	}
	addrs := addressesIn(resp)
	if len(addrs) != 1 || addrs[0] != "10.0.0.99" {
		t.Errorf("addresses = %v, want [10.0.0.99] from the internal view", addrs)
	}
}

func TestViewCNAME_FollowsAChain(t *testing.T) {
	h := viewTestHandler(t)

	resp := askFrom(t, h, "127.0.0.1", "chain1.view.test.", protocol.TypeA)
	addrs := addressesIn(resp)
	if len(addrs) != 1 || addrs[0] != "10.0.0.10" {
		t.Errorf("addresses = %v, want [10.0.0.10]", addrs)
	}
	cnames := 0
	for _, rr := range resp.Answers {
		if rr.Type == protocol.TypeCNAME {
			cnames++
		}
	}
	if cnames != 2 {
		t.Errorf("%d CNAME records, want 2 for a two-link chain", cnames)
	}
}

// TestViewCNAME_EachHorizonResolvesItsOwn: the same alias must land on
// different data per view, and the chase must not cross horizons.
func TestViewCNAME_EachHorizonResolvesItsOwn(t *testing.T) {
	h := viewTestHandler(t)

	internal := addressesIn(askFrom(t, h, "127.0.0.1", "alias.view.test.", protocol.TypeA))
	external := addressesIn(askFrom(t, h, "192.0.2.50", "alias.view.test.", protocol.TypeA))

	if len(internal) != 1 || internal[0] != "10.0.0.99" {
		t.Errorf("internal = %v, want [10.0.0.99]", internal)
	}
	if len(external) != 1 || external[0] != "192.0.2.10" {
		t.Errorf("external = %v, want [192.0.2.10]", external)
	}
}

// TestViewCNAME_NoLeakAcrossHorizons: names that exist only in the internal
// view must stay invisible from outside, including through the CNAME path.
func TestViewCNAME_NoLeakAcrossHorizons(t *testing.T) {
	h := viewTestHandler(t)

	for _, qname := range []string{"secret.view.test.", "chain1.view.test.", "chain2.view.test."} {
		resp := askFrom(t, h, "192.0.2.50", qname, protocol.TypeA)
		for _, addr := range addressesIn(resp) {
			if len(addr) >= 3 && addr[:3] == "10." {
				t.Errorf("%s: external client received internal address %s", qname, addr)
			}
		}
		if resp.Header.Flags.RCODE == protocol.RcodeSuccess && len(resp.Answers) > 0 {
			t.Errorf("%s: external client got %d answers for an internal-only name",
				qname, len(resp.Answers))
		}
	}
}

// TestViewCNAME_LoopIsDetected: a loop inside a view must SERVFAIL rather than
// spin or fall through to REFUSED.
func TestViewCNAME_LoopIsDetected(t *testing.T) {
	h := viewTestHandler(t)

	resp := askFrom(t, h, "127.0.0.1", "loopa.view.test.", protocol.TypeA)
	if resp.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Errorf("rcode = %d, want SERVFAIL for a CNAME loop", resp.Header.Flags.RCODE)
	}
}

// TestViewCNAME_DirectRecordsStillWork guards the non-CNAME paths through the
// same stage.
func TestViewCNAME_DirectRecordsStillWork(t *testing.T) {
	h := viewTestHandler(t)

	if addrs := addressesIn(askFrom(t, h, "127.0.0.1", "www.view.test.", protocol.TypeA)); len(addrs) != 1 || addrs[0] != "10.0.0.10" {
		t.Errorf("internal www = %v, want [10.0.0.10]", addrs)
	}
	if addrs := addressesIn(askFrom(t, h, "192.0.2.50", "www.view.test.", protocol.TypeA)); len(addrs) != 1 || addrs[0] != "192.0.2.10" {
		t.Errorf("external www = %v, want [192.0.2.10]", addrs)
	}
}
