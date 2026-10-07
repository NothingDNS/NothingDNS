package main

// Regression tests for P2-E6 (F512–F515): wildcard-expanded answers from a
// signed zone are signed at the wildcard owner and carry the no-closer-match
// proof; wildcard NODATA in NSEC mode carries the QNAME cover; names below a
// DNAME are occluded — absent from the denial chain and redirected rather
// than answered. Verdicts come from internal/dnssec's Validator, whose
// fetches are answered by the real handler (odcSetup).

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

var wdModes = []struct {
	name  string
	nsec3 *config.NSEC3Config
}{
	{"NSEC", nil},
	{"NSEC3", &config.NSEC3Config{}},
	{"NSEC3-salt-iter", &config.NSEC3Config{Iterations: 3, Salt: "ABCD"}},
	{"NSEC3-optout", &config.NSEC3Config{Iterations: 1, Salt: "ABCD", OptOut: true}},
}

func wdSetup(t *testing.T, nsec3 *config.NSEC3Config) *odcEnv {
	t.Helper()
	e := odcSetup(t, nsec3)
	z := e.h.zones["odc.test."]
	extra := loadTestZoneFile(t, "odc.test.", `$ORIGIN odc.test.
$TTL 3600
@         IN SOA ns1.odc.test. admin.odc.test. ( 1 3600 600 86400 300 )
*.wild    IN A  192.0.2.71
m.wild    IN A  192.0.2.80
*.wc      IN CNAME www.odc.test.
dn        IN DNAME target.example.
x.dn      IN A  192.0.2.90
y.z.dn    IN A  192.0.2.91
`)
	for name, recs := range extra.Records {
		for _, r := range recs {
			if r.Type != "SOA" {
				z.Records[name] = append(z.Records[name], r)
			}
		}
	}
	e.h.RebuildZoneTree()
	return e
}

func wdSigLabels(rrs []*protocol.ResourceRecord, typ uint16) int {
	for _, rr := range rrs {
		if s, ok := rr.Data.(*protocol.RDataRRSIG); ok && s.TypeCovered == typ {
			return int(s.Labels)
		}
	}
	return -1
}

func wdDenials(rrs []*protocol.ResourceRecord) []string {
	var out []string
	for _, rr := range rrs {
		switch d := rr.Data.(type) {
		case *protocol.RDataNSEC:
			out = append(out, strings.ToLower(rr.Name.String())+"->"+strings.ToLower(d.NextDomain.String()))
		case *protocol.RDataNSEC3:
			out = append(out, strings.ToLower(rr.Name.String()))
		}
	}
	return out
}

// TestWildcardAnswer_SignedAtWildcardWithProof_F512: the RRSIG Labels field
// marks the expansion (labels of *.wild.odc.test. minus the "*") and the
// authority section proves no closer match (RFC 4035 §3.1.3.3, RFC 5155
// §7.2.6). Before the fix the RRset was signed as if QNAME existed, with no
// proof, and a.b.wild.odc.test. validated BOGUS.
func TestWildcardAnswer_SignedAtWildcardWithProof_F512(t *testing.T) {
	for _, m := range wdModes {
		e := wdSetup(t, m.nsec3)
		for _, q := range []struct {
			n  string
			qt uint16
		}{{"a.wild.odc.test.", protocol.TypeA}, {"a.b.wild.odc.test.", protocol.TypeA}, {"q.wc.odc.test.", protocol.TypeCNAME}} {
			r := dnssecRegAsk(t, e.h, q.n, q.qt)
			if got := wdSigLabels(r.Answers, q.qt); got != 3 {
				t.Errorf("%s %s: RRSIG labels %d, want 3", m.name, q.n, got)
			}
			if len(wdDenials(r.Authorities)) == 0 {
				t.Errorf("%s %s: no NSEC/NSEC3 proof in authority", m.name, q.n)
			}
			// RFC 5155 §9.2: a next-closer cover with opt-out leaves the
			// wildcard answer unauthenticated (INSECURE, P2-E8 validator).
			want := "SECURE"
			if m.nsec3 != nil && m.nsec3.OptOut {
				want = "INSECURE"
			}
			if v := e.verdict(r, q.n); v != want {
				t.Errorf("%s %s: verdict %s, want %s", m.name, q.n, v, want)
			}
			stripped := *r
			stripped.Authorities = nil
			if v := e.verdict(&stripped, q.n); v != "BOGUS" {
				t.Errorf("%s %s: proof stripped -> %s, want BOGUS", m.name, q.n, v)
			}
		}
		// Wildcard CNAME answering another type (F303 path) gets the same.
		r := dnssecRegAsk(t, e.h, "q.wc.odc.test.", protocol.TypeA)
		if wdSigLabels(r.Answers, protocol.TypeCNAME) != 3 || len(wdDenials(r.Authorities)) == 0 {
			t.Errorf("%s wildcard CNAME/A: labels %d proof %v", m.name, wdSigLabels(r.Answers, protocol.TypeCNAME), wdDenials(r.Authorities))
		}
		// Control: an explicit name is signed as itself, with no proof.
		r = dnssecRegAsk(t, e.h, "m.wild.odc.test.", protocol.TypeA)
		if wdSigLabels(r.Answers, protocol.TypeA) != 4 || len(r.Authorities) != 0 || e.verdict(r, "m.wild.odc.test.") != "SECURE" {
			t.Errorf("%s explicit m.wild: labels %d auth %d", m.name, wdSigLabels(r.Answers, protocol.TypeA), len(r.Authorities))
		}
	}
}

// TestWildcardNoData_NSECCoversQName_F513: RFC 4035 §3.1.3.4 needs an NSEC
// proving QNAME does not exist besides the wildcard's NSEC. Before the fix
// only the wildcard NSEC was sent, which covers z.wild only when no other
// name sorts between them (here m.wild does) — BOGUS.
func TestWildcardNoData_NSECCoversQName_F513(t *testing.T) {
	e := wdSetup(t, nil)
	for _, n := range []string{"a.wild.odc.test.", "z.wild.odc.test.", "x.y.wild.odc.test."} {
		r := dnssecRegAsk(t, e.h, n, protocol.TypeAAAA)
		if v := e.verdict(r, n); v != "SECURE" {
			t.Errorf("%s/AAAA: verdict %s, denial %v", n, v, wdDenials(r.Authorities))
		}
	}
}

// TestDenialChain_ExcludesNamesBelowDNAME_F514: data below a DNAME owner is
// occluded (RFC 6672 §2.4) and must not appear in the NSEC/NSEC3 chain.
func TestDenialChain_ExcludesNamesBelowDNAME_F514(t *testing.T) {
	for _, m := range wdModes {
		e := wdSetup(t, m.nsec3)
		c := e.h.denialChainFor(e.h.zones["odc.test."])
		for n := range c.nodes {
			if strings.HasSuffix(n, ".dn.odc.test.") {
				t.Errorf("%s: occluded name %s in the chain", m.name, n)
			}
		}
		if !c.isNode("dn.odc.test.") {
			t.Errorf("%s: DNAME owner missing from the chain", m.name)
		}
		r := dnssecRegAsk(t, e.h, "dn.odc.test.", protocol.TypeMX)
		if v := e.verdict(r, "dn.odc.test."); v != "SECURE" {
			t.Errorf("%s dn/MX: verdict %s", m.name, v)
		}
		for _, d := range wdDenials(r.Authorities) {
			if strings.Contains(d, ".dn.odc.test.") {
				t.Errorf("%s: served NSEC names an occluded name: %s", m.name, d)
			}
		}
	}
}

// TestDNAME_RedirectsOccludedNames_F515: a name below a DNAME is redirected
// even when the zone file holds data for it (RFC 6672 §2.4, RFC 1034
// §4.3.2); before the fix x.dn.odc.test./A was answered — and signed — from
// the occluded record.
func TestDNAME_RedirectsOccludedNames_F515(t *testing.T) {
	e := wdSetup(t, nil)
	for _, n := range []string{"x.dn.odc.test.", "y.z.dn.odc.test.", "other.dn.odc.test."} {
		r := dnssecRegAsk(t, e.h, n, protocol.TypeA)
		if len(r.Answers) == 0 || r.Answers[0].Type != protocol.TypeDNAME {
			t.Errorf("%s/A: answers %v, want DNAME first", n, r.Answers)
		}
	}
	if r := dnssecRegAsk(t, e.h, "dn.odc.test.", protocol.TypeA); len(r.Answers) != 0 {
		t.Errorf("DNAME owner dn/A redirected: %v", r.Answers)
	}
}
