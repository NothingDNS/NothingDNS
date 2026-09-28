// Round-028 proof: extractDelegation keys the glue-address map by the RAW-CASE
// owner name, but every consumer looks it up by the NS target's raw-case name.
// DNS names are case-insensitive, and this resolver's own bailiwick/nsTargets
// filters normalize with ToLower — so a referral whose NS target and its glue
// differ only in case is ACCEPTED by the gate and then silently lost.
//
// DEFECT (internal/resolver/resolver.go, extractDelegation):
//
//	nsTargets[strings.ToLower(strings.TrimSuffix(n, "."))] = true   // line 737 (LOWERCASED)
//	...
//	ownerKey := strings.ToLower(strings.TrimSuffix(owner, "."))     // line 752 (LOWERCASED)
//	if !nsTargets[ownerKey] { continue }                             // gate PASSES
//	deleg.addrs[owner] = append(...)                                 // line 767 (RAW CASE key)
//
// while deleg.nsNames holds ns.NSDName.String() (RAW CASE, line 725). Every
// consumer then looks the address up under the raw-case NS name and misses:
//
//	queryDelegation:  addrs = append(addrs, deleg.addrs[nsName]...)  // line 578
//	resolveNSAddresses: if len(deleg.addrs[nsName]) > 0 { continue }  // line 797
//	hasAnyAddress:      if len(deleg.addrs[nsName]) > 0 { return true } // line 1274
//
// IMPACT. A referral that supplies perfectly valid in-bailiwick glue for a
// listed NS target is treated as if it carried no address at all: hasAnyAddress
// is false, resolve() does `continue` (line 556-558), and after MaxDepth the
// query SERVFAILs — even though the delegation was fully usable. RFC 4343 §4
// makes DNS names case-insensitive, so this resolver must match them that way;
// it already does for the bailiwick and nsTargets comparisons, which is what
// makes the raw-case store inconsistent with its own gate. This resolver also
// supports 0x20 case randomization (Use0x20), so it necessarily sees
// mixed-case names on the wire.
//
// REACHABILITY. Any authoritative server (or an off-path attacker who can pass
// the bailiwick filter) that returns the NS target and its glue with differing
// case — legal per RFC 4343 — triggers it. The test drives the REAL resolve()
// loop over a fake Transport so the defect surfaces exactly as it would in
// production: the glue is present and accepted, yet the delegation is dropped.
package resolver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

const (
	refGlueIP   = "93.184.216.34" // public; survives the SSRF private-IP filter
	refRootAddr = "127.0.0.1:53"
	refGlueAddr = "93.184.216.34:53"
)

// caseReferralTransport answers like an authoritative server whose referral for
// qname delegates to nsTarget, supplying glue A rr for glueOwner.
//
// glueOwner is the owner name written on the glue A record. When it differs in
// case from nsTarget, the delegation still passes extractDelegation's nsTargets
// gate (which lowercases) but its address is stored under the raw-case owner
// and is therefore invisible to every consumer.
type caseReferralTransport struct {
	nsTarget  string // NSDName placed in the NS record (RAW case, as on the wire)
	glueOwner string // owner name on the glue A record
	target    string // the name being resolved

	rootQueries int
	glueQueries int
}

func (t *caseReferralTransport) QueryContext(ctx context.Context, msg *protocol.Message, addr string) (*protocol.Message, error) {
	qname := ""
	if len(msg.Questions) > 0 && msg.Questions[0] != nil && msg.Questions[0].Name != nil {
		qname = msg.Questions[0].Name.String()
	}

	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    msg.Header.ID,
			Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
		},
	}

	switch {
	// A glueless NS-name lookup: the zone cut is trying to resolve the NS
	// target on its own. Fail it so the ONLY source of an address is the glue
	// record under test.
	case strings.EqualFold(qname, t.nsTarget):
		resp.Header.Flags.RCODE = protocol.RcodeNameError // NXDOMAIN
		return resp, nil

	case addr == refGlueAddr:
		t.glueQueries++
		owner, err := protocol.ParseName(t.target)
		if err != nil {
			return nil, err
		}
		resp.Header.Flags.AA = true
		resp.AddAnswer(&protocol.ResourceRecord{
			Name: owner, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 60,
			Data: &protocol.RDataA{Address: [4]byte{198, 41, 0, 4}},
		})
		return resp, nil

	case addr == refRootAddr:
		t.rootQueries++
		zoneOwner, err := protocol.ParseName(t.target)
		if err != nil {
			return nil, err
		}
		nsName, err := protocol.ParseName(t.nsTarget)
		if err != nil {
			return nil, err
		}
		glueOwner, err := protocol.ParseName(t.glueOwner)
		if err != nil {
			return nil, err
		}
		// Referral: NS in Authority, glue A in Additional, no answers, AA clear.
		resp.AddAuthority(&protocol.ResourceRecord{
			Name: zoneOwner, Type: protocol.TypeNS, Class: protocol.ClassIN, TTL: 172800,
			Data: &protocol.RDataNS{NSDName: nsName},
		})
		resp.AddAdditional(&protocol.ResourceRecord{
			Name: glueOwner, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 172800,
			Data: &protocol.RDataA{Address: [4]byte{93, 184, 216, 34}},
		})
		return resp, nil
	}
	return resp, nil
}

func newCaseReferralResolver(tr Transport) *Resolver {
	return NewResolver(Config{
		MaxDepth: 3,
		Timeout:  2 * time.Second,
		Use0x20:  false,
		Hints:    []RootHint{{Name: "fake.root.", IPv4: []string{"127.0.0.1"}}},
	}, nil, tr)
}

// TestReferral_GlueCaseMismatchIsHonored is the CLAIM: a referral whose NS
// target and glue differ only in case must still be followed. DNS name matching
// is case-insensitive (RFC 4343 §4), so the supplied glue is authoritative
// evidence of the NS address and must be used.
func TestReferral_GlueCaseMismatchIsHonored(t *testing.T) {
	// NS target uppercase, glue owner lowercase — the same name to DNS.
	tr := &caseReferralTransport{
		nsTarget:  "NS1.Example.COM.",
		glueOwner: "ns1.example.com.",
		target:    "www.example.com.",
	}
	r := newCaseReferralResolver(tr)

	msg, err := r.Resolve(context.Background(), "www.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if msg == nil {
		t.Fatalf("harness setup: Resolve returned nil")
	}

	if msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("FAIL: referral supplied valid in-bailiwick glue for its NS target, but "+
			"the mixed-case owner (%q vs NS target %q) made the resolver drop the "+
			"delegation and SERVFAIL (rcode=%s, rootQueries=%d, glueQueries=%d). "+
			"DNS names are case-insensitive, so this glue must be honored.",
			tr.glueOwner, tr.nsTarget, protocol.RcodeString(int(msg.Header.Flags.RCODE)),
			tr.rootQueries, tr.glueQueries)
	}
	if tr.glueQueries == 0 {
		t.Fatalf("FAIL: resolver never queried the glue address %s; the delegation "+
			"was dropped before the supplied glue could be used (rootQueries=%d).",
			refGlueAddr, tr.rootQueries)
	}
	t.Logf("PASS: mixed-case glue followed; answered via %s", refGlueAddr)
}

// TestReferral_GlueExactCaseStillFollowed is the CONTROL: a referral whose NS
// target and glue already share the exact same case must be followed both
// before and after the fix. A harness that merely broke delegation handling
// would fail this.
func TestReferral_GlueExactCaseStillFollowed(t *testing.T) {
	tr := &caseReferralTransport{
		nsTarget:  "ns1.example.com.",
		glueOwner: "ns1.example.com.",
		target:    "www.example.com.",
	}
	r := newCaseReferralResolver(tr)

	msg, err := r.Resolve(context.Background(), "www.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if msg == nil {
		t.Fatalf("harness setup: Resolve returned nil")
	}
	if msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("FAIL (control): exact-case glue referral must resolve; got rcode=%s "+
			"(rootQueries=%d, glueQueries=%d)",
			protocol.RcodeString(int(msg.Header.Flags.RCODE)), tr.rootQueries, tr.glueQueries)
	}
	if tr.glueQueries == 0 {
		t.Fatalf("FAIL (control): resolver never queried the glue address %s",
			refGlueAddr)
	}
	t.Logf("PASS: exact-case glue followed")
}
