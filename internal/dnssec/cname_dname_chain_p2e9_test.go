package dnssec

// P2-E9 (F527, F528): CNAME/DNAME chains in a response.
//
//   - F527: the CNAME a DNAME synthesizes is unsigned (RFC 6672 §5.3.1); it is
//     authenticated by checking it is exactly the DNAME's derivation (owner
//     suffix replaced by the DNAME target, TTL not above the DNAME's).
//     Before: every signed DNAME answer was Bogus.
//   - F528: the chain's last name, when the Answer section has no data of
//     the query type there, is a negative answer that its own zone must
//     prove (RFC 6604 §2.1, RFC 4035 §5.4). Before: a stripped target RRset
//     or a forged/unproven NXDOMAIN ending validated Secure.
//
// Uses the zonecut_p2d1_test.go harness (p2d1Zone, p2d1Resolver).

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

type p2e9World struct {
	parent, child *p2d1Zone
	v             *Validator
}

func newP2E9World(t *testing.T, nsec3 bool) *p2e9World {
	t.Helper()
	cfg := DefaultSignerConfig()
	cfg.NSEC3Enabled = nsec3
	soa := func(z string) *protocol.ResourceRecord {
		return p2d1RR(t, z, protocol.TypeSOA, "ns1."+z+" h.example.com. 1 3600 600 86400 300")
	}
	child := p2d1Sign(t, "sec.example.com.", cfg, soa("sec.example.com."),
		p2d1RR(t, "sec.example.com.", protocol.TypeNS, "ns1.sec.example.com."),
		p2d1RR(t, "www.sec.example.com.", protocol.TypeA, "192.0.2.20"))
	parent := p2d1Sign(t, "example.com.", cfg, soa("example.com."),
		p2d1RR(t, "example.com.", protocol.TypeNS, "ns1.example.com."),
		p2d1RR(t, "www.example.com.", protocol.TypeA, "192.0.2.1"),
		p2d1RR(t, "alias.example.com.", protocol.TypeCNAME, "www.example.com."),
		p2d1RR(t, "alias2.example.com.", protocol.TypeCNAME, "alias.example.com."),
		p2d1RR(t, "nxalias.example.com.", protocol.TypeCNAME, "nothere.example.com."),
		p2d1RR(t, "dn.example.com.", protocol.TypeDNAME, "tgt.example.com."),
		p2d1RR(t, "a.tgt.example.com.", protocol.TypeA, "192.0.2.9"),
		p2d1RR(t, "xz.example.com.", protocol.TypeCNAME, "www.sec.example.com."),
		p2d1RR(t, "xznx.example.com.", protocol.TypeCNAME, "nx.sec.example.com."),
		p2d1RR(t, "sec.example.com.", protocol.TypeNS, "ns1.sec.example.com."),
		child.ds(t))
	ta, err := DSFromDNSKEY("example.com.", parent.signer.GetKSKs()[0].DNSKEY, 2)
	if err != nil {
		t.Fatal(err)
	}
	store := NewTrustAnchorStore()
	store.AddAnchor(ta)
	vcfg := DefaultValidatorConfig()
	vcfg.ValidationCacheTTL = 0
	res := &p2d1Resolver{zones: []*p2d1Zone{parent, child}}
	return &p2e9World{parent: parent, child: child, v: NewValidator(vcfg, store, res)}
}

func p2e9Msg(qname string, qtype uint16, rcode uint8, ans, auth []*protocol.ResourceRecord) *protocol.Message {
	m := p2d1Msg(qname, qtype, ans, auth)
	m.Header.Flags.RCODE = rcode
	return m
}

func p2e9Cat(parts ...[]*protocol.ResourceRecord) []*protocol.ResourceRecord {
	var out []*protocol.ResourceRecord
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func p2e9Synth(t *testing.T, owner, target string, ttl uint32) []*protocol.ResourceRecord {
	t.Helper()
	rr := p2d1RR(t, owner, protocol.TypeCNAME, target)
	rr.TTL = ttl
	return []*protocol.ResourceRecord{rr}
}

// p2e9Signed signs an RRset with z's ZSK (data the zone does not publish).
func p2e9Signed(t *testing.T, z *p2d1Zone, rrs ...*protocol.ResourceRecord) []*protocol.ResourceRecord {
	t.Helper()
	now := time.Now()
	sig, err := z.signer.SignRRSet(rrs, z.signer.GetZSKs()[0], uint32(now.Add(-time.Hour).Unix()), uint32(now.Add(24*time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]*protocol.ResourceRecord{}, rrs...), sig)
}

type p2e9Case struct {
	name, q string
	m       *protocol.Message
	want    ValidationResult
	budget  *responseBudget // nil: default
}

func p2e9Cases(t *testing.T, w *p2e9World) []p2e9Case {
	t.Helper()
	p, c := w.parent, w.child
	pd := p2e9Cat(p.rrset("example.com.", protocol.TypeSOA), p.denial())
	cd := p2e9Cat(c.rrset("sec.example.com.", protocol.TypeSOA), c.denial())
	dname := p.rrset("dn.example.com.", protocol.TypeDNAME)
	alias := p.rrset("alias.example.com.", protocol.TypeCNAME)
	alias2 := p.rrset("alias2.example.com.", protocol.TypeCNAME)
	nxalias := p.rrset("nxalias.example.com.", protocol.TypeCNAME)
	xz := p.rrset("xz.example.com.", protocol.TypeCNAME)
	xznx := p.rrset("xznx.example.com.", protocol.TypeCNAME)
	wwwA := p.rrset("www.example.com.", protocol.TypeA)
	tgtA := p.rrset("a.tgt.example.com.", protocol.TypeA)
	strippedDNAME := []*protocol.ResourceRecord{dname[0]}
	for _, rr := range dname {
		if rr.Type == protocol.TypeDNAME {
			strippedDNAME = []*protocol.ResourceRecord{rr}
		}
	}
	twoSynth := p2e9Cat(p2e9Synth(t, "a.dn.example.com.", "a.tgt.example.com.", 300), p2e9Synth(t, "a.dn.example.com.", "a.tgt.example.com.", 300))
	tiny := newResponseBudget()
	tiny.sigLimit = 3
	var long []*protocol.ResourceRecord
	for i := 0; i < maxRRsetsValidated; i++ {
		long = append(long, p2e9Signed(t, p, p2d1RR(t, fmt.Sprintf("l%d.example.com.", i), protocol.TypeCNAME, fmt.Sprintf("l%d.example.com.", i+1)))...)
	}
	long = append(long, p2e9Signed(t, p, p2d1RR(t, fmt.Sprintf("l%d.example.com.", maxRRsetsValidated), protocol.TypeA, "192.0.2.5"))...)
	loop := p2e9Cat(p2e9Signed(t, p, p2d1RR(t, "loop1.example.com.", protocol.TypeCNAME, "loop2.example.com.")),
		p2e9Signed(t, p, p2d1RR(t, "loop2.example.com.", protocol.TypeCNAME, "loop1.example.com.")))
	ext := p2e9Signed(t, p, p2d1RR(t, "ext.example.com.", protocol.TypeCNAME, "target.example.net."))
	forgedChild := p2e9Signed(t, p, p2d1RR(t, "www.sec.example.com.", protocol.TypeA, "203.0.113.66"))

	const nx = protocol.RcodeNameError
	return []p2e9Case{
		// Controls (unchanged behaviour).
		{"signed CNAME chain", "alias.example.com.", p2e9Msg("alias.example.com.", protocol.TypeA, 0, p2e9Cat(alias, wwwA), nil), ValidationSecure, nil},
		{"two-hop CNAME chain", "alias2.example.com.", p2e9Msg("alias2.example.com.", protocol.TypeA, 0, p2e9Cat(alias2, alias, wwwA), nil), ValidationSecure, nil},
		{"CNAME query answered by the CNAME", "alias.example.com.", p2e9Msg("alias.example.com.", protocol.TypeCNAME, 0, alias, nil), ValidationSecure, nil},
		{"cross-zone chain, child-signed target", "xz.example.com.", p2e9Msg("xz.example.com.", protocol.TypeA, 0, p2e9Cat(xz, c.rrset("www.sec.example.com.", protocol.TypeA)), nil), ValidationSecure, nil},
		{"cross-zone chain, parent-forged target", "xz.example.com.", p2e9Msg("xz.example.com.", protocol.TypeA, 0, p2e9Cat(xz, forgedChild), nil), ValidationBogus, nil},
		{"cross-zone chain charged to the budget", "xz.example.com.", p2e9Msg("xz.example.com.", protocol.TypeA, 0, p2e9Cat(xz, c.rrset("www.sec.example.com.", protocol.TypeA)), nil), ValidationBogus, tiny},
		{"chain above the RRset cap", "l0.example.com.", p2e9Msg("l0.example.com.", protocol.TypeA, 0, long, nil), ValidationBogus, nil},
		{"signed CNAME loop (no terminal)", "loop1.example.com.", p2e9Msg("loop1.example.com.", protocol.TypeA, 0, loop, nil), ValidationSecure, nil},
		// F527: DNAME-synthesized CNAME.
		{"F527 DNAME + synth CNAME + target", "a.dn.example.com.", p2e9Msg("a.dn.example.com.", protocol.TypeA, 0, p2e9Cat(dname, p2e9Synth(t, "a.dn.example.com.", "a.tgt.example.com.", 300), tgtA), nil), ValidationSecure, nil},
		{"F527 mixed-case query name", "A.Dn.Example.COM.", p2e9Msg("A.Dn.Example.COM.", protocol.TypeA, 0, p2e9Cat(dname, p2e9Synth(t, "A.Dn.Example.COM.", "a.tgt.example.com.", 300), tgtA), nil), ValidationSecure, nil},
		{"F527 CNAME query below DNAME", "a.dn.example.com.", p2e9Msg("a.dn.example.com.", protocol.TypeCNAME, 0, p2e9Cat(dname, p2e9Synth(t, "a.dn.example.com.", "a.tgt.example.com.", 300)), nil), ValidationSecure, nil},
		{"F527 synth TTL 0 (RFC 2672 server)", "a.dn.example.com.", p2e9Msg("a.dn.example.com.", protocol.TypeA, 0, p2e9Cat(dname, p2e9Synth(t, "a.dn.example.com.", "a.tgt.example.com.", 0), tgtA), nil), ValidationSecure, nil},
		{"F527 DNAME without synth CNAME", "a.dn.example.com.", p2e9Msg("a.dn.example.com.", protocol.TypeA, 0, p2e9Cat(dname, tgtA), nil), ValidationSecure, nil},
		{"F527 synth TTL above DNAME TTL", "a.dn.example.com.", p2e9Msg("a.dn.example.com.", protocol.TypeA, 0, p2e9Cat(dname, p2e9Synth(t, "a.dn.example.com.", "a.tgt.example.com.", 301), tgtA), nil), ValidationBogus, nil},
		{"F527 synth target not derived", "a.dn.example.com.", p2e9Msg("a.dn.example.com.", protocol.TypeA, 0, p2e9Cat(dname, p2e9Synth(t, "a.dn.example.com.", "www.example.com.", 300), wwwA), nil), ValidationBogus, nil},
		{"F527 synth target one label off", "a.dn.example.com.", p2e9Msg("a.dn.example.com.", protocol.TypeA, 0, p2e9Cat(dname, p2e9Synth(t, "a.dn.example.com.", "tgt.example.com.", 300)), pd), ValidationBogus, nil},
		{"F527 two synth CNAME records", "a.dn.example.com.", p2e9Msg("a.dn.example.com.", protocol.TypeA, 0, p2e9Cat(dname, twoSynth, tgtA), nil), ValidationBogus, nil},
		{"F527 DNAME absent", "a.dn.example.com.", p2e9Msg("a.dn.example.com.", protocol.TypeA, 0, p2e9Cat(p2e9Synth(t, "a.dn.example.com.", "a.tgt.example.com.", 300), tgtA), nil), ValidationBogus, nil},
		{"F527 DNAME RRSIG stripped", "a.dn.example.com.", p2e9Msg("a.dn.example.com.", protocol.TypeA, 0, p2e9Cat(strippedDNAME, p2e9Synth(t, "a.dn.example.com.", "a.tgt.example.com.", 300), tgtA), nil), ValidationBogus, nil},
		{"F527+F528 DNAME -> NXDOMAIN target, proven", "x.dn.example.com.", p2e9Msg("x.dn.example.com.", protocol.TypeA, nx, p2e9Cat(dname, p2e9Synth(t, "x.dn.example.com.", "x.tgt.example.com.", 300)), pd), ValidationSecure, nil},
		{"F527+F528 DNAME -> NXDOMAIN target, unproven", "x.dn.example.com.", p2e9Msg("x.dn.example.com.", protocol.TypeA, nx, p2e9Cat(dname, p2e9Synth(t, "x.dn.example.com.", "x.tgt.example.com.", 300)), nil), ValidationBogus, nil},
		// F528: negative chain endings.
		{"F528 NXDOMAIN target proven", "nxalias.example.com.", p2e9Msg("nxalias.example.com.", protocol.TypeA, nx, nxalias, pd), ValidationSecure, nil},
		{"F528 NXDOMAIN target, proof stripped", "nxalias.example.com.", p2e9Msg("nxalias.example.com.", protocol.TypeA, nx, nxalias, nil), ValidationBogus, nil},
		{"F528 NXDOMAIN target, SOA only", "nxalias.example.com.", p2e9Msg("nxalias.example.com.", protocol.TypeA, nx, nxalias, p.rrset("example.com.", protocol.TypeSOA)), ValidationBogus, nil},
		{"F528 target RRset stripped", "alias.example.com.", p2e9Msg("alias.example.com.", protocol.TypeA, 0, alias, nil), ValidationBogus, nil},
		{"F528 two-hop, target stripped", "alias2.example.com.", p2e9Msg("alias2.example.com.", protocol.TypeA, 0, p2e9Cat(alias2, alias), nil), ValidationBogus, nil},
		{"F528 forged NXDOMAIN for an existing target", "alias.example.com.", p2e9Msg("alias.example.com.", protocol.TypeA, nx, alias, pd), ValidationBogus, nil},
		{"F528 NODATA target proven", "alias.example.com.", p2e9Msg("alias.example.com.", protocol.TypeAAAA, 0, alias, pd), ValidationSecure, nil},
		{"F528 NODATA target, proof stripped", "alias.example.com.", p2e9Msg("alias.example.com.", protocol.TypeAAAA, 0, alias, nil), ValidationBogus, nil},
		{"F528 cross-zone NXDOMAIN, child proof", "xznx.example.com.", p2e9Msg("xznx.example.com.", protocol.TypeA, nx, xznx, cd), ValidationSecure, nil},
		{"F528 cross-zone NXDOMAIN, parent proof", "xznx.example.com.", p2e9Msg("xznx.example.com.", protocol.TypeA, nx, xznx, pd), ValidationBogus, nil},
		{"F528 cross-zone NXDOMAIN, no proof", "xznx.example.com.", p2e9Msg("xznx.example.com.", protocol.TypeA, nx, xznx, nil), ValidationBogus, nil},
		{"F528 target outside every anchor", "ext.example.com.", p2e9Msg("ext.example.com.", protocol.TypeA, 0, ext, nil), ValidationInsecure, nil},
	}
}

func TestValidateResponse_CNAMEDNAMEChain_P2E9(t *testing.T) {
	ctx := context.Background()
	for _, nsec3 := range []bool{false, true} {
		w := newP2E9World(t, nsec3)
		for _, tc := range p2e9Cases(t, w) {
			for i := 0; i < 2; i++ {
				b := newResponseBudget()
				if tc.budget != nil {
					b.sigLimit = tc.budget.sigLimit
				}
				got, err := w.v.validateResponseBudget(ctx, tc.m, tc.q, b)
				if got != tc.want {
					t.Errorf("nsec3=%v %s (run %d): got %v (err %v), want %v", nsec3, tc.name, i, got, err, tc.want)
				}
			}
		}
	}
}

// Unit level: synthesized-CNAME derivation and the chain's terminal name.
func TestWalkAnswerChain_P2E9(t *testing.T) {
	rr := func(owner string, rrtype uint16, text string, ttl uint32) *protocol.ResourceRecord {
		r := p2d1RR(t, owner, rrtype, text)
		r.TTL = ttl
		return r
	}
	msg := func(q string, qt uint16, ans ...*protocol.ResourceRecord) *protocol.Message {
		return p2d1Msg(q, qt, ans, nil)
	}
	long := strings.Repeat(strings.Repeat("a", 60)+".", 3)
	cases := []struct {
		name     string
		m        *protocol.Message
		synth    string // owner expected synthesized ("" none)
		terminal string // "" closed
	}{
		{"DNAME at root of redirect", msg("a.b.dn.example.", protocol.TypeA, rr("dn.example.", protocol.TypeDNAME, "t.example.", 60), rr("a.b.dn.example.", protocol.TypeCNAME, "a.b.t.example.", 60)), "a.b.dn.example.", "a.b.t.example."},
		{"DNAME to root", msg("a.dn.example.", protocol.TypeA, rr("dn.example.", protocol.TypeDNAME, ".", 60), rr("a.dn.example.", protocol.TypeCNAME, "a.", 60)), "a.dn.example.", "a."},
		{"shallowest DNAME wins", msg("a.b.dn.example.", protocol.TypeA, rr("dn.example.", protocol.TypeDNAME, "t.example.", 60), rr("b.dn.example.", protocol.TypeDNAME, "evil.example.", 60), rr("a.b.dn.example.", protocol.TypeCNAME, "a.evil.example.", 60)), "", "a.b.t.example."},
		{"DNAME owner itself not redirected", msg("dn.example.", protocol.TypeA, rr("dn.example.", protocol.TypeDNAME, "t.example.", 60)), "", "dn.example."},
		{"DNAME query at owner", msg("dn.example.", protocol.TypeDNAME, rr("dn.example.", protocol.TypeDNAME, "t.example.", 60)), "", ""},
		{"ANY answered", msg("x.example.", protocol.TypeANY, rr("x.example.", protocol.TypeTXT, "\"t\"", 60)), "", ""},
		{"overlong synthesized target (YXDOMAIN)", msg(long+"dn.example.", protocol.TypeA,
			rr("dn.example.", protocol.TypeDNAME, strings.Repeat("c", 60)+"."+strings.Repeat("d", 60)+".example.", 60)), "", ""},
	}
	for _, tc := range cases {
		got := walkAnswerChain(tc.m, tc.m.Questions[0].Name.String())
		gotSynth := ""
		for o := range got.synthesized {
			gotSynth = o
		}
		gotTerm := ""
		if got.open {
			gotTerm = got.terminal
		}
		if gotSynth != tc.synth || gotTerm != tc.terminal {
			t.Errorf("%s: synthesized %q terminal %q, want %q %q", tc.name, gotSynth, gotTerm, tc.synth, tc.terminal)
		}
	}
	if got := walkAnswerChain(&protocol.Message{}, "x.example."); got.open {
		t.Errorf("no question: open terminal %q", got.terminal)
	}
}
