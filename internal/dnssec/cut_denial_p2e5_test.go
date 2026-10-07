package dnssec

// P2-E5 (F507-F510): a zone's denial (and apex-type data) is honoured only for
// names the zone is authoritative for.
//
//   - F507: the parent's NSEC/NSEC3 at a delegation (NS set, SOA clear) proves
//     only that DS is absent there — never NODATA for another type at the cut
//     nor NXDOMAIN/NODATA for a name below it (RFC 6840 §4.1, RFC 5155 §8.3).
//   - F510: the same for a DNAME owner and the names below it (RFC 6672).
//   - F508: a parent-signed denial (e.g. a stale pre-delegation NSEC) for a
//     name below a zone cut: the names between the signer and the proof's
//     closest encloser must be proven not to be cuts (F472's check, F477 cache,
//     F408 lookup budget).
//   - F509: SOA/DNSKEY/NS/NSEC3PARAM/CDS/CDNSKEY signed by an ancestor zone at
//     a name other than the signer (child apex data) is Bogus.
//
// Uses the zonecut_p2d1_test.go harness (p2d1Zone, p2d1Resolver).

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

type cutDenialWorld struct {
	parent, child, stale *p2d1Zone
	res                  *p2d1Resolver
	v                    *Validator
}

func newCutDenialWorld(t *testing.T, nsec3 bool) *cutDenialWorld {
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
		p2d1RR(t, "a.b.c.example.com.", protocol.TypeA, "192.0.2.3"),
		p2d1RR(t, "*.w.example.com.", protocol.TypeTXT, "\"wild\""),
		p2d1RR(t, "ins.example.com.", protocol.TypeNS, "ns1.ins.example.net."),
		p2d1RR(t, "old.example.com.", protocol.TypeNS, "ns1.old.example.net."),
		p2d1RR(t, "sec.example.com.", protocol.TypeNS, "ns1.sec.example.com."),
		child.ds(t),
		p2d1RR(t, "dn.example.com.", protocol.TypeDNAME, "target.example.net."))
	// Pre-delegation example.com. (same keys): old.example.com. was an
	// ordinary subtree before it was delegated.
	staleRecs, err := parent.signer.SignZone([]*protocol.ResourceRecord{soa("example.com."),
		p2d1RR(t, "example.com.", protocol.TypeNS, "ns1.example.com."),
		p2d1RR(t, "a.old.example.com.", protocol.TypeA, "192.0.2.4"),
		p2d1RR(t, "z.old.example.com.", protocol.TypeA, "192.0.2.5")})
	if err != nil {
		t.Fatal(err)
	}
	ta, err := DSFromDNSKEY("example.com.", parent.signer.GetKSKs()[0].DNSKEY, 2)
	if err != nil {
		t.Fatal(err)
	}
	store := NewTrustAnchorStore()
	store.AddAnchor(ta)
	vcfg := DefaultValidatorConfig()
	vcfg.ValidationCacheTTL = 0
	res := &p2d1Resolver{zones: []*p2d1Zone{parent, child}}
	return &cutDenialWorld{parent: parent, child: child, res: res, v: NewValidator(vcfg, store, res),
		stale: &p2d1Zone{zone: "example.com.", signed: staleRecs, signer: parent.signer}}
}

func cutDenialNeg(qname string, qtype uint16, nx bool, auth []*protocol.ResourceRecord) *protocol.Message {
	m := p2d1Msg(qname, qtype, nil, auth)
	if nx {
		m.Header.Flags.RCODE = protocol.RcodeNameError
	}
	return m
}

func cutDenialForge(t *testing.T, z *p2d1Zone, owner string, rrtype uint16, text string) []*protocol.ResourceRecord {
	t.Helper()
	rr := p2d1RR(t, owner, rrtype, text)
	now := time.Now()
	sig, err := z.signer.SignRRSet([]*protocol.ResourceRecord{rr}, z.signer.GetZSKs()[0],
		uint32(now.Add(-time.Hour).Unix()), uint32(now.Add(24*time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	return []*protocol.ResourceRecord{rr, sig}
}

func TestValidateResponse_DenialAtOrBelowZoneCut_P2E5(t *testing.T) {
	ctx := context.Background()
	for _, nsec3 := range []bool{false, true} {
		w := newCutDenialWorld(t, nsec3)
		pd, sd := w.parent.denial(), w.stale.denial()
		unsignedNX := cutDenialNeg("www.ins.example.com.", protocol.TypeA, true,
			[]*protocol.ResourceRecord{p2d1RR(t, "ins.example.com.", protocol.TypeSOA, "ns1.ins.example.net. h.ins.example.net. 1 3600 600 86400 300")})
		cases := []struct {
			name        string
			q           string
			m           *protocol.Message
			want        ValidationResult
			wantLookups int
		}{
			// Controls.
			{"NODATA www AAAA", "www.example.com.", cutDenialNeg("www.example.com.", protocol.TypeAAAA, false, pd), ValidationSecure, 0},
			{"DS NODATA at insecure cut", "ins.example.com.", cutDenialNeg("ins.example.com.", protocol.TypeDS, false, pd), ValidationSecure, 0},
			{"NXDOMAIN one below apex", "nx.example.com.", cutDenialNeg("nx.example.com.", protocol.TypeA, true, pd), ValidationSecure, 0},
			{"NXDOMAIN below deep name (CE a.b.c)", "x.a.b.c.example.com.", cutDenialNeg("x.a.b.c.example.com.", protocol.TypeA, true, pd), ValidationSecure, 3},
			{"ENT NODATA", "b.c.example.com.", cutDenialNeg("b.c.example.com.", protocol.TypeA, false, pd), ValidationSecure, 1},
			{"wildcard NODATA (CE w)", "q.w.example.com.", cutDenialNeg("q.w.example.com.", protocol.TypeA, false, pd), ValidationSecure, 1},
			{"NODATA at DNAME owner itself", "dn.example.com.", cutDenialNeg("dn.example.com.", protocol.TypeA, false, pd), ValidationSecure, 0},
			{"child NODATA", "www.sec.example.com.", cutDenialNeg("www.sec.example.com.", protocol.TypeAAAA, false, w.child.denial()), ValidationSecure, 0},
			{"child apex SOA", "sec.example.com.", p2d1Msg("sec.example.com.", protocol.TypeSOA, w.child.rrset("sec.example.com.", protocol.TypeSOA), nil), ValidationSecure, 0},
			{"child apex DNSKEY", "sec.example.com.", p2d1Msg("sec.example.com.", protocol.TypeDNSKEY, w.child.rrset("sec.example.com.", protocol.TypeDNSKEY), nil), ValidationSecure, 0},
			{"parent apex NS", "example.com.", p2d1Msg("example.com.", protocol.TypeNS, w.parent.rrset("example.com.", protocol.TypeNS), nil), ValidationSecure, 0},
			{"unsigned child NXDOMAIN", "www.ins.example.com.", unsignedNX, ValidationInsecure, 0},
			// F507: parent's delegation NSEC/NSEC3.
			{"F507 A NODATA at insecure cut", "ins.example.com.", cutDenialNeg("ins.example.com.", protocol.TypeA, false, pd), ValidationBogus, 0},
			{"F507 MX NODATA at insecure cut", "ins.example.com.", cutDenialNeg("ins.example.com.", protocol.TypeMX, false, pd), ValidationBogus, 0},
			{"F507 AAAA NODATA at secure cut", "sec.example.com.", cutDenialNeg("sec.example.com.", protocol.TypeAAAA, false, pd), ValidationBogus, 0},
			{"F507 NXDOMAIN below insecure cut", "www.ins.example.com.", cutDenialNeg("www.ins.example.com.", protocol.TypeA, true, pd), ValidationBogus, 0},
			{"F507 NXDOMAIN below secure cut", "www.sec.example.com.", cutDenialNeg("www.sec.example.com.", protocol.TypeA, true, pd), ValidationBogus, 0},
			{"F507 DS NODATA below a cut", "x.ins.example.com.", cutDenialNeg("x.ins.example.com.", protocol.TypeDS, false, pd), ValidationBogus, 0},
			// F510: DNAME owner.
			{"F510 NXDOMAIN below DNAME", "x.dn.example.com.", cutDenialNeg("x.dn.example.com.", protocol.TypeA, true, pd), ValidationBogus, 0},
			// F508: stale pre-delegation denial (stops at the first cut).
			{"F508 stale NXDOMAIN below cut", "m.old.example.com.", cutDenialNeg("m.old.example.com.", protocol.TypeA, true, sd), ValidationBogus, 1},
			{"F508 stale NODATA below cut", "a.old.example.com.", cutDenialNeg("a.old.example.com.", protocol.TypeAAAA, false, sd), ValidationBogus, 1},
			// F509: apex types signed by the parent at a child apex.
			{"F509 parent SOA at child apex", "sec.example.com.", p2d1Msg("sec.example.com.", protocol.TypeSOA, cutDenialForge(t, w.parent, "sec.example.com.", protocol.TypeSOA, "ns1.evil. h.evil. 9 3600 600 86400 300"), nil), ValidationBogus, 0},
			{"F509 parent NS at cut", "ins.example.com.", p2d1Msg("ins.example.com.", protocol.TypeNS, cutDenialForge(t, w.parent, "ins.example.com.", protocol.TypeNS, "ns.evil."), nil), ValidationBogus, 0},
			{"F509 parent DNSKEY at child apex", "sec.example.com.", p2d1Msg("sec.example.com.", protocol.TypeDNSKEY, cutDenialForge(t, w.parent, "sec.example.com.", protocol.TypeDNSKEY, "257 3 13 "+strings.Repeat("A", 88)), nil), ValidationBogus, 0},
		}
		w.v.zoneCuts = nil // assert per-response lookup counts
		for _, tc := range cases {
			for i := 0; i < 2; i++ {
				b := newResponseBudget()
				got, err := w.v.validateResponseBudget(ctx, tc.m, tc.q, b)
				if got != tc.want || b.lookups != tc.wantLookups {
					t.Fatalf("nsec3=%v %s: got %v (err %v) lookups %d, want %v lookups %d",
						nsec3, tc.name, got, err, b.lookups, tc.want, tc.wantLookups)
				}
			}
		}

		deep := func() *protocol.Message {
			return cutDenialNeg("x.a.b.c.example.com.", protocol.TypeA, true, pd)
		}
		// Fail closed: DS fetch failure at an intermediate name, lookup budget.
		w.res.failDS = "b.c.example.com."
		if got, _ := w.v.ValidateResponse(ctx, deep(), "x.a.b.c.example.com."); got != ValidationBogus {
			t.Fatalf("nsec3=%v DS fetch failure below signer: got %v, want BOGUS", nsec3, got)
		}
		w.res.failDS = ""
		b := newResponseBudget()
		b.lookupLimit = 2
		if got, err := w.v.validateResponseBudget(ctx, deep(), "x.a.b.c.example.com.", b); got != ValidationBogus || err != errWorkBudgetExceeded {
			t.Fatalf("nsec3=%v lookup budget 2: got %v (err %v), want BOGUS budget exceeded", nsec3, got, err)
		}

		// Cross-response cache (F477): the second deep NXDOMAIN costs nothing,
		// and the cached cut keeps the stale replay Bogus without a lookup.
		w.v.zoneCuts = newZoneCutCache(maxZoneCutCacheEntries)
		for i, want := range []int{3, 0} {
			b := newResponseBudget()
			if got, _ := w.v.validateResponseBudget(ctx, deep(), "x.a.b.c.example.com.", b); got != ValidationSecure || b.lookups != want {
				t.Fatalf("nsec3=%v cached deep NXDOMAIN #%d: got %v lookups %d, want SECURE %d", nsec3, i, got, b.lookups, want)
			}
		}
		for i, want := range []int{1, 0} {
			b := newResponseBudget()
			if got, _ := w.v.validateResponseBudget(ctx, cutDenialNeg("m.old.example.com.", protocol.TypeA, true, sd), "m.old.example.com.", b); got != ValidationBogus || b.lookups != want {
				t.Fatalf("nsec3=%v cached stale replay #%d: got %v lookups %d, want BOGUS %d", nsec3, i, got, b.lookups, want)
			}
		}
	}
}

// Unit level: which authenticated NSEC records the filter keeps.
func TestAncestorDelegationFiltered_P2E5(t *testing.T) {
	nsec := func(owner, next string, types ...uint16) *protocol.ResourceRecord {
		n, _ := protocol.ParseName(owner)
		nx, _ := protocol.ParseName(next)
		return &protocol.ResourceRecord{Name: n, Type: protocol.TypeNSEC, Class: protocol.ClassIN,
			Data: &protocol.RDataNSEC{NextDomain: nx, TypeBitMap: types}}
	}
	cut := nsec("ins.example.com.", "www.example.com.", protocol.TypeNS, protocol.TypeRRSIG, protocol.TypeNSEC)
	apex := nsec("example.com.", "ins.example.com.", protocol.TypeNS, protocol.TypeSOA, protocol.TypeRRSIG, protocol.TypeNSEC)
	dname := nsec("dn.example.com.", "ins.example.com.", protocol.TypeDNAME, protocol.TypeRRSIG, protocol.TypeNSEC)
	cases := []struct {
		rr    *protocol.ResourceRecord
		qname string
		qtype uint16
		keep  bool
	}{
		{cut, "ins.example.com.", protocol.TypeDS, true},
		{cut, "INS.Example.COM.", protocol.TypeA, false},
		{cut, "a.ins.example.com.", protocol.TypeDS, false},
		{cut, "zzz.example.com.", protocol.TypeA, true}, // not an ancestor
		{apex, "x.example.com.", protocol.TypeA, true},  // apex NSEC (SOA set)
		{apex, "example.com.", protocol.TypeA, true},
		{dname, "dn.example.com.", protocol.TypeA, true},
		{dname, "x.dn.example.com.", protocol.TypeA, false},
	}
	for _, tc := range cases {
		got := ancestorDelegationFiltered([]*protocol.ResourceRecord{tc.rr}, tc.qname, tc.qtype)
		if (len(got) == 1) != tc.keep {
			t.Errorf("%s for %s/%d: kept=%v, want %v", tc.rr.Name, tc.qname, tc.qtype, len(got) == 1, tc.keep)
		}
	}
	for _, tc := range []struct {
		rrtype        uint16
		owner, signer string
		want          bool
	}{
		{protocol.TypeSOA, "sec.example.com.", "example.com.", true},
		{protocol.TypeSOA, "Example.COM", "example.com.", false},
		{protocol.TypeNS, "ins.example.com.", "example.com.", true},
		{protocol.TypeCDS, "a.example.com.", "example.com.", true},
		{protocol.TypeA, "sec.example.com.", "example.com.", false},
		{protocol.TypeDS, "sec.example.com.", "example.com.", false},
	} {
		if got := apexTypeBelowSigner(tc.rrtype, tc.owner, tc.signer); got != tc.want {
			t.Errorf("apexTypeBelowSigner(%d, %s, %s) = %v, want %v", tc.rrtype, tc.owner, tc.signer, got, tc.want)
		}
	}
}
