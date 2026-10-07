package dnssec

// F472 (P2-D1): an RRset signed by a parent zone's key for a name below one of
// the parent's delegations must not validate (RFC 4035 §5.3.1: the signer is
// the zone containing the RRset). The chain is built only to the RRSIG signer
// (715f339), so the validator proves "no zone cut" for each name strictly
// between the signer and a deeper owner with the signer's authenticated DS
// denial — zero extra lookups for owners at or one label below the signer.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

type p2d1Zone struct {
	zone   string
	signed []*protocol.ResourceRecord
	signer *Signer
}

func p2d1RR(t *testing.T, name string, rrtype uint16, text string) *protocol.ResourceRecord {
	t.Helper()
	rd := protocol.ParseRDataText(protocol.TypeString(rrtype), text)
	if rd == nil {
		t.Fatalf("ParseRDataText(%s, %q) = nil", protocol.TypeString(rrtype), text)
	}
	rr, err := protocol.NewResourceRecord(name, rrtype, protocol.ClassIN, 300, rd)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func p2d1Sign(t *testing.T, zone string, cfg SignerConfig, recs ...*protocol.ResourceRecord) *p2d1Zone {
	t.Helper()
	s := NewSigner(zone, cfg)
	for _, ksk := range []bool{true, false} {
		if _, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, ksk); err != nil {
			t.Fatal(err)
		}
	}
	signed, err := s.SignZone(recs)
	if err != nil {
		t.Fatal(err)
	}
	return &p2d1Zone{zone: zone, signed: signed, signer: s}
}

// rrset returns name/rrtype plus its RRSIGs, freshly copied.
func (z *p2d1Zone) rrset(name string, rrtype uint16) []*protocol.ResourceRecord {
	var out []*protocol.ResourceRecord
	for _, rr := range z.signed {
		if !strings.EqualFold(rr.Name.String(), name) {
			continue
		}
		sig, isSig := rr.Data.(*protocol.RDataRRSIG)
		if rr.Type == rrtype || (isSig && sig.TypeCovered == rrtype) {
			out = append(out, rr.Copy())
		}
	}
	return out
}

func (z *p2d1Zone) denial() []*protocol.ResourceRecord {
	var out []*protocol.ResourceRecord
	for _, rr := range z.signed {
		c := uint16(0)
		if sig, ok := rr.Data.(*protocol.RDataRRSIG); ok {
			c = sig.TypeCovered
		}
		if rr.Type == protocol.TypeNSEC || rr.Type == protocol.TypeNSEC3 || c == protocol.TypeNSEC || c == protocol.TypeNSEC3 {
			out = append(out, rr.Copy())
		}
	}
	return out
}

func (z *p2d1Zone) ds(t *testing.T) *protocol.ResourceRecord {
	t.Helper()
	ta, err := DSFromDNSKEY(z.zone, z.signer.GetKSKs()[0].DNSKEY, 2)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := protocol.ParseName(z.zone)
	return &protocol.ResourceRecord{Name: n, Type: protocol.TypeDS, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataDS{KeyTag: ta.KeyTag, Algorithm: ta.Algorithm, DigestType: ta.DigestType, Digest: ta.Digest}}
}

func p2d1Msg(qname string, qtype uint16, ans, auth []*protocol.ResourceRecord) *protocol.Message {
	qn, _ := protocol.ParseName(qname)
	return &protocol.Message{
		Header:      protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions:   []*protocol.Question{{Name: qn, QType: qtype, QClass: protocol.ClassIN}},
		Answers:     ans,
		Authorities: auth,
	}
}

// p2d1Resolver serves DNSKEY/NSEC3PARAM from each zone and DS (or the
// zone's denial) from the closest zone strictly above the name. failDS makes
// the DS query for that name fail.
type p2d1Resolver struct {
	zones  []*p2d1Zone // parent first
	failDS string
	ds     []string
}

func (r *p2d1Resolver) Query(_ context.Context, name string, qtype uint16) (*protocol.Message, error) {
	lname := strings.ToLower(name)
	if qtype == protocol.TypeDS {
		r.ds = append(r.ds, lname)
		if lname == r.failDS {
			return nil, context.DeadlineExceeded
		}
		for i := len(r.zones) - 1; i >= 0; i-- {
			z := r.zones[i]
			if z.zone == lname || (z.zone != "." && !strings.HasSuffix(lname, "."+z.zone)) {
				continue
			}
			if ds := z.rrset(name, protocol.TypeDS); len(ds) > 0 {
				return p2d1Msg(name, qtype, ds, nil), nil
			}
			return p2d1Msg(name, qtype, nil, z.denial()), nil
		}
	}
	for _, z := range r.zones {
		if z.zone == lname {
			return p2d1Msg(name, qtype, z.rrset(name, qtype), nil), nil
		}
	}
	return p2d1Msg(name, qtype, nil, nil), nil
}

func TestValidateResponse_ParentSignedDataBelowZoneCut_F472(t *testing.T) {
	ctx := context.Background()
	for _, nsec3 := range []bool{false, true} {
		cfg := DefaultSignerConfig()
		cfg.NSEC3Enabled = nsec3
		child := p2d1Sign(t, "secure.example.com.", cfg,
			p2d1RR(t, "secure.example.com.", protocol.TypeSOA, "ns1.secure.example.com. h.example.com. 1 3600 600 86400 300"),
			p2d1RR(t, "secure.example.com.", protocol.TypeNS, "ns1.secure.example.com."),
			p2d1RR(t, "www.secure.example.com.", protocol.TypeA, "192.0.2.20"))
		parent := p2d1Sign(t, "example.com.", cfg,
			p2d1RR(t, "example.com.", protocol.TypeSOA, "ns1.example.com. h.example.com. 1 3600 600 86400 300"),
			p2d1RR(t, "example.com.", protocol.TypeNS, "ns1.example.com."),
			p2d1RR(t, "www.example.com.", protocol.TypeA, "192.0.2.1"),
			p2d1RR(t, "a.b.c.example.com.", protocol.TypeA, "192.0.2.3"),
			p2d1RR(t, "secure.example.com.", protocol.TypeNS, "ns1.secure.example.com."),
			child.ds(t),
			p2d1RR(t, "insecure.example.com.", protocol.TypeNS, "ns1.insecure.example.com."))
		ta, err := DSFromDNSKEY("example.com.", parent.signer.GetKSKs()[0].DNSKEY, 2)
		if err != nil {
			t.Fatal(err)
		}
		store := NewTrustAnchorStore()
		store.AddAnchor(ta)
		vcfg := DefaultValidatorConfig()
		vcfg.ValidationCacheTTL = 0
		res := &p2d1Resolver{zones: []*p2d1Zone{parent, child}}
		v := NewValidator(vcfg, store, res)
		// Measure the per-response cost of the check itself; the
		// cross-response cache (F477) is covered by zonecut_cache_p2d2_test.go.
		v.zoneCuts = nil

		forge := func(owner string) []*protocol.ResourceRecord {
			rr := p2d1RR(t, owner, protocol.TypeA, "203.0.113.66")
			now := time.Now()
			sig, err := parent.signer.SignRRSet([]*protocol.ResourceRecord{rr}, parent.signer.GetZSKs()[0],
				uint32(now.Add(-time.Hour).Unix()), uint32(now.Add(24*time.Hour).Unix()))
			if err != nil {
				t.Fatal(err)
			}
			return []*protocol.ResourceRecord{rr, sig}
		}
		cases := []struct {
			name        string
			qname       string
			ans         []*protocol.ResourceRecord
			want        ValidationResult
			wantLookups int
		}{
			{"apex (owner == signer)", "example.com.", parent.rrset("example.com.", protocol.TypeSOA), ValidationSecure, 0},
			{"one label below signer", "www.example.com.", parent.rrset("www.example.com.", protocol.TypeA), ValidationSecure, 0},
			{"deep in-zone name, no cuts", "a.b.c.example.com.", parent.rrset("a.b.c.example.com.", protocol.TypeA), ValidationSecure, 2},
			{"genuine child data", "www.secure.example.com.", child.rrset("www.secure.example.com.", protocol.TypeA), ValidationSecure, 0},
			{"parent-signed below secure cut", "www.secure.example.com.", forge("www.secure.example.com."), ValidationBogus, 1},
			{"parent-signed below insecure cut", "www.insecure.example.com.", forge("www.insecure.example.com."), ValidationBogus, 1},
			{"parent-signed two below a cut", "x.y.insecure.example.com.", forge("x.y.insecure.example.com."), ValidationBogus, 1},
		}
		for _, tc := range cases {
			for i := 0; i < 2; i++ {
				b := newResponseBudget()
				got, err := v.validateResponseBudget(ctx, p2d1Msg(tc.qname, tc.ans[0].Type, tc.ans, nil), tc.qname, b) // question type = answer type (P2-E9: an A question answered by SOA alone needs a denial)
				if got != tc.want || b.lookups != tc.wantLookups {
					t.Fatalf("nsec3=%v %s: got %v (err %v) lookups %d, want %v lookups %d",
						nsec3, tc.name, got, err, b.lookups, tc.want, tc.wantLookups)
				}
			}
		}

		// The same forgery reached through an in-zone CNAME.
		alias := p2d1RR(t, "alias.example.com.", protocol.TypeCNAME, "www.insecure.example.com.")
		now := time.Now()
		aliasSig, err := parent.signer.SignRRSet([]*protocol.ResourceRecord{alias}, parent.signer.GetZSKs()[0],
			uint32(now.Add(-time.Hour).Unix()), uint32(now.Add(24*time.Hour).Unix()))
		if err != nil {
			t.Fatal(err)
		}
		ans := append([]*protocol.ResourceRecord{alias, aliasSig}, forge("www.insecure.example.com.")...)
		if got, _ := v.ValidateResponse(ctx, p2d1Msg("alias.example.com.", protocol.TypeA, ans, nil), "alias.example.com."); got != ValidationBogus {
			t.Fatalf("nsec3=%v CNAME into parent-signed data below a cut: got %v, want BOGUS", nsec3, got)
		}

		// Fail closed: a DS fetch failure at an intermediate name, and a
		// lookup budget too small for the owner's depth.
		res.failDS = "b.c.example.com."
		if got, _ := v.ValidateResponse(ctx, p2d1Msg("a.b.c.example.com.", protocol.TypeA, parent.rrset("a.b.c.example.com.", protocol.TypeA), nil), "a.b.c.example.com."); got != ValidationBogus {
			t.Fatalf("nsec3=%v DS fetch failure at intermediate name: got %v, want BOGUS", nsec3, got)
		}
		res.failDS = ""
		b := newResponseBudget()
		b.lookupLimit = 1
		if got, err := v.validateResponseBudget(ctx, p2d1Msg("a.b.c.example.com.", protocol.TypeA, parent.rrset("a.b.c.example.com.", protocol.TypeA), nil), "a.b.c.example.com.", b); got != ValidationBogus || err != errWorkBudgetExceeded {
			t.Fatalf("nsec3=%v lookup budget 1: got %v (err %v), want BOGUS budget exceeded", nsec3, got, err)
		}
	}
}
