package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// A DO=1 referral from a presigned zone to an unsigned child carries the
// zone's own stored NSEC/NSEC3 proving there is no DS, with its stored RRSIG
// (RFC 4035 §3.1.4.1, RFC 5155 §7.2.7) — the same records its DS NODATA
// answer for the cut serves (F864).

func presignedRefZone(t *testing.T, nsec3, optOut bool) (*dnssec.Signer, *integratedHandler) {
	cfg := dnssec.DefaultSignerConfig()
	cfg.NSEC3Enabled = nsec3
	cfg.NSEC3OptOut = optOut
	s := dnssec.NewSigner("p4.test.", cfg)
	for _, ksk := range []bool{true, false} {
		k, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, ksk)
		if err != nil {
			t.Fatal(err)
		}
		s.SetKeyState(k.KeyTag, dnssec.KeyStateActive)
	}
	n := func(x string) *protocol.Name { y, _ := protocol.ParseName(x); return y }
	mk := func(name string, typ uint16, d protocol.RData) *protocol.ResourceRecord {
		rr, _ := protocol.NewResourceRecord(name, typ, protocol.ClassIN, 300, d)
		return rr
	}
	signed, err := s.SignZone([]*protocol.ResourceRecord{
		mk("p4.test.", protocol.TypeSOA, &protocol.RDataSOA{MName: n("ns1.p4.test."), RName: n("h.p4.test."), Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}),
		mk("p4.test.", protocol.TypeNS, &protocol.RDataNS{NSDName: n("ns1.p4.test.")}),
		mk("ns1.p4.test.", protocol.TypeA, &protocol.RDataA{Address: [4]byte{192, 0, 2, 53}}),
		mk("www.p4.test.", protocol.TypeA, &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}),
		mk("ins.p4.test.", protocol.TypeNS, &protocol.RDataNS{NSDName: n("ns.example.net.")}),
	})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, rr := range signed {
		fmt.Fprintf(&b, "%s %d IN %s %s\n", rr.Name.String(), rr.TTL, typeToString(rr.Type), rr.Data.String())
	}
	z, err := zone.ParseFile("p4.test.zone", strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	h := newTestHandler()
	h.zones["p4.test."] = z
	h.RebuildZoneTree()
	return s, h
}

func presignedRefValidate(t *testing.T, s *dnssec.Signer, h *integratedHandler, name string, qt uint16) (*protocol.Message, dnssec.ValidationResult, error) {
	k := s.GetKSKs()[0]
	store := dnssec.NewTrustAnchorStore()
	store.AddAnchor(&dnssec.TrustAnchor{Zone: "p4.test.", KeyTag: k.KeyTag, Algorithm: k.DNSKEY.Algorithm, PublicKey: k.DNSKEY.PublicKey})
	v := dnssec.NewValidator(dnssec.DefaultValidatorConfig(), store, &presignedTestResolver{t: t, h: h})
	m := dnssecRegAsk(t, h, name, qt)
	res, err := v.ValidateResponse(t.Context(), m, name)
	return m, res, err
}

func presignedRefProof(m *protocol.Message) (proofs, sigs int) {
	for _, rr := range m.Authorities {
		switch rr.Type {
		case protocol.TypeNSEC, protocol.TypeNSEC3:
			proofs++
		case protocol.TypeRRSIG:
			if s, ok := rr.Data.(*protocol.RDataRRSIG); ok && (s.TypeCovered == protocol.TypeNSEC || s.TypeCovered == protocol.TypeNSEC3) {
				sigs++
			}
		}
	}
	return
}

// presignedRefSameAsDSAnswer reports whether every NSEC/NSEC3 of the referral is a
// record of the DS-query NODATA answer for the cut, which validates SECURE.
func presignedRefSameAsDSAnswer(ref, ds *protocol.Message) bool {
	want := map[string]bool{}
	for _, rr := range ds.Authorities {
		if rr.Type == protocol.TypeNSEC || rr.Type == protocol.TypeNSEC3 {
			want[rr.Name.String()+" "+rr.Data.String()] = true
		}
	}
	for _, rr := range ref.Authorities {
		if (rr.Type == protocol.TypeNSEC || rr.Type == protocol.TypeNSEC3) && !want[rr.Name.String()+" "+rr.Data.String()] {
			return false
		}
	}
	return true
}

func TestPresignedInsecureReferralCarriesStoredProof(t *testing.T) {
	for _, nsec3 := range []bool{false, true} {
		s, h := presignedRefZone(t, nsec3, false)
		ds, res, err := presignedRefValidate(t, s, h, "ins.p4.test.", protocol.TypeDS)
		if res != dnssec.ValidationSecure {
			t.Fatalf("nsec3=%v: DS NODATA for the cut: %v (%v)", nsec3, res, err)
		}
		m := dnssecRegAsk(t, h, "host.ins.p4.test.", protocol.TypeA)
		if dnssecRegCount(m.Authorities, protocol.TypeNS) == 0 {
			t.Fatalf("nsec3=%v: no referral", nsec3)
		}
		p, sg := presignedRefProof(m)
		if p == 0 || sg < p {
			t.Fatalf("nsec3=%v: referral proof records=%d RRSIGs=%d", nsec3, p, sg)
		}
		if !presignedRefSameAsDSAnswer(m, ds) {
			t.Fatalf("nsec3=%v: referral proof is not the zone's stored record", nsec3)
		}
	}
}

// TestPresignedOptOutChainIsTheStoredChain (F865): dnssec.SignZone with
// opt-out flags only an unsigned delegation's NSEC3 and keeps it in the
// chain. Proofs were picked from a chain whose Opt-Out setting came from
// whichever stored NSEC3 was read first, so some builds left the delegation
// out and served a wrong proof. Every build must pick from the stored chain.
func TestPresignedOptOutChainIsTheStoredChain(t *testing.T) {
	for i := 0; i < 30; i++ {
		s, h := presignedRefZone(t, true, true)
		for _, q := range []struct {
			name string
			qt   uint16
		}{{"ins.p4.test.", protocol.TypeDS}, {"zz.p4.test.", protocol.TypeA}, {"www.p4.test.", protocol.TypeAAAA}} {
			if _, res, err := presignedRefValidate(t, s, h, q.name, q.qt); res != dnssec.ValidationSecure && res != dnssec.ValidationInsecure {
				t.Fatalf("build %d: %s %s: %v (%v)", i, q.name, typeToString(q.qt), res, err)
			}
		}
	}
}
