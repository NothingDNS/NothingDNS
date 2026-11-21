package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// A presigned zone in an algorithm rollover (RFC 6781 §4.1.4) carries RRSIGs
// of two algorithms while its DNSKEY RRset holds only the old one's keys.
// Every answer must carry all stored RRSIGs so the verifiable one is there
// (RFC 4035 §3.1.1) — not only the exact-match path (F866).

func presignedRolloverHandler(t *testing.T) (*dnssec.Signer, *integratedHandler) {
	n := func(x string) *protocol.Name { y, _ := protocol.ParseName(x); return y }
	mk := func(name string, typ uint16, d protocol.RData) *protocol.ResourceRecord {
		rr, _ := protocol.NewResourceRecord(name, typ, protocol.ClassIN, 300, d)
		return rr
	}
	data := func() []*protocol.ResourceRecord {
		return []*protocol.ResourceRecord{
			mk("p6.test.", protocol.TypeSOA, &protocol.RDataSOA{MName: n("ns1.p6.test."), RName: n("h.p6.test."), Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}),
			mk("p6.test.", protocol.TypeNS, &protocol.RDataNS{NSDName: n("ns1.p6.test.")}),
			mk("ns1.p6.test.", protocol.TypeA, &protocol.RDataA{Address: [4]byte{192, 0, 2, 53}}),
			mk("www.p6.test.", protocol.TypeA, &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}),
			mk("*.wild.p6.test.", protocol.TypeTXT, &protocol.RDataTXT{Strings: []string{"wild"}}),
			mk("sec.p6.test.", protocol.TypeNS, &protocol.RDataNS{NSDName: n("ns.example.net.")}),
			mk("sec.p6.test.", protocol.TypeDS, &protocol.RDataDS{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: make([]byte, 32)}),
			mk("old.p6.test.", protocol.TypeDNAME, &protocol.RDataDNAME{DName: n("www.p6.test.")}),
		}
	}
	signer := func(alg uint8) *dnssec.Signer {
		s := dnssec.NewSigner("p6.test.", dnssec.DefaultSignerConfig())
		for _, ksk := range []bool{true, false} {
			k, err := s.GenerateKeyPair(alg, ksk)
			if err != nil {
				t.Fatal(err)
			}
			s.SetKeyState(k.KeyTag, dnssec.KeyStateActive)
		}
		return s
	}
	oldS, newS := signer(protocol.AlgorithmECDSAP256SHA256), signer(protocol.AlgorithmED25519)
	oldZ, err := oldS.SignZone(data())
	if err != nil {
		t.Fatal(err)
	}
	newZ, err := newS.SignZone(data())
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	line := func(rr *protocol.ResourceRecord) {
		fmt.Fprintf(&b, "%s %d IN %s %s\n", rr.Name.String(), rr.TTL, typeToString(rr.Type), rr.Data.String())
	}
	// New-algorithm RRSIGs first (except over DNSKEY: not yet published).
	for _, rr := range newZ {
		if sig, ok := rr.Data.(*protocol.RDataRRSIG); ok && sig.TypeCovered != protocol.TypeDNSKEY {
			line(rr)
		}
	}
	for _, rr := range oldZ {
		line(rr)
	}
	z, err := zone.ParseFile("p6.test.zone", strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	h := newTestHandler()
	h.zones["p6.test."] = z
	h.RebuildZoneTree()
	return oldS, h
}

func presignedRolloverValidate(t *testing.T, s *dnssec.Signer, h *integratedHandler, name string, qt uint16) (*protocol.Message, dnssec.ValidationResult, error) {
	k := s.GetKSKs()[0]
	store := dnssec.NewTrustAnchorStore()
	store.AddAnchor(&dnssec.TrustAnchor{Zone: "p6.test.", KeyTag: k.KeyTag, Algorithm: k.DNSKEY.Algorithm, PublicKey: k.DNSKEY.PublicKey})
	v := dnssec.NewValidator(dnssec.DefaultValidatorConfig(), store, &presignedTestResolver{t: t, h: h})
	m := dnssecRegAsk(t, h, name, qt)
	res, err := v.ValidateResponse(t.Context(), m, name)
	return m, res, err
}

func countCovering(rrs []*protocol.ResourceRecord, covered uint16) int {
	n := 0
	for _, rr := range rrs {
		if s, ok := rr.Data.(*protocol.RDataRRSIG); ok && s.TypeCovered == covered {
			n++
		}
	}
	return n
}

func TestPresignedRolloverServesEveryStoredRRSIG(t *testing.T) {
	s, h := presignedRolloverHandler(t)
	for _, q := range []struct {
		name string
		qt   uint16
	}{{"www.p6.test.", protocol.TypeA}, {"foo.wild.p6.test.", protocol.TypeTXT}} {
		if _, res, err := presignedRolloverValidate(t, s, h, q.name, q.qt); res != dnssec.ValidationSecure {
			t.Fatalf("%s %s: %v (%v)", q.name, typeToString(q.qt), res, err)
		}
	}
	wild := dnssecRegAsk(t, h, "foo.wild.p6.test.", protocol.TypeTXT)
	if got := countCovering(wild.Answers, protocol.TypeTXT); got != 2 {
		t.Fatalf("wildcard answer: %d RRSIG(TXT), want 2", got)
	}
	ref := dnssecRegAsk(t, h, "host.sec.p6.test.", protocol.TypeA)
	if got := countCovering(ref.Authorities, protocol.TypeDS); got != 2 {
		t.Fatalf("referral: %d RRSIG(DS), want 2", got)
	}
	dn := dnssecRegAsk(t, h, "x.old.p6.test.", protocol.TypeA)
	if got := countCovering(dn.Answers, protocol.TypeDNAME); got != 2 {
		t.Fatalf("DNAME answer: %d RRSIG(DNAME), want 2", got)
	}
}
