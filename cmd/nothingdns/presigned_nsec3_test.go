package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// A zone signed offline with NSEC3 is served with its stored NSEC3 proofs,
// which validate Secure (F757).

func presignedNSEC3Zone(t *testing.T, nsec3 bool) (*dnssec.Signer, *zone.Zone) {
	cfg := dnssec.DefaultSignerConfig()
	cfg.NSEC3Enabled = nsec3
	s := dnssec.NewSigner("p3.test.", cfg)
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
		mk("p3.test.", protocol.TypeSOA, &protocol.RDataSOA{MName: n("ns1.p3.test."), RName: n("h.p3.test."), Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}),
		mk("p3.test.", protocol.TypeNS, &protocol.RDataNS{NSDName: n("ns1.p3.test.")}),
		mk("ns1.p3.test.", protocol.TypeA, &protocol.RDataA{Address: [4]byte{192, 0, 2, 53}}),
		mk("www.p3.test.", protocol.TypeA, &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}),
		mk("*.wild.p3.test.", protocol.TypeTXT, &protocol.RDataTXT{Strings: []string{"wild"}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, rr := range signed {
		fmt.Fprintf(&b, "%s %d IN %s %s\n", rr.Name.String(), rr.TTL, typeToString(rr.Type), rr.Data.String())
	}
	z, err := zone.ParseFile("p3.test.zone", strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return s, z
}

func presignedNSEC3Handler(t *testing.T, nsec3 bool) (*dnssec.Signer, *integratedHandler) {
	s, z := presignedNSEC3Zone(t, nsec3)
	h := newTestHandler()
	h.zones["p3.test."] = z
	h.RebuildZoneTree()
	return s, h
}

func TestPresignedNSEC3ZoneValidates(t *testing.T) {
	signer, h := presignedNSEC3Handler(t, true)
	k := signer.GetKSKs()[0]
	store := dnssec.NewTrustAnchorStore()
	store.AddAnchor(&dnssec.TrustAnchor{Zone: "p3.test.", KeyTag: k.KeyTag, Algorithm: k.DNSKEY.Algorithm, PublicKey: k.DNSKEY.PublicKey})
	cfg := dnssec.DefaultValidatorConfig()
	v := dnssec.NewValidator(cfg, store, &presignedTestResolver{t: t, h: h})
	for _, tc := range []struct {
		name string
		qt   uint16
	}{
		{"www.p3.test.", protocol.TypeA},
		{"nx.p3.test.", protocol.TypeA},
		{"www.p3.test.", protocol.TypeAAAA},
		{"foo.wild.p3.test.", protocol.TypeTXT},
		{"foo.wild.p3.test.", protocol.TypeA},
		{"wild.p3.test.", protocol.TypeA},
		{"a.b.c.p3.test.", protocol.TypeA},
	} {
		m := dnssecRegAsk(t, h, tc.name, tc.qt)
		if res, err := v.ValidateResponse(t.Context(), m, tc.name); res != dnssec.ValidationSecure {
			t.Fatalf("%s %s: %v (%v), authority %d", tc.name, typeToString(tc.qt), res, err, len(m.Authorities))
		}
	}

	// A zone signed before NSEC3PARAM was published (F758): the parameters
	// come from a stored NSEC3, and its proofs are still served.
	_, h2 := presignedNSEC3Handler(t, true)
	z2 := h2.zones["p3.test."]
	z2.Lock()
	var keep []zone.Record
	for _, r := range z2.Records["p3.test."] {
		if r.Type != "NSEC3PARAM" && !(r.Type == "RRSIG" && strings.HasPrefix(r.RData, "NSEC3PARAM ")) {
			keep = append(keep, r)
		}
	}
	z2.Records["p3.test."] = keep
	z2.Unlock()
	if p := storedNSEC3Params(z2); p == nil {
		t.Fatal("no parameters without NSEC3PARAM")
	}
	if nx := dnssecRegAsk(t, h2, "nx.p3.test.", protocol.TypeA); dnssecRegCount(nx.Authorities, protocol.TypeNSEC3) == 0 {
		t.Fatal("no NSEC3 proof without NSEC3PARAM")
	}
}
