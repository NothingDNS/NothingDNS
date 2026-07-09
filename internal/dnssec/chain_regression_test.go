// Regression tests for the 2026-07-02 validator fixes:
//   - buildChain walking remaining leaf-first (chain links out of order,
//     answers validated against the wrong zone's keys),
//   - DS RRsets accepted without an RRSIG from the parent zone,
//   - exact-match NSEC/NSEC3 NoData proofs unreachable behind the strict
//     range check,
//   - nameInRange using plain string order instead of RFC 4034 §6.1
//     canonical order.

package dnssec

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strconv"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// testZoneKeys bundles one ECDSA KSK for a zone in wire and signing form.
type testZoneKeys struct {
	priv   *ecdsa.PrivateKey
	dnskey *protocol.RDataDNSKEY
	keyRR  *protocol.ResourceRecord
	keyTag uint16
}

func newTestZoneKeys(t *testing.T, zone string) *testZoneKeys {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key for %s: %v", zone, err)
	}
	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &priv.PublicKey}
	keyData, err := packECDSAPublicKey(pub)
	if err != nil {
		t.Fatalf("packing key for %s: %v", zone, err)
	}
	dnskey := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: keyData,
	}
	name, _ := protocol.ParseName(zone)
	return &testZoneKeys{
		priv:   priv,
		dnskey: dnskey,
		keyRR:  &protocol.ResourceRecord{Name: name, Type: protocol.TypeDNSKEY, Data: dnskey},
		keyTag: protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey),
	}
}

func (k *testZoneKeys) dsFor(t *testing.T, childZone string, child *testZoneKeys) *protocol.ResourceRecord {
	t.Helper()
	name, _ := protocol.ParseName(childZone)
	return &protocol.ResourceRecord{
		Name: name,
		Type: protocol.TypeDS,
		Data: &protocol.RDataDS{
			KeyTag:     child.keyTag,
			Algorithm:  protocol.AlgorithmECDSAP256SHA256,
			DigestType: 2,
			Digest:     calculateDSDigestFromDNSKEY(childZone, child.dnskey, 2),
		},
	}
}

func (k *testZoneKeys) sign(t *testing.T, zone string, rrs []*protocol.ResourceRecord) *protocol.ResourceRecord {
	t.Helper()
	return makeDNSKEYRRSIG(t, zone, k.priv, k.dnskey, rrs)
}

// buildTwoLevelFixture wires a root → com. → example.com. chain into a mock
// resolver and returns the validator plus the per-zone keys.
func buildTwoLevelFixture(t *testing.T) (*Validator, map[string]*testZoneKeys) {
	t.Helper()
	root := newTestZoneKeys(t, ".")
	com := newTestZoneKeys(t, "com.")
	example := newTestZoneKeys(t, "example.com.")

	rootKeySig := root.sign(t, ".", []*protocol.ResourceRecord{root.keyRR})
	comKeySig := com.sign(t, "com.", []*protocol.ResourceRecord{com.keyRR})
	exampleKeySig := example.sign(t, "example.com.", []*protocol.ResourceRecord{example.keyRR})

	comDS := root.dsFor(t, "com.", com)
	comDSSig := root.sign(t, ".", []*protocol.ResourceRecord{comDS})
	exampleDS := com.dsFor(t, "example.com.", example)
	exampleDSSig := com.sign(t, "com.", []*protocol.ResourceRecord{exampleDS})

	mock := &mockResolver{
		responses: map[string]*protocol.Message{
			".|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{root.keyRR, rootKeySig},
			},
			"com.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{com.keyRR, comKeySig},
			},
			"example.com.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{example.keyRR, exampleKeySig},
			},
			"com.|" + strconv.Itoa(int(protocol.TypeDS)): {
				Answers: []*protocol.ResourceRecord{comDS, comDSSig},
			},
			"example.com.|" + strconv.Itoa(int(protocol.TypeDS)): {
				Answers: []*protocol.ResourceRecord{exampleDS, exampleDSSig},
			},
		},
	}

	anchor := &TrustAnchor{
		Zone:       ".",
		KeyTag:     root.keyTag,
		Algorithm:  protocol.AlgorithmECDSAP256SHA256,
		DigestType: 2,
		Digest:     calculateDSDigestFromDNSKEY(".", root.dnskey, 2),
		ValidFrom:  time.Now().Add(-time.Hour),
	}
	store := NewTrustAnchorStore()
	store.AddAnchor(anchor)

	return NewValidator(DefaultValidatorConfig(), store, mock), map[string]*testZoneKeys{
		".": root, "com.": com, "example.com.": example,
	}
}

// The chain must be built anchor-first: . → com. → example.com. The old loop
// walked the leaf-first `remaining` slice forwards, producing
// . → example.com. → com., and validateMessage then checked example.com.'s
// answer signatures against com.'s DNSKEYs — every correctly-signed answer
// went Bogus.
func TestBuildChain_TwoLevelOrder(t *testing.T) {
	v, _ := buildTwoLevelFixture(t)
	anchor, remaining := v.trustAnchors.FindClosestAnchor("example.com.")
	if anchor == nil {
		t.Fatal("no anchor found")
	}

	chain, insecure, err := v.buildChain(context.Background(), anchor, remaining)
	if err != nil {
		t.Fatalf("buildChain: %v", err)
	}
	if insecure {
		t.Fatal("chain unexpectedly insecure")
	}
	want := []string{".", "com.", "example.com."}
	if len(chain) != len(want) {
		t.Fatalf("chain length = %d, want %d", len(chain), len(want))
	}
	for i, zone := range want {
		if chain[i].zone != zone {
			t.Errorf("chain[%d].zone = %q, want %q (chain out of order)", i, chain[i].zone, zone)
		}
	}
}

// End-to-end through the misorder bug's blast radius: a correctly signed
// answer for example.com. must validate Secure against the full chain.
func TestValidateMessage_TwoLevelChainSecure(t *testing.T) {
	v, keys := buildTwoLevelFixture(t)
	example := keys["example.com."]

	name, _ := protocol.ParseName("example.com.")
	aRR := &protocol.ResourceRecord{
		Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
	}
	aSig := example.sign(t, "example.com.", []*protocol.ResourceRecord{aRR})
	msg := &protocol.Message{
		Header:  protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Answers: []*protocol.ResourceRecord{aRR, aSig},
	}

	result, err := v.ValidateResponse(context.Background(), msg, "example.com.")
	if err != nil {
		t.Fatalf("ValidateResponse: %v", err)
	}
	if result != ValidationSecure {
		t.Errorf("result = %v, want SECURE", result)
	}
}

// A DS RRset without an RRSIG from the parent zone must be rejected — the
// digest match alone authenticates nothing, so accepting it lets an on-path
// attacker splice a forged KSK into the chain (full DNSSEC bypass).
func TestBuildChain_RejectsUnsignedDS(t *testing.T) {
	v, _ := buildTwoLevelFixture(t)
	mock := v.resolver.(*mockResolver)
	dsKey := "com.|" + strconv.Itoa(int(protocol.TypeDS))
	signed := mock.responses[dsKey]
	// Strip the RRSIG, keep the DS.
	var dsOnly []*protocol.ResourceRecord
	for _, rr := range signed.Answers {
		if rr.Type == protocol.TypeDS {
			dsOnly = append(dsOnly, rr)
		}
	}
	mock.responses[dsKey] = &protocol.Message{Answers: dsOnly}

	anchor, remaining := v.trustAnchors.FindClosestAnchor("example.com.")
	_, _, err := v.buildChain(context.Background(), anchor, remaining)
	if err == nil {
		t.Fatal("buildChain accepted a DS RRset with no parent RRSIG (DNSSEC bypass)")
	}
}

func TestCanonicalNameCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"example.com.", "example.com.", 0},
		{"EXAMPLE.com.", "example.COM.", 0},
		{"com.", "example.com.", -1}, // parent sorts before child
		{"a.example.com.", "b.example.com.", -1},
		// Plain string order gets this one wrong: "sub.a.example." >
		// "b.example." bytewise, but canonically everything under
		// a.example. sorts before b.example.
		{"sub.a.example.", "b.example.", -1},
		{"z.", "a.a.", 1}, // rightmost label decides: "a" < "z", so a.a. sorts first
	}
	for _, tt := range tests {
		got := canonicalNameCompare(tt.a, tt.b)
		norm := func(v int) int {
			if v < 0 {
				return -1
			}
			if v > 0 {
				return 1
			}
			return 0
		}
		if norm(got) != tt.want {
			t.Errorf("canonicalNameCompare(%q, %q) = %d, want sign %d", tt.a, tt.b, got, tt.want)
		}
		if tt.want != 0 {
			if rev := canonicalNameCompare(tt.b, tt.a); norm(rev) != -tt.want {
				t.Errorf("canonicalNameCompare(%q, %q) = %d, want sign %d", tt.b, tt.a, rev, -tt.want)
			}
		}
	}
}

// nameInRange must use canonical order for the NSEC gap test: the name
// sub.a.example. lies canonically between a.example. and b.example., even
// though plain string comparison puts it after b.example.
func TestNameInRange_CanonicalOrder(t *testing.T) {
	if !nameInRange("sub.a.example.", "a.example.", "b.example.") {
		t.Error("sub.a.example. must fall in NSEC gap (a.example., b.example.) under canonical ordering")
	}
	if nameInRange("c.example.", "a.example.", "b.example.") {
		t.Error("c.example. must NOT fall in NSEC gap (a.example., b.example.)")
	}
}

// Exact-match NSEC3 NoData proof: hashed name equals the owner hash and the
// type bitmap lacks the queried type. The strict range check used to run
// first and rejected every such proof.
func TestValidateNSEC3_ExactMatchNoData(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	const qname = "example.com."
	hash, err := NSEC3Hash(qname, 1, 0, nil)
	if err != nil {
		t.Fatalf("NSEC3Hash: %v", err)
	}
	owner := protocol.Base32Encode(hash) + ".com."

	nsec3 := &protocol.RDataNSEC3{
		HashAlgorithm: 1,
		Iterations:    0,
		NextHashed:    []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		TypeBitMap:    []uint16{protocol.TypeA, protocol.TypeRRSIG},
	}
	chain := []*chainLink{{zone: "com."}}

	if !v.validateNSEC3(owner, qname, protocol.TypeDS, nsec3, chain) {
		t.Error("exact-match NSEC3 with DS absent from bitmap must prove NoData")
	}
	if v.validateNSEC3(owner, qname, protocol.TypeA, nsec3, chain) {
		t.Error("exact-match NSEC3 with A present in bitmap must NOT prove denial")
	}
}
