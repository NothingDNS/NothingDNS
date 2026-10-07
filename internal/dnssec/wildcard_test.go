package dnssec

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestWildcardOwnerWire verifies the RFC 4034 §3.1.8.1 wildcard owner
// reconstruction used when canonicalizing a wildcard-expanded RR: the owner
// hashed by the signer is "*.<closest-encloser>" (the rightmost sigLabels
// labels), not the literal expanded name.
func TestWildcardOwnerWire(t *testing.T) {
	owner, _ := protocol.ParseName("anything.wild.example.com.")

	// sigLabels = 3 → closest encloser wild.example.com. → wildcard
	// *.wild.example.com.
	wire, wildcard := wildcardOwnerWire(owner, 3)
	if !wildcard {
		t.Fatal("expected wildcard reconstruction when sigLabels < owner labels")
	}
	wantName, _ := protocol.ParseName("*.wild.example.com.")
	if string(wire) != string(wantName.CanonicalWire()) {
		t.Errorf("reconstructed wildcard owner wire mismatch")
	}

	// sigLabels == owner labels → literal owner, not a wildcard.
	litWire, isWild := wildcardOwnerWire(owner, 4)
	if isWild {
		t.Error("expected non-wildcard when sigLabels == owner labels")
	}
	if string(litWire) != string(owner.CanonicalWire()) {
		t.Errorf("literal owner wire mismatch")
	}
}

// wildcardTestFixture builds an ECDSA-signed validator setup for the
// example.com. zone and returns the validator, chain, key, and key tag.
func wildcardTestFixture(t *testing.T) (*Validator, []*chainLink, *PrivateKey, uint16) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	priv := &PrivateKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: privKey}
	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	keyData, err := packECDSAPublicKey(pub)
	if err != nil {
		t.Fatalf("packECDSAPublicKey: %v", err)
	}
	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: keyData,
	}
	keyTag := protocol.CalculateKeyTag(dnskeyData.Flags, dnskeyData.Algorithm, dnskeyData.PublicKey)
	zoneName, _ := protocol.ParseName("example.com.")
	dnskeyRR := &protocol.ResourceRecord{Name: zoneName, Type: protocol.TypeDNSKEY, Data: dnskeyData}
	chain := []*chainLink{{zone: "example.com.", dnsKeys: []*protocol.ResourceRecord{dnskeyRR}, validated: true}}

	config := DefaultValidatorConfig()
	config.IgnoreTime = true
	v := NewValidator(config, nil, nil)
	return v, chain, priv, keyTag
}

// signRR signs a single-record RRset and returns the RRSIG RR.
func signRR(t *testing.T, v *Validator, rr *protocol.ResourceRecord, labels uint8, priv *PrivateKey, keyTag uint16) *protocol.ResourceRecord {
	t.Helper()
	signer, _ := protocol.ParseName("example.com.")
	rrsig := &protocol.RDataRRSIG{
		TypeCovered: rr.Type,
		Algorithm:   protocol.AlgorithmECDSAP256SHA256,
		Labels:      labels,
		OriginalTTL: rr.TTL,
		Expiration:  uint32(time.Now().Add(time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		KeyTag:      keyTag,
		SignerName:  signer,
	}
	signedData, err := v.canonicalizeRRSet([]*protocol.ResourceRecord{rr}, rrsig)
	if err != nil {
		t.Fatalf("canonicalizeRRSet: %v", err)
	}
	sig, err := SignData(protocol.AlgorithmECDSAP256SHA256, priv, signedData)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	rrsig.Signature = sig
	return &protocol.ResourceRecord{Name: rr.Name, Type: protocol.TypeRRSIG, Class: protocol.ClassIN, TTL: rr.TTL, Data: rrsig}
}

func TestValidateMessage_WildcardWithNSECProof(t *testing.T) {
	v, chain, priv, keyTag := wildcardTestFixture(t)

	// Wildcard-expanded A at anything.wild.example.com. (4 labels), signed as
	// *.wild.example.com. (Labels=3).
	qname := "anything.wild.example.com."
	owner, _ := protocol.ParseName(qname)
	aRecord := &protocol.ResourceRecord{Name: owner, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}}
	aRRSIG := signRR(t, v, aRecord, 3, priv, keyTag)

	// Signed NSEC covering anything.wild.example.com. (a. < anything. < z.
	// in RFC 4034 §6.1 canonical order).
	nsecOwner, _ := protocol.ParseName("a.wild.example.com.")
	nsecNext, _ := protocol.ParseName("z.wild.example.com.")
	nsecRR := &protocol.ResourceRecord{Name: nsecOwner, Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataNSEC{NextDomain: nsecNext, TypeBitMap: []uint16{protocol.TypeA}}}
	nsecRRSIG := signRR(t, v, nsecRR, 4, priv, keyTag)

	// The closest encloser wild.example.com. lies between the signer and the
	// owner, so the validator asks for its DS and needs the parent's proof
	// that it is not a zone cut (F472): an NSEC at wild.example.com. without NS.
	wildName, _ := protocol.ParseName("wild.example.com.")
	wildNSEC := &protocol.ResourceRecord{Name: wildName, Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataNSEC{NextDomain: nsecOwner, TypeBitMap: []uint16{protocol.TypeTXT, protocol.TypeRRSIG, protocol.TypeNSEC}}}
	v.resolver = &mockResolver{responses: map[string]*protocol.Message{
		"wild.example.com.|43": {Authorities: []*protocol.ResourceRecord{wildNSEC, signRR(t, v, wildNSEC, 3, priv, keyTag)}},
	}}

	// With the authenticated no-exact-match NSEC proof → SECURE.
	withProof := &protocol.Message{
		Answers:     []*protocol.ResourceRecord{aRecord, aRRSIG},
		Authorities: []*protocol.ResourceRecord{nsecRR, nsecRRSIG},
	}
	if got := v.validateMessage(context.Background(), withProof, qname, chain); got != ValidationSecure {
		t.Errorf("wildcard answer WITH NSEC proof = %s, want SECURE", got)
	}

	// Without the proof → BOGUS (fail-closed, RFC 4035 §5.3.4). Critically NOT
	// fail-open: a valid *.wild.example.com. signature must not be accepted for
	// an arbitrary name without proof that the name has no exact match.
	withoutProof := &protocol.Message{Answers: []*protocol.ResourceRecord{aRecord, aRRSIG}}
	if got := v.validateMessage(context.Background(), withoutProof, qname, chain); got != ValidationBogus {
		t.Errorf("wildcard answer WITHOUT NSEC proof = %s, want BOGUS (must not fail open)", got)
	}
}
