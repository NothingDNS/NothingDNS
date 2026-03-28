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

// ---------------------------------------------------------------------------
// signer.go:150 - SignZone with existing TypeDNSKEY records in input
// Exercises the `if rr.Type == protocol.TypeDNSKEY` true branch so the
// signer reuses the supplied DNSKEY RRs instead of generating new ones.
// ---------------------------------------------------------------------------

func TestSignZone_WithExistingDNSKEYRecords(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())
	// Generate a KSK so signing can proceed
	_, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, true)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	name, _ := protocol.ParseName("example.com.")
	// Build a DNSKEY record that matches one of the signer's keys
	keys := s.GetKSKs()
	if len(keys) == 0 {
		t.Fatal("expected at least one KSK")
	}
	existingDNSKEY := &protocol.ResourceRecord{
		Name:  name,
		Type:  protocol.TypeDNSKEY,
		Class: protocol.ClassIN,
		TTL:   3600,
		Data:  keys[0].DNSKEY,
	}

	aName, _ := protocol.ParseName("www.example.com.")
	records := []*protocol.ResourceRecord{
		existingDNSKEY,
		{
			Name:  aName,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{10, 0, 0, 1}},
		},
	}

	signed, err := s.SignZone(records)
	if err != nil {
		t.Fatalf("SignZone with existing DNSKEY: %v", err)
	}
	if len(signed) == 0 {
		t.Error("expected signed records")
	}

	// Verify the existing DNSKEY is present in the output
	found := false
	for _, rr := range signed {
		if rr.Type == protocol.TypeDNSKEY {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DNSKEY record in signed output")
	}
}

// ---------------------------------------------------------------------------
// signer.go:245 - SignRRSet with empty RRSet
// Exercises the early-return error path for len(rrSet)==0.
// ---------------------------------------------------------------------------

func TestSignRRSet_EmptyRRSet(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())
	key, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, true)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	_, err = s.SignRRSet([]*protocol.ResourceRecord{}, key, 0, 0)
	if err == nil {
		t.Error("expected error when signing empty RRSet")
	}
}

// ---------------------------------------------------------------------------
// validator.go:334 - findRRSIG with record having TypeRRSIG but wrong Data type
// Exercises the `ok=false` branch when the type assertion to *RDataRRSIG
// fails because Data is actually &RDataA{}.
// ---------------------------------------------------------------------------

func TestFindRRSIG_WrongDataType(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), NewTrustAnchorStore(), nil)
	name, _ := protocol.ParseName("test.com.")

	// Record has TypeRRSIG but Data is not *RDataRRSIG
	answers := []*protocol.ResourceRecord{
		{
			Name:  name,
			Type:  protocol.TypeRRSIG,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
		},
	}

	result := v.findRRSIG(answers, "test.com.", protocol.TypeA)
	if result != nil {
		t.Error("expected nil when RRSIG record has wrong Data type")
	}
}

// ---------------------------------------------------------------------------
// validator.go:361 - validateRRSIG key search with DNSKEY record having wrong
// Data type. Exercises the `ok=false` branch in the dnskey loop.
// ---------------------------------------------------------------------------

func TestValidateRRSIG_DNSKEYWrongDataType(t *testing.T) {
	cfg := DefaultValidatorConfig()
	cfg.IgnoreTime = true
	v := NewValidator(cfg, NewTrustAnchorStore(), nil)

	signerName, _ := protocol.ParseName("example.com.")
	rrsig := &protocol.RDataRRSIG{
		TypeCovered: protocol.TypeA,
		Algorithm:   protocol.AlgorithmECDSAP256SHA256,
		Labels:      2,
		OriginalTTL: 300,
		Expiration:  uint32(time.Now().Add(1 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()),
		KeyTag:      12345,
		SignerName:  signerName,
		Signature:   make([]byte, 64),
	}

	// dnsKeys list has a record with wrong Data type
	name, _ := protocol.ParseName("example.com.")
	dnsKeys := []*protocol.ResourceRecord{
		{
			Name:  name,
			Type:  protocol.TypeDNSKEY,
			Class: protocol.ClassIN,
			TTL:   3600,
			Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}, // wrong type
		},
	}

	result := v.validateRRSIG(nil, rrsig, dnsKeys)
	if result {
		t.Error("expected false when DNSKEY has wrong Data type")
	}
}

// ---------------------------------------------------------------------------
// validator.go:567 - validateNSEC3 with unsupported HashAlgorithm (99)
// Exercises the error path in NSEC3Hash where algorithm != 1 returns error.
// ---------------------------------------------------------------------------

func TestValidateNSEC3_UnsupportedHashAlgorithm(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), NewTrustAnchorStore(), nil)

	owner, _ := protocol.ParseName("abc.example.com.")
	nextHash := make([]byte, 20)

	nsec3 := &protocol.RDataNSEC3{
		HashAlgorithm: 99, // unsupported
		Iterations:    0,
		Salt:          nil,
		HashLength:    uint8(len(nextHash)),
		NextHashed:    nextHash,
		TypeBitMap:    []uint16{protocol.TypeA},
	}

	chain := []*chainLink{
		{zone: "example.com.", validated: true},
	}

	result := v.validateNSEC3(owner.String(), "www.example.com.", protocol.TypeA, nsec3, chain)
	if result {
		t.Error("expected false for unsupported NSEC3 hash algorithm")
	}
}

// ---------------------------------------------------------------------------
// trustanchor.go:234 - Parse XML with valid validFrom but invalid validUntil
// Exercises the error-return path when validUntil cannot be parsed.
// ---------------------------------------------------------------------------

func TestParseTrustAnchorXML_InvalidValidUntil(t *testing.T) {
	xmlData := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="test">
  <Zone>.</Zone>
  <KeyDigest id="1" validFrom="2024-01-01T00:00:00Z" validUntil="not-a-valid-date">
    <KeyTag>20326</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>AABBCCDD</Digest>
  </KeyDigest>
</TrustAnchor>`)

	_, err := ParseTrustAnchorXML(xmlData)
	if err == nil {
		t.Error("expected error for invalid validUntil time string")
	}
}

// ---------------------------------------------------------------------------
// validator.go:493 - canonicalSort with records having same name+type but
// different RDATA. Exercises the RDATA comparison branch.
// ---------------------------------------------------------------------------

func TestCanonicalSort_SameNameTypeDifferentRDATA(t *testing.T) {
	name, _ := protocol.ParseName("multi.example.com.")

	rr1 := &protocol.ResourceRecord{
		Name:  name,
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataA{Address: [4]byte{192, 168, 1, 1}},
	}
	rr2 := &protocol.ResourceRecord{
		Name:  name,
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataA{Address: [4]byte{10, 0, 0, 1}},
	}
	rr3 := &protocol.ResourceRecord{
		Name:  name,
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataA{Address: [4]byte{172, 16, 0, 1}},
	}

	rrs := []*protocol.ResourceRecord{rr2, rr3, rr1}
	canonicalSort(rrs)

	// After sorting, records should be ordered by RDATA.
	// 10.0.0.1 < 172.16.0.1 < 192.168.1.1
	if len(rrs) != 3 {
		t.Fatalf("expected 3 records, got %d", len(rrs))
	}

	first := rrs[0].Data.(*protocol.RDataA)
	if first.Address != [4]byte{10, 0, 0, 1} {
		t.Errorf("first record address = %v, want 10.0.0.1", first.Address)
	}

	last := rrs[2].Data.(*protocol.RDataA)
	if last.Address != [4]byte{192, 168, 1, 1} {
		t.Errorf("last record address = %v, want 192.168.1.1", last.Address)
	}
}

// ---------------------------------------------------------------------------
// validator.go:227 - validateTrustAnchor with DNSKEY records where some have
// non-matching algorithms. Exercises the `continue` branches.
// ---------------------------------------------------------------------------

func TestValidateTrustAnchor_NonMatchingAlgorithm(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), NewTrustAnchorStore(), nil)

	anchor := &TrustAnchor{
		Zone:       "example.com.",
		KeyTag:     12345,
		Algorithm:  protocol.AlgorithmECDSAP256SHA256,
		DigestType: 2,
		Digest:     make([]byte, 32), // arbitrary digest
		PublicKey:  nil,
	}

	name, _ := protocol.ParseName("example.com.")

	// First DNSKEY has a non-matching key tag (should hit continue)
	// Second DNSKEY has a matching key tag but non-matching algorithm (should hit continue)
	dnsKeys := []*protocol.ResourceRecord{
		{
			Name:  name,
			Type:  protocol.TypeDNSKEY,
			Class: protocol.ClassIN,
			TTL:   3600,
			Data: &protocol.RDataDNSKEY{
				Flags:     0x0100,
				Protocol:  3,
				Algorithm: protocol.AlgorithmECDSAP256SHA256,
				PublicKey: make([]byte, 64),
			},
		},
		{
			Name:  name,
			Type:  protocol.TypeDNSKEY,
			Class: protocol.ClassIN,
			TTL:   3600,
			Data: &protocol.RDataDNSKEY{
				Flags:     0x0100,
				Protocol:  3,
				Algorithm: protocol.AlgorithmRSASHA256, // non-matching algorithm
				PublicKey: make([]byte, 128),
			},
		},
	}

	// None should match since KeyTag of the anchor doesn't match any key
	result := v.validateTrustAnchor(anchor, dnsKeys)
	if result {
		t.Error("expected false when no DNSKEY matches the trust anchor")
	}
}

// ---------------------------------------------------------------------------
// signer.go:441 - NSEC3 generation with unsupported algorithm (99).
// NSEC3Hash will fail, triggering the `continue` in the loop so no NSEC3
// records are generated for names that fail to hash.
// ---------------------------------------------------------------------------

func TestGenerateNSEC3_UnsupportedAlgorithm(t *testing.T) {
	cfg := SignerConfig{
		NSEC3Enabled:      true,
		NSEC3Algorithm:    99, // unsupported
		NSEC3Iterations:   0,
		NSEC3Salt:         nil,
		SignatureValidity: 30 * 24 * time.Hour,
		InceptionOffset:   1 * time.Hour,
	}
	s := NewSigner("example.com.", cfg)
	_, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, true)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	name, _ := protocol.ParseName("www.example.com.")
	records := []*protocol.ResourceRecord{
		{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
		},
	}

	nsec3Records := s.generateNSEC3(records)
	// With an unsupported algorithm, NSEC3Hash fails for every name,
	// so no NSEC3 records should be produced.
	if len(nsec3Records) != 0 {
		t.Errorf("expected 0 NSEC3 records with unsupported algorithm, got %d", len(nsec3Records))
	}
}

// ---------------------------------------------------------------------------
// Additional: validateRRSIG with real ECDSA key but tampered signature
// Exercises the full verification path that returns false.
// ---------------------------------------------------------------------------

func TestValidateRRSIG_TamperedSignature(t *testing.T) {
	cfg := DefaultValidatorConfig()
	cfg.IgnoreTime = true
	v := NewValidator(cfg, NewTrustAnchorStore(), nil)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pubKeyData, err := packECDSAPublicKey(&PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey})
	if err != nil {
		t.Fatalf("pack key: %v", err)
	}

	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     0x0100,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: pubKeyData,
	}
	keyTag := protocol.CalculateKeyTag(dnskeyData.Flags, dnskeyData.Algorithm, dnskeyData.PublicKey)

	name, _ := protocol.ParseName("example.com.")
	signerName, _ := protocol.ParseName("example.com.")

	dnsKeys := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeDNSKEY, Class: protocol.ClassIN, TTL: 3600, Data: dnskeyData},
	}

	rrsig := &protocol.RDataRRSIG{
		TypeCovered: protocol.TypeA,
		Algorithm:   protocol.AlgorithmECDSAP256SHA256,
		Labels:      2,
		OriginalTTL: 300,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()),
		KeyTag:      keyTag,
		SignerName:  signerName,
		Signature:   make([]byte, 64), // all zeros - tampered
	}

	rrSet := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
	}

	result := v.validateRRSIG(rrSet, rrsig, dnsKeys)
	if result {
		t.Error("expected false for tampered signature")
	}
}

// ---------------------------------------------------------------------------
// Additional: validateRRSIG with expired signature and no matching key
// Ensures the no-matching-key path returns false even with IgnoreTime.
// ---------------------------------------------------------------------------

func TestValidateRRSIG_NoMatchingKeyWithIgnoreTime(t *testing.T) {
	cfg := DefaultValidatorConfig()
	cfg.IgnoreTime = true
	v := NewValidator(cfg, NewTrustAnchorStore(), nil)

	signerName, _ := protocol.ParseName("example.com.")
	rrsig := &protocol.RDataRRSIG{
		TypeCovered: protocol.TypeA,
		Algorithm:   protocol.AlgorithmECDSAP256SHA256,
		KeyTag:      65535, // no matching key
		SignerName:  signerName,
		Signature:   make([]byte, 64),
	}

	// Empty dnsKeys list
	result := v.validateRRSIG(nil, rrsig, []*protocol.ResourceRecord{})
	if result {
		t.Error("expected false when no matching DNSKEY found")
	}
}

// ---------------------------------------------------------------------------
// Additional: validateTrustAnchor with a DNSKEY record whose Data is not
// *RDataDNSKEY (wrong Data type). Exercises the `ok=false` continue branch.
// ---------------------------------------------------------------------------

func TestValidateTrustAnchor_WrongDataType(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), NewTrustAnchorStore(), nil)

	anchor := &TrustAnchor{
		Zone:      "example.com.",
		KeyTag:    12345,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
	}

	name, _ := protocol.ParseName("example.com.")
	dnsKeys := []*protocol.ResourceRecord{
		{
			Name:  name,
			Type:  protocol.TypeDNSKEY,
			Class: protocol.ClassIN,
			TTL:   3600,
			Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}, // wrong type
		},
	}

	result := v.validateTrustAnchor(anchor, dnsKeys)
	if result {
		t.Error("expected false when DNSKEY Data is wrong type")
	}
}

// ---------------------------------------------------------------------------
// Additional: validateTrustAnchor with matching PublicKey (not Digest).
// Exercises the `len(anchor.PublicKey) > 0` branch returning true.
// ---------------------------------------------------------------------------

func TestValidateTrustAnchor_MatchingPublicKey(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), NewTrustAnchorStore(), nil)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pubKeyData, err := packECDSAPublicKey(&PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey})
	if err != nil {
		t.Fatalf("pack key: %v", err)
	}

	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     0x0100,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: pubKeyData,
	}
	keyTag := protocol.CalculateKeyTag(dnskeyData.Flags, dnskeyData.Algorithm, dnskeyData.PublicKey)

	anchor := &TrustAnchor{
		Zone:      "example.com.",
		KeyTag:    keyTag,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: pubKeyData,
	}

	name, _ := protocol.ParseName("example.com.")
	dnsKeys := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeDNSKEY, Class: protocol.ClassIN, TTL: 3600, Data: dnskeyData},
	}

	result := v.validateTrustAnchor(anchor, dnsKeys)
	if !result {
		t.Error("expected true when PublicKey matches")
	}
}

// ---------------------------------------------------------------------------
// Additional: buildChain returns error when resolver is nil
// ---------------------------------------------------------------------------

func TestBuildChain_NilResolver(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), NewTrustAnchorStore(), nil)

	anchor := &TrustAnchor{
		Zone:      ".",
		KeyTag:    20326,
		Algorithm: protocol.AlgorithmRSASHA256,
	}

	_, err := v.buildChain(context.Background(), anchor, []string{})
	if err == nil {
		t.Error("expected error when resolver is nil")
	}
}

// ---------------------------------------------------------------------------
// Additional: validateDelegation with non-DS Data type
// ---------------------------------------------------------------------------

func TestValidateDelegation_WrongDSType(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), NewTrustAnchorStore(), nil)

	parent := &chainLink{zone: "com.", validated: true}

	name, _ := protocol.ParseName("example.com.")
	dsRecords := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeDS, Class: protocol.ClassIN, TTL: 3600, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
	}
	childKeys := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeDNSKEY, Class: protocol.ClassIN, TTL: 3600, Data: &protocol.RDataDNSKEY{Flags: 0x0100, Protocol: 3, Algorithm: 8, PublicKey: make([]byte, 64)}},
	}

	result := v.validateDelegation(parent, dsRecords, childKeys)
	if result {
		t.Error("expected false when DS Data is wrong type")
	}
}
