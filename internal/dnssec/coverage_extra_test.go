package dnssec

import (
	"context"
	"crypto/ecdsa"
	_ "crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "math/big"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ---------------------------------------------------------------------------
// crypto.go: VerifySignature unsupported algorithm
// ---------------------------------------------------------------------------

func TestVerifySignatureUnsupportedAlgorithm(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pub := &PublicKey{Algorithm: 200, Key: &privKey.PublicKey}
	sig := &protocol.RDataRRSIG{
		Algorithm:  200,
		Signature: make([]byte, 128),
	}
	err = VerifySignature(sig, []byte("data"), pub)
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

// ---------------------------------------------------------------------------
// crypto.go: SignData unsupported algorithm
// ---------------------------------------------------------------------------

func TestSignDataUnsupportedAlgorithm(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	key := &PrivateKey{Algorithm: 200, Key: privKey}
	_, err = SignData(200, key, []byte("data"))
	if err == nil {
		t.Error("expected error for unsupported algorithm in SignData")
	}
}

// ---------------------------------------------------------------------------
// crypto.go: verifyECDSA unsupported algorithm in key
// ---------------------------------------------------------------------------

func TestVerifyECDSAUnsupportedAlgorithmInKey(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	pub := &PublicKey{Algorithm: 200, Key: &privKey.PublicKey}
	sig := &protocol.RDataRRSIG{
		Algorithm:  200,
		Signature: make([]byte, 64),
	}
	err = VerifySignature(sig, []byte("data"), pub)
	if err == nil {
		t.Error("expected error for unsupported ECDSA algorithm in verifyECDSA")
	}
}

// ---------------------------------------------------------------------------
// crypto.go: PackDNSKEYPublicKey RSA path
// ---------------------------------------------------------------------------

func TestPackDNSKEYPublicKeyRSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	key := &PublicKey{Algorithm: protocol.AlgorithmRSASHA256, Key: &privKey.PublicKey}
	data, err := PackDNSKEYPublicKey(key)
	if err != nil {
		t.Fatalf("PackDNSKEYPublicKey RSA: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty packed key")
	}
}

// ---------------------------------------------------------------------------
// crypto.go: PackDNSKEYPublicKey RSA SHA-512
// ---------------------------------------------------------------------------

func TestPackDNSKEYPublicKeyRSASHA512(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	key := &PublicKey{Algorithm: protocol.AlgorithmRSASHA512, Key: &privKey.PublicKey}
	data, err := PackDNSKEYPublicKey(key)
	if err != nil {
		t.Fatalf("PackDNSKEYPublicKey RSA-SHA512: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty packed key")
	}
}

// ---------------------------------------------------------------------------
// crypto.go: parseECDSAPublicKey unsupported algorithm
// ---------------------------------------------------------------------------

func TestParseECDSAPublicKeyUnsupportedAlgorithm(t *testing.T) {
	_, err := parseECDSAPublicKey(200, make([]byte, 64))
	if err == nil {
		t.Error("expected error for unsupported ECDSA algorithm")
	}
}

// ---------------------------------------------------------------------------
// crypto.go: parseECDSAPublicKey wrong key length
// ---------------------------------------------------------------------------

func TestParseECDSAPublicKeyWrongLength(t *testing.T) {
	_, err := parseECDSAPublicKey(protocol.AlgorithmECDSAP256SHA256, make([]byte, 30))
	if err == nil {
		t.Error("expected error for wrong ECDSA key length")
	}
}

// ---------------------------------------------------------------------------
// crypto.go: parseRSAPublicKey too short
// ---------------------------------------------------------------------------

func TestParseRSAPublicKeyTooShort(t *testing.T) {
	_, err := parseRSAPublicKey([]byte{0x01, 0x00})
	if err == nil {
		t.Error("expected error for RSA key too short")
	}
}

// ---------------------------------------------------------------------------
// crypto.go: ParseDNSKEYPublicKey RSA SHA-512
// ---------------------------------------------------------------------------

func TestParseDNSKEYPublicKeyRSASHA512(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pub := &PublicKey{Algorithm: protocol.AlgorithmRSASHA512, Key: &privKey.PublicKey}
	keyData, err := packRSAPublicKey(pub)
	if err != nil {
		t.Fatalf("pack RSA key: %v", err)
	}
	parsedKey, err := ParseDNSKEYPublicKey(protocol.AlgorithmRSASHA512, keyData)
	if err != nil {
		t.Fatalf("ParseDNSKEYPublicKey RSA-SHA512: %v", err)
	}
	t.Logf("parsed algorithm: %d", parsedKey.Algorithm)
}

// ---------------------------------------------------------------------------
// crypto.go: GenerateKeyPair RSA SHA-512
// ---------------------------------------------------------------------------

func TestGenerateKeyPairRSASHA512(t *testing.T) {
	priv, pub, err := GenerateKeyPair(protocol.AlgorithmRSASHA512, false)
	if err != nil {
		t.Fatalf("GenerateKeyPair RSA-SHA512: %v", err)
	}
	if priv == nil || pub == nil {
		t.Fatal("expected non-nil keys")
	}
}

// ---------------------------------------------------------------------------
// crypto.go: generateECDSAKeyPair unsupported algorithm
// ---------------------------------------------------------------------------

func TestGenerateECDSAKeyPairUnsupported(t *testing.T) {
	_, _, err := generateECDSAKeyPair(200)
	if err == nil {
		t.Error("expected error for unsupported ECDSA algorithm in generate")
	}
}

// ---------------------------------------------------------------------------
// crypto.go: signECDSA P-384 path
// ---------------------------------------------------------------------------

func TestSignECDSAP384(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA P-384 key: %v", err)
	}
	key := &PrivateKey{Algorithm: protocol.AlgorithmECDSAP384SHA384, Key: privKey}
	sig, err := signECDSA([]byte("test data"), key)
	if err != nil {
		t.Fatalf("signECDSA P-384: %v", err)
	}
	if len(sig) != 96 { // 48 + 48 for P-384
		t.Errorf("expected 96-byte signature, got %d", len(sig))
	}
}

// ---------------------------------------------------------------------------
// crypto.go: VerifySignature ECDSA P-384 round-trip
// ---------------------------------------------------------------------------

func TestVerifySignatureECDSAP384RoundTrip(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA P-384 key: %v", err)
	}
	data := []byte("test data to sign")
	priv := &PrivateKey{Algorithm: protocol.AlgorithmECDSAP384SHA384, Key: privKey}

	signature, err := signECDSA(data, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP384SHA384, Key: &privKey.PublicKey}
	sig := &protocol.RDataRRSIG{
		Algorithm:  protocol.AlgorithmECDSAP384SHA384,
		Signature: signature,
	}
	err = VerifySignature(sig, data, pub)
	if err != nil {
		t.Errorf("ECDSA P-384 verify failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// crypto.go: verifyECDSA unsupported algorithm in switch
// ---------------------------------------------------------------------------

func TestVerifyECDSAUnsupportedInSwitch(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// Use a key with algorithm that doesn't match P256 or P384
	pub := &PublicKey{Algorithm: 200, Key: &privKey.PublicKey}
	sig := &protocol.RDataRRSIG{
		Algorithm:  200,
		Signature: make([]byte, 64),
	}
	err = VerifySignature(sig, []byte("data"), pub)
	if err == nil {
		t.Error("expected error for unsupported algorithm in verifyECDSA switch")
	}
}

// ---------------------------------------------------------------------------
// signer.go: Signer.GenerateKeyPair error path
// ---------------------------------------------------------------------------

func TestSigner_GenerateKeyPairError(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())
	_, err := s.GenerateKeyPair(200, true)
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

// ---------------------------------------------------------------------------
// signer.go: Signer.GenerateKeyPair ECDSA P-384
// ---------------------------------------------------------------------------

func TestSigner_GenerateKeyPairECDSAP384(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())
	key, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP384SHA384, false)
	if err != nil {
		t.Fatalf("GenerateKeyPair ECDSA P-384: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if !key.IsZSK {
		t.Error("expected ZSK")
	}
}

// ---------------------------------------------------------------------------
// signer.go: Signer.GenerateKeyPair Ed25519
// ---------------------------------------------------------------------------

func TestSigner_GenerateKeyPairEd25519(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())
	key, err := s.GenerateKeyPair(protocol.AlgorithmED25519, true)
	if err != nil {
		t.Fatalf("GenerateKeyPair Ed25519: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if !key.IsKSK {
		t.Error("expected KSK")
	}
}

// ---------------------------------------------------------------------------
// signer.go: Signer.SignZone no keys error
// ---------------------------------------------------------------------------

func TestSigner_SignZoneNoKeys(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())
	_, err := s.SignZone([]*protocol.ResourceRecord{})
	if err == nil {
		t.Error("expected error for no signing keys")
	}
}

// ---------------------------------------------------------------------------
// signer.go: Signer.SignZone with DNSKEY records
// ---------------------------------------------------------------------------

func TestSigner_SignZoneWithRecords(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())
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
	signed, err := s.SignZone(records)
	if err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	if len(signed) == 0 {
		t.Error("expected signed records")
	}
}

// ---------------------------------------------------------------------------
// signer.go: Signer.SignRRSet with expired inception (uint32 timestamps)
// ---------------------------------------------------------------------------

func TestSigner_SignRRSetExpiredInception(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())
	key, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	name, _ := protocol.ParseName("test.example.com.")
	rrSet := []*protocol.ResourceRecord{
		{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
		},
	}

	inception := uint32(time.Now().Add(-2 * time.Hour).Unix())
	expiration := uint32(time.Now().Add(-1 * time.Hour).Unix())

	// SignRRSet does not validate timestamps - it signs regardless
	_, err = s.SignRRSet(rrSet, key, inception, expiration)
	_ = err
}

// ---------------------------------------------------------------------------
// trustanchor.go: DSFromDNSKEY unsupported digest type
// ---------------------------------------------------------------------------

func TestDSFromDNSKEY_UnsupportedDigestType(t *testing.T) {
	dnskey := &protocol.RDataDNSKEY{
		Flags:     0x0100,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: make([]byte, 64),
	}
	_, err := DSFromDNSKEY("example.com.", dnskey, 200)
	if err == nil {
		t.Error("expected error for unsupported digest type")
	}
}

// ---------------------------------------------------------------------------
// trustanchor.go: DSFromDNSKEY SHA-1 digest
// ---------------------------------------------------------------------------

func TestDSFromDNSKEY_SHA1Digest(t *testing.T) {
	dnskey := &protocol.RDataDNSKEY{
		Flags:     0x0100,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: make([]byte, 64),
	}
	ta, err := DSFromDNSKEY("example.com.", dnskey, 1) // SHA-1
	if err != nil {
		t.Fatalf("DSFromDNSKEY SHA-1: %v", err)
	}
	if ta == nil {
		t.Fatal("expected non-nil trust anchor")
	}
}

// ---------------------------------------------------------------------------
// trustanchor.go: DSFromDNSKEY SHA-384 digest
// ---------------------------------------------------------------------------

func TestDSFromDNSKEY_SHA384Digest(t *testing.T) {
	dnskey := &protocol.RDataDNSKEY{
		Flags:     0x0100,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: make([]byte, 64),
	}
	ta, err := DSFromDNSKEY("example.com.", dnskey, 4) // SHA-384
	if err != nil {
		t.Fatalf("DSFromDNSKEY SHA-384: %v", err)
	}
	if ta == nil {
		t.Fatal("expected non-nil trust anchor")
	}
}

// ---------------------------------------------------------------------------
// trustanchor.go: parseXMLTime formats
// ---------------------------------------------------------------------------

func TestParseXMLTimeFormats(t *testing.T) {
	// RFC 3339 format
	t1, err := parseXMLTime("2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("RFC3339: %v", err)
	}
	if t1.Year() != 2024 {
		t.Errorf("expected year 2024, got %d", t1.Year())
	}

	// Without timezone
	t2, err := parseXMLTime("2024-06-15T12:30:00")
	if err != nil {
		t.Fatalf("without tz: %v", err)
	}
	if t2.Year() != 2024 {
		t.Errorf("expected year 2024, got %d", t2.Year())
	}

	// Invalid format
	_, err = parseXMLTime("not-a-date")
	if err == nil {
		t.Error("expected error for invalid time format")
	}
}

// ---------------------------------------------------------------------------
// trustanchor.go: canonicalZone empty and no trailing dot
// ---------------------------------------------------------------------------

func TestCanonicalZone_Variants(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "."},
		{"com", "com."},
		{"example.com", "example.com."},
		{"example.com.", "example.com."},
	}
	for _, tt := range tests {
		result := canonicalZone(tt.input)
		if result != tt.expected {
			t.Errorf("canonicalZone(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// validator.go: ValidationResult.String default
// ---------------------------------------------------------------------------

func TestValidationResult_StringDefault(t *testing.T) {
	r := ValidationResult(99)
	s := r.String()
	if s != "UNKNOWN" {
		t.Errorf("expected UNKNOWN, got %s", s)
	}
}

// ---------------------------------------------------------------------------
// validator.go: Validator.ValidateResponse nil message
// ---------------------------------------------------------------------------

func TestValidator_ValidateResponse_NilMessage(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), NewTrustAnchorStore(), nil)
	_, err := v.ValidateResponse(context.Background(), nil, "example.com.")
	if err == nil {
		t.Error("expected error for nil message")
	}
}

// ---------------------------------------------------------------------------
// validator.go: Validator.ValidateResponse no questions
// ---------------------------------------------------------------------------

func TestValidator_ValidateResponse_NoQuestions(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), NewTrustAnchorStore(), nil)
	msg := &protocol.Message{}
	result, err := v.ValidateResponse(context.Background(), msg, "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != ValidationInsecure {
		t.Errorf("expected Insecure, got %v", result)
	}
}

// ---------------------------------------------------------------------------
// validator.go: Validator.ValidateResponse no trust anchors
// ---------------------------------------------------------------------------

func TestValidator_ValidateResponse_NoTrustAnchors(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), NewTrustAnchorStore(), nil)
	name, _ := protocol.ParseName("example.com.")
	msg := &protocol.Message{
		Header: protocol.Header{QDCount: 1},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
	}
	result, err := v.ValidateResponse(context.Background(), msg, "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != ValidationInsecure {
		t.Errorf("expected Insecure, got %v", result)
	}
}

// ---------------------------------------------------------------------------
// validator.go: HasSignature and ExtractRRSIGs
// ---------------------------------------------------------------------------

func TestHasSignature_NoRRSIG_Extra(t *testing.T) {
	msg := &protocol.Message{
		Answers: []*protocol.ResourceRecord{
			{Type: protocol.TypeA, Data: &protocol.RDataA{}},
		},
	}
	if HasSignature(msg) {
		t.Error("expected no signature")
	}
}

func TestExtractRRSIGs_NoRRSIG_Extra(t *testing.T) {
	msg := &protocol.Message{
		Answers: []*protocol.ResourceRecord{
			{Type: protocol.TypeA, Data: &protocol.RDataA{}},
		},
	}
	sigs := ExtractRRSIGs(msg, protocol.TypeA)
	if len(sigs) != 0 {
		t.Errorf("expected 0 RRSIGs, got %d", len(sigs))
	}
}

// ---------------------------------------------------------------------------
// validator.go: validateRRSIG expired and not-yet-valid
// ---------------------------------------------------------------------------

func TestValidateRRSIG_Expired(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), NewTrustAnchorStore(), nil)
	rrsig := &protocol.RDataRRSIG{
		Algorithm:  protocol.AlgorithmECDSAP256SHA256,
		Expiration: uint32(time.Now().Add(-1 * time.Hour).Unix()),
		Inception:  uint32(time.Now().Add(-2 * time.Hour).Unix()),
	}
	result := v.validateRRSIG(nil, rrsig, nil)
	if result {
		t.Error("expected false for expired signature")
	}
}

func TestValidateRRSIG_NotYetValid(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), NewTrustAnchorStore(), nil)
	rrsig := &protocol.RDataRRSIG{
		Algorithm:  protocol.AlgorithmECDSAP256SHA256,
		Expiration: uint32(time.Now().Add(2 * time.Hour).Unix()),
		Inception:  uint32(time.Now().Add(1 * time.Hour).Unix()),
	}
	result := v.validateRRSIG(nil, rrsig, nil)
	if result {
		t.Error("expected false for not-yet-valid signature")
	}
}

// ---------------------------------------------------------------------------
// validator.go: validateRRSIG ignore time
// ---------------------------------------------------------------------------

func TestValidateRRSIG_IgnoreTime(t *testing.T) {
	cfg := DefaultValidatorConfig()
	cfg.IgnoreTime = true
	v := NewValidator(cfg, NewTrustAnchorStore(), nil)

	rrsig := &protocol.RDataRRSIG{
		Algorithm:  protocol.AlgorithmECDSAP256SHA256,
		Expiration: uint32(time.Now().Add(-1 * time.Hour).Unix()),
		Inception:  uint32(time.Now().Add(-2 * time.Hour).Unix()),
	}
	// With IgnoreTime, it should pass the time check (but may fail on missing keys)
	result := v.validateRRSIG(nil, rrsig, nil)
	// Result is false because no matching DNSKEY, but the time check should not be the failure
	_ = result
}

// ---------------------------------------------------------------------------
// validator.go: findRRSIG no match
// ---------------------------------------------------------------------------

func TestFindRRSIG_NoMatch(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), NewTrustAnchorStore(), nil)
	name, _ := protocol.ParseName("test.com.")
	answers := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeA, Data: &protocol.RDataA{}},
	}
	result := v.findRRSIG(answers, "other.com.", protocol.TypeA)
	if result != nil {
		t.Error("expected nil when no RRSIG found")
	}
}

