package dnssec

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestParseDNSKEYPublicKeyRSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Pack the public key
	pub := &PublicKey{Algorithm: protocol.AlgorithmRSASHA256, Key: &privKey.PublicKey}
	keyData, err := packRSAPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to pack RSA public key: %v", err)
	}

	// Parse it back
	parsedKey, err := ParseDNSKEYPublicKey(protocol.AlgorithmRSASHA256, keyData)
	if err != nil {
		t.Fatalf("Failed to parse RSA public key: %v", err)
	}

	if parsedKey.Algorithm != protocol.AlgorithmRSASHA256 {
		t.Errorf("Algorithm mismatch: got %d, want %d", parsedKey.Algorithm, protocol.AlgorithmRSASHA256)
	}

	rsaKey, ok := parsedKey.Key.(*rsa.PublicKey)
	if !ok {
		t.Fatal("Expected RSA public key")
	}
	if rsaKey.E != privKey.E {
		t.Errorf("Exponent mismatch: got %d, want %d", rsaKey.E, privKey.E)
	}
}

func TestParseDNSKEYPublicKeyECDSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Pack the public key
	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	keyData, err := packECDSAPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to pack ECDSA public key: %v", err)
	}

	// Parse it back
	parsedKey, err := ParseDNSKEYPublicKey(protocol.AlgorithmECDSAP256SHA256, keyData)
	if err != nil {
		t.Fatalf("Failed to parse ECDSA public key: %v", err)
	}

	if parsedKey.Algorithm != protocol.AlgorithmECDSAP256SHA256 {
		t.Errorf("Algorithm mismatch: got %d, want %d", parsedKey.Algorithm, protocol.AlgorithmECDSAP256SHA256)
	}
}

func TestParseDNSKEYPublicKeyEd25519(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Parse it back
	parsedKey, err := ParseDNSKEYPublicKey(protocol.AlgorithmED25519, pubKey)
	if err != nil {
		t.Fatalf("Failed to parse Ed25519 public key: %v", err)
	}

	if parsedKey.Algorithm != protocol.AlgorithmED25519 {
		t.Errorf("Algorithm mismatch: got %d, want %d", parsedKey.Algorithm, protocol.AlgorithmED25519)
	}
}

func TestParseDNSKEYPublicKeyInvalid(t *testing.T) {
	tests := []struct {
		name      string
		algorithm uint8
		data      []byte
	}{
		{"invalid algorithm", 99, []byte{1, 2, 3}},
		{"empty RSA key", protocol.AlgorithmRSASHA256, []byte{}},
		{"short RSA key", protocol.AlgorithmRSASHA256, []byte{1}},
		{"empty ECDSA key", protocol.AlgorithmECDSAP256SHA256, []byte{}},
		{"short Ed25519 key", protocol.AlgorithmED25519, []byte{1, 2, 3}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseDNSKEYPublicKey(tt.algorithm, tt.data)
			if err == nil {
				t.Error("Expected error for invalid key")
			}
		})
	}
}

func TestVerifySignatureRSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	data := []byte("test data to sign")
	priv := &PrivateKey{Algorithm: protocol.AlgorithmRSASHA256, Key: privKey}

	// Sign
	signature, err := signRSASHA256(data, priv)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Pack public key
	pub := &PublicKey{Algorithm: protocol.AlgorithmRSASHA256, Key: &privKey.PublicKey}

	// Create RRSIG
	sig := &protocol.RDataRRSIG{
		Algorithm: protocol.AlgorithmRSASHA256,
		Signature: signature,
	}

	// Verify
	err = VerifySignature(sig, data, pub)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
}

func TestVerifySignatureECDSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	data := []byte("test data to sign")
	priv := &PrivateKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: privKey}

	// Sign
	signature, err := signECDSA(data, priv)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Pack public key
	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}

	// Create RRSIG
	sig := &protocol.RDataRRSIG{
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		Signature: signature,
	}

	// Verify
	err = VerifySignature(sig, data, pub)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
}

func TestVerifySignatureEd25519(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	data := []byte("test data to sign")
	priv := &PrivateKey{Algorithm: protocol.AlgorithmED25519, Key: privKey}

	// Sign
	signature, err := signEd25519(data, priv)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Pack public key
	pub := &PublicKey{Algorithm: protocol.AlgorithmED25519, Key: pubKey}

	// Create RRSIG
	sig := &protocol.RDataRRSIG{
		Algorithm: protocol.AlgorithmED25519,
		Signature: signature,
	}

	// Verify
	err = VerifySignature(sig, data, pub)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
}

func TestVerifySignatureInvalid(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	pub := &PublicKey{Algorithm: protocol.AlgorithmED25519, Key: pubKey}

	// Wrong signature
	sig := &protocol.RDataRRSIG{
		Algorithm: protocol.AlgorithmED25519,
		Signature: []byte("wrong signature"),
	}
	err = VerifySignature(sig, []byte("data"), pub)
	if err == nil {
		t.Error("Expected error for wrong signature")
	}

	// Algorithm mismatch
	sig2 := &protocol.RDataRRSIG{
		Algorithm: 99,
		Signature: []byte("sig"),
	}
	err = VerifySignature(sig2, []byte("data"), pub)
	if err == nil {
		t.Error("Expected error for algorithm mismatch")
	}
}

func TestGenerateKeyPairRSA(t *testing.T) {
	priv, pub, err := GenerateKeyPair(protocol.AlgorithmRSASHA256, true)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	if priv == nil || pub == nil {
		t.Fatal("Keys should not be nil")
	}
	if priv.Algorithm != protocol.AlgorithmRSASHA256 {
		t.Errorf("Algorithm mismatch: got %d", priv.Algorithm)
	}
}

func TestGenerateKeyPairECDSA(t *testing.T) {
	priv, pub, err := GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	if priv == nil || pub == nil {
		t.Fatal("Keys should not be nil")
	}
	if priv.Algorithm != protocol.AlgorithmECDSAP256SHA256 {
		t.Errorf("Algorithm mismatch: got %d", priv.Algorithm)
	}
}

func TestGenerateKeyPairEd25519(t *testing.T) {
	priv, pub, err := GenerateKeyPair(protocol.AlgorithmED25519, true)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	if priv == nil || pub == nil {
		t.Fatal("Keys should not be nil")
	}
	if priv.Algorithm != protocol.AlgorithmED25519 {
		t.Errorf("Algorithm mismatch: got %d", priv.Algorithm)
	}
}

func TestGenerateKeyPairInvalidAlgorithm(t *testing.T) {
	_, _, err := GenerateKeyPair(99, true)
	if err == nil {
		t.Error("Expected error for invalid algorithm")
	}
}

func TestSignData(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	key := &PrivateKey{
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		Key:       privKey,
	}

	data := []byte("test data")
	signature, err := SignData(protocol.AlgorithmECDSAP256SHA256, key, data)
	if err != nil {
		t.Fatalf("SignData failed: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature should not be empty")
	}
}

func TestSignDataAlgorithmMismatch(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	key := &PrivateKey{
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		Key:       privKey,
	}

	_, err = SignData(protocol.AlgorithmRSASHA256, key, []byte("data"))
	if err == nil {
		t.Error("Expected error for algorithm mismatch")
	}
}

func TestPackDNSKEYPublicKey(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	key := &PublicKey{
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		Key:       &privKey.PublicKey,
	}

	data, err := PackDNSKEYPublicKey(key)
	if err != nil {
		t.Fatalf("PackDNSKEYPublicKey failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("Packed key should not be empty")
	}
}

func TestPackDNSKEYPublicKeyInvalid(t *testing.T) {
	key := &PublicKey{Algorithm: 99, Key: nil}
	_, err := PackDNSKEYPublicKey(key)
	if err == nil {
		t.Error("Expected error for invalid algorithm")
	}
}

func TestNSEC3Hash(t *testing.T) {
	hash, err := NSEC3Hash("example.com", 1, 0, []byte{})
	if err != nil {
		t.Fatalf("NSEC3Hash failed: %v", err)
	}

	if len(hash) != 20 { // SHA-1 produces 20 bytes
		t.Errorf("Hash length: got %d, want 20", len(hash))
	}
}

func TestNSEC3HashInvalidAlgorithm(t *testing.T) {
	_, err := NSEC3Hash("example.com", 99, 0, []byte{})
	if err == nil {
		t.Error("Expected error for invalid algorithm")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt, err := GenerateSalt(16)
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	if len(salt) != 16 {
		t.Errorf("Salt length: got %d, want 16", len(salt))
	}
}

func TestIsAlgorithmSecure(t *testing.T) {
	tests := []struct {
		algorithm uint8
		secure    bool
	}{
		{protocol.AlgorithmRSASHA256, true},
		{protocol.AlgorithmRSASHA512, true},
		{protocol.AlgorithmECDSAP256SHA256, true},
		{protocol.AlgorithmECDSAP384SHA384, true},
		{protocol.AlgorithmED25519, true},
		{1, false}, // RSAMD5 - not secure
		{99, false},
	}

	for _, tt := range tests {
		result := IsAlgorithmSecure(tt.algorithm)
		if result != tt.secure {
			t.Errorf("IsAlgorithmSecure(%d) = %v, want %v", tt.algorithm, result, tt.secure)
		}
	}
}

func TestRecommendedAlgorithm(t *testing.T) {
	alg := RecommendedAlgorithm()
	if alg != protocol.AlgorithmECDSAP256SHA256 {
		t.Errorf("RecommendedAlgorithm() = %d, want %d", alg, protocol.AlgorithmECDSAP256SHA256)
	}
}

func TestEncodeDecodeString(t *testing.T) {
	data := []byte("test data")
	encoded := EncodeToString(data)

	decoded, err := DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString failed: %v", err)
	}

	if string(decoded) != string(data) {
		t.Errorf("Round-trip mismatch: got %q, want %q", decoded, data)
	}
}

func TestVerifySignatureRSASHA512(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	data := []byte("test data to sign with SHA-512")
	priv := &PrivateKey{Algorithm: protocol.AlgorithmRSASHA512, Key: privKey}

	// Sign with RSA-SHA512
	signature, err := signRSASHA512(data, priv)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Pack public key
	pub := &PublicKey{Algorithm: protocol.AlgorithmRSASHA512, Key: &privKey.PublicKey}

	// Create RRSIG
	sig := &protocol.RDataRRSIG{
		Algorithm: protocol.AlgorithmRSASHA512,
		Signature: signature,
	}

	// Verify
	err = VerifySignature(sig, data, pub)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}

	// Test with wrong data
	err = VerifySignature(sig, []byte("wrong data"), pub)
	if err == nil {
		t.Error("Expected error for wrong data")
	}
}

func TestSignDataRSASHA512(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	key := &PrivateKey{
		Algorithm: protocol.AlgorithmRSASHA512,
		Key:       privKey,
	}

	data := []byte("test data")
	signature, err := SignData(protocol.AlgorithmRSASHA512, key, data)
	if err != nil {
		t.Fatalf("SignData failed: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature should not be empty")
	}
}

func TestPackEd25519PublicKey(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	key := &PublicKey{
		Algorithm: protocol.AlgorithmED25519,
		Key:       pubKey,
	}

	data, err := PackDNSKEYPublicKey(key)
	if err != nil {
		t.Fatalf("PackDNSKEYPublicKey failed: %v", err)
	}

	// Ed25519 public key is 32 bytes
	if len(data) != 32 {
		t.Errorf("Packed key length: got %d, want 32", len(data))
	}
}

func TestSignDataInvalidAlgorithm(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	key := &PrivateKey{
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		Key:       privKey,
	}

	_, err = SignData(99, key, []byte("data"))
	if err == nil {
		t.Error("Expected error for invalid algorithm")
	}
}

func TestVerifySignatureWrongKey(t *testing.T) {
	// Generate two different keys
	privKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 1: %v", err)
	}

	privKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 2: %v", err)
	}

	data := []byte("test data to sign")
	priv := &PrivateKey{Algorithm: protocol.AlgorithmRSASHA256, Key: privKey1}

	// Sign with key 1
	signature, err := signRSASHA256(data, priv)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Try to verify with key 2 (should fail)
	pub := &PublicKey{Algorithm: protocol.AlgorithmRSASHA256, Key: &privKey2.PublicKey}
	sig := &protocol.RDataRRSIG{
		Algorithm: protocol.AlgorithmRSASHA256,
		Signature: signature,
	}

	err = VerifySignature(sig, data, pub)
	if err == nil {
		t.Error("Expected error for wrong key")
	}
}
