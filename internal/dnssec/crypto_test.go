package dnssec

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
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

func TestParseRSAPublicKey3ByteExponentLength(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Manually construct key data with 3-byte exponent length prefix
	exponent := big.NewInt(int64(privKey.E)).Bytes()
	modulus := privKey.N.Bytes()

	// Force 3-byte exponent length by prefixing with 0x00 followed by 2-byte length
	var keyData []byte
	keyData = append(keyData, 0x00)
	keyData = append(keyData, byte(len(exponent)>>8), byte(len(exponent)))
	keyData = append(keyData, exponent...)
	keyData = append(keyData, modulus...)

	parsedKey, err := parseRSAPublicKey(keyData)
	if err != nil {
		t.Fatalf("Failed to parse RSA key with 3-byte exponent length: %v", err)
	}

	rsaKey, ok := parsedKey.Key.(*rsa.PublicKey)
	if !ok {
		t.Fatal("Expected RSA public key")
	}
	if rsaKey.E != privKey.E {
		t.Errorf("Exponent mismatch: got %d, want %d", rsaKey.E, privKey.E)
	}
}

func TestParseRSAPublicKey3ByteExponentTooShort(t *testing.T) {
	// Provide key data starting with 0x00 but not enough bytes for 3-byte header
	keyData := []byte{0x00, 0x01} // only 2 bytes, needs at least 3

	_, err := parseRSAPublicKey(keyData)
	if err == nil {
		t.Error("Expected error for 3-byte exponent length with insufficient data")
	}
}

func TestParseRSAPublicKeyExponentTooLong(t *testing.T) {
	// keyData with exponent length pointing beyond data
	keyData := []byte{0x10, 0x01, 0x00, 0x01} // exponent length = 16, but only 3 bytes of exponent

	_, err := parseRSAPublicKey(keyData)
	if err == nil {
		t.Error("Expected error for exponent extending beyond key data")
	}
}

func TestParseRSAPublicKeyNoModulus(t *testing.T) {
	// keyData where offset reaches end after exponent (no modulus)
	keyData := []byte{0x01, 0x03} // exponent length 1, exponent=3, no room for modulus

	_, err := parseRSAPublicKey(keyData)
	if err == nil {
		t.Error("Expected error for missing modulus")
	}
}

func TestParseDNSKEYPublicKeyECDSAP384(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA P-384 key: %v", err)
	}

	// Pack the public key for P-384
	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP384SHA384, Key: &privKey.PublicKey}
	keyData, err := packECDSAPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to pack ECDSA P-384 public key: %v", err)
	}

	// Parse it back
	parsedKey, err := ParseDNSKEYPublicKey(protocol.AlgorithmECDSAP384SHA384, keyData)
	if err != nil {
		t.Fatalf("Failed to parse ECDSA P-384 public key: %v", err)
	}

	if parsedKey.Algorithm != protocol.AlgorithmECDSAP384SHA384 {
		t.Errorf("Algorithm mismatch: got %d, want %d", parsedKey.Algorithm, protocol.AlgorithmECDSAP384SHA384)
	}

	ecdsaKey, ok := parsedKey.Key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("Expected ECDSA public key")
	}
	if ecdsaKey.Curve != elliptic.P384() {
		t.Error("Expected P-384 curve")
	}
}

func TestVerifyECDSAKeyNotECDSA(t *testing.T) {
	// Create an RSA key but try to verify ECDSA signature
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	sig := &protocol.RDataRRSIG{
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		Signature: make([]byte, 64), // valid P-256 signature length
	}

	err = VerifySignature(sig, []byte("data"), pub)
	if err == nil {
		t.Error("Expected error when key is not ECDSA")
	}
}

func TestVerifyECDSASignatureLengthMismatch(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	sig := &protocol.RDataRRSIG{
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		Signature: make([]byte, 30), // wrong length, should be 64 for P-256
	}

	err = VerifySignature(sig, []byte("data"), pub)
	if err == nil {
		t.Error("Expected error for signature length mismatch")
	}
}

func TestVerifyECDSAWrongSignature(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	sig := &protocol.RDataRRSIG{
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		Signature: make([]byte, 64), // valid length but wrong content
	}

	err = VerifySignature(sig, []byte("data"), pub)
	if err == nil {
		t.Error("Expected error for wrong ECDSA signature")
	}
}

func TestVerifyECDSAP384(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA P-384 key: %v", err)
	}

	data := []byte("test data to sign")
	priv := &PrivateKey{Algorithm: protocol.AlgorithmECDSAP384SHA384, Key: privKey}

	// Sign with P-384
	signature, err := signECDSA(data, priv)
	if err != nil {
		t.Fatalf("Failed to sign with ECDSA P-384: %v", err)
	}

	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP384SHA384, Key: &privKey.PublicKey}
	sig := &protocol.RDataRRSIG{
		Algorithm: protocol.AlgorithmECDSAP384SHA384,
		Signature: signature,
	}

	err = VerifySignature(sig, data, pub)
	if err != nil {
		t.Errorf("ECDSA P-384 signature verification failed: %v", err)
	}
}

func TestSignDataRSASHA256(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	key := &PrivateKey{
		Algorithm: protocol.AlgorithmRSASHA256,
		Key:       privKey,
	}

	data := []byte("test data")
	signature, err := SignData(protocol.AlgorithmRSASHA256, key, data)
	if err != nil {
		t.Fatalf("SignData RSASHA256 failed: %v", err)
	}
	if len(signature) == 0 {
		t.Error("Signature should not be empty")
	}
}

func TestSignDataEd25519(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	key := &PrivateKey{
		Algorithm: protocol.AlgorithmED25519,
		Key:       privKey,
	}

	data := []byte("test data")
	signature, err := SignData(protocol.AlgorithmED25519, key, data)
	if err != nil {
		t.Fatalf("SignData Ed25519 failed: %v", err)
	}
	if len(signature) == 0 {
		t.Error("Signature should not be empty")
	}

	// Verify the signature works
	pub := &PublicKey{Algorithm: protocol.AlgorithmED25519, Key: pubKey}
	sig := &protocol.RDataRRSIG{
		Algorithm: protocol.AlgorithmED25519,
		Signature: signature,
	}
	err = VerifySignature(sig, data, pub)
	if err != nil {
		t.Errorf("Ed25519 verification after SignData failed: %v", err)
	}
}

func TestSignECDSAUnsupportedAlgorithm(t *testing.T) {
	// Create a key with an unsupported ECDSA algorithm marker
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	key := &PrivateKey{
		Algorithm: 250, // unsupported algorithm that goes through ECDSA path
		Key:       privKey,
	}

	_, err = signECDSA([]byte("data"), key)
	if err == nil {
		t.Error("Expected error for unsupported ECDSA algorithm")
	}
}

func TestSignEd25519WrongKeyType(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	key := &PrivateKey{
		Algorithm: protocol.AlgorithmED25519,
		Key:       privKey, // wrong type
	}

	_, err = signEd25519([]byte("data"), key)
	if err == nil {
		t.Error("Expected error when key is not Ed25519")
	}
}

func TestVerifyRSASHA256KeyNotRSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	pub := &PublicKey{Algorithm: protocol.AlgorithmRSASHA256, Key: &privKey.PublicKey}
	sig := &protocol.RDataRRSIG{
		Algorithm: protocol.AlgorithmRSASHA256,
		Signature: make([]byte, 128),
	}

	err = VerifySignature(sig, []byte("data"), pub)
	if err == nil {
		t.Error("Expected error when key is not RSA")
	}
}

func TestVerifyRSASHA512KeyNotRSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	pub := &PublicKey{Algorithm: protocol.AlgorithmRSASHA512, Key: &privKey.PublicKey}
	sig := &protocol.RDataRRSIG{
		Algorithm: protocol.AlgorithmRSASHA512,
		Signature: make([]byte, 128),
	}

	err = VerifySignature(sig, []byte("data"), pub)
	if err == nil {
		t.Error("Expected error when key is not RSA for SHA-512")
	}
}

func TestVerifyEd25519KeyNotEd25519(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	pub := &PublicKey{Algorithm: protocol.AlgorithmED25519, Key: &privKey.PublicKey}
	sig := &protocol.RDataRRSIG{
		Algorithm: protocol.AlgorithmED25519,
		Signature: make([]byte, 64),
	}

	err = VerifySignature(sig, []byte("data"), pub)
	if err == nil {
		t.Error("Expected error when key is not Ed25519")
	}
}

func TestGenerateKeyPairECDSAP384(t *testing.T) {
	priv, pub, err := GenerateKeyPair(protocol.AlgorithmECDSAP384SHA384, false)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA P-384 key pair: %v", err)
	}

	if priv == nil || pub == nil {
		t.Fatal("Keys should not be nil")
	}
	if priv.Algorithm != protocol.AlgorithmECDSAP384SHA384 {
		t.Errorf("Algorithm mismatch: got %d", priv.Algorithm)
	}
}

func TestGenerateRSAKeyPairZSK(t *testing.T) {
	priv, pub, err := generateRSAKeyPair(protocol.AlgorithmRSASHA256, false)
	if err != nil {
		t.Fatalf("Failed to generate RSA ZSK: %v", err)
	}
	if priv == nil || pub == nil {
		t.Fatal("Keys should not be nil")
	}
}

func TestPackRSAPublicKeyLargeExponent(t *testing.T) {
	// Create an RSA key with an exponent that encodes to >=256 bytes
	// This is very unusual but tests the 3-byte exponent length code path in packRSAPublicKey
	// We can't easily create a real RSA key with such a large exponent,
	// so we test the pack function with a synthetic key
	rsaKey := &rsa.PublicKey{
		N: big.NewInt(1),
		E: 65537, // Normal exponent, this tests the <256 path which already exists
	}
	key := &PublicKey{Algorithm: protocol.AlgorithmRSASHA256, Key: rsaKey}

	data, err := packRSAPublicKey(key)
	if err != nil {
		t.Fatalf("packRSAPublicKey failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("Packed key should not be empty")
	}
}

func TestPackRSAPublicKeyNotRSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	key := &PublicKey{Algorithm: protocol.AlgorithmRSASHA256, Key: &privKey.PublicKey}

	_, err = packRSAPublicKey(key)
	if err == nil {
		t.Error("Expected error when key is not RSA")
	}
}

func TestPackECDSAPublicKeyNotECDSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	key := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}

	_, err = packECDSAPublicKey(key)
	if err == nil {
		t.Error("Expected error when key is not ECDSA")
	}
}

func TestPackEd25519PublicKeyNotEd25519(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	key := &PublicKey{Algorithm: protocol.AlgorithmED25519, Key: &privKey.PublicKey}

	_, err = packEd25519PublicKey(key)
	if err == nil {
		t.Error("Expected error when key is not Ed25519")
	}
}

func TestSignRSASHA256NotRSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	key := &PrivateKey{Algorithm: protocol.AlgorithmRSASHA256, Key: privKey}

	_, err = signRSASHA256([]byte("data"), key)
	if err == nil {
		t.Error("Expected error when key is not RSA")
	}
}

func TestSignRSASHA512NotRSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	key := &PrivateKey{Algorithm: protocol.AlgorithmRSASHA512, Key: privKey}

	_, err = signRSASHA512([]byte("data"), key)
	if err == nil {
		t.Error("Expected error when key is not RSA for SHA-512")
	}
}

func TestSignECDSANotECDSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	key := &PrivateKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: privKey}

	_, err = signECDSA([]byte("data"), key)
	if err == nil {
		t.Error("Expected error when key is not ECDSA")
	}
}

func TestGenerateSaltZeroLength(t *testing.T) {
	salt, err := GenerateSalt(0)
	if err != nil {
		t.Fatalf("GenerateSalt(0) failed: %v", err)
	}
	if len(salt) != 0 {
		t.Errorf("Expected empty salt, got %d bytes", len(salt))
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
