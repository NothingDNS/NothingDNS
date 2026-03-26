package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 - Required for NSEC3 hash, not for security
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// PublicKey wraps a crypto.PublicKey with DNSSEC algorithm information.
type PublicKey struct {
	Algorithm uint8
	Key       crypto.PublicKey
}

// PrivateKey wraps a crypto.PrivateKey with DNSSEC algorithm information.
type PrivateKey struct {
	Algorithm uint8
	Key       crypto.PrivateKey
}

// ParseDNSKEYPublicKey parses a wire-format DNSKEY public key into a usable public key.
// This function supports RSA, ECDSA, and Ed25519 algorithms.
func ParseDNSKEYPublicKey(algorithm uint8, keyData []byte) (*PublicKey, error) {
	switch algorithm {
	case protocol.AlgorithmRSASHA256, protocol.AlgorithmRSASHA512:
		return parseRSAPublicKey(keyData)
	case protocol.AlgorithmECDSAP256SHA256, protocol.AlgorithmECDSAP384SHA384:
		return parseECDSAPublicKey(algorithm, keyData)
	case protocol.AlgorithmED25519:
		return parseEd25519PublicKey(keyData)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %d", algorithm)
	}
}

// parseRSAPublicKey parses an RSA public key from DNSKEY wire format.
// Wire format: exponent length (1 or 3 bytes) + exponent + modulus
func parseRSAPublicKey(keyData []byte) (*PublicKey, error) {
	if len(keyData) < 3 {
		return nil, fmt.Errorf("RSA key data too short: %d bytes", len(keyData))
	}

	offset := 0

	// Read exponent length
	var expLen int
	if keyData[0] != 0 {
		// Single byte exponent length
		expLen = int(keyData[0])
		offset = 1
	} else {
		// 3-byte exponent length
		if len(keyData) < 4 {
			return nil, fmt.Errorf("RSA key data too short for 3-byte exponent length")
		}
		expLen = int(binary.BigEndian.Uint16(keyData[1:3]))
		offset = 3
	}

	// Read exponent
	if offset+expLen > len(keyData) {
		return nil, fmt.Errorf("RSA key data too short for exponent")
	}
	exponent := new(big.Int).SetBytes(keyData[offset : offset+expLen])
	offset += expLen

	// Read modulus
	if offset >= len(keyData) {
		return nil, fmt.Errorf("RSA key data missing modulus")
	}
	modulus := new(big.Int).SetBytes(keyData[offset:])

	// Determine algorithm from key size or use a default
	// This is a simplified approach - real implementation should track algorithm
	algorithm := protocol.AlgorithmRSASHA256

	return &PublicKey{
		Algorithm: algorithm,
		Key: &rsa.PublicKey{
			N: modulus,
			E: int(exponent.Int64()),
		},
	}, nil
}

// parseECDSAPublicKey parses an ECDSA public key from DNSKEY wire format.
// Wire format: X coordinate (32 bytes for P-256, 48 bytes for P-384) + Y coordinate
func parseECDSAPublicKey(algorithm uint8, keyData []byte) (*PublicKey, error) {
	var curve elliptic.Curve
	var coordLen int

	switch algorithm {
	case protocol.AlgorithmECDSAP256SHA256:
		curve = elliptic.P256()
		coordLen = 32
	case protocol.AlgorithmECDSAP384SHA384:
		curve = elliptic.P384()
		coordLen = 48
	default:
		return nil, fmt.Errorf("unsupported ECDSA algorithm: %d", algorithm)
	}

	if len(keyData) != coordLen*2 {
		return nil, fmt.Errorf("ECDSA key data length mismatch: expected %d, got %d", coordLen*2, len(keyData))
	}

	x := new(big.Int).SetBytes(keyData[:coordLen])
	y := new(big.Int).SetBytes(keyData[coordLen:])

	return &PublicKey{
		Algorithm: algorithm,
		Key: &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
	}, nil
}

// parseEd25519PublicKey parses an Ed25519 public key from DNSKEY wire format.
// Wire format: 32-byte public key
func parseEd25519PublicKey(keyData []byte) (*PublicKey, error) {
	if len(keyData) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("Ed25519 key must be %d bytes, got %d", ed25519.PublicKeySize, len(keyData))
	}

	return &PublicKey{
		Algorithm: protocol.AlgorithmED25519,
		Key:       ed25519.PublicKey(keyData),
	}, nil
}

// VerifySignature verifies an RRSIG over signed data.
// The signedData should be the canonical wire format of the RRSet.
func VerifySignature(sig *protocol.RDataRRSIG, signedData []byte, key *PublicKey) error {
	// Check algorithm matches
	if sig.Algorithm != key.Algorithm {
		return fmt.Errorf("algorithm mismatch: sig=%d, key=%d", sig.Algorithm, key.Algorithm)
	}

	switch sig.Algorithm {
	case protocol.AlgorithmRSASHA256:
		return verifyRSASHA256(sig.Signature, signedData, key)
	case protocol.AlgorithmRSASHA512:
		return verifyRSASHA512(sig.Signature, signedData, key)
	case protocol.AlgorithmECDSAP256SHA256, protocol.AlgorithmECDSAP384SHA384:
		return verifyECDSA(sig.Signature, signedData, key)
	case protocol.AlgorithmED25519:
		return verifyEd25519(sig.Signature, signedData, key)
	default:
		return fmt.Errorf("unsupported algorithm: %d", sig.Algorithm)
	}
}

// verifyRSASHA256 verifies an RSA/SHA-256 signature.
func verifyRSASHA256(signature, signedData []byte, key *PublicKey) error {
	rsaKey, ok := key.Key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("key is not RSA")
	}

	hash := sha256.Sum256(signedData)
	err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return fmt.Errorf("RSA verification failed: %w", err)
	}
	return nil
}

// verifyRSASHA512 verifies an RSA/SHA-512 signature.
func verifyRSASHA512(signature, signedData []byte, key *PublicKey) error {
	rsaKey, ok := key.Key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("key is not RSA")
	}

	hash := sha512.Sum512(signedData)
	err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA512, hash[:], signature)
	if err != nil {
		return fmt.Errorf("RSA verification failed: %w", err)
	}
	return nil
}

// verifyECDSA verifies an ECDSA signature.
// DNSSEC uses the raw R||S format without ASN.1 encoding.
func verifyECDSA(signature, signedData []byte, key *PublicKey) error {
	ecdsaKey, ok := key.Key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("key is not ECDSA")
	}

	var hash []byte
	var coordLen int

	switch key.Algorithm {
	case protocol.AlgorithmECDSAP256SHA256:
		h := sha256.Sum256(signedData)
		hash = h[:]
		coordLen = 32
	case protocol.AlgorithmECDSAP384SHA384:
		h := sha512.Sum384(signedData)
		hash = h[:]
		coordLen = 48
	default:
		return fmt.Errorf("unsupported ECDSA algorithm: %d", key.Algorithm)
	}

	if len(signature) != coordLen*2 {
		return fmt.Errorf("ECDSA signature length mismatch: expected %d, got %d", coordLen*2, len(signature))
	}

	r := new(big.Int).SetBytes(signature[:coordLen])
	s := new(big.Int).SetBytes(signature[coordLen:])

	if !ecdsa.Verify(ecdsaKey, hash, r, s) {
		return fmt.Errorf("ECDSA verification failed")
	}
	return nil
}

// verifyEd25519 verifies an Ed25519 signature.
func verifyEd25519(signature, signedData []byte, key *PublicKey) error {
	edKey, ok := key.Key.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("key is not Ed25519")
	}

	if !ed25519.Verify(edKey, signedData, signature) {
		return fmt.Errorf("Ed25519 verification failed")
	}
	return nil
}

// SignData creates a signature for the given data using the specified algorithm.
func SignData(algorithm uint8, key *PrivateKey, data []byte) ([]byte, error) {
	if algorithm != key.Algorithm {
		return nil, fmt.Errorf("algorithm mismatch: data=%d, key=%d", algorithm, key.Algorithm)
	}

	switch algorithm {
	case protocol.AlgorithmRSASHA256:
		return signRSASHA256(data, key)
	case protocol.AlgorithmRSASHA512:
		return signRSASHA512(data, key)
	case protocol.AlgorithmECDSAP256SHA256, protocol.AlgorithmECDSAP384SHA384:
		return signECDSA(data, key)
	case protocol.AlgorithmED25519:
		return signEd25519(data, key)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %d", algorithm)
	}
}

// signRSASHA256 creates an RSA/SHA-256 signature.
func signRSASHA256(data []byte, key *PrivateKey) ([]byte, error) {
	rsaKey, ok := key.Key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}

	hash := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
}

// signRSASHA512 creates an RSA/SHA-512 signature.
func signRSASHA512(data []byte, key *PrivateKey) ([]byte, error) {
	rsaKey, ok := key.Key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}

	hash := sha512.Sum512(data)
	return rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA512, hash[:])
}

// signECDSA creates an ECDSA signature in DNSSEC format (R||S).
func signECDSA(data []byte, key *PrivateKey) ([]byte, error) {
	ecdsaKey, ok := key.Key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not ECDSA")
	}

	var hash []byte
	var coordLen int

	switch key.Algorithm {
	case protocol.AlgorithmECDSAP256SHA256:
		h := sha256.Sum256(data)
		hash = h[:]
		coordLen = 32
	case protocol.AlgorithmECDSAP384SHA384:
		h := sha512.Sum384(data)
		hash = h[:]
		coordLen = 48
	default:
		return nil, fmt.Errorf("unsupported ECDSA algorithm: %d", key.Algorithm)
	}

	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hash)
	if err != nil {
		return nil, fmt.Errorf("ECDSA signing failed: %w", err)
	}

	// Convert to fixed-length byte arrays
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Pad to coordLen if necessary
	if len(rBytes) < coordLen {
		rBytes = append(make([]byte, coordLen-len(rBytes)), rBytes...)
	}
	if len(sBytes) < coordLen {
		sBytes = append(make([]byte, coordLen-len(sBytes)), sBytes...)
	}

	return append(rBytes, sBytes...), nil
}

// signEd25519 creates an Ed25519 signature.
func signEd25519(data []byte, key *PrivateKey) ([]byte, error) {
	edKey, ok := key.Key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519")
	}

	return ed25519.Sign(edKey, data), nil
}

// GenerateKeyPair generates a new DNSSEC key pair for the specified algorithm.
func GenerateKeyPair(algorithm uint8, isKSK bool) (*PrivateKey, *PublicKey, error) {
	switch algorithm {
	case protocol.AlgorithmRSASHA256, protocol.AlgorithmRSASHA512:
		return generateRSAKeyPair(algorithm, isKSK)
	case protocol.AlgorithmECDSAP256SHA256, protocol.AlgorithmECDSAP384SHA384:
		return generateECDSAKeyPair(algorithm)
	case protocol.AlgorithmED25519:
		return generateEd25519KeyPair()
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %d", algorithm)
	}
}

// generateRSAKeyPair generates an RSA key pair.
func generateRSAKeyPair(algorithm uint8, isKSK bool) (*PrivateKey, *PublicKey, error) {
	// KSKs should use larger keys than ZSKs
	bits := 2048
	if isKSK {
		bits = 4096
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("RSA key generation failed: %w", err)
	}

	priv := &PrivateKey{Algorithm: algorithm, Key: privateKey}
	pub := &PublicKey{Algorithm: algorithm, Key: &privateKey.PublicKey}

	return priv, pub, nil
}

// generateECDSAKeyPair generates an ECDSA key pair.
func generateECDSAKeyPair(algorithm uint8) (*PrivateKey, *PublicKey, error) {
	var curve elliptic.Curve

	switch algorithm {
	case protocol.AlgorithmECDSAP256SHA256:
		curve = elliptic.P256()
	case protocol.AlgorithmECDSAP384SHA384:
		curve = elliptic.P384()
	default:
		return nil, nil, fmt.Errorf("unsupported ECDSA algorithm: %d", algorithm)
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDSA key generation failed: %w", err)
	}

	priv := &PrivateKey{Algorithm: algorithm, Key: privateKey}
	pub := &PublicKey{Algorithm: algorithm, Key: &privateKey.PublicKey}

	return priv, pub, nil
}

// generateEd25519KeyPair generates an Ed25519 key pair.
func generateEd25519KeyPair() (*PrivateKey, *PublicKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("Ed25519 key generation failed: %w", err)
	}

	priv := &PrivateKey{Algorithm: protocol.AlgorithmED25519, Key: privateKey}
	pub := &PublicKey{Algorithm: protocol.AlgorithmED25519, Key: publicKey}

	return priv, pub, nil
}

// PackDNSKEYPublicKey packs a public key into DNSKEY wire format.
func PackDNSKEYPublicKey(key *PublicKey) ([]byte, error) {
	switch key.Algorithm {
	case protocol.AlgorithmRSASHA256, protocol.AlgorithmRSASHA512:
		return packRSAPublicKey(key)
	case protocol.AlgorithmECDSAP256SHA256, protocol.AlgorithmECDSAP384SHA384:
		return packECDSAPublicKey(key)
	case protocol.AlgorithmED25519:
		return packEd25519PublicKey(key)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %d", key.Algorithm)
	}
}

// packRSAPublicKey packs an RSA public key into DNSKEY wire format.
func packRSAPublicKey(key *PublicKey) ([]byte, error) {
	rsaKey, ok := key.Key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}

	exponent := big.NewInt(int64(rsaKey.E)).Bytes()
	modulus := rsaKey.N.Bytes()

	var result []byte

	// Exponent length
	if len(exponent) < 256 {
		result = append(result, byte(len(exponent)))
	} else {
		result = append(result, 0)
		result = append(result, byte(len(exponent)>>8), byte(len(exponent)))
	}

	// Exponent
	result = append(result, exponent...)

	// Modulus
	result = append(result, modulus...)

	return result, nil
}

// packECDSAPublicKey packs an ECDSA public key into DNSKEY wire format.
func packECDSAPublicKey(key *PublicKey) ([]byte, error) {
	ecdsaKey, ok := key.Key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not ECDSA")
	}

	coordLen := (ecdsaKey.Curve.Params().BitSize + 7) / 8

	xBytes := ecdsaKey.X.Bytes()
	yBytes := ecdsaKey.Y.Bytes()

	// Pad to fixed length
	if len(xBytes) < coordLen {
		xBytes = append(make([]byte, coordLen-len(xBytes)), xBytes...)
	}
	if len(yBytes) < coordLen {
		yBytes = append(make([]byte, coordLen-len(yBytes)), yBytes...)
	}

	return append(xBytes, yBytes...), nil
}

// packEd25519PublicKey packs an Ed25519 public key into DNSKEY wire format.
func packEd25519PublicKey(key *PublicKey) ([]byte, error) {
	edKey, ok := key.Key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519")
	}

	return []byte(edKey), nil
}

// NSEC3Hash computes the NSEC3 hash of a domain name.
// algorithm: only SHA-1 (1) is defined
// iterations: number of additional hash iterations
// salt: optional salt (can be empty)
func NSEC3Hash(name string, algorithm uint8, iterations uint16, salt []byte) ([]byte, error) {
	if algorithm != 1 {
		return nil, fmt.Errorf("unsupported NSEC3 hash algorithm: %d", algorithm)
	}

	// Convert name to wire format (lowercase, no trailing dot)
	wireName, err := toWireFormat(name)
	if err != nil {
		return nil, fmt.Errorf("converting name to wire format: %w", err)
	}

	// Initial hash: SHA-1(wireName + salt)
	h := sha1.New() // #nosec G505 - NSEC3 requires SHA-1 per RFC 5155
	h.Write(wireName)
	h.Write(salt)
	hash := h.Sum(nil)

	// Additional iterations
	for i := uint16(0); i < iterations; i++ {
		h = sha1.New() // #nosec G505
		h.Write(hash)
		h.Write(salt)
		hash = h.Sum(nil)
	}

	return hash, nil
}

// toWireFormat converts a domain name to wire format (lowercase labels).
func toWireFormat(name string) ([]byte, error) {
	// This is a simplified implementation
	// Real implementation would use proper label packing
	return []byte(name), nil
}

// EncodeToString encodes bytes to base64.
func EncodeToString(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeString decodes a base64 string.
func DecodeString(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// GenerateSalt generates a random salt for NSEC3.
func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// IsAlgorithmSecure returns true if the algorithm is considered secure.
func IsAlgorithmSecure(algorithm uint8) bool {
	switch algorithm {
	case protocol.AlgorithmRSASHA256,
		protocol.AlgorithmRSASHA512,
		protocol.AlgorithmECDSAP256SHA256,
		protocol.AlgorithmECDSAP384SHA384,
		protocol.AlgorithmED25519:
		return true
	default:
		return false
	}
}

// RecommendedAlgorithm returns the recommended algorithm for new keys.
func RecommendedAlgorithm() uint8 {
	// ECDSA P-256 is recommended for most use cases (good balance of security and performance)
	// Ed25519 is also excellent but not yet as widely supported
	return protocol.AlgorithmECDSAP256SHA256
}
