// Package dnssec provides DNSSEC (DNS Security Extensions) functionality.
// This file implements SIG(0) transaction signatures as specified in RFC 2931.
// SIG(0) provides authentication for DNS transactions using public key cryptography.
package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// SIG0Error represents errors in SIG(0) operations.
type SIG0Error struct {
	Msg string
}

func (e *SIG0Error) Error() string {
	return fmt.Sprintf("SIG(0): %s", e.Msg)
}

// SIG0Record represents a SIG(0) record (RFC 2931).
// SIG(0) is used for transaction-level signatures to authenticate DNS messages.
type SIG0Record struct {
	// TypeCovered is the type of record being signed (0 for transaction signatures)
	TypeCovered uint16

	// Algorithm is the cryptographic algorithm used
	Algorithm uint8

	// Labels is the number of labels in the original name (for compression validation)
	Labels uint8

	// Original TTL is not used for SIG(0) but kept for compatibility
	OriginalTTL uint32

	// Expiration is the signature expiration time (Unix timestamp)
	Expiration uint32

	// Inception is the signature inception time (Unix timestamp)
	Inception uint32

	// KeyTag is the key tag of the signing key
	KeyTag uint16

	// SignerName is the name of the signer (usually the zone name)
	SignerName string

	// Signature is the actual cryptographic signature
	Signature []byte
}

// SIG0Algorithm represents SIG(0) algorithm identifiers.
type SIG0Algorithm uint8

const (
	SIG0AlgorithmRSASHA256  SIG0Algorithm = 7  // RSASHA256 (RFC 6605)
	SIG0AlgorithmRSASHA512  SIG0Algorithm = 8  // RSASHA512 (RFC 6605)
	SIG0AlgorithmECDSAP256 SIG0Algorithm = 13 // ECDSAP256SHA256 (RFC 6605)
	SIG0AlgorithmECDSAP384 SIG0Algorithm = 14 // ECDSAP384SHA384 (RFC 6605)
)

// SIG0 constants
const (
	// TypeCoveredTransaction indicates a transaction signature (covers entire message)
	TypeCoveredTransaction = 0

	// SIG0DefaultValidity is the default signature validity period
	SIG0DefaultValidity = 5 * time.Minute

	// SIG0InceptionSkew allows signatures to be valid before their inception time
	SIG0InceptionSkew = 5 * time.Minute
)

// SignSIG0 creates a SIG(0) record for a DNS message.
func SignSIG0(msg []byte, signerName string, privateKey crypto.Signer, algorithm uint8, keyTag uint16) (*SIG0Record, error) {
	now := uint32(time.Now().Unix())

	sig := &SIG0Record{
		TypeCovered: TypeCoveredTransaction,
		Algorithm:   algorithm,
		Labels:      countLabels(signerName),
		OriginalTTL: 0,
		Expiration:  now + uint32(SIG0DefaultValidity.Seconds()),
		Inception:   now - uint32(SIG0InceptionSkew.Seconds()),
		KeyTag:      keyTag,
		SignerName:  signerName,
	}

	// Build canonical wire format for signing
	canonicalMsg := buildSIG0CanonicalMessage(msg, sig)

	// Sign the message
	var err error
	switch alg := SIG0Algorithm(algorithm); alg {
	case SIG0AlgorithmRSASHA256, SIG0AlgorithmRSASHA512:
		var hashFunc crypto.Hash
		if alg == SIG0AlgorithmRSASHA256 {
			hashFunc = crypto.SHA256
		} else {
			hashFunc = crypto.SHA512
		}
		h := hashFunc.New()
		h.Write(canonicalMsg)
		// Type assert to get the underlying RSA private key
		if rsaKey, ok := privateKey.(*rsa.PrivateKey); ok {
			sig.Signature, err = rsa.SignPKCS1v15(nil, rsaKey, hashFunc, h.Sum(nil))
		} else {
			err = &SIG0Error{Msg: "private key is not RSA"}
		}
	case SIG0AlgorithmECDSAP256, SIG0AlgorithmECDSAP384:
		h := sha256.New()
		h.Write(canonicalMsg)
		// Type assert to get the underlying ECDSA private key
		if ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey); ok {
			var sigBytes []byte
			sigBytes, err = ecdsa.SignASN1(nil, ecdsaKey, h.Sum(nil))
			sig.Signature = sigBytes
		} else {
			err = &SIG0Error{Msg: "private key is not ECDSA"}
		}
	default:
		err = &SIG0Error{Msg: fmt.Sprintf("unsupported algorithm: %d", algorithm)}
	}

	if err != nil {
		return nil, &SIG0Error{Msg: fmt.Sprintf("signing failed: %v", err)}
	}

	return sig, nil
}

// VerifySIG0 verifies a SIG(0) record against a DNS message.
func VerifySIG0(msg []byte, sig *SIG0Record, publicKey crypto.PublicKey) error {
	// Check temporal validity
	now := uint32(time.Now().Unix())

	// Allow some skew for inception
	if now < sig.Inception-uint32(SIG0InceptionSkew.Seconds()) {
		return &SIG0Error{Msg: "signature not yet valid"}
	}
	if now > sig.Expiration {
		return &SIG0Error{Msg: "signature expired"}
	}

	// Build canonical message
	canonicalMsg := buildSIG0CanonicalMessage(msg, sig)

	// Verify signature
	switch alg := SIG0Algorithm(sig.Algorithm); alg {
	case SIG0AlgorithmRSASHA256, SIG0AlgorithmRSASHA512:
		var hashFunc crypto.Hash
		if alg == SIG0AlgorithmRSASHA256 {
			hashFunc = crypto.SHA256
		} else {
			hashFunc = crypto.SHA512
		}
		h := hashFunc.New()
		h.Write(canonicalMsg)
		switch key := publicKey.(type) {
		case *rsa.PublicKey:
			err := rsa.VerifyPKCS1v15(key, hashFunc, h.Sum(nil), sig.Signature)
			if err != nil {
				return &SIG0Error{Msg: fmt.Sprintf("signature verification failed: %v", err)}
			}
		default:
			return &SIG0Error{Msg: "incompatible public key for RSA algorithm"}
		}
	case SIG0AlgorithmECDSAP256, SIG0AlgorithmECDSAP384:
		h := sha256.New()
		h.Write(canonicalMsg)
		switch key := publicKey.(type) {
		case *ecdsa.PublicKey:
			if !ecdsa.VerifyASN1(key, h.Sum(nil), sig.Signature) {
				return &SIG0Error{Msg: "signature verification failed"}
			}
		default:
			return &SIG0Error{Msg: "incompatible public key for ECDSA algorithm"}
		}
	default:
		return &SIG0Error{Msg: fmt.Sprintf("unsupported algorithm: %d", sig.Algorithm)}
	}

	return nil
}

// buildSIG0CanonicalMessage builds the canonical wire format for SIG(0) signing.
// Per RFC 2931, this includes the entire DNS message plus the SIG RDATA fields.
func buildSIG0CanonicalMessage(msg []byte, sig *SIG0Record) []byte {
	var result []byte

	// Add the DNS message
	result = append(result, msg...)

	// Add the SIG RDATA fields in canonical order
	// Type Covered (2 bytes)
	result = append(result, byte(sig.TypeCovered>>8), byte(sig.TypeCovered))

	// Algorithm (1 byte)
	result = append(result, sig.Algorithm)

	// Labels (1 byte)
	result = append(result, sig.Labels)

	// Original TTL (4 bytes)
	result = append(result, byte(sig.OriginalTTL>>24), byte(sig.OriginalTTL>>16),
		byte(sig.OriginalTTL>>8), byte(sig.OriginalTTL))

	// Expiration (4 bytes)
	result = append(result, byte(sig.Expiration>>24), byte(sig.Expiration>>16),
		byte(sig.Expiration>>8), byte(sig.Expiration))

	// Inception (4 bytes)
	result = append(result, byte(sig.Inception>>24), byte(sig.Inception>>16),
		byte(sig.Inception>>8), byte(sig.Inception))

	// Key Tag (2 bytes)
	result = append(result, byte(sig.KeyTag>>8), byte(sig.KeyTag))

	// Signer Name (compressed wire format)
	signerName := canonicalNameWire(sig.SignerName)
	result = append(result, signerName...)

	return result
}

// countLabels counts the number of labels in a domain name.
func countLabels(name string) uint8 {
	if name == "" {
		return 0
	}
	// Remove trailing dot if present
	if strings.HasSuffix(name, ".") {
		name = name[:len(name)-1]
	}
	count := 0
	for _, c := range name {
		if c == '.' {
			count++
		}
		count++
	}
	return uint8(count)
}

// canonicalNameWire converts a name to canonical wire format for SIG(0).
func canonicalNameWire(name string) []byte {
	// Remove trailing dot
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	// Lowercase
	name = strings.ToLower(name)

	// Split into labels
	labels := strings.Split(name, ".")

	var result []byte
	// Process from TLD to subdomain (reverse)
	for i := len(labels) - 1; i >= 0; i-- {
		result = append(result, byte(len(labels[i])))
		result = append(result, labels[i]...)
	}
	result = append(result, 0) // Root label

	return result
}

// SIG0ToResourceRecord converts a SIG0Record to a protocol ResourceRecord.
func SIG0ToResourceRecord(sig *SIG0Record) *protocol.ResourceRecord {
	// Pack SIG(0) data
	// 2 + 1 + 1 + 4 + 4 + 4 + 2 + signerName + signature
	signerNameWire := canonicalNameWire(sig.SignerName)
	rdataLen := 18 + len(signerNameWire) + len(sig.Signature)
	rdata := make([]byte, rdataLen)
	offset := 0

	// Type Covered
	binary.BigEndian.PutUint16(rdata[offset:], sig.TypeCovered)
	offset += 2

	// Algorithm
	rdata[offset] = sig.Algorithm
	offset++

	// Labels
	rdata[offset] = sig.Labels
	offset++

	// Original TTL
	binary.BigEndian.PutUint32(rdata[offset:], sig.OriginalTTL)
	offset += 4

	// Expiration
	binary.BigEndian.PutUint32(rdata[offset:], sig.Expiration)
	offset += 4

	// Inception
	binary.BigEndian.PutUint32(rdata[offset:], sig.Inception)
	offset += 4

	// Key Tag
	binary.BigEndian.PutUint16(rdata[offset:], sig.KeyTag)
	offset += 2

	// Signer Name
	copy(rdata[offset:], signerNameWire)
	offset += len(signerNameWire)

	// Signature
	copy(rdata[offset:], sig.Signature)

	// Create protocol.Name from string
	signerNameParsed, _ := protocol.ParseName(sig.SignerName)

	return &protocol.ResourceRecord{
		Name:  signerNameParsed,
		Type:  protocol.TypeSIG,
		Class: protocol.ClassANY, // SIG(0) uses ANY class
		TTL:   0,
		Data:  &protocol.RDataRaw{TypeVal: protocol.TypeSIG, Data: rdata},
	}
}

// ComputeKeyTag computes the key tag for a DNSKEY record.
func ComputeKeyTag(algorithm uint8, key []byte) uint16 {
	// RFC 4034 Appendix B
	var sum uint32
	for i := 0; i < len(key); i++ {
		sum += uint32(key[i]) << uint((8-i%2)*8)
	}
	return uint16(sum>>16 + sum&0xFFFF)
}

// String returns a human-readable representation of the SIG(0) record.
func (s *SIG0Record) String() string {
	return fmt.Sprintf("SIG0{type=%d algo=%d signer=%s keytag=%d exp=%d}",
		s.TypeCovered, s.Algorithm, s.SignerName, s.KeyTag, s.Expiration)
}

// ECDSACurveForAlgorithm returns the elliptic curve for a SIG(0) algorithm.
func ECDSACurveForAlgorithm(alg SIG0Algorithm) elliptic.Curve {
	switch alg {
	case SIG0AlgorithmECDSAP256:
		return elliptic.P256()
	case SIG0AlgorithmECDSAP384:
		return elliptic.P384()
	default:
		return nil
	}
}
