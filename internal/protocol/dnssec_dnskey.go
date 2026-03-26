package protocol

import (
	"fmt"
)

// DNSKEY flag constants (RFC 4034).
const (
	// DNSKEYFlagZone is set if this is a zone key.
	// The DNSKEY record MUST have this flag set to be used for DNSSEC.
	DNSKEYFlagZone = 0x0100

	// DNSKEYFlagSEP is the Secure Entry Point flag.
	// Used to distinguish KSK (Key Signing Key) from ZSK (Zone Signing Key).
	DNSKEYFlagSEP = 0x0001

	// DNSKEYFlagRevoke indicates a key that has been revoked (RFC 5011).
	DNSKEYFlagRevoke = 0x0080
)

// DNSSEC Algorithm Numbers (RFC 8624).
const (
	// AlgorithmRSAMD5 is RSA/MD5 (NOT RECOMMENDED).
	AlgorithmRSAMD5 = 1

	// AlgorithmDH is Diffie-Hellman (NOT RECOMMENDED).
	AlgorithmDH = 2

	// AlgorithmDSASHA1 is DSA/SHA-1 (NOT RECOMMENDED).
	AlgorithmDSASHA1 = 3

	// AlgorithmRSASHA1 is RSA/SHA-1 (NOT RECOMMENDED, deprecated).
	AlgorithmRSASHA1 = 5

	// AlgorithmDSASHA1NSEC3 is DSA/SHA-1 for NSEC3 (NOT RECOMMENDED).
	AlgorithmDSASHA1NSEC3 = 6

	// AlgorithmRSASHA1NSEC3 is RSA/SHA-1 for NSEC3 (NOT RECOMMENDED).
	AlgorithmRSASHA1NSEC3 = 7

	// AlgorithmRSASHA256 is RSA/SHA-256 (MUST implement per RFC 8624).
	AlgorithmRSASHA256 = 8

	// AlgorithmRSASHA512 is RSA/SHA-512 (SHOULD implement per RFC 8624).
	AlgorithmRSASHA512 = 10

	// AlgorithmECCGOST is GOST R 34.10-2001 (obsoleted).
	AlgorithmECCGOST = 12

	// AlgorithmECDSAP256SHA256 is ECDSA Curve P-256 with SHA-256 (MUST implement per RFC 8624).
	AlgorithmECDSAP256SHA256 = 13

	// AlgorithmECDSAP384SHA384 is ECDSA Curve P-384 with SHA-384 (MAY implement per RFC 8624).
	AlgorithmECDSAP384SHA384 = 14

	// AlgorithmED25519 is Ed25519 (RECOMMENDED per RFC 8624).
	AlgorithmED25519 = 15

	// AlgorithmED448 is Ed448 (NOT RECOMMENDED per RFC 8624, too slow).
	AlgorithmED448 = 16
)

// AlgorithmToString returns the name of a DNSSEC algorithm.
func AlgorithmToString(alg uint8) string {
	switch alg {
	case AlgorithmRSAMD5:
		return "RSAMD5"
	case AlgorithmDH:
		return "DH"
	case AlgorithmDSASHA1:
		return "DSA"
	case AlgorithmRSASHA1:
		return "RSASHA1"
	case AlgorithmDSASHA1NSEC3:
		return "DSA-NSEC3-SHA1"
	case AlgorithmRSASHA1NSEC3:
		return "RSASHA1-NSEC3-SHA1"
	case AlgorithmRSASHA256:
		return "RSASHA256"
	case AlgorithmRSASHA512:
		return "RSASHA512"
	case AlgorithmECCGOST:
		return "ECC-GOST"
	case AlgorithmECDSAP256SHA256:
		return "ECDSAP256SHA256"
	case AlgorithmECDSAP384SHA384:
		return "ECDSAP384SHA384"
	case AlgorithmED25519:
		return "ED25519"
	case AlgorithmED448:
		return "ED448"
	default:
		return fmt.Sprintf("ALG%d", alg)
	}
}

// IsAlgorithmSupported returns true if the algorithm is supported by this implementation.
func IsAlgorithmSupported(alg uint8) bool {
	switch alg {
	case AlgorithmRSASHA256, AlgorithmRSASHA512,
		AlgorithmECDSAP256SHA256, AlgorithmECDSAP384SHA384,
		AlgorithmED25519:
		return true
	default:
		return false
	}
}

// IsAlgorithmRecommended returns true if the algorithm is recommended per RFC 8624.
func IsAlgorithmRecommended(alg uint8) bool {
	switch alg {
	case AlgorithmRSASHA256, AlgorithmRSASHA512,
		AlgorithmECDSAP256SHA256, AlgorithmED25519:
		return true
	default:
		return false
	}
}

// RDataDNSKEY represents a DNSKEY record (RFC 4034).
// DNSKEY records contain the public keys used for DNSSEC signature verification.
type RDataDNSKEY struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey []byte
}

// Type returns TypeDNSKEY.
func (r *RDataDNSKEY) Type() uint16 { return TypeDNSKEY }

// Pack serializes the DNSKEY record to wire format.
func (r *RDataDNSKEY) Pack(buf []byte, offset int) (int, error) {
	startOffset := offset

	// Flags (2 bytes)
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.Flags)
	offset += 2

	// Protocol (1 byte)
	if offset+1 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = r.Protocol
	offset++

	// Algorithm (1 byte)
	if offset+1 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = r.Algorithm
	offset++

	// Public Key
	keyLen := len(r.PublicKey)
	if offset+keyLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.PublicKey)
	offset += keyLen

	return offset - startOffset, nil
}

// Unpack deserializes the DNSKEY record from wire format.
func (r *RDataDNSKEY) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	startOffset := offset
	endOffset := offset + int(rdlength)

	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// Need at least 4 bytes for fixed fields
	if offset+4 > endOffset {
		return 0, ErrBufferTooSmall
	}

	// Flags
	r.Flags = Uint16(buf[offset:])
	offset += 2

	// Protocol
	r.Protocol = buf[offset]
	offset++

	// Algorithm
	r.Algorithm = buf[offset]
	offset++

	// Public Key (remaining bytes)
	keyLen := endOffset - offset
	r.PublicKey = make([]byte, keyLen)
	copy(r.PublicKey, buf[offset:endOffset])
	offset = endOffset

	return offset - startOffset, nil
}

// String returns the DNSKEY record in presentation format.
func (r *RDataDNSKEY) String() string {
	return fmt.Sprintf("%d %d %d %s", r.Flags, r.Protocol, r.Algorithm, base64Encode(r.PublicKey))
}

// Len returns the wire length of the DNSKEY record.
func (r *RDataDNSKEY) Len() int {
	return 4 + len(r.PublicKey)
}

// Copy creates a deep copy of the DNSKEY record.
func (r *RDataDNSKEY) Copy() RData {
	keyCopy := make([]byte, len(r.PublicKey))
	copy(keyCopy, r.PublicKey)
	return &RDataDNSKEY{
		Flags:     r.Flags,
		Protocol:  r.Protocol,
		Algorithm: r.Algorithm,
		PublicKey: keyCopy,
	}
}

// IsZoneKey returns true if this is a zone key (Zone flag set).
func (r *RDataDNSKEY) IsZoneKey() bool {
	return r.Flags&DNSKEYFlagZone != 0
}

// IsSEP returns true if this is a Secure Entry Point (SEP flag set).
// SEP keys are typically KSKs (Key Signing Keys).
func (r *RDataDNSKEY) IsSEP() bool {
	return r.Flags&DNSKEYFlagSEP != 0
}

// IsKSK returns true if this is a Key Signing Key (Zone + SEP flags set).
func (r *RDataDNSKEY) IsKSK() bool {
	return r.IsZoneKey() && r.IsSEP()
}

// IsZSK returns true if this is a Zone Signing Key (Zone flag set, SEP not set).
func (r *RDataDNSKEY) IsZSK() bool {
	return r.IsZoneKey() && !r.IsSEP()
}

// IsRevoked returns true if the key has been revoked.
func (r *RDataDNSKEY) IsRevoked() bool {
	return r.Flags&DNSKEYFlagRevoke != 0
}

// CalculateKeyTag computes the key tag (key identifier) for this DNSKEY.
// This is used in RRSIG and DS records to identify which key signed the data.
func (r *RDataDNSKEY) CalculateKeyTag() uint16 {
	return CalculateKeyTag(r.Flags, r.Algorithm, r.PublicKey)
}

// CalculateKeyTag computes the key tag from DNSKEY components.
// This implements the algorithm from RFC 4034 Appendix B.
func CalculateKeyTag(flags uint16, algorithm uint8, publicKey []byte) uint16 {
	var keyTag uint32

	// Add flags
	keyTag += uint32(flags)

	// Add algorithm
	keyTag += uint32(algorithm)

	// Add public key bytes
	for i, b := range publicKey {
		if i&1 == 1 {
			keyTag += uint32(b)
		} else {
			keyTag += uint32(b) << 8
		}
	}

	// Add high 16 bits to low 16 bits
	keyTag += keyTag >> 16

	return uint16(keyTag & 0xFFFF)
}

// base64Encode encodes bytes to base64 (helper for String()).
func base64Encode(data []byte) string {
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	if len(data) == 0 {
		return ""
	}

	result := make([]byte, 0, (len(data)+2)/3*4)
	for i := 0; i < len(data); i += 3 {
		b1 := data[i]
		b2 := byte(0)
		b3 := byte(0)
		if i+1 < len(data) {
			b2 = data[i+1]
		}
		if i+2 < len(data) {
			b3 = data[i+2]
		}

		result = append(result, base64Chars[b1>>2])
		result = append(result, base64Chars[((b1&0x03)<<4)|(b2>>4)])
		if i+1 < len(data) {
			result = append(result, base64Chars[((b2&0x0f)<<2)|(b3>>6)])
		} else {
			result = append(result, '=')
		}
		if i+2 < len(data) {
			result = append(result, base64Chars[b3&0x3f])
		} else {
			result = append(result, '=')
		}
	}

	return string(result)
}
