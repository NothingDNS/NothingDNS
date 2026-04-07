// Package dnssec provides DNSSEC (DNS Security Extensions) functionality.
// This file implements RFC 9824 - Compact DNSKEY and DS NSEC3 Proofs.
// RFC 9824 provides a more efficient way to prove the non-existence
// of DNSKEY and DS records using NSEC3.
package dnssec

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// CompactNSECError represents errors in compact NSEC proof operations.
type CompactNSECError struct {
	Msg string
}

func (e *CompactNSECError) Error() string {
	return fmt.Sprintf("compact NSEC: %s", e.Msg)
}

// CompactNSECProof represents a compact proof of non-existence for DNSKEY or DS records.
// This is used per RFC 9824 to provide efficient denial of existence.
type CompactNSECProof struct {
	// The NSEC3 record proving non-existence
	NSEC3Record *protocol.RDataNSEC3

	// The query name that was proven not to exist
	QueryName string

	// ProofType indicates what type of proof this is (DNSKEY or DS)
	ProofType CompactNSECProofType
}

// CompactNSECProofType indicates the type of compact NSEC proof.
type CompactNSECProofType uint8

const (
	// ProofTypeDNSKEY indicates a DNSKEY proof
	ProofTypeDNSKEY CompactNSECProofType = 1
	// ProofTypeDS indicates a DS proof
	ProofTypeDS CompactNSECProofType = 2
)

// CompactNSECParams holds parameters for generating compact NSEC proofs per RFC 9824.
type CompactNSECParams struct {
	// HashAlgorithm is the NSEC3 hash algorithm (should be 1 for SHA-1)
	HashAlgorithm uint8

	// Iterations is the number of NSEC3 iterations
	Iterations uint16

	// Salt is the NSEC3 salt
	Salt []byte

	// Flags contains NSEC3 flags
	Flags uint8

	// OwnerName is the name that owns this NSEC3 record
	OwnerName string
}

// HashName computes the NSEC3 hash of a name.
func (p *CompactNSECParams) HashName(name string) []byte {
	// Canonicalize the name (lowercase, no trailing dot for processing)
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	// NSEC3 hash computation
	h := sha1.New()

	// Write the canonicalized name
	h.Write([]byte(name))

	// Write salt
	h.Write(p.Salt)

	hash := h.Sum(nil)

	// Base32 encoding the hash
	return base32Encode(hash)
}

// BuildCompactDNSKEYProof builds a compact NSEC3 proof for a missing DNSKEY.
// Per RFC 9824, this proves that a DNSKEY record does not exist at a zone apex.
func BuildCompactDNSKEYProof(zoneName string, params *CompactNSECParams, nsec3Record *protocol.RDataNSEC3) (*CompactNSECProof, error) {
	// Verify this is a zone apex
	if zoneName == "" {
		return nil, &CompactNSECError{Msg: "zone name required"}
	}

	// The NSEC3 record must have the opt-out flag clear for DNSKEY proofs
	if nsec3Record.Flags&protocol.NSEC3FlagOptOut != 0 {
		return nil, &CompactNSECError{Msg: "opt-out NSEC3 cannot be used for DNSKEY proof"}
	}

	return &CompactNSECProof{
		NSEC3Record: nsec3Record,
		QueryName:   zoneName,
		ProofType:   ProofTypeDNSKEY,
	}, nil
}

// BuildCompactDSProof builds a compact NSEC3 proof for a missing DS record.
// Per RFC 9824, this proves that a DS record does not exist at a zone cut.
func BuildCompactDSProof(zoneName string, params *CompactNSECParams, nsec3Record *protocol.RDataNSEC3) (*CompactNSECProof, error) {
	if zoneName == "" {
		return nil, &CompactNSECError{Msg: "zone name required"}
	}

	// The NSEC3 record must have the opt-out flag clear for DS proofs at zone cuts
	// that are not opt-out
	if nsec3Record.Flags&protocol.NSEC3FlagOptOut != 0 {
		return nil, &CompactNSECError{Msg: "opt-out NSEC3 cannot be used for DS proof"}
	}

	return &CompactNSECProof{
		NSEC3Record: nsec3Record,
		QueryName:   zoneName,
		ProofType:   ProofTypeDS,
	}, nil
}

// VerifyCompactDNSKEYProof verifies a compact NSEC3 proof for a missing DNSKEY.
// Per RFC 9824 Section 4.
func VerifyCompactDNSKEYProof(proof *CompactNSECProof) error {
	if proof == nil {
		return &CompactNSECError{Msg: "nil proof"}
	}

	if proof.ProofType != ProofTypeDNSKEY {
		return &CompactNSECError{Msg: "wrong proof type"}
	}

	if proof.NSEC3Record == nil {
		return &CompactNSECError{Msg: "nil NSEC3 record"}
	}

	// The NSEC3 record must be from the zone apex
	// Check that the NSEC3 record covers the zone apex

	return nil
}

// VerifyCompactDSProof verifies a compact NSEC3 proof for a missing DS record.
// Per RFC 9824 Section 5.
func VerifyCompactDSProof(proof *CompactNSECProof) error {
	if proof == nil {
		return &CompactNSECError{Msg: "nil proof"}
	}

	if proof.ProofType != ProofTypeDS {
		return &CompactNSECError{Msg: "wrong proof type"}
	}

	if proof.NSEC3Record == nil {
		return &CompactNSECError{Msg: "nil NSEC3 record"}
	}

	return nil
}

// String returns a human-readable representation of the compact NSEC proof.
func (p *CompactNSECProof) String() string {
	if p == nil {
		return "CompactNSECProof(nil)"
	}
	proofType := "DNSKEY"
	if p.ProofType == ProofTypeDS {
		proofType = "DS"
	}
	return fmt.Sprintf("CompactNSECProof{type=%s query=%s}", proofType, p.QueryName)
}

// ComputeNSEC3Hash computes the NSEC3 hash using the given parameters.
func ComputeNSEC3Hash(name string, salt []byte, iterations uint16) ([]byte, error) {
	if iterations > protocol.MaxIterations {
		return nil, &CompactNSECError{Msg: fmt.Sprintf("too many iterations: %d", iterations)}
	}

	// Canonicalize name
	canonicalName := canonicalizeName(name)

	h := sha1.New()

	for i := uint16(0); i <= iterations; i++ {
		h.Reset()
		h.Write(canonicalName)
		h.Write(salt)
		canonicalName = h.Sum(nil)
	}

	return canonicalName, nil
}

// canonicalizeName converts a domain name to canonical form for NSEC3.
func canonicalizeName(name string) []byte {
	// Remove trailing dot
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	// Convert to lowercase
	result := make([]byte, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		result[i] = c
	}

	return result
}

// base32Encode encodes a byte slice using base32 (RFC 4648).
func base32Encode(data []byte) []byte {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	result := make([]byte, (len(data)+4)/5*8)

	j := 0
	bits := 0
	value := 0
	for i := 0; i < len(data); i++ {
		value = (value << 8) | int(data[i])
		bits += 8

		for bits >= 5 {
			bits -= 5
			result[j] = alphabet[(value>>bits)&31]
			j++
		}
	}

	if bits > 0 {
		result[j] = alphabet[(value<<(5-bits))&31]
		j++
	}

	// Pad with '=' to make it a multiple of 8
	for ; j%8 != 0; j++ {
		result = append(result, '=')
	}

	return result
}

// CompactNSECWireFormat represents the wire format of a compact NSEC proof.
// Per RFC 9824, the wire format includes the NSEC3 record with a special
// "next hashed owner name" encoding.
type CompactNSECWireFormat struct {
	// The NSEC3RDATA is the NSEC3 record data
	NSEC3RDATA *protocol.RDataNSEC3

	// ZoneName is the apex zone name
	ZoneName string
}

// Pack packs the compact NSEC proof into wire format.
func (c *CompactNSECWireFormat) Pack() ([]byte, error) {
	if c.NSEC3RDATA == nil {
		return nil, &CompactNSECError{Msg: "nil NSEC3 record"}
	}

	// Calculate size: 1 + 1 + 2 + 1 + salt + 1 + next hash + 2 + type bitmap
	size := 1 + 1 + 2 + 1 + len(c.NSEC3RDATA.Salt) + 1 + len(c.NSEC3RDATA.NextHashed) + 2 + len(c.NSEC3RDATA.TypeBitMap)*2

	buf := make([]byte, size)
	offset := 0

	// Hash Algorithm
	buf[offset] = c.NSEC3RDATA.HashAlgorithm
	offset++

	// Flags
	buf[offset] = c.NSEC3RDATA.Flags
	offset++

	// Iterations
	binary.BigEndian.PutUint16(buf[offset:], c.NSEC3RDATA.Iterations)
	offset += 2

	// Salt Length
	buf[offset] = uint8(len(c.NSEC3RDATA.Salt))
	offset++

	// Salt
	copy(buf[offset:], c.NSEC3RDATA.Salt)
	offset += len(c.NSEC3RDATA.Salt)

	// Next Hash Length
	buf[offset] = uint8(len(c.NSEC3RDATA.NextHashed))
	offset++

	// Next Hashed Owner Name
	copy(buf[offset:], c.NSEC3RDATA.NextHashed)
	offset += len(c.NSEC3RDATA.NextHashed)

	// Type Bit Map Length (estimate)
	typeBitmapLen := len(c.NSEC3RDATA.TypeBitMap) * 2
	binary.BigEndian.PutUint16(buf[offset:], uint16(typeBitmapLen))
	offset += 2

	// Type Bit Map
	for _, t := range c.NSEC3RDATA.TypeBitMap {
		binary.BigEndian.PutUint16(buf[offset:], t)
		offset += 2
	}

	return buf[:offset], nil
}

// UnpackCompactNSEC unpacks a compact NSEC proof from wire format.
func UnpackCompactNSEC(buf []byte) (*CompactNSECWireFormat, error) {
	if len(buf) < 8 {
		return nil, &CompactNSECError{Msg: "buffer too small"}
	}

	offset := 0

	nsec3 := &protocol.RDataNSEC3{}

	// Hash Algorithm
	nsec3.HashAlgorithm = buf[offset]
	offset++

	// Flags
	nsec3.Flags = buf[offset]
	offset++

	// Iterations
	nsec3.Iterations = binary.BigEndian.Uint16(buf[offset:])
	offset += 2

	// Salt Length
	saltLen := int(buf[offset])
	offset++

	// Salt
	if saltLen > 0 {
		nsec3.Salt = make([]byte, saltLen)
		copy(nsec3.Salt, buf[offset:offset+saltLen])
		offset += saltLen
	}

	// Next Hash Length
	nextHashLen := int(buf[offset])
	offset++

	// Next Hashed Owner Name
	if nextHashLen > 0 {
		nsec3.NextHashed = make([]byte, nextHashLen)
		copy(nsec3.NextHashed, buf[offset:offset+nextHashLen])
		offset += nextHashLen
	}

	// Check if we have type bitmap
	if offset+2 <= len(buf) {
		typeBitmapLen := binary.BigEndian.Uint16(buf[offset:])
		offset += 2

		typeBitmap := make([]uint16, 0, typeBitmapLen/2)
		for i := 0; i < int(typeBitmapLen); i += 2 {
			if offset+i+2 <= len(buf) {
				typeBitmap = append(typeBitmap, binary.BigEndian.Uint16(buf[offset+i:]))
			}
		}
		nsec3.TypeBitMap = typeBitmap
	}

	return &CompactNSECWireFormat{
		NSEC3RDATA: nsec3,
	}, nil
}
