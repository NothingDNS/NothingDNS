// Package protocol provides DNS protocol types for NothingDNS.
//
// Zone message digest: ZONEMD.

package protocol

import (
	"encoding/hex"
	"fmt"
)

type RDataZONEMD struct {
	Serial    uint32 // SOA serial associated with this digest
	Scheme    uint8  // Digest scheme (1 = simple ZONEMD)
	Algorithm uint8  // Hash algorithm (1 = SHA-256, 2 = SHA-384)
	Digest    []byte // The digest value
}

// Pack serializes the ZONEMD RData into wire format.
func (r *RDataZONEMD) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil ZONEMD record")
	}

	// Match sibling DNSSEC RData types (DNSKEY/DS/RRSIG) by bounds-checking
	// before writing — prevents silent truncation/panic if a future caller
	// sizes the buffer from something other than Len() (VULN-026).
	need := 6 + len(r.Digest)
	if offset+need > len(buf) {
		return 0, ErrBufferTooSmall
	}
	startOffset := offset

	// Serial (4 bytes, network byte order)
	buf[offset] = byte(r.Serial >> 24)
	buf[offset+1] = byte(r.Serial >> 16)
	buf[offset+2] = byte(r.Serial >> 8)
	buf[offset+3] = byte(r.Serial)
	offset += 4

	// Scheme (1 byte)
	buf[offset] = r.Scheme
	offset++

	// Algorithm (1 byte)
	buf[offset] = r.Algorithm
	offset++

	// Digest (variable length)
	copy(buf[offset:], r.Digest)
	offset += len(r.Digest)

	return offset - startOffset, nil
}

// Unpack deserializes the ZONEMD RData from wire format.
func (r *RDataZONEMD) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil ZONEMD record")
	}

	startOffset := offset
	endOffset := offset + int(rdlength)

	// Defense-in-depth: the record-level unpacker (record.go) already ensures
	// endOffset <= len(buf) before dispatching here, but the sibling RData
	// unpackers (SVCB/SSHFP/TLSA) all re-check, and the buf[offset:endOffset]
	// slice below would panic if a direct caller skipped that guard.
	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}
	if offset+6 > endOffset {
		return 0, fmt.Errorf("ZONEMD rdata too short")
	}

	// Serial (4 bytes)
	r.Serial = uint32(buf[offset])<<24 | uint32(buf[offset+1])<<16 | uint32(buf[offset+2])<<8 | uint32(buf[offset+3])
	offset += 4

	// Scheme (1 byte)
	r.Scheme = buf[offset]
	offset++

	// Algorithm (1 byte)
	r.Algorithm = buf[offset]
	offset++

	// Digest (remaining bytes)
	digestLen := endOffset - offset
	r.Digest = make([]byte, digestLen)
	copy(r.Digest, buf[offset:offset+digestLen])
	offset += digestLen

	return offset - startOffset, nil
}

// String returns a string representation of the ZONEMD record.
func (r *RDataZONEMD) String() string {
	if r == nil {
		return ""
	}

	return fmt.Sprintf("%d %d %d %s", r.Serial, r.Scheme, r.Algorithm, hex.EncodeToString(r.Digest))
}

// Copy creates a deep copy of the ZONEMD record.
func (r *RDataZONEMD) Copy() RData {
	if r == nil {
		return nil
	}

	digestCopy := make([]byte, len(r.Digest))
	copy(digestCopy, r.Digest)
	return &RDataZONEMD{
		Serial:    r.Serial,
		Scheme:    r.Scheme,
		Algorithm: r.Algorithm,
		Digest:    digestCopy,
	}
}

// Type returns the DNS record type code for ZONEMD.
func (r *RDataZONEMD) Type() uint16 {
	return TypeZONEMD
}

// Len returns the length of the ZONEMD record data in wire format.
func (r *RDataZONEMD) Len() int {
	if r == nil {
		return 0
	}

	return 6 + len(r.Digest) // Serial(4) + Scheme(1) + Algorithm(1) + Digest
}
