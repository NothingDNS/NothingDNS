package protocol

import (
	"crypto/sha1" //nolint:gosec // SHA-1 needed for DS digest type 1 (deprecated but still used)
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

// DS digest type 3 (GOST R 34.11-94, RFC 5933) is intentionally not
// implemented. A previous attempt with a placeholder S-box silently
// produced non-conformant hashes — far worse than returning an error,
// because the bogus hash could accidentally match either side and
// validate forged delegations. GOST is deprecated by RFC 8624 §3.2
// ("MUST NOT be used for signing; MAY be used for validation") and is
// not used outside historical Russian deployments. If a deployment
// truly needs GOST validation, wire in a vetted external implementation
// (e.g. github.com/martinlindhe/gogost) rather than rolling crypto here.

// RDataDS represents a Delegation Signer (DS) record (RFC 4034).
// DS records are used to secure delegation to child zones.
type RDataDS struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

// Type returns TypeDS.
func (r *RDataDS) Type() uint16 { return TypeDS }

// Pack serializes the DS record to wire format.
func (r *RDataDS) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil DS record")
	}

	if offset < 0 || offset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	startOffset := offset

	// Key Tag (2 bytes)
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.KeyTag)
	offset += 2

	// Algorithm (1 byte)
	if offset+1 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = r.Algorithm
	offset++

	// Digest Type (1 byte)
	if offset+1 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = r.DigestType
	offset++

	// Digest
	digestLen := len(r.Digest)
	if offset+digestLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.Digest)
	offset += digestLen

	return offset - startOffset, nil
}

// Unpack deserializes the DS record from wire format.
func (r *RDataDS) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil DS record")
	}

	if offset < 0 || offset > len(buf) || int(rdlength) > len(buf)-offset {
		return 0, ErrBufferTooSmall
	}

	startOffset := offset
	endOffset := offset + int(rdlength)

	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// Need at least 4 bytes for fixed fields
	if offset+4 > endOffset {
		return 0, ErrBufferTooSmall
	}

	// Key Tag
	r.KeyTag = Uint16(buf[offset:])
	offset += 2

	// Algorithm
	r.Algorithm = buf[offset]
	offset++

	// Digest Type
	r.DigestType = buf[offset]
	offset++

	// Digest (remaining bytes)
	digestLen := endOffset - offset
	r.Digest = make([]byte, digestLen)
	copy(r.Digest, buf[offset:endOffset])
	offset = endOffset

	return offset - startOffset, nil
}

// String returns the DS record in presentation format.
func (r *RDataDS) String() string {
	if r == nil {
		return ""
	}

	return fmt.Sprintf("%d %d %d %s", r.KeyTag, r.Algorithm, r.DigestType, hex.EncodeToString(r.Digest))
}

// Len returns the wire length of the DS record.
func (r *RDataDS) Len() int {
	if r == nil {
		return 0
	}

	return 4 + len(r.Digest)
}

// Copy creates a deep copy of the DS record.
func (r *RDataDS) Copy() RData {
	if r == nil {
		return nil
	}

	digestCopy := make([]byte, len(r.Digest))
	copy(digestCopy, r.Digest)
	return &RDataDS{
		KeyTag:     r.KeyTag,
		Algorithm:  r.Algorithm,
		DigestType: r.DigestType,
		Digest:     digestCopy,
	}
}

// DigestTypeToString returns the name of a digest type.
func DigestTypeToString(digestType uint8) string {
	switch digestType {
	case 1:
		return "SHA-1"
	case 2:
		return "SHA-256"
	case 3:
		return "GOST R 34.11-94"
	case 4:
		return "SHA-384"
	default:
		return fmt.Sprintf("TYPE%d", digestType)
	}
}

// CalculateDSDigest computes the digest for a DS record from DNSKEY data.
// This is used to verify that a DNSKEY matches a DS record.
func CalculateDSDigest(fqdn string, key *RDataDNSKEY, digestType uint8) ([]byte, error) {
	// Pack the DNSKEY RDATA (excluding the name, type, class, TTL, rdlength)
	keyData := make([]byte, key.Len())
	_, err := key.Pack(keyData, 0)
	if err != nil {
		return nil, fmt.Errorf("packing DNSKEY: %w", err)
	}

	// Pack the owner name in wire format
	ownerName, err := ParseName(fqdn)
	if err != nil {
		return nil, fmt.Errorf("parsing owner name: %w", err)
	}
	nameBuf := make([]byte, 256)
	nameLen, err := PackName(ownerName, nameBuf, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("packing owner name: %w", err)
	}

	// Concatenate: owner name + DNSKEY RDATA
	data := make([]byte, nameLen+len(keyData))
	copy(data, nameBuf[:nameLen])
	copy(data[nameLen:], keyData)

	// Calculate digest based on digest type
	switch digestType {
	case 1: // SHA-1 (NOT RECOMMENDED, but supported for compatibility)
		h := sha1.Sum(data) //nolint:gosec
		return h[:], nil
	case 2: // SHA-256
		digest := sha256.Sum256(data)
		return digest[:], nil
	case 3: // GOST R 34.11-94 (RFC 5933) — not implemented; see file header.
		return nil, fmt.Errorf("DS digest type 3 (GOST R 34.11-94) is not supported by this server; deprecated by RFC 8624 §3.2")
	case 4: // SHA-384
		digest := sha512.Sum384(data)
		return digest[:], nil
	default:
		return nil, fmt.Errorf("unsupported digest type: %d", digestType)
	}
}
