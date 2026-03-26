package protocol

import (
	"encoding/hex"
	"fmt"
)

// RDataNSEC3PARAM represents an NSEC3PARAM record (RFC 5155).
// NSEC3PARAM records provide parameters for generating NSEC3 chains.
// They are used by authoritative servers to signal NSEC3 usage and
// by signers to know which parameters to use when signing a zone.
type RDataNSEC3PARAM struct {
	HashAlgorithm uint8
	Flags         uint8
	Iterations    uint16
	Salt          []byte
}

// Type returns TypeNSEC3PARAM.
func (r *RDataNSEC3PARAM) Type() uint16 { return TypeNSEC3PARAM }

// Pack serializes the NSEC3PARAM record to wire format.
func (r *RDataNSEC3PARAM) Pack(buf []byte, offset int) (int, error) {
	startOffset := offset

	// Hash Algorithm (1 byte)
	if offset+1 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = r.HashAlgorithm
	offset++

	// Flags (1 byte)
	if offset+1 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = r.Flags
	offset++

	// Iterations (2 bytes)
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.Iterations)
	offset += 2

	// Salt Length (1 byte)
	saltLen := len(r.Salt)
	if saltLen > 255 {
		return 0, ErrLabelTooLong
	}
	if offset+1 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = uint8(saltLen)
	offset++

	// Salt
	if offset+saltLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.Salt)
	offset += saltLen

	return offset - startOffset, nil
}

// Unpack deserializes the NSEC3PARAM record from wire format.
func (r *RDataNSEC3PARAM) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	startOffset := offset
	endOffset := offset + int(rdlength)

	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// Need at least 5 bytes for fixed fields before salt
	if offset+5 > endOffset {
		return 0, ErrBufferTooSmall
	}

	// Hash Algorithm
	r.HashAlgorithm = buf[offset]
	offset++

	// Flags
	r.Flags = buf[offset]
	offset++

	// Iterations
	r.Iterations = Uint16(buf[offset:])
	offset += 2

	// Salt Length
	saltLen := int(buf[offset])
	offset++

	// Salt
	if offset+saltLen > endOffset {
		return 0, ErrBufferTooSmall
	}
	r.Salt = make([]byte, saltLen)
	copy(r.Salt, buf[offset:offset+saltLen])
	offset += saltLen

	return offset - startOffset, nil
}

// String returns the NSEC3PARAM record in presentation format.
func (r *RDataNSEC3PARAM) String() string {
	saltStr := "-"
	if len(r.Salt) > 0 {
		saltStr = hex.EncodeToString(r.Salt)
	}

	return fmt.Sprintf("%d %d %d %s",
		r.HashAlgorithm,
		r.Flags,
		r.Iterations,
		saltStr,
	)
}

// Len returns the wire length of the NSEC3PARAM record.
func (r *RDataNSEC3PARAM) Len() int {
	return 1 + 1 + 2 + 1 + len(r.Salt)
}

// Copy creates a deep copy of the NSEC3PARAM record.
func (r *RDataNSEC3PARAM) Copy() RData {
	saltCopy := make([]byte, len(r.Salt))
	copy(saltCopy, r.Salt)
	return &RDataNSEC3PARAM{
		HashAlgorithm: r.HashAlgorithm,
		Flags:         r.Flags,
		Iterations:    r.Iterations,
		Salt:          saltCopy,
	}
}

// IsOptOut returns true if the opt-out flag is set.
func (r *RDataNSEC3PARAM) IsOptOut() bool {
	return r.Flags&NSEC3FlagOptOut != 0
}

// ToNSEC3Params returns the hash parameters as an NSEC3Params struct.
// This is useful for computing NSEC3 hashes.
func (r *RDataNSEC3PARAM) ToNSEC3Params() NSEC3Params {
	return NSEC3Params{
		Algorithm:  r.HashAlgorithm,
		Iterations: r.Iterations,
		Salt:       r.Salt,
	}
}

// NSEC3Params holds the parameters needed for NSEC3 hash computation.
type NSEC3Params struct {
	Algorithm  uint8
	Iterations uint16
	Salt       []byte
}

// VerifyParams verifies that the parameters are valid per RFC 5155.
func (r *RDataNSEC3PARAM) VerifyParams() error {
	// Check hash algorithm
	if r.HashAlgorithm != NSEC3HashSHA1 {
		return fmt.Errorf("unsupported NSEC3 hash algorithm: %d", r.HashAlgorithm)
	}

	// Check iterations (RFC 5155 recommends limiting this for security)
	// While there's no strict limit in the RFC, 150 is a common implementation limit
	if r.Iterations > 150 {
		return fmt.Errorf("NSEC3 iterations too high: %d (max recommended: 150)", r.Iterations)
	}

	// Check salt length
	if len(r.Salt) > 255 {
		return fmt.Errorf("NSEC3 salt too long: %d bytes (max: 255)", len(r.Salt))
	}

	return nil
}

// MaxIterations is the recommended maximum for NSEC3 iterations.
// This helps prevent computational DoS attacks.
const MaxIterations = 150

// DefaultNSEC3Params returns recommended NSEC3 parameters.
func DefaultNSEC3Params() *RDataNSEC3PARAM {
	return &RDataNSEC3PARAM{
		HashAlgorithm: NSEC3HashSHA1,
		Flags:         0,
		Iterations:    0, // No iterations recommended for most zones
		Salt:          []byte{},
	}
}
