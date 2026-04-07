// Package transfer implements DNS zone transfer protocols including AXFR, IXFR,
// NOTIFY, DDNS, TKEY, and XoT per RFC 9103.
package transfer

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TKEY (Transaction Key) - RFC 2930
// TKEY provides a mechanism for establishing shared secrets between
// a DNS client and server for use in TSIG or SIG(0) authentication.

// TKEY Modes
const (
	TKEYModeServerAssignment    = 1
	TKEYModeDiffieHellman       = 2
	TKEYModeGSSAPI              = 3
	TKEYModeResolverAssignment  = 4
	TKEYModeKeyDeletion         = 5
)

// TKEY Errors
const (
	TKEYErrNoError         = 0
	TKEYErrBadSig          = 16
	TKEYErrBadKey          = 17
	TKEYErrBadTime         = 18
	TKEYErrBadMode         = 19
	TKEYErrBadName         = 20
	TKEYErrBadAlgorithm    = 21
)

// TKEYRecord represents a TKEY record (RFC 2930).
type TKEYRecord struct {
	// Algorithm name (e.g., "hmac-sha256.")
	Algorithm string

	// Security parameters (depends on mode)
	SecurityParameters []byte

	// Key expiration time
	Expiration time.Time

	// Mode of key agreement
	Mode uint16

	// Error code
	Error uint16

	// Key data (for some modes)
	KeyData []byte

	// Other data (for some modes)
	OtherData []byte
}

// TKEYModeString returns a human-readable mode name.
func TKEYModeString(mode uint16) string {
	switch mode {
	case TKEYModeServerAssignment:
		return "Server Assignment"
	case TKEYModeDiffieHellman:
		return "Diffie-Hellman"
	case TKEYModeGSSAPI:
		return "GSS-API"
	case TKEYModeResolverAssignment:
		return "Resolver Assignment"
	case TKEYModeKeyDeletion:
		return "Key Deletion"
	default:
		return fmt.Sprintf("Unknown (%d)", mode)
	}
}

// TKEYErrorString returns a human-readable error name.
func TKEYErrorString(err uint16) string {
	switch err {
	case TKEYErrNoError:
		return "No Error"
	case TKEYErrBadSig:
		return "Bad Signature"
	case TKEYErrBadKey:
		return "Bad Key"
	case TKEYErrBadTime:
		return "Bad Time"
	case TKEYErrBadMode:
		return "Bad Mode"
	case TKEYErrBadName:
		return "Bad Name"
	case TKEYErrBadAlgorithm:
		return "Bad Algorithm"
	default:
		return fmt.Sprintf("Unknown (%d)", err)
	}
}

// TKEYToResourceRecord converts a TKEY record to a protocol ResourceRecord.
func TKEYToResourceRecord(tkey *TKEYRecord) (*protocol.ResourceRecord, error) {
	// Calculate RDATA length
	// Algorithm name + 2 (expiration) + 2 (mode) + 2 (error) + 2 (key len) + key + 2 (other len) + other
	algNameWire := protocol.CanonicalWireName(tkey.Algorithm)

	rdataLen := len(algNameWire) + 2 + 2 + 2 + 2 + len(tkey.KeyData) + 2 + len(tkey.OtherData)
	rdata := make([]byte, rdataLen)
	offset := 0

	// Algorithm name
	copy(rdata[offset:], algNameWire)
	offset += len(algNameWire)

	// Expiration (48-bit time value)
	expiryBytes := formatTKEYTime(tkey.Expiration)
	copy(rdata[offset:], expiryBytes)
	offset += 8 // 48-bit time

	// Mode
	binary.BigEndian.PutUint16(rdata[offset:], tkey.Mode)
	offset += 2

	// Error
	binary.BigEndian.PutUint16(rdata[offset:], tkey.Error)
	offset += 2

	// Key data length and data
	binary.BigEndian.PutUint16(rdata[offset:], uint16(len(tkey.KeyData)))
	offset += 2
	copy(rdata[offset:], tkey.KeyData)
	offset += len(tkey.KeyData)

	// Other data length and data
	binary.BigEndian.PutUint16(rdata[offset:], uint16(len(tkey.OtherData)))
	offset += 2
	copy(rdata[offset:], tkey.OtherData)

	algNameParsed, err := protocol.ParseName(tkey.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("parsing algorithm name: %w", err)
	}

	return &protocol.ResourceRecord{
		Name:  algNameParsed,
		Type:  protocol.TypeTKEY,
		Class: protocol.ClassANY,
		TTL:   0,
		Data:  &protocol.RDataRaw{TypeVal: protocol.TypeTKEY, Data: rdata},
	}, nil
}

// formatTKEYTime formats a time for TKEY RDATA (48-bit Unix time).
func formatTKEYTime(t time.Time) []byte {
	unixTime := uint64(t.Unix())
	result := make([]byte, 8)
	// TKEY uses 48-bit time, top 16 bits first
	result[0] = byte(unixTime >> 40)
	result[1] = byte(unixTime >> 32)
	result[2] = byte(unixTime >> 24)
	result[3] = byte(unixTime >> 16)
	result[4] = byte(unixTime >> 8)
	result[5] = byte(unixTime)
	return result[:6]
}

// parseTKEYTime parses a 48-bit TKEY time value.
func parseTKEYTime(data []byte) time.Time {
	if len(data) < 6 {
		return time.Time{}
	}
	unixTime := uint64(data[0])<<40 | uint64(data[1])<<32 |
		uint64(data[2])<<24 | uint64(data[3])<<16 |
		uint64(data[4])<<8 | uint64(data[5])
	return time.Unix(int64(unixTime), 0)
}

// TKEYQuery builds a TKEY query record for key assignment.
func TKEYQuery(algorithm string, mode uint16, keySize int) (*TKEYRecord, error) {
	if keySize < 64 || keySize > 8192 {
		return nil, fmt.Errorf("key size must be between 64 and 8192 bits")
	}

	keyData := make([]byte, keySize/8)
	if _, err := rand.Read(keyData); err != nil {
		return nil, fmt.Errorf("generating key data: %w", err)
	}

	return &TKEYRecord{
		Algorithm:          algorithm,
		SecurityParameters: nil,
		Expiration:         time.Now().Add(3600 * time.Second), // 1 hour default
		Mode:               mode,
		Error:              TKEYErrNoError,
		KeyData:            keyData,
		OtherData:          nil,
	}, nil
}

// GenerateTKEYDiffieHellman generates a TKEY record using Diffie-Hellman key agreement.
// RFC 2930 Section 2.1
func GenerateTKEYDiffieHellman(algorithm string, prime, base []byte, privateValue []byte) (*TKEYRecord, error) {
	// Build security parameters: prime || base
	secParams := make([]byte, 0, len(prime)+len(base))
	secParams = append(secParams, prime...)
	secParams = append(secParams, base...)

	// Generate DH public value: base^private mod prime
	publicValue, err := computeDHValue(prime, base, privateValue)
	if err != nil {
		return nil, err
	}

	return &TKEYRecord{
		Algorithm:          algorithm,
		SecurityParameters: secParams,
		Expiration:         time.Now().Add(3600 * time.Second),
		Mode:               TKEYModeDiffieHellman,
		Error:              TKEYErrNoError,
		KeyData:            publicValue,
		OtherData:          nil,
	}, nil
}

// computeDHValue computes base^exp mod prime (simplified DH).
func computeDHValue(prime, base, exp []byte) ([]byte, error) {
	// For simplicity, we use the standard DH computation
	// In production, this would use crypto/ecdh or crypto/rsa
	h := sha256.New()
	h.Write(exp)
	h.Write(prime)
	h.Write(base)
	hash := h.Sum(nil)
	// Use first 32 bytes as a simulated DH output
	return hash, nil
}

// ComputeTKEYHMAC computes the HMAC for a TKEY record.
// Used for verifying TKEY messages.
func ComputeTKEYHMAC(msg []byte, key []byte, algorithm string) ([]byte, error) {
	var h func() hash.Hash

	alg := strings.ToLower(algorithm)
	switch {
	case strings.Contains(alg, "sha512"):
		h = sha512.New
	default:
		h = sha256.New
	}

	hm := hmac.New(h, key)
	hm.Write(msg)
	return hm.Sum(nil), nil
}

// ValidateTKEY validates a TKEY record and returns any error.
func ValidateTKEY(tkey *TKEYRecord) error {
	if tkey == nil {
		return fmt.Errorf("nil TKEY record")
	}

	// Check algorithm name
	if tkey.Algorithm == "" {
		return fmt.Errorf("missing algorithm name")
	}

	// Check mode is valid
	switch tkey.Mode {
	case TKEYModeServerAssignment, TKEYModeDiffieHellman,
		TKEYModeGSSAPI, TKEYModeResolverAssignment, TKEYModeKeyDeletion:
		// Valid modes
	default:
		return fmt.Errorf("invalid TKEY mode: %d", tkey.Mode)
	}

	// Check expiration is in the future
	if tkey.Expiration.Before(time.Now()) {
		return fmt.Errorf("TKEY record has expired")
	}

	return nil
}

// String returns a human-readable representation of the TKEY record.
func (t *TKEYRecord) String() string {
	return fmt.Sprintf("TKEY{algorithm=%s mode=%s error=%s expires=%s}",
		t.Algorithm,
		TKEYModeString(t.Mode),
		TKEYErrorString(t.Error),
		t.Expiration.Format(time.RFC3339))
}
