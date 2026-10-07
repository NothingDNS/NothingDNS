// Package transfer implements DNS zone transfer protocols including AXFR, IXFR,
// NOTIFY, DDNS, TKEY, and XoT per RFC 9103.
package transfer

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TKEY (Transaction Key) - RFC 2930
// TKEY provides a mechanism for establishing shared secrets between
// a DNS client and server for use in TSIG or SIG(0) authentication.

// TKEY Modes
const (
	TKEYModeServerAssignment   = 1
	TKEYModeDiffieHellman      = 2
	TKEYModeGSSAPI             = 3
	TKEYModeResolverAssignment = 4
	TKEYModeKeyDeletion        = 5
)

// TKEY Errors
const (
	TKEYErrNoError      = 0
	TKEYErrBadSig       = 16
	TKEYErrBadKey       = 17
	TKEYErrBadTime      = 18
	TKEYErrBadMode      = 19
	TKEYErrBadName      = 20
	TKEYErrBadAlgorithm = 21
)

// TKEYRecord represents a TKEY record (RFC 2930).
type TKEYRecord struct {
	// Algorithm name (e.g., "hmac-sha256.")
	Algorithm string

	// Security parameters (depends on mode)
	SecurityParameters []byte

	// Key inception time
	Inception time.Time

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
	if tkey == nil {
		return nil, fmt.Errorf("nil TKEY record")
	}
	if len(tkey.KeyData) > 65535 {
		return nil, fmt.Errorf("TKEY key data too large: %d bytes", len(tkey.KeyData))
	}
	if len(tkey.OtherData) > 65535 {
		return nil, fmt.Errorf("TKEY other data too large: %d bytes", len(tkey.OtherData))
	}

	algNameParsed, err := protocol.ParseName(tkey.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("parsing algorithm name: %w", err)
	}

	algNameWire := protocol.CanonicalWireName(tkey.Algorithm)

	// RFC 2930 §2: Algorithm, Inception u32, Expiration u32, Mode u16,
	// Error u16, Key Size u16, Key Data, Other Size u16, Other Data.
	rdataLen := len(algNameWire) + 4 + 4 + 2 + 2 + 2 + len(tkey.KeyData) + 2 + len(tkey.OtherData)
	rdata := make([]byte, rdataLen)
	offset := 0

	// Algorithm name
	copy(rdata[offset:], algNameWire)
	offset += len(algNameWire)

	// Inception and Expiration are 32-bit Unix times.
	inception := tkey.Inception
	if inception.IsZero() {
		inception = tkey.Expiration.Add(-time.Hour)
	}
	inceptionUnix, err := formatTKEYTime(inception)
	if err != nil {
		return nil, fmt.Errorf("invalid TKEY inception: %w", err)
	}
	binary.BigEndian.PutUint32(rdata[offset:], inceptionUnix)
	offset += 4
	expirationUnix, err := formatTKEYTime(tkey.Expiration)
	if err != nil {
		return nil, fmt.Errorf("invalid TKEY expiration: %w", err)
	}
	binary.BigEndian.PutUint32(rdata[offset:], expirationUnix)
	offset += 4

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

	return &protocol.ResourceRecord{
		Name:  algNameParsed,
		Type:  protocol.TypeTKEY,
		Class: protocol.ClassANY,
		TTL:   0,
		Data:  &protocol.RDataRaw{TypeVal: protocol.TypeTKEY, Data: rdata},
	}, nil
}

// formatTKEYTime formats a time for TKEY RDATA (32-bit Unix time).
func formatTKEYTime(t time.Time) (uint32, error) {
	sec := t.Unix()
	if sec < 0 || sec > int64(^uint32(0)) {
		return 0, fmt.Errorf("time %s outside uint32 Unix range", t.UTC().Format(time.RFC3339))
	}
	return uint32(sec), nil
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

	now := time.Now()
	return &TKEYRecord{
		Algorithm:          algorithm,
		SecurityParameters: nil,
		Inception:          now,
		Expiration:         now.Add(time.Hour),
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

	now := time.Now()
	return &TKEYRecord{
		Algorithm:          algorithm,
		SecurityParameters: secParams,
		Inception:          now,
		Expiration:         now.Add(time.Hour),
		Mode:               TKEYModeDiffieHellman,
		Error:              TKEYErrNoError,
		KeyData:            publicValue,
		OtherData:          nil,
	}, nil
}

// computeDHValue computes base^exp mod prime using Diffie-Hellman.
// This implements proper DH key exchange as per RFC 2631.
func computeDHValue(prime, base, exp []byte) ([]byte, error) {
	p := new(big.Int).SetBytes(prime)
	g := new(big.Int).SetBytes(base)
	x := new(big.Int).SetBytes(exp)

	// Reject degenerate parameters (F212): a zero modulus makes Exp compute
	// the unbounded g^x, and p < 3, g outside [2, p-2] or x = 0 yield a
	// public value that carries no secret.
	if p.Cmp(big.NewInt(3)) < 0 {
		return nil, fmt.Errorf("DH prime must be at least 3")
	}
	if g.Cmp(big.NewInt(2)) < 0 || g.Cmp(new(big.Int).Sub(p, big.NewInt(1))) >= 0 {
		return nil, fmt.Errorf("DH base must be in [2, p-2]")
	}
	if x.Sign() == 0 {
		return nil, fmt.Errorf("DH private value must be non-zero")
	}

	// Compute g^x mod p
	result := new(big.Int).Exp(g, x, p)
	return result.Bytes(), nil
}

// ComputeTKEYHMAC computes the HMAC for a TKEY record.
// Used for verifying TKEY messages.
// The algorithm is a TSIG HMAC name (trailing dot optional); unsupported
// algorithms are an error rather than a silent HMAC-SHA256 (F213).
func ComputeTKEYHMAC(msg []byte, key []byte, algorithm string) ([]byte, error) {
	return calculateMAC(key, msg, strings.TrimSuffix(strings.ToLower(algorithm), "."))
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
	if tkeyExpiredAt(tkey.Expiration, time.Now()) {
		return fmt.Errorf("TKEY record has expired")
	}

	return nil
}

func tkeyExpiredAt(expiration, now time.Time) bool {
	return !now.Before(expiration)
}

// String returns a human-readable representation of the TKEY record.
func (t *TKEYRecord) String() string {
	return fmt.Sprintf("TKEY{algorithm=%s mode=%s error=%s expires=%s}",
		t.Algorithm,
		TKEYModeString(t.Mode),
		TKEYErrorString(t.Error),
		t.Expiration.Format(time.RFC3339))
}
