package transfer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// Algorithm constants for TSIG
const (
	// HMAC-MD5 is deprecated but included for compatibility
	HmacMD5    = "hmac-md5.sig-alg.reg.int"
	HmacSHA1   = "hmac-sha1"
	HmacSHA224 = "hmac-sha224"
	HmacSHA256 = "hmac-sha256"
	HmacSHA384 = "hmac-sha384"
	HmacSHA512 = "hmac-sha512"
)

// Error codes for TSIG
const (
	TSIGErrNoError      = 0
	TSIGErrBadSig       = 16
	TSIGErrBadKey       = 17
	TSIGErrBadTime      = 18
	TSIGErrBadMode      = 19
	TSIGErrBadName      = 20
	TSIGErrBadAlgorithm = 21
	TSIGErrBadTrunc     = 22
)

// TSIGError represents a TSIG error
var tsigErrorMessages = map[uint16]string{
	TSIGErrNoError:      "NOERROR",
	TSIGErrBadSig:       "BADSIG",
	TSIGErrBadKey:       "BADKEY",
	TSIGErrBadTime:      "BADTIME",
	TSIGErrBadMode:      "BADMODE",
	TSIGErrBadName:      "BADNAME",
	TSIGErrBadAlgorithm: "BADALG",
	TSIGErrBadTrunc:     "BADTRUNC",
}

func TSIGErrorString(code uint16) string {
	if msg, ok := tsigErrorMessages[code]; ok {
		return msg
	}
	return fmt.Sprintf("UNKNOWN(%d)", code)
}

// TSIGKey represents a TSIG key for signing/verification
type TSIGKey struct {
	Name      string    // Key name (FQDN)
	Algorithm string    // Algorithm name (e.g., hmac-sha256)
	Secret    []byte    // Raw key bytes
	CreatedAt time.Time // When key was created
}

// TSIGRecord represents a TSIG resource record
// Wire format: Algorithm TimeSigned Fudge MAC OriginalID Error OtherLen OtherData
type TSIGRecord struct {
	Algorithm  string    // FQDN of algorithm
	TimeSigned time.Time // Signature timestamp
	Fudge      uint16    // Allowed clock skew in seconds
	MAC        []byte    // Message authentication code
	OriginalID uint16    // Original message ID
	Error      uint16    // Extended error code
	OtherLen   uint16    // Length of other data
	OtherData  []byte    // Additional error info
}

// KeyStore manages TSIG keys
type KeyStore struct {
	keys map[string]*TSIGKey // keyed by key name
}

// NewKeyStore creates a new TSIG key store
func NewKeyStore() *KeyStore {
	return &KeyStore{
		keys: make(map[string]*TSIGKey),
	}
}

// AddKey adds a key to the store
func (ks *KeyStore) AddKey(key *TSIGKey) {
	ks.keys[strings.ToLower(key.Name)] = key
}

// GetKey retrieves a key by name
func (ks *KeyStore) GetKey(name string) (*TSIGKey, bool) {
	key, ok := ks.keys[strings.ToLower(name)]
	return key, ok
}

// RemoveKey removes a key from the store
func (ks *KeyStore) RemoveKey(name string) {
	delete(ks.keys, strings.ToLower(name))
}

// ParseTSIGKey parses a TSIG key from base64 secret
func ParseTSIGKey(name, algorithm, secretB64 string) (*TSIGKey, error) {
	secret, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		return nil, fmt.Errorf("decoding secret: %w", err)
	}

	return &TSIGKey{
		Name:      name,
		Algorithm: algorithm,
		Secret:    secret,
		CreatedAt: time.Now(),
	}, nil
}

// PackTSIGRecord packs a TSIG record into wire format
func PackTSIGRecord(tsig *TSIGRecord) ([]byte, error) {
	buf := make([]byte, 0, 512)

	// Algorithm (domain name)
	algoName, err := protocol.ParseName(tsig.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("parsing algorithm name: %w", err)
	}
	algoBytes := make([]byte, 256)
	n, err := protocol.PackName(algoName, algoBytes, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("packing algorithm name: %w", err)
	}
	buf = append(buf, algoBytes[:n]...)

	// Time Signed (48 bits: 6 bytes)
	// Upper 16 bits are 0, lower 32 bits are Unix timestamp
	timeSigned := uint64(tsig.TimeSigned.Unix())
	buf = append(buf, byte(timeSigned>>40))
	buf = append(buf, byte(timeSigned>>32))
	buf = append(buf, byte(timeSigned>>24))
	buf = append(buf, byte(timeSigned>>16))
	buf = append(buf, byte(timeSigned>>8))
	buf = append(buf, byte(timeSigned))

	// Fudge (16 bits)
	buf = append(buf, byte(tsig.Fudge>>8), byte(tsig.Fudge))

	// MAC Size (16 bits)
	macLen := uint16(len(tsig.MAC))
	buf = append(buf, byte(macLen>>8), byte(macLen))

	// MAC
	buf = append(buf, tsig.MAC...)

	// Original ID (16 bits)
	buf = append(buf, byte(tsig.OriginalID>>8), byte(tsig.OriginalID))

	// Error (16 bits)
	buf = append(buf, byte(tsig.Error>>8), byte(tsig.Error))

	// Other Len (16 bits)
	buf = append(buf, byte(tsig.OtherLen>>8), byte(tsig.OtherLen))

	// Other Data
	buf = append(buf, tsig.OtherData...)

	return buf, nil
}

// UnpackTSIGRecord unpacks a TSIG record from wire format
func UnpackTSIGRecord(data []byte, offset int) (*TSIGRecord, int, error) {
	if len(data) < offset+10 {
		return nil, 0, fmt.Errorf("insufficient data for TSIG")
	}

	ts := &TSIGRecord{}
	n := offset

	// Algorithm (domain name)
	algoName, consumed, err := protocol.UnpackName(data, n)
	if err != nil {
		return nil, 0, fmt.Errorf("unpacking algorithm name: %w", err)
	}
	ts.Algorithm = strings.TrimSuffix(algoName.String(), ".")
	n += consumed

	// Time Signed (48 bits: 6 bytes)
	if len(data) < n+6 {
		return nil, 0, fmt.Errorf("insufficient data for time signed")
	}
	var timeSigned uint64
	timeSigned = uint64(data[n])<<40 | uint64(data[n+1])<<32 |
		uint64(data[n+2])<<24 | uint64(data[n+3])<<16 |
		uint64(data[n+4])<<8 | uint64(data[n+5])
	ts.TimeSigned = time.Unix(int64(timeSigned), 0)
	n += 6

	// Fudge (16 bits)
	if len(data) < n+2 {
		return nil, 0, fmt.Errorf("insufficient data for fudge")
	}
	ts.Fudge = uint16(data[n])<<8 | uint16(data[n+1])
	n += 2

	// MAC Size (16 bits)
	if len(data) < n+2 {
		return nil, 0, fmt.Errorf("insufficient data for MAC size")
	}
	macLen := uint16(data[n])<<8 | uint16(data[n+1])
	n += 2

	// MAC
	if len(data) < n+int(macLen) {
		return nil, 0, fmt.Errorf("insufficient data for MAC")
	}
	ts.MAC = make([]byte, macLen)
	copy(ts.MAC, data[n:n+int(macLen)])
	n += int(macLen)

	// Original ID (16 bits)
	if len(data) < n+2 {
		return nil, 0, fmt.Errorf("insufficient data for original ID")
	}
	ts.OriginalID = uint16(data[n])<<8 | uint16(data[n+1])
	n += 2

	// Error (16 bits)
	if len(data) < n+2 {
		return nil, 0, fmt.Errorf("insufficient data for error")
	}
	ts.Error = uint16(data[n])<<8 | uint16(data[n+1])
	n += 2

	// Other Len (16 bits)
	if len(data) < n+2 {
		return nil, 0, fmt.Errorf("insufficient data for other len")
	}
	ts.OtherLen = uint16(data[n])<<8 | uint16(data[n+1])
	n += 2

	// Other Data
	if len(data) < n+int(ts.OtherLen) {
		return nil, 0, fmt.Errorf("insufficient data for other data")
	}
	ts.OtherData = make([]byte, ts.OtherLen)
	copy(ts.OtherData, data[n:n+int(ts.OtherLen)])
	n += int(ts.OtherLen)

	return ts, n, nil
}

// SignMessage signs a DNS message with TSIG
func SignMessage(msg *protocol.Message, key *TSIGKey, fudge uint16) (*protocol.ResourceRecord, error) {
	// Create TSIG variables
	timeSigned := time.Now().UTC()

	// Build the message to sign (RFC 2845)
	// The message is signed without the TSIG record itself
	// Format: request MAC (if any) + message (before TSIG) + TSIG variables
	signedData, err := buildSignedData(msg, nil, key.Algorithm, timeSigned, fudge, msg.Header.ID)
	if err != nil {
		return nil, fmt.Errorf("building signed data: %w", err)
	}

	// Calculate MAC
	mac, err := calculateMAC(key.Secret, signedData, key.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("calculating MAC: %w", err)
	}

	// Create TSIG record
	tsig := &TSIGRecord{
		Algorithm:  key.Algorithm,
		TimeSigned: timeSigned,
		Fudge:      fudge,
		MAC:        mac,
		OriginalID: msg.Header.ID,
		Error:      TSIGErrNoError,
		OtherLen:   0,
		OtherData:  nil,
	}

	// Pack TSIG RDATA
	rdata, err := PackTSIGRecord(tsig)
	if err != nil {
		return nil, fmt.Errorf("packing TSIG: %w", err)
	}

	// Create TSIG resource record
	keyName, _ := protocol.ParseName(key.Name)
	tsigRR := &protocol.ResourceRecord{
		Name:  keyName,
		Type:  protocol.TypeTSIG,
		Class: protocol.ClassANY, // TSIG uses ANY class
		TTL:   0,                 // TSIG TTL is always 0
		Data: &RDataTSIG{
			Raw: rdata,
		},
	}

	return tsigRR, nil
}

// VerifyMessage verifies a TSIG-signed message
func VerifyMessage(msg *protocol.Message, key *TSIGKey, previousMAC []byte) error {
	// Find TSIG record in additional section
	tsigRR, err := findTSIGRecord(msg)
	if err != nil {
		return fmt.Errorf("finding TSIG record: %w", err)
	}

	// Unpack TSIG data
	tsigs := &TSIGRecord{}
	if rdata, ok := tsigRR.Data.(*RDataTSIG); ok {
		tsigs, _, err = UnpackTSIGRecord(rdata.Raw, 0)
		if err != nil {
			return fmt.Errorf("unpacking TSIG: %w", err)
		}
	} else {
		return fmt.Errorf("invalid TSIG data type")
	}

	// Check algorithm matches
	if tsigs.Algorithm != key.Algorithm {
		return fmt.Errorf("algorithm mismatch: got %s, expected %s", tsigs.Algorithm, key.Algorithm)
	}

	// Check time
	now := time.Now().UTC()
	fudge := time.Duration(tsigs.Fudge) * time.Second
	if now.Before(tsigs.TimeSigned.Add(-fudge)) || now.After(tsigs.TimeSigned.Add(fudge)) {
		return fmt.Errorf("TSIG time out of range")
	}

	// Build signed data
	signedData, err := buildSignedData(msg, previousMAC, key.Algorithm, tsigs.TimeSigned, tsigs.Fudge, tsigs.OriginalID)
	if err != nil {
		return fmt.Errorf("building signed data: %w", err)
	}

	// Calculate expected MAC
	expectedMAC, err := calculateMAC(key.Secret, signedData, key.Algorithm)
	if err != nil {
		return fmt.Errorf("calculating MAC: %w", err)
	}

	// Compare MACs
	if !hmac.Equal(tsigs.MAC, expectedMAC) {
		return fmt.Errorf("MAC verification failed")
	}

	return nil
}

// calculateMAC calculates HMAC for given data and algorithm
func calculateMAC(key, data []byte, algorithm string) ([]byte, error) {
	var mac []byte

	switch strings.ToLower(algorithm) {
	case HmacSHA256:
		h := hmac.New(sha256.New, key)
		h.Write(data)
		mac = h.Sum(nil)
	case HmacSHA384:
		h := hmac.New(sha512.New384, key)
		h.Write(data)
		mac = h.Sum(nil)
	case HmacSHA512:
		h := hmac.New(sha512.New, key)
		h.Write(data)
		mac = h.Sum(nil)
	case HmacSHA1:
		// SHA-1 is deprecated, use SHA-256 for compatibility
		return nil, fmt.Errorf("SHA-1 is deprecated, use SHA-256 or SHA-512")
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	return mac, nil
}

// buildSignedData builds the data to be signed according to RFC 2845
func buildSignedData(msg *protocol.Message, previousMAC []byte, algorithm string, timeSigned time.Time, fudge uint16, originalID uint16) ([]byte, error) {
	var buf bytes.Buffer

	// If there's a previous MAC (multi-message transfer), include it
	if len(previousMAC) > 0 {
		buf.Write(previousMAC)
	}

	// Write message (excluding TSIG record)
	// Clone message without TSIG
	msgCopy := cloneMessageWithoutTSIG(msg)
	msgBytes := make([]byte, 65535)
	n, err := msgCopy.Pack(msgBytes)
	if err != nil {
		return nil, fmt.Errorf("packing message: %w", err)
	}
	buf.Write(msgBytes[:n])

	// Write TSIG variables
	// Algorithm name (wire format)
	algoName, _ := protocol.ParseName(algorithm)
	algoBytes := make([]byte, 256)
	algoLen, _ := protocol.PackName(algoName, algoBytes, 0, nil)
	buf.Write(algoBytes[:algoLen])

	// Time signed (48 bits)
	timeUnix := uint64(timeSigned.Unix())
	buf.WriteByte(byte(timeUnix >> 40))
	buf.WriteByte(byte(timeUnix >> 32))
	buf.WriteByte(byte(timeUnix >> 24))
	buf.WriteByte(byte(timeUnix >> 16))
	buf.WriteByte(byte(timeUnix >> 8))
	buf.WriteByte(byte(timeUnix))

	// Fudge
	buf.WriteByte(byte(fudge >> 8))
	buf.WriteByte(byte(fudge))

	// Error (0 for requests)
	buf.WriteByte(0)
	buf.WriteByte(0)

	// Other length (0 for requests)
	buf.WriteByte(0)
	buf.WriteByte(0)

	return buf.Bytes(), nil
}

// findTSIGRecord finds the TSIG record in a message's additional section
func findTSIGRecord(msg *protocol.Message) (*protocol.ResourceRecord, error) {
	for _, rr := range msg.Additionals {
		if rr.Type == protocol.TypeTSIG {
			return rr, nil
		}
	}
	return nil, fmt.Errorf("no TSIG record found")
}

// cloneMessageWithoutTSIG creates a copy of the message without TSIG records
func cloneMessageWithoutTSIG(msg *protocol.Message) *protocol.Message {
	clone := &protocol.Message{
		Header:      msg.Header,
		Questions:   msg.Questions,
		Answers:     msg.Answers,
		Authorities: msg.Authorities,
	}

	// Copy additionals except TSIG
	for _, rr := range msg.Additionals {
		if rr.Type != protocol.TypeTSIG {
			clone.Additionals = append(clone.Additionals, rr)
		}
	}

	return clone
}

// RDataTSIG represents TSIG record data
type RDataTSIG struct {
	Raw []byte // Wire format TSIG data
}

// Type implements protocol.RData
func (r *RDataTSIG) Type() uint16 {
	return protocol.TypeTSIG
}

// Pack implements protocol.RData
func (r *RDataTSIG) Pack(buf []byte, offset int) (int, error) {
	if len(buf) < offset+len(r.Raw) {
		return 0, fmt.Errorf("buffer too small for TSIG data")
	}
	copy(buf[offset:], r.Raw)
	return len(r.Raw), nil
}

// Unpack implements protocol.RData
func (r *RDataTSIG) Unpack(buf []byte, offset int, length uint16) (int, error) {
	if len(buf) < offset+int(length) {
		return 0, fmt.Errorf("buffer too small for TSIG data")
	}
	r.Raw = make([]byte, length)
	copy(r.Raw, buf[offset:offset+int(length)])
	return int(length), nil
}

// String implements protocol.RData
func (r *RDataTSIG) String() string {
	if len(r.Raw) == 0 {
		return "TSIG ()"
	}
	ts, _, err := UnpackTSIGRecord(r.Raw, 0)
	if err != nil {
		return fmt.Sprintf("TSIG (<invalid: %v>)", err)
	}
	return fmt.Sprintf("TSIG (%s %s fudge=%d error=%s)",
		ts.Algorithm,
		ts.TimeSigned.Format(time.RFC3339),
		ts.Fudge,
		TSIGErrorString(ts.Error),
	)
}

// Len returns the length of the TSIG data
func (r *RDataTSIG) Len() int {
	return len(r.Raw)
}

// Copy creates a deep copy of the TSIG data
func (r *RDataTSIG) Copy() protocol.RData {
	if r == nil {
		return nil
	}
	rawCopy := make([]byte, len(r.Raw))
	copy(rawCopy, r.Raw)
	return &RDataTSIG{Raw: rawCopy}
}
