package transfer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- HMAC-SHA1 required for TSIG algorithm hmac-sha1 (RFC 4635)
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

// Algorithm constants for TSIG
var tsigLogger = util.NewLogger(util.WARN, util.TextFormat, nil)

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

const (
	maxTSIGWireFieldLen = 0xffff
	maxTSIGTimeSigned   = 1<<48 - 1
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
	// AllowedCIDRs restricts which client IPs can use this key for AXFR/IXFR.
	// If empty, no IP restriction is applied (key can be used from any IP).
	// This prevents a key from being used by an unauthorized client if leaked.
	AllowedCIDRs []string // JSON/YAML: comma-separated CIDR notation
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

// KeyStore manages TSIG keys with support for key rotation.
// During rotation, both the old and new keys are valid, allowing
// seamless transitions without downtime.
type KeyStore struct {
	keys        map[string]*TSIGKey // keyed by key name
	previous    *TSIGKey            // previous key for rotation grace period
	rotatedAt   time.Time           // when the last rotation occurred
	gracePeriod time.Duration       // how long the previous key remains valid after rotation
	mu          sync.RWMutex
}

// NewKeyStore creates a new TSIG key store with default grace period of 5 minutes
func NewKeyStore() *KeyStore {
	return &KeyStore{
		keys:        make(map[string]*TSIGKey),
		gracePeriod: 5 * time.Minute,
	}
}

// NewKeyStoreWithGracePeriod creates a new TSIG key store with custom grace period
func NewKeyStoreWithGracePeriod(gracePeriod time.Duration) *KeyStore {
	return &KeyStore{
		keys:        make(map[string]*TSIGKey),
		gracePeriod: gracePeriod,
	}
}

// AddKey adds a key to the store
func (ks *KeyStore) AddKey(key *TSIGKey) {
	ks.mu.Lock()
	ks.keys[strings.ToLower(key.Name)] = key
	ks.mu.Unlock()
}

// GetKey retrieves a key by name
func (ks *KeyStore) GetKey(name string) (*TSIGKey, bool) {
	ks.mu.RLock()
	key, ok := ks.keys[strings.ToLower(name)]
	ks.mu.RUnlock()
	return key, ok
}

// RemoveKey removes a key from the store
func (ks *KeyStore) RemoveKey(name string) {
	ks.mu.Lock()
	delete(ks.keys, strings.ToLower(name))
	ks.mu.Unlock()
}

// HasKeys returns true if the store has at least one key configured
func (ks *KeyStore) HasKeys() bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return len(ks.keys) > 0
}

// ValidateKeySource checks if a client IP is allowed to use the named key.
// Returns nil if allowed, or an error describing the restriction.
// If the key has no AllowedCIDRs, the check is a no-op (IP is not restricted).
func (ks *KeyStore) ValidateKeySource(keyName string, clientIP net.IP) error {
	ks.mu.RLock()
	key, ok := ks.keys[strings.ToLower(keyName)]
	ks.mu.RUnlock()
	if !ok {
		return fmt.Errorf("TSIG key not found: %s", keyName)
	}
	if len(key.AllowedCIDRs) == 0 {
		return nil // No IP restriction on this key
	}
	// L-9: skip malformed CIDR entries instead of returning an error
	// outright. The earlier short-circuit silently dropped every key
	// whose AllowedCIDRs list contained a typo in any position — even
	// if the operator-intended CIDR was present and would have matched
	// the request. Log a warning per malformed entry so the misconfig
	// is visible, then fall through to the "no match" error below if
	// none of the valid CIDRs contained the client IP.
	matched := false
	for _, cidr := range key.AllowedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			util.Warnf("TSIG key %s AllowedCIDR %q is malformed (%v); skipping this entry", keyName, cidr, err)
			continue
		}
		if ipNet.Contains(clientIP) {
			matched = true
			break
		}
	}
	if matched {
		return nil
	}
	return fmt.Errorf("client IP %s not in TSIG key %s allowed list", clientIP, keyName)
}

// RotateKey replaces the current key with a new one, keeping the old key
// as the previous key for a grace period. This allows seamless key rotation
// where both keys are valid during the transition.
// After grace period, call ClearPreviousKey() to remove the old key.
func (ks *KeyStore) RotateKey(newKey *TSIGKey) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Save current key as previous
	oldKey, exists := ks.keys[strings.ToLower(newKey.Name)]
	if exists {
		ks.previous = oldKey
		ks.rotatedAt = time.Now()
	}

	// Add new key
	ks.keys[strings.ToLower(newKey.Name)] = newKey
}

// GetPreviousKey returns the previous key (if within grace period)
func (ks *KeyStore) GetPreviousKey(name string) *TSIGKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.previous == nil {
		return nil
	}

	if previousKeyExpiredAt(ks.rotatedAt, time.Now(), ks.gracePeriod) {
		return nil
	}

	// Only return previous key if it's the same name (same key being rotated)
	if ks.previous.Name == name {
		return ks.previous
	}
	return nil
}

func previousKeyExpiredAt(rotatedAt, now time.Time, gracePeriod time.Duration) bool {
	return !now.Before(rotatedAt.Add(gracePeriod))
}

// ClearPreviousKey removes the previous key after rotation grace period
func (ks *KeyStore) ClearPreviousKey() {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.previous = nil
}

// ReplaceKey atomically replaces a key by name
func (ks *KeyStore) ReplaceKey(name string, newKey *TSIGKey) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys[strings.ToLower(name)] = newKey
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
	if tsig == nil {
		return nil, fmt.Errorf("nil TSIG record")
	}
	if len(tsig.MAC) > maxTSIGWireFieldLen {
		return nil, fmt.Errorf("TSIG MAC too large: %d bytes", len(tsig.MAC))
	}
	if len(tsig.OtherData) > maxTSIGWireFieldLen {
		return nil, fmt.Errorf("TSIG other data too large: %d bytes", len(tsig.OtherData))
	}
	if int(tsig.OtherLen) != len(tsig.OtherData) {
		return nil, fmt.Errorf("TSIG other length mismatch: field=%d data=%d", tsig.OtherLen, len(tsig.OtherData))
	}

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
	timeSigned, err := encodeTSIGTimeSigned(tsig.TimeSigned)
	if err != nil {
		return nil, err
	}
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

func encodeTSIGTimeSigned(t time.Time) (uint64, error) {
	sec := t.Unix()
	if sec < 0 {
		return 0, fmt.Errorf("TSIG time signed %s before Unix epoch", t.UTC().Format(time.RFC3339))
	}
	if uint64(sec) > maxTSIGTimeSigned {
		return 0, fmt.Errorf("TSIG time signed %s exceeds 48-bit Unix time", t.UTC().Format(time.RFC3339))
	}
	return uint64(sec), nil
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
	timeSigned := uint64(data[n])<<40 | uint64(data[n+1])<<32 |
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
	signedData, err := buildSignedData(msg, key.Name, nil, key.Algorithm, timeSigned, fudge, msg.Header.ID)
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
	keyName, err := protocol.ParseName(key.Name)
	if err != nil {
		return nil, fmt.Errorf("invalid TSIG key name %q: %w", key.Name, err)
	}
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
// VerifyMessage verifies a TSIG-signed message using the current key.
// For key rotation scenarios, use VerifyMessageWithPrevious.
func VerifyMessage(msg *protocol.Message, key *TSIGKey, previousMAC []byte) error {
	return verifyWithKey(msg, key, previousMAC)
}

// VerifyMessageWithPrevious tries the current key first, then the previous key
// if the current key fails. This supports seamless key rotation.
func VerifyMessageWithPrevious(msg *protocol.Message, key *TSIGKey, previousKey *TSIGKey, previousMAC []byte) error {
	// Try current key first
	if err := verifyWithKey(msg, key, previousMAC); err == nil {
		return nil
	}

	// If previous key exists, try that too (key rotation scenario)
	if previousKey != nil {
		if err := verifyWithKey(msg, previousKey, previousMAC); err == nil {
			return nil
		}
	}

	return fmt.Errorf("TSIG verification failed with current and previous keys")
}

// tsigReplayWindow tracks the highest time_signed value ever accepted for
// each TSIG key name. The check below rejects time_signed values that fall
// further than one fudge window BEFORE the recorded high-water mark — i.e.
// strict replays of stale captures, including those within the current
// fudge window of "now". Concurrent multi-message AXFR streams remain
// usable because successive messages always carry a non-decreasing
// time_signed.
//
// Memory bound: an attacker could probe with an unbounded set of key
// names. We cap the map at a generous limit and evict in FIFO order on
// overflow (an attacker who manages to evict legitimate state has only
// regained the pre-fix behaviour — replay still requires a captured valid
// signed message).
var (
	tsigReplayMu        sync.Mutex
	tsigReplayHighWater = make(map[string]time.Time)
)

const tsigReplayKeyCap = 10000

// checkReplay returns an error if timeSigned is more than one fudge before
// the recorded high-water mark for keyName. On accept, updates the mark.
func checkReplay(keyName string, timeSigned time.Time, fudge time.Duration) error {
	tsigReplayMu.Lock()
	defer tsigReplayMu.Unlock()
	if prev, ok := tsigReplayHighWater[keyName]; ok {
		if timeSigned.Before(prev.Add(-fudge)) {
			return fmt.Errorf("TSIG replay: time_signed %s is more than fudge=%s before last-accepted %s for key %q",
				timeSigned.UTC().Format(time.RFC3339Nano), fudge, prev.UTC().Format(time.RFC3339Nano), keyName)
		}
		if timeSigned.After(prev) {
			tsigReplayHighWater[keyName] = timeSigned
		}
	} else {
		if len(tsigReplayHighWater) >= tsigReplayKeyCap {
			// FIFO eviction: drop a single arbitrary entry. Sets in Go
			// iterate in random order so this is effectively random eviction.
			for k := range tsigReplayHighWater {
				delete(tsigReplayHighWater, k)
				break
			}
		}
		tsigReplayHighWater[keyName] = timeSigned
	}
	return nil
}

// verifyWithKey performs the actual TSIG verification with a given key
func verifyWithKey(msg *protocol.Message, key *TSIGKey, previousMAC []byte) error {
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

	// Check algorithm matches. RFC 8945 §4.3.3 (referencing RFC 1035 §2.3.3)
	// makes the algorithm a DNS name, which is case-insensitive. A peer
	// sending "HMAC-SHA256." with our configured "hmac-sha256" otherwise
	// fails this strict equality check before we even attempt the MAC,
	// which the cryptographic verification would have accepted because
	// PackName canonicalizes to lowercase when building the signed-data.
	if !strings.EqualFold(tsigs.Algorithm, key.Algorithm) {
		return fmt.Errorf("algorithm mismatch: got %s, expected %s", tsigs.Algorithm, key.Algorithm)
	}

	// Check time
	now := time.Now().UTC()
	fudge := time.Duration(tsigs.Fudge) * time.Second
	if now.Before(tsigs.TimeSigned.Add(-fudge)) || now.After(tsigs.TimeSigned.Add(fudge)) {
		return fmt.Errorf("TSIG time out of range")
	}

	// Build signed data
	signedData, err := buildSignedData(msg, key.Name, previousMAC, key.Algorithm, tsigs.TimeSigned, tsigs.Fudge, tsigs.OriginalID)
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

	// RFC 8945 anti-replay: now that the MAC has authenticated the message,
	// check the time_signed against the per-key high-water mark. Stale
	// captured-and-replayed messages are rejected here even if they fall
	// within the fudge window of "now".
	if err := checkReplay(key.Name, tsigs.TimeSigned, fudge); err != nil {
		return err
	}

	return nil
}

// calculateMAC calculates HMAC for given data and algorithm
func calculateMAC(key, data []byte, algorithm string) ([]byte, error) {
	var mac []byte

	switch strings.ToLower(algorithm) {
	case HmacMD5:
		return nil, fmt.Errorf("HMAC-MD5 is no longer supported for TSIG (cryptographically broken). Use hmac-sha256 or hmac-sha512")
	case HmacSHA1:
		// SHA-1 is deprecated, log warning but support for compatibility
		tsigLogger.Warnf("HMAC-SHA1 is deprecated for TSIG. Consider using SHA-256 or SHA-512.")
		h := hmac.New(sha1.New, key) // #nosec G401,G505 -- hmac-sha1 TSIG algorithm, RFC 4635
		h.Write(data)
		mac = h.Sum(nil)
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
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	return mac, nil
}

// buildSignedData builds the data to be digested by HMAC per RFC 8945 §5.3.2.
//
// Layout (concatenated, network byte order):
//
//	(optional) previous-message MAC, length-prefixed per §5.3.2.1 for multi-
//	    message transfers (TCP AXFR). For single messages or the first message
//	    of a chain, pass nil/empty.
//	DNS message (with the TSIG RR removed AND ARCOUNT decremented).
//	TSIG RR variables:
//	    KEY_NAME (canonical wire form, lowercased, no compression)
//	    CLASS    (uint16 = 255, ANY)
//	    TTL      (uint32 = 0)
//	    ALGORITHM (canonical wire form, lowercased, no compression)
//	    TIME_SIGNED (uint48)
//	    FUDGE       (uint16)
//	    ERROR       (uint16)
//	    OTHER_LEN   (uint16)
//	    OTHER_DATA  (OTHER_LEN bytes)
//
// keyName must be the same on-wire owner name that appears on the TSIG RR;
// both signer and verifier must lowercase it identically for the MAC to match
// across implementations (BIND/Knot/NSD).
func buildSignedData(msg *protocol.Message, keyName string, previousMAC []byte, algorithm string, timeSigned time.Time, fudge uint16, originalID uint16) ([]byte, error) {
	var buf bytes.Buffer

	// Previous MAC (multi-message TCP AXFR sequence per RFC 8945 §5.3.2.1).
	// Length-prefixed: uint16 length followed by the MAC bytes.
	if len(previousMAC) > 0 {
		buf.WriteByte(byte(len(previousMAC) >> 8))
		buf.WriteByte(byte(len(previousMAC)))
		buf.Write(previousMAC)
	}

	// Message bytes with the TSIG RR removed and ARCOUNT adjusted to match
	// the now-shorter Additionals slice (handled by cloneMessageWithoutTSIG).
	msgCopy := cloneMessageWithoutTSIG(msg)
	msgBytes := make([]byte, 65535)
	n, err := msgCopy.Pack(msgBytes)
	if err != nil {
		return nil, fmt.Errorf("packing message: %w", err)
	}
	buf.Write(msgBytes[:n])

	// TSIG RR variables: KEY_NAME (canonical wire form, no compression).
	keyNameParsed, err := protocol.ParseName(keyName)
	if err != nil {
		return nil, fmt.Errorf("invalid TSIG key name %q: %w", keyName, err)
	}
	keyNameBytes := make([]byte, 256)
	keyNameLen, err := protocol.PackName(keyNameParsed, keyNameBytes, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("packing TSIG key name: %w", err)
	}
	buf.Write(keyNameBytes[:keyNameLen])

	// CLASS (uint16 = ClassANY)
	buf.WriteByte(byte(protocol.ClassANY >> 8))
	buf.WriteByte(byte(protocol.ClassANY))

	// TTL (uint32 = 0)
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0)

	// Algorithm name (canonical wire form, no compression).
	algoName, err := protocol.ParseName(algorithm)
	if err != nil {
		return nil, fmt.Errorf("invalid TSIG algorithm name %q: %w", algorithm, err)
	}
	algoBytes := make([]byte, 256)
	algoLen, err := protocol.PackName(algoName, algoBytes, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("packing TSIG algorithm name: %w", err)
	}
	buf.Write(algoBytes[:algoLen])

	// Time signed (48 bits, big-endian)
	timeUnix, err := encodeTSIGTimeSigned(timeSigned)
	if err != nil {
		return nil, err
	}
	buf.WriteByte(byte(timeUnix >> 40))
	buf.WriteByte(byte(timeUnix >> 32))
	buf.WriteByte(byte(timeUnix >> 24))
	buf.WriteByte(byte(timeUnix >> 16))
	buf.WriteByte(byte(timeUnix >> 8))
	buf.WriteByte(byte(timeUnix))

	// Fudge (uint16)
	buf.WriteByte(byte(fudge >> 8))
	buf.WriteByte(byte(fudge))

	// Error (uint16 = 0 for non-error)
	buf.WriteByte(0)
	buf.WriteByte(0)

	// Other length (uint16 = 0) + Other data (empty)
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

// cloneMessageWithoutTSIG creates a copy of the message with TSIG records
// removed AND the header's ARCOUNT updated to reflect the new additionals
// section length. RFC 8945 §5.3.2 requires the digested message to have
// ARCOUNT decremented when the TSIG RR is stripped — leaving the original
// value would produce a wrong MAC and break interop with BIND/Knot/NSD.
func cloneMessageWithoutTSIG(msg *protocol.Message) *protocol.Message {
	clone := &protocol.Message{
		Header:      msg.Header, // value copy, safe to mutate ARCount below
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

	// Header.ARCount is the wire-format count for the additional section; it
	// must match len(clone.Additionals) after stripping TSIG, otherwise the
	// packed bytes have an inconsistent count and the digest is computed
	// against malformed input.
	clone.Header.ARCount = uint16(len(clone.Additionals))

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
