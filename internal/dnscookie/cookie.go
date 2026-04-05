// Package dnscookie implements DNS Cookies per RFC 7873.
//
// DNS Cookies provide lightweight mutual authentication between DNS clients
// and servers, protecting against off-path spoofing and amplification attacks.
//
// A client sends an 8-byte client cookie derived from client IP, server IP,
// and a secret. The server responds with the client cookie plus a server
// cookie (8-32 bytes). Subsequent queries include both cookies so the server
// can validate the client without heavyweight cryptographic handshakes.
package dnscookie

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Cookie size constraints per RFC 7873.
const (
	// ClientCookieLen is the fixed size of a client cookie (8 bytes).
	ClientCookieLen = 8
	// MinServerCookieLen is the minimum server cookie size (8 bytes).
	MinServerCookieLen = 8
	// MaxServerCookieLen is the maximum server cookie size (32 bytes).
	MaxServerCookieLen = 32
	// InteropServerCookieLen is the RFC 7873 interoperable server cookie size (16 bytes).
	InteropServerCookieLen = 16

	// serverCookieVersion is the version byte for interoperable server cookies.
	serverCookieVersion = 1

	// secretLen is the size of the server secret used for HMAC (16 bytes).
	secretLen = 16
)

// Errors returned by cookie operations.
var (
	ErrCookieTooShort  = errors.New("dnscookie: option data too short (< 8 bytes)")
	ErrCookieTooLong   = errors.New("dnscookie: option data too long (> 40 bytes)")
	ErrServerCookieLen = errors.New("dnscookie: server cookie must be 8-32 bytes")
)

// ServerSecret is a 16-byte secret used for HMAC-based cookie generation.
type ServerSecret [secretLen]byte

// Cookie represents a parsed DNS Cookie option from an EDNS0 OPT record.
type Cookie struct {
	// ClientCookie is the 8-byte client cookie, always present.
	ClientCookie [ClientCookieLen]byte
	// ServerCookie is the 8-32 byte server cookie, may be nil for first queries.
	ServerCookie []byte
}

// CookieJar manages server secrets with periodic rotation, allowing
// generation and validation of DNS cookies. It is safe for concurrent use.
type CookieJar struct {
	mu               sync.RWMutex
	current          ServerSecret
	previous         ServerSecret
	hasPrevious      bool
	rotationInterval time.Duration
	lastRotation     time.Time
}

// NewCookieJar creates a new CookieJar with a random initial secret and the
// given rotation interval. The jar automatically rotates secrets when
// GenerateServerCookie detects the interval has elapsed.
func NewCookieJar(rotationInterval time.Duration) *CookieJar {
	jar := &CookieJar{
		rotationInterval: rotationInterval,
		lastRotation:     time.Now(),
	}
	if _, err := io.ReadFull(rand.Reader, jar.current[:]); err != nil {
		panic("dnscookie: failed to generate initial secret: " + err.Error())
	}
	return jar
}

// GenerateClientCookie produces an 8-byte client cookie by computing
// HMAC-SHA256(clientIP || serverIP || secret) and truncating to 8 bytes.
func (j *CookieJar) GenerateClientCookie(clientIP, serverIP net.IP) [ClientCookieLen]byte {
	j.mu.RLock()
	secret := j.current
	j.mu.RUnlock()

	return computeClientCookie(clientIP, serverIP, secret)
}

// GenerateServerCookie produces a 16-byte interoperable server cookie
// per the RFC 7873 format:
//
//	Byte  0   : version (1)
//	Bytes 1-3 : reserved (0)
//	Bytes 4-7 : Unix timestamp (big-endian, seconds)
//	Bytes 8-15: HMAC-SHA256(clientCookie || clientIP || timestamp || secret) truncated to 8 bytes
//
// This method automatically triggers secret rotation when the rotation
// interval has elapsed.
func (j *CookieJar) GenerateServerCookie(clientCookie [ClientCookieLen]byte, clientIP net.IP) []byte {
	j.maybeRotate()

	j.mu.RLock()
	secret := j.current
	j.mu.RUnlock()

	now := uint32(time.Now().Unix())
	return buildServerCookie(clientCookie, clientIP, now, secret)
}

// ValidateServerCookie checks whether a server cookie is valid. It extracts
// the embedded timestamp, verifies it is within 2x the rotation interval,
// and recomputes the HMAC against both the current and previous secrets.
func (j *CookieJar) ValidateServerCookie(clientCookie [ClientCookieLen]byte, serverCookie []byte, clientIP net.IP) bool {
	if len(serverCookie) != InteropServerCookieLen {
		return false
	}

	// Check version byte.
	if serverCookie[0] != serverCookieVersion {
		return false
	}

	// Extract timestamp (bytes 4-7, big-endian).
	ts := binary.BigEndian.Uint32(serverCookie[4:8])

	// Check freshness: timestamp must be within 2x rotation interval.
	now := uint32(time.Now().Unix())
	maxAge := uint32(j.rotationInterval.Seconds() * 2)
	if maxAge == 0 {
		maxAge = 1
	}
	// Handle time going backwards gracefully.
	if now > ts && (now-ts) > maxAge {
		return false
	}
	// Reject cookies from the future (with 1-second tolerance for clock skew).
	if ts > now && (ts-now) > 1 {
		return false
	}

	j.mu.RLock()
	current := j.current
	previous := j.previous
	hasPrev := j.hasPrevious
	j.mu.RUnlock()

	// Try current secret.
	expected := buildServerCookie(clientCookie, clientIP, ts, current)
	if hmac.Equal(serverCookie, expected) {
		return true
	}

	// Try previous secret (covers the rotation grace period).
	if hasPrev {
		expected = buildServerCookie(clientCookie, clientIP, ts, previous)
		return hmac.Equal(serverCookie, expected)
	}

	return false
}

// RotateSecret moves the current secret to previous and generates a fresh
// random secret as the new current. Cookies generated with the previous
// secret remain valid during the grace period.
func (j *CookieJar) RotateSecret() {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.previous = j.current
	j.hasPrevious = true
	if _, err := io.ReadFull(rand.Reader, j.current[:]); err != nil {
		panic("dnscookie: failed to generate rotated secret: " + err.Error())
	}
	j.lastRotation = time.Now()
}

// maybeRotate checks whether the rotation interval has elapsed and
// rotates if needed.
func (j *CookieJar) maybeRotate() {
	j.mu.RLock()
	needsRotation := time.Since(j.lastRotation) >= j.rotationInterval
	j.mu.RUnlock()

	if needsRotation {
		j.RotateSecret()
	}
}

// ParseCookieOption parses the raw EDNS0 option data into a Cookie.
// The first 8 bytes are the client cookie; the remaining 0-32 bytes
// are the server cookie. A total length < 8 or > 40 is an error.
func ParseCookieOption(data []byte) (*Cookie, error) {
	if len(data) < ClientCookieLen {
		return nil, ErrCookieTooShort
	}
	if len(data) > ClientCookieLen+MaxServerCookieLen {
		return nil, ErrCookieTooLong
	}

	c := &Cookie{}
	copy(c.ClientCookie[:], data[:ClientCookieLen])

	if len(data) > ClientCookieLen {
		serverLen := len(data) - ClientCookieLen
		if serverLen < MinServerCookieLen || serverLen > MaxServerCookieLen {
			return nil, fmt.Errorf("dnscookie: invalid server cookie length %d (must be %d-%d)",
				serverLen, MinServerCookieLen, MaxServerCookieLen)
		}
		c.ServerCookie = make([]byte, serverLen)
		copy(c.ServerCookie, data[ClientCookieLen:])
	}

	return c, nil
}

// PackCookieOption serializes a client cookie and optional server cookie
// into the wire format suitable for an EDNS0 option.
func PackCookieOption(clientCookie [ClientCookieLen]byte, serverCookie []byte) []byte {
	out := make([]byte, ClientCookieLen+len(serverCookie))
	copy(out[:ClientCookieLen], clientCookie[:])
	if len(serverCookie) > 0 {
		copy(out[ClientCookieLen:], serverCookie)
	}
	return out
}

// ============================================================================
// Internal helpers
// ============================================================================

// computeClientCookie produces an 8-byte client cookie via HMAC-SHA256.
func computeClientCookie(clientIP, serverIP net.IP, secret ServerSecret) [ClientCookieLen]byte {
	mac := hmac.New(sha256.New, secret[:])
	mac.Write(normalizeIP(clientIP))
	mac.Write(normalizeIP(serverIP))
	sum := mac.Sum(nil) // 32 bytes

	var cookie [ClientCookieLen]byte
	copy(cookie[:], sum[:ClientCookieLen])
	return cookie
}

// buildServerCookie constructs the 16-byte interoperable server cookie.
func buildServerCookie(clientCookie [ClientCookieLen]byte, clientIP net.IP, ts uint32, secret ServerSecret) []byte {
	cookie := make([]byte, InteropServerCookieLen)

	// Version (1 byte) + reserved (3 bytes).
	cookie[0] = serverCookieVersion
	cookie[1] = 0
	cookie[2] = 0
	cookie[3] = 0

	// Timestamp (4 bytes, big-endian).
	binary.BigEndian.PutUint32(cookie[4:8], ts)

	// HMAC-SHA256(clientCookie || clientIP || timestamp || secret) truncated to 8 bytes.
	mac := hmac.New(sha256.New, secret[:])
	mac.Write(clientCookie[:])
	mac.Write(normalizeIP(clientIP))

	var tsBuf [4]byte
	binary.BigEndian.PutUint32(tsBuf[:], ts)
	mac.Write(tsBuf[:])

	sum := mac.Sum(nil)
	copy(cookie[8:], sum[:8])

	return cookie
}

// normalizeIP returns a consistent byte representation of an IP address.
// IPv4 addresses are returned as 4 bytes; IPv6 as 16 bytes.
func normalizeIP(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}
