package dnscookie

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func TestNewCookieJar(t *testing.T) {
	jar, err := NewCookieJar(1 * time.Hour)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}
	if jar == nil {
		t.Fatal("NewCookieJar returned nil")
	}

	// Secret must not be all zeros.
	var zero ServerSecret
	if jar.current == zero {
		t.Error("initial secret is all zeros")
	}

	// Previous should not be set yet.
	if jar.hasPrevious {
		t.Error("new jar should not have a previous secret")
	}
}

func TestGenerateClientCookie(t *testing.T) {
	jar, err := NewCookieJar(1 * time.Hour)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1")
	serverIP := net.ParseIP("198.51.100.1")

	// Same inputs must produce the same cookie.
	c1 := jar.GenerateClientCookie(clientIP, serverIP)
	c2 := jar.GenerateClientCookie(clientIP, serverIP)
	if c1 != c2 {
		t.Error("same inputs produced different client cookies")
	}

	// Different client IP must produce a different cookie.
	otherClient := net.ParseIP("192.0.2.99")
	c3 := jar.GenerateClientCookie(otherClient, serverIP)
	if c1 == c3 {
		t.Error("different client IPs produced the same cookie")
	}

	// Different server IP must produce a different cookie.
	otherServer := net.ParseIP("198.51.100.99")
	c4 := jar.GenerateClientCookie(clientIP, otherServer)
	if c1 == c4 {
		t.Error("different server IPs produced the same cookie")
	}

	// IPv6 addresses should work too.
	clientIPv6 := net.ParseIP("2001:db8::1")
	serverIPv6 := net.ParseIP("2001:db8::2")
	c5 := jar.GenerateClientCookie(clientIPv6, serverIPv6)
	c6 := jar.GenerateClientCookie(clientIPv6, serverIPv6)
	if c5 != c6 {
		t.Error("same IPv6 inputs produced different cookies")
	}
	if c5 == c1 {
		t.Error("IPv4 and IPv6 produced the same cookie (extremely unlikely)")
	}
}

func TestGenerateServerCookie(t *testing.T) {
	jar, err := NewCookieJar(1 * time.Hour)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1")
	var clientCookie [ClientCookieLen]byte
	copy(clientCookie[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})

	sc := jar.GenerateServerCookie(clientCookie, clientIP)

	// Must be exactly 16 bytes (interoperable format).
	if len(sc) != InteropServerCookieLen {
		t.Fatalf("server cookie length = %d, want %d", len(sc), InteropServerCookieLen)
	}

	// Version byte must be 1.
	if sc[0] != serverCookieVersion {
		t.Errorf("version byte = %d, want %d", sc[0], serverCookieVersion)
	}

	// Reserved bytes must be 0.
	if sc[1] != 0 || sc[2] != 0 || sc[3] != 0 {
		t.Errorf("reserved bytes = [%d,%d,%d], want [0,0,0]", sc[1], sc[2], sc[3])
	}

	// Timestamp must be recent (within 2 seconds of now).
	ts := binary.BigEndian.Uint32(sc[4:8])
	now := uint32(time.Now().Unix())
	if now < ts || (now-ts) > 2 {
		t.Errorf("timestamp %d not close to now %d", ts, now)
	}
}

func TestValidateServerCookie(t *testing.T) {
	jar, err := NewCookieJar(1 * time.Hour)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}
	clientIP := net.ParseIP("192.0.2.1")
	clientCookie := jar.GenerateClientCookie(clientIP, net.ParseIP("198.51.100.1"))

	// Generate and immediately validate.
	sc := jar.GenerateServerCookie(clientCookie, clientIP)
	if !jar.ValidateServerCookie(clientCookie, sc, clientIP) {
		t.Error("freshly generated server cookie failed validation")
	}

	// Tampered cookie must fail.
	tampered := make([]byte, len(sc))
	copy(tampered, sc)
	tampered[15] ^= 0xFF
	if jar.ValidateServerCookie(clientCookie, tampered, clientIP) {
		t.Error("tampered server cookie passed validation")
	}

	// Wrong client IP must fail.
	wrongIP := net.ParseIP("10.0.0.1")
	if jar.ValidateServerCookie(clientCookie, sc, wrongIP) {
		t.Error("server cookie validated with wrong client IP")
	}

	// Wrong client cookie must fail.
	var wrongCC [ClientCookieLen]byte
	copy(wrongCC[:], []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8})
	if jar.ValidateServerCookie(wrongCC, sc, clientIP) {
		t.Error("server cookie validated with wrong client cookie")
	}

	// Wrong version byte must fail.
	badVersion := make([]byte, len(sc))
	copy(badVersion, sc)
	badVersion[0] = 99
	if jar.ValidateServerCookie(clientCookie, badVersion, clientIP) {
		t.Error("server cookie with wrong version passed validation")
	}

	// Wrong length must fail.
	if jar.ValidateServerCookie(clientCookie, sc[:8], clientIP) {
		t.Error("8-byte server cookie passed validation (expected 16)")
	}
	if jar.ValidateServerCookie(clientCookie, nil, clientIP) {
		t.Error("nil server cookie passed validation")
	}
}

func TestValidateServerCookieExpired(t *testing.T) {
	// Use a short rotation interval so we can create an "expired" cookie.
	jar, err := NewCookieJar(1 * time.Second)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}
	clientIP := net.ParseIP("192.0.2.1")
	var clientCookie [ClientCookieLen]byte
	copy(clientCookie[:], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22})

	// Build a server cookie with a timestamp far in the past.
	jar.mu.RLock()
	secret := jar.current
	jar.mu.RUnlock()

	oldTS := uint32(time.Now().Unix()) - 100 // 100 seconds ago
	expired := buildServerCookie(clientCookie, clientIP, oldTS, secret)

	if jar.ValidateServerCookie(clientCookie, expired, clientIP) {
		t.Error("expired server cookie passed validation")
	}
}

func TestSecretRotation(t *testing.T) {
	jar, err := NewCookieJar(1 * time.Hour)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}
	clientIP := net.ParseIP("192.0.2.1")
	clientCookie := jar.GenerateClientCookie(clientIP, net.ParseIP("198.51.100.1"))

	// Generate a cookie with the current secret.
	sc := jar.GenerateServerCookie(clientCookie, clientIP)

	// Rotate the secret.
	if err := jar.RotateSecret(); err != nil {
		t.Fatalf("RotateSecret failed: %v", err)
	}

	// The old cookie must still validate via the previous secret.
	if !jar.ValidateServerCookie(clientCookie, sc, clientIP) {
		t.Error("cookie from before rotation failed validation (previous secret should work)")
	}

	// New cookies must also work.
	sc2 := jar.GenerateServerCookie(clientCookie, clientIP)
	if !jar.ValidateServerCookie(clientCookie, sc2, clientIP) {
		t.Error("cookie after rotation failed validation")
	}

	// Rotate a second time: the original secret is now gone.
	if err := jar.RotateSecret(); err != nil {
		t.Fatalf("RotateSecret failed: %v", err)
	}

	// The second cookie (from the first rotation) should still work.
	if !jar.ValidateServerCookie(clientCookie, sc2, clientIP) {
		t.Error("cookie from first rotation failed after second rotation")
	}

	// The very first cookie should no longer validate (its secret is gone).
	// This depends on the timestamp still being fresh enough, so we build
	// a cookie manually with the original secret to isolate the test.
	jar.mu.RLock()
	currentSec := jar.current
	prevSec := jar.previous
	jar.mu.RUnlock()

	// Forge a cookie with a secret that is neither current nor previous.
	var oldSecret ServerSecret
	copy(oldSecret[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10})
	// Ensure our test secret is different from both current and previous.
	if oldSecret == currentSec || oldSecret == prevSec {
		t.Skip("test secret collides with jar secrets (astronomically unlikely)")
	}
	ts := uint32(time.Now().Unix())
	forged := buildServerCookie(clientCookie, clientIP, ts, oldSecret)
	if jar.ValidateServerCookie(clientCookie, forged, clientIP) {
		t.Error("cookie from unknown secret passed validation")
	}
}

func TestParseCookieOption(t *testing.T) {
	// Client-only cookie (8 bytes).
	clientOnly := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	c, err := ParseCookieOption(clientOnly)
	if err != nil {
		t.Fatalf("parse client-only: %v", err)
	}
	if c.ServerCookie != nil {
		t.Error("expected nil server cookie for client-only option")
	}
	var expectedCC [ClientCookieLen]byte
	copy(expectedCC[:], clientOnly)
	if c.ClientCookie != expectedCC {
		t.Error("client cookie mismatch")
	}

	// Client + server cookie (8 + 16 = 24 bytes).
	serverPart := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	full := append(clientOnly, serverPart...)
	c, err = ParseCookieOption(full)
	if err != nil {
		t.Fatalf("parse client+server: %v", err)
	}
	if len(c.ServerCookie) != 16 {
		t.Fatalf("server cookie length = %d, want 16", len(c.ServerCookie))
	}
	if !bytes.Equal(c.ServerCookie, serverPart) {
		t.Error("server cookie data mismatch")
	}

	// Too short (< 8 bytes).
	_, err = ParseCookieOption([]byte{0x01, 0x02, 0x03})
	if err != ErrCookieTooShort {
		t.Errorf("expected ErrCookieTooShort, got %v", err)
	}

	// Too long (> 40 bytes).
	tooLong := make([]byte, 41)
	_, err = ParseCookieOption(tooLong)
	if err != ErrCookieTooLong {
		t.Errorf("expected ErrCookieTooLong, got %v", err)
	}

	// Invalid server cookie length (8 + 5 = 13 bytes; 5 is < MinServerCookieLen).
	badLen := make([]byte, 13)
	_, err = ParseCookieOption(badLen)
	if err == nil {
		t.Error("expected error for server cookie length 5, got nil")
	}
}

func TestPackCookieOption(t *testing.T) {
	var cc [ClientCookieLen]byte
	copy(cc[:], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22})

	// Client only.
	packed := PackCookieOption(cc, nil)
	if len(packed) != ClientCookieLen {
		t.Fatalf("packed client-only length = %d, want %d", len(packed), ClientCookieLen)
	}

	parsed, err := ParseCookieOption(packed)
	if err != nil {
		t.Fatalf("round-trip parse (client-only): %v", err)
	}
	if parsed.ClientCookie != cc {
		t.Error("round-trip client cookie mismatch")
	}
	if parsed.ServerCookie != nil {
		t.Error("round-trip: expected nil server cookie")
	}

	// Client + server.
	sc := []byte{0x01, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
		0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	packed = PackCookieOption(cc, sc)
	if len(packed) != ClientCookieLen+len(sc) {
		t.Fatalf("packed length = %d, want %d", len(packed), ClientCookieLen+len(sc))
	}

	parsed, err = ParseCookieOption(packed)
	if err != nil {
		t.Fatalf("round-trip parse (client+server): %v", err)
	}
	if parsed.ClientCookie != cc {
		t.Error("round-trip client cookie mismatch (with server)")
	}
	if !bytes.Equal(parsed.ServerCookie, sc) {
		t.Error("round-trip server cookie mismatch")
	}
}

func TestAutoRotation(t *testing.T) {
	// Use a very short rotation interval.
	jar, err := NewCookieJar(1 * time.Millisecond)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}

	// Record the initial secret.
	jar.mu.RLock()
	initial := jar.current
	jar.mu.RUnlock()

	// Sleep long enough for rotation to trigger.
	time.Sleep(5 * time.Millisecond)

	// GenerateServerCookie triggers maybeRotate.
	clientIP := net.ParseIP("192.0.2.1")
	var cc [ClientCookieLen]byte
	jar.GenerateServerCookie(cc, clientIP)

	jar.mu.RLock()
	after := jar.current
	hasPrev := jar.hasPrevious
	prev := jar.previous
	jar.mu.RUnlock()

	if after == initial {
		t.Error("secret was not rotated after interval elapsed")
	}
	if !hasPrev {
		t.Error("hasPrevious should be true after rotation")
	}
	if prev != initial {
		t.Error("previous secret should equal the initial secret")
	}
}

func TestConcurrentAccess(t *testing.T) {
	jar, err := NewCookieJar(50 * time.Millisecond)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}
	clientIP := net.ParseIP("192.0.2.1")
	serverIP := net.ParseIP("198.51.100.1")

	done := make(chan struct{})
	const goroutines = 10
	const iterations = 100

	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < iterations; j++ {
				cc := jar.GenerateClientCookie(clientIP, serverIP)
				sc := jar.GenerateServerCookie(cc, clientIP)
				// We don't assert validity here because rotation may
				// happen between generate and validate; we just ensure
				// no panics or data races.
				jar.ValidateServerCookie(cc, sc, clientIP)
			}
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// TestClientCookieEdgeCases tests client cookie generation edge cases
func TestClientCookieEdgeCases(t *testing.T) {
	jar, err := NewCookieJar(1 * time.Hour)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}

	tests := []struct {
		name      string
		clientIP  net.IP
		serverIP  net.IP
		shouldGen bool
	}{
		{"nil_client_ip", nil, net.ParseIP("198.51.100.1"), true},
		{"nil_server_ip", net.ParseIP("192.0.2.1"), nil, true},
		{"both_nil", nil, nil, true},
		{"ipv4", net.ParseIP("192.0.2.1"), net.ParseIP("198.51.100.1"), true},
		{"ipv6", net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), true},
		{"ipv4_mapped_ipv6", net.ParseIP("::ffff:192.0.2.1"), net.ParseIP("::ffff:198.51.100.1"), true},
		{"loopback_v4", net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.1"), true},
		{"loopback_v6", net.ParseIP("::1"), net.ParseIP("::1"), true},
		{"broadcast", net.ParseIP("255.255.255.255"), net.ParseIP("192.0.2.1"), true},
		{"multicast", net.ParseIP("224.0.0.1"), net.ParseIP("192.0.2.1"), true},
		{"link_local", net.ParseIP("169.254.1.1"), net.ParseIP("192.0.2.1"), true},
		{"private_range_10", net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), true},
		{"private_range_172", net.ParseIP("172.16.0.1"), net.ParseIP("172.16.0.2"), true},
		{"private_range_192", net.ParseIP("192.168.0.1"), net.ParseIP("192.168.0.2"), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cc := jar.GenerateClientCookie(tc.clientIP, tc.serverIP)
			// Just ensure it doesn't panic and produces valid length
			if len(cc) != ClientCookieLen {
				t.Errorf("client cookie length = %d, want %d", len(cc), ClientCookieLen)
			}
		})
	}
}

// TestClientCookieDeterminism tests that same inputs always produce same output
func TestClientCookieDeterminism(t *testing.T) {
	jar, err := NewCookieJar(1 * time.Hour)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1")
	serverIP := net.ParseIP("198.51.100.1")

	// Generate multiple cookies with same inputs
	cookies := make(map[[ClientCookieLen]byte]int)
	for i := 0; i < 100; i++ {
		cc := jar.GenerateClientCookie(clientIP, serverIP)
		cookies[cc]++
	}

	// All should be identical
	if len(cookies) != 1 {
		t.Errorf("expected 1 unique cookie, got %d", len(cookies))
	}
}

// TestServerCookieStructure tests server cookie byte structure
func TestServerCookieStructure(t *testing.T) {
	jar, err := NewCookieJar(1 * time.Hour)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1")
	clientCookie := jar.GenerateClientCookie(clientIP, net.ParseIP("198.51.100.1"))

	sc := jar.GenerateServerCookie(clientCookie, clientIP)

	// Check structure
	if len(sc) != InteropServerCookieLen {
		t.Fatalf("server cookie length = %d, want %d", len(sc), InteropServerCookieLen)
	}

	// Version byte
	if sc[0] != serverCookieVersion {
		t.Errorf("version byte = %d, want %d", sc[0], serverCookieVersion)
	}

	// Reserved bytes must be 0
	if sc[1] != 0 || sc[2] != 0 || sc[3] != 0 {
		t.Errorf("reserved bytes not zero: [%d,%d,%d]", sc[1], sc[2], sc[3])
	}

	// Timestamp should be valid (not zero, not max)
	ts := binary.BigEndian.Uint32(sc[4:8])
	if ts == 0 {
		t.Error("timestamp is zero")
	}
	now := uint32(time.Now().Unix())
	if ts > now+60 {
		t.Errorf("timestamp %d is in the future (now: %d)", ts, now)
	}
	if ts < now-60 {
		t.Errorf("timestamp %d is too old (now: %d)", ts, now)
	}

	// Hash portion (8 bytes) should not be all zeros (unlikely but possible)
	hash := sc[8:16]
	allZero := true
	for _, b := range hash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Log("warning: hash is all zeros (statistically unlikely)")
	}
}

// TestServerCookieTampering tests various tampering scenarios
func TestServerCookieTampering(t *testing.T) {
	jar, err := NewCookieJar(1 * time.Hour)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1")
	clientCookie := jar.GenerateClientCookie(clientIP, net.ParseIP("198.51.100.1"))
	sc := jar.GenerateServerCookie(clientCookie, clientIP)

	tests := []struct {
		name     string
		modify   func([]byte) []byte
		expected bool
	}{
		{
			"original",
			func(b []byte) []byte { return b },
			true,
		},
		{
			"flip_version_byte",
			func(b []byte) []byte {
				c := make([]byte, len(b))
				copy(c, b)
				c[0] = 99
				return c
			},
			false,
		},
		{
			"flip_reserved_byte",
			func(b []byte) []byte {
				c := make([]byte, len(b))
				copy(c, b)
				c[1] = 1
				return c
			},
			false,
		},
		{
			"modify_timestamp",
			func(b []byte) []byte {
				c := make([]byte, len(b))
				copy(c, b)
				c[4] ^= 0xFF
				return c
			},
			false,
		},
		{
			"modify_hash_byte_0",
			func(b []byte) []byte {
				c := make([]byte, len(b))
				copy(c, b)
				c[8] ^= 0xFF
				return c
			},
			false,
		},
		{
			"modify_hash_byte_7",
			func(b []byte) []byte {
				c := make([]byte, len(b))
				copy(c, b)
				c[15] ^= 0xFF
				return c
			},
			false,
		},
		{
			"all_zeros",
			func(b []byte) []byte {
				return make([]byte, len(b))
			},
			false,
		},
		{
			"all_ones",
			func(b []byte) []byte {
				c := make([]byte, len(b))
				for i := range c {
					c[i] = 0xFF
				}
				return c
			},
			false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			modified := tc.modify(sc)
			valid := jar.ValidateServerCookie(clientCookie, modified, clientIP)
			if valid != tc.expected {
				t.Errorf("validation = %v, want %v", valid, tc.expected)
			}
		})
	}
}

// TestServerCookieWrongClientIP tests validation with wrong client IP
func TestServerCookieWrongClientIP(t *testing.T) {
	jar, err := NewCookieJar(1 * time.Hour)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1")
	clientCookie := jar.GenerateClientCookie(clientIP, net.ParseIP("198.51.100.1"))
	sc := jar.GenerateServerCookie(clientCookie, clientIP)

	testCases := []struct {
		name string
		ip   net.IP
	}{
		{"different_v4", net.ParseIP("192.0.2.2")},
		{"different_subnet", net.ParseIP("10.0.0.1")},
		{"loopback", net.ParseIP("127.0.0.1")},
		{"ipv6", net.ParseIP("2001:db8::1")},
		{"nil", nil},
		{"empty", net.IP{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if jar.ValidateServerCookie(clientCookie, sc, tc.ip) {
				t.Error("should not validate with wrong client IP")
			}
		})
	}
}

// TestServerCookieExpirationBoundaries tests expiration at boundaries
func TestServerCookieExpirationBoundaries(t *testing.T) {
	// Use a 1-second rotation interval
	jar, err := NewCookieJar(1 * time.Second)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1")
	var clientCookie [ClientCookieLen]byte
	copy(clientCookie[:], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22})

	// Get current secret
	jar.mu.RLock()
	secret := jar.current
	jar.mu.RUnlock()

	tests := []struct {
		name      string
		age       time.Duration
		shouldVal bool
	}{
		{"fresh", 0, true},
		{"1_second_old", 1 * time.Second, true},
		{"3_seconds_old", 3 * time.Second, false}, // Beyond grace period (2x rotation interval = 2s)
		{"10_seconds_old", 10 * time.Second, false},
		{"100_seconds_old", 100 * time.Second, false},
		{"1_hour_old", 1 * time.Hour, false},
		{"1_day_old", 24 * time.Hour, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := uint32(time.Now().Unix()) - uint32(tc.age.Seconds())
			sc := buildServerCookie(clientCookie, clientIP, ts, secret)
			valid := jar.ValidateServerCookie(clientCookie, sc, clientIP)
			if valid != tc.shouldVal {
				t.Errorf("validation = %v, want %v (age: %v)", valid, tc.shouldVal, tc.age)
			}
		})
	}
}

// TestParseCookieOptionEdgeCases tests cookie option parsing edge cases
func TestParseCookieOptionEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{"exactly_8_bytes", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, nil},
		{"exactly_24_bytes", append(
			[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			make([]byte, 16)...,
		), nil},
		{"exactly_40_bytes", append(
			[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			make([]byte, 32)...,
		), nil},
		{"7_bytes", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, ErrCookieTooShort},
		{"0_bytes", []byte{}, ErrCookieTooShort},
		{"41_bytes", make([]byte, 41), ErrCookieTooLong},
		{"255_bytes", make([]byte, 255), ErrCookieTooLong},
		{"9_bytes", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}, errors.New("invalid server cookie length")}, // 1-byte server cookie is too short
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := ParseCookieOption(tc.input)
			if tc.wantErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tc.wantErr)
					return
				}
				// Check if error message contains expected text
				if tc.wantErr != ErrCookieTooShort && tc.wantErr != ErrCookieTooLong {
					// For custom error messages, check substring
					if !bytes.Contains([]byte(err.Error()), []byte(tc.wantErr.Error())) {
						t.Errorf("expected error containing %q, got %q", tc.wantErr.Error(), err.Error())
					}
				} else if err != tc.wantErr {
					t.Errorf("expected error %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			// Verify client cookie is always extracted
			if len(tc.input) >= 8 {
				var expectedCC [ClientCookieLen]byte
				copy(expectedCC[:], tc.input)
				if c.ClientCookie != expectedCC {
					t.Error("client cookie mismatch")
				}
			}
		})
	}
}

// TestPackCookieOptionRoundTrip tests pack/parse round-trip
func TestPackCookieOptionRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		cc     [ClientCookieLen]byte
		sc     []byte
		wantSC []byte
	}{
		{
			"client_only",
			[ClientCookieLen]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			nil,
			nil,
		},
		{
			"with_server_cookie",
			[ClientCookieLen]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22},
			[]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE},
			[]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE},
		},
		{
			"empty_server_cookie",
			[ClientCookieLen]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
			[]byte{},
			nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			packed := PackCookieOption(tc.cc, tc.sc)
			parsed, err := ParseCookieOption(packed)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if parsed.ClientCookie != tc.cc {
				t.Error("client cookie mismatch")
			}
			if tc.wantSC == nil {
				if parsed.ServerCookie != nil {
					t.Error("expected nil server cookie")
				}
			} else {
				if !bytes.Equal(parsed.ServerCookie, tc.wantSC) {
					t.Errorf("server cookie mismatch: got %x, want %x", parsed.ServerCookie, tc.wantSC)
				}
			}
		})
	}
}

// TestSecretRotationStress tests rapid secret rotation
func TestSecretRotationStress(t *testing.T) {
	jar, err := NewCookieJar(1 * time.Hour)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1")
	clientCookie := jar.GenerateClientCookie(clientIP, net.ParseIP("198.51.100.1"))

	// Rotate 10 times
	for i := 0; i < 10; i++ {
		if err := jar.RotateSecret(); err != nil {
			t.Fatalf("rotation %d failed: %v", i, err)
		}
		// Generate and validate after each rotation
		sc := jar.GenerateServerCookie(clientCookie, clientIP)
		if !jar.ValidateServerCookie(clientCookie, sc, clientIP) {
			t.Errorf("cookie failed validation after rotation %d", i)
		}
	}

	// After 10 rotations, only the last 2 secrets should be valid
	jar.mu.RLock()
	hasPrev := jar.hasPrevious
	jar.mu.RUnlock()

	if !hasPrev {
		t.Error("hasPrevious should be true after rotations")
	}
}

// TestNewCookieJarInvalidInterval tests NewCookieJar with invalid intervals
func TestNewCookieJarInvalidInterval(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
		wantErr  bool
	}{
		{"zero", 0, false},             // Zero is valid (no rotation)
		{"negative", -1 * time.Hour, false}, // Negative might be treated as zero
		{"very_small", 1 * time.Nanosecond, false},
		{"very_large", 365 * 24 * time.Hour, false}, // 1 year
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jar, err := NewCookieJar(tc.interval)
			if tc.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if jar == nil && err == nil {
				t.Error("jar is nil without error")
			}
		})
	}
}

// TestCookieConstants validates cookie-related constants
func TestCookieConstants(t *testing.T) {
	// ClientCookieLen should be 8
	if ClientCookieLen != 8 {
		t.Errorf("ClientCookieLen = %d, want 8", ClientCookieLen)
	}

	// InteropServerCookieLen should be 16
	if InteropServerCookieLen != 16 {
		t.Errorf("InteropServerCookieLen = %d, want 16", InteropServerCookieLen)
	}

	// MinServerCookieLen should be 8
	if MinServerCookieLen != 8 {
		t.Errorf("MinServerCookieLen = %d, want 8", MinServerCookieLen)
	}

	// MaxServerCookieLen should be 32
	if MaxServerCookieLen != 32 {
		t.Errorf("MaxServerCookieLen = %d, want 32", MaxServerCookieLen)
	}

	// serverCookieVersion should be 1
	if serverCookieVersion != 1 {
		t.Errorf("serverCookieVersion = %d, want 1", serverCookieVersion)
	}
}

// TestConcurrentCookieGeneration tests concurrent cookie generation
func TestConcurrentCookieGeneration(t *testing.T) {
	jar, err := NewCookieJar(1 * time.Hour)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1")
	serverIP := net.ParseIP("198.51.100.1")

	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func() {
			cc := jar.GenerateClientCookie(clientIP, serverIP)
			sc := jar.GenerateServerCookie(cc, clientIP)
			if !jar.ValidateServerCookie(cc, sc, clientIP) {
				t.Error("concurrent validation failed")
			}
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}

// TestVersionMismatch tests server cookie version mismatch
func TestVersionMismatch(t *testing.T) {
	jar, err := NewCookieJar(1 * time.Hour)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1")
	clientCookie := jar.GenerateClientCookie(clientIP, net.ParseIP("198.51.100.1"))
	sc := jar.GenerateServerCookie(clientCookie, clientIP)

	// Modify version byte to invalid value
	sc[0] = 0xFF

	if jar.ValidateServerCookie(clientCookie, sc, clientIP) {
		t.Error("should reject invalid version")
	}
}

// TestReservedByteMismatch tests server cookie reserved byte mismatch
func TestReservedByteMismatch(t *testing.T) {
	jar, err := NewCookieJar(1 * time.Hour)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1")
	clientCookie := jar.GenerateClientCookie(clientIP, net.ParseIP("198.51.100.1"))
	sc := jar.GenerateServerCookie(clientCookie, clientIP)

	// Modify reserved byte
	sc[1] = 0xFF

	if jar.ValidateServerCookie(clientCookie, sc, clientIP) {
		t.Error("should reject when reserved byte is non-zero")
	}
}
