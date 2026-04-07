package dnscookie

import (
	"bytes"
	"encoding/binary"
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
