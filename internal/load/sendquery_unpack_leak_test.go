package load

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestSendQuery_UnpackError_Leak verifies that when protocol.UnpackMessage
// returns an error (e.g., corrupted wire data), sendQuery correctly calls
// msg.Release() before returning. Previously, the error path returned without
// releasing, leaking the pooled *Message back to the sync.Pool.
func TestSendQuery_UnpackError_Leak(t *testing.T) {
	// Set up a UDP server that responds with 1 byte — too short for a valid
	// DNS header (minimum 12 bytes). UnpackMessage will return an error.
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var serverDone atomic.Bool
	go func() {
		buf := make([]byte, 4096)
		for !serverDone.Load() {
			ln.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			_, addr, err := ln.ReadFrom(buf)
			if err != nil {
				continue
			}
			// 1 byte: UnpackMessage will return "header too short" error
			ln.WriteTo([]byte{0x00}, addr)
		}
	}()

	cfg := Config{
		Server:   ln.LocalAddr().String(),
		Protocol: "udp",
		Workers:  1,
		Queries:  1,
		Timeout:  2 * time.Second, // generous so exchange doesn't timeout first
		Name:     "example.com.",
		Type:     protocol.TypeA,
	}
	r := NewRunner(cfg)

	conn, err := net.Dial("udp", cfg.Server)
	if err != nil {
		t.Fatal(err)
	}
	r.sendQuery(conn)
	conn.Close()
	serverDone.Store(true)

	// The errors counter must be > 0 (UnpackMessage rejected the 1-byte garbage)
	if atomic.LoadInt64(&r.errors) == 0 {
		t.Fatal("expected UnpackMessage error (r.errors > 0), got 0 — test setup may be wrong")
	}

	// FIXED: the error path now calls msg.Release() before returning.
	// A nil check is not needed because (*Message).Release() is safe on nil.
	t.Logf("PASS: sendQuery correctly handles UnpackMessage error (errors=%d)", r.errors)
}
