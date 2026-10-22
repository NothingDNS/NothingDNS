package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/dso"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/util"
)

// dsoRawRequest builds a DSO request (opcode 6, nonzero MESSAGE ID, zero section
// counts) whose Primary TLV is typ with the given value.
func dsoRawRequest(id uint16, typ uint16, value []byte) []byte {
	msg := make([]byte, 12+4+len(value))
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], uint16(protocol.OpcodeDSO)<<11)
	binary.BigEndian.PutUint16(msg[12:14], typ)
	binary.BigEndian.PutUint16(msg[14:16], uint16(len(value)))
	copy(msg[16:], value)
	return msg
}

// RFC 8490 §6.3: every complete DNS message resets both timers on a DSO session,
// "with the one exception being that a DSO Keepalive message resets only the
// keepalive timer, not the inactivity timeout timer" — otherwise "keepalive
// traffic would be sent indefinitely to keep a DSO Session alive" and an idle
// connection could pin a session slot forever.
//
// The transports call Touch(conn) for every message before they dispatch DSO,
// and HandleDSORequest refreshes the session itself; both paths must leave the
// inactivity timer alone for a Keepalive, while still counting a regular DNS
// query and any other DSO message.
func TestDSOKeepaliveOverTCPDoesNotResetInactivity(t *testing.T) {
	const inactivity = 300 * time.Millisecond

	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	manager := dso.NewManager(dso.Config{
		Enabled: true, AllowPlainTCP: true, MaxSessions: 10, InactivityTimeout: inactivity,
	}, logger)
	manager.Start()
	t.Cleanup(manager.Stop)
	adapter := newDSOConnAdapter(manager, logger)

	srv := server.NewTCPServerWithWorkers("127.0.0.1:0", server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		// A regular query: answer nothing, the point is only that it arrived.
	}), 1)
	srv.SetDSOHandler(adapter)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Stop() })

	// session returns the (only) DSO session the adapter holds.
	session := func(t *testing.T) *dso.Session {
		t.Helper()
		adapter.mu.Lock()
		defer adapter.mu.Unlock()
		for _, s := range adapter.sessions {
			return s
		}
		t.Fatal("no DSO session was created")
		return nil
	}

	// start dials, creates the session with a non-keepalive DSO message
	// (Maximum Payload), then lets the inactivity timeout elapse.
	start := func(t *testing.T) (net.Conn, *dso.Session) {
		t.Helper()
		c, err := net.Dial("tcp", srv.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { c.Close() })
		writeFrame(t, c, dsoRawRequest(0x0101, dso.DSOTLVMaximumPayload, []byte{0x10, 0x00}))
		if got := readOutcome(c, 2*time.Second); got != "answered" {
			t.Fatalf("setup: Maximum Payload request outcome = %s, want answered", got)
		}
		s := session(t)
		time.Sleep(inactivity + 150*time.Millisecond)
		if !s.IsExpired(inactivity) {
			t.Fatal("setup: session did not become idle")
		}
		return c, s
	}

	t.Run("control: a regular DNS query on the connection counts as activity", func(t *testing.T) {
		c, s := start(t)
		q, err := protocol.NewQuery(0x2222, "example.com.", protocol.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 512)
		n, err := q.Pack(buf)
		if err != nil {
			t.Fatal(err)
		}
		writeFrame(t, c, buf[:n])
		time.Sleep(100 * time.Millisecond)
		if s.IsExpired(inactivity) {
			t.Fatal("control: a regular query did not reset the inactivity timer")
		}
	})

	t.Run("control: a non-keepalive DSO message counts as activity", func(t *testing.T) {
		c, s := start(t)
		writeFrame(t, c, dsoRawRequest(0x0102, dso.DSOTLVMaximumPayload, []byte{0x10, 0x00}))
		if got := readOutcome(c, 2*time.Second); got != "answered" {
			t.Fatalf("control: outcome = %s, want answered", got)
		}
		if s.IsExpired(inactivity) {
			t.Fatal("control: a Maximum Payload message did not reset the inactivity timer")
		}
	})

	t.Run("a Keepalive does not reset the inactivity timer", func(t *testing.T) {
		c, s := start(t)
		writeFrame(t, c, buildDSOKeepaliveRequest(t, 0x0103))
		if got := readOutcome(c, 2*time.Second); got != "answered" {
			t.Fatalf("a Keepalive must still be answered, outcome = %s", got)
		}
		if !s.IsExpired(inactivity) {
			t.Fatal("FAIL: a Keepalive reset the inactivity timer of an idle DSO session; it must reset only the keepalive timer (RFC 8490 §6.3), or an idle client can hold the session open forever")
		}
	})
}
