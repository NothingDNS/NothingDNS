package main

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/dso"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/util"
)

// dsoTCPServer starts the real TCP server with the real DSO adapter and
// returns a dialer for it.
func dsoTCPServer(t *testing.T) func() net.Conn {
	t.Helper()
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	manager := dso.NewManager(dso.Config{Enabled: true, AllowPlainTCP: true, MaxSessions: 10}, logger)
	manager.Start()
	t.Cleanup(manager.Stop)

	srv := server.NewTCPServerWithWorkers("127.0.0.1:0", server.HandlerFunc(func(server.ResponseWriter, *protocol.Message) {
		t.Error("regular handler must not receive DSO messages")
	}), 1)
	srv.SetDSOHandler(newDSOConnAdapter(manager, logger))
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Stop() })

	return func() net.Conn {
		c, err := net.Dial("tcp", srv.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
}

func writeFrame(t *testing.T, c net.Conn, msg []byte) {
	t.Helper()
	framed := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(framed[0:2], uint16(len(msg)))
	copy(framed[2:], msg)
	if _, err := c.Write(framed); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// readOutcome reports what the server did after a request: it either sent a
// frame (answered), closed the connection (EOF/reset: aborted), or did
// neither within the window (silent — the client is left waiting).
func readOutcome(c net.Conn, window time.Duration) string {
	_ = c.SetReadDeadline(time.Now().Add(window))
	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return "silent"
		}
		return "closed"
	}
	// Consume the whole frame: leaving the body in the socket would make the
	// next call read it as a length prefix and report a response that was
	// never sent.
	body := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(c, body); err != nil {
		return "closed"
	}
	return "answered"
}

// RFC 8490 §7.1: a server that receives a Keepalive with a zero MESSAGE ID
// "MUST forcibly abort the connection immediately". A client-initiated request
// has a nonzero ID and gets an answer; a zero ID must close the connection —
// never be accepted-and-ignored, which leaves the client waiting forever for a
// response the transport is forbidden to send to a "unidirectional" message.
func TestDSOKeepaliveWithZeroMessageIDAbortsTheConnection(t *testing.T) {
	dial := dsoTCPServer(t)

	t.Run("control: nonzero MESSAGE ID is answered", func(t *testing.T) {
		c := dial()
		writeFrame(t, c, buildDSOKeepaliveRequest(t, 0x1234))
		if got := readOutcome(c, 2*time.Second); got != "answered" {
			t.Fatalf("control: outcome = %s, want answered", got)
		}
	})

	t.Run("zero MESSAGE ID closes the connection", func(t *testing.T) {
		c := dial()
		writeFrame(t, c, buildDSOKeepaliveRequest(t, 0))
		if got := readOutcome(c, 2*time.Second); got != "closed" {
			t.Fatalf("FAIL: Keepalive with MESSAGE ID 0 left the connection %s; RFC 8490 §7.1 requires the server to forcibly abort it", got)
		}
	})
}
