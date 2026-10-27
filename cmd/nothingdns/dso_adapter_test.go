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

// buildDSOKeepaliveRequest builds a raw DSO request (opcode 6, all section
// counts zero) carrying a Keepalive TLV, framed for TCP (2-byte length
// prefix NOT included — caller frames it).
func buildDSOKeepaliveRequest(t *testing.T, id uint16) []byte {
	t.Helper()
	tlv := dso.NewKeepaliveTLV(30*time.Second, 15*time.Second)
	body := make([]byte, 64)
	n, err := tlv.Pack(body, 0)
	if err != nil {
		t.Fatalf("packing keepalive TLV: %v", err)
	}
	msg := make([]byte, 12+n)
	binary.BigEndian.PutUint16(msg[0:2], id)
	// Flags: QR=0, Opcode=6 -> bits 14-11.
	binary.BigEndian.PutUint16(msg[2:4], uint16(protocol.OpcodeDSO)<<11)
	copy(msg[12:], body[:n])
	return msg
}

// exchangeTCP writes one length-prefixed message and reads one
// length-prefixed response.
func exchangeTCP(t *testing.T, conn net.Conn, msg []byte) []byte {
	t.Helper()
	framed := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(framed[0:2], uint16(len(msg)))
	copy(framed[2:], msg)
	if _, err := conn.Write(framed); err != nil {
		t.Fatalf("writing DSO request: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("setting read deadline: %v", err)
	}
	var lengthBuf [2]byte
	if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
		t.Fatalf("reading response length: %v", err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(lengthBuf[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	return resp
}

// Regression: DSO (RFC 8490) was fully implemented in internal/dso but
// never dispatched from the request path — opcode 6 over TCP/TLS fell
// through to the regular query pipeline. This exercises the full wire
// path: TCP server -> opcode dispatch -> dsoConnAdapter -> dso.Manager.
func TestDSO_KeepaliveOverTCP(t *testing.T) {
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	manager := dso.NewManager(dso.Config{
		Enabled:       true,
		AllowPlainTCP: true, // plain TCP for the test listener
		MaxSessions:   10,
	}, logger)
	manager.Start()
	defer manager.Stop()

	adapter := newDSOConnAdapter(manager, logger)

	srv := server.NewTCPServerWithWorkers("127.0.0.1:0", server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		t.Error("regular handler must not receive DSO messages")
	}), 1)
	srv.SetDSOHandler(adapter)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve() }()
	defer srv.Stop()

	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	resp := exchangeTCP(t, conn, buildDSOKeepaliveRequest(t, 0x1234))
	respMsg, err := protocol.UnpackMessage(resp)
	if err != nil {
		t.Fatalf("unpacking DSO response: %v", err)
	}
	if respMsg.Header.ID != 0x1234 {
		t.Errorf("response ID = %#x, want 0x1234", respMsg.Header.ID)
	}
	if respMsg.Header.Flags.Opcode != protocol.OpcodeDSO {
		t.Errorf("response opcode = %d, want %d (DSO)", respMsg.Header.Flags.Opcode, protocol.OpcodeDSO)
	}
	if !respMsg.Header.Flags.QR {
		t.Error("response QR flag not set")
	}
	if respMsg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("response RCODE = %d, want NOERROR", respMsg.Header.Flags.RCODE)
	}
	if len(respMsg.RawBody) == 0 {
		t.Fatal("DSO response has empty TLV body, want keepalive TLV")
	}
	tlv, _, err := dso.UnpackTLV(respMsg.RawBody, 0)
	if err != nil {
		t.Fatalf("unpacking response TLV: %v", err)
	}
	if tlv.Type != dso.DSOTLVKeepalive {
		t.Errorf("response TLV type = %d, want keepalive (%d)", tlv.Type, dso.DSOTLVKeepalive)
	}
	if manager.SessionCount() != 1 {
		t.Errorf("session count = %d, want 1", manager.SessionCount())
	}

	// Closing the connection must tear the session down (ConnClosed hook).
	conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	for manager.SessionCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := manager.SessionCount(); got != 0 {
		t.Errorf("session count after close = %d, want 0", got)
	}
}

// A server without a DSO handler must answer opcode 6 with NOTIMP instead
// of feeding it to the query pipeline.
func TestDSO_NotImplementedWithoutHandler(t *testing.T) {
	srv := server.NewTCPServerWithWorkers("127.0.0.1:0", server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		t.Error("regular handler must not receive DSO messages")
	}), 1)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve() }()
	defer srv.Stop()

	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	resp := exchangeTCP(t, conn, buildDSOKeepaliveRequest(t, 0x4242))
	respMsg, err := protocol.UnpackMessage(resp)
	if err != nil {
		t.Fatalf("unpacking response: %v", err)
	}
	if respMsg.Header.Flags.RCODE != protocol.RcodeNotImplemented {
		t.Errorf("RCODE = %d, want NOTIMP", respMsg.Header.Flags.RCODE)
	}
}

// Regression: the DSO inactivity sweeper closes the underlying connection.
// LastActivity was only updated by DSO messages, so a connection actively
// serving REGULAR DNS queries (which don't touch the session) got closed
// ~15s after its last DSO message. Touch(conn), called by the transport
// on every message, must reset the session's activity.
func TestDSOAdapter_TouchResetsInactivity(t *testing.T) {
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	manager := dso.NewManager(dso.Config{
		Enabled:           true,
		AllowPlainTCP:     true,
		MaxSessions:       10,
		InactivityTimeout: 50 * time.Millisecond,
	}, logger)
	manager.Start()
	defer manager.Stop()

	adapter := newDSOConnAdapter(manager, logger)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Establish a session via a keepalive DSO message.
	if _, err := adapter.HandleDSO(server, mustUnpackDSO(t, buildDSOKeepaliveRequest(t, 0x1))); err != nil {
		t.Fatalf("HandleDSO: %v", err)
	}
	if manager.SessionCount() != 1 {
		t.Fatalf("session count = %d, want 1", manager.SessionCount())
	}

	// Keep touching faster than the inactivity timeout; the session must
	// survive well past one timeout window.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		adapter.Touch(server)
		time.Sleep(10 * time.Millisecond)
	}
	if manager.SessionCount() != 1 {
		t.Fatalf("touched session was reaped: count = %d, want 1", manager.SessionCount())
	}

	// Touch on an unknown conn is a no-op (must not panic).
	other, _ := net.Pipe()
	defer other.Close()
	adapter.Touch(other)
}

func mustUnpackDSO(t *testing.T, raw []byte) *protocol.Message {
	t.Helper()
	msg, err := protocol.UnpackMessage(raw)
	if err != nil {
		t.Fatalf("unpack DSO: %v", err)
	}
	return msg
}

// A connection hosting a DSO session is read with the session's abort time,
// not the transport's idle timeout (RFC 8490 §5; F743).
func TestDSOAdapterReadTimeout(t *testing.T) {
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	m := dso.NewManager(dso.Config{Enabled: true, AllowPlainTCP: true, MaxSessions: 10, InactivityTimeout: 40 * time.Second}, logger)
	a := newDSOConnAdapter(m, logger)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if got := a.ReadTimeout(c1); got != 0 {
		t.Fatalf("ReadTimeout without a session = %v, want 0", got)
	}
	if _, err := a.HandleDSO(c1, &protocol.Message{Header: protocol.Header{ID: 1, Flags: protocol.Flags{Opcode: protocol.OpcodeDSO}}}); err != nil {
		t.Logf("HandleDSO: %v (session creation is what matters)", err)
	}
	if got := a.ReadTimeout(c1); got != 80*time.Second {
		t.Fatalf("ReadTimeout with a session = %v, want 80s", got)
	}
}
