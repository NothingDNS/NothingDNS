package dso

// Tests for HandleDSORequest's per-TLV-type branches. Lifts dso
// coverage by driving each switch arm of the TLV processing loop
// through real RawBody bytes (the same path a real DSO client takes).

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// packTLV builds an RFC 8490 TLV: type(2) || length(2) || value
func packTLV(typ uint16, value []byte) []byte {
	out := make([]byte, 4+len(value))
	binary.BigEndian.PutUint16(out[0:2], typ)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(value)))
	copy(out[4:], value)
	return out
}

// dsoMessage wraps a TLV stream in the OPCODE-DSO header form
// HandleDSORequest expects. It builds a DSO REQUEST: RFC 8490 §5.4.1 requires
// a request to carry a unique nonzero MESSAGE ID (zero marks a unidirectional
// message, which a Keepalive or an unrecognized primary TLV must never be), so
// the ID is nonzero. Tests of the zero-ID rules set Header.ID = 0 explicitly.
func dsoMessage(tlvs ...[]byte) *protocol.Message {
	var body []byte
	for _, t := range tlvs {
		body = append(body, t...)
	}
	return &protocol.Message{
		Header: protocol.Header{
			ID:    0x4242,
			Flags: protocol.Flags{Opcode: protocol.OpcodeDSO},
		},
		RawBody: body,
	}
}

// freshSession returns a non-nil DSO session usable as the request peer.
func freshSession() *Session {
	return &Session{
		ID:         1,
		MaxPayload: 65535,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
}

func TestHandleDSORequest_Keepalive(t *testing.T) {
	cfg := DefaultConfig()
	cfg.InactivityTimeout = 22 * time.Second
	m := NewManager(cfg, nil)
	sess := freshSession()

	// RFC 8490 §4.1: Keepalive TLV body = primary(4) || secondary(4),
	// both in milliseconds. The server chooses its response values.
	body := make([]byte, 8)
	binary.BigEndian.PutUint32(body[0:4], 15000)
	binary.BigEndian.PutUint32(body[4:8], 500)

	resp, err := m.HandleDSORequest(sess, dsoMessage(packTLV(DSOTLVKeepalive, body)))
	if err != nil {
		t.Fatalf("HandleDSORequest: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !sess.keepalivesEnabled {
		t.Error("keepalivesEnabled should be true after Keepalive TLV")
	}
	if sess.KeepaliveTime != MinKeepaliveInterval {
		t.Errorf("KeepaliveTime = %v, want %v", sess.KeepaliveTime, MinKeepaliveInterval)
	}
	tlv, _, err := UnpackTLV(resp.RawBody, 0)
	if err != nil {
		t.Fatalf("response keepalive TLV unpack: %v", err)
	}
	primary, secondary, err := ParseKeepaliveTLV(tlv)
	if err != nil {
		t.Fatalf("response keepalive TLV parse: %v", err)
	}
	if primary != 22*time.Second {
		t.Errorf("response inactivity timeout = %v, want 22s", primary)
	}
	if secondary != MinKeepaliveInterval {
		t.Errorf("response keepalive interval = %v, want %v", secondary, MinKeepaliveInterval)
	}
}

func TestHandleDSORequest_MaximumPayload_ShrinksOnRequest(t *testing.T) {
	m := NewManager(DefaultConfig(), nil)
	sess := freshSession()
	// Send a smaller-than-default max payload (4096); session should adopt it.
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, 4096)

	_, err := m.HandleDSORequest(sess, dsoMessage(packTLV(DSOTLVMaximumPayload, body)))
	if err != nil {
		t.Fatalf("HandleDSORequest: %v", err)
	}
	if sess.MaxPayload != 4096 {
		t.Errorf("MaxPayload = %d, want 4096 (shrunk from 65535)", sess.MaxPayload)
	}
}

func TestHandleDSORequest_MaximumPayload_NoGrowOverSessionCap(t *testing.T) {
	m := NewManager(DefaultConfig(), nil)
	sess := freshSession()
	sess.MaxPayload = 8192 // pre-set session cap
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, 65000) // client wants more

	_, err := m.HandleDSORequest(sess, dsoMessage(packTLV(DSOTLVMaximumPayload, body)))
	if err != nil {
		t.Fatalf("HandleDSORequest: %v", err)
	}
	if sess.MaxPayload != 8192 {
		t.Errorf("MaxPayload = %d, want 8192 (client may not raise it)", sess.MaxPayload)
	}
}

func TestHandleDSORequest_PrimaryPaddingRejected(t *testing.T) {
	m := NewManager(DefaultConfig(), nil)
	sess := freshSession()
	_, err := m.HandleDSORequest(sess, dsoMessage(packTLV(DSOTLVPadding, []byte{0, 0, 0, 0})))
	if err == nil {
		t.Fatal("expected error for primary padding TLV")
	}
}

func TestHandleDSORequest_AdditionalPaddingIgnored(t *testing.T) {
	// Padding TLVs are only valid as Additional TLVs and are ignored.
	m := NewManager(DefaultConfig(), nil)
	sess := freshSession()

	keepalive := make([]byte, 8)
	binary.BigEndian.PutUint32(keepalive[0:4], 5000)
	binary.BigEndian.PutUint32(keepalive[4:8], 30000)

	resp, err := m.HandleDSORequest(sess, dsoMessage(
		packTLV(DSOTLVKeepalive, keepalive),
		packTLV(DSOTLVPadding, []byte{0, 0, 0, 0}),
	))
	if err != nil {
		t.Fatalf("HandleDSORequest: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestHandleDSORequest_RetryDelay_RejectedInRequest(t *testing.T) {
	// RetryDelay is a server→client-only TLV (RFC 8490 §6.6.1). When a
	// client sends one, the request must be rejected.
	m := NewManager(DefaultConfig(), nil)
	sess := freshSession()
	body := make([]byte, 4) // RetryDelay payload: uint32 ms
	binary.BigEndian.PutUint32(body, 5000)
	_, err := m.HandleDSORequest(sess, dsoMessage(packTLV(DSOTLVRetryDelay, body)))
	if err == nil {
		t.Error("expected error for client-side RetryDelay TLV")
	}
}

func TestHandleDSORequest_UnknownTLV_Rejected(t *testing.T) {
	// RFC 8490 §5.1.1: an unrecognized PRIMARY TLV is answered with
	// DSOTYPENI and the session STAYS OPEN — it is NOT a fatal error
	// (aborting would tear down pipelined regular DNS queries on the conn).
	m := NewManager(DefaultConfig(), nil)
	sess := freshSession()
	resp, err := m.HandleDSORequest(sess, dsoMessage(packTLV(0x7FFF, []byte{1, 2, 3})))
	if err != nil {
		t.Fatalf("unknown primary TLV must not be a fatal error, got %v", err)
	}
	if resp == nil {
		t.Fatal("expected a DSOTYPENI response, got nil")
	}
	if resp.Header.Flags.RCODE != protocol.RcodeDSOTypeNI {
		t.Errorf("RCODE = %d, want DSOTYPENI (%d)", resp.Header.Flags.RCODE, protocol.RcodeDSOTypeNI)
	}
	if !resp.Header.Flags.QR {
		t.Error("response QR flag not set")
	}
}

func TestHandleDSORequest_UnknownAdditionalTLV_Ignored(t *testing.T) {
	m := NewManager(DefaultConfig(), nil)
	sess := freshSession()

	keepalive := make([]byte, 8)
	binary.BigEndian.PutUint32(keepalive[0:4], 5000)
	binary.BigEndian.PutUint32(keepalive[4:8], 30000)

	resp, err := m.HandleDSORequest(sess, dsoMessage(
		packTLV(DSOTLVKeepalive, keepalive),
		packTLV(0x7FFF, []byte{1, 2, 3}),
	))
	if err != nil {
		t.Fatalf("HandleDSORequest: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !sess.keepalivesEnabled {
		t.Fatal("known primary TLV should still be applied")
	}
}

func TestHandleDSORequest_MultipleTLVsInOneRequest(t *testing.T) {
	// A DSO message can carry multiple TLVs back-to-back. Confirm
	// both branches fire and the session state reflects both.
	m := NewManager(DefaultConfig(), nil)
	sess := freshSession()

	// 5s = 5000ms, 30s = 30000ms.
	keepalive := make([]byte, 8)
	binary.BigEndian.PutUint32(keepalive[0:4], 5000)
	binary.BigEndian.PutUint32(keepalive[4:8], 30000)
	mp := make([]byte, 2)
	binary.BigEndian.PutUint16(mp, 16000)

	_, err := m.HandleDSORequest(sess, dsoMessage(
		packTLV(DSOTLVKeepalive, keepalive),
		packTLV(DSOTLVMaximumPayload, mp),
	))
	if err != nil {
		t.Fatalf("HandleDSORequest: %v", err)
	}
	if !sess.keepalivesEnabled {
		t.Error("keepalive should be enabled")
	}
	if sess.MaxPayload != 16000 {
		t.Errorf("MaxPayload = %d, want 16000", sess.MaxPayload)
	}
}
