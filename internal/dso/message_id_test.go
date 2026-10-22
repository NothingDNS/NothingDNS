package dso

import (
	"encoding/binary"
	"errors"
	"testing"
)

// keepaliveBody is a client Keepalive TLV body: inactivity timeout then
// keepalive interval, both in milliseconds.
func keepaliveBody(inactivityMS, keepaliveMS uint32) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:4], inactivityMS)
	binary.BigEndian.PutUint32(b[4:8], keepaliveMS)
	return b
}

// RFC 8490 §5.4.1: "Whether a message is a DSO request message or a DSO
// unidirectional message is determined only by the specification for the
// Primary TLV. ... Nor can an acknowledgment be prevented by sending a MESSAGE
// ID of zero in a message that is required to be a DSO request message
// according to its Primary TLV. A responder that receives either such
// malformed message MUST treat it as a fatal error and forcibly abort the
// connection immediately."
//
// RFC 8490 §7.1: a client-sent Keepalive "MUST be sent as a DSO request message
// with a nonzero MESSAGE ID. If a server receives a DSO Keepalive message with a
// zero MESSAGE ID, then this is a fatal error and the server MUST forcibly abort
// the connection immediately."
//
// The transport (internal/server) answers a DSO message only when its ID is
// nonzero and aborts only when HandleDSORequest returns an error, so unless
// HandleDSORequest reports this as fatal, a zero-ID Keepalive is silently
// "accepted", its timeouts are applied to the session, and no response is
// ever sent — the client waits for an acknowledgment it can never receive.
func TestHandleDSORequestKeepaliveWithZeroMessageIDIsFatal(t *testing.T) {
	m := NewManager(DefaultConfig(), nil)

	t.Run("control: nonzero MESSAGE ID Keepalive is answered", func(t *testing.T) {
		sess := freshSession()
		msg := dsoMessage(packTLV(DSOTLVKeepalive, keepaliveBody(15000, 15000)))
		msg.Header.ID = 0x1234
		resp, err := m.HandleDSORequest(sess, msg)
		if err != nil || resp == nil {
			t.Fatalf("control: err=%v resp=%v, want a normal response", err, resp)
		}
		if resp.Header.ID != 0x1234 {
			t.Errorf("response MESSAGE ID = %#x, want a copy of the request's 0x1234", resp.Header.ID)
		}
	})

	t.Run("zero MESSAGE ID Keepalive is a fatal error", func(t *testing.T) {
		sess := freshSession()
		before := sess.KeepaliveTime
		msg := dsoMessage(packTLV(DSOTLVKeepalive, keepaliveBody(15000, 20000)))
		msg.Header.ID = 0
		resp, err := m.HandleDSORequest(sess, msg)
		if err == nil || !errors.Is(err, ErrDSOFatal) {
			t.Fatalf("FAIL: Keepalive with MESSAGE ID 0 returned err=%v resp=%v; RFC 8490 §7.1 requires the server to forcibly abort the connection (ErrDSOFatal)", err, resp)
		}
		if resp != nil {
			t.Error("a fatal error must not also produce a response")
		}
		if sess.KeepaliveTime != before || sess.keepalivesEnabled {
			t.Errorf("the session's timeouts were changed (KeepaliveTime %v -> %v, enabled=%v) by a message that must be rejected",
				before, sess.KeepaliveTime, sess.keepalivesEnabled)
		}
	})
}

// RFC 8490 §5.4.5: an unrecognized Primary TLV in a request (nonzero MESSAGE ID)
// gets DSOTYPENI and the session stays open; but "if a DSO unidirectional
// message is received containing both an unrecognized Primary TLV and a zero
// MESSAGE ID (indicating that no response is expected), then this is a fatal
// error and the recipient MUST forcibly abort the connection immediately."
func TestHandleDSORequestUnknownPrimaryTLVWithZeroMessageIDIsFatal(t *testing.T) {
	m := NewManager(DefaultConfig(), nil)
	const unknownType = 0x0777

	t.Run("control: nonzero MESSAGE ID gets DSOTYPENI and keeps the session", func(t *testing.T) {
		msg := dsoMessage(packTLV(unknownType, []byte{1, 2, 3}))
		msg.Header.ID = 0x00aa
		resp, err := m.HandleDSORequest(freshSession(), msg)
		if err != nil || resp == nil {
			t.Fatalf("control: err=%v resp=%v, want a DSOTYPENI response", err, resp)
		}
		if resp.Header.Flags.RCODE != 11 || resp.Header.ID != 0x00aa {
			t.Errorf("control: rcode=%d id=%#x, want DSOTYPENI(11) echoing 0x00aa", resp.Header.Flags.RCODE, resp.Header.ID)
		}
	})

	t.Run("zero MESSAGE ID with an unknown primary TLV is fatal", func(t *testing.T) {
		msg := dsoMessage(packTLV(unknownType, []byte{1, 2, 3}))
		msg.Header.ID = 0
		resp, err := m.HandleDSORequest(freshSession(), msg)
		if err == nil || !errors.Is(err, ErrDSOFatal) {
			t.Fatalf("FAIL: unidirectional message with an unrecognized primary TLV returned err=%v resp=%v; RFC 8490 §5.4.5 requires a forcible abort (ErrDSOFatal)", err, resp)
		}
	})
}
