// Package websocket regression tests (round-032): RFC 6455 §5.5.1 close
// handshake. An endpoint that receives a Close frame and has not previously
// sent one MUST respond with a Close frame before closing. ReadMessage
// previously returned close frames to callers without echoing, and neither
// production consumer (internal/doh/wshandler.go, dashboard ClientLoop)
// sent one — every clean client close ended in a bare TCP close (client
// close code 1006 instead of the negotiated code). The echo now lives in
// Conn.ReadMessage's close case, mirroring the auto-pong precedent.

package websocket

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestReadMessage_CloseFrameEchoesReceivedCode pins the §5.5.1 MUST:
// after reading a client close frame, the server has written a close
// frame echoing the received status code.
func TestReadMessage_CloseFrameEchoesReceivedCode(t *testing.T) {
	closeFrame := buildClientFrame(0x8, true, []byte{0x03, 0xE8}) // 1000 NORMAL_CLOSURE
	c := newConn(closeFrame)

	msgType, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage on close frame: unexpected error: %v", err)
	}
	if msgType != 8 {
		t.Fatalf("ReadMessage msgType = %d, want 8 (close)", msgType)
	}
	if len(data) != 2 || data[0] != 0x03 || data[1] != 0xE8 {
		t.Fatalf("ReadMessage close payload = %x, want 03e8", data)
	}

	written := c.conn.(*bufferConn).writer.Bytes()
	if len(written) < 4 {
		t.Fatalf("no close frame echoed in response to a client close (got %d bytes); RFC 6455 §5.5.1 requires a close frame response before closing", len(written))
	}
	if written[0] != 0x88 { // FIN + close opcode
		t.Fatalf("expected close frame opcode 0x88, got 0x%02x in %x", written[0], written)
	}
	if code := binary.BigEndian.Uint16(written[2:4]); code != 1000 {
		t.Fatalf("echoed close code = %d, want 1000", code)
	}
}

// TestReadMessage_CloseEchoPreservesCodeAndReason pins echo fidelity for
// a close frame carrying a reason string.
func TestReadMessage_CloseEchoPreservesCodeAndReason(t *testing.T) {
	payload := append([]byte{0x03, 0xE9}, []byte("going away")...) // 1001 + reason
	c := newConn(buildClientFrame(0x8, true, payload))

	if msgType, _, err := c.ReadMessage(); err != nil || msgType != 8 {
		t.Fatalf("ReadMessage = (%d, %v), want (8, nil)", msgType, err)
	}

	written := c.conn.(*bufferConn).writer.Bytes()
	if len(written) < 2+2+len("going away") {
		t.Fatalf("no complete close echo written (%d bytes)", len(written))
	}
	if written[0] != 0x88 {
		t.Fatalf("expected close opcode 0x88, got 0x%02x", written[0])
	}
	if !bytes.Equal(written[2:], payload) {
		t.Fatalf("echoed close payload = %x, want %x", written[2:], payload)
	}
}

// TestReadMessage_EmptyCloseFrameStillEchoed covers the zero-payload
// close frame (legal: no status code).
func TestReadMessage_EmptyCloseFrameStillEchoed(t *testing.T) {
	c := newConn(buildClientFrame(0x8, true, nil))

	if msgType, data, err := c.ReadMessage(); err != nil || msgType != 8 || len(data) != 0 {
		t.Fatalf("ReadMessage = (%d, %x, %v), want (8, empty, nil)", msgType, data, err)
	}

	written := c.conn.(*bufferConn).writer.Bytes()
	if len(written) < 2 || written[0] != 0x88 || written[1] != 0x00 {
		t.Fatalf("expected empty close echo frame 0x88 0x00, got %x", written)
	}
}

// TestReadMessage_PongAndCloseEchoCoexist is the control: the echo must
// not displace the established auto-pong when both control frames arrive
// in one read loop session.
func TestReadMessage_PongAndCloseEchoCoexist(t *testing.T) {
	pingFrame := buildClientFrame(0x9, true, []byte("ping"))
	closeFrame := buildClientFrame(0x8, true, []byte{0x03, 0xE8})
	full := append(append([]byte{}, pingFrame...), closeFrame...)
	c := newConn(full)

	if _, _, err := c.ReadMessage(); err != nil {
		t.Fatalf("ReadMessage: unexpected error: %v", err)
	}

	written := c.conn.(*bufferConn).writer.Bytes()
	foundPong, foundClose := false, false
	for i := 0; i+1 < len(written); {
		op := written[i] & 0x0F
		plen := int(written[i+1] & 0x7F)
		if op == 0xA {
			foundPong = true
		}
		if op == 0x8 {
			foundClose = true
		}
		i += 2 + plen
	}
	if !foundPong {
		t.Fatalf("auto-pong missing after ping")
	}
	if !foundClose {
		t.Fatalf("close echo missing after close frame")
	}
}
