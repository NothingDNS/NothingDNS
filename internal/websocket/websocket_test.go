package websocket

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// IsWebSocketRequest
// ============================================================================

func TestIsWebSocketRequest_Valid(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	if !IsWebSocketRequest(r) {
		t.Error("expected valid WebSocket request")
	}
}

func TestIsWebSocketRequest_CaseInsensitive(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "WebSocket")
	r.Header.Set("Connection", "keep-alive, upgrade")
	if !IsWebSocketRequest(r) {
		t.Error("expected case-insensitive match")
	}
}

func TestIsWebSocketRequest_MissingUpgrade(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Connection", "Upgrade")
	if IsWebSocketRequest(r) {
		t.Error("expected false with missing Upgrade header")
	}
}

func TestIsWebSocketRequest_MissingConnection(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	if IsWebSocketRequest(r) {
		t.Error("expected false with missing Connection header")
	}
}

func TestIsWebSocketRequest_Neither(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws", nil)
	if IsWebSocketRequest(r) {
		t.Error("expected false with no relevant headers")
	}
}

// ============================================================================
// readFrame / ReadMessage — frame parsing
// ============================================================================

// buildFrame constructs a WebSocket frame. If masked, applies XOR mask.
func buildFrame(opcode byte, fin bool, mask bool, maskKey []byte, payload []byte) []byte {
	var buf []byte
	firstByte := opcode & 0x0F
	if fin {
		firstByte |= 0x80
	}
	buf = append(buf, firstByte)

	length := len(payload)
	secondByte := byte(0)
	if mask {
		secondByte |= 0x80
	}

	switch {
	case length <= 125:
		buf = append(buf, secondByte|byte(length))
	case length <= 65535:
		buf = append(buf, secondByte|126)
		buf = append(buf, byte(length>>8), byte(length))
	default:
		buf = append(buf, secondByte|127)
		for i := 7; i >= 0; i-- {
			buf = append(buf, byte(length>>(i*8)))
		}
	}

	if mask {
		buf = append(buf, maskKey...)
		for i, b := range payload {
			buf = append(buf, b^maskKey[i%4])
		}
	} else {
		buf = append(buf, payload...)
	}

	return buf
}

type bufferConn struct {
	reader io.Reader
	writer *bytes.Buffer
}

func (bc *bufferConn) Read(p []byte) (int, error)  { return bc.reader.Read(p) }
func (bc *bufferConn) Write(p []byte) (int, error) { return bc.writer.Write(p) }
func (bc *bufferConn) Close() error                { return nil }

func newConn(data []byte) *Conn {
	return &Conn{conn: &bufferConn{
		reader: bytes.NewReader(data),
		writer: &bytes.Buffer{},
	}}
}

func TestReadFrame_SmallPayload(t *testing.T) {
	payload := []byte("hello")
	mask := []byte{0x37, 0xfa, 0x21, 0x3d}
	frame := buildFrame(0x1, true, true, mask, payload)
	c := newConn(frame)

	opcode, data, err := c.readFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opcode != 0x1 {
		t.Errorf("expected opcode 0x1, got 0x%x", opcode)
	}
	if string(data) != "hello" {
		t.Errorf("expected 'hello', got %q", string(data))
	}
}

func TestReadFrame_EmptyPayload(t *testing.T) {
	frame := buildFrame(0x1, true, false, nil, []byte{})
	c := newConn(frame)

	opcode, data, err := c.readFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opcode != 0x1 {
		t.Errorf("expected opcode 0x1, got 0x%x", opcode)
	}
	if len(data) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(data))
	}
}

func TestReadFrame_MediumPayload(t *testing.T) {
	payload := make([]byte, 200)
	for i := range payload {
		payload[i] = byte(i)
	}
	frame := buildFrame(0x2, true, true, []byte{0xAA, 0xBB, 0xCC, 0xDD}, payload)
	c := newConn(frame)

	opcode, data, err := c.readFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opcode != 0x2 {
		t.Errorf("expected opcode 0x2, got 0x%x", opcode)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("payload mismatch: expected %d bytes, got %d bytes", len(payload), len(data))
	}
}

func TestReadFrame_LargePayload(t *testing.T) {
	// Test that a payload within the 16KB limit can be read
	payload := make([]byte, 15*1024) // 15KB — under the 16KB limit
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	frame := buildFrame(0x1, true, false, nil, payload)
	c := newConn(frame)

	opcode, data, err := c.readFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opcode != 0x1 {
		t.Errorf("expected opcode 0x1, got 0x%x", opcode)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("payload mismatch")
	}
}

func TestReadFrame_TooLarge(t *testing.T) {
	// Build a frame claiming > 16KB payload
	buf := []byte{0x81, 0x7F} // FIN + text, 127 = 64-bit length
	lenBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBytes, 16*1024+1) // 16KB + 1
	buf = append(buf, lenBytes...)

	c := newConn(buf)
	_, _, err := c.readFrame()
	if err == nil || err.Error() != "websocket: frame too large" {
		t.Errorf("expected frame too large error, got %v", err)
	}
}

func TestReadFrame_TruncatedHeader(t *testing.T) {
	c := newConn([]byte{0x81}) // Only 1 byte, need 2
	_, _, err := c.readFrame()
	if err == nil {
		t.Error("expected error for truncated header")
	}
}

func TestReadFrame_UnmaskedPayload(t *testing.T) {
	payload := []byte("test data")
	frame := buildFrame(0x1, true, false, nil, payload)
	c := newConn(frame)

	_, data, err := c.readFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "test data" {
		t.Errorf("expected 'test data', got %q", string(data))
	}
}

// ============================================================================
// WriteMessage
// ============================================================================

func TestWriteMessage_SmallPayload(t *testing.T) {
	buf := &bytes.Buffer{}
	c := &Conn{conn: &bufferConn{reader: strings.NewReader(""), writer: buf}}

	err := c.WriteMessage(1, []byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data := buf.Bytes()
	// FIN + opcode 1
	if data[0] != 0x81 {
		t.Errorf("expected first byte 0x81, got 0x%x", data[0])
	}
	// Length = 5, no mask
	if data[1] != 5 {
		t.Errorf("expected length 5, got %d", data[1])
	}
	if string(data[2:]) != "hello" {
		t.Errorf("expected 'hello', got %q", string(data[2:]))
	}
}

func TestWriteMessage_MediumPayload(t *testing.T) {
	buf := &bytes.Buffer{}
	c := &Conn{conn: &bufferConn{reader: strings.NewReader(""), writer: buf}}

	payload := make([]byte, 200)
	err := c.WriteMessage(2, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data := buf.Bytes()
	// FIN + opcode 2
	if data[0] != 0x82 {
		t.Errorf("expected first byte 0x82, got 0x%x", data[0])
	}
	// Extended length marker
	if data[1] != 126 {
		t.Errorf("expected 126 length marker, got %d", data[1])
	}
	// 16-bit length
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length != 200 {
		t.Errorf("expected length 200, got %d", length)
	}
}

func TestWriteMessage_LargePayload(t *testing.T) {
	buf := &bytes.Buffer{}
	c := &Conn{conn: &bufferConn{reader: strings.NewReader(""), writer: buf}}

	payload := make([]byte, 70000)
	err := c.WriteMessage(1, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data := buf.Bytes()
	if data[0] != 0x81 {
		t.Errorf("expected first byte 0x81, got 0x%x", data[0])
	}
	if data[1] != 127 {
		t.Errorf("expected 127 length marker, got %d", data[1])
	}
	length := int(binary.BigEndian.Uint64(data[2:10]))
	if length != 70000 {
		t.Errorf("expected length 70000, got %d", length)
	}
}

func TestWriteMessage_Empty(t *testing.T) {
	buf := &bytes.Buffer{}
	c := &Conn{conn: &bufferConn{reader: strings.NewReader(""), writer: buf}}

	err := c.WriteMessage(1, []byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data := buf.Bytes()
	if data[0] != 0x81 {
		t.Errorf("expected first byte 0x81, got 0x%x", data[0])
	}
	if data[1] != 0 {
		t.Errorf("expected length 0, got %d", data[1])
	}
	if len(data) != 2 {
		t.Errorf("expected 2 bytes total, got %d", len(data))
	}
}

// ============================================================================
// ReadMessage — control frame handling
// ============================================================================

func TestReadMessage_PingAutoPong(t *testing.T) {
	pingFrame := buildFrame(0x9, true, false, nil, []byte("ping"))
	// Follow with a text frame so ReadMessage returns
	textFrame := buildFrame(0x1, true, true, []byte{1, 2, 3, 4}, []byte("data"))
	c := newConn(append(pingFrame, textFrame...))

	msgType, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != 1 {
		t.Errorf("expected text message type 1, got %d", msgType)
	}
	if string(data) != "data" {
		t.Errorf("expected 'data', got %q", string(data))
	}

	// Check that pong was written
	bc := c.conn.(*bufferConn)
	pong := bc.writer.Bytes()
	if len(pong) < 2 {
		t.Fatal("expected pong frame to be written")
	}
	if pong[0]&0x0F != 0xA {
		t.Errorf("expected pong opcode 0xA, got 0x%x", pong[0]&0x0F)
	}
}

func TestReadMessage_PongDiscarded(t *testing.T) {
	pongFrame := buildFrame(0xA, true, false, nil, []byte("pong"))
	textFrame := buildFrame(0x1, true, false, nil, []byte("after"))
	c := newConn(append(pongFrame, textFrame...))

	msgType, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != 1 {
		t.Errorf("expected text message, got type %d", msgType)
	}
	if string(data) != "after" {
		t.Errorf("expected 'after', got %q", string(data))
	}
}

func TestReadMessage_CloseFrame(t *testing.T) {
	closeFrame := buildFrame(0x8, true, false, nil, []byte{0x03, 0xE8}) // 1000
	c := newConn(closeFrame)

	msgType, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != 8 {
		t.Errorf("expected close type 8, got %d", msgType)
	}
	if len(data) != 2 {
		t.Errorf("expected 2-byte close payload, got %d", len(data))
	}
}

func TestReadMessage_BinaryMessage(t *testing.T) {
	payload := []byte{0x00, 0x01, 0x02, 0xFF}
	frame := buildFrame(0x2, true, false, nil, payload)
	c := newConn(frame)

	msgType, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != 2 {
		t.Errorf("expected binary type 2, got %d", msgType)
	}
	if !bytes.Equal(data, payload) {
		t.Error("payload mismatch")
	}
}

// ============================================================================
// Round-trip: write then read
// ============================================================================

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	writer := &Conn{conn: &bufferConn{reader: strings.NewReader(""), writer: &buf}}

	original := []byte("round-trip test")
	if err := writer.WriteMessage(1, original); err != nil {
		t.Fatalf("write error: %v", err)
	}

	// Client would mask the frame, simulate that
	wireData := buf.Bytes()
	// Re-parse: skip FIN+opcode byte, check it's unmasked (server->client)
	reader := &Conn{conn: &bufferConn{reader: bytes.NewReader(wireData), writer: &bytes.Buffer{}}}

	opcode, data, err := reader.readFrame()
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if opcode != 0x1 {
		t.Errorf("expected opcode 0x1, got 0x%x", opcode)
	}
	if !bytes.Equal(data, original) {
		t.Errorf("expected %q, got %q", original, data)
	}
}

// ============================================================================
// Masking edge cases
// ============================================================================

func TestMasking_NonAlignedPayload(t *testing.T) {
	// Payload length not multiple of 4 — tests mask wrapping
	payload := []byte{1, 2, 3, 4, 5, 6, 7} // 7 bytes
	mask := []byte{0xFF, 0x00, 0xFF, 0x00}

	frame := buildFrame(0x1, true, true, mask, payload)
	c := newConn(frame)

	_, data, err := c.readFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("masking roundtrip failed: expected %v, got %v", payload, data)
	}
}

// ============================================================================
// Handshake validation (without full HTTP hijack)
// ============================================================================

func TestHandshake_NotWebSocketRequest(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/ws", nil)

	conn, err := Handshake(w, r)
	if conn != nil {
		t.Error("expected nil conn")
	}
	if !errors.Is(err, ErrNotWebSocket) {
		t.Errorf("expected ErrNotWebSocket, got %v", err)
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandshake_MissingKey(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	// No Sec-WebSocket-Key

	conn, err := Handshake(w, r)
	if conn != nil {
		t.Error("expected nil conn")
	}
	if !errors.Is(err, ErrNotWebSocket) {
		t.Errorf("expected ErrNotWebSocket, got %v", err)
	}
}

// ============================================================================
// Conn.Close
// ============================================================================

func TestConn_Close(t *testing.T) {
	c := newConn([]byte{})
	if err := c.Close(); err != nil {
		t.Errorf("unexpected close error: %v", err)
	}
}

// ============================================================================
// SetReadDeadline
// ============================================================================

func TestSetReadDeadline_NoNetConn(t *testing.T) {
	// bufferConn does not implement net.Conn, so SetReadDeadline should fail
	c := newConn([]byte{})
	err := c.SetReadDeadline(time.Now().Add(time.Second))
	if err == nil {
		t.Error("expected error when underlying conn does not support net.Conn")
	}
	if err != nil && err.Error() != "websocket: underlying connection does not support deadlines" {
		t.Errorf("unexpected error: %v", err)
	}
}
