// Package websocket implements a minimal RFC 6455 WebSocket server
// using only Go standard library. No external dependencies.
package websocket

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// WebSocket GUID per RFC 6455 Section 4.2.1.5
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// ErrNotWebSocket is returned when the request is not a valid WebSocket upgrade.
var ErrNotWebSocket = errors.New("websocket: not a websocket request")

// IsWebSocketRequest checks if the request is a WebSocket upgrade.
func IsWebSocketRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// Handshake performs the WebSocket upgrade handshake. On success the response
// writer has been hijacked and the caller can use ReadMessage/WriteMessage.
func Handshake(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if !IsWebSocketRequest(r) {
		http.Error(w, "not a websocket request", http.StatusBadRequest)
		return nil, ErrNotWebSocket
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, ErrNotWebSocket
	}

	// Compute accept value
	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte(wsGUID))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket: cannot hijack", http.StatusInternalServerError)
		return nil, errors.New("websocket: response writer cannot hijack")
	}

	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	// Write handshake response
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := conn.Write([]byte(response)); err != nil {
		conn.Close()
		return nil, err
	}

	// Drain any buffered data from the bufio reader.
	// Only read what's already buffered — don't block on the network.
	if brw.Reader.Buffered() > 0 {
		n := brw.Reader.Buffered()
		drain := make([]byte, n)
		if _, err := io.ReadFull(brw.Reader, drain); err != nil {
			// Best effort — don't fail the handshake
			_ = err
		}
	}

	return &Conn{conn: conn}, nil
}

// Conn represents a WebSocket connection.
type Conn struct {
	conn io.ReadWriteCloser
}

// Close closes the underlying connection.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// SetReadDeadline sets the read deadline on the underlying connection.
// Returns an error if the underlying connection does not support deadlines.
func (c *Conn) SetReadDeadline(t time.Time) error {
	if nc, ok := c.conn.(net.Conn); ok {
		return nc.SetReadDeadline(t)
	}
	return errors.New("websocket: underlying connection does not support deadlines")
}

// ReadMessage reads a single text or binary message.
// Returns messageType (1=text, 2=binary), payload, error.
func (c *Conn) ReadMessage() (int, []byte, error) {
	for {
		opcode, payload, err := c.readFrame()
		if err != nil {
			return 0, nil, err
		}

		switch opcode {
		case 0x0: // continuation - discard (fragmented messages not supported)
			// Fragmented messages are not expected in dashboard usage.
			// Discard continuation frames and continue reading.
		case 0x1: // text
			return 1, payload, nil
		case 0x2: // binary
			return 2, payload, nil
		case 0x8: // close
			return 8, payload, nil
		case 0x9: // ping - respond with pong
			_ = c.WriteMessage(0xA, payload)
		case 0xA: // pong - ignore
		}
	}
}

// WriteMessage writes a message to the connection.
func (c *Conn) WriteMessage(messageType int, data []byte) error {
	var buf []byte

	// FIN bit + opcode
	buf = append(buf, byte(0x80|messageType))

	// No mask for server -> client
	length := len(data)
	switch {
	case length <= 125:
		buf = append(buf, byte(length))
	case length <= 65535:
		buf = append(buf, 126)
		buf = append(buf, byte(length>>8), byte(length))
	default:
		buf = append(buf, 127)
		for i := 7; i >= 0; i-- {
			buf = append(buf, byte(length>>(i*8)))
		}
	}

	buf = append(buf, data...)
	_, err := c.conn.Write(buf)
	return err
}

// readFrame reads a single WebSocket frame.
func (c *Conn) readFrame() (opcode byte, payload []byte, err error) {
	// Read first 2 bytes
	header := make([]byte, 2)
	if _, err = io.ReadFull(c.conn, header); err != nil {
		return 0, nil, err
	}

	opcode = header[0] & 0x0F
	masked := (header[1] & 0x80) != 0
	payloadLen := int(header[1] & 0x7F)

	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(c.conn, ext); err != nil {
			return 0, nil, err
		}
		payloadLen = int(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(c.conn, ext); err != nil {
			return 0, nil, err
		}
		payloadLen = int(binary.BigEndian.Uint64(ext))
	}

	if payloadLen > 1<<20 { // 1MB max frame
		return 0, nil, errors.New("websocket: frame too large")
	}

	payload = make([]byte, payloadLen)

	// Unmask if needed (client -> server frames must be masked)
	if masked {
		mask := make([]byte, 4)
		if _, err = io.ReadFull(c.conn, mask); err != nil {
			return 0, nil, err
		}
		if payloadLen > 0 {
			if _, err = io.ReadFull(c.conn, payload); err != nil {
				return 0, nil, err
			}
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}
	} else if payloadLen > 0 {
		if _, err = io.ReadFull(c.conn, payload); err != nil {
			return 0, nil, err
		}
	}

	return opcode, payload, nil
}
