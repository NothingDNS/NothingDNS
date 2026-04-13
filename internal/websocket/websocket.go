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
	"sync"
	"time"
)

// WebSocket GUID per RFC 6455 Section 4.2.1.5
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// ErrNotWebSocket is returned when the request is not a valid WebSocket upgrade.
var ErrNotWebSocket = errors.New("websocket: not a websocket request")

// WebSocket rate limiting defaults.
const (
	// DefaultWSRateLimitWindow is the sliding window for per-connection rate limiting.
	DefaultWSRateLimitWindow = time.Second
	// DefaultWSRateLimitMaxMessages is the maximum messages per connection per window.
	DefaultWSRateLimitMaxMessages = 100
)

// IsWebSocketRequest checks if the request is a WebSocket upgrade.
func IsWebSocketRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// Handshake performs the WebSocket upgrade handshake. On success the response
// writer has been hijacked and the caller can use ReadMessage/WriteMessage.
// If allowedOrigins is non-empty, the Origin header is validated against the list.
// If allowedOrigins is empty and an Origin header is present, the connection is
// rejected to prevent cross-site WebSocket hijacking.
func Handshake(w http.ResponseWriter, r *http.Request, allowedOrigins ...string) (*Conn, error) {
	if !IsWebSocketRequest(r) {
		http.Error(w, "not a websocket request", http.StatusBadRequest)
		return nil, ErrNotWebSocket
	}

	// Validate Origin — fail closed: reject cross-site origins when not explicitly configured
	origin := r.Header.Get("Origin")
	if origin != "" {
		if len(allowedOrigins) == 0 {
			http.Error(w, "origin not allowed: configure allowed origins", http.StatusForbidden)
			return nil, errors.New("websocket: origin rejected — no allowed origins configured")
		}
		if !isOriginAllowed(origin, allowedOrigins) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return nil, errors.New("websocket: origin not allowed")
		}
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

// isOriginAllowed checks if the origin matches the allowed list.
// Wildcard "*" is not allowed — it must be an explicit origin match.
func isOriginAllowed(origin string, allowedOrigins []string) bool {
	for _, o := range allowedOrigins {
		if o == origin {
			return true
		}
	}
	return false
}

// Conn represents a WebSocket connection.
type Conn struct {
	conn       io.ReadWriteCloser
	mu         sync.Mutex   // protects fragmented state during reads
	fragmented bool         // true if we're reading a fragmented message
	fragType   int          // message type (1=text, 2=binary) for fragmented message
	fragAccum  []byte       // accumulated payload for fragmented message

	// Rate limiting
	rateWindow  time.Time
	rateCount   int
	rateMax     int
	rateDur     time.Duration
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

// SetWriteDeadline sets the write deadline on the underlying connection.
// Returns an error if the underlying connection does not support deadlines.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if nc, ok := c.conn.(net.Conn); ok {
		return nc.SetWriteDeadline(t)
	}
	return errors.New("websocket: underlying connection does not support deadlines")
}

// SetRateLimit configures per-connection message rate limiting.
// Use maxMessages <= 0 to disable.
func (c *Conn) SetRateLimit(maxMessages int, window time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if maxMessages <= 0 {
		c.rateMax = 0 // disabled
		return
	}
	c.rateMax = maxMessages
	c.rateDur = window
	c.rateWindow = time.Now()
	c.rateCount = 0
}

// checkRateLimit returns true if the connection is within rate limits.
func (c *Conn) checkRateLimit() bool {
	if c.rateMax == 0 {
		return true
	}
	now := time.Now()
	if now.Sub(c.rateWindow) > c.rateDur {
		c.rateWindow = now
		c.rateCount = 1
		return true
	}
	c.rateCount++
	return c.rateCount <= c.rateMax
}

// ReadMessage reads a single text or binary message.
// Returns messageType (1=text, 2=binary), payload, error.
func (c *Conn) ReadMessage() (int, []byte, error) {
	for {
		// Read frame (may block, so we don't hold the lock during I/O)
		fin, opcode, payload, err := c.readFrame()
		if err != nil {
			return 0, nil, err
		}

		// Lock for fragmented state modification
		c.mu.Lock()

		switch opcode {
		case 0x0: // continuation
			if !c.fragmented {
				c.mu.Unlock()
				continue
			}
			c.fragAccum = append(c.fragAccum, payload...)
			if fin {
				msgType := c.fragType
				msg := c.fragAccum
				c.fragmented = false
				c.fragType = 0
				c.fragAccum = nil
				c.mu.Unlock()
				// Check rate limit before returning
				if !c.checkRateLimit() {
					c.writeClose(1008, "rate limit exceeded")
					return 0, nil, errors.New("websocket: rate limit exceeded")
				}
				return msgType, msg, nil
			}
			c.mu.Unlock()

		case 0x1: // text
			if fin {
				c.mu.Unlock()
				// Check rate limit before returning
				if !c.checkRateLimit() {
					c.writeClose(1008, "rate limit exceeded")
					return 0, nil, errors.New("websocket: rate limit exceeded")
				}
				return 1, payload, nil
			}
			if c.fragmented {
				c.mu.Unlock()
				continue
			}
			c.fragmented = true
			c.fragType = 1
			c.fragAccum = append(c.fragAccum, payload...)
			c.mu.Unlock()

		case 0x2: // binary
			if fin {
				c.mu.Unlock()
				// Check rate limit before returning
				if !c.checkRateLimit() {
					c.writeClose(1008, "rate limit exceeded")
					return 0, nil, errors.New("websocket: rate limit exceeded")
				}
				return 2, payload, nil
			}
			if c.fragmented {
				c.mu.Unlock()
				continue
			}
			c.fragmented = true
			c.fragType = 2
			c.fragAccum = append(c.fragAccum, payload...)
			c.mu.Unlock()

		case 0x8: // close
			c.mu.Unlock()
			return 8, payload, nil

		case 0x9: // ping - respond with pong
			// Note: WriteMessage will block, holding the lock
			// This is intentional - we don't want concurrent writes
			c.mu.Unlock() // Release before blocking write
			_ = c.WriteMessage(0xA, payload)

		case 0xA: // pong - ignore
			c.mu.Unlock()
		}
	}
}

// writeClose sends a close frame with the given code and reason.
func (c *Conn) writeClose(code int, reason string) {
	buf := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(buf[:2], uint16(code))
	copy(buf[2:], reason)

	var frame []byte
	frame = append(frame, byte(0x80|0x8)) // FIN + close opcode
	length := len(buf)
	switch {
	case length <= 125:
		frame = append(frame, byte(length))
	default:
		frame = append(frame, 126)
		frame = append(frame, byte(length>>8), byte(length))
	}
	frame = append(frame, buf...)
	c.conn.Write(frame)
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
func (c *Conn) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	// Read first 2 bytes
	header := make([]byte, 2)
	if _, err = io.ReadFull(c.conn, header); err != nil {
		return false, 0, nil, err
	}

	fin = (header[0] & 0x80) != 0
	opcode = header[0] & 0x0F
	masked := (header[1] & 0x80) != 0
	payloadLen := int(header[1] & 0x7F)

	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(c.conn, ext); err != nil {
			return false, 0, nil, err
		}
		payloadLen = int(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(c.conn, ext); err != nil {
			return false, 0, nil, err
		}
		payloadLen = int(binary.BigEndian.Uint64(ext))
	}

	if payloadLen > 16*1024 { // 16KB max frame (DNS messages are typically < 4KB)
		return false, 0, nil, errors.New("websocket: frame too large")
	}

	payload = make([]byte, payloadLen)

	// Unmask if needed (client -> server frames must be masked)
	if masked {
		mask := make([]byte, 4)
		if _, err = io.ReadFull(c.conn, mask); err != nil {
			return false, 0, nil, err
		}
		if payloadLen > 0 {
			if _, err = io.ReadFull(c.conn, payload); err != nil {
				return false, 0, nil, err
			}
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}
	} else if payloadLen > 0 {
		if _, err = io.ReadFull(c.conn, payload); err != nil {
			return false, 0, nil, err
		}
	}

	return fin, opcode, payload, nil
}
