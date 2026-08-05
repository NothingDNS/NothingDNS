// Package websocket implements a minimal RFC 6455 WebSocket server
// using only Go standard library. No external dependencies.
package websocket

import (
	"crypto/sha1" // #nosec G505 -- SHA-1 is mandatory for WebSocket handshake (RFC 6455 §1.3)
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/nothingdns/nothingdns/internal/util"
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
	// MaxFragmentationSize is the maximum size of a reassembled fragmented message.
	// DNS messages are at most 65535 bytes; 64KB provides ample room.
	MaxFragmentationSize = 65536
)

// IsWebSocketRequest checks if the request is a WebSocket upgrade.
func IsWebSocketRequest(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		headerHasToken(r.Header.Get("Connection"), "upgrade")
}

func headerHasToken(header string, token string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

// Handshake performs the WebSocket upgrade handshake. On success the response
// writer has been hijacked and the caller can use ReadMessage/WriteMessage.
// If allowedOrigins is non-empty, the Origin header is validated against the list.
// If allowedOrigins is empty and an Origin header is present, only same-origin
// browser upgrades are accepted.
func Handshake(w http.ResponseWriter, r *http.Request, allowedOrigins ...string) (*Conn, error) {
	if !IsWebSocketRequest(r) {
		http.Error(w, "not a websocket request", http.StatusBadRequest)
		return nil, ErrNotWebSocket
	}

	// Validate Origin — fail closed: reject cross-site origins when not explicitly configured
	origin := r.Header.Get("Origin")
	if origin != "" {
		if len(allowedOrigins) == 0 {
			if !isSameOrigin(origin, r) {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return nil, errors.New("websocket: origin not allowed")
			}
		} else if !isOriginAllowed(origin, allowedOrigins) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return nil, errors.New("websocket: origin not allowed")
		}
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, ErrNotWebSocket
	}
	if decoded, err := base64.StdEncoding.DecodeString(key); err != nil || len(decoded) != 16 {
		http.Error(w, "invalid Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, ErrNotWebSocket
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "unsupported Sec-WebSocket-Version", http.StatusBadRequest)
		return nil, ErrNotWebSocket
	}

	// Compute accept value
	h := sha1.New() // #nosec G401,G505 -- WebSocket handshake requires SHA-1 (RFC 6455 §1.3)
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
	if err := util.WriteFull(conn, []byte(response)); err != nil {
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

func isSameOrigin(origin string, r *http.Request) bool {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return origin == scheme+"://"+r.Host
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
	mu         sync.Mutex // protects fragmented state during reads
	fragmented bool       // true if we're reading a fragmented message
	fragType   int        // message type (1=text, 2=binary) for fragmented message
	fragAccum  []byte     // accumulated payload for fragmented message

	// Rate limiting
	rateWindow time.Time
	rateCount  int
	rateMax    int
	rateDur    time.Duration
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
//
// Reads/writes the rate-limit fields under c.mu — SetRateLimit
// holds c.mu while resetting these same fields, and ReadMessage
// releases c.mu before calling us (to avoid holding the lock
// across I/O). Without locking here, the post-unlock checkRateLimit
// raced with any operator-initiated SetRateLimit on the same Conn:
// rateMax could be read as the old value while rateWindow/rateCount
// were already reset, or rateCount could overflow past the new
// rateMax without being noticed. Take the lock for the brief
// state mutation.
func (c *Conn) checkRateLimit() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rateMax == 0 {
		return true
	}
	now := time.Now()
	if wsRateWindowExpiredAt(c.rateWindow, now, c.rateDur) {
		c.rateWindow = now
		c.rateCount = 1
		return true
	}
	c.rateCount++
	return c.rateCount <= c.rateMax
}

func wsRateWindowExpiredAt(windowStart, now time.Time, window time.Duration) bool {
	return !now.Before(windowStart.Add(window))
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
				err := errors.New("websocket: unexpected continuation frame")
				return 0, nil, errors.Join(err, c.writeClose(1002, "protocol error"))
			}
			if len(c.fragAccum)+len(payload) > MaxFragmentationSize {
				c.fragmented = false
				c.fragAccum = nil
				c.mu.Unlock()
				err := errors.New("websocket: fragmented message exceeds size limit")
				return 0, nil, errors.Join(err, c.writeClose(1009, "message too large"))
			}
			c.fragAccum = append(c.fragAccum, payload...)
			if fin {
				msgType := c.fragType
				msg := c.fragAccum
				c.fragmented = false
				c.fragType = 0
				c.fragAccum = nil
				c.mu.Unlock()
				if msgType == 1 && !utf8.Valid(msg) {
					err := errors.New("websocket: invalid text payload")
					return 0, nil, errors.Join(err, c.writeClose(1007, "invalid text payload"))
				}
				// Check rate limit before returning
				if !c.checkRateLimit() {
					err := errors.New("websocket: rate limit exceeded")
					return 0, nil, errors.Join(err, c.writeClose(1008, "rate limit exceeded"))
				}
				return msgType, msg, nil
			}
			c.mu.Unlock()

		case 0x1: // text
			if c.fragmented {
				c.fragmented = false
				c.fragType = 0
				c.fragAccum = nil
				c.mu.Unlock()
				err := errors.New("websocket: data frame received before fragmented message complete")
				return 0, nil, errors.Join(err, c.writeClose(1002, "protocol error"))
			}
			if fin {
				c.mu.Unlock()
				if !utf8.Valid(payload) {
					err := errors.New("websocket: invalid text payload")
					return 0, nil, errors.Join(err, c.writeClose(1007, "invalid text payload"))
				}
				// Check rate limit before returning
				if !c.checkRateLimit() {
					err := errors.New("websocket: rate limit exceeded")
					return 0, nil, errors.Join(err, c.writeClose(1008, "rate limit exceeded"))
				}
				return 1, payload, nil
			}
			c.fragmented = true
			c.fragType = 1
			if len(payload) > MaxFragmentationSize {
				c.fragmented = false
				c.fragAccum = nil
				c.mu.Unlock()
				err := errors.New("websocket: fragmented message exceeds size limit")
				return 0, nil, errors.Join(err, c.writeClose(1009, "message too large"))
			}
			c.fragAccum = append(c.fragAccum, payload...)
			c.mu.Unlock()

		case 0x2: // binary
			if c.fragmented {
				c.fragmented = false
				c.fragType = 0
				c.fragAccum = nil
				c.mu.Unlock()
				err := errors.New("websocket: data frame received before fragmented message complete")
				return 0, nil, errors.Join(err, c.writeClose(1002, "protocol error"))
			}
			if fin {
				c.mu.Unlock()
				// Check rate limit before returning
				if !c.checkRateLimit() {
					err := errors.New("websocket: rate limit exceeded")
					return 0, nil, errors.Join(err, c.writeClose(1008, "rate limit exceeded"))
				}
				return 2, payload, nil
			}
			c.fragmented = true
			c.fragType = 2
			if len(payload) > MaxFragmentationSize {
				c.fragmented = false
				c.fragAccum = nil
				c.mu.Unlock()
				err := errors.New("websocket: fragmented message exceeds size limit")
				return 0, nil, errors.Join(err, c.writeClose(1009, "message too large"))
			}
			c.fragAccum = append(c.fragAccum, payload...)
			c.mu.Unlock()

		case 0x8: // close
			c.mu.Unlock()
			return 8, payload, nil

		case 0x9: // ping - respond with pong
			// Note: WriteMessage will block, holding the lock
			// This is intentional - we don't want concurrent writes
			c.mu.Unlock() // Release before blocking write
			if err := c.WriteMessage(0xA, payload); err != nil {
				return 0, nil, err
			}

		case 0xA: // pong - ignore
			c.mu.Unlock()

		default:
			c.mu.Unlock()
			err := errors.New("websocket: invalid opcode")
			return 0, nil, errors.Join(err, c.writeClose(1002, "protocol error"))
		}
	}
}

// writeClose sends a close frame with the given code and reason.
func (c *Conn) writeClose(code int, reason string) error {
	if code < 0 || code > 65535 || !isValidCloseCode(uint16(code)) {
		return errors.New("websocket: invalid close code")
	}
	if !utf8.ValidString(reason) {
		return errors.New("websocket: invalid close reason")
	}
	reason = truncateCloseReason(reason)
	buf := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(buf[:2], uint16(code))
	copy(buf[2:], reason)

	var frame []byte
	frame = append(frame, byte(0x80|0x8)) // FIN + close opcode
	frame = append(frame, byte(len(buf)))
	frame = append(frame, buf...)
	return util.WriteFull(c.conn, frame)
}

func truncateCloseReason(reason string) string {
	const maxCloseReasonBytes = 123 // close code takes 2 bytes; control payload max is 125.
	if len(reason) <= maxCloseReasonBytes {
		return reason
	}

	end := 0
	for i := range reason {
		if i > maxCloseReasonBytes {
			break
		}
		end = i
	}
	if end == 0 {
		return ""
	}
	return reason[:end]
}

// WriteMessage writes a message to the connection.
func (c *Conn) WriteMessage(messageType int, data []byte) error {
	if err := validateServerMessageType(messageType, data); err != nil {
		return err
	}

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
	return util.WriteFull(c.conn, buf)
}

func validateServerMessageType(messageType int, payload []byte) error {
	switch messageType {
	case 0x1:
		if !utf8.Valid(payload) {
			return errors.New("websocket: invalid text payload")
		}
		return nil
	case 0x2:
		return nil
	case 0x8, 0x9, 0xA:
		if len(payload) > 125 {
			return errors.New("websocket: control frame too large")
		}
		if messageType == 0x8 {
			if err := validateClosePayload(payload); err != nil {
				return err
			}
		}
		return nil
	default:
		return errors.New("websocket: invalid message type")
	}
}

// readFrame reads a single WebSocket frame.
func (c *Conn) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	// Read first 2 bytes
	header := make([]byte, 2)
	if _, err = io.ReadFull(c.conn, header); err != nil {
		return false, 0, nil, err
	}

	if header[0]&0x70 != 0 {
		return false, 0, nil, errors.New("websocket: reserved bits set")
	}
	fin = (header[0] & 0x80) != 0
	opcode = header[0] & 0x0F
	masked := (header[1] & 0x80) != 0
	payloadLen := int(header[1] & 0x7F)

	if !masked {
		return false, 0, nil, errors.New("websocket: client frame not masked")
	}

	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(c.conn, ext); err != nil {
			return false, 0, nil, err
		}
		payloadLen = int(binary.BigEndian.Uint16(ext))
		if payloadLen < 126 {
			return false, 0, nil, errors.New("websocket: non-minimal payload length")
		}
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(c.conn, ext); err != nil {
			return false, 0, nil, err
		}
		raw := binary.BigEndian.Uint64(ext)
		if raw < 65536 {
			return false, 0, nil, errors.New("websocket: non-minimal payload length")
		}
		// L-1: bound the uint64 BEFORE narrowing to int. On 64-bit
		// platforms `int(uint64)` for values ≥ 2^63 sign-flips to a
		// negative number; the `> 16*1024` check below then sees a
		// negative value and passes, and make([]byte, N) panics with
		// "makeslice: len out of range". RFC 6455 also says the MSB
		// MUST be zero, so reject the whole upper half plus anything
		// above our frame cap in one check.
		const maxFrame = 16 * 1024
		if raw > maxFrame {
			return false, 0, nil, errors.New("websocket: frame too large")
		}
		payloadLen = int(raw)
	}

	if payloadLen > 16*1024 { // 16KB max frame (DNS messages are typically < 4KB)
		return false, 0, nil, errors.New("websocket: frame too large")
	}
	if opcode >= 0x8 {
		if !fin {
			return false, 0, nil, errors.New("websocket: fragmented control frame")
		}
		if payloadLen > 125 {
			return false, 0, nil, errors.New("websocket: control frame too large")
		}
		if opcode == 0x8 && payloadLen == 1 {
			return false, 0, nil, errors.New("websocket: invalid close frame payload")
		}
	}

	payload = make([]byte, payloadLen)

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
	if opcode == 0x8 {
		if err := validateClosePayload(payload); err != nil {
			return false, 0, nil, err
		}
	}

	return fin, opcode, payload, nil
}

func validateClosePayload(payload []byte) error {
	if len(payload) == 1 {
		return errors.New("websocket: invalid close frame payload")
	}
	if len(payload) >= 2 {
		if !isValidCloseCode(binary.BigEndian.Uint16(payload[:2])) {
			return errors.New("websocket: invalid close code")
		}
		if !utf8.Valid(payload[2:]) {
			return errors.New("websocket: invalid close reason")
		}
	}
	return nil
}

func isValidCloseCode(code uint16) bool {
	if code < 1000 || code > 4999 {
		return false
	}
	switch code {
	case 1004, 1005, 1006, 1015:
		return false
	}
	if code >= 1016 && code <= 2999 {
		return false
	}
	return true
}
