package doh

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ============================================================================
// WSHandler.ServeHTTP — end-to-end coverage over real RFC 6455 frames.
//
// internal/websocket exposes only the server side, so these tests drive the
// handler with a minimal hand-rolled client: masked client→server frames and
// unmasked server→client parsing, per RFC 6455 §5.3. Each test targets one
// ServeHTTP branch: close-frame exit, non-binary skip, invalid-DNS skip,
// no-question skip, and the full query→answer loop.
// ============================================================================

// wsTestClient is a minimal RFC 6455 client connected to the handler.
type wsTestClient struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
	srv  *httptest.Server
}

// dialDoWS starts an httptest server around the handler and upgrades to
// WebSocket. Each invocation gets a fresh server, so tests are independent.
func dialDoWS(t *testing.T, h *WSHandler) *wsTestClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// Extract host:port from the httptest URL.
	addr := srv.Listener.Addr().String()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatalf("rand: %v", err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	req := "GET /dns-query HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if want := "101"; !strings.Contains(line, want) {
		t.Fatalf("upgrade status = %q, want 101", line)
	}
	// Drain remaining handshake headers.
	for {
		hdr, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if hdr == "\r\n" || hdr == "\n" {
			break
		}
	}

	return &wsTestClient{t: t, conn: conn, br: br, srv: srv}
}

// writeMaskedFrame sends a client→server frame. All client frames MUST be
// masked (RFC 6455 §5.3); the server rejects unmasked ones.
func (c *wsTestClient) writeMaskedFrame(opcode byte, payload []byte) {
	c.t.Helper()
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		c.t.Fatalf("rand mask: %v", err)
	}

	buf := []byte{0x80 | opcode} // FIN + opcode
	n := len(payload)
	switch {
	case n < 126:
		buf = append(buf, byte(0x80|n))
	case n <= 0xffff:
		buf = append(buf, 0x80|126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		buf = append(buf, ext[:]...)
	default:
		c.t.Fatalf("payload too large for test client: %d", n)
	}
	buf = append(buf, mask[:]...)

	masked := make([]byte, n)
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}
	buf = append(buf, masked...)

	if _, err := c.conn.Write(buf); err != nil {
		c.t.Fatalf("write frame: %v", err)
	}
}

// readServerFrame reads one server→client frame (unmasked) and returns
// opcode and payload. Returns io.EOF when the server closes.
func (c *wsTestClient) readServerFrame() (byte, []byte, error) {
	c.t.Helper()
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.br, header); err != nil {
		return 0, nil, err
	}
	opcode := header[0] & 0x0f
	length := int(header[1] & 0x7f)
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(c.br, ext); err != nil {
			return 0, nil, err
		}
		length = int(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(c.br, ext); err != nil {
			return 0, nil, err
		}
		length = int(binary.BigEndian.Uint64(ext))
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return 0, nil, err
	}
	return opcode, payload, nil
}

// TestServeHTTP_QueryLoop covers the main path: a valid DNS query binary
// frame is dispatched to the DNS handler and the answer comes back as a
// binary frame whose ID matches the query.
func TestServeHTTP_QueryLoop(t *testing.T) {
	c := dialDoWS(t, NewWSHandler(&mockDNSHandler{}, nil))

	queryData, msg := createTestQuery()
	c.writeMaskedFrame(2, queryData) // opcode 2 = binary

	op, payload, err := c.readServerFrame()
	if err != nil {
		t.Fatalf("read answer: %v", err)
	}
	if op != 2 {
		t.Fatalf("answer opcode = %d, want 2 (binary)", op)
	}

	answer, err := protocol.UnpackMessage(payload)
	if err != nil {
		t.Fatalf("unpack answer: %v", err)
	}
	defer answer.Release()
	if answer.Header.ID != msg.Header.ID {
		t.Errorf("answer ID = %d, want %d", answer.Header.ID, msg.Header.ID)
	}
	if !answer.Header.Flags.QR {
		t.Error("answer missing QR flag")
	}
}

// TestServeHTTP_CloseFrameExits covers the wsCloseMessage branch: a close
// frame (opcode 8) terminates the loop and the server closes the TCP
// connection.
func TestServeHTTP_CloseFrameExits(t *testing.T) {
	c := dialDoWS(t, NewWSHandler(&mockDNSHandler{}, nil))

	c.writeMaskedFrame(8, nil) // opcode 8 = close

	// The handler must return (and close the conn) rather than hang. The
	// read deadline in ServeHTTP is 30s, so use a shorter client deadline.
	_ = c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := c.readServerFrame(); err == nil {
		t.Error("expected connection close after close frame")
	}
}

// TestServeHTTP_TextFrameSkipped covers the non-binary skip branch: a text
// frame (opcode 1) is ignored, the loop continues, and a subsequent valid
// query still gets answered.
func TestServeHTTP_TextFrameSkipped(t *testing.T) {
	c := dialDoWS(t, NewWSHandler(&mockDNSHandler{}, nil))

	c.writeMaskedFrame(1, []byte("not a dns message")) // text — skipped
	c.writeMaskedFrame(1, []byte("still not dns"))     // skipped again
	c.writeMaskedFrame(2, createTestQueryBytes(t))     // binary — answered

	op, payload, err := c.readServerFrame()
	if err != nil {
		t.Fatalf("read answer after text frames: %v", err)
	}
	if op != 2 {
		t.Fatalf("answer opcode = %d, want 2", op)
	}
	if _, err := protocol.UnpackMessage(payload); err != nil {
		t.Fatalf("unpack answer: %v", err)
	}
}

// TestServeHTTP_InvalidDNSSkipped covers the unpack-error branch: a binary
// frame containing garbage is skipped without killing the connection, and
// the loop continues to serve the next query.
func TestServeHTTP_InvalidDNSSkipped(t *testing.T) {
	c := dialDoWS(t, NewWSHandler(&mockDNSHandler{}, nil))

	garbage := make([]byte, 64)
	_, _ = rand.Read(garbage)
	c.writeMaskedFrame(2, garbage)                 // invalid DNS — skipped
	c.writeMaskedFrame(2, createTestQueryBytes(t)) // valid — answered

	op, _, err := c.readServerFrame()
	if err != nil {
		t.Fatalf("read answer after garbage: %v", err)
	}
	if op != 2 {
		t.Fatalf("answer opcode = %d, want 2", op)
	}
}

// TestServeHTTP_NoQuestionSkipped covers the zero-question branch: a
// well-formed DNS message with no questions is released and skipped, and
// the connection stays usable.
func TestServeHTTP_NoQuestionSkipped(t *testing.T) {
	c := dialDoWS(t, NewWSHandler(&mockDNSHandler{}, nil))

	// Valid DNS message with QDCount=0 and no questions.
	noQ := &protocol.Message{
		Header: protocol.Header{
			ID:    4321,
			Flags: protocol.NewQueryFlags(),
		},
	}
	buf := make([]byte, noQ.WireLength())
	n, err := noQ.Pack(buf)
	if err != nil {
		t.Fatalf("pack no-question message: %v", err)
	}
	c.writeMaskedFrame(2, buf[:n])
	c.writeMaskedFrame(2, createTestQueryBytes(t))

	op, _, err := c.readServerFrame()
	if err != nil {
		t.Fatalf("read answer after no-question frame: %v", err)
	}
	if op != 2 {
		t.Fatalf("answer opcode = %d, want 2", op)
	}
}

// TestServeHTTP_MultipleQueriesOneConnection covers the persistent loop:
// several queries over one connection each get their own answer with the
// matching ID.
func TestServeHTTP_MultipleQueriesOneConnection(t *testing.T) {
	c := dialDoWS(t, NewWSHandler(&mockDNSHandler{}, nil))

	for i := 0; i < 3; i++ {
		q := &protocol.Message{
			Header: protocol.Header{
				ID:      uint16(1000 + i),
				Flags:   protocol.NewQueryFlags(),
				QDCount: 1,
			},
			Questions: []*protocol.Question{
				{
					Name:   mustName("www.example.com."),
					QType:  protocol.TypeA,
					QClass: protocol.ClassIN,
				},
			},
		}
		buf := make([]byte, q.WireLength())
		n, err := q.Pack(buf)
		if err != nil {
			t.Fatalf("pack query %d: %v", i, err)
		}
		c.writeMaskedFrame(2, buf[:n])

		op, payload, err := c.readServerFrame()
		if err != nil {
			t.Fatalf("read answer %d: %v", i, err)
		}
		if op != 2 {
			t.Fatalf("answer %d opcode = %d, want 2", i, op)
		}
		answer, err := protocol.UnpackMessage(payload)
		if err != nil {
			t.Fatalf("unpack answer %d: %v", i, err)
		}
		if answer.Header.ID != uint16(1000+i) {
			t.Errorf("answer %d ID = %d, want %d", i, answer.Header.ID, 1000+i)
		}
		answer.Release()
	}
}

// createTestQueryBytes builds a packed A-query for www.example.com.
func createTestQueryBytes(t *testing.T) []byte {
	t.Helper()
	data, _ := createTestQuery()
	if len(data) == 0 {
		t.Fatal("createTestQuery returned empty wire data")
	}
	return data
}
