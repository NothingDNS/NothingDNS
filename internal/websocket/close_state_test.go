// Regression tests for the close-frame write path (RFC 6455 §5.2, §5.5.1).
//
// F62: writeClose (the protocol-error close the read loop sends) wrote
// directly to the socket without writeMu, so it could be spliced into the
// middle of a data frame being emitted by a concurrent writer goroutine
// (dashboard ClientLoop topology) and corrupt the peer's frame stream.
//
// F63: Conn did not remember that a Close frame had been sent, so data
// frames were still written after it and a peer's Close reply to a
// server-initiated close was echoed a second time.

package websocket

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// gatedWriteConn holds the first Write (a data frame) half-written until a
// second writer enters Write. When writes are correctly serialized the second
// writer can never enter, so a deadline bounds the wait; the asserted outcome
// is then independent of timing because frames are intact in either order.
type gatedWriteConn struct {
	mu        sync.Mutex
	out       bytes.Buffer
	in        io.Reader
	writes    int
	firstHalf chan struct{}
	partner   chan struct{}
}

func (g *gatedWriteConn) Read(p []byte) (int, error) { return g.in.Read(p) }
func (g *gatedWriteConn) Close() error               { return nil }

func (g *gatedWriteConn) Write(p []byte) (int, error) {
	g.mu.Lock()
	g.writes++
	n := g.writes
	g.mu.Unlock()
	if n == 1 {
		h := len(p) / 2
		g.mu.Lock()
		g.out.Write(p[:h])
		g.mu.Unlock()
		close(g.firstHalf)
		select {
		case <-g.partner:
		case <-time.After(300 * time.Millisecond):
		}
		g.mu.Lock()
		g.out.Write(p[h:])
		g.mu.Unlock()
		return len(p), nil
	}
	if n == 2 {
		close(g.partner)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.out.Write(p)
}

func TestWriteClose_DoesNotInterleaveWithConcurrentDataFrame(t *testing.T) {
	cases := map[string][]byte{
		"unexpected continuation": buildClientFrame(0x0, true, nil),
		"invalid opcode":          buildClientFrame(0x3, true, nil),
	}
	for name, in := range cases {
		for _, size := range []int{1000, 16000} {
			g := &gatedWriteConn{in: bytes.NewReader(in), firstHalf: make(chan struct{}), partner: make(chan struct{})}
			c := &Conn{conn: g}
			done := make(chan error, 1)
			go func() { done <- c.WriteMessage(1, bytes.Repeat([]byte("A"), size)) }()
			<-g.firstHalf // data frame is half on the wire
			if _, _, err := c.ReadMessage(); err == nil {
				t.Fatalf("%s: ReadMessage returned nil error", name)
			}
			if err := <-done; err != nil {
				t.Fatalf("%s: WriteMessage: %v", name, err)
			}
			ops, payloads, err := parseServerFrames(g.out.Bytes())
			if err != nil || len(ops) != 2 || ops[0] != 0x1 || ops[1] != 0x8 || len(payloads[0]) != size {
				t.Fatalf("%s/%d: corrupt server stream: ops=%v err=%v", name, size, ops, err)
			}
			if code := binary.BigEndian.Uint16(payloads[1][:2]); code != 1002 {
				t.Fatalf("%s: close code = %d, want 1002", name, code)
			}
		}
	}
}

func serverOps(t *testing.T, c *Conn) []byte {
	t.Helper()
	ops, _, err := parseServerFrames(c.conn.(*bufferConn).writer.Bytes())
	if err != nil {
		t.Fatalf("parse server frames: %v", err)
	}
	return ops
}

func TestWriteMessage_RejectedAfterCloseEcho(t *testing.T) {
	c := newConn(buildClientFrame(0x8, true, []byte{0x03, 0xE8}))
	if mt, _, err := c.ReadMessage(); err != nil || mt != 8 {
		t.Fatalf("ReadMessage = (%d, %v), want (8, nil)", mt, err)
	}
	if err := c.WriteMessage(1, []byte("late")); !errors.Is(err, errCloseSent) {
		t.Fatalf("WriteMessage after close echo = %v, want errCloseSent", err)
	}
	if ops := serverOps(t, c); !bytes.Equal(ops, []byte{0x8}) {
		t.Fatalf("server frames = %v, want only the close echo", ops)
	}
}

func TestWriteMessage_RejectedAfterProtocolErrorClose(t *testing.T) {
	c := newConn(buildClientFrame(0x0, true, nil))
	if _, _, err := c.ReadMessage(); err == nil {
		t.Fatal("expected protocol error")
	}
	if err := c.WriteMessage(2, []byte{1}); !errors.Is(err, errCloseSent) {
		t.Fatalf("WriteMessage after protocol-error close = %v, want errCloseSent", err)
	}
}

func TestReadMessage_NoSecondCloseAfterServerInitiatedClose(t *testing.T) {
	ping := buildClientFrame(0x9, true, []byte("p"))
	reply := buildClientFrame(0x8, true, []byte{0x03, 0xE8})
	c := newConn(append(ping, reply...))
	if err := c.WriteMessage(8, []byte{0x03, 0xE8}); err != nil {
		t.Fatalf("server close: %v", err)
	}
	// The ping that races the peer's close reply is not answered and does
	// not fail the read; the close reply is delivered but not echoed.
	if mt, _, err := c.ReadMessage(); err != nil || mt != 8 {
		t.Fatalf("ReadMessage = (%d, %v), want (8, nil)", mt, err)
	}
	if ops := serverOps(t, c); !bytes.Equal(ops, []byte{0x8}) {
		t.Fatalf("server frames = %v, want exactly one close frame", ops)
	}
	if err := c.WriteMessage(8, []byte{0x03, 0xE8}); !errors.Is(err, errCloseSent) {
		t.Fatalf("second WriteMessage(close) = %v, want errCloseSent", err)
	}
}

// Control: frames before any close behave as before.
func TestWriteMessage_AllowedBeforeClose(t *testing.T) {
	c := newConn(buildClientFrame(0x9, true, []byte("p")))
	_, _, _ = c.ReadMessage() // pong, then EOF
	if err := c.WriteMessage(1, []byte("ok")); err != nil {
		t.Fatalf("WriteMessage before close: %v", err)
	}
	if ops := serverOps(t, c); !bytes.Equal(ops, []byte{0xA, 0x1}) {
		t.Fatalf("server frames = %v, want [pong text]", ops)
	}
}
