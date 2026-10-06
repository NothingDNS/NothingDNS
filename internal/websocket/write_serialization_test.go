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

// interleavingSink is a network-boundary double for Conn.conn. It behaves like
// a socket: a Write may be split across the wire and every byte lands in one
// shared stream in call order. The split point is where a competing writer is
// given a deterministic chance to inject its own frame, modelling a large
// frame that util.WriteFull emits over several Write calls once the socket
// buffer fills.
//
// The double never corrupts anything by itself — it appends exactly the bytes
// it was handed, in call order. Any corruption in the resulting stream is
// therefore caused by production code interleaving two frames.
type interleavingSink struct {
	mu  sync.Mutex
	buf bytes.Buffer

	// inFlight counts writers currently inside Write.
	inFlight int
	// partnerArrived is closed once a second writer is inside Write.
	partnerArrived chan struct{}
	partnerOnce    sync.Once

	// yield opens the interleaving window. Disabled for the control case.
	yield bool

	readMu  sync.Mutex
	readBuf []byte
}

func newInterleavingSink(yield bool) *interleavingSink {
	return &interleavingSink{
		partnerArrived: make(chan struct{}),
		yield:          yield,
	}
}

func (s *interleavingSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.inFlight++
	if s.inFlight >= 2 {
		s.partnerOnce.Do(func() { close(s.partnerArrived) })
	}
	s.mu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	half := len(p) / 2
	if half == 0 {
		half = len(p)
	}

	s.mu.Lock()
	s.buf.Write(p[:half])
	s.mu.Unlock()

	if s.yield {
		// Bounded, so the test terminates even when writes are serialized.
		select {
		case <-s.partnerArrived:
		case <-time.After(150 * time.Millisecond):
		}
	}

	s.mu.Lock()
	s.buf.Write(p[half:])
	s.inFlight--
	s.mu.Unlock()

	return len(p), nil
}

func (s *interleavingSink) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if len(s.readBuf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}

func (s *interleavingSink) Close() error { return nil }

func (s *interleavingSink) wire() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]byte, s.buf.Len())
	copy(out, s.buf.Bytes())
	return out
}

// maskedPingFrame builds a client-to-server masked PING frame, as required by
// readFrame's "client frame not masked" rule (RFC 6455 §5.3).
func maskedPingFrame(payload string) []byte {
	mask := [4]byte{0x01, 0x02, 0x03, 0x04}
	frame := []byte{0x80 | 0x9, 0x80 | byte(len(payload))}
	frame = append(frame, mask[:]...)
	for i := 0; i < len(payload); i++ {
		frame = append(frame, payload[i]^mask[i%4])
	}
	return frame
}

// parseServerFrames decodes a stream of unmasked server-to-client frames,
// returning an error if it is not a clean sequence of whole frames — which is
// exactly the corruption a peer would observe.
func parseServerFrames(stream []byte) (ops []byte, payloads [][]byte, err error) {
	for len(stream) > 0 {
		if len(stream) < 2 {
			return nil, nil, errors.New("truncated frame header")
		}
		opcode := stream[0] & 0x0F
		length := int(stream[1] & 0x7F)
		stream = stream[2:]

		switch length {
		case 126:
			if len(stream) < 2 {
				return nil, nil, errors.New("truncated 16-bit length")
			}
			length = int(binary.BigEndian.Uint16(stream[:2]))
			stream = stream[2:]
		case 127:
			if len(stream) < 8 {
				return nil, nil, errors.New("truncated 64-bit length")
			}
			length = int(binary.BigEndian.Uint64(stream[:8]))
			stream = stream[8:]
		}

		if length < 0 || len(stream) < length {
			return nil, nil, errors.New("truncated frame payload")
		}
		ops = append(ops, opcode)
		payloads = append(payloads, stream[:length])
		stream = stream[length:]
	}
	return ops, payloads, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestWriteMessage_ConcurrentWritesDoNotInterleave pins RFC 6455 §5.2: a frame
// must reach the peer as one contiguous unit.
//
// It reproduces the production topology of dashboard.ClientLoop, which runs a
// dedicated write goroutine while the read loop runs concurrently. When the
// read loop receives a PING, Conn.ReadMessage auto-responds with a PONG by
// calling WriteMessage from the read goroutine. Without whole-frame write
// serialization those two frames interleave on the wire and the peer's frame
// parser desynchronizes.
func TestWriteMessage_ConcurrentWritesDoNotInterleave(t *testing.T) {
	sink := newInterleavingSink(true)
	sink.readBuf = maskedPingFrame("hb") // read loop sees a PING -> auto-PONG
	conn := &Conn{conn: sink}

	broadcast := bytes.Repeat([]byte("A"), 200)

	var wg sync.WaitGroup

	// The dashboard broadcast write loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := conn.WriteMessage(0x1, broadcast); err != nil {
			t.Errorf("broadcast WriteMessage: %v", err)
		}
	}()

	// The dashboard read loop, which auto-pongs.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, _, err := conn.ReadMessage(); err != nil && !errors.Is(err, io.EOF) {
			t.Logf("read loop ended: %v", err)
		}
	}()

	wg.Wait()

	wire := sink.wire()
	ops, payloads, err := parseServerFrames(wire)
	if err != nil {
		t.Fatalf("concurrent write + auto-pong corrupted the frame stream: %v\n"+
			"RFC 6455 §5.2 requires each frame to reach the peer contiguously.\n"+
			"first 48 bytes: %x", err, wire[:minInt(48, len(wire))])
	}

	if len(ops) != 2 {
		t.Fatalf("expected 2 frames (broadcast + pong), got %d", len(ops))
	}
	sawBroadcast, sawPong := false, false
	for i, op := range ops {
		switch op {
		case 0x1:
			if !bytes.Equal(payloads[i], broadcast) {
				t.Fatalf("broadcast frame corrupted: got %d intact bytes, want %d",
					bytes.Index(payloads[i], broadcast)+1, len(broadcast))
			}
			sawBroadcast = true
		case 0xA:
			if !bytes.Equal(payloads[i], []byte("hb")) {
				t.Fatalf("pong frame corrupted: got %q, want %q", payloads[i], "hb")
			}
			sawPong = true
		}
	}
	if !sawBroadcast || !sawPong {
		t.Fatalf("missing frames: broadcast=%v pong=%v", sawBroadcast, sawPong)
	}
}

// TestWriteMessage_SequentialWritesAreIntact is the control: with writers
// serialized, both frames already parse cleanly, so a failure in the test above
// cannot be blamed on the harness or the frame builder.
func TestWriteMessage_SequentialWritesAreIntact(t *testing.T) {
	sink := newInterleavingSink(false)
	sink.readBuf = maskedPingFrame("hb")
	conn := &Conn{conn: sink}

	broadcast := bytes.Repeat([]byte("A"), 200)

	if err := conn.WriteMessage(0x1, broadcast); err != nil {
		t.Fatalf("broadcast WriteMessage: %v", err)
	}
	if _, _, err := conn.ReadMessage(); err != nil && !errors.Is(err, io.EOF) {
		t.Logf("read loop ended: %v", err)
	}

	ops, payloads, err := parseServerFrames(sink.wire())
	if err != nil {
		t.Fatalf("sequential writes did not parse: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(ops))
	}
	if !bytes.Equal(payloads[0], broadcast) {
		t.Fatal("broadcast frame corrupted")
	}
}

// TestWriteMessage_ConcurrentLargeFramesStayIntact is the boundary check on the
// fix: a 16-bit extended payload length frame (the 126 encoding) written
// concurrently with an auto-pong must also stay contiguous.
func TestWriteMessage_ConcurrentLargeFramesStayIntact(t *testing.T) {
	sink := newInterleavingSink(true)
	sink.readBuf = maskedPingFrame("hb")
	conn := &Conn{conn: sink}

	// >125 bytes forces the 126 two-byte extended length encoding.
	large := bytes.Repeat([]byte("B"), 5000)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := conn.WriteMessage(0x2, large); err != nil {
			t.Errorf("large WriteMessage: %v", err)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, _, err := conn.ReadMessage(); err != nil && !errors.Is(err, io.EOF) {
			t.Logf("read loop ended: %v", err)
		}
	}()
	wg.Wait()

	ops, payloads, err := parseServerFrames(sink.wire())
	if err != nil {
		t.Fatalf("concurrent large frame corrupted the stream: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(ops))
	}
	// Frame order is not guaranteed — whichever writer acquired writeMu first
	// goes first — so look for the large frame rather than assuming an index.
	found := false
	for i, op := range ops {
		if op == 0x2 {
			if !bytes.Equal(payloads[i], large) {
				t.Fatalf("large frame corrupted: got %d bytes, want %d", len(payloads[i]), len(large))
			}
			found = true
		}
	}
	if !found {
		t.Fatal("large binary frame missing from the stream")
	}
}

// TestInterleavingSinkIsFaithful guards the harness itself: the double appends
// exactly the bytes it is handed, in call order, so it cannot manufacture
// corruption on its own.
func TestInterleavingSinkIsFaithful(t *testing.T) {
	sink := newInterleavingSink(true)

	var want []byte
	for _, p := range [][]byte{
		bytes.Repeat([]byte("A"), 40),
		bytes.Repeat([]byte("B"), 40),
		bytes.Repeat([]byte("C"), 40),
	} {
		var frame []byte
		frame = append(frame, 0x80|0x1)
		frame = append(frame, byte(len(p)))
		frame = append(frame, p...)
		if _, err := sink.Write(frame); err != nil {
			t.Fatalf("sink.Write: %v", err)
		}
		want = append(want, frame...)
	}

	if !bytes.Equal(sink.wire(), want) {
		t.Fatal("harness double corrupted bytes on its own; proof is unsound")
	}
}
