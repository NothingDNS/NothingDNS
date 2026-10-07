package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// acceptSignalListener reports every accepted connection so a test can order
// "idle connection accepted" strictly before the next dial.
type acceptSignalListener struct {
	net.Listener
	accepted chan struct{}
}

func (l *acceptSignalListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted <- struct{}{}
	}
	return c, err
}

// TestStreamServers_IdleConnsDoNotStarveOthers is the F72 regression: with a
// fixed worker pool, `workers` idle connections (no query, or no TLS
// handshake) blocked every other TCP/DoT client for up to the 30s read
// timeout.
func TestStreamServers_IdleConnsDoNotStarveOthers(t *testing.T) {
	cfg := &tls.Config{Certificates: []tls.Certificate{generateTestTLSCert(t)}}
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		_, _ = w.Write(&protocol.Message{Header: protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)}})
	})

	for _, tc := range []struct {
		name string
		tls  *tls.Config
	}{{"tcp", nil}, {"dot", cfg}} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ln := &acceptSignalListener{Listener: raw, accepted: make(chan struct{}, 8)}
			done := make(chan error, 1)
			var stop func() error
			if tc.tls == nil {
				s := NewTCPServerWithWorkers("", handler, 1)
				s.ListenWithListener(ln)
				stop = s.Stop
				go func() { done <- s.Serve() }()
			} else {
				s := NewTLSServerWithWorkers("", handler, tc.tls, 1)
				s.ListenWithListener(tls.NewListener(ln, tc.tls))
				stop = s.Stop
				go func() { done <- s.Serve() }()
			}
			addr := raw.Addr().String()

			var conns []net.Conn
			defer func() {
				_ = stop()
				for _, c := range conns {
					_ = c.Close()
				}
				<-done
			}()
			for i := 0; i < 3; i++ { // 3 idle conns > 1 worker
				c, err := net.Dial("tcp", addr)
				if err != nil {
					t.Fatal(err)
				}
				conns = append(conns, c)
				<-ln.accepted
			}

			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			conns = append(conns, c)
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if tc.tls != nil {
				tlsC := tls.Client(c, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- test
				if err := tlsC.Handshake(); err != nil {
					t.Fatalf("handshake starved behind idle connections: %v", err)
				}
				c = tlsC
			}

			q, _ := protocol.NewQuery(0x7272, "starve.example.", protocol.TypeA)
			buf := make([]byte, 512)
			n, err := q.Pack(buf[2:])
			if err != nil {
				t.Fatal(err)
			}
			binary.BigEndian.PutUint16(buf, uint16(n))
			if _, err := c.Write(buf[:n+2]); err != nil {
				t.Fatal(err)
			}
			var l [2]byte
			if _, err := io.ReadFull(c, l[:]); err != nil {
				t.Fatalf("query starved behind idle connections: %v", err)
			}
			resp := make([]byte, binary.BigEndian.Uint16(l[:]))
			if _, err := io.ReadFull(c, resp); err != nil {
				t.Fatal(err)
			}
			if got := binary.BigEndian.Uint16(resp); got != 0x7272 {
				t.Fatalf("response id = %#x, want 0x7272", got)
			}
		})
	}
}

// TestAcceptRetryBackoff is the F73 regression: persistent Accept errors
// (EMFILE) must back off instead of spinning, and the wait must be
// cancellable by shutdown.
func TestAcceptRetryBackoff(t *testing.T) {
	want := []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond,
		40 * time.Millisecond, 80 * time.Millisecond, 160 * time.Millisecond, 320 * time.Millisecond,
		640 * time.Millisecond, time.Second, time.Second}
	d := time.Duration(0)
	for i, w := range want {
		d = nextAcceptRetryDelay(d)
		if d != w {
			t.Fatalf("step %d: delay = %v, want %v", i, d, w)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	returned := make(chan struct{})
	go func() { waitAcceptRetry(ctx, time.Hour); close(returned) }()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("waitAcceptRetry ignored a cancelled context")
	}
}
