package upstream

import (
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// Regression F92: one failed Query (UDP refused, TCP refused) must count a
// single strike against the 3-strike health threshold. It previously called
// markFailure three times (queryUDPBuf, queryTCPBuf, Query) and ejected the
// upstream after one lost query.
func TestClientQuery_OneFailureIsOneStrike(t *testing.T) {
	addr := deadUpstreamAddr(t)
	c, err := NewClient(Config{Servers: []string{addr}, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	for i := 1; i <= 3; i++ {
		if _, err := c.Query(lbTestMessage(t)); err == nil {
			t.Fatalf("query %d to dead upstream succeeded", i)
		}
		s := c.servers[0]
		s.mu.RLock()
		fc, healthy := s.failCount, s.healthy
		s.mu.RUnlock()
		if fc != i {
			t.Fatalf("after %d failed queries failCount=%d, want %d", i, fc, i)
		}
		if healthy != (i < 3) {
			t.Fatalf("after %d failed queries healthy=%v, want %v", i, healthy, i < 3)
		}
	}
}

// Regression F93: a reply with the right transaction ID but a different
// question must be rejected on both UDP and TCP (RFC 5452 section 9.1).
func TestClientQuery_RejectsQuestionMismatch(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer l.Close()
	pc, err := net.ListenPacket("udp", l.Addr().String())
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()

	evil, err := protocol.ParseName("evil.example.")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	spoof := func(b []byte) []byte {
		m, err := protocol.UnpackMessage(b)
		if err != nil {
			return nil
		}
		m.Header.Flags.QR = true
		m.Questions[0].Name = evil
		out := make([]byte, 4096)
		n, err := m.Pack(out)
		if err != nil {
			return nil
		}
		return out[:n]
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if r := spoof(buf[:n]); r != nil {
				_, _ = pc.WriteTo(r, from)
			}
		}
	}()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				lb := make([]byte, 2)
				if _, err := readFullConn(conn, lb); err != nil {
					return
				}
				b := make([]byte, int(lb[0])<<8|int(lb[1]))
				if _, err := readFullConn(conn, b); err != nil {
					return
				}
				r := spoof(b)
				_, _ = conn.Write(append([]byte{byte(len(r) >> 8), byte(len(r))}, r...))
			}(conn)
		}
	}()

	c, err := NewClient(Config{Servers: []string{l.Addr().String()}, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	resp, err := c.Query(lbTestMessage(t))
	if err == nil {
		t.Fatalf("accepted reply for %s to a query for example.com.", resp.Questions[0].Name.String())
	}
}

func readFullConn(c net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

// Regression F443: the dead upstream used by the failure-accounting tests must
// keep its UDP and TCP ports bound for the whole test, so no parallel test
// binary can grab the port and answer the "dead" upstream.
func TestDeadUpstreamAddrHoldsPort(t *testing.T) {
	addr := deadUpstreamAddr(t)
	if pc, err := net.ListenPacket("udp", addr); err == nil {
		pc.Close()
		t.Fatalf("udp %s could be bound by another socket; dead upstream port not held", addr)
	}
	if l, err := net.Listen("tcp", addr); err == nil {
		l.Close()
		t.Fatalf("tcp %s could be bound by another socket; dead upstream port not held", addr)
	}
	c, err := NewClient(Config{Servers: []string{addr}, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()
	start := time.Now()
	if _, err := c.Query(lbTestMessage(t)); err == nil {
		t.Fatal("query to dead upstream succeeded")
	}
	if d := time.Since(start); d >= time.Second {
		t.Fatalf("dead upstream query took %v; must fail fast, not time out", d)
	}
}
