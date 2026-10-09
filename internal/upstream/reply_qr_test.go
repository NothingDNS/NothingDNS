package upstream

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// qrTestServers starts a UDP and a TCP server on one address pair that send
// every query back, with QR set only when reply is true.
func qrTestServers(t *testing.T, reply bool) (udpAddr, tcpAddr string) {
	t.Helper()
	flip := func(b []byte) []byte {
		out := append([]byte{}, b...)
		if reply && len(out) > 2 {
			out[2] |= 0x80
		}
		return out
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close(); ln.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(flip(buf[:n]), addr)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					var l [2]byte
					if _, err := io.ReadFull(c, l[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(l[:]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					_, _ = c.Write(append(l[:], flip(q)...))
				}
			}(c)
		}
	}()
	return pc.LocalAddr().String(), ln.Addr().String()
}

// F650: a reflected query (QR=0) with the right ID and question was accepted
// as the upstream answer on every Client and LoadBalancer path.
func TestUpstreamRejectsRepliesWithoutQR(t *testing.T) {
	for _, reply := range []bool{true, false} {
		udp, tcp := qrTestServers(t, reply)
		c, err := NewClient(Config{Servers: []string{udp}, Timeout: time.Second, HealthCheck: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		lb, err := NewLoadBalancer(LoadBalancerConfig{Servers: []string{udp}, Strategy: "random", HealthCheck: time.Hour, FailoverTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		tcpServer := &Server{Address: tcp, Network: "tcp", Timeout: time.Second, healthy: true}
		paths := map[string]func(*protocol.Message) (*protocol.Message, error){
			"client udp": func(q *protocol.Message) (*protocol.Message, error) { return c.queryUDP(c.servers[0], q) },
			"client tcp": func(q *protocol.Message) (*protocol.Message, error) { return c.queryTCP(tcpServer, q) },
			"lb udp":     func(q *protocol.Message) (*protocol.Message, error) { return lb.queryUDP(udp, q) },
			"lb tcp":     func(q *protocol.Message) (*protocol.Message, error) { return lb.queryTCP(tcp, q) },
		}
		for name, query := range paths {
			q, err := protocol.NewQuery(RandomTXID(), "www.example.com.", protocol.TypeA)
			if err != nil {
				t.Fatal(err)
			}
			_, err = query(q)
			if reply && err != nil {
				t.Errorf("%s: QR=1 reply rejected: %v", name, err)
			}
			if !reply && err == nil {
				t.Errorf("%s: reflected query (QR=0) accepted as the answer", name)
			}
		}
		_ = c.Close()
		lb.Close()
	}
}
