package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// startDigTCPServer starts a TCP listener whose handler is invoked once per
// accepted connection with the raw query bytes (length prefix stripped).
// The handler returns the response wire bytes to send back (prefix added by
// the harness), nil to close without responding, or a non-nil empty slice to
// advertise a zero-length response.
func startDigTCPServer(t *testing.T, handler func(query []byte) []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var prefix [2]byte
				if _, err := io.ReadFull(c, prefix[:]); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(prefix[:]))
				if _, err := io.ReadFull(c, query); err != nil {
					return
				}
				resp := handler(query)
				if resp == nil {
					return
				}
				binary.BigEndian.PutUint16(prefix[:], uint16(len(resp)))
				if _, err := c.Write(prefix[:]); err != nil {
					return
				}
				if len(resp) > 0 {
					c.Write(resp)
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// cannedDigTCPAnswer packs a NOERROR response echoing the query with one A
// record for 192.0.2.99 — a distinct address so tests can prove the answer
// came from the TCP path rather than any UDP fixture.
func cannedDigTCPAnswer(query []byte) []byte {
	msg, err := protocol.UnpackMessage(query)
	if err != nil {
		return nil
	}
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:      msg.Header.ID,
			Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
			QDCount: 1,
			ANCount: 1,
		},
		Questions: msg.Questions,
		Answers: []*protocol.ResourceRecord{
			{
				Name:  msg.Questions[0].Name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 99}},
			},
		},
	}
	buf := make([]byte, 65535)
	n, err := resp.Pack(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

// packedDigQuery builds a wire-format A query for name.
func packedDigQuery(t *testing.T, name string) []byte {
	t.Helper()
	msg, err := protocol.NewQuery(0x4242, name, protocol.TypeA)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}
	buf := make([]byte, 65535)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return buf[:n]
}

func TestDigQueryTCP_Success(t *testing.T) {
	addr := startDigTCPServer(t, cannedDigTCPAnswer)
	resp, err := digQueryTCP(addr, packedDigQuery(t, "example.com."))
	if err != nil {
		t.Fatalf("digQueryTCP: %v", err)
	}
	if resp.Header.ID != 0x4242 {
		t.Errorf("ID = %#x, want 0x4242 (echoed)", resp.Header.ID)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answers))
	}
	addrA, ok := resp.Answers[0].Data.(*protocol.RDataA)
	if !ok || addrA.Address != [4]byte{192, 0, 2, 99} {
		t.Errorf("answer data = %v, want 192.0.2.99", resp.Answers[0].Data)
	}
}

func TestDigQueryTCP_DialError(t *testing.T) {
	// Port 1 on loopback: no listener, refuses immediately.
	_, err := digQueryTCP("127.0.0.1:1", packedDigQuery(t, "example.com."))
	if err == nil {
		t.Fatal("expected dial error")
	}
	if !strings.Contains(err.Error(), "dial tcp") {
		t.Errorf("error = %v, want dial tcp failure", err)
	}
}

func TestDigQueryTCP_ServerClosesBeforeResponse(t *testing.T) {
	// Handler returns nil: connection accepted, query drained, then closed
	// with no response — the client must fail reading the length prefix.
	addr := startDigTCPServer(t, func([]byte) []byte { return nil })
	_, err := digQueryTCP(addr, packedDigQuery(t, "example.com."))
	if err == nil {
		t.Fatal("expected error when server closes before responding")
	}
	if !strings.Contains(err.Error(), "read tcp len-prefix") {
		t.Errorf("error = %v, want read tcp len-prefix failure", err)
	}
}

func TestDigQueryTCP_EmptyResponse(t *testing.T) {
	// Handler returns a non-nil empty slice: the server advertises a
	// zero-length response, which the client must reject.
	addr := startDigTCPServer(t, func([]byte) []byte { return []byte{} })
	_, err := digQueryTCP(addr, packedDigQuery(t, "example.com."))
	if err == nil {
		t.Fatal("expected error for zero-length response")
	}
	if !strings.Contains(err.Error(), "tcp response empty") {
		t.Errorf("error = %v, want tcp response empty", err)
	}
}

func TestDigQueryTCP_MalformedBody(t *testing.T) {
	// Well-framed prefix, garbage payload: framing succeeds and the failure
	// must surface from the DNS unpack step, not the length reads.
	addr := startDigTCPServer(t, func([]byte) []byte {
		return []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	})
	_, err := digQueryTCP(addr, packedDigQuery(t, "example.com."))
	if err == nil {
		t.Fatal("expected unpack error for malformed response body")
	}
}

func TestDigQueryTCP_BodyTruncated(t *testing.T) {
	// Server advertises 64 bytes but sends 4 and closes — the body read
	// must fail with the "read tcp body" context rather than returning a
	// short buffer to the unpacker.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(prefix[:]))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		binary.BigEndian.PutUint16(prefix[:], 64) // advertise 64…
		conn.Write(prefix[:])
		conn.Write([]byte{0xde, 0xad, 0xbe, 0xef}) // …send 4
	}()

	_, err = digQueryTCP(ln.Addr().String(), packedDigQuery(t, "example.com."))
	if err == nil {
		t.Fatal("expected error when response body is truncated")
	}
	if !strings.Contains(err.Error(), "read tcp body") {
		t.Errorf("error = %v, want read tcp body failure", err)
	}
}

// TestCmdDig_TCRetryOverTCP exercises the RFC 1035 §4.2.1 retry at command
// level: the UDP responder answers with TC=1 and no answers, and the full
// answer is only available over TCP. cmdDig must transparently retry over
// TCP and print the TCP answer without a truncation warning.
func TestCmdDig_TCRetryOverTCP(t *testing.T) {
	// Bind UDP first, then TCP on the same port number (UDP and TCP port
	// spaces are independent).
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { udpConn.Close() })
	udpPort := udpConn.LocalAddr().(*net.UDPAddr).Port

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", udpPort))
	if err != nil {
		t.Fatalf("listen tcp on udp port: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	// UDP side: always answer TC=1 with no answer records.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, clientAddr, err := udpConn.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, err := protocol.UnpackMessage(buf[:n])
			if err != nil {
				continue
			}
			flags := protocol.NewResponseFlags(protocol.RcodeSuccess)
			flags.TC = true
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   flags,
					QDCount: 1,
				},
				Questions: msg.Questions,
			}
			packed, _ := resp.Pack(buf)
			udpConn.WriteTo(buf[:packed], clientAddr)
		}
	}()

	// TCP side: full answer, distinct IP 192.0.2.99.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var prefix [2]byte
				if _, err := io.ReadFull(c, prefix[:]); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(prefix[:]))
				if _, err := io.ReadFull(c, query); err != nil {
					return
				}
				resp := cannedDigTCPAnswer(query)
				if resp == nil {
					return
				}
				binary.BigEndian.PutUint16(prefix[:], uint16(len(resp)))
				c.Write(prefix[:])
				c.Write(resp)
			}(conn)
		}
	}()

	output := captureOutput(func() {
		if err := cmdDig([]string{fmt.Sprintf("@127.0.0.1:%d", udpPort), "example.com", "A"}); err != nil {
			t.Errorf("cmdDig: %v", err)
		}
	})
	if !strings.Contains(output, "192.0.2.99") {
		t.Errorf("output missing TCP retried answer 192.0.2.99:\n%s", output)
	}
}
