package resolver

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// F699: the iterative transport matched ID and question but never required
// QR=1, so a reflected query (same ID, same question) was accepted as an
// answer. The upstream client has checked this since F650.
func TestStdioTransportRequiresResponseBit(t *testing.T) {
	for _, qr := range []bool{false, true} {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Skip(err)
		}
		ln, err := net.Listen("tcp", pc.LocalAddr().String())
		if err != nil {
			pc.Close()
			t.Skip(err)
		}
		echo := func(raw []byte) []byte {
			// flip QR in the raw query bytes to the wanted value
			out := append([]byte(nil), raw...)
			if qr {
				out[2] |= 0x80
			} else {
				out[2] &^= 0x80
			}
			return out
		}
		go func() {
			buf := make([]byte, 512)
			n, addr, err := pc.ReadFrom(buf)
			if err == nil {
				pc.WriteTo(echo(buf[:n]), addr)
			}
		}()
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			var l [2]byte
			if _, err := readN(c, l[:]); err != nil {
				return
			}
			b := make([]byte, binary.BigEndian.Uint16(l[:]))
			if _, err := readN(c, b); err != nil {
				return
			}
			r := echo(b)
			binary.BigEndian.PutUint16(l[:], uint16(len(r)))
			c.Write(append(l[:], r...))
		}()

		name, _ := protocol.ParseName("example.com.")
		msg := &protocol.Message{
			Header:    protocol.Header{ID: 0x1234, QDCount: 1},
			Questions: []*protocol.Question{{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN}},
		}
		tr := NewStdioTransport(time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		for _, proto := range []string{"udp", "tcp"} {
			var resp *protocol.Message
			if proto == "udp" {
				resp, err = tr.queryUDP(ctx, msg, pc.LocalAddr().String())
			} else {
				resp, err = tr.queryTCP(ctx, msg, ln.Addr().String())
			}
			if qr && err != nil {
				t.Errorf("%s: genuine response (QR=1) rejected: %v", proto, err)
			}
			if !qr && err == nil {
				t.Errorf("%s: reflected query (QR=0) accepted as a response", proto)
			}
			resp.Release()
		}
		cancel()
		pc.Close()
		ln.Close()
	}
}

func readN(c net.Conn, b []byte) (int, error) {
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
