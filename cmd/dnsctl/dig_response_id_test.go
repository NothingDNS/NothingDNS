package main

import (
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// F698: dig took the first datagram that arrived and printed it, even when
// its ID did not match the query (a stray or spoofed packet).
func TestDigIgnoresMismatchedResponseID(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("udp unavailable:", err)
	}
	defer pc.Close()

	reply := func(q *protocol.Message, id uint16, ip byte) []byte {
		name, _ := protocol.ParseName("example.com.")
		resp := &protocol.Message{
			Header:    protocol.Header{ID: id, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: q.Questions,
			Answers: []*protocol.ResourceRecord{{
				Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 60,
				Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, ip}},
			}},
		}
		buf := make([]byte, 512)
		n, err := resp.Pack(buf)
		if err != nil {
			t.Error(err)
		}
		return buf[:n]
	}
	go func() {
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q, err := protocol.UnpackMessage(buf[:n])
		if err != nil {
			return
		}
		pc.WriteTo(reply(q, q.Header.ID+1, 66), addr) // stray: wrong ID
		pc.WriteTo(reply(q, q.Header.ID, 10), addr)   // the real answer
	}()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	runErr := cmdDig([]string{"@" + pc.LocalAddr().String(), "example.com", "A"})
	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	if runErr != nil {
		t.Fatal(runErr)
	}
	if strings.Contains(string(out), "192.0.2.66") {
		t.Errorf("printed the mismatched-ID response:\n%s", out)
	}
	if !strings.Contains(string(out), "192.0.2.10") {
		t.Errorf("did not print the matching response:\n%s", out)
	}
}
