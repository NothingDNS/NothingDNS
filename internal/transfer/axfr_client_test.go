package transfer

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestAXFRClientReturnsIntactRecords pins the AXFR client's ownership
// contract: records returned from Transfer must be intact, not pooled
// corpses. Previously receiveAXFRResponse appended pooled-message record
// pointers into the returned slice while deferring msg.Release() inside the
// read loop — the deferred releases gutted every returned record (Type/TTL
// zeroed, Name released, RData nil'd) right before the caller received it.
func TestAXFRClientReturnsIntactRecords(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer ln.Close()

	origin, _ := protocol.ParseName("example.com.")
	wwwName, _ := protocol.ParseName("www.example.com.")
	soa := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data: &protocol.RDataSOA{
			MName:   origin,
			RName:   origin,
			Serial:  42,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minimum: 60,
		},
	}
	aRecord := &protocol.ResourceRecord{
		Name:  wwwName,
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
	}

	client := NewAXFRClient(ln.Addr().String())

	var got *protocol.ResourceRecord
	ready := make(chan struct{})
	go func() {
		defer close(ready)
		records, err := client.Transfer("example.com.", nil)
		if err != nil {
			t.Errorf("Transfer: %v", err)
			return
		}
		for _, rr := range records {
			if rr != nil && rr.Type == protocol.TypeA {
				got = rr
			}
		}
	}()

	// Serve the AXFR stream: read the client's request (for its TXID),
	// then write the two framed response messages.
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		t.Fatalf("reading request length: %v", err)
	}
	reqBuf := make([]byte, int(lenBuf[0])<<8|int(lenBuf[1]))
	if _, err := io.ReadFull(conn, reqBuf); err != nil {
		t.Fatalf("reading request: %v", err)
	}
	reqMsg, err := protocol.UnpackMessage(reqBuf)
	if err != nil {
		t.Fatalf("unpacking request: %v", err)
	}
	id := reqMsg.Header.ID
	reqMsg.Release()

	msg1 := protocol.NewMessage(protocol.Header{
		ID:      id,
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 1,
	})
	msg1.Questions = []*protocol.Question{{
		Name:   origin,
		QType:  protocol.TypeAXFR,
		QClass: protocol.ClassIN,
	}}
	msg1.Answers = []*protocol.ResourceRecord{soa, aRecord}

	msg2 := protocol.NewMessage(protocol.Header{
		ID:      id,
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 1,
	})
	msg2.Questions = []*protocol.Question{{
		Name:   origin,
		QType:  protocol.TypeAXFR,
		QClass: protocol.ClassIN,
	}}
	msg2.Answers = []*protocol.ResourceRecord{soa}

	frames := [][]byte{frameMessage(t, msg1), frameMessage(t, msg2)}
	msg1.Release()
	msg2.Release()

	for _, frame := range frames {
		if _, err := conn.Write(frame); err != nil {
			t.Fatalf("writing AXFR frame: %v", err)
		}
	}

	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the transfer to complete")
	}

	if got == nil {
		t.Fatal("FAIL: no A record in the transfer result")
	}
	if got.Type != protocol.TypeA || got.TTL != 300 || got.Name == nil {
		t.Fatalf("FAIL: AXFR client returned released records — "+
			"Type=%d TTL=%d Name=%v (the pooled-message corpse; the caller "+
			"received gutted records because receiveAXFRResponse defers "+
			"msg.Release() over records it returns)", got.Type, got.TTL, got.Name)
	}
}

// frameMessage packs a message into a TCP-framed AXFR chunk (the 2-byte
// big-endian length prefix followed by the wire bytes).
func frameMessage(t *testing.T, msg *protocol.Message) []byte {
	t.Helper()
	buf := make([]byte, 2+65535)
	n, err := msg.Pack(buf[2:])
	if err != nil {
		t.Fatalf("packing AXFR message: %v", err)
	}
	frame := buf[:2+n]
	frame[0] = byte(n >> 8)
	frame[1] = byte(n)
	return frame
}
