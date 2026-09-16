package transfer

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestIXFRClientHandlesUpToDateSingleSOA pins the RFC 1995 §2 contract: an
// up-to-date IXFR response is a single SOA record, and the client must
// return it as a clean no-changes result. Previously the receive loop
// required two SOAs to terminate, so the single-SOA response fell through
// to the next read, hit EOF, and surfaced as a transport error — every
// up-to-date refresh failed.
func TestIXFRClientHandlesUpToDateSingleSOA(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer ln.Close()

	origin, _ := protocol.ParseName("example.com.")
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

	client := NewIXFRClient(ln.Addr().String())

	var records []*protocol.ResourceRecord
	var transferErr error
	ready := make(chan struct{})
	go func() {
		defer close(ready)
		records, transferErr = client.Transfer("example.com.", 42, nil)
		t.Logf("DBG-CLIENT: done, err=%v records=%d", transferErr, len(records))
	}()

	// Serve the up-to-date response: read the client's request (for its
	// TXID), then write the single-SOA message.
	conn, err := ln.Accept()
	if err != nil {
		t.Logf("DBG-SERVE: accept failed: %v", err)
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()
	t.Logf("DBG-SERVE: accepted")

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		t.Logf("DBG-SERVE: read length failed: %v", err)
		t.Fatalf("reading request length: %v", err)
	}
	reqBuf := make([]byte, int(lenBuf[0])<<8|int(lenBuf[1]))
	if _, err := io.ReadFull(conn, reqBuf); err != nil {
		t.Logf("DBG-SERVE: read body failed: %v", err)
		t.Fatalf("reading request: %v", err)
	}
	t.Logf("DBG-SERVE: request read (%d bytes)", len(reqBuf))
	reqMsg, err := protocol.UnpackMessage(reqBuf)
	if err != nil {
		t.Fatalf("unpacking request: %v", err)
	}
	id := reqMsg.Header.ID
	reqMsg.Release()

	respMsg := protocol.NewMessage(protocol.Header{
		ID:      id,
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 1,
	})
	respMsg.Questions = []*protocol.Question{{
		Name:   origin,
		QType:  protocol.TypeIXFR,
		QClass: protocol.ClassIN,
	}}
	respMsg.Answers = []*protocol.ResourceRecord{soa}

	if _, err := conn.Write(frameMessage(t, respMsg)); err != nil {
		t.Fatalf("writing IXFR frame: %v", err)
	}
	// A real master closes the connection after the final SOA — close
	// now (not deferred) so the client's next read sees EOF and its
	// termination logic actually runs.
	conn.Close()
	respMsg.Release()

	select {
	case <-ready:
	case <-time.After(60 * time.Second):
		t.Fatal("timed out waiting for the transfer to complete")
	}

	if transferErr != nil {
		t.Fatalf("FAIL: an up-to-date (single-SOA) IXFR response surfaced as a transport error: %v", transferErr)
	}
	if len(records) != 1 || records[0].Type != protocol.TypeSOA {
		t.Fatalf("FAIL: expected exactly one SOA record, got %d records", len(records))
	}
}
