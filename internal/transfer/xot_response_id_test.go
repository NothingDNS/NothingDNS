package transfer

// Round-2/10 regression guard: RFC 5936 §2.2 requires every DNS message in an
// AXFR/IXFR response stream to carry the query's ID. sendAXFRResponse used to
// hardcode ID 0 ("Use 0 for AXFR responses"), which fails every RFC 5936
// compliant secondary — including this repo's own slave client, which enforces
// the TXID binding verified in TestAXFRClientReturnsIntactRecords' round.

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestXoTServerSendAXFRResponseEchoesRequestID(t *testing.T) {
	origin, err := protocol.ParseName("xot.example.com.")
	if err != nil {
		t.Fatalf("ParseName(origin): %v", err)
	}
	mname, err := protocol.ParseName("ns1.xot.example.com.")
	if err != nil {
		t.Fatalf("ParseName(mname): %v", err)
	}
	rname, err := protocol.ParseName("admin.xot.example.com.")
	if err != nil {
		t.Fatalf("ParseName(rname): %v", err)
	}

	openSOA := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data: &protocol.RDataSOA{
			MName: mname, RName: rname,
			Serial: 42, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300,
		},
	}
	aName, aNameErr := protocol.ParseName("www.xot.example.com.")
	if aNameErr != nil {
		t.Fatalf("ParseName(a): %v", aNameErr)
	}
	aRecord := &protocol.ResourceRecord{
		Name:  aName,
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 7}},
	}
	closeSOA := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data: &protocol.RDataSOA{
			MName: mname, RName: rname,
			Serial: 43, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300,
		},
	}
	records := []*protocol.ResourceRecord{openSOA, aRecord, closeSOA}

	const requestID uint16 = 0x4242
	conn := &xotValidationConn{remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}
	srv := &XoTServer{}

	if err := srv.sendAXFRResponse(conn, records, requestID); err != nil {
		t.Fatalf("sendAXFRResponse: %v", err)
	}

	// Parse the length-prefixed frames and require EVERY response message in
	// the stream to echo the query's ID (RFC 5936 §2.2).
	buf := conn.Bytes()
	msgs := 0
	for len(buf) >= 2 {
		msgLen := int(buf[0])<<8 | int(buf[1])
		if msgLen == 0 || len(buf) < 2+msgLen {
			t.Fatalf("malformed frame: msgLen=%d remaining=%d", msgLen, len(buf))
		}
		msg, err := protocol.UnpackMessage(buf[2 : 2+msgLen])
		if err != nil {
			t.Fatalf("UnpackMessage on frame %d: %v", msgs, err)
		}
		msgs++
		if msg.Header.ID != requestID {
			t.Fatalf("FAIL: response message %d carries ID %d, want the query's ID %d (RFC 5936 §2.2: every message in the stream echoes the query ID)", msgs, msg.Header.ID, requestID)
		}
		buf = buf[2+msgLen:]
	}
	if msgs == 0 {
		t.Fatalf("no response frames were written")
	}
	t.Logf("PASS: all %d response messages echo the query ID %d", msgs, requestID)
}
