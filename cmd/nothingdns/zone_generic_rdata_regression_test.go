package main

// F688: a record of a type the server does not model (RFC 3597 TYPE<n> with
// `\# <len> <hex>` RDATA, as a zone file or a slave transfer stores it) is
// answered for a query of that type.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestZoneGenericRDataAnswered(t *testing.T) {
	z, err := zone.ParseFile("z", strings.NewReader("$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\nx TYPE65280 \\# 4 01020304\n"))
	if err != nil {
		t.Fatal(err)
	}
	h := newTestHandler()
	h.zones["example.com."] = z
	h.zoneProvider = NewMultiZoneProvider(h.zones, nil, nil, nil)
	msg := newTestQuery(t, "x.example.com.", 65280)
	w := newCaptureWriter("192.0.2.10", "udp")
	h.ServeDNS(w, msg)
	if w.msg == nil || len(w.msg.Answers) != 1 {
		t.Fatalf("TYPE65280 answered %+v, want 1 answer", w.msg)
	}
	rr := w.msg.Answers[0]
	buf := make([]byte, 64)
	n, err := rr.Data.Pack(buf, 0)
	if err != nil || !bytes.Equal(buf[:n], []byte{1, 2, 3, 4}) {
		t.Fatalf("answer rdata %x (%v), want 01020304", buf[:n], err)
	}
}
