package main

// F687: an apex SOA written with BIND unit timers (3H 1H 1W 1D) is answered for an
// SOA query; its stored text used to be unparseable, giving an empty NOERROR.

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func soaUnitsQuery(t *testing.T, times string) (answers int, rr string) {
	z, err := zone.ParseFile("z", strings.NewReader("$ORIGIN example.com.\n$TTL 1h\n@ IN SOA ns1 h 2024010101 "+times+"\n@ NS ns1\nns1 A 192.0.2.1\n"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	h := newTestHandler()
	h.zones["example.com."] = z
	h.zoneProvider = NewMultiZoneProvider(h.zones, nil, nil, nil)
	msg := newTestQuery(t, "example.com.", protocol.TypeSOA)
	w := newCaptureWriter("192.0.2.10", "udp")
	h.ServeDNS(w, msg)
	if w.msg == nil {
		t.Fatalf("no response")
	}
	if len(w.msg.Answers) > 0 {
		rr = w.msg.Answers[0].String()
	}
	return len(w.msg.Answers), rr
}

func TestSOATimerUnitsApexSOAQuery(t *testing.T) {
	// control: numeric SOA timers are answered
	if n, _ := soaUnitsQuery(t, "10800 3600 604800 86400"); n != 1 {
		t.Fatalf("control numeric SOA answered %d records", n)
	}
	// defect: the canonical BIND unit spelling
	n, rr := soaUnitsQuery(t, "3H 1H 1W 1D")
	if n != 1 || !strings.Contains(rr, "10800 3600 604800 86400") {
		t.Fatalf("SOA query answered %d records %q, want 1 with the timers in seconds", n, rr)
	}
}
