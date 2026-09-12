package main

// Round-3/25 regression guard: nsecRecord rewrote an explicit TTL 0 (the
// no-caching semantics, per the falsy-zero family fixed in rounds 18/20/26
// on the TS side) to 3600 on every negative answer's NSEC records.

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestNsecRecordPreservesExplicitTTLZero(t *testing.T) {
	data := zone.NSECRecordData{
		Owner: "_covered.example.com.",
		Next:  "_end.example.com.",
		Types: []string{"A", "NSEC"},
	}

	rr := nsecRecord(data, 0)
	if rr == nil {
		t.Fatalf("FAIL: nsecRecord returned nil for a valid NSEC data set")
	}
	if rr.TTL != 0 {
		t.Fatalf("FAIL: explicit TTL 0 was rewritten to %d — the falsy-zero family's Go-side instance", rr.TTL)
	}
	if rr.Type != protocol.TypeNSEC {
		t.Fatalf("FAIL: the record type is not NSEC: %d", rr.Type)
	}
}

func TestNsecRecordPreservesNonzeroTTL(t *testing.T) {
	data := zone.NSECRecordData{
		Owner: "_covered.example.com.",
		Next:  "_end.example.com.",
		Types: []string{"A", "NSEC"},
	}

	rr := nsecRecord(data, 300)
	if rr == nil {
		t.Fatalf("FAIL: nsecRecord returned nil for a valid NSEC data set")
	}
	if rr.TTL != 300 {
		t.Fatalf("FAIL: TTL 300 was rewritten to %d", rr.TTL)
	}
}
