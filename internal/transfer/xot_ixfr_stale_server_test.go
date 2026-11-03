package transfer

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestXoTIXFRServerBehindClientFallsBackToAXFR(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		Name: "example.com.", MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 100, TTL: 3600, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}
	z.Records["www.example.com."] = []zone.Record{{
		Name: "www.example.com.", Type: "A", TTL: 300, RData: "192.0.2.1",
	}}

	records, err := (&XoTServer{}).generateIXFRRecords(z, 200)
	if err != nil {
		t.Fatalf("generateIXFRRecords: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("server behind client returned %d records, want full SOA/A/SOA AXFR", len(records))
	}
	if records[0].Type != protocol.TypeSOA || records[1].Type != protocol.TypeA || records[2].Type != protocol.TypeSOA {
		t.Fatalf("server behind client returned types %d/%d/%d, want SOA/A/SOA", records[0].Type, records[1].Type, records[2].Type)
	}
}
