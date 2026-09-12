package zone

// Round-2/25 regression guard: storedRecordsToZone's SOA search broke out of
// the name loop unconditionally after the first-visited name — Go's
// randomized map iteration means the SOA record (which lives on the apex)
// was only found if the apex happened to be visited first, leaving
// z.SOA = nil on virtually every KV-loaded zone. Every consumer of z.SOA
// (serial checks, the DDNS SOA-replacement rule) then hits nil-pointer
// territory.

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/storage"
)

func TestStoredRecordsToZoneFindsSOARegardlessOfMapOrder(t *testing.T) {
	k := NewKVPersistence(nil, nil)
	meta := storage.ZoneMeta{Origin: "example.com.", DefaultTTL: 300}

	records := map[string][]storage.StoredRecord{
		"example.com.": {
			{Name: "example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.example.com. hostmaster.example.com. 2024010101 3600 900 604800 86400"},
		},
		"www.example.com.": {
			{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
		},
	}

	// Go's map iteration order is randomized per-range, so one pass can pass
	// by luck (the apex visited first). 100 rounds make a map-order-dependent
	// SOA search fail deterministically-in-practice.
	for i := 0; i < 100; i++ {
		z := k.storedRecordsToZone(meta, records)
		if z.SOA == nil {
			t.Fatalf("FAIL: iteration %d — z.SOA is nil after loading a zone whose apex holds the SOA record (the SOA search is map-order-dependent)", i)
		}
		if z.SOA.Serial != 2024010101 {
			t.Fatalf("FAIL: iteration %d — z.SOA.Serial = %d, want 2024010101", i, z.SOA.Serial)
		}
	}
}
