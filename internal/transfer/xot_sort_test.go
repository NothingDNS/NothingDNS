package transfer

// Round-3/10 regression guard: sortRecordsCanonically was an O(n²) selection
// sort running on the full zone record set during every AXFR/IXFR generation.
// A large zone paid quadratic comparisons (each with two string conversions)
// per transfer. This test pins both the canonical ORDER and the complexity
// class: a 20,000-record zone must sort well inside a bound that the O(n²)
// implementation cannot meet.

import (
	"fmt"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func makeCanonicalRecords(n int) []*protocol.ResourceRecord {
	records := make([]*protocol.ResourceRecord, 0, n)
	for i := 0; i < n; i++ {
		name, err := protocol.ParseName(fmt.Sprintf("host%05d.xot.example.com.", i))
		if err != nil {
			panic(err)
		}
		var rtype uint16 = protocol.TypeA
		var data protocol.RData = &protocol.RDataA{Address: [4]byte{192, 0, 2, byte(i % 251)}}
		if i%3 == 1 {
			rtype = protocol.TypeAAAA
			data = &protocol.RDataAAAA{Address: [16]byte{0x20, 0x01, 0xdb, 0x8: byte(i % 251)}}
		} else if i%3 == 2 {
			rtype = protocol.TypeTXT
			data = &protocol.RDataTXT{Strings: []string{fmt.Sprintf("record-%05d", i)}}
		}
		records = append(records, &protocol.ResourceRecord{
			Name:  name,
			Type:  rtype,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  data,
		})
	}
	return records
}

func assertCanonicalOrder(t *testing.T, records []*protocol.ResourceRecord) {
	t.Helper()
	for i := 1; i < len(records); i++ {
		if canonicalLess(records[i], records[i-1]) {
			t.Fatalf("records not in canonical order at index %d: %q after %q", i, records[i].Name.String(), records[i-1].Name.String())
		}
	}
}

func TestSortRecordsCanonicallyOrder(t *testing.T) {
	records := []*protocol.ResourceRecord{}
	// Interleave owners and types so the comparator exercises both axes.
	for _, suffix := range []string{"alpha", "beta"} {
		for i := 0; i < 3; i++ {
			name, err := protocol.ParseName(fmt.Sprintf("%s%02d.xot.example.com.", suffix, i))
			if err != nil {
				t.Fatalf("ParseName: %v", err)
			}
			records = append(records, &protocol.ResourceRecord{
				Name:  name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, byte(i)}},
			})
		}
	}

	(&XoTServer{}).sortRecordsCanonically(records)
	assertCanonicalOrder(t, records)
}

func TestSortRecordsCanonicallyHandles20kRecordZone(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive: skipped in -short mode")
	}
	records := makeCanonicalRecords(20000)

	start := time.Now()
	(&XoTServer{}).sortRecordsCanonically(records)
	elapsed := time.Since(start)

	assertCanonicalOrder(t, records)
	// The O(n²) selection sort with per-comparison string conversions takes
	// multiple seconds at this size; the stdlib sort finishes in milliseconds.
	if elapsed > 2*time.Second {
		t.Fatalf("FAIL: sorting 20,000 records took %s — the O(n²) selection sort is on the AXFR/IXFR transfer path", elapsed)
	}
	t.Logf("PASS: 20,000 records sorted in %s", elapsed)
}
