package transfer

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// TestXoTGenerateAXFRRecords_SingleApexSOAPerBoundary is the XoT counterpart of
// TestGenerateAXFRRecords_SingleApexSOAPerBoundary (axfr_soa_regression_test.go).
// The zone parser stores the apex SOA in both z.SOA and z.Records[apex], so
// XoTServer.generateAXFRRecords used to emit the SOA three times
// (start + mid-stream + end). RFC 5936 secondaries treat the second SOA as
// end-of-transfer and discard every record after it, truncating the zone for
// every XoT transfer (and for the IXFR AXFR-fallback path). The XoT stream
// must contain exactly two SOA records: first and last.
func TestXoTGenerateAXFRRecords_SingleApexSOAPerBoundary(t *testing.T) {
	const zoneText = `$ORIGIN example.test.
$TTL 3600
@   IN SOA ns1.example.test. admin.example.test. ( 2026071001 7200 3600 1209600 3600 )
@   IN NS  ns1.example.test.
ns1 IN A   192.0.2.1
@   IN A   192.0.2.10
www IN A   192.0.2.20
www IN AAAA 2001:db8::20
mail IN MX 10 mail.example.test.
`

	z, err := zone.ParseFile("example.test.zone", strings.NewReader(zoneText))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	// Sanity: the parser stores the apex SOA inside z.Records too — this is
	// the precondition that made the duplicate-SOA bug possible.
	var apexSOAsInRecords int
	for _, recs := range z.Records {
		for _, r := range recs {
			if strings.EqualFold(r.Type, "SOA") {
				apexSOAsInRecords++
			}
		}
	}
	if apexSOAsInRecords == 0 {
		t.Fatalf("test precondition failed: expected the parser to store the apex SOA in z.Records")
	}

	server, err := NewXoTServer(
		map[string]*zone.Zone{"example.test.": z},
		&XoTConfig{AllowedNetworks: []string{"127.0.0.1/32"}},
		nil,
	)
	if err != nil {
		t.Fatalf("NewXoTServer: %v", err)
	}

	t.Run("axfr", func(t *testing.T) {
		records, err := server.generateAXFRRecords(z)
		if err != nil {
			t.Fatalf("generateAXFRRecords: %v", err)
		}

		var soaCount int
		for _, rr := range records {
			if rr.Type == protocol.TypeSOA {
				soaCount++
			}
		}
		if soaCount != 2 {
			t.Fatalf("XoT AXFR stream has %d SOA records, want exactly 2 (first + last); duplicate mid-stream SOA truncates the zone on compliant secondaries", soaCount)
		}

		if len(records) < 2 || records[0].Type != protocol.TypeSOA || records[len(records)-1].Type != protocol.TypeSOA {
			t.Fatalf("XoT AXFR stream must start and end with SOA; got first=%v last=%v", records[0].Type, records[len(records)-1].Type)
		}

		var sawWWW bool
		for _, rr := range records {
			if strings.EqualFold(rr.Name.String(), "www.example.test.") {
				sawWWW = true
			}
		}
		if !sawWWW {
			t.Fatalf("XoT AXFR stream is missing www.example.test. records — zone appears truncated")
		}
	})

	t.Run("ixfr_axfr_fallback", func(t *testing.T) {
		// A client serial older than the zone with no journal configured must
		// degrade to the same full AXFR — and therefore obey the same
		// two-SOA-per-boundary contract.
		records, err := server.generateIXFRRecords(z, 1)
		if err != nil {
			t.Fatalf("generateIXFRRecords: %v", err)
		}

		var soaCount int
		for _, rr := range records {
			if rr.Type == protocol.TypeSOA {
				soaCount++
			}
		}
		if soaCount != 2 {
			t.Fatalf("XoT IXFR AXFR-fallback stream has %d SOA records, want exactly 2 (first + last)", soaCount)
		}
	})
}
