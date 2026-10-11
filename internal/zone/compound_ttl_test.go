package zone

// F686: BIND combined TTL units (1h30m, 1w2d) in record lines and $TTL. A record
// line used to skip the unrecognized token and fall back to $TTL silently.

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func f686Parse(src string) (*Zone, error) {
	return ParseFile("z", strings.NewReader(src))
}

func TestCompoundTTLInZoneFile(t *testing.T) {
	soa := "@ IN SOA ns1 h 1 2 3 4 5\n@ IN NS ns1\n"
	ttlOf := func(t *testing.T, head, line string) (uint32, error) {
		z, err := f686Parse("$ORIGIN example.com.\n" + head + soa + line + "\n")
		if err != nil {
			return 0, err
		}
		recs := z.Records["r.example.com."]
		if len(recs) != 1 {
			t.Fatalf("record missing")
		}
		return recs[0].TTL, nil
	}
	// controls: single-unit TTLs work
	for in, want := range map[string]uint32{"60": 60, "1h": 3600, "1d": 86400, "2w": 1209600} {
		if got, err := ttlOf(t, "$TTL 300\n", "r "+in+" IN A 192.0.2.1"); err != nil || got != want {
			t.Fatalf("control %s: %d %v", in, got, err)
		}
	}
	for in, want := range map[string]uint32{"1h30m": 5400, "1d2h": 93600, "1w2d3h4m5s": 604800 + 172800 + 10800 + 240 + 5} {
		got, err := ttlOf(t, "$TTL 300\n", "r "+in+" IN A 192.0.2.1")
		if err != nil || got != want {
			t.Errorf("record TTL %s = %d (err %v), want %d", in, got, err, want)
		}
		got, err = ttlOf(t, "$TTL "+in+"\n", "r IN A 192.0.2.1")
		if err != nil || got != want {
			t.Errorf("$TTL %s = %d (err %v), want %d", in, got, err, want)
		}
	}
}

// F687: SOA timers written with BIND units are stored as plain seconds, so the
// stored RDATA parses and the apex SOA RR can be served.
func TestSOATimerUnitsStoredAsSeconds(t *testing.T) {
	z, err := f686Parse("$ORIGIN example.com.\n$TTL 1h\n@ IN SOA ns1 h 2024010101 3H 1H 1W 1D\n@ NS ns1\n")
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	for _, r := range z.Records["example.com."] {
		if r.Type == "SOA" {
			stored = r.RData
		}
	}
	const want = "ns1.example.com. h.example.com. 2024010101 10800 3600 604800 86400"
	if stored != want {
		t.Fatalf("stored SOA = %q, want %q", stored, want)
	}
	if protocol.ParseRDataText("SOA", stored) == nil {
		t.Fatalf("stored SOA %q does not parse", stored)
	}
	if z.SOA.Refresh != 10800 || z.SOA.Minimum != 86400 {
		t.Fatalf("SOA struct timers = %+v", z.SOA)
	}
}
