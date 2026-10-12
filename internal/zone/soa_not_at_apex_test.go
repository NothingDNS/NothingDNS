package zone

import (
	"strings"
	"testing"
)

// F701: an SOA record at a non-apex owner was accepted and its data replaced
// the zone's SOA (serial, MNAME, timers — what AXFR/IXFR and SOA answers
// use) while the apex SOA record kept the old values, so a zone file with a
// stray SOA served and transferred two different SOAs. BIND refuses such a
// file ("SOA not at top of zone").
func TestParseSOANotAtApex(t *testing.T) {
	base := "$ORIGIN example.com.\n$TTL 300\n@ SOA ns h 1 2 3 4 5\n@ NS ns\n"
	_, err := ParseFile("x", strings.NewReader(base+"sub SOA ns2 h2 99 2 3 4 5\n"))
	if err == nil {
		t.Fatalf("SOA at sub.example.com. accepted")
	}
	// controls: apex SOA by '@', by name, and a plain record
	for _, src := range []string{
		base,
		"$ORIGIN example.com.\n$TTL 300\nexample.com. SOA ns h 1 2 3 4 5\n@ NS ns\n",
		base + "www A 192.0.2.1\n",
	} {
		z, err := ParseFile("x", strings.NewReader(src))
		if err != nil {
			t.Fatalf("valid zone rejected: %v\n%s", err, src)
		}
		if z.SOA == nil || z.SOA.Serial != 1 {
			t.Errorf("SOA = %+v", z.SOA)
		}
	}
}
