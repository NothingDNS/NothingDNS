package zone

// F691: a zone file with no $TTL used to give every record without a TTL the
// value 0 (uncacheable). RFC 1035 §5.1: the last stated TTL, and for records
// before any the SOA minimum (BIND's behaviour).

import (
	"strings"
	"testing"
)

func TestMissingTTLDefaults(t *testing.T) {
	soa := "@ IN SOA ns1 h 1 7200 3600 86400 900\n@ NS ns1\n"
	ttlOf := func(z *Zone, name string) uint32 {
		rs := z.Records[name]
		if len(rs) != 1 {
			t.Fatalf("%s: %d records", name, len(rs))
		}
		return rs[0].TTL
	}
	parse := func(src string) *Zone {
		z, err := ParseFile("z", strings.NewReader(src))
		if err != nil {
			t.Fatal(err)
		}
		return z
	}
	// $TTL present: unchanged, an explicit TTL does not become the default.
	z := parse("$ORIGIN example.com.\n$TTL 300\n" + soa + "a A 192.0.2.1\nb 77 A 192.0.2.2\nc A 192.0.2.3\n")
	if ttlOf(z, "a.example.com.") != 300 || ttlOf(z, "b.example.com.") != 77 || ttlOf(z, "c.example.com.") != 300 {
		t.Errorf("$TTL file: a=%d b=%d c=%d", ttlOf(z, "a.example.com."), ttlOf(z, "b.example.com."), ttlOf(z, "c.example.com."))
	}
	// An explicit $TTL 0 is deliberate and stays 0.
	z = parse("$ORIGIN example.com.\n$TTL 0\n" + soa + "a A 192.0.2.1\n")
	if ttlOf(z, "a.example.com.") != 0 {
		t.Errorf("$TTL 0: a=%d", ttlOf(z, "a.example.com."))
	}
	// No $TTL: records before any stated TTL take the SOA minimum, later ones
	// inherit the last stated TTL.
	z = parse("$ORIGIN example.com.\n" + soa + "a A 192.0.2.1\nb 77 A 192.0.2.2\nc A 192.0.2.3\n")
	if got := ttlOf(z, "a.example.com."); got != 900 {
		t.Errorf("a = %d, want SOA minimum 900", got)
	}
	if got := ttlOf(z, "b.example.com."); got != 77 {
		t.Errorf("b = %d, want explicit 77", got)
	}
	if got := ttlOf(z, "c.example.com."); got != 77 {
		t.Errorf("c = %d, want last stated 77", got)
	}
	if z.SOA.TTL != 900 || z.DefaultTTL != 900 {
		t.Errorf("SOA.TTL = %d, DefaultTTL = %d, want 900", z.SOA.TTL, z.DefaultTTL)
	}
	// The SOA record itself, with an explicit TTL, anchors the following ones.
	z = parse("$ORIGIN example.com.\n@ 3600 IN SOA ns1 h 1 7200 3600 86400 900\n@ NS ns1\na A 192.0.2.1\n")
	if got := ttlOf(z, "a.example.com."); got != 3600 {
		t.Errorf("after explicit SOA TTL: a = %d, want 3600", got)
	}
}
