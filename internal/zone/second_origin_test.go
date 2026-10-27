package zone

// F690: a later $ORIGIN (a sub-delegation section) changes the origin names are
// resolved against, not the zone's own origin. The zone used to be renamed to
// the last $ORIGIN of the file, so the manager registered it under the wrong
// name and its apex was never found.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secondOriginHead = "$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\n"

func TestSecondOriginKeepsZoneOrigin(t *testing.T) {
	z, err := ParseFile("z", strings.NewReader(secondOriginHead+
		"$ORIGIN sub.example.com.\nwww A 192.0.2.3\n@ A 192.0.2.4\n$ORIGIN deep\nh A 192.0.2.5\n$ORIGIN other.org.\nx A 192.0.2.6\n"))
	if err != nil {
		t.Fatal(err)
	}
	if z.Origin != "example.com." {
		t.Fatalf("zone origin = %q, want example.com.", z.Origin)
	}
	for _, name := range []string{"www.sub.example.com.", "sub.example.com.", "h.deep.sub.example.com."} {
		if len(z.Records[name]) != 1 {
			t.Errorf("record %s missing (names: %v)", name, keys(z.Records))
		}
	}
	// x is resolved against other.org., which is outside the zone: it is
	// ignored with a warning (F696).
	if _, ok := z.Records["x.other.org."]; ok || len(z.Warnings) != 1 || !strings.Contains(z.Warnings[0], "x.other.org.") {
		t.Errorf("out-of-zone x.other.org.: kept=%v warnings=%q", ok, z.Warnings)
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestSecondOriginManagerRegistersApex(t *testing.T) {
	p := filepath.Join(t.TempDir(), "example.com.zone")
	if err := os.WriteFile(p, []byte(secondOriginHead+"$ORIGIN sub.example.com.\nwww A 192.0.2.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManager()
	if err := m.Load("example.com.", p); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Get("example.com."); !ok {
		t.Fatalf("zone not registered as example.com.: %v", keys(m.List()))
	}
}

// F731: the apex was taken from the first $ORIGIN even when the SOA came
// before it, so a file written with absolute names that used $ORIGIN for a
// later section loaded as that section's zone (and, with out-of-zone data
// dropped, lost its own apex records).
func TestSOABeforeFirstOriginNamesTheApex(t *testing.T) {
	const soa = "example.com. 3600 IN SOA ns1.example.com. h.example.com. 1 3600 600 86400 300\nexample.com. 3600 IN NS ns1.example.com.\n"
	z, err := ParseFile("x.zone", strings.NewReader(soa+"$ORIGIN sub.example.com.\n@ 3600 IN NS ns1.sub\nns1 A 192.0.2.9\n"))
	if err != nil {
		t.Fatal(err)
	}
	if z.Origin != "example.com." || len(z.Warnings) != 0 || len(z.Records["ns1.sub.example.com."]) != 1 {
		t.Fatalf("origin %s, warnings %v", z.Origin, z.Warnings)
	}
	if err := z.Validate(); err != nil {
		t.Fatal(err)
	}

	// Without any $ORIGIN (dig AXFR output) the SOA owner is the apex too.
	z, err = ParseFile("x.zone", strings.NewReader(soa+"www.example.com. 300 IN A 192.0.2.2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if z.Origin != "example.com." || z.Validate() != nil {
		t.Fatalf("no $ORIGIN: origin %s, %v", z.Origin, z.Validate())
	}
}
