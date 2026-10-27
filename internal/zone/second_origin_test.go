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
