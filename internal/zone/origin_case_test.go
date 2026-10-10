package zone

// F676: $ORIGIN was stored as written while owner names are keyed in lower case,
// so a zone with a mixed-case origin was not found by the (lower-casing) manager
// and API, and WriteZone emitted its apex SOA and NS twice.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mixedCaseOriginZone(origin string) string {
	return "$ORIGIN " + origin + "\n$TTL 300\n@ IN SOA ns1 admin 7 3600 600 86400 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.2\n"
}

// mixedCaseOriginProbe loads the zone from a file and reports what the API-facing
// surface (normalized lowercase names) and the writer do with it.
func mixedCaseOriginProbe(t *testing.T, origin string) (found bool, soaLines, nsLines int, addErr error) {
	p := filepath.Join(t.TempDir(), "z.zone")
	if err := os.WriteFile(p, []byte(mixedCaseOriginZone(origin)), 0o644); err != nil {
		t.Fatal(err)
	}
	m := NewManager()
	if err := m.Load("x", p); err != nil {
		t.Fatalf("INVALID PROOF: load: %v", err)
	}
	_, found = m.Get("example.com.") // what normalizeZoneName hands the manager
	addErr = m.AddRecord("example.com.", Record{Name: "new", Type: "A", TTL: 60, RData: "192.0.2.9"})
	z, ok := m.List()["example.com."]
	if !ok {
		for _, zz := range m.List() {
			z = zz
		}
	}
	out, err := WriteZone(z)
	if err != nil {
		t.Fatalf("INVALID PROOF: WriteZone: %v", err)
	}
	return found, strings.Count(out, "\tSOA\t"), strings.Count(out, "\tNS\t"), addErr
}

func TestParseFile_MixedCaseOriginIsLowerCased(t *testing.T) {
	// 1. proof scenario
	f, s, n, e := mixedCaseOriginProbe(t, "Example.COM.")
	if !f || e != nil || s != 1 || n != 1 {
		t.Fatalf("found=%v add=%v soa=%d ns=%d", f, e, s, n)
	}
	// 2. origin is stored lower-case; write/reparse/write is stable; lookups work
	z, err := ParseFile("z", strings.NewReader(mixedCaseOriginZone("Example.COM.")))
	if err != nil {
		t.Fatal(err)
	}
	if z.Origin != "example.com." {
		t.Fatalf("Origin = %q", z.Origin)
	}
	out, _ := WriteZone(z)
	z2, err := ParseFile("z2", strings.NewReader(out))
	if err != nil {
		t.Fatalf("reparse: %v\n%s", err, out)
	}
	out2, _ := WriteZone(z2)
	if out != out2 || strings.Count(out, "\tSOA\t") != 1 || strings.Count(out, "\tNS\t") != 1 {
		t.Fatalf("write not stable or duplicated:\n%s\n---\n%s", out, out2)
	}
	if got := z.Lookup("www.example.com.", "A"); len(got) != 1 {
		t.Fatalf("Lookup www = %v", got)
	}
	if got := z.Lookup("example.com.", "NS"); len(got) != 1 {
		t.Fatalf("Lookup apex NS = %v", got)
	}
	// 3. a $INCLUDE with a mixed-case origin override is lower-cased too
	dir := t.TempDir()
	inc := filepath.Join(dir, "inc.zone")
	if err := os.WriteFile(inc, []byte("host IN A 192.0.2.77\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(dir, "main.zone")
	body := mixedCaseOriginZone("example.com.") + "$INCLUDE inc.zone Sub.Example.COM.\n"
	if err := os.WriteFile(main, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	f3, err := os.Open(main)
	if err != nil {
		t.Fatal(err)
	}
	defer f3.Close()
	z3, err := ParseFile(main, f3)
	if err != nil {
		t.Fatalf("include parse: %v", err)
	}
	if z3.Origin != "example.com." {
		t.Fatalf("Origin after include = %q", z3.Origin)
	}
	if got := z3.Lookup("host.sub.example.com.", "A"); len(got) != 1 {
		t.Fatalf("included record not found: %v", got)
	}
	// 4. already-lower-case origins are unaffected
	if f, s, n, e := mixedCaseOriginProbe(t, "example.com."); !f || e != nil || s != 1 || n != 1 {
		t.Fatalf("control regressed: %v %v %d %d", f, e, s, n)
	}
}
