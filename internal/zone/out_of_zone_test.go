package zone

import (
	"strings"
	"testing"
)

// F696: a zone file's out-of-zone records are ignored with a warning (as
// BIND does), not served, transferred or signed as the zone's data.
func TestParseFile_IgnoresOutOfZoneRecords(t *testing.T) {
	src := `$ORIGIN example.com.
$TTL 300
@ IN SOA ns1 admin 1 3600 600 604800 300
@ IN NS ns1
ns1 IN A 192.0.2.1
foo.example.org. IN A 192.0.2.2
notexample.com. IN TXT "x"
$ORIGIN sub.example.com.
www IN A 192.0.2.3
`
	z, err := ParseFile("example.com.zone", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if z.Origin != "example.com." {
		t.Fatalf("origin = %q", z.Origin)
	}
	for _, name := range []string{"foo.example.org.", "notexample.com."} {
		if _, ok := z.Records[name]; ok {
			t.Errorf("out-of-zone %s kept", name)
		}
	}
	for _, name := range []string{"example.com.", "ns1.example.com.", "www.sub.example.com."} {
		if len(z.Records[name]) == 0 {
			t.Errorf("in-zone %s dropped", name)
		}
	}
	want := []string{
		"example.com.zone:6: ignoring out-of-zone record foo.example.org. A (zone example.com.)",
		"example.com.zone:7: ignoring out-of-zone record notexample.com. TXT (zone example.com.)",
	}
	if strings.Join(z.Warnings, "\n") != strings.Join(want, "\n") {
		t.Fatalf("warnings = %q, want %q", z.Warnings, want)
	}
}
