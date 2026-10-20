package zone

import (
	"strings"
	"testing"
)

// RFC 1035 §5.1: a record line that starts with whitespace takes the last
// stated owner name — the same name, not the same text re-read against a
// $ORIGIN that changed in between.
func TestInheritedOwnerSurvivesOriginChange(t *testing.T) {
	const src = `$TTL 300
$ORIGIN example.com.
@ IN SOA ns1 hostmaster 1 3600 900 604800 300
@ IN NS ns1
ns1 IN A 192.0.2.1
www IN A 192.0.2.10
$ORIGIN sub.example.com.
    IN A 192.0.2.20
other IN A 192.0.2.30
`
	z, err := ParseFile("example.com.zone", strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	addrs := func(name string) []string {
		var out []string
		for _, r := range z.Lookup(name, "A") {
			out = append(out, r.RData)
		}
		return out
	}

	// Control: explicit owners resolve against the origin in force.
	if got := addrs("other.sub.example.com."); len(got) != 1 || got[0] != "192.0.2.30" {
		t.Fatalf("control: other.sub.example.com. A = %v", got)
	}
	if got := addrs("www.example.com."); len(got) != 2 {
		t.Fatalf("FAIL: www.example.com. A = %v, want both 192.0.2.10 and the inherited 192.0.2.20", got)
	}
	if got := addrs("www.sub.example.com."); len(got) != 0 {
		t.Fatalf("FAIL: inherited owner re-resolved under the new origin: www.sub.example.com. A = %v", got)
	}
}
