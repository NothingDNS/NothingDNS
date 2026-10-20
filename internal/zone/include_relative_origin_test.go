package zone

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RFC 1035 §5.1: the optional $INCLUDE origin is a domain name that, like
// $ORIGIN, is relative to the current origin when it does not end in a dot.
func TestIncludeRelativeOriginResolvesAgainstCurrentOrigin(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "inc.zone"), []byte("host IN A 192.0.2.7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "abs.zone"), []byte("host IN A 192.0.2.8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const src = `$TTL 300
$ORIGIN example.com.
@ IN SOA ns1 hostmaster 1 3600 900 604800 300
@ IN NS ns1
ns1 IN A 192.0.2.1
$INCLUDE inc.zone sub
$INCLUDE abs.zone other.example.com.
$INCLUDE inc.zone @
after IN A 192.0.2.9
`
	z, err := ParseFile(filepath.Join(dir, "example.com.zone"), strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	has := func(name, rdata string) bool {
		for _, r := range z.Lookup(name, "A") {
			if r.RData == rdata {
				return true
			}
		}
		return false
	}

	// Control: an absolute include origin and the origin after the include.
	if !has("host.other.example.com.", "192.0.2.8") {
		t.Fatal("control: absolute include origin not applied")
	}
	if !has("after.example.com.", "192.0.2.9") {
		t.Fatal("control: origin not restored after $INCLUDE")
	}
	if !has("host.sub.example.com.", "192.0.2.7") {
		t.Fatalf("FAIL: relative include origin %q not resolved against example.com.; names: %v", "sub", includeTestNames(z))
	}
	if !has("host.example.com.", "192.0.2.7") {
		t.Fatalf("FAIL: '@' include origin is not the current origin; names: %v", includeTestNames(z))
	}
}

func includeTestNames(z *Zone) []string {
	var out []string
	for k := range z.Records {
		out = append(out, k)
	}
	return out
}
