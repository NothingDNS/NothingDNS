package protocol

import "testing"

// F693: ParseName split on "." and treated an empty label as valid, so
// "a..b.example.com." produced a wire name with a root byte in the middle
// (01 61 00 01 62 ...). Packed into a record it corrupts the message.
func TestParseNameRejectsEmptyLabel(t *testing.T) {
	for _, s := range []string{"a..b.example.com.", ".a.example.com.", "..", "a.b..", ".", "a.."} {
		n, err := ParseName(s)
		if s == "." {
			if err != nil || !n.IsRoot() {
				t.Errorf("ParseName(%q) = %v, %v; want root", s, n, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("ParseName(%q) accepted, wire=%x", s, n.CanonicalWire())
		}
	}
	for _, s := range []string{"a.b.", "a.b", "*.w.example.com.", "_dmarc.example.com."} {
		if _, err := ParseName(s); err != nil {
			t.Errorf("ParseName(%q) rejected: %v", s, err)
		}
	}
}
