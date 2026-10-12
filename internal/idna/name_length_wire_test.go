package idna

import (
	"strings"
	"testing"
)

// F703: MaxNameLength (255) is the wire limit, but ToASCII compared the
// presentation string against it. A name of 254 or 255 characters needs 256
// or 257 wire bytes and can never be encoded; it passed IDNA and failed later
// in ParseName. The longest valid presentation form is 253 characters.
func TestToASCIIPresentationLengthLimit(t *testing.T) {
	build := func(n int) string {
		var parts []string
		for n > 0 {
			k := 63
			if n < k {
				k = n
			}
			parts = append(parts, strings.Repeat("a", k))
			n -= k + 1
		}
		return strings.Join(parts, ".")
	}
	for _, n := range []int{253, 100} {
		if name := build(n); len(name) != n {
			t.Fatalf("test builder: len %d != %d", len(name), n)
		}
		if _, err := ToASCII(build(n)); err != nil {
			t.Errorf("len %d rejected: %v", n, err)
		}
	}
	for _, n := range []int{254, 255} {
		name := build(n)
		if len(name) != n {
			t.Fatalf("test builder: len %d != %d", len(name), n)
		}
		if _, err := ToASCII(name); err == nil {
			t.Errorf("len %d accepted (needs %d wire bytes)", n, n+2)
		}
	}
}
