package zone

import (
	"strings"
	"testing"
)

// F702: an unterminated quote swallowed the rest of the line into one field,
// so `@ MX " 10 mail` loaded as an MX whose text was "10 mail" (one quoted
// token) — stored with the target relative and unqualified — and the
// written-out zone then read back differently. BIND: "unbalanced quotes".
func TestParseUnterminatedQuote(t *testing.T) {
	base := "$ORIGIN example.com.\n$TTL 300\n@ SOA ns h 1 2 3 4 5\n@ NS ns\n"
	for _, line := range []string{
		`@ MX " 10 mail`,
		`@ TXT "abc`,
		`txt TXT "a" "b`,
		`@ CAA 0 issue "x`,
	} {
		if _, err := ParseFile("x", strings.NewReader(base+line+"\n")); err == nil {
			t.Errorf("%q accepted", line)
		}
	}
	// controls: balanced quotes, escaped quote, quote inside a comment, a
	// semicolon inside quotes
	for _, line := range []string{
		`@ MX 10 mail`,
		`@ TXT "abc"`,
		`@ TXT "a \"quoted\" word"`,
		`@ TXT "a;b" ; comment with " quote`,
		`@ TXT key="a b"`,
	} {
		if _, err := ParseFile("x", strings.NewReader(base+line+"\n")); err != nil {
			t.Errorf("%q rejected: %v", line, err)
		}
	}
}
