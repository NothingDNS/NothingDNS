package zone

// F689: a token before the record type that is not a TTL, class or type is a parse
// error (an unsupported mnemonic such as CSYNC used to be skipped, and a later
// token spelling a type became the record).

import (
	"strings"
	"testing"
)

func f689Parse(line string) (*Zone, error) {
	return ParseFile("z", strings.NewReader("$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns1 h 1 2 3 4 5\n@ NS ns1\n"+line+"\n"))
}

func TestUnknownTokenBeforeTypeRejected(t *testing.T) {
	// controls: a valid line parses; a line with no known type token already errors
	if z, err := f689Parse("ok IN A 192.0.2.1"); err != nil || len(z.Records["ok.example.com."]) != 1 {
		t.Fatalf("control A: %v", err)
	}
	if _, err := f689Parse("nid IN NID 10 0014:4fff:ff20:ee64"); err == nil {
		t.Fatalf("control unknown mnemonic without a type-looking token should already error")
	}
	for _, line := range []string{"csync IN CSYNC 66 3 A NS AAAA", "www xyz IN A 192.0.2.1", "w IN 3600x A 192.0.2.1"} {
		if z, err := f689Parse(line); err == nil {
			t.Errorf("%q parsed without error: %+v", line, z.Records)
		}
	}
	// A TYPE<n> mnemonic is a type (F688) and still parses.
	if _, err := f689Parse("w IN TYPE65280 \\# 1 00"); err != nil {
		t.Errorf("TYPE65280 line: %v", err)
	}
}
