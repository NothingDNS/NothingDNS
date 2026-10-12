package zone

import (
	"strings"
	"testing"
)

// F711: the "X" radix of $GENERATE produced lower-case hex (BIND: x and X are
// lower- and upper-case hex).
func TestGenerateUpperCaseHexRadix(t *testing.T) {
	src := "$ORIGIN example.com.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\n@ NS ns\n" +
		"$GENERATE 10-11 t$ TXT \"U${0,2,X} l${0,2,x} d${0,3,d} o${0,3,o}\"\n"
	z, err := ParseFile("example.com.", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	for n, want := range map[string]string{
		"t10.example.com.": "U0A l0a d010 o012",
		"t11.example.com.": "U0B l0b d011 o013",
	} {
		recs := z.Records[n]
		if len(recs) != 1 || !strings.Contains(recs[0].RData, want) {
			t.Errorf("%s = %+v, want RDATA containing %q", n, recs, want)
		}
	}
}
