package zone

// Round-8/10 regression guard: the paren-continuation accumulation path in
// parse() stripped comments with a naive strings.Index(line, ";") and counted
// parentheses without quote-awareness — so a multi-line TXT record whose
// quoted strings contain semicolons (the standard DKIM record shape) was
// truncated at its first quoted semicolon during paren accumulation, even
// though parseRecordOwned itself strips comments quote-aware via
// stripZoneComment. The same record parsed correctly on a single line.

import (
	"strings"
	"testing"
)

func TestParseFileMultiLineParenPreservesQuotedSemicolons(t *testing.T) {
	zoneFile := `$ORIGIN example.com.
_test 300 IN TXT ("v=DKIM1; k=rsa; "
	"p=MIGfMA0GCSqGSIb3DQEB")
`
	z, err := ParseFile("xot.example.com.zone", strings.NewReader(zoneFile))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	recs := z.Records["_test.example.com."]
	if len(recs) == 0 {
		t.Fatalf("FAIL: the _test.example.com. record missing from the parsed zone")
	}
	rdata := recs[0].RData

	// The contract: the quoted semicolons survive paren accumulation — the
	// DKIM record content is intact end-to-end.
	if !strings.Contains(rdata, "v=DKIM1; k=rsa;") {
		t.Fatalf("FAIL: the quoted semicolons were truncated by the paren-continuation accumulation: %q", rdata)
	}
	if !strings.Contains(rdata, "p=MIGfMA0GCSqGSIb3DQEB") {
		t.Fatalf("FAIL: the second TXT string missing from the RData: %q", rdata)
	}
}

func TestParseFileMultiLineParenPlainStillParses(t *testing.T) {
	// The not-overcorrected control: a plain multi-line TXT (no quoted
	// semicolons or parens in the content) must keep parsing — the parens
	// are line continuations, not content.
	zoneFile := `$ORIGIN example.com.
_plain 300 IN TXT ("part one "
	"part two end")
`
	z, err := ParseFile("xot.example.com.zone", strings.NewReader(zoneFile))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	recs := z.Records["_plain.example.com."]
	if len(recs) == 0 {
		t.Fatalf("FAIL: the _plain.example.com. record missing from the parsed zone")
	}
	rdata := recs[0].RData
	if !strings.Contains(rdata, "part one") || !strings.Contains(rdata, "part two end") {
		t.Fatalf("FAIL: the plain multi-line TXT did not parse: %q", rdata)
	}
}
