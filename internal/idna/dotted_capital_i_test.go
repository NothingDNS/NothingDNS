package idna

import "testing"

// F704: U+0130 (LATIN CAPITAL LETTER I WITH DOT ABOVE) lower-cases to "i" +
// U+0307 under the full case mapping RFC 5895 §2 requires (Unicode
// SpecialCasing); Go's unicode.ToLower gives the simple mapping, a plain "i",
// so "bİ1" collapsed onto the ASCII name "bi1" instead of "xn--bi1-9dc".
func TestToASCIIDottedCapitalI(t *testing.T) {
	got, err := ToASCII("bİ1.example")
	if err != nil {
		t.Fatal(err)
	}
	if got != "xn--bi1-9dc.example" {
		t.Errorf("ToASCII(bİ1.example) = %q, want xn--bi1-9dc.example", got)
	}
	// control: the decomposed spelling already gave this, and plain ASCII
	// and other upper-case letters are unchanged
	for in, want := range map[string]string{
		"bi\u03071.example": "xn--bi1-9dc.example",
		"BI1.example":       "BI1.example",
	} {
		if got, err := ToASCII(in); err != nil || got != want {
			t.Errorf("ToASCII(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
