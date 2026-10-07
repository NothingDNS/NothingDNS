package idna

import (
	"errors"
	"testing"
	"unicode"
)

// F622: the Bidi rule uses the exact Unicode Bidi_Class table (F631: of
// the toolchain's Unicode version).

func TestTablesUnicodeVersion(t *testing.T) {
	// The generated tables must describe the Unicode version of the
	// standard library (script and category lookups use it): one
	// tables<version>.go per supported toolchain, selected by build
	// constraint (F631); regenerate with gen_idna_tables.go when a Go
	// release changes unicode.Version.
	if tablesUnicodeVersion != unicode.Version {
		t.Fatalf("tables%s.go selected, standard library is Unicode %s: generate tables%s.go", tablesUnicodeVersion, unicode.Version, unicode.Version)
	}
}

func TestBidiTableSorted(t *testing.T) {
	for i, r := range bidiRanges {
		if r.lo > r.hi || r.class == bidiL {
			t.Fatalf("entry %d %+v malformed", i, r)
		}
		if i > 0 && bidiRanges[i-1].hi >= r.lo {
			t.Fatalf("entries %d/%d overlap or are unsorted", i-1, i)
		}
	}
}

func TestBidiClassKnownValues(t *testing.T) {
	cases := map[rune]bidiClass{
		'a': bidiL, 'Z': bidiL, '0': bidiEN, '-': bidiES, '.': bidiCS,
		0x00E9: bidiL, 0x0301: bidiNSM, 0x200C: bidiBN, 0x200D: bidiBN,
		0x05D0: bidiR, 0x05B0: bidiNSM, 0x05F3: bidiR,
		0x0627: bidiAL, 0x064B: bidiNSM, 0x0660: bidiAN, 0x0669: bidiAN, 0x06F0: bidiEN, 0x06F9: bidiEN,
		0x0710: bidiAL, 0x0780: bidiAL, 0x07A6: bidiNSM, 0x07C0: bidiR, 0x07CA: bidiR,
		0x0939: bidiL, 0x093F: bidiL, 0x094D: bidiNSM, 0x4E2D: bidiL, 0x1E900: bidiR,
		// Code points the former script/category approximation got wrong.
		0x0640: bidiAL, 0x02B9: bidiON, 0x10D30: bidiAN, 0x10D4A: bidiR, 0x10D40: bidiAN,
		0x10940: bidiR, 0x0CBF: bidiL, 0xFF10: bidiEN,
	}
	for r, want := range cases {
		if derivedProperty(r) == propUnassigned {
			continue // added after this toolchain's Unicode version (F631)
		}
		if got := bidiClassOf(r); got != want {
			t.Errorf("bidiClassOf(%U) = %d, want %d", r, got, want)
		}
	}
}

// TestBidiRuleRealWorldCorpus runs real-world IDN labels of the RTL scripts
// through the query-path profile (check_bidi on, unassigned rejected): none
// may be rejected, and the RFC 5893 violations must be.
func TestBidiRuleRealWorldCorpus(t *testing.T) {
	p := Profile{UseSTD3Rules: true, CheckBidi: true}
	cases := []struct {
		name, note string
		ok         bool
		want       error // when !ok; nil means ErrInvalidBid
	}{
		{"مثال.example", "Arabic", true, nil},
		{"مثال١٢٣.example", "Arabic + Arabic-Indic digits (ends AN)", true, nil},
		{"مثال123.example", "Arabic + ASCII digits (ends EN)", true, nil},
		{"نمونه۱۲.example", "Persian + extended Arabic-Indic digits", true, nil},
		{"می\u200cخواهم.example", "Persian with ZWNJ", true, nil},
		{"پاکستان.example", "Urdu", true, nil},
		{"דוגמה.example", "Hebrew", true, nil},
		{"דוגמה12.example", "Hebrew ending in digits", true, nil},
		{"שָׁלוֹם.example", "Hebrew with niqqud", true, nil},
		{"ܫܠܡܐ.example", "Syriac", true, nil},
		{"ދިވެހި.example", "Thaana with fili", true, nil},
		{"ߒߞߏ߁.example", "N'Ko + N'Ko digit", true, nil},
		{"café.אב", "LTR label ending in NSM, Bidi domain", true, nil},
		{"हिन्दी.אב", "Devanagari, Bidi domain", true, nil},
		{"مثـال.example", "Arabic with tatweel: DISALLOWED (RFC 5892 §2.6, F627)", false, ErrDisallowed},
		{"אʹב.example", "Hebrew with U+02B9 (ON)", true, nil},
		{"\U00010D00\U00010D31.example", "Hanifi Rohingya letter + digit", true, nil},
		{mustACE(t, "مثال١٢") + ".example", "A-label of Arabic + AN digits", true, nil},
		{"مثال١" + "2.example", "rule 4: EN and AN", false, nil},
		{"نمونه۱١.example", "extended (EN) and Arabic-Indic (AN) digits: CONTEXTO A.8/A.9 (F628)", false, ErrContextO},
		{"אa.example", "rule 2: L in RTL label", false, nil},
		{"aא.example", "rule 5: R in LTR label", false, nil},
		{"אב.3com", "rule 1: EN first in a Bidi domain", false, nil},
		{"\U00010D00\U00010D31" + "1.example", "rule 4: Rohingya digit (AN) and EN", false, nil},
		{"\U00010D30\U00010D00.example", "rule 1: Rohingya label starting with AN", false, nil},
		{"\U00010D4A\U00010D4Ba.example", "rule 2: Garay (R) with Latin", false, nil},
		{"\U00010940\U00010941a.example", "rule 2: Sidetic (R) with Latin", false, nil},
	}
	for _, c := range cases {
		if !assignedInTables(c.name) {
			continue // uses code points added after this toolchain's Unicode version (F631)
		}
		_, err := p.ToASCII(c.name)
		if c.ok && err != nil {
			t.Errorf("%s (%q) rejected: %v", c.note, c.name, err)
		}
		want := c.want
		if want == nil {
			want = ErrInvalidBid
		}
		if !c.ok && !errors.Is(err, want) {
			t.Errorf("%s (%q): err=%v, want %v", c.note, c.name, err, want)
		}
	}
}

// F623: ValidateLabel / ValidateDomain accept valid U-labels (RTL labels
// may end in a digit) and share the Bidi rule with Profile.ToASCII.
func TestValidateULabels(t *testing.T) {
	ok := []string{
		"bücher", "مرحبا", "مرحبا١٢٣",
		"דוגמה1", "דוגמה12", "نمونه۱",
		"xn--mnchen-3ya", mustACE(t, "דוגמה1"),
	}
	for _, l := range ok {
		if err := ValidateLabel(l); err != nil {
			t.Errorf("ValidateLabel(%q) = %v", l, err)
		}
	}
	bad := map[string]error{
		"אa":                     ErrInvalidBid,
		"م١" + "2":               ErrInvalidBid,
		"́abc":                   ErrLeadingCombining,
		"-ü":                     ErrHyphenStart,
		"ü-":                     ErrHyphenEnd,
		mustACE(t, "אa"):         ErrInvalidBid,
		"xn--bcher-kva8":         ErrInvalidPunycode,
		"ex ample":               ErrInvalidRune,
		string(make([]byte, 64)): ErrLabelTooLong,
		"":                       ErrEmptyLabel,
		"हिन्":                   nil, // LTR U-label: valid
	}
	for l, want := range bad {
		if err := ValidateLabel(l); !errors.Is(err, want) && !(want == nil && err == nil) {
			t.Errorf("ValidateLabel(%q) = %v, want %v", l, err, want)
		}
	}
	if err := validateLabel("bücher", false); !errors.Is(err, ErrInvalidRune) {
		t.Errorf("validateLabel(U-label, isIDNA=false) = %v, want ErrInvalidRune", err)
	}

	for _, d := range []string{"مثال١٢٣.example", "דוגמה12.example", "bücher.example.", "www.example.com"} {
		if err := ValidateDomain(d); err != nil {
			t.Errorf("ValidateDomain(%q) = %v", d, err)
		}
	}
	// Domain-wide rule: an LTR label starting with a digit in a Bidi domain.
	for _, d := range []string{"אב.3com", "אב." + mustACE(t, "aא")} {
		if err := ValidateDomain(d); !errors.Is(err, ErrInvalidBid) {
			t.Errorf("ValidateDomain(%q) = %v, want ErrInvalidBid", d, err)
		}
	}
}

// F624: an "xn--" label must be a valid A-label (RFC 5891 §5.4).
func TestALabelMustRoundTrip(t *testing.T) {
	profiles := map[string]func(string) (string, error){
		"ToASCII":         ToASCII,
		"Profile(query)":  Profile{UseSTD3Rules: true, CheckBidi: true}.ToASCII,
		"Profile(noSTD3)": Profile{AllowUnassigned: true}.ToASCII,
	}
	invalid := map[string]error{
		"xn--bcher-kva8.example": ErrInvalidPunycode, // trailing garbage digit
		"xn--4gbrim0.example":    ErrInvalidPunycode,
		"xn--mnchen-3y.example":  ErrInvalidPunycode, // decodes to ASCII
		"xn--99.example":         ErrInvalidPunycode, // does not decode
		"bücher.xn--99":          ErrInvalidPunycode, // mixed (non-ASCII) path
		"xn--a.example":          ErrDisallowed,      // U+0080 control
		"xn--abc.example":        ErrDisallowed,
	}
	valid := []string{"xn--mnchen-3ya.example", "XN--MNCHEN-3YA.example", "xn--4gbrim.example", "xn--9dbq2a.example", "xn--zzzz-invalid.example", "ab--cd.example"}
	for pname, fn := range profiles {
		for name, want := range invalid {
			if _, err := fn(name); !errors.Is(err, want) {
				t.Errorf("%s(%q) = %v, want %v", pname, name, err, want)
			}
		}
		for _, name := range valid {
			if _, err := fn(name); err != nil {
				t.Errorf("%s(%q) rejected: %v", pname, name, err)
			}
		}
	}
	// STD3 off still rejects a bare "xn--" prefix.
	if _, err := (Profile{AllowUnassigned: true}).ToASCII("xn--.example"); !errors.Is(err, ErrInvalidPunycode) {
		t.Errorf("bare xn-- with STD3 off: %v", err)
	}
}

// assignedInTables reports whether every non-ASCII code point of s is
// assigned in the Unicode version of the selected tables; tests skip names
// using scripts newer than the toolchain's Unicode version.
func assignedInTables(s string) bool {
	for _, r := range s {
		if r > 0x7F && derivedProperty(r) == propUnassigned {
			return false
		}
	}
	return true
}
