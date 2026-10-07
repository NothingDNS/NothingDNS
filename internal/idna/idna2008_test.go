package idna

import (
	"errors"
	"testing"
)

// P2-M1 (F627–F631): RFC 5892 derived property, CONTEXTJ/CONTEXTO rules,
// RFC 5891 §5.4 checks on every U-label (decoded A-labels included), a
// validating ToUnicode, NFC, and version-matched Unicode tables.

func ace(u string) string { return ACEPrefix + encodePunycode(u) }

func TestGeneratedTablesSorted(t *testing.T) {
	for name, tbl := range map[string][]runeRange8{"derived": derivedRanges[:], "joining": joiningRanges[:], "ccc": cccRanges[:]} {
		for i, r := range tbl {
			if r.lo > r.hi || r.v == 0 {
				t.Fatalf("%s entry %d %+v malformed", name, i, r)
			}
			if i > 0 && tbl[i-1].hi >= r.lo {
				t.Fatalf("%s entries %d/%d overlap or are unsorted", name, i-1, i)
			}
		}
	}
	for i := 1; i < len(decompositions); i++ {
		if decompositions[i-1].r >= decompositions[i].r {
			t.Fatalf("decompositions unsorted at %d", i)
		}
	}
	for i := 1; i < len(compositions); i++ {
		a, b := compositions[i-1], compositions[i]
		if a.a > b.a || (a.a == b.a && a.b >= b.b) {
			t.Fatalf("compositions unsorted at %d", i)
		}
	}
}

// TestDerivedPropertyKnownValues checks each RFC 5892 §2 category.
func TestDerivedPropertyKnownValues(t *testing.T) {
	cases := map[rune]uint8{
		'a': propPVALID, '0': propPVALID, '-': propPVALID, // E: LDH
		'A': propDisallowed, '_': propDisallowed, '.': propDisallowed, // B (upper case) / other
		0x00DF: propPVALID, 0x03C2: propPVALID, 0x06FD: propPVALID, 0x0F0B: propPVALID, 0x3007: propPVALID, // F: PVALID
		0x00B7: propContextO, 0x0375: propContextO, 0x05F3: propContextO, 0x05F4: propContextO, 0x30FB: propContextO,
		0x0660: propContextO, 0x0669: propContextO, 0x06F0: propContextO, 0x06F9: propContextO, // F: CONTEXTO
		0x0640: propDisallowed, 0x07FA: propDisallowed, 0x302E: propDisallowed, 0x3031: propDisallowed, 0x303B: propDisallowed, // F: DISALLOWED
		0x200C: propContextJ, 0x200D: propContextJ, // H
		0x00FC: propPVALID, 0x0131: propPVALID, 0x015F: propPVALID, 0x011F: propPVALID, // ü ı ş ğ
		0x00DC: propDisallowed, 0x0130: propDisallowed, 0x1E9E: propDisallowed, // Ü İ ẞ (B: Unstable)
		0x13F8: propDisallowed, 0xAB70: propDisallowed, // Cherokee small letters fold to capitals (B)
		0x13A0: propPVALID,
		0xFF41: propDisallowed, 0x2160: propDisallowed, 0x00BD: propDisallowed, // fullwidth a, ROMAN NUMERAL ONE, 1/2
		0x1F4A9: propDisallowed, 0x2665: propDisallowed, 0x00A9: propDisallowed, // emoji / symbols
		0x00AD: propDisallowed, 0xFE0F: propDisallowed, 0x0020: propDisallowed, 0xFDD0: propDisallowed, // C
		0x20D0: propDisallowed, 0x1D165: propDisallowed, // D: ignorable blocks
		0x1100: propDisallowed, 0x1161: propDisallowed, 0x11A8: propDisallowed, 0xA960: propDisallowed, // I: old Hangul jamo
		0xAC00: propPVALID, 0x4E2D: propPVALID, 0x3042: propPVALID, 0x30A2: propPVALID, // Hangul syllable, Han, kana
		0x0915: propPVALID, 0x094D: propPVALID, 0x0627: propPVALID, 0x05D0: propPVALID, 0x0301: propPVALID,
		0x0378: propUnassigned, 0xE0080: propUnassigned, // J
		0xD800: propDisallowed, 0xE000: propDisallowed, // surrogate, private use
	}
	for r, want := range cases {
		if got := derivedProperty(r); got != want {
			t.Errorf("derivedProperty(%U) = %d, want %d", r, got, want)
		}
	}
}

func TestNFC(t *testing.T) {
	cases := []struct{ in, want string }{
		{"café", "café"},
		{"café", "café"},
		{"각", "각"},
		{"각", "각"},
		{"Ậ", "Ậ"},
		{"Ậ", "Ậ"},   // reordered first
		{"q̣̇", "q̣̇"}, // no composite: canonical order only
		{"Å", "Å"},     // singleton ANGSTROM SIGN
		{"́a", "́a"},   // leading non-starter
		{"eௗ̀", "eௗ̀"}, // ccc=0 U+0BD7 blocks (UAX #15)
		{"ொ", "ொ"},
		{"ガ", "ガ"},
		{"", ""},
		{"ẹ́", "ẹ́"}, // é + dot below -> ẹ + acute
		{"ḍ̇", "ḍ̇"},
		{"\U0001D15E", "\U0001D157\U0001D165"}, // excluded composition
		{"̈́", "̈́"},
		{"ཱི", "ཱི"},
		{"אַָּ", "אַָּ"}, // ccc 17, 21, 18 -> 17, 18, 21
	}
	for _, c := range cases {
		if got := nfc(c.in); got != c.want {
			t.Errorf("nfc(%+q) = %+q, want %+q", c.in, got, c.want)
		}
		if !isNFC(c.want) {
			t.Errorf("isNFC(%+q) = false", c.want)
		}
		if isNFC(c.in) != (c.in == c.want) {
			t.Errorf("isNFC(%+q) = %v", c.in, isNFC(c.in))
		}
	}
}

// TestIDNA2008RealWorldCorpus: real-world IDN labels must pass the query
// profile (STD3, unassigned rejected, Bidi on) as Unicode and as A-labels,
// and round-trip through ToUnicode.
func TestIDNA2008RealWorldCorpus(t *testing.T) {
	p := Profile{UseSTD3Rules: true, CheckBidi: true}
	ok := []string{
		"straße", "bücher", "münchen", "größe", // German ß/ü/ö
		"ırmak", "şişli", "ağaç", "türkçe", "İstanbul", // Turkish ı/ş/ğ/ç (İ maps to i + U+0307)
		"λόγος", "ελληνικός", "σίσυφος", "ς", // Greek incl. final sigma
		"日本語", "例え", "ドメイン名例", "中文网", "中國", // Japanese/Chinese
		"한국어", "도메인", // Korean
		"हिन्दी", "क्\u200Dष", "क्\u200Cष", "मराठी", // Devanagari incl. virama+ZWJ/ZWNJ
		"مثال", "می\u200Cخواهم", "پاکستان", "דוגמה", "ישראל", // RTL
		"col·legi", "ア・イ", "א׳ב", "͵α", "ب١٢", "ب۱۲", // CONTEXTO satisfied
		"ελλάδα", "россия", "україна", "ไทย", "ქართული", "հայերեն", "தமிழ்", "বাংলা", "ಕನ್ನಡ",
	}
	for _, u := range ok {
		name := u + ".example"
		a, err := p.ToASCII(name)
		if err != nil {
			t.Errorf("ToASCII(%q) rejected: %v", name, err)
			continue
		}
		if _, err := p.ToASCII(a); err != nil {
			t.Errorf("ToASCII(%q) (A-label of %q) rejected: %v", a, name, err)
		}
		back, err := ToUnicode(a)
		if err != nil {
			t.Errorf("ToUnicode(%q) rejected: %v", a, err)
		} else if back != mapLabel(u)+".example" {
			t.Errorf("ToUnicode(%q) = %q, want %q", a, back, mapLabel(u)+".example")
		}
		if err := ValidateDomain(a); err != nil {
			t.Errorf("ValidateDomain(%q) = %v", a, err)
		}
	}
}

// TestIDNA2008Rejections: one case per rule, as Unicode input and as the
// A-label (decoded A-labels get the same checks, F629).
func TestIDNA2008Rejections(t *testing.T) {
	noBidi := Profile{UseSTD3Rules: true}
	cases := []struct {
		u    string
		want error
	}{
		{"\U0001F4A9", ErrDisallowed}, // F627: emoji (So)
		{"i♥ny", ErrDisallowed},       // F627: heart
		{"مثـال", ErrDisallowed},      // F627: tatweel exception
		{"ａｂｃ", ErrDisallowed},        // F627: fullwidth (Unstable, not mapped)
		{"xⅠ", ErrDisallowed},         // F627: ROMAN NUMERAL ONE (Nl)
		{"a©b", ErrDisallowed},        // F627: copyright sign
		{"a\u200Cb", ErrContextJ},     // F628: A.1 Latin is not joining
		{"ب\u200C", ErrContextJ},      // F628: A.1 nothing after
		{"a\u200Db", ErrContextJ},     // F628: A.2 needs a virama
		{"\u200Dक", ErrContextJ},      // F628
		{"a·b", ErrContextO},          // F628: A.3
		{"l·", ErrContextO},           // F628: A.3
		{"͵a", ErrContextO},           // F628: A.4
		{"a׳", ErrContextO},           // F628: A.5
		{"a״", ErrContextO},           // F628: A.6
		{"a・b", ErrContextO},          // F628: A.7
		{"・", ErrContextO},            // F628: A.7 the dot itself does not count
		{"ب١۲", ErrContextO},          // F628: A.8/A.9
		{"́a", ErrLeadingCombining},   // F629
		{"ab--ü", ErrHyphen34},        // F629
		{"-ü", ErrHyphenStart},        // F629
		{"ü-", ErrHyphenEnd},          // F629
	}
	for _, c := range cases {
		for _, name := range []string{c.u, ace(c.u)} {
			if _, err := noBidi.ToASCII(name + ".example"); !errors.Is(err, c.want) {
				t.Errorf("ToASCII(%+q) = %v, want %v", name, err, c.want)
			}
			if err := ValidateLabel(name); !errors.Is(err, c.want) {
				t.Errorf("ValidateLabel(%+q) = %v, want %v", name, err, c.want)
			}
		}
		if _, err := ToUnicode(ace(c.u) + ".example"); !errors.Is(err, c.want) {
			t.Errorf("ToUnicode(%q) = %v, want %v", ace(c.u), err, c.want)
		}
	}
	// F629 (NFC): Unicode input is normalized; a non-NFC A-label is invalid.
	if a, err := noBidi.ToASCII("café.example"); err != nil || a != "xn--caf-dma.example" {
		t.Errorf("ToASCII(decomposed café) = %q, %v", a, err)
	}
	if a, err := noBidi.ToASCII("가x.example"); err != nil || a != ace("가x")+".example" {
		t.Errorf("ToASCII(conjoining jamo) = %q, %v", a, err)
	}
	for _, name := range []string{"xn--cafe-yvc.example", ace("가x") + ".example"} {
		if _, err := noBidi.ToASCII(name); !errors.Is(err, ErrNotNFC) {
			t.Errorf("ToASCII(%q) = %v, want ErrNotNFC", name, err)
		}
	}
	// ASCII labels are not U-labels: R-LDH "ab--cd" stays valid.
	if _, err := noBidi.ToASCII("ab--cd.example"); err != nil {
		t.Errorf("ab--cd rejected: %v", err)
	}
	// AllowUnassigned: an unassigned code point is accepted only when allowed.
	if _, err := (Profile{UseSTD3Rules: true}).ToASCII("a͸b.example"); !errors.Is(err, ErrUnassigned) {
		t.Errorf("unassigned with AllowUnassigned=false: %v", err)
	}
	if _, err := (Profile{UseSTD3Rules: true, AllowUnassigned: true}).ToASCII("a͸b.example"); err != nil {
		t.Errorf("unassigned with AllowUnassigned=true: %v", err)
	}
}

// TestToUnicodeValidates (F630): invalid A-labels are errors, never decoded
// as-is; other ASCII labels pass through unchanged.
func TestToUnicodeValidates(t *testing.T) {
	bad := map[string]error{
		"xn--bcher-kva8.example": ErrInvalidPunycode,
		"xn--99.example":         ErrInvalidPunycode,
		"xn--.example":           ErrInvalidPunycode,
		"xn--a.example":          ErrDisallowed,
		"xn--ls8h.la":            ErrDisallowed,
		"xn--lsa.example":        ErrLeadingCombining,
		"xn--cafe-yvc.example":   ErrNotNFC,
		ace("אa") + ".example":   ErrInvalidBid,
		"a..b":                   ErrEmptyLabel,
	}
	for in, want := range bad {
		if got, err := ToUnicode(in); !errors.Is(err, want) {
			t.Errorf("ToUnicode(%q) = %q, %v; want %v", in, got, err, want)
		}
	}
	good := map[string]string{
		"xn--mnchen-3ya.de":  "münchen.de",
		"XN--MNCHEN-3YA.de":  "münchen.de",
		"_dmarc.example.com": "_dmarc.example.com",
		"xn--zca.example":    "ß.example",
		"Bücher.example.":    "bücher.example",
		"xn--4gbrim.example": "موقع.example",
	}
	for in, want := range good {
		if got, err := ToUnicode(in); err != nil || got != want {
			t.Errorf("ToUnicode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	// Profile.ToUnicode applies STD3 to the other ASCII labels.
	if _, err := (Profile{UseSTD3Rules: true}).ToUnicode("_dmarc.example"); err == nil {
		t.Error("Profile{STD3}.ToUnicode accepted _dmarc")
	}
}
