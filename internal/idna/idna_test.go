package idna

import (
	"testing"
)

func TestToASCII(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		// ASCII-only domains
		{
			name:    "simple ASCII domain",
			input:   "example.com",
			want:    "example.com",
			wantErr: nil,
		},
		{
			name:    "subdomain ASCII",
			input:   "www.example.com",
			want:    "www.example.com",
			wantErr: nil,
		},
		{
			name:    "trailing dot",
			input:   "example.com.",
			want:    "example.com",
			wantErr: nil,
		},

		// ToUnicode - only check error for punycode input
		{
			name:    "ASCII domain",
			input:   "xn--mnchen-3ya.de",
			want:    "xn--mnchen-3ya.de", // Will be "münchen.de" when punycode decode works
			wantErr: nil,
		},

		// Edge cases
		{
			name:    "empty string",
			input:   "",
			want:    "",
			wantErr: nil,
		},
		{
			name:    "root domain",
			input:   ".",
			want:    "",
			wantErr: nil,
		},

		// Error cases
		{
			name:    "label starts with hyphen",
			input:   "-example.com",
			want:    "",
			wantErr: ErrHyphenStart,
		},
		{
			name:    "label ends with hyphen",
			input:   "example-.com",
			want:    "",
			wantErr: ErrHyphenEnd,
		},
		{
			name:    "mixed domain invalid ASCII label",
			input:   "bad_label.münchen.de",
			want:    "",
			wantErr: ErrInvalidRune,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToASCII(tt.input)
			if err != tt.wantErr {
				t.Errorf("ToASCII(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if tt.want != "" && got != tt.want {
				t.Errorf("ToASCII(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestToUnicode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		// ASCII-only
		{
			name:    "ASCII domain",
			input:   "example.com",
			want:    "example.com",
			wantErr: nil,
		},
		{
			name:    "subdomain",
			input:   "www.example.com",
			want:    "www.example.com",
			wantErr: nil,
		},

		// Punycode — RFC 3492-compliant decoder produces the original
		// Unicode form. The earlier test pinned the broken behaviour where
		// the decoder returned the punycode body verbatim.
		{
			name:    "simple punycode",
			input:   "xn--mnchen-3ya.de",
			want:    "münchen.de",
			wantErr: nil,
		},

		// Edge cases
		{
			name:    "empty string",
			input:   "",
			want:    "",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToUnicode(tt.input)
			if err != tt.wantErr {
				t.Errorf("ToUnicode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ToUnicode(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateLabel(t *testing.T) {
	tests := []struct {
		name    string
		label   string
		wantErr error
	}{
		{
			name:    "valid label",
			label:   "example",
			wantErr: nil,
		},
		{
			name:    "valid with hyphen",
			label:   "my-label",
			wantErr: nil,
		},
		{
			name:    "empty label",
			label:   "",
			wantErr: ErrEmptyLabel,
		},
		{
			name:    "starts with hyphen",
			label:   "-example",
			wantErr: ErrHyphenStart,
		},
		{
			name:    "ends with hyphen",
			label:   "example-",
			wantErr: ErrHyphenEnd,
		},
		{
			name:    "too long label",
			label:   string(make([]byte, 64)),
			wantErr: ErrLabelTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLabel(tt.label)
			if err != tt.wantErr {
				t.Errorf("ValidateLabel(%q) = %v, want %v", tt.label, err, tt.wantErr)
			}
		})
	}
}

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr error
	}{
		{
			name:    "valid domain",
			domain:  "example.com",
			wantErr: nil,
		},
		{
			name:    "valid subdomain",
			domain:  "www.example.com",
			wantErr: nil,
		},
		{
			name:    "valid with trailing dot",
			domain:  "example.com.",
			wantErr: nil,
		},
		{
			name:    "invalid label",
			domain:  "-example.com",
			wantErr: ErrHyphenStart,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomain(tt.domain)
			// Check if got error when expected no error or vice versa
			if (err == nil) != (tt.wantErr == nil) {
				t.Errorf("ValidateDomain(%q) error = %v, wantErr %v", tt.domain, err, tt.wantErr)
			}
		})
	}
}

func TestIsASCII(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"münchen.de", false},
		{"مثال.إيران", false},
		{"", true},
		{"test123", true},
		{"test中文", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isASCII(tt.input); got != tt.want {
				t.Errorf("isASCII(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsCombiningMark(t *testing.T) {
	tests := []struct {
		r    rune
		want bool
	}{
		{0x0300, true},  // Combining grave accent
		{0x0320, true},  // Combining diaeresis below
		{0x093F, true},  // Devanagari vowel sign I (Mc)
		{0x0930, false}, // Devanagari letter RA (Lo), not a mark
		{0x20DD, true},  // combining enclosing circle (Me)
		{'a', false},
		{'0', false},
		{0x200D, false}, // ZWJ is not a combining mark in this check
	}

	for _, tt := range tests {
		t.Run(string(tt.r), func(t *testing.T) {
			if got := isCombiningMark(tt.r); got != tt.want {
				t.Errorf("isCombiningMark(%U) = %v, want %v", tt.r, got, tt.want)
			}
		})
	}
}

func TestFromUnicode(t *testing.T) {
	// Alias for ToASCII
	got, err := FromUnicode("example.com")
	if err != nil {
		t.Errorf("FromUnicode error = %v", err)
	}
	if got != "example.com" {
		t.Errorf("FromUnicode = %q, want %q", got, "example.com")
	}
}

func TestFromASCII(t *testing.T) {
	// Alias for ToUnicode
	got, err := FromASCII("example.com")
	if err != nil {
		t.Errorf("FromASCII error = %v", err)
	}
	if got != "example.com" {
		t.Errorf("FromASCII = %q, want %q", got, "example.com")
	}
}

func TestConstants(t *testing.T) {
	if MaxLabelLength != 63 {
		t.Errorf("MaxLabelLength = %d, want 63", MaxLabelLength)
	}
	if MaxNameLength != 255 {
		t.Errorf("MaxNameLength = %d, want 255", MaxNameLength)
	}
	if ACEPrefix != "xn--" {
		t.Errorf("ACEPrefix = %q, want \"xn--\"", ACEPrefix)
	}
}

func TestErrors(t *testing.T) {
	if ErrEmptyLabel.Error() != "empty label" {
		t.Errorf("ErrEmptyLabel = %q", ErrEmptyLabel.Error())
	}
	if ErrLabelTooLong.Error() != "label too long" {
		t.Errorf("ErrLabelTooLong = %q", ErrLabelTooLong.Error())
	}
	if ErrNameTooLong.Error() != "domain name too long" {
		t.Errorf("ErrNameTooLong = %q", ErrNameTooLong.Error())
	}
	if ErrInvalidRune.Error() != "invalid rune for IDNA" {
		t.Errorf("ErrInvalidRune = %q", ErrInvalidRune.Error())
	}
	if ErrInvalidPunycode.Error() != "invalid punycode" {
		t.Errorf("ErrInvalidPunycode = %q", ErrInvalidPunycode.Error())
	}
	if ErrInvalidBid.Error() != "bidirectional restriction violation" {
		t.Errorf("ErrInvalidBid = %q", ErrInvalidBid.Error())
	}
	if ErrContextJ.Error() != "contextual rule J failure" {
		t.Errorf("ErrContextJ = %q", ErrContextJ.Error())
	}
	if ErrContextO.Error() != "contextual rule O failure" {
		t.Errorf("ErrContextO = %q", ErrContextO.Error())
	}
	if ErrHyphenStart.Error() != "label starts with hyphen" {
		t.Errorf("ErrHyphenStart = %q", ErrHyphenStart.Error())
	}
	if ErrHyphenEnd.Error() != "label ends with hyphen" {
		t.Errorf("ErrHyphenEnd = %q", ErrHyphenEnd.Error())
	}
}

func TestMapLabel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"EXAMPLE", "example"},
		{"Example", "example"},
		{"MÜNCHEN", "münchen"}, // Unicode stays as-is but lowercased
		{"test123", "test123"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := mapLabel(tt.input)
			if got != tt.want {
				t.Errorf("mapLabel(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateSTD3(t *testing.T) {
	tests := []struct {
		label   string
		wantErr error
	}{
		{"example", nil},
		{"my-label", nil},
		{"test123", nil},
		{"-example", ErrHyphenStart},
		{"example-", ErrHyphenEnd},
		{"", nil},                    // empty returns nil (not validated)
		{"exam ple", ErrInvalidRune}, // space is invalid
		{"exam\ble", ErrInvalidRune}, // control char
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			err := validateSTD3(tt.label)
			if err != tt.wantErr {
				t.Errorf("validateSTD3(%q) = %v, want %v", tt.label, err, tt.wantErr)
			}
		})
	}
}

// TestValidateBidi checks the RFC 5893 Bidi rule through ValidateLabel,
// which shares bidiLabelOK with Profile.ToASCII (F623). RFC 5893 rule 3
// allows an RTL label to end in a digit (EN or AN).
func TestValidateBidi(t *testing.T) {
	tests := []struct {
		label   string
		wantErr error
	}{
		{"example", nil},
		{"مرحبا", nil},
		{"123abc", nil},
		{"مرحبا١٢٣", nil},          // AL ... AN at the end: allowed
		{"מרחבא123", nil},          // R ... EN at the end: allowed
		{"مرحبا١2", ErrInvalidBid}, // rule 4: EN and AN together
		{"אa", ErrInvalidBid},      // rule 2: L in an RTL label
		{"א-ב", nil},               // interior ES
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			err := ValidateLabel(tt.label)
			if err != tt.wantErr {
				t.Errorf("ValidateLabel(%q) = %v, want %v", tt.label, err, tt.wantErr)
			}
		})
	}
}

func TestValidateContext(t *testing.T) {
	// RFC 5892 A.8/A.9 (F628): Arabic-Indic and extended Arabic-Indic
	// digits must not be mixed; an ASCII digit next to them is no CONTEXTO
	// violation (the replaced "Rule O" rejected "test1٢٣").
	tests := []struct {
		label   string
		wantErr error
	}{
		{"example", nil},
		{"test", nil},
		{"test١٢٣", nil},
		{"١٢٣test", nil},
		{"test1٢٣", nil},
		{"ب١٢", nil},
		{"ب۱۲", nil},
		{"ب١۲", ErrContextO},
		{"ب۱٢", ErrContextO},
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			err := checkULabel(tt.label, false)
			if err != tt.wantErr {
				t.Errorf("checkULabel(%q) = %v, want %v", tt.label, err, tt.wantErr)
			}
		})
	}
}

func TestDecodeLabel(t *testing.T) {
	// decodeLabel is called by ToUnicode after the "xn--" ACE prefix has
	// been stripped, so the input here is the punycode body to decode per
	// RFC 3492. Valid punycode inputs that happen to look like ASCII still
	// get decoded — caller should not pass non-punycode strings through.
	tests := []struct {
		input   string
		want    string
		wantErr error
	}{
		// "mnchen-3ya" is the canonical punycode body for "münchen".
		{"mnchen-3ya", "münchen", nil},
		// Empty input is an error.
		{"", "", ErrEmptyLabel},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := decodeLabel(tt.input)
			if err != tt.wantErr {
				t.Errorf("decodeLabel(%q) error = %v, want %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("decodeLabel(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestJoiningType(t *testing.T) {
	tests := []struct {
		r    rune
		want uint8
	}{
		{0x0628, jtD}, // ARABIC LETTER BEH
		{0x0627, jtR}, // ARABIC LETTER ALEF
		{0x064B, jtT}, // ARABIC FATHATAN
		{0x06CC, jtD}, // ARABIC LETTER FARSI YEH
		{0x0710, jtR}, // SYRIAC LETTER ALAPH
		{0xA872, jtL}, // PHAGS-PA SUPERFIXED LETTER RA
		{0x1F600, jtU},
		{'a', jtU},
		{0x0640, jtU}, // TATWEEL is C but DISALLOWED: not recorded
	}

	for _, tt := range tests {
		if got := joiningType(tt.r); got != tt.want {
			t.Errorf("joiningType(%U) = %d, want %d", tt.r, got, tt.want)
		}
	}
}

func TestToASCIITrimSpace(t *testing.T) {
	got, err := ToASCII("  example.com  ")
	if err != nil {
		t.Errorf("ToASCII error = %v", err)
	}
	if got != "example.com" {
		t.Errorf("ToASCII = %q, want %q", got, "example.com")
	}
}

func TestToUnicodeTrimSpace(t *testing.T) {
	got, err := ToUnicode("  example.com  ")
	if err != nil {
		t.Errorf("ToUnicode error = %v", err)
	}
	if got != "example.com" {
		t.Errorf("ToUnicode = %q, want %q", got, "example.com")
	}
}

func TestToASCIIEmpty(t *testing.T) {
	got, err := ToASCII("")
	if err != nil {
		t.Errorf("ToASCII('') error = %v", err)
	}
	if got != "" {
		t.Errorf("ToASCII('') = %q, want %q", got, "")
	}
}

func TestToUnicodeEmpty(t *testing.T) {
	got, err := ToUnicode("")
	if err != nil {
		t.Errorf("ToUnicode('') error = %v", err)
	}
	if got != "" {
		t.Errorf("ToUnicode('') = %q, want %q", got, "")
	}
}

func TestValidateDomainTooLong(t *testing.T) {
	// Create a domain longer than 255 bytes
	longDomain := ""
	for i := 0; i < 300; i++ {
		longDomain += "a"
	}
	longDomain += ".com"

	err := ValidateDomain(longDomain)
	if err != ErrNameTooLong {
		t.Errorf("ValidateDomain too long domain = %v, want ErrNameTooLong", err)
	}
}

func TestProfile(t *testing.T) {
	p := Profile{
		AllowUnassigned: true,
		UseSTD3Rules:    true,
		CheckBidi:       true,
		CheckJoiner:     true,
	}

	if !p.AllowUnassigned {
		t.Error("Profile.AllowUnassigned = false, want true")
	}
	if !p.UseSTD3Rules {
		t.Error("Profile.UseSTD3Rules = false, want true")
	}
	if !p.CheckBidi {
		t.Error("Profile.CheckBidi = false, want true")
	}
	if !p.CheckJoiner {
		t.Error("Profile.CheckJoiner = false, want true")
	}
}

// Punycode tests

func TestDigitToChar(t *testing.T) {
	tests := []struct {
		digit int
		want  rune
	}{
		{0, 'a'},
		{25, 'z'},
		{26, '0'},
		{35, '9'},
	}

	for _, tt := range tests {
		t.Run(string(tt.want), func(t *testing.T) {
			got := digitToChar(tt.digit)
			if got != tt.want {
				t.Errorf("digitToChar(%d) = %c, want %c", tt.digit, got, tt.want)
			}
		})
	}
}

func TestCharToDigit(t *testing.T) {
	tests := []struct {
		char rune
		want int
	}{
		{'a', 0},
		{'z', 25},
		{'A', 0},
		{'Z', 25},
		{'0', 26},
		{'9', 35},
		{'-', -1},
		{' ', -1},
	}

	for _, tt := range tests {
		t.Run(string(tt.char), func(t *testing.T) {
			got := charToDigit(tt.char)
			if got != tt.want {
				t.Errorf("charToDigit(%c) = %d, want %d", tt.char, got, tt.want)
			}
		})
	}
}

func TestEncodePunycode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example", "example"},    // ASCII only
		{"bücher", "bcher-kva"},   // RFC 3492-style mixed basic/non-basic
		{"münchen", "mnchen-3ya"}, // German umlaut
		{"mañana", "maana-pta"},   // Multiple basic chars around non-basic
		{"☃", "n3h"},              // No basic code points
		{"München", "Mnchen-3ya"}, // Punycode preserves input case
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := encodePunycode(tt.input)
			if got != tt.want {
				t.Errorf("encodePunycode(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDecodePunycode(t *testing.T) {
	// decodePunycode implements RFC 3492 §6.2 directly. Inputs that contain
	// no '-' delimiter are interpreted as "empty basic prefix + variable
	// part = input", which is a valid punycode shape (e.g. "nxasmq6b" for
	// names with no ASCII letters). The earlier identity short-circuit was
	// wrong: any ASCII-only string was returned verbatim, leaving real
	// punycode un-decoded for caller paths that stripped the "xn--" ACE
	// prefix.
	tests := []struct {
		input string
		want  string
	}{
		// Canonical punycode body for "münchen".
		{"mnchen-3ya", "münchen"},
		// Basic prefix only ("foo-" → "foo"), no variable part.
		{"foo-", "foo"},
		// Empty input.
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := decodePunycode(tt.input)
			if got != tt.want {
				t.Errorf("decodePunycode(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestAdapt(t *testing.T) {
	tests := []struct {
		delta     int
		numPoints int
		first     bool
	}{
		{10, 10, true},
		{10, 10, false},
		{100, 50, true},
		{100, 50, false},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := adapt(tt.delta, tt.numPoints, tt.first)
			if got < 0 {
				t.Errorf("adapt(%d, %d, %v) = %d, want non-negative",
					tt.delta, tt.numPoints, tt.first, got)
			}
		})
	}
}

func TestEncodeSuffix(t *testing.T) {
	// encodeSuffix is used by encodePunycode for non-ASCII labels
	tests := []struct {
		src  []rune
		b    int
		want string
	}{
		{[]rune("münchen"), 6, "3ya"},
		{[]rune("bücher"), 5, "kva"},
		{[]rune("☃"), 0, "n3h"},
	}

	for _, tt := range tests {
		t.Run(string(tt.src), func(t *testing.T) {
			got := encodeSuffix(tt.src, tt.b)
			if got != tt.want {
				t.Errorf("encodeSuffix(%q, %d) = %q, want %q", string(tt.src), tt.b, got, tt.want)
			}
		})
	}
}

func TestEncodeLabelUnicode(t *testing.T) {
	// Test encodeLabel with Unicode input
	label := "münchen"
	encoded, err := encodeLabel(label)
	if err != nil {
		t.Errorf("encodeLabel(%q) error = %v", label, err)
	}
	if encoded != "mnchen-3ya" {
		t.Errorf("encodeLabel(%q) = %q, want %q", label, encoded, "mnchen-3ya")
	}
}

func TestToASCIIDomainWithPunycode(t *testing.T) {
	// A domain that would use punycode
	// This exercises the full ToASCII path for non-ASCII domains
	domain := "münchen.de"
	got, err := ToASCII(domain)
	if err != nil {
		t.Errorf("ToASCII(%q) error = %v", domain, err)
	}
	if got != "xn--mnchen-3ya.de" {
		t.Errorf("ToASCII(%q) = %q, want %q", domain, got, "xn--mnchen-3ya.de")
	}
}

func TestToUnicodePunycode(t *testing.T) {
	// A domain with punycode
	domain := "xn--mnchen-3ya.de"
	got, err := ToUnicode(domain)
	if err != nil {
		t.Errorf("ToUnicode(%q) error = %v", domain, err)
	}
	if got != "münchen.de" {
		t.Errorf("ToUnicode(%q) = %q, want %q", domain, got, "münchen.de")
	}
}

func TestValidateLabelWithIDNA(t *testing.T) {
	// Test validateLabel with IDNA=true
	label := "example"
	err := validateLabel(label, true)
	if err != nil {
		t.Errorf("validateLabel(%q, true) error = %v", label, err)
	}
}

// Benchmark tests
func BenchmarkToASCII(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ToASCII("www.example.com")
	}
}

func BenchmarkToUnicode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ToUnicode("xn--mnchen-3ya.de")
	}
}

func BenchmarkValidateDomain(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ValidateDomain("www.example.com")
	}
}
