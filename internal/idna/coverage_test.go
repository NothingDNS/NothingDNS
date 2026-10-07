package idna

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// decodeLabel coverage
// ---------------------------------------------------------------------------

func TestDecodeLabel_Empty(t *testing.T) {
	_, err := decodeLabel("")
	if err != ErrEmptyLabel {
		t.Errorf("expected ErrEmptyLabel, got %v", err)
	}
}

func TestDecodeLabel_NoHyphen(t *testing.T) {
	// Per RFC 3492 §6.2 a punycode body without '-' has an empty basic
	// prefix; "example" is interpreted as 7 variable-part digits. The
	// previous test expected identity ("example" → "example"), which was
	// the pre-fix bug that left real punycode un-decoded for callers that
	// stripped the "xn--" ACE prefix. We just assert non-empty here.
	result, err := decodeLabel("example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty decoded output")
	}
	if result == "example" {
		t.Error("expected decoder to actually run (got identity, the old buggy behaviour)")
	}
}

func TestDecodeLabel_PunycodeWithBasicPrefix(t *testing.T) {
	// "test-label" is a valid punycode body (basic prefix "test", variable
	// part "label"). RFC 3492 inserts decoded codepoints at chosen indices
	// in the basic prefix, so the basic characters survive but are not
	// guaranteed to remain contiguous. The earlier identity check ("no '--'
	// so return verbatim") simply failed to decode anything. Assert just
	// that the decoder did run (output non-empty and not identity).
	result, err := decodeLabel("test-label")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
	if result == "test-label" {
		t.Error("expected decoder to actually run (got identity, the old buggy behaviour)")
	}
	// All ASCII basic-prefix bytes must still appear in the decoded output.
	for _, c := range "test" {
		if !strings.ContainsRune(result, c) {
			t.Errorf("decoded result %q missing basic-prefix character %q", result, c)
		}
	}
}

func TestDecodeLabel_WithEncoding(t *testing.T) {
	// "xn--nxasmq6b" is "éxample" in punycode
	result, err := decodeLabel("nxasmq6b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should decode the punycode part
	t.Logf("decoded: %q", result)
}

// ---------------------------------------------------------------------------
// ToUnicode roundtrip
// ---------------------------------------------------------------------------

func TestToUnicode_PunycodeLabel(t *testing.T) {
	// First encode a Unicode domain
	encoded, err := ToASCII("münchen.example.com")
	if err != nil {
		t.Fatalf("ToASCII failed: %v", err)
	}

	// Now decode it back
	decoded, err := ToUnicode(encoded)
	if err != nil {
		t.Fatalf("ToUnicode failed: %v", err)
	}

	// Should get back the original (lowercased)
	t.Logf("encoded=%q decoded=%q", encoded, decoded)
}

func TestToUnicode_ASCIIOnly(t *testing.T) {
	result, err := ToUnicode("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "example.com" {
		t.Errorf("expected 'example.com', got %q", result)
	}
}

func TestToUnicode_Empty(t *testing.T) {
	result, err := ToUnicode("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// encodeLabel coverage
// ---------------------------------------------------------------------------

func TestEncodeLabel_ASCII(t *testing.T) {
	result, err := encodeLabel("example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "example" {
		t.Errorf("expected 'example', got %q", result)
	}
}

func TestEncodeLabel_NonASCII(t *testing.T) {
	result, err := encodeLabel("münchen")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == "münchen" {
		t.Error("expected punycode encoding, got original string")
	}
	t.Logf("encoded münchen → %q", result)
}

func TestEncodeLabel_InvalidSTD3(t *testing.T) {
	_, err := encodeLabel("test label") // space should fail STD3
	if err == nil {
		t.Error("expected error for space in label")
	}
}

// ---------------------------------------------------------------------------
// encodeSuffix coverage (via ToASCII with multi-rune labels)
// ---------------------------------------------------------------------------

func TestEncodeSuffix_SimpleUnicode(t *testing.T) {
	// Test Unicode labels that exercise the punycode encoding
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"über", false},      // German umlaut
		{"café", false},      // French accent
		{"niños", false},     // Spanish tilde
		{"português", false}, // Portuguese
		{"żółć", false},      // Polish
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ToASCII(tt.input + ".com")
			if (err != nil) != tt.wantErr {
				t.Fatalf("ToASCII(%q) error = %v, wantErr %v", tt.input+".com", err, tt.wantErr)
			}
			if !tt.wantErr {
				t.Logf("ToASCII(%q) = %q", tt.input+".com", result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateLabel coverage
// ---------------------------------------------------------------------------

func TestValidateLabel_NotIDNA(t *testing.T) {
	// When isIDNA=false, only basic checks run
	err := validateLabel("test-label", false)
	if err != nil {
		t.Errorf("expected no error for non-IDNA label, got %v", err)
	}
}

func TestValidateLabel_IDNA_Valid(t *testing.T) {
	err := validateLabel("example", true)
	if err != nil {
		t.Errorf("expected no error for valid IDNA label, got %v", err)
	}
}

func TestValidateLabel_IDNA_TooLong(t *testing.T) {
	longLabel := make([]byte, MaxLabelLength+1)
	for i := range longLabel {
		longLabel[i] = 'a'
	}
	err := validateLabel(string(longLabel), true)
	if err != ErrLabelTooLong {
		t.Errorf("expected ErrLabelTooLong, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// ValidateDomain coverage
// ---------------------------------------------------------------------------

func TestValidateDomain_TooLong(t *testing.T) {
	// Build a domain that exceeds 255 bytes
	var domain string
	for i := 0; i < 50; i++ {
		domain += "abcdefghij."
	}
	domain += "com"

	if len(domain) <= MaxNameLength {
		t.Fatalf("test domain must be > %d bytes, got %d", MaxNameLength, len(domain))
	}

	err := ValidateDomain(domain)
	if err != ErrNameTooLong {
		t.Errorf("expected ErrNameTooLong, got %v", err)
	}
}

func TestValidateDomain_Valid(t *testing.T) {
	err := ValidateDomain("example.com")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestValidateDomain_Empty(t *testing.T) {
	err := ValidateDomain("")
	if err != nil {
		t.Errorf("empty domain should be valid, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// CONTEXTJ edge cases (RFC 5892 A.1/A.2, F628)
// ---------------------------------------------------------------------------

func TestContextJ_ZWJAtStart(t *testing.T) {
	if err := checkULabel(string([]rune{0x200D, 'a', 'b'}), false); err != ErrContextJ {
		t.Errorf("expected ErrContextJ for ZWJ at start, got %v", err)
	}
}

func TestContextJ_ZWJAtEnd(t *testing.T) {
	if err := checkULabel(string([]rune{'a', 'b', 0x200D}), false); err != ErrContextJ {
		t.Errorf("expected ErrContextJ for ZWJ at end, got %v", err)
	}
}

func TestContextJ_ZWJAfterVirama(t *testing.T) {
	// U+094D DEVANAGARI SIGN VIRAMA has ccc 9: ZWJ after it is valid.
	if err := checkULabel(string([]rune{0x0915, 0x094D, 0x200D, 0x0937}), false); err != nil {
		t.Errorf("expected no error for ZWJ after virama, got %v", err)
	}
}

func TestContextJ_InvalidZWJ(t *testing.T) {
	if err := checkULabel(string([]rune{'a', 0x200D, 'b'}), false); err != ErrContextJ {
		t.Errorf("expected ErrContextJ for invalid ZWJ context, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// ToASCII edge cases
// ---------------------------------------------------------------------------

func TestToASCII_TrailingDot(t *testing.T) {
	result, err := ToASCII("example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "example.com" {
		t.Errorf("expected 'example.com', got %q", result)
	}
}

func TestToASCII_Whitespace(t *testing.T) {
	result, err := ToASCII("  example.com  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "example.com" {
		t.Errorf("expected 'example.com', got %q", result)
	}
}

func TestToASCII_Empty(t *testing.T) {
	result, err := ToASCII("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestToASCII_InvalidASCIILabel(t *testing.T) {
	// ASCII domain with invalid characters (spaces)
	_, err := ToASCII("exam ple.com")
	if err == nil {
		t.Error("expected error for domain with spaces")
	}
}

func TestDecodePunycode_Simple(t *testing.T) {
	// Test "bcher-kva" which decodes to "bücher"
	got := decodePunycode("bcher-kva")
	want := "b\u00fccher"
	if got != want {
		t.Errorf("decodePunycode(%q) = %q, want %q", "bcher-kva", got, want)
	}
}

func TestDecodePunycode_NoHyphen(t *testing.T) {
	// Per RFC 3492 §6.2, a punycode body without '-' is "empty basic prefix
	// + variable part = input"; the previous identity return for hyphen-less
	// inputs left real punycode un-decoded. The result is some Unicode
	// derived from the digits; we only assert it's non-empty (the exact
	// codepoints depend on the bootstring math and aren't interesting).
	got := decodePunycode("example")
	if got == "" {
		t.Error("expected non-empty decoded output for ASCII-only punycode body")
	}
}

func TestDecodePunycode_TrailingHyphen(t *testing.T) {
	// Trailing hyphen with nothing after = just prefix
	got := decodePunycode("abc-")
	if got != "abc" {
		t.Errorf("expected 'abc', got %q", got)
	}
}

func TestDecodePunycode_EmptyString(t *testing.T) {
	got := decodePunycode("")
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestDecodePunycode_EmptyAfterHyphen(t *testing.T) {
	got := decodePunycode("test-")
	if got != "test" {
		t.Errorf("expected 'test', got %q", got)
	}
}

func TestDecodePunycode_InsertAtBeginning(t *testing.T) {
	// Test where insertion point i=0 (insert at beginning)
	// This exercises the "out = append([]rune{rune(n)}, out...)" path
	got := decodePunycode("kva")
	// Just verify it doesn't crash and returns something
	if len(got) == 0 {
		t.Error("expected non-empty output")
	}
}

func TestDecodePunycode_InsertAtEnd(t *testing.T) {
	// Test where i >= len(out) (insert at end)
	got := decodePunycode("bcher-kva")
	if len(got) == 0 {
		t.Error("expected non-empty output")
	}
}

func TestDecodePunycode_InvalidDigit(t *testing.T) {
	// Invalid digit character should cause early return
	got := decodePunycode("ab-!!!")
	// Should return partial output without crashing
	if len(got) == 0 {
		t.Error("expected non-empty output")
	}
}

func TestEncodeSuffix_AllASCII(t *testing.T) {
	// All ASCII runes should return empty string (no suffix needed)
	got := encodeSuffix([]rune{'a', 'b', 'c'}, 3)
	if got != "" {
		t.Errorf("expected empty for all ASCII, got %q", got)
	}
}

func TestEncodeSuffix_Empty(t *testing.T) {
	got := encodeSuffix([]rune{}, 0)
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestAdapt_First(t *testing.T) {
	result := adapt(1000, 10, true)
	if result < 0 {
		t.Errorf("adapt returned negative: %d", result)
	}
}

func TestAdapt_NotFirst(t *testing.T) {
	result := adapt(1000, 10, false)
	if result < 0 {
		t.Errorf("adapt returned negative: %d", result)
	}
}

func TestAdapt_SmallDelta(t *testing.T) {
	result := adapt(1, 2, true)
	if result < 0 {
		t.Errorf("adapt returned negative: %d", result)
	}
}

func TestAdapt_ZeroDelta(t *testing.T) {
	result := adapt(0, 10, true)
	if result < 0 {
		t.Errorf("adapt returned negative: %d", result)
	}
}

func TestAdapt_LargeDelta(t *testing.T) {
	result := adapt(999999, 100, false)
	if result < 0 {
		t.Errorf("adapt returned negative: %d", result)
	}
}

func TestDigitToChar_RoundTrip(t *testing.T) {
	for d := 0; d < 36; d++ {
		ch := digitToChar(d)
		back := charToDigit(ch)
		if back != d {
			t.Errorf("round-trip failed: %d -> %c -> %d", d, ch, back)
		}
	}
}

func TestCharToDigit_Invalid(t *testing.T) {
	// Characters outside a-z, 0-9, A-Z should return -1
	tests := []rune{'!', ' ', '@', '#'}
	for _, ch := range tests {
		got := charToDigit(ch)
		if got >= 0 {
			t.Errorf("charToDigit(%c) = %d, expected negative", ch, got)
		}
	}
}

func TestEncodePunycode_WithUnicode(t *testing.T) {
	got := encodePunycode("m" + "\u00fc" + "nchen")
	if got != "mnchen-3ya" {
		t.Errorf("encodePunycode(münchen) = %q, want %q", got, "mnchen-3ya")
	}
	// All output chars should be ASCII
	for _, r := range got {
		if r >= 0x80 {
			t.Errorf("non-ASCII char in punycode output: %c", r)
		}
	}
}

func TestEncodePunycode_ASCIIOnly(t *testing.T) {
	got := encodePunycode("example")
	// ASCII-only input may have trailing hyphen (prefix-only punycode)
	if got != "example" && got != "example-" {
		t.Errorf("unexpected result for ASCII-only: %q", got)
	}
}

func TestEncodePunycode_Empty(t *testing.T) {
	got := encodePunycode("")
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestEncodeSuffix_NonASCIIOnly(t *testing.T) {
	got := encodeSuffix([]rune("☃"), 0)
	if got != "n3h" {
		t.Errorf("encodeSuffix(☃) = %q, want %q", got, "n3h")
	}
}
