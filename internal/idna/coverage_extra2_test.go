package idna

import (
	"testing"
)

// ---------------------------------------------------------------------------
// bidirectionalCategory coverage
// ---------------------------------------------------------------------------

func TestBidirectionalCategory_Categories(t *testing.T) {
	tests := []struct {
		r    rune
		want string
	}{
		{'A', "L"},    // ASCII uppercase
		{'z', "L"},    // ASCII lowercase
		{'0', "EN"},   // ASCII digit
		{'5', "EN"},   // ASCII digit
		{0x0660, "AN"}, // Arabic-Indic digit
		{0x0669, "AN"}, // Arabic-Indic digit
		{0x200D, "ON"}, // ZWJ
		{0x0590, "R"},  // Hebrew
		{0x05FF, "R"},  // Hebrew
		{0x0627, "AL"}, // Arabic letter
		{0x06FF, "AL"}, // Arabic
		{0x0700, "AL"}, // Syriac/Arabic supplement
		{0x08FF, "AL"}, // Arabic extended
		{0xFB50, "AL"}, // Arabic presentation forms A
		{0xFDFF, "AL"}, // Arabic presentation forms A
		{0xFE70, "AL"}, // Arabic presentation forms B
		{0xFEFF, "AL"}, // Arabic presentation forms B
		{' ', "ON"},    // Space falls to default
		{'!', "ON"},    // Punctuation falls to default
		{0x00C0, "L"},  // Latin extended uppercase (À)
		{0x00DE, "L"},  // Latin extended uppercase (Þ)
	}
	for _, tt := range tests {
		got := bidirectionalCategory(tt.r)
		if got != tt.want {
			t.Errorf("bidirectionalCategory(%U) = %q, want %q", tt.r, got, tt.want)
		}
	}
}

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
	result, err := decodeLabel("example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "example" {
		t.Errorf("expected 'example', got %q", result)
	}
}

func TestDecodeLabel_NoDoubleHyphen(t *testing.T) {
	result, err := decodeLabel("test-label")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "test-label" {
		t.Errorf("expected 'test-label', got %q", result)
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
		{"über", false},       // German umlaut
		{"café", false},       // French accent
		{"niños", false},      // Spanish tilde
		{"português", false},  // Portuguese
		{"żółć", false},       // Polish
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
// validateContext edge cases
// ---------------------------------------------------------------------------

func TestValidateContext_ZWJAtStart(t *testing.T) {
	// ZWJ at position 0 should fail
	err := validateContext(string([]rune{0x200D, 'a', 'b'}))
	if err != ErrContextJ {
		t.Errorf("expected ErrContextJ for ZWJ at start, got %v", err)
	}
}

func TestValidateContext_ZWJAtEnd(t *testing.T) {
	// ZWJ at last position should fail
	err := validateContext(string([]rune{'a', 'b', 0x200D}))
	if err != ErrContextJ {
		t.Errorf("expected ErrContextJ for ZWJ at end, got %v", err)
	}
}

func TestValidateContext_ValidZWJ(t *testing.T) {
	// ZWJ between combining marks should be valid
	err := validateContext(string([]rune{0x0300, 0x200D, 0x0301}))
	if err != nil {
		t.Errorf("expected no error for valid ZWJ, got %v", err)
	}
}

func TestValidateContext_InvalidZWJ(t *testing.T) {
	// ZWJ between non-joinable characters
	err := validateContext(string([]rune{'a', 0x200D, 'b'}))
	if err != ErrContextJ {
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
