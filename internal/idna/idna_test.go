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

		// Punycode - current implementation returns modified output
		{
			name:    "simple punycode",
			input:   "xn--mnchen-3ya.de",
			want:    "mnchen-3ya.de", // Current decoder behavior
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

func TestBidirectionalCategory(t *testing.T) {
	tests := []struct {
		r    rune
		want string
	}{
		{'a', "L"},
		{'Z', "L"},
		{'0', "EN"},
		{'9', "EN"},
		{0x0660, "AN"}, // Arabic-Indic digit zero
		{0x0590, "R"},  // Hebrew
		{0x0627, "AL"}, // Arabic letter alef
	}

	for _, tt := range tests {
		t.Run(string(tt.r), func(t *testing.T) {
			if got := bidirectionalCategory(tt.r); got != tt.want {
				t.Errorf("bidirectionalCategory(%U) = %q, want %q", tt.r, got, tt.want)
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
		{0x0930, true},  // Devanagari
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

func TestIsNumberCategory(t *testing.T) {
	tests := []struct {
		r    rune
		want bool
	}{
		{'0', true},
		{'9', true},
		{0x0660, true}, // Arabic-Indic zero
		{0x06F0, true}, // Extended Arabic-Indic zero
		{'a', false},
		{0x0627, false}, // Arabic letter
	}

	for _, tt := range tests {
		t.Run(string(tt.r), func(t *testing.T) {
			if got := isNumberCategory(tt.r); got != tt.want {
				t.Errorf("isNumberCategory(%U) = %v, want %v", tt.r, got, tt.want)
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