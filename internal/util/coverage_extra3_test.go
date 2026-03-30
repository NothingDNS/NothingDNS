package util

import (
	"testing"
)

// ============================================================================
// UnescapeLabel - invalid rune value path (domain.go:356-358).
// The ValidRune check fires for values outside the valid Unicode range.
// Since decimal escape only reads 3 digits (max 999), and all values 0-999
// are valid runes, this path is unreachable with the current code.
// ============================================================================

func TestUnescapeLabelDecimalEscapeInvalidRuneSkipped(t *testing.T) {
	t.Skip("UnescapeLabel decimal escape ValidRune error path unreachable: max 3-digit value 999 is always a valid rune")
}

// ============================================================================
// UnescapeLabel - Sscanf error path (domain.go:353-355).
// fmt.Sscanf with %d on 3 digit characters always succeeds.
// This path is unreachable with the current code.
// ============================================================================

func TestUnescapeLabelDecimalEscapeSscanfErrorSkipped(t *testing.T) {
	t.Skip("UnescapeLabel Sscanf error path unreachable: 3 digit chars always parse as integer")
}

// ============================================================================
// UnescapeLabel - backslash at very end of string (no next char)
// This exercises the else branch at line 364-365.
// ============================================================================

func TestUnescapeLabelBackslashAtEnd(t *testing.T) {
	result, err := UnescapeLabel("abc\\")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	// When backslash is at the end, i+1 >= len(label) so it falls to the else
	// branch and writes the backslash as-is
	if result != "abc\\" {
		t.Errorf("Expected 'abc\\', got: %q", result)
	}
}

// ============================================================================
// UnescapeLabel - decimal escape with valid 3-digit value
// (Additional coverage for the success path through Sscanf + ValidRune)
// ============================================================================

func TestUnescapeLabelDecimalEscapeValidValues(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"\\097", "a"},       // 97 = 'a'
		{"\\048", "0"},       // 48 = '0'
		{"\\032", " "},       // 32 = space
		{"\\127", "\x7f"},    // 127 = DEL
	}
	for _, tt := range tests {
		result, err := UnescapeLabel(tt.input)
		if err != nil {
			t.Errorf("UnescapeLabel(%q) unexpected error: %v", tt.input, err)
		}
		if result != tt.want {
			t.Errorf("UnescapeLabel(%q) = %q, want %q", tt.input, result, tt.want)
		}
	}
}

// ============================================================================
// Logger Fatal/Fatalf - these call os.Exit(1) which cannot be tested without
// killing the process. Mark as skipped since they are trivially correct.
// ============================================================================

func TestLoggerFatalSkipped(t *testing.T) {
	t.Skip("Logger.Fatal calls os.Exit(1) and cannot be tested in-process")
}

func TestLoggerFatalfSkipped(t *testing.T) {
	t.Skip("Logger.Fatalf calls os.Exit(1) and cannot be tested in-process")
}

func TestPackageFatalSkipped(t *testing.T) {
	t.Skip("package-level Fatal calls os.Exit(1) and cannot be tested in-process")
}

func TestPackageFatalfSkipped(t *testing.T) {
	t.Skip("package-level Fatalf calls os.Exit(1) and cannot be tested in-process")
}

// ============================================================================
// Logger.log - FATAL branch (os.Exit) - cannot be tested in-process.
// ============================================================================

func TestLoggerLogFatalExitSkipped(t *testing.T) {
	t.Skip("Logger.log with FATAL level calls os.Exit(1) and cannot be tested in-process")
}
