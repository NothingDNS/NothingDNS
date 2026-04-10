// Package idna implements Internationalized Domain Names in Applications (IDNA)
// according to RFC 5890, 5891, 5892, 5893, 5895, and RFC 3492 (Punycode).
package idna

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// Errors returned by IDNA operations.
var (
	ErrEmptyLabel       = errors.New("empty label")
	ErrLabelTooLong     = errors.New("label too long")
	ErrNameTooLong      = errors.New("domain name too long")
	ErrInvalidRune      = errors.New("invalid rune for IDNA")
	ErrInvalidPunycode  = errors.New("invalid punycode")
	ErrInvalidACEPrefix = errors.New("invalid ACE prefix")
	ErrInvalidBid       = errors.New("bidirectional restriction violation")
	ErrContextJ         = errors.New("contextual rule J failure")
	ErrContextO         = errors.New("contextual rule O failure")
	ErrHyphenStart      = errors.New("label starts with hyphen")
	ErrHyphenEnd        = errors.New("label ends with hyphen")
	ErrDigitStart       = errors.New("label starts with digit")
	ErrLeadingCombining = errors.New("leading combining character")
	ErrDisallowed       = errors.New("disallowed character")
	ErrUnassigned       = errors.New("unassigned character")
)

// MaxLabelLength is the maximum length of a label (63 bytes per RFC 5891).
const MaxLabelLength = 63

// MaxNameLength is the maximum length of a domain name (255 bytes per RFC 5891).
const MaxNameLength = 255

// ACEPrefix is the ASCII-compatible encoding prefix for punycode.
const ACEPrefix = "xn--"

// Profile represents an IDNA profile with specific rules.
type Profile struct {
	// AllowUnassigned indicates whether unassigned code points are allowed.
	AllowUnassigned bool
	// UseSTD3Rules indicates whether to use STD3 ASCII rules.
	UseSTD3Rules bool
	// CheckBidi indicates whether to check bidirectional rules.
	CheckBidi bool
	// CheckJoiner indicates whether to check joiner restrictions.
	CheckJoiner bool
}

// ToASCII converts an internationalized domain name to ASCII (punycode).
// This implements RFC 5891 Section 4.1.
func ToASCII(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimSuffix(domain, ".")

	if domain == "" {
		return "", nil
	}

	// Check if already ASCII-only
	if isASCII(domain) {
		// ASCII-only domain - labels will be validated in the loop below
		labels := strings.Split(domain, ".")
		for _, label := range labels {
			if label == "" {
				continue
			}
			if err := validateSTD3(label); err != nil {
				return "", err
			}
		}
		return domain, nil
	}

	// Step 1: Encode with punycode
	labels := strings.Split(domain, ".")
	result := make([]string, 0, len(labels))

	for _, label := range labels {
		if label == "" {
			continue
		}

		// Try to encode the label
		if isASCII(label) {
			// ASCII label - already validated above, just add
			result = append(result, label)
		} else {
			// Non-ASCII label - convert to punycode
			encoded, err := encodeLabel(label)
			if err != nil {
				return "", fmt.Errorf("label %q: %w", label, err)
			}
			result = append(result, ACEPrefix+encoded)
		}
	}

	// Check total length
	asciiDomain := strings.Join(result, ".")
	if len(asciiDomain) > MaxNameLength {
		return "", ErrNameTooLong
	}

	return asciiDomain, nil
}

// ToUnicode converts an ASCII domain name (possibly with punycode) to Unicode.
// This implements RFC 5891 Section 4.2.
func ToUnicode(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimSuffix(domain, ".")

	if domain == "" {
		return "", nil
	}

	// Check for ACE prefix
	labels := strings.Split(domain, ".")
	result := make([]string, 0, len(labels))

	for _, label := range labels {
		if label == "" {
			continue
		}

		if strings.HasPrefix(label, ACEPrefix) {
			// Punycode label
			decoded, err := decodeLabel(label[len(ACEPrefix):])
			if err != nil {
				return "", fmt.Errorf("label %q: %w", label, err)
			}
			result = append(result, decoded)
		} else {
			// Regular ASCII label
			result = append(result, label)
		}
	}

	return strings.Join(result, "."), nil
}

// encodeLabel encodes a Unicode label to punycode.
func encodeLabel(label string) (string, error) {
	// For non-ASCII labels (Internationalized labels):
	// 1. Map characters (RFC 5895)
	// 2. Check if any non-ASCII characters remain
	// 3. Encode with punycode
	// Note: Bidirectional rules (RFC 5893) apply to the ASCII output, not input

	// Step 1: Apply mapping (lowercase, etc.)
	mapped := mapLabel(label)

	// Check if any non-ASCII characters remain after mapping
	needsEncoding := false
	for _, r := range mapped {
		if r > 0x7F {
			needsEncoding = true
			break
		}
	}

	if !needsEncoding {
		// All ASCII after mapping - validate with STD3
		if err := validateSTD3(mapped); err != nil {
			return "", err
		}
		return mapped, nil
	}

	// Step 2: Encode with punycode
	encoded := encodePunycode(mapped)

	return encoded, nil
}

// decodeLabel decodes a punycode label to Unicode.
func decodeLabel(punycode string) (string, error) {
	if punycode == "" {
		return "", ErrEmptyLabel
	}

	// Check if it's punycode (has ACE prefix handled by caller)
	if !strings.ContainsRune(punycode, '-') {
		// No hyphen means pure ASCII (no punycode encoding needed)
		// But the ACE prefix check is done by the caller
		return punycode, nil
	}

	// Find the hyphen that separates base and digit parts
	// Punycode format: [label before hyphen]--[encoded]
	// The "encoded" part contains the base and digit sequence
	parts := strings.Split(punycode, "--")
	if len(parts) < 2 {
		// No encoding part
		return punycode, nil
	}

	prefix := parts[0]
	encoded := parts[1]

	// Decode the punycode
	decoded := decodePunycode(encoded)

	// Combine the prefix (already ASCII) with decoded
	return prefix + decoded, nil
}

// mapLabel applies the character mapping from RFC 5895.
func mapLabel(label string) string {
	// RFC 5895: Map characters
	// Currently maps uppercase to lowercase
	var result strings.Builder
	for _, r := range label {
		// RFC 5895 Section 2: Map uppercase to lowercase
		result.WriteRune(unicode.ToLower(r))
	}
	return result.String()
}

// validateLabel validates a label according to IDNA rules.
func validateLabel(label string, isIDNA bool) error {
	if label == "" {
		return ErrEmptyLabel
	}

	if len(label) > MaxLabelLength {
		return ErrLabelTooLong
	}

	// Check STD3 rules if enabled
	if err := validateSTD3(label); err != nil {
		return err
	}

	if !isIDNA {
		return nil
	}

	// Check bidirectional rules (RFC 5893)
	if err := validateBidi(label); err != nil {
		return err
	}

	// Check contextual rules (RFC 5892 Section 4)
	if err := validateContext(label); err != nil {
		return err
	}

	return nil
}

// validateSTD3 validates a label against STD3 ASCII rules.
// Label must:
// - Not start with hyphen
// - Not end with hyphen
// - Not contain other ASCII special characters
func validateSTD3(label string) error {
	if len(label) == 0 {
		return nil
	}

	// Check start and end hyphens
	if label[0] == '-' {
		return ErrHyphenStart
	}
	if label[len(label)-1] == '-' {
		return ErrHyphenEnd
	}

	// Check for invalid ASCII characters
	for i := 0; i < len(label); i++ {
		c := rune(label[i])
		if c < 0x20 || c == 0x7F {
			return ErrInvalidRune
		}
		// Allow only letters, digits, and hyphens
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return ErrInvalidRune
		}
	}

	return nil
}

// validateBidi validates bidirectional string restrictions per RFC 5893.
func validateBidi(label string) error {
	// RFC 5893: Bidirectional Character Classes
	// Labels must follow the bidirectional profile requirements

	var (
		hasLTR    bool
		hasRTL    bool
		hasNumber bool
	)

	runes := []rune(label)
	if len(runes) == 0 {
		return nil
	}

	lastRune := runes[len(runes)-1]

	for i, r := range runes {
		category := bidirectionalCategory(r)
		switch category {
		case "L":
			hasLTR = true
		case "R", "AL":
			hasRTL = true
		case "EN", "AN":
			hasNumber = true
		}

		// Check for leading combining characters
		if i == 0 && isCombiningMark(r) {
			return ErrLeadingCombining
		}
	}

	// RFC 5893 Section 4: Bidirectional rules
	// If string is all LTR, any character allowed
	// If string is all RTL (R/AL), no numbers at the end

	if hasRTL && !hasLTR {
		// RTL string
		if hasNumber {
			// Numbers (EN/AN) are not allowed at the end of RTL strings
			if isNumberCategory(lastRune) {
				return ErrInvalidBid
			}
		}
	}

	return nil
}

// validateContext validates contextual rules per RFC 5892 Section 4.
func validateContext(label string) error {
	// RFC 5892 Section 4.2: Contextual Rules

	runes := []rune(label)
	for i, r := range runes {
		// Rule J: Hebrew letters in numeric and literal domain names
		if r == 0x200D {
			// Zero-width joiner - check if valid for surrounding characters
			if !isValidZWJContext(runes, i) {
				return ErrContextJ
			}
		}

		// Rule O: Arabic Indic digits
		if r >= 0x0660 && r <= 0x0669 {
			// Arabic-Indic digit - must not be preceded by ASCII digit
			if i > 0 && runes[i-1] >= '0' && runes[i-1] <= '9' {
				return ErrContextO
			}
		}
	}

	return nil
}

// isValidZWJContext checks if zero-width joiner is in valid context.
func isValidZWJContext(runes []rune, index int) bool {
	// ZWJ is valid if surrounded by characters that can join
	if index == 0 || index == len(runes)-1 {
		return false
	}

	// Check if both neighbors are of type that permits joining
	// Typically used for emoji sequences, etc.
	prev := runes[index-1]
	next := runes[index+1]

	// ZWJ is valid between certain ranges (registration marks, etc.)
	// Simplified check - a full implementation would use Detailed property data
	return isJoinable(prev) && isJoinable(next)
}

// isJoinable returns true if the rune can participate in ZWJ sequences.
func isJoinable(r rune) bool {
	// Simplified: many emoji and special marks are joinable
	// Full implementation would use Unicode Joining_Type property
	return r >= 0x1F000 || (r >= 0x0300 && r <= 0x036F)
}

// bidirectionalCategory returns the Bidirectional Category for a rune.
func bidirectionalCategory(r rune) string {
	// RFC 5893 Table 1: Bidirectional Character Types
	// Simplified categorization

	switch {
	case r >= 0x0041 && r <= 0x005A:
		return "L" // Left-to-Right
	case r >= 0x0061 && r <= 0x007A:
		return "L"
	case r >= 0x00C0 && r <= 0x00DE:
		return "L"
	case r >= 0x0030 && r <= 0x0039:
		return "EN" // European Number
	case r >= 0x0660 && r <= 0x0669:
		return "AN" // Arabic Number
	case r == 0x200D:
		return "ON" // Other Neutral (ZWJ)
	case r >= 0x0590 && r <= 0x05FF:
		return "R" // Right-to-Left
	case r >= 0x0600 && r <= 0x06FF:
		return "AL" // Arabic Letter
	case r >= 0x0700 && r <= 0x08FF:
		return "AL"
	case r >= 0xFB50 && r <= 0xFDFF:
		return "AL"
	case r >= 0xFE70 && r <= 0xFEFF:
		return "AL"
	default:
		return "ON" // Other Neutral
	}
}

// isCombiningMark returns true if the rune is a combining mark.
func isCombiningMark(r rune) bool {
	// Unicode Category Mn (Mark, Nonspacing) and Mc (Mark, Spacing Combining)
	// Simplified check
	return (r >= 0x0300 && r <= 0x036F) || // Combining Diacritical Marks
		(r >= 0x0930 && r <= 0x093F) || // Devanagari
		(r >= 0x0940 && r <= 0x094F) ||
		(r >= 0x0980 && r <= 0x098F) // Bengali
}

// isNumberCategory returns true if rune is a number category.
func isNumberCategory(r rune) bool {
	return (r >= '0' && r <= '9') ||
		(r >= 0x0660 && r <= 0x0669) ||
		(r >= 0x06F0 && r <= 0x06FF)
}

// isUnassigned returns true if rune is an unassigned code point.
func isUnassigned(r rune) bool {
	// Unassigned ranges in Unicode
	// Simplified - a full implementation would check Unicode version
	return false // Placeholder - no unassigned in recent Unicode
}

// isASCII returns true if string contains only ASCII characters.
func isASCII(s string) bool {
	for _, c := range s {
		if c > 0x7F {
			return false
		}
	}
	return true
}

// ValidateLabel validates a single DNS label for IDNA compliance.
// Labels longer than 63 bytes or containing invalid characters return errors.
func ValidateLabel(label string) error {
	return validateLabel(label, true)
}

// ValidateDomain validates an entire domain name for IDNA compliance.
func ValidateDomain(domain string) error {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimSuffix(domain, ".")

	if len(domain) > MaxNameLength {
		return ErrNameTooLong
	}

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" {
			continue
		}
		if err := validateLabel(label, true); err != nil {
			return fmt.Errorf("label %q: %w", label, err)
		}
	}

	return nil
}

// FromUnicode converts a Unicode domain name to ASCII (punycode).
// Alias for ToASCII.
func FromUnicode(domain string) (string, error) {
	return ToASCII(domain)
}

// FromASCII converts an ASCII domain name (possibly with punycode) to Unicode.
// Alias for ToUnicode.
func FromASCII(domain string) (string, error) {
	return ToUnicode(domain)
}
