package protocol

import (
	"errors"
	"fmt"
	"strings"
)

// Label compression constants.
const (
	// PointerMask is the mask to identify a compression pointer (0xC0 = 1100 0000).
	PointerMask = 0xC0
	// PointerOffsetMask is the mask to extract the offset from a pointer (0x3FFF).
	PointerOffsetMask = 0x3FFF
	// MaxLabelLength is the maximum length of a single label (63 bytes).
	MaxLabelLength = 63
	// MaxNameLength is the maximum length of a domain name (255 bytes).
	MaxNameLength = 255
	// MaxPointerDepth is the maximum number of pointer indirections to follow.
	MaxPointerDepth = 10
)

// Common label errors.
var (
	ErrLabelTooLong     = errors.New("label too long")
	ErrNameTooLong      = errors.New("domain name too long")
	ErrInvalidLabel     = errors.New("invalid label")
	ErrInvalidPointer   = errors.New("invalid compression pointer")
	ErrPointerLoop      = errors.New("compression pointer loop detected")
	ErrPointerTooDeep   = errors.New("compression pointer depth exceeded")
	ErrInvalidWireData  = errors.New("invalid wire format data")
)

// Name represents a DNS domain name as a sequence of labels.
type Name struct {
	// Labels contains the labels in normal order (e.g., ["www", "example", "com"]).
	// The root label (empty string) is implicit and not stored.
	Labels []string
	// FQDN indicates if the name is fully qualified (ends with root).
	FQDN bool
}

// NewName creates a Name from a slice of labels.
func NewName(labels []string, fqdn bool) *Name {
	// Make a copy of the labels
	l := make([]string, len(labels))
	copy(l, labels)
	return &Name{Labels: l, FQDN: fqdn}
}

// ParseName parses a domain name string into a Name struct.
func ParseName(s string) (*Name, error) {
	// Remove trailing dot if present
	fqdn := strings.HasSuffix(s, ".")
	if fqdn {
		s = s[:len(s)-1]
	}

	// Root domain
	if s == "" {
		return &Name{Labels: []string{}, FQDN: fqdn}, nil
	}

	// Split into labels
	labels := strings.Split(s, ".")

	// Validate each label
	for i, label := range labels {
		if err := ValidateLabel(label); err != nil {
			return nil, fmt.Errorf("invalid label %d: %w", i, err)
		}
	}

	return &Name{Labels: labels, FQDN: fqdn}, nil
}

// String returns the domain name as a string.
func (n *Name) String() string {
	result := strings.Join(n.Labels, ".")
	if n.FQDN {
		result += "."
	}
	return result
}

// IsRoot returns true if this is the root domain.
func (n *Name) IsRoot() bool {
	return len(n.Labels) == 0
}

// IsWildcard returns true if this is a wildcard name (starts with *).
func (n *Name) IsWildcard() bool {
	return len(n.Labels) > 0 && n.Labels[0] == "*"
}

// HasPrefix returns true if the name has the given prefix labels.
func (n *Name) HasPrefix(prefix []string) bool {
	if len(prefix) > len(n.Labels) {
		return false
	}
	for i, label := range prefix {
		if !strings.EqualFold(label, n.Labels[i]) {
			return false
		}
	}
	return true
}

// HasSuffix returns true if the name has the given suffix labels.
func (n *Name) HasSuffix(suffix []string) bool {
	if len(suffix) > len(n.Labels) {
		return false
	}
	offset := len(n.Labels) - len(suffix)
	for i, label := range suffix {
		if !strings.EqualFold(label, n.Labels[offset+i]) {
			return false
		}
	}
	return true
}

// Equal returns true if the names are equal (case-insensitive).
func (n *Name) Equal(other *Name) bool {
	if len(n.Labels) != len(other.Labels) {
		return false
	}
	for i, label := range n.Labels {
		if !strings.EqualFold(label, other.Labels[i]) {
			return false
		}
	}
	return n.FQDN == other.FQDN
}

// WireLength returns the length of the name in wire format.
func (n *Name) WireLength() int {
	length := 0
	for _, label := range n.Labels {
		length += 1 + len(label) // length byte + label data
	}
	length++ // terminating zero
	return length
}

// ValidateLabel validates a single label.
func ValidateLabel(label string) error {
	// Empty label (root) is valid
	if label == "" {
		return nil
	}

	// Check length
	if len(label) > MaxLabelLength {
		return ErrLabelTooLong
	}

	// Check characters
	for i, c := range label {
		if i == 0 || i == len(label)-1 {
			// First and last character cannot be hyphen
			if c == '-' {
				return ErrInvalidLabel
			}
		}
		// Allow letters, digits, hyphens, and underscores
		if !isValidLabelChar(c) {
			return ErrInvalidLabel
		}
	}

	return nil
}

// isValidLabelChar returns true if the character is valid in a DNS label.
func isValidLabelChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '*'
}

// PackName packs a domain name into wire format with optional compression.
// Returns the number of bytes written and any compression pointer offset.
func PackName(name *Name, buf []byte, offset int, compression map[string]int) (int, error) {
	if offset < 0 || offset >= len(buf) {
		return 0, ErrInvalidOffset
	}

	startOffset := offset
	originalOffset := offset

	// Try compression - check all suffixes of the name
	if compression != nil {
		for i := 0; i < len(name.Labels); i++ {
			suffix := strings.ToLower(strings.Join(name.Labels[i:], "."))
			if ptrOffset, ok := compression[suffix]; ok && ptrOffset < PointerOffsetMask {
				// Write pointer
				if offset+2 > len(buf) {
					return 0, ErrBufferTooSmall
				}
				pointer := uint16(PointerMask<<8) | uint16(ptrOffset)
				PutUint16(buf[offset:], pointer)
				return offset + 2 - originalOffset, nil
			}
		}
	}

	// Write labels
	for i, label := range name.Labels {
		// Store compression offset for this prefix
		if compression != nil {
			prefix := strings.ToLower(strings.Join(name.Labels[i:], "."))
			compression[prefix] = offset
		}

		// Write label length and data
		labelLen := len(label)
		if labelLen > MaxLabelLength {
			return 0, ErrLabelTooLong
		}

		if offset+1+labelLen > len(buf) {
			return 0, ErrBufferTooSmall
		}

		buf[offset] = byte(labelLen)
		offset++

		// Write label data (lowercase for consistency)
		for j := 0; j < labelLen; j++ {
			buf[offset] = toLower(label[j])
			offset++
		}
	}

	// Write terminating zero
	if offset >= len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = 0
	offset++

	// Check total name length
	if offset-startOffset > MaxNameLength {
		return 0, ErrNameTooLong
	}

	return offset - originalOffset, nil
}

// UnpackName unpacks a domain name from wire format.
// Returns the name and the number of bytes consumed from the current offset.
func UnpackName(buf []byte, offset int) (*Name, int, error) {
	if offset < 0 || offset >= len(buf) {
		return nil, 0, ErrInvalidOffset
	}

	var labels []string
	var nameLen int
	startOffset := offset
	ptrDepth := 0
	ptrOffset := -1

	for {
		// Check bounds
		if offset >= len(buf) {
			return nil, 0, ErrBufferTooSmall
		}

		// Check for compression pointer
		if buf[offset]&PointerMask == PointerMask {
			// Compression pointer
			if offset+2 > len(buf) {
				return nil, 0, ErrBufferTooSmall
			}

			pointer := int(Uint16(buf[offset:]) & PointerOffsetMask)

			// Validate pointer
			if pointer >= len(buf) {
				return nil, 0, ErrInvalidPointer
			}

			// Check for loops
			if ptrDepth >= MaxPointerDepth {
				return nil, 0, ErrPointerTooDeep
			}

			// Record the pointer offset for byte counting
			if ptrOffset == -1 {
				ptrOffset = offset + 2
			}

			// Follow the pointer
			offset = pointer
			ptrDepth++
			continue
		}

		// Regular label
		labelLen := int(buf[offset])

		// Check for root (empty label)
		if labelLen == 0 {
			offset++
			if ptrOffset > 0 {
				// We followed a pointer, return the pointer offset as bytes consumed
				return &Name{Labels: labels, FQDN: true}, ptrOffset - startOffset, nil
			}
			return &Name{Labels: labels, FQDN: true}, offset - startOffset, nil
		}

		// Validate label length
		if labelLen > MaxLabelLength {
			return nil, 0, ErrLabelTooLong
		}

		// Check for buffer overflow
		if offset+1+labelLen > len(buf) {
			return nil, 0, ErrBufferTooSmall
		}

		// Check total name length
		nameLen += 1 + labelLen
		if nameLen > MaxNameLength {
			return nil, 0, ErrNameTooLong
		}

		// Extract label
		label := string(buf[offset+1 : offset+1+labelLen])
		labels = append(labels, label)

		offset += 1 + labelLen
	}
}

// toLower converts a byte to lowercase if it's an uppercase letter.
func toLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// WireNameLength returns the length of a domain name at the given offset.
// This is useful for skipping over names without fully parsing them.
func WireNameLength(buf []byte, offset int) (int, error) {
	if offset < 0 || offset >= len(buf) {
		return 0, ErrInvalidOffset
	}

	startOffset := offset
	ptrDepth := 0

	for {
		if offset >= len(buf) {
			return 0, ErrBufferTooSmall
		}

		// Check for compression pointer
		if buf[offset]&PointerMask == PointerMask {
			if offset+2 > len(buf) {
				return 0, ErrBufferTooSmall
			}
			// Pointer is always 2 bytes and terminates the name
			return offset + 2 - startOffset, nil
		}

		labelLen := int(buf[offset])
		if labelLen == 0 {
			// Root label
			return offset + 1 - startOffset, nil
		}

		if labelLen > MaxLabelLength {
			return 0, ErrLabelTooLong
		}

		offset += 1 + labelLen

		// Safety check
		ptrDepth++
		if ptrDepth > MaxNameLength {
			return 0, ErrPointerLoop
		}
	}
}

// CompareNames compares two domain names for ordering.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
// Comparison is done label by label from the TLD (right to left).
func CompareNames(a, b *Name) int {
	// Compare from the rightmost label (TLD) to the leftmost
	i, j := len(a.Labels)-1, len(b.Labels)-1

	for i >= 0 && j >= 0 {
		cmp := strings.Compare(
			strings.ToLower(a.Labels[i]),
			strings.ToLower(b.Labels[j]),
		)
		if cmp != 0 {
			return cmp
		}
		i--
		j--
	}

	// One name is a subdomain of the other
	if i < 0 && j < 0 {
		return 0 // Equal
	}
	if i < 0 {
		return -1 // a is shorter
	}
	return 1 // b is shorter
}

// IsSubdomain returns true if child is a subdomain of parent.
func IsSubdomain(child, parent *Name) bool {
	return child.HasSuffix(parent.Labels)
}
