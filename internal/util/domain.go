package util

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Domain constants per RFC 1035
const (
	// MaxLabelLength is the maximum length of a single label (63 bytes)
	MaxLabelLength = 63
	// MaxNameLength is the maximum length of a full domain name (253 bytes, excluding trailing dot)
	MaxNameLength = 253
	// MaxLabels is the maximum number of labels in a domain name
	MaxLabels = 127
)

// Label represents a single DNS label.
type Label string

// IsValid returns true if the label is valid per RFC 1035.
func (l Label) IsValid() bool {
	if len(l) == 0 || len(l) > MaxLabelLength {
		return false
	}

	// Check each byte
	for i := 0; i < len(l); i++ {
		c := l[i]
		// Labels can contain letters, digits, and hyphens
		// Cannot start or end with hyphen
		if c >= 'a' && c <= 'z' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			continue
		}
		if c >= '0' && c <= '9' {
			continue
		}
		if c == '-' {
			if i == 0 || i == len(l)-1 {
				return false
			}
			continue
		}
		if c == '_' {
			// Underscore is technically not allowed in hostnames per RFC 952,
			// but is commonly used for service records (_dmarc, _domainkey, etc.)
			continue
		}
		return false
	}

	return true
}

// Domain represents a domain name with its labels.
type Domain struct {
	Labels []string
	IsFQDN bool // Fully Qualified Domain Name (ends with dot)
}

// ParseDomain parses a domain name string into a Domain struct.
func ParseDomain(name string) (*Domain, error) {
	d := &Domain{}

	// Check for trailing dot (FQDN)
	if strings.HasSuffix(name, ".") {
		d.IsFQDN = true
		name = name[:len(name)-1]
	}

	// Empty domain (root) is valid
	if name == "" {
		return d, nil
	}

	// Split into labels
	labels := strings.Split(name, ".")
	if len(labels) > MaxLabels {
		return nil, fmt.Errorf("domain has too many labels: %d (max %d)", len(labels), MaxLabels)
	}

	// Validate each label
	for i, label := range labels {
		// Wildcard label * is only valid at the beginning
		if label == "*" {
			if i != 0 {
				return nil, fmt.Errorf("wildcard * can only appear at the start of a domain")
			}
			d.Labels = append(d.Labels, label)
			continue
		}

		if !Label(label).IsValid() {
			return nil, fmt.Errorf("invalid label %q at position %d", label, i)
		}

		d.Labels = append(d.Labels, strings.ToLower(label))
	}

	// Validate total length
	if d.Length() > MaxNameLength {
		return nil, fmt.Errorf("domain name too long: %d bytes (max %d)", d.Length(), MaxNameLength)
	}

	return d, nil
}

// String returns the domain as a string.
func (d *Domain) String() string {
	result := strings.Join(d.Labels, ".")
	if d.IsFQDN {
		result += "."
	}
	return result
}

// Length returns the length of the domain name in bytes.
func (d *Domain) Length() int {
	length := 0
	for i, label := range d.Labels {
		length += len(label)
		if i < len(d.Labels)-1 {
			length++ // Dot separator
		}
	}
	return length
}

// Normalize normalizes the domain name:
// - Converts to lowercase
// - Removes trailing dot
func (d *Domain) Normalize() string {
	return strings.ToLower(strings.TrimSuffix(d.String(), "."))
}

// IsRoot returns true if this is the root domain (.) or empty.
func (d *Domain) IsRoot() bool {
	return len(d.Labels) == 0 || (len(d.Labels) == 1 && d.Labels[0] == "")
}

// IsWildcard returns true if the domain is a wildcard (starts with *).
func (d *Domain) IsWildcard() bool {
	return len(d.Labels) > 0 && d.Labels[0] == "*"
}

// Parent returns the parent domain.
// Returns nil if this is the root domain.
func (d *Domain) Parent() *Domain {
	if len(d.Labels) <= 1 {
		return &Domain{Labels: []string{}, IsFQDN: d.IsFQDN}
	}
	return &Domain{
		Labels: d.Labels[1:],
		IsFQDN: d.IsFQDN,
	}
}

// HasParent returns true if this domain is a subdomain of the given parent.
func (d *Domain) HasParent(parent *Domain) bool {
	if len(parent.Labels) > len(d.Labels) {
		return false
	}

	offset := len(d.Labels) - len(parent.Labels)
	for i, label := range parent.Labels {
		if !strings.EqualFold(label, d.Labels[offset+i]) {
			return false
		}
	}
	return true
}

// Equal returns true if the domains are equal (case-insensitive).
func (d *Domain) Equal(other *Domain) bool {
	if len(d.Labels) != len(other.Labels) {
		return false
	}
	for i, label := range d.Labels {
		if !strings.EqualFold(label, other.Labels[i]) {
			return false
		}
	}
	return true
}

// WireLabels returns the labels in wire format order (reversed).
// For wire format, labels are written in normal order, but when comparing
// domains, we often compare from the root (TLD first).
func (d *Domain) WireLabels() []string {
	// Return a copy
	labels := make([]string, len(d.Labels))
	copy(labels, d.Labels)
	return labels
}

// ReverseLabels returns the labels in reverse order (for comparison).
func (d *Domain) ReverseLabels() []string {
	labels := make([]string, len(d.Labels))
	for i, label := range d.Labels {
		labels[len(d.Labels)-1-i] = label
	}
	return labels
}

// Package-level utility functions

// NormalizeDomain normalizes a domain name string.
// - Converts to lowercase
// - Removes trailing dot
// Returns error if the domain is invalid.
func NormalizeDomain(name string) (string, error) {
	d, err := ParseDomain(name)
	if err != nil {
		return "", err
	}
	return d.Normalize(), nil
}

// IsValidDomain returns true if the domain name is valid.
func IsValidDomain(name string) bool {
	_, err := ParseDomain(name)
	return err == nil
}

// IsFQDN returns true if the domain name ends with a dot (fully qualified).
func IsFQDN(name string) bool {
	return strings.HasSuffix(name, ".")
}

// EnsureFQDN ensures the domain name ends with a dot.
func EnsureFQDN(name string) string {
	if !IsFQDN(name) {
		return name + "."
	}
	return name
}

// RemoveFQDN removes the trailing dot if present.
func RemoveFQDN(name string) string {
	return strings.TrimSuffix(name, ".")
}

// SplitDomain splits a domain name into its labels.
// Returns error if the domain is invalid.
func SplitDomain(name string) ([]string, error) {
	d, err := ParseDomain(name)
	if err != nil {
		return nil, err
	}
	return d.Labels, nil
}

// JoinLabels joins labels into a domain name.
func JoinLabels(labels []string, fqdn bool) string {
	result := strings.Join(labels, ".")
	if fqdn && result != "" {
		result += "."
	}
	return result
}

// CountLabels returns the number of labels in a domain name.
func CountLabels(name string) int {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return 0
	}
	return strings.Count(name, ".") + 1
}

// LongestCommonSuffix returns the longest common suffix between two domains.
// Returns the number of matching labels from the end.
func LongestCommonSuffix(a, b string) int {
	aLabels, _ := SplitDomain(a)
	bLabels, _ := SplitDomain(b)

	// Reverse both
	for i, j := 0, len(aLabels)-1; i < j; i, j = i+1, j-1 {
		aLabels[i], aLabels[j] = aLabels[j], aLabels[i]
	}
	for i, j := 0, len(bLabels)-1; i < j; i, j = i+1, j-1 {
		bLabels[i], bLabels[j] = bLabels[j], bLabels[i]
	}

	// Count matching labels
	count := 0
	for i := 0; i < len(aLabels) && i < len(bLabels); i++ {
		if !strings.EqualFold(aLabels[i], bLabels[i]) {
			break
		}
		count++
	}
	return count
}

// IsSubdomain returns true if child is a subdomain of parent.
func IsSubdomain(child, parent string) bool {
	childDomain, err := ParseDomain(child)
	if err != nil {
		return false
	}
	parentDomain, err := ParseDomain(parent)
	if err != nil {
		return false
	}
	return childDomain.HasParent(parentDomain)
}

// EscapeLabel escapes a domain label for use in zone files.
// Handles special characters like dots, backslashes, and non-printable characters.
func EscapeLabel(label string) string {
	var result strings.Builder
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c == '.':
			result.WriteString("\\.")
		case c == '\\':
			result.WriteString("\\\\")
		case c == '"':
			result.WriteString("\\\"")
		case c < 0x20 || c >= 0x7F:
			result.WriteString(fmt.Sprintf("\\%03d", c))
		default:
			result.WriteByte(c)
		}
	}
	return result.String()
}

// UnescapeLabel unescapes a domain label from zone file format.
func UnescapeLabel(label string) (string, error) {
	var result strings.Builder
	for i := 0; i < len(label); i++ {
		c := label[i]
		if c == '\\' && i+1 < len(label) {
			next := label[i+1]
			switch next {
			case '.', '\\', '"':
				result.WriteByte(next)
				i++
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				// Decimal escape \DDD
				if i+3 >= len(label) {
					return "", fmt.Errorf("incomplete decimal escape at position %d", i)
				}
				var val int
				_, err := fmt.Sscanf(label[i+1:i+4], "%d", &val)
				if err != nil {
					return "", fmt.Errorf("invalid decimal escape at position %d", i)
				}
				if !utf8.ValidRune(rune(val)) {
					return "", fmt.Errorf("invalid rune value %d", val)
				}
				result.WriteByte(byte(val))
				i += 3
			default:
				result.WriteByte(c)
			}
		} else {
			result.WriteByte(c)
		}
	}
	return result.String(), nil
}
