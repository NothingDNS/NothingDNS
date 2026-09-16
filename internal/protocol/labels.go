package protocol

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
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
	// RFC 1035 allows 2-byte pointers, depth limit prevents compression attacks.
	MaxPointerDepth = 5
	// maxLabels is the maximum number of labels a name can contain.
	// With MaxNameLength=255 and min label=1 byte (1 len + 1 data), max ≈ 127.
	maxLabels = 127
)

// Common label errors.
var (
	ErrLabelTooLong    = errors.New("label too long")
	ErrNameTooLong     = errors.New("domain name too long")
	ErrInvalidLabel    = errors.New("invalid label")
	ErrInvalidPointer  = errors.New("invalid compression pointer")
	ErrPointerLoop     = errors.New("compression pointer loop detected")
	ErrPointerTooDeep  = errors.New("compression pointer depth exceeded")
	ErrInvalidWireData = errors.New("invalid wire format data")
)

// Name represents a DNS domain name in canonical wire format.
type Name struct {
	// wire contains the canonical lowercase, uncompressed wire-format name,
	// including the terminating root label.
	wire []byte
	// stringCache memoizes String() for request-path callers that repeatedly
	// stringify the same unpacked name. Must be cleared on every pool reuse.
	// Uses atomic.Pointer for safe concurrent access.
	stringCache atomic.Pointer[string]
}

// NewName creates a Name from a slice of labels.
func NewName(labels []string, fqdn bool) *Name {
	name := acquireName()
	name.wire = canonicalWireFromLabels(labels, fqdn)
	return name
}

// Copy creates a deep copy of the Name.
func (n *Name) Copy() *Name {
	if n == nil {
		return nil
	}
	copyName := acquireName()
	copyName.wire = append(acquireWireNameBuffer(), n.wire...)
	return copyName
}

// NewUnsafeName constructs a Name without validation. It exists to support
// tests that intentionally exercise pack-time validation failures.
func NewUnsafeName(labels []string, fqdn bool) *Name {
	name := acquireName()
	name.wire = canonicalWireFromLabels(labels, fqdn)
	return name
}

// CanonicalWire returns the canonical lowercase wire-format name.
func (n *Name) CanonicalWire() []byte {
	if n == nil {
		return []byte{0}
	}
	canonical := make([]byte, len(n.wire))
	for i, b := range n.wire {
		if b >= 'A' && b <= 'Z' {
			canonical[i] = b + ('a' - 'A')
		} else {
			canonical[i] = b
		}
	}
	return canonical
}

// LabelsSlice returns a copy-compatible view of the labels.
// Compatibility helper during migration away from direct field-based cloning.
func (n *Name) LabelsSlice() []string {
	if n == nil {
		return nil
	}
	return labelsFromWire(n.wire)
}

// ForEachLabel iterates labels in left-to-right order.
func (n *Name) ForEachLabel(fn func(label string) bool) {
	if n == nil || fn == nil {
		return
	}
	forEachWireLabel(n.wire, func(label []byte) bool {
		return fn(string(label))
	})
}

// Release returns the Name and its label-slice backing storage to internal pools.
// After Release the Name must not be used again.
func (n *Name) Release() {
	if n == nil {
		return
	}
	if n.wire != nil {
		// Release a LOCAL header, not &n.wire: pooling an interior pointer
		// into this Name struct lets a later acquireWireNameBuffer() alias
		// this struct's backing array after n is recycled from namePool and
		// given fresh content — the next Release of n then zeroes the other
		// name's bytes (order-dependent corruption under pool churn).
		buf := n.wire
		n.wire = nil
		releaseWireNameBuffer(&buf)
	}
	n.stringCache.Store(nil)
	// NOTE: the struct is deliberately NOT returned to namePool. Records
	// routinely share one *Name (same owner across RRsets), and Release runs
	// once per record — a shared Name was multi-Put, so subsequent
	// acquireName calls returned the same struct to independent callers and
	// the last write clobbered every other name's content. Wire buffers are
	// still recycled above; the small Name header is re-allocated instead.
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
		name := acquireName()
		name.wire = append(acquireWireNameBuffer(), 0)
		return name, nil
	}

	// Split into labels
	labels := strings.Split(s, ".")

	if err := validateNameLabels(labels); err != nil {
		return nil, err
	}

	// Validate each label
	for i, label := range labels {
		if err := ValidateLabel(label); err != nil {
			return nil, fmt.Errorf("invalid label %d: %w", i, err)
		}
	}

	name := acquireName()
	name.wire = canonicalWireFromLabels(labels, fqdn)
	return name, nil
}

// String returns the domain name as a string.
func (n *Name) String() string {
	if n == nil {
		return "."
	}
	if p := n.stringCache.Load(); p != nil {
		return *p
	}
	result := presentationFromWire(n.wire)
	n.stringCache.Store(&result)
	return result
}

// IsRoot returns true if this is the root domain.
func (n *Name) IsRoot() bool {
	if n == nil {
		return true
	}
	return len(n.wire) == 1 && n.wire[0] == 0
}

// IsWildcard returns true if this is a wildcard name (starts with *).
func (n *Name) IsWildcard() bool {
	if n == nil {
		return false
	}
	return len(n.wire) >= 2 && n.wire[0] == 1 && n.wire[1] == '*'
}

// HasPrefix returns true if the name has the given prefix labels.
func (n *Name) HasPrefix(prefix []string) bool {
	if n == nil {
		return len(prefix) == 0
	}
	labels := labelsFromWire(n.wire)
	if len(prefix) > len(labels) {
		return false
	}
	for i, label := range prefix {
		if !strings.EqualFold(label, labels[i]) {
			return false
		}
	}
	return true
}

// HasPrefixName returns true if the name has the given prefix name.
func (n *Name) HasPrefixName(prefix *Name) bool {
	if prefix == nil {
		return true
	}
	return n.HasPrefix(prefix.LabelsSlice())
}

// HasSuffix returns true if the name has the given suffix labels.
func (n *Name) HasSuffix(suffix []string) bool {
	if n == nil {
		return len(suffix) == 0
	}
	labels := labelsFromWire(n.wire)
	if len(suffix) > len(labels) {
		return false
	}
	offset := len(labels) - len(suffix)
	for i, label := range suffix {
		if !strings.EqualFold(label, labels[offset+i]) {
			return false
		}
	}
	return true
}

// HasSuffixName returns true if the name has the given suffix name.
func (n *Name) HasSuffixName(suffix *Name) bool {
	if suffix == nil {
		return true
	}
	return n.HasSuffix(suffix.LabelsSlice())
}

// Equal returns true if the names are equal (case-insensitive).
func (n *Name) Equal(other *Name) bool {
	if n == nil || other == nil {
		return false
	}
	labelsA := labelsFromWire(n.wire)
	labelsB := labelsFromWire(other.wire)
	if len(labelsA) != len(labelsB) {
		return false
	}
	for i := range labelsA {
		if !strings.EqualFold(labelsA[i], labelsB[i]) {
			return false
		}
	}
	return true
}

// WireLength returns the length of the name in wire format.
func (n *Name) WireLength() int {
	if n == nil {
		return 1
	}
	return len(n.wire)
}

func validateNameLabels(labels []string) error {
	if len(labels) > maxLabels {
		return ErrNameTooLong
	}
	length := 1 // terminating root label
	for _, label := range labels {
		length += 1 + len(label)
		if length > MaxNameLength {
			return ErrNameTooLong
		}
	}
	return nil
}

func validateWireName(wire []byte) error {
	if len(wire) == 0 {
		return nil
	}
	if len(wire) > MaxNameLength {
		return ErrNameTooLong
	}
	labelCount := 0
	nameLen := 0
	for i := 0; i < len(wire); {
		labelLen := int(wire[i])
		nameLen += 1
		i++
		if labelLen == 0 {
			if i != len(wire) {
				return ErrInvalidWireData
			}
			return nil
		}
		if labelLen > MaxLabelLength {
			return ErrLabelTooLong
		}
		if i+labelLen > len(wire) {
			return ErrBufferTooSmall
		}
		nameLen += labelLen
		if nameLen > MaxNameLength {
			return ErrNameTooLong
		}
		labelCount++
		if labelCount > maxLabels {
			return ErrNameTooLong
		}
		i += labelLen
	}
	return ErrInvalidWireData
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
	if name == nil {
		buf[offset] = 0
		return 1, nil
	}
	if err := validateWireName(name.wire); err != nil {
		return 0, err
	}
	if compression == nil {
		if offset+len(name.wire) > len(buf) {
			return 0, ErrBufferTooSmall
		}
		for i, b := range name.wire {
			buf[offset+i] = toLower(b)
		}
		return len(name.wire), nil
	}

	originalOffset := offset

	// Compression keys and suffix boundaries are derived from the WIRE
	// form, not the presentation string: presentationFromWire does not
	// escape special bytes, so a wire label containing a literal '.'
	// renders as multiple presentation labels and the two label counts
	// desync — the old presentation-based bookkeeping emitted wrong
	// labels and polluted the compression map for such names.
	var starts [maxLabels]int
	labelCount := 0
	for i := 0; i < len(name.wire); {
		labelLen := int(name.wire[i])
		if labelLen == 0 {
			break
		}
		if labelCount >= maxLabels {
			return 0, ErrNameTooLong
		}
		starts[labelCount] = i
		labelCount++
		i += 1 + labelLen
	}
	if labelCount == 0 { // root
		if offset >= len(buf) {
			return 0, ErrBufferTooSmall
		}
		buf[offset] = 0
		return 1, nil
	}

	// RFC 1035 §4.1.4: a name may end with a pointer, but the labels
	// BEFORE the matched suffix must still be emitted (an earlier version
	// jumped straight to the pointer for any suffix match, silently
	// dropping the leading labels — packing "www.example.com." after
	// "a.example.com." produced a name that decoded as "example.com.").
	for i := 0; i < labelCount; i++ {
		key := wireSuffixKey(name.wire[starts[i]:])
		if ptrOffset, ok := compression[key]; ok && ptrOffset < PointerOffsetMask {
			for l := 0; l < i; l++ {
				start := starts[l]
				labelLen := int(name.wire[start])
				if prefixKey := wireSuffixKey(name.wire[start:]); prefixKey != "" {
					if _, exists := compression[prefixKey]; !exists {
						compression[prefixKey] = offset
					}
				}
				if offset+1+labelLen > len(buf) {
					return 0, ErrBufferTooSmall
				}
				copy(buf[offset:offset+1+labelLen], name.wire[start:start+1+labelLen])
				offset += 1 + labelLen
			}
			if offset+2 > len(buf) {
				return 0, ErrBufferTooSmall
			}
			pointer := uint16(PointerMask<<8) | uint16(ptrOffset)
			PutUint16(buf[offset:], pointer)
			offset += 2
			return offset - originalOffset, nil
		}
	}

	// No suffix already packed: emit every label, registering each suffix
	// (keyed on wire bytes) as a future compression target.
	for l := 0; l < labelCount; l++ {
		start := starts[l]
		labelLen := int(name.wire[start])
		if key := wireSuffixKey(name.wire[start:]); key != "" {
			if _, exists := compression[key]; !exists {
				compression[key] = offset
			}
		}
		if offset+1+labelLen > len(buf) {
			return 0, ErrBufferTooSmall
		}
		copy(buf[offset:offset+1+labelLen], name.wire[start:start+1+labelLen])
		offset += 1 + labelLen
	}

	if offset >= len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = 0
	offset++
	return offset - originalOffset, nil
}

// wireSuffixKey returns the case-folded wire bytes of a name suffix
// (length-prefixed labels, excluding any trailing root byte) for use as a
// compression-map key. Keying on wire bytes keeps label boundaries exact
// even when a label contains a literal '.' — the unescaped presentation
// form is ambiguous for such labels. DNS name compression matches
// case-insensitively (RFC 1035 §4.1.4), hence the fold.
func wireSuffixKey(wireSuffix []byte) string {
	end := len(wireSuffix)
	if end > 0 && wireSuffix[end-1] == 0 {
		end--
	}
	if end <= 0 {
		return ""
	}
	b := make([]byte, end)
	for i := 0; i < end; i++ {
		b[i] = toLower(wireSuffix[i])
	}
	return string(b)
}

// UnpackName unpacks a domain name from wire format.
// Returns the name and the number of bytes consumed from the current offset.
func UnpackName(buf []byte, offset int) (*Name, int, error) {
	if offset < 0 || offset >= len(buf) {
		return nil, 0, ErrInvalidOffset
	}

	var nameLen int
	startOffset := offset
	ptrDepth := 0
	ptrOffset := -1
	wire := acquireWireNameBuffer()

	for {
		if offset >= len(buf) {
			releaseWireNameBuffer(&wire)
			return nil, 0, ErrBufferTooSmall
		}

		if buf[offset]&PointerMask == PointerMask {
			if offset+2 > len(buf) {
				releaseWireNameBuffer(&wire)
				return nil, 0, ErrBufferTooSmall
			}

			pointer := int(Uint16(buf[offset:]) & PointerOffsetMask)
			if pointer >= len(buf) || pointer >= offset {
				releaseWireNameBuffer(&wire)
				return nil, 0, ErrInvalidPointer
			}
			if ptrDepth >= MaxPointerDepth {
				releaseWireNameBuffer(&wire)
				return nil, 0, ErrPointerTooDeep
			}
			if ptrOffset == -1 {
				ptrOffset = offset + 2
			}
			offset = pointer
			ptrDepth++
			continue
		}

		labelLen := int(buf[offset])
		if labelLen == 0 {
			wire = append(wire, 0)
			offset++
			name := acquireName()
			name.wire = wire
			name.stringCache.Store(nil)
			if ptrOffset > 0 {
				return name, ptrOffset - startOffset, nil
			}
			return name, offset - startOffset, nil
		}

		if labelLen > MaxLabelLength {
			releaseWireNameBuffer(&wire)
			return nil, 0, ErrLabelTooLong
		}
		if offset+1+labelLen > len(buf) {
			releaseWireNameBuffer(&wire)
			return nil, 0, ErrBufferTooSmall
		}

		nameLen += 1 + labelLen
		if nameLen > MaxNameLength || len(wire)+1+labelLen+1 > MaxNameLength {
			releaseWireNameBuffer(&wire)
			return nil, 0, ErrNameTooLong
		}

		wire = append(wire, byte(labelLen))
		wire = append(wire, buf[offset+1:offset+1+labelLen]...)
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

func canonicalWireFromLabels(labels []string, fqdn bool) []byte {
	_ = fqdn // all protocol names are stored in fully-qualified wire form
	wire := acquireWireNameBuffer()
	for _, label := range labels {
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	wire = append(wire, 0)
	return wire
}

func labelsFromWire(wire []byte) []string {
	labels := make([]string, 0, maxLabels)
	forEachWireLabel(wire, func(label []byte) bool {
		labels = append(labels, string(label))
		return true
	})
	return labels
}

func presentationFromWire(wire []byte) string {
	if len(wire) == 0 {
		return ""
	}
	if len(wire) == 1 && wire[0] == 0 {
		return "."
	}
	var b strings.Builder
	first := true
	forEachWireLabel(wire, func(label []byte) bool {
		if !first {
			b.WriteByte('.')
		}
		b.Write(label)
		first = false
		return true
	})
	b.WriteByte('.')
	return b.String()
}

func forEachWireLabel(wire []byte, fn func(label []byte) bool) {
	if fn == nil {
		return
	}
	for i := 0; i < len(wire); {
		labelLen := int(wire[i])
		i++
		if labelLen == 0 {
			return
		}
		if i+labelLen > len(wire) {
			return
		}
		if !fn(wire[i : i+labelLen]) {
			return
		}
		i += labelLen
	}
}

// CanonicalWireName converts a DNS name string to canonical lowercase wire
// format (RFC 4034 Section 6.2). Each label is prefixed with its length byte,
// and the name is terminated with a zero-length root label. The name is
// lowercased using ASCII-only rules (DNS names are ASCII).
func CanonicalWireName(name string) []byte {
	// Trim whitespace and trailing dot
	start := 0
	end := len(name)
	for start < end && (name[start] == ' ' || name[start] == '\t') {
		start++
	}
	for end > start && (name[end-1] == ' ' || name[end-1] == '\t') {
		end--
	}
	name = name[start:end]
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	if name == "" {
		return []byte{0}
	}

	// Count dots to estimate wire size
	dots := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			dots++
		}
	}

	// Pre-allocate: labels + length bytes + root zero
	wire := make([]byte, 0, len(name)+2-dots)
	labelStart := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			labelLen := i - labelStart
			if labelLen == 0 {
				labelStart = i + 1
				continue
			}
			wire = append(wire, byte(labelLen))
			for j := 0; j < labelLen; j++ {
				wire = append(wire, toLower(name[labelStart+j]))
			}
			labelStart = i + 1
		}
	}
	wire = append(wire, 0)
	return wire
}

// WireNameLength returns the length of a domain name at the given offset.
// This is useful for skipping over names without fully parsing them.
func WireNameLength(buf []byte, offset int) (int, error) {
	if offset < 0 || offset >= len(buf) {
		return 0, ErrInvalidOffset
	}

	startOffset := offset
	labelCount := 0
	nameLen := 1

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
		if offset+1+labelLen > len(buf) {
			return 0, ErrBufferTooSmall
		}

		labelCount++
		if labelCount > maxLabels {
			return 0, ErrNameTooLong
		}
		nameLen += 1 + labelLen
		if nameLen > MaxNameLength {
			return 0, ErrNameTooLong
		}

		offset += 1 + labelLen
	}
}

// CompareNames compares two domain names for ordering.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
// Comparison is done label by label from the TLD (right to left).
func CompareNames(a, b *Name) int {
	var aLabels, bLabels []string
	if a != nil {
		aLabels = a.LabelsSlice()
	}
	if b != nil {
		bLabels = b.LabelsSlice()
	}

	// Compare from the rightmost label (TLD) to the leftmost
	i, j := len(aLabels)-1, len(bLabels)-1

	for i >= 0 && j >= 0 {
		cmp := strings.Compare(
			strings.ToLower(aLabels[i]),
			strings.ToLower(bLabels[j]),
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
	if parent == nil {
		return true
	}
	return child.HasSuffixName(parent)
}
