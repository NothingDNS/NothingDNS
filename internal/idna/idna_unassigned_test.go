package idna

import "testing"

// Regression: isUnassigned was a placeholder returning false, so
// AllowUnassigned=false never rejected anything. The RFC 5892 derived
// property (tables<version>.go, same Unicode version as the toolchain)
// now decides; noncharacters are DISALLOWED, not UNASSIGNED (§2.10).
func TestIsUnassigned(t *testing.T) {
	isUnassigned := func(r rune) bool { return derivedProperty(r) == propUnassigned }
	assigned := []rune{'a', 'é', 'ü', '中', 'א', 'ع', '9', 0x00E9}
	for _, r := range assigned {
		if isUnassigned(r) {
			t.Errorf("isUnassigned(%U) = true, want false (assigned)", r)
		}
	}
	unassigned := []rune{
		0x0378,  // unassigned in the Greek block
		0x2FE0,  // unassigned range
		0xE01F0, // beyond variation selectors supplement
	}
	for _, r := range unassigned {
		if !isUnassigned(r) {
			t.Errorf("isUnassigned(%U) = false, want true", r)
		}
	}
	if !isUnassigned(-1) || !isUnassigned(0x110000) {
		t.Error("out-of-range runes must be treated as unassigned")
	}
	if p := derivedProperty(0x10FFFE); p != propDisallowed {
		t.Errorf("noncharacter U+10FFFE = %d, want DISALLOWED", p)
	}
}
