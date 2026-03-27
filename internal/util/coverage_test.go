package util

// coverage_test.go adds tests for low-coverage functions in the util package.
// Functions targeted (below 80% or 0%):
//   - Domain.IsRoot: 0%
//   - Domain.Parent: 0%
//   - Domain.WireLabels: 0%
//   - Domain.ReverseLabels: 0%
//   - NormalizeDomain: 0%
//   - RemoveFQDN: 0%
//   - IPFamily.String: 0%
//   - IsSubdomain: 71.4%
//   - ParseDomain (wildcard at non-first position): 85.7%
//   - SplitDomain: 75%

import (
	"net"
	"strings"
	"testing"
)

// ============================================================================
// Domain.IsRoot
// ============================================================================

func TestDomainIsRoot(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		{".", true},
		{"", true},
		{"example.com", false},
		{"www.example.com", false},
	}
	for _, tt := range tests {
		d, err := ParseDomain(tt.domain)
		if err != nil {
			t.Fatalf("ParseDomain(%q) error: %v", tt.domain, err)
		}
		if got := d.IsRoot(); got != tt.want {
			t.Errorf("Domain(%q).IsRoot() = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

// ============================================================================
// Domain.Parent
// ============================================================================

func TestDomainParent(t *testing.T) {
	tests := []struct {
		domain  string
		wantStr string
	}{
		{"www.example.com", "example.com"},
		{"example.com", "com"},
		{"a.b.c.example.com", "b.c.example.com"},
		{".", "."},
	}
	for _, tt := range tests {
		d, err := ParseDomain(tt.domain)
		if err != nil {
			t.Fatalf("ParseDomain(%q) error: %v", tt.domain, err)
		}
		parent := d.Parent()
		if parent == nil {
			t.Fatalf("Domain(%q).Parent() returned nil", tt.domain)
		}
		if parent.String() != tt.wantStr {
			t.Errorf("Domain(%q).Parent().String() = %q, want %q", tt.domain, parent.String(), tt.wantStr)
		}
	}

	// Parent of single-label domain returns root
	single, _ := ParseDomain("com")
	parent := single.Parent()
	if parent == nil {
		t.Fatal("Parent of single-label should not return nil")
	}
	if !parent.IsRoot() {
		t.Error("Parent of single-label domain should be root")
	}

	// Parent of root is root
	root, _ := ParseDomain(".")
	rootParent := root.Parent()
	if rootParent == nil {
		t.Fatal("Root Parent() should not return nil")
	}
	if !rootParent.IsRoot() {
		t.Error("Root Parent() should be root")
	}
}

// ============================================================================
// Domain.WireLabels
// ============================================================================

func TestDomainWireLabels(t *testing.T) {
	d, _ := ParseDomain("www.example.com")
	wl := d.WireLabels()
	expected := []string{"www", "example", "com"}
	if len(wl) != len(expected) {
		t.Fatalf("WireLabels length = %d, want %d", len(wl), len(expected))
	}
	for i, label := range wl {
		if label != expected[i] {
			t.Errorf("WireLabels[%d] = %q, want %q", i, label, expected[i])
		}
	}

	// Verify it's a copy
	wl[0] = "modified"
	if d.Labels[0] == "modified" {
		t.Error("WireLabels should return a copy, not reference original")
	}
}

// ============================================================================
// Domain.ReverseLabels
// ============================================================================

func TestDomainReverseLabels(t *testing.T) {
	d, _ := ParseDomain("www.example.com")
	rl := d.ReverseLabels()
	expected := []string{"com", "example", "www"}
	if len(rl) != len(expected) {
		t.Fatalf("ReverseLabels length = %d, want %d", len(rl), len(expected))
	}
	for i, label := range rl {
		if label != expected[i] {
			t.Errorf("ReverseLabels[%d] = %q, want %q", i, label, expected[i])
		}
	}

	// Root domain
	root, _ := ParseDomain(".")
	rlRoot := root.ReverseLabels()
	if len(rlRoot) != 0 {
		t.Errorf("Root ReverseLabels length = %d, want 0", len(rlRoot))
	}
}

// ============================================================================
// NormalizeDomain
// ============================================================================

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"EXAMPLE.COM", "example.com", false},
		{"www.Example.COM.", "www.example.com", false},
		{"-invalid.com", "", true},
		{"example.com.", "example.com", false},
	}
	for _, tt := range tests {
		result, err := NormalizeDomain(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("NormalizeDomain(%q) should return error", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("NormalizeDomain(%q) error: %v", tt.input, err)
			}
			if result != tt.expected {
				t.Errorf("NormalizeDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		}
	}
}

// ============================================================================
// RemoveFQDN
// ============================================================================

func TestRemoveFQDN(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com.", "example.com"},
		{"example.com", "example.com"},
		{"www.example.com.", "www.example.com"},
		{".", ""},
	}
	for _, tt := range tests {
		result := RemoveFQDN(tt.input)
		if result != tt.expected {
			t.Errorf("RemoveFQDN(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// ============================================================================
// IPFamily.String
// ============================================================================

func TestIPFamilyString(t *testing.T) {
	tests := []struct {
		family   IPFamily
		expected string
	}{
		{IPv4, "IPv4"},
		{IPv6, "IPv6"},
		{IPFamily(99), "Unknown"},
	}
	for _, tt := range tests {
		result := tt.family.String()
		if result != tt.expected {
			t.Errorf("IPFamily(%d).String() = %q, want %q", tt.family, result, tt.expected)
		}
	}
}

// ============================================================================
// IsSubdomain edge cases
// ============================================================================

func TestIsSubdomainEdgeCases(t *testing.T) {
	// Invalid child
	result := IsSubdomain("-invalid.com", "example.com")
	if result {
		t.Error("IsSubdomain should return false for invalid child")
	}

	// Invalid parent
	result = IsSubdomain("www.example.com", "-invalid.com")
	if result {
		t.Error("IsSubdomain should return false for invalid parent")
	}

	// Both invalid
	result = IsSubdomain("-a.com", "-b.com")
	if result {
		t.Error("IsSubdomain should return false for both invalid")
	}
}

// ============================================================================
// ParseDomain wildcard at non-first position
// ============================================================================

func TestParseDomainWildcardNotFirst(t *testing.T) {
	_, err := ParseDomain("www.*.example.com")
	if err == nil {
		t.Error("ParseDomain should reject wildcard at non-first position")
	}
	if !strings.Contains(err.Error(), "wildcard") {
		t.Errorf("Error should mention wildcard, got: %v", err)
	}
}

// ============================================================================
// ParseDomain too many labels
// ============================================================================

func TestParseDomainTooManyLabels(t *testing.T) {
	// Create a domain with more than MaxLabels
	labels := make([]string, MaxLabels+2)
	for i := range labels {
		labels[i] = "a"
	}
	domain := strings.Join(labels, ".")
	_, err := ParseDomain(domain)
	if err == nil {
		t.Error("ParseDomain should reject domain with too many labels")
	}
}

// ============================================================================
// SplitDomain error case
// ============================================================================

func TestSplitDomainError(t *testing.T) {
	_, err := SplitDomain("-invalid.com")
	if err == nil {
		t.Error("SplitDomain should return error for invalid domain")
	}
}

// ============================================================================
// NormalizeIP edge cases
// ============================================================================

func TestNormalizeIPEdgeCases(t *testing.T) {
	// IPv4 that needs no change
	ip := net.ParseIP("192.168.1.1")
	result := NormalizeIP(ip)
	if !result.Equal(ip) {
		t.Error("NormalizeIP should not change valid IPv4")
	}

	// nil IP
	result = NormalizeIP(nil)
	if result != nil {
		t.Error("NormalizeIP(nil) should return nil")
	}
}

// ============================================================================
// ParseCIDRList edge case
// ============================================================================

func TestParseCIDRListWithInvalid(t *testing.T) {
	_, err := ParseCIDRList([]string{"192.168.0.0/16", "invalid-cidr"})
	if err == nil {
		t.Error("ParseCIDRList should return error for invalid CIDR")
	}
}

func TestParseCIDRListValid(t *testing.T) {
	result, err := ParseCIDRList([]string{"192.168.0.0/16", "10.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseCIDRList error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("ParseCIDRList = %d results, want 2", len(result))
	}
}
