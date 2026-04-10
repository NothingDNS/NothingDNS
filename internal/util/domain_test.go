package util

import (
	"testing"
)

func TestLabelIsValid(t *testing.T) {
	tests := []struct {
		label    string
		expected bool
	}{
		{"www", true},
		{"example", true},
		{"test-123", true},
		{"_dmarc", true},     // Underscore for service records
		{"_domainkey", true}, // Underscore for DKIM
		{"-invalid", false},  // Cannot start with hyphen
		{"invalid-", false},  // Cannot end with hyphen
		{"", false},          // Empty label
		{"a.b", false},       // Cannot contain dot
	}

	for _, tc := range tests {
		result := Label(tc.label).IsValid()
		if result != tc.expected {
			t.Errorf("Label(%q).IsValid() = %v, want %v", tc.label, result, tc.expected)
		}
	}
}

func TestParseDomain(t *testing.T) {
	tests := []struct {
		domain  string
		wantErr bool
	}{
		{"example.com", false},
		{"www.example.com", false},
		{"example.com.", false}, // FQDN
		{"*", false},            // Wildcard
		{"*.example.com", false},
		{"a.b.c.d.e.f.example.com", false},
		{"", false},            // Root domain is valid
		{".", false},           // Root domain with trailing dot is valid
		{"-invalid.com", true}, // Label cannot start with hyphen
		{"invalid-.com", true}, // Label cannot end with hyphen
		{"test..example.com", true},
	}

	for _, tc := range tests {
		d, err := ParseDomain(tc.domain)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseDomain(%q) should return error", tc.domain)
			}
		} else {
			if err != nil {
				t.Errorf("ParseDomain(%q) returned error: %v", tc.domain, err)
			}
			if d == nil {
				t.Errorf("ParseDomain(%q) returned nil domain", tc.domain)
			}
		}
	}
}

func TestDomainNormalize(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"EXAMPLE.COM", "example.com"},
		{"WWW.Example.COM", "www.example.com"},
		{"example.com.", "example.com"},
		{"*.Example.COM", "*.example.com"},
	}

	for _, tc := range tests {
		d, err := ParseDomain(tc.input)
		if err != nil {
			t.Fatalf("ParseDomain(%q) failed: %v", tc.input, err)
		}
		result := d.Normalize()
		if result != tc.expected {
			t.Errorf("Normalize(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestDomainIsWildcard(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		{"*.example.com", true},
		{"*.com", true},
		{"*", true},
		{"www.example.com", false},
		{"example.com", false},
	}

	for _, tc := range tests {
		d, err := ParseDomain(tc.domain)
		if err != nil {
			t.Fatalf("ParseDomain(%q) failed: %v", tc.domain, err)
		}
		result := d.IsWildcard()
		if result != tc.expected {
			t.Errorf("IsWildcard(%q) = %v, want %v", tc.domain, result, tc.expected)
		}
	}
}

func TestDomainHasParent(t *testing.T) {
	child, _ := ParseDomain("www.example.com")
	parent, _ := ParseDomain("example.com")

	if !child.HasParent(parent) {
		t.Error("www.example.com should have parent example.com")
	}

	if parent.HasParent(child) {
		t.Error("example.com should not have parent www.example.com")
	}
}

func TestDomainEqual(t *testing.T) {
	d1, _ := ParseDomain("Example.COM")
	d2, _ := ParseDomain("example.com")
	d3, _ := ParseDomain("example.org")

	if !d1.Equal(d2) {
		t.Error("Example.COM should equal example.com")
	}

	if d1.Equal(d3) {
		t.Error("Example.COM should not equal example.org")
	}
}

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"-invalid.com", false},
		{"", true}, // Root domain is valid
		{"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z", true},
	}

	for _, tc := range tests {
		result := IsValidDomain(tc.domain)
		if result != tc.expected {
			t.Errorf("IsValidDomain(%q) = %v, want %v", tc.domain, result, tc.expected)
		}
	}
}

func TestIsFQDN(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		{"example.com", false},
		{"example.com.", true},
		{"www.example.com.", true},
	}

	for _, tc := range tests {
		result := IsFQDN(tc.domain)
		if result != tc.expected {
			t.Errorf("IsFQDN(%q) = %v, want %v", tc.domain, result, tc.expected)
		}
	}
}

func TestEnsureFQDN(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com."},
		{"example.com.", "example.com."},
	}

	for _, tc := range tests {
		result := EnsureFQDN(tc.input)
		if result != tc.expected {
			t.Errorf("EnsureFQDN(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestSplitDomain(t *testing.T) {
	labels, err := SplitDomain("www.example.com")
	if err != nil {
		t.Fatalf("SplitDomain failed: %v", err)
	}

	if len(labels) != 3 {
		t.Errorf("Expected 3 labels, got %d", len(labels))
	}

	expected := []string{"www", "example", "com"}
	for i, label := range labels {
		if label != expected[i] {
			t.Errorf("Label[%d] = %q, want %q", i, label, expected[i])
		}
	}
}

func TestJoinLabels(t *testing.T) {
	tests := []struct {
		labels   []string
		fqdn     bool
		expected string
	}{
		{[]string{"www", "example", "com"}, false, "www.example.com"},
		{[]string{"www", "example", "com"}, true, "www.example.com."},
		{[]string{}, false, ""},
		{[]string{}, true, ""},
	}

	for _, tc := range tests {
		result := JoinLabels(tc.labels, tc.fqdn)
		if result != tc.expected {
			t.Errorf("JoinLabels(%v, %v) = %q, want %q", tc.labels, tc.fqdn, result, tc.expected)
		}
	}
}

func TestCountLabels(t *testing.T) {
	tests := []struct {
		domain   string
		expected int
	}{
		{"example.com", 2},
		{"www.example.com", 3},
		{"a.b.c.d.e", 5},
		{"single", 1},
		{"", 0},
		{"example.com.", 2},
	}

	for _, tc := range tests {
		result := CountLabels(tc.domain)
		if result != tc.expected {
			t.Errorf("CountLabels(%q) = %d, want %d", tc.domain, result, tc.expected)
		}
	}
}

func TestIsSubdomain(t *testing.T) {
	tests := []struct {
		child    string
		parent   string
		expected bool
	}{
		{"www.example.com", "example.com", true},
		{"a.b.c.example.com", "example.com", true},
		{"example.com", "example.com", true},
		{"example.org", "example.com", false},
		{"evil-example.com", "example.com", false},
	}

	for _, tc := range tests {
		result := IsSubdomain(tc.child, tc.parent)
		if result != tc.expected {
			t.Errorf("IsSubdomain(%q, %q) = %v, want %v", tc.child, tc.parent, result, tc.expected)
		}
	}
}

func TestEscapeUnescapeLabel(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"dot.here", "dot\\.here"},
		{"back\\slash", "back\\\\slash"},
		{"quote\"here", "quote\\\"here"},
		{"\x00\x01\x02", "\\000\\001\\002"},
	}

	for _, tc := range tests {
		escaped := EscapeLabel(tc.input)
		if escaped != tc.expected {
			t.Errorf("EscapeLabel(%q) = %q, want %q", tc.input, escaped, tc.expected)
		}

		unescaped, err := UnescapeLabel(escaped)
		if err != nil {
			t.Errorf("UnescapeLabel(%q) returned error: %v", escaped, err)
			continue
		}
		if unescaped != tc.input {
			t.Errorf("UnescapeLabel(%q) = %q, want %q", escaped, unescaped, tc.input)
		}
	}
}

func TestLongestCommonSuffix(t *testing.T) {
	tests := []struct {
		a        string
		b        string
		expected int
	}{
		{"www.example.com", "mail.example.com", 2}, // example.com
		{"a.b.c.d", "x.y.c.d", 2},                  // c.d
		{"example.com", "example.org", 0},
		{"same.domain.com", "same.domain.com", 3},
	}

	for _, tc := range tests {
		result := LongestCommonSuffix(tc.a, tc.b)
		if result != tc.expected {
			t.Errorf("LongestCommonSuffix(%q, %q) = %d, want %d", tc.a, tc.b, result, tc.expected)
		}
	}
}
