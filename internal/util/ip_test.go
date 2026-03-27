package util

import (
	"net"
	"testing"
)

func TestIsIPv4(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"255.255.255.255", true},
		{"::1", false},
		{"2001:db8::1", false},
		{"::ffff:192.168.1.1", true}, // IPv4-mapped IPv6
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		result := IsIPv4(ip)
		if result != tc.expected {
			t.Errorf("IsIPv4(%q) = %v, want %v", tc.ip, result, tc.expected)
		}
	}
}

func TestIsIPv6(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", false},
		{"::1", true},
		{"2001:db8::1", true},
		{"fe80::1", true},
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		result := IsIPv6(ip)
		if result != tc.expected {
			t.Errorf("IsIPv6(%q) = %v, want %v", tc.ip, result, tc.expected)
		}
	}
}

func TestIPToUint32(t *testing.T) {
	tests := []struct {
		ip       string
		expected uint32
	}{
		{"192.168.1.1", 0xC0A80101},
		{"10.0.0.1", 0x0A000001},
		{"255.255.255.255", 0xFFFFFFFF},
		{"0.0.0.0", 0x00000000},
		{"::1", 0}, // IPv6 returns 0
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		result := IPToUint32(ip)
		if result != tc.expected {
			t.Errorf("IPToUint32(%q) = 0x%08X, want 0x%08X", tc.ip, result, tc.expected)
		}
	}
}

func TestUint32ToIP(t *testing.T) {
	tests := []struct {
		value    uint32
		expected string
	}{
		{0xC0A80101, "192.168.1.1"},
		{0x0A000001, "10.0.0.1"},
		{0xFFFFFFFF, "255.255.255.255"},
		{0x00000000, "0.0.0.0"},
	}

	for _, tc := range tests {
		result := Uint32ToIP(tc.value).String()
		if result != tc.expected {
			t.Errorf("Uint32ToIP(0x%08X) = %q, want %q", tc.value, result, tc.expected)
		}
	}
}

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		cidr     string
		expected bool // whether it should parse successfully
	}{
		{"192.168.1.0/24", true},
		{"10.0.0.0/8", true},
		{"2001:db8::/32", true},
		{"192.168.1.1", false},
		{"invalid", false},
		{"192.168.1.0/33", false}, // Invalid prefix
	}

	for _, tc := range tests {
		cidr, err := ParseCIDR(tc.cidr)
		if tc.expected {
			if err != nil {
				t.Errorf("ParseCIDR(%q) returned error: %v", tc.cidr, err)
			}
			if cidr == nil {
				t.Errorf("ParseCIDR(%q) returned nil", tc.cidr)
			}
		} else {
			if err == nil {
				t.Errorf("ParseCIDR(%q) should have returned error", tc.cidr)
			}
		}
	}
}

func TestCIDRContains(t *testing.T) {
	cidr, err := ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatalf("Failed to parse CIDR: %v", err)
	}

	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", true},
		{"192.168.1.255", true},
		{"192.168.2.1", false},
		{"10.0.0.1", false},
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		result := cidr.Contains(ip)
		if result != tc.expected {
			t.Errorf("CIDR(192.168.1.0/24).Contains(%q) = %v, want %v", tc.ip, result, tc.expected)
		}
	}
}

func TestCIDRList(t *testing.T) {
	list, err := ParseCIDRList([]string{"192.168.1.0/24", "10.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseCIDRList failed: %v", err)
	}

	if len(list) != 2 {
		t.Errorf("Expected 2 CIDRs, got %d", len(list))
	}

	// Test Contains
	if !list.Contains(net.ParseIP("192.168.1.1")) {
		t.Error("List should contain 192.168.1.1")
	}
	if !list.Contains(net.ParseIP("10.0.0.1")) {
		t.Error("List should contain 10.0.0.1")
	}
	if list.Contains(net.ParseIP("172.16.0.1")) {
		t.Error("List should not contain 172.16.0.1")
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"::1", true},
		{"fc00::1", true},
		{"fe80::1", true},
		{"2001:db8::1", false},
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		result := IsPrivateIP(ip)
		if result != tc.expected {
			t.Errorf("IsPrivateIP(%q) = %v, want %v", tc.ip, result, tc.expected)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.53", true},
		{"192.168.1.1", false},
		{"::1", true},
		{"::ffff:127.0.0.1", true},
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		result := IsLoopback(ip)
		if result != tc.expected {
			t.Errorf("IsLoopback(%q) = %v, want %v", tc.ip, result, tc.expected)
		}
	}
}

func TestNormalizeIP(t *testing.T) {
	// Test IPv4-mapped IPv6
	ip := net.ParseIP("::ffff:192.168.1.1")
	normalized := NormalizeIP(ip)
	if !IsIPv4(normalized) {
		t.Error("IPv4-mapped IPv6 should be normalized to IPv4")
	}
	if normalized.String() != "192.168.1.1" {
		t.Errorf("Expected 192.168.1.1, got %s", normalized.String())
	}

	// Test nil
	normalized = NormalizeIP(nil)
	if normalized != nil {
		t.Error("Normalizing nil should return nil")
	}
}

func TestReverseDNS(t *testing.T) {
	tests := []struct {
		ip       string
		expected string
	}{
		{"192.168.1.1", "1.1.168.192.in-addr.arpa"},
		{"10.0.0.1", "1.0.0.10.in-addr.arpa"},
		{"::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"},
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		result := ReverseDNS(ip)
		if result != tc.expected {
			t.Errorf("ReverseDNS(%q) = %q, want %q", tc.ip, result, tc.expected)
		}
	}
}

func TestMaskIP(t *testing.T) {
	ip := net.ParseIP("192.168.1.123")
	masked := MaskIP(ip, 24)

	if masked.String() != "192.168.1.0" {
		t.Errorf("MaskIP(192.168.1.123, 24) = %s, want 192.168.1.0", masked.String())
	}
}

// TestParseIP tests the ParseIP function
func TestParseIP(t *testing.T) {
	tests := []struct {
		input    string
		isNil    bool
	}{
		{"192.168.1.1", false},
		{"::1", false},
		{"invalid", true},
		{"", true},
	}

	for _, tc := range tests {
		result := ParseIP(tc.input)
		if (result == nil) != tc.isNil {
			t.Errorf("ParseIP(%q) nil = %v, want %v", tc.input, result == nil, tc.isNil)
		}
	}
}

// TestIPToBytes tests the IPToBytes function
func TestIPToBytes(t *testing.T) {
	// IPv4
	ip4 := net.ParseIP("192.168.1.1")
	bytes4 := IPToBytes(ip4)
	if len(bytes4) != 4 {
		t.Errorf("IPv4 bytes length = %d, want 4", len(bytes4))
	}

	// IPv6
	ip6 := net.ParseIP("2001:db8::1")
	bytes6 := IPToBytes(ip6)
	if len(bytes6) != 16 {
		t.Errorf("IPv6 bytes length = %d, want 16", len(bytes6))
	}
}

// TestIPToString tests the IPToString function
func TestIPToString(t *testing.T) {
	tests := []struct {
		ip       net.IP
		expected string
	}{
		{net.ParseIP("192.168.1.1"), "192.168.1.1"},
		{net.ParseIP("::1"), "::1"},
		{nil, ""},
	}

	for _, tc := range tests {
		result := IPToString(tc.ip)
		if result != tc.expected {
			t.Errorf("IPToString(%v) = %q, want %q", tc.ip, result, tc.expected)
		}
	}
}

// TestIPRangeContains tests the IPRange.Contains method
func TestIPRangeContains(t *testing.T) {
	// IPv4 range
	r4 := &IPRange{
		Start: net.ParseIP("192.168.1.0"),
		End:   net.ParseIP("192.168.1.255"),
	}

	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", true},
		{"192.168.1.128", true},
		{"192.168.1.255", true},
		{"192.168.2.1", false},
		{"10.0.0.1", false},
		{"::1", false}, // IPv6 in IPv4 range
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		result := r4.Contains(ip)
		if result != tc.expected {
			t.Errorf("IPRange.Contains(%q) = %v, want %v", tc.ip, result, tc.expected)
		}
	}

	// IPv6 range
	r6 := &IPRange{
		Start: net.ParseIP("2001:db8::1"),
		End:   net.ParseIP("2001:db8::ffff"),
	}

	if !r6.Contains(net.ParseIP("2001:db8::100")) {
		t.Error("IPv6 range should contain address in range")
	}
	if r6.Contains(net.ParseIP("192.168.1.1")) {
		t.Error("IPv6 range should not contain IPv4 address")
	}
}

// TestBytesCompare tests the bytesCompare function
func TestBytesCompare(t *testing.T) {
	tests := []struct {
		a, b     []byte
		expected int
	}{
		{[]byte{1, 2, 3}, []byte{1, 2, 3}, 0},
		{[]byte{1, 2, 3}, []byte{1, 2, 4}, -1},
		{[]byte{1, 2, 4}, []byte{1, 2, 3}, 1},
		{[]byte{1, 2}, []byte{1, 2, 3}, -1},
		{[]byte{1, 2, 3}, []byte{1, 2}, 1},
	}

	for _, tc := range tests {
		result := bytesCompare(tc.a, tc.b)
		if result != tc.expected {
			t.Errorf("bytesCompare(%v, %v) = %d, want %d", tc.a, tc.b, result, tc.expected)
		}
	}
}

// TestCIDRString tests the CIDR.String method
func TestCIDRString(t *testing.T) {
	cidr, err := ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR error: %v", err)
	}

	result := cidr.String()
	if result != "192.168.1.0/24" {
		t.Errorf("CIDR.String() = %q, want %q", result, "192.168.1.0/24")
	}
}

// TestIsMulticast tests the IsMulticast function
func TestIsMulticast(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"224.0.0.1", true},
		{"239.255.255.255", true},
		{"192.168.1.1", false},
		{"ff00::1", true},
		{"ff02::1", true},
		{"2001:db8::1", false},
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		result := IsMulticast(ip)
		if result != tc.expected {
			t.Errorf("IsMulticast(%q) = %v, want %v", tc.ip, result, tc.expected)
		}
	}
}

// TestGetIPFamily tests the GetIPFamily function
func TestGetIPFamily(t *testing.T) {
	tests := []struct {
		ip       string
		expected IPFamily
	}{
		{"192.168.1.1", IPv4},
		{"::1", IPv6},
		{"2001:db8::1", IPv6},
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		result := GetIPFamily(ip)
		if result != tc.expected {
			t.Errorf("GetIPFamily(%q) = %d, want %d", tc.ip, result, tc.expected)
		}
	}
}

// TestNewPooledBufferSized tests NewPooledBufferSized
func TestNewPooledBufferSized(t *testing.T) {
	buf := NewPooledBufferSized(1024)
	if buf == nil {
		t.Error("NewPooledBufferSized should not return nil")
	}
	if buf.Cap() < 1024 {
		t.Errorf("Buffer cap = %d, want at least 1024", buf.Cap())
	}
	buf.Release()
}
