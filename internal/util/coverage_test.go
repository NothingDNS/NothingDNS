package util

// coverage_test.go adds tests for low-coverage functions in the util package.

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

// ============================================================================
// Domain.Equal - nil/empty labels edge case (83.3% -> higher)
// ============================================================================

func TestDomainEqualEdgeCases(t *testing.T) {
	// Both empty label domains
	root1, _ := ParseDomain(".")
	root2, _ := ParseDomain(".")
	if !root1.Equal(root2) {
		t.Error("Two root domains should be equal")
	}

	// Different number of labels
	d1, _ := ParseDomain("example.com")
	d2, _ := ParseDomain("www.example.com")
	if d1.Equal(d2) {
		t.Error("Domains with different label counts should not be equal")
	}
	if d2.Equal(d1) {
		t.Error("Domains with different label counts should not be equal (reversed)")
	}

	// Same number of labels, different content
	d3, _ := ParseDomain("example.org")
	if d1.Equal(d3) {
		t.Error("Different domains should not be equal")
	}
}

// ============================================================================
// UnescapeLabel - additional edge cases (81.0% -> higher)
// ============================================================================

func TestUnescapeLabelEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "incomplete decimal escape at end",
			input:   "\\12",
			wantErr: true,
		},
		{
			name:    "incomplete decimal escape at end 2",
			input:   "\\1",
			wantErr: true,
		},
		{
			name:  "backslash followed by unknown char",
			input: "\\z",
			want:  "\\z",
		},
		{
			name:  "backslash at very end of string",
			input: "hello\\",
			want:  "hello\\",
		},
		{
			name:  "valid decimal escape",
			input: "\\065",
			want:  "A",
		},
		{
			name:  "mixed escapes",
			input: "a\\.b\\\\c\\\"d\\065e",
			want:  "a.b\\c\"dAe",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnescapeLabel(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("UnescapeLabel(%q) expected error, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("UnescapeLabel(%q) unexpected error: %v", tt.input, err)
				}
				if got != tt.want {
					t.Errorf("UnescapeLabel(%q) = %q, want %q", tt.input, got, tt.want)
				}
			}
		})
	}
}

// ============================================================================
// NormalizeIP - pure IPv6 path (80.0% -> higher)
// ============================================================================

func TestNormalizeIPPureIPv6(t *testing.T) {
	// Pure IPv6 address (not IPv4-mapped) should go through ip.To16() path
	ip := net.ParseIP("2001:db8::1")
	result := NormalizeIP(ip)
	if result == nil {
		t.Fatal("NormalizeIP should not return nil for valid IPv6")
	}
	if !result.Equal(ip) {
		t.Errorf("NormalizeIP(%s) = %s, want same IPv6", ip, result)
	}
	if len(result) != 16 {
		t.Errorf("Normalized IPv6 should be 16 bytes, got %d", len(result))
	}
}

// ============================================================================
// ReverseDNS - v6 nil path (90.0% -> higher)
// ============================================================================

func TestReverseDNSEdgeCases(t *testing.T) {
	// Test with an IPv6 address to exercise the v6 path more thoroughly
	ip := net.ParseIP("2001:db8::1")
	result := ReverseDNS(ip)
	if !strings.HasSuffix(result, ".ip6.arpa") {
		t.Errorf("IPv6 reverse DNS should end with .ip6.arpa, got: %s", result)
	}
}

// ============================================================================
// Logger - log method with extra fields and JSON marshal path
// ============================================================================

func TestLoggerLogWithExtraFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, TextFormat, &buf)

	// Call log directly with additional fields
	logger.log(INFO, "msg1", Fields{"extra_key": "extra_val"})
	output := buf.String()
	if !strings.Contains(output, "extra_key=extra_val") {
		t.Errorf("Expected output to contain extra_key=extra_val, got: %s", output)
	}
}

func TestLoggerLogJSONWithExtraFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, JSONFormat, &buf)

	// Call log directly with extra fields in JSON format
	logger.log(INFO, "json_msg", Fields{"f1": "v1"})
	output := buf.String()
	if !strings.Contains(output, `"f1":"v1"`) {
		t.Errorf("Expected JSON output with f1 field, got: %s", output)
	}
}

func TestLoggerLogFilteredLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(ERROR, TextFormat, &buf)

	// These should be filtered by level check
	logger.log(DEBUG, "debug msg")
	logger.log(INFO, "info msg")
	logger.log(WARN, "warn msg")

	if buf.Len() > 0 {
		t.Errorf("Messages below ERROR should be filtered, got output: %s", buf.String())
	}
}

func TestLoggerWithFieldChained(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, TextFormat, &buf)

	// Chain WithField calls to exercise the field copy path
	logger2 := logger.WithField("k1", "v1")
	logger3 := logger2.WithField("k2", "v2")
	logger3.Info("chained")
	output := buf.String()

	if !strings.Contains(output, "k1=v1") {
		t.Errorf("Expected k1=v1 in output, got: %s", output)
	}
	if !strings.Contains(output, "k2=v2") {
		t.Errorf("Expected k2=v2 in output, got: %s", output)
	}
}

func TestLoggerWithFieldsMerge(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, TextFormat, &buf)

	// Logger with existing field, then WithFields to merge
	logger2 := logger.WithField("existing", "val")
	logger3 := logger2.WithFields(Fields{"new1": "a", "new2": "b"})
	logger3.Info("merged")
	output := buf.String()

	if !strings.Contains(output, "existing=val") {
		t.Errorf("Expected existing=val in output, got: %s", output)
	}
	if !strings.Contains(output, "new1=a") {
		t.Errorf("Expected new1=a in output, got: %s", output)
	}
	if !strings.Contains(output, "new2=b") {
		t.Errorf("Expected new2=b in output, got: %s", output)
	}
}

// ============================================================================
// SignalHandler - Start, Stop, Done, Wait
// ============================================================================

func TestSignalHandlerStartStop(t *testing.T) {
	s := NewSignalHandler()

	// Start the signal listener
	s.Start()

	// Stop should cancel context and wait for goroutine
	s.Stop()

	if !s.IsShutdown() {
		t.Error("SignalHandler should be in shutdown state after Stop()")
	}
}

func TestSignalHandlerDone(t *testing.T) {
	s := NewSignalHandler()

	// Done should return a channel that is not closed initially
	select {
	case <-s.Done():
		t.Error("Done channel should not be closed initially")
	default:
		// Expected
	}

	// After cancel, Done should be closed
	s.cancel()

	select {
	case <-s.Done():
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Error("Done channel should be closed after cancel")
	}
}

func TestSignalHandlerWait(t *testing.T) {
	s := NewSignalHandler()

	// Wait blocks until shutdown. Start a goroutine to cancel.
	go func() {
		time.Sleep(50 * time.Millisecond)
		s.cancel()
	}()

	done := make(chan struct{})
	go func() {
		s.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Expected - Wait returned after cancel
	case <-time.After(500 * time.Millisecond):
		t.Error("Wait should return after context is cancelled")
	}
}

func TestSignalHandlerGracefulShutdownTimeout(t *testing.T) {
	s := NewSignalHandler()

	// Register a shutdown function that waits longer than the timeout
	s.RegisterShutdown(func() error {
		time.Sleep(2 * time.Second)
		return nil
	})

	// Use a very short timeout - but performShutdown is called first,
	// which cancels the context. The wg.Wait() will take too long.
	// The select in GracefulShutdown should hit the timeout path.
	err := s.GracefulShutdown(50 * time.Millisecond)
	if err == nil {
		t.Error("GracefulShutdown should return error on timeout")
	}
	if err != context.DeadlineExceeded {
		t.Errorf("Expected context.DeadlineExceeded, got: %v", err)
	}
}

func TestSignalHandlerPerformShutdownNilFunc(t *testing.T) {
	s := NewSignalHandler()

	// Register a nil shutdown function
	s.RegisterShutdown(nil)
	s.RegisterShutdown(func() error { return nil })

	// Should not panic with nil function
	s.performShutdown()

	if !s.IsShutdown() {
		t.Error("Should be in shutdown state after performShutdown")
	}
}

func TestSignalHandlerPerformReloadNoFunc(t *testing.T) {
	s := NewSignalHandler()

	// Don't set a reload function - should log warning but not panic
	s.performReload()
}

func TestSignalHandlerPerformShutdownError(t *testing.T) {
	s := NewSignalHandler()

	var called int32
	s.RegisterShutdown(func() error {
		atomic.AddInt32(&called, 1)
		return context.Canceled // any non-nil error
	})
	s.RegisterShutdown(func() error {
		atomic.AddInt32(&called, 1)
		return nil
	})

	s.performShutdown()

	if atomic.LoadInt32(&called) != 2 {
		t.Errorf("Expected 2 shutdown functions called, got %d", atomic.LoadInt32(&called))
	}
}

// ============================================================================
// PooledBuffer - Grow negative panic (85.7% -> higher)
// ============================================================================

func TestPooledBufferGrowNegative(t *testing.T) {
	p := NewPooledBuffer()
	defer p.Release()
	err := p.Grow(-1)
	if err == nil {
		t.Error("Grow(-1) should return an error")
	}
	if !strings.Contains(err.Error(), "negative") {
		t.Errorf("Expected error with 'negative', got: %v", err)
	}
}

func TestPooledBufferGrowNoOp(t *testing.T) {
	p := NewPooledBuffer()
	defer p.Release()

	// Write a small amount
	p.WriteString("hi")
	initialCap := p.Cap()

	// Grow(0) should be a no-op
	p.Grow(0)
	if p.Cap() != initialCap {
		t.Errorf("Grow(0) should not change capacity")
	}

	// Grow with n that fits in remaining capacity should be a no-op
	remaining := p.Cap() - p.Len()
	if remaining > 0 {
		p.Grow(remaining - 1)
		if p.Cap() != initialCap {
			t.Errorf("Grow within remaining capacity should not reallocate")
		}
	}
}

func TestPooledBufferReleaseTwice(t *testing.T) {
	p := NewPooledBuffer()
	p.Release()
	// Second release should be safe (buf is nil after first release)
	p.Release()
}

// ============================================================================
// Domain - ParseDomain domain too long
// ============================================================================

func TestParseDomainTooLong(t *testing.T) {
	// Create a domain name longer than MaxNameLength bytes
	// Each label is 63 chars (max), joined with dots
	label := strings.Repeat("a", MaxLabelLength)
	labels := make([]string, 5)
	for i := range labels {
		labels[i] = label
	}
	longDomain := strings.Join(labels, ".")
	if len(longDomain) <= MaxNameLength {
		t.Fatalf("Test domain too short: %d bytes, need > %d", len(longDomain), MaxNameLength)
	}

	_, err := ParseDomain(longDomain)
	if err == nil {
		t.Error("ParseDomain should reject domain exceeding MaxNameLength")
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Errorf("Error should mention 'too long', got: %v", err)
	}
}

// ============================================================================
// Label.IsValid - 64-char label (too long)
// ============================================================================

func TestLabelIsValidTooLong(t *testing.T) {
	label := Label(strings.Repeat("a", MaxLabelLength+1))
	if label.IsValid() {
		t.Error("Label with 64 characters should be invalid (max is 63)")
	}
}

// ============================================================================
// EscapeLabel - character 0x7F (DEL, high boundary)
// ============================================================================

func TestEscapeLabelHighByte(t *testing.T) {
	result := EscapeLabel("\x7f")
	if result != "\\127" {
		t.Errorf("EscapeLabel(0x7F) = %q, want \\127", result)
	}
}
