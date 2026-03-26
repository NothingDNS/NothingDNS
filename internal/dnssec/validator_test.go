package dnssec

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// mockResolver is a test resolver that returns predefined responses.
type mockResolver struct {
	responses map[string]*protocol.Message
}

func (m *mockResolver) Query(ctx context.Context, name string, qtype uint16) (*protocol.Message, error) {
	key := name + "|" + strconv.Itoa(int(qtype))
	if resp, ok := m.responses[key]; ok {
		return resp, nil
	}
	// Return empty response for unknown queries
	return protocol.NewMessage(protocol.Header{
		ID:      1,
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 1,
	}), nil
}

func TestValidationResultString(t *testing.T) {
	tests := []struct {
		result   ValidationResult
		expected string
	}{
		{ValidationSecure, "SECURE"},
		{ValidationInsecure, "INSECURE"},
		{ValidationBogus, "BOGUS"},
		{ValidationIndeterminate, "INDETERMINATE"},
		{ValidationResult(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.result.String(); got != tt.expected {
				t.Errorf("ValidationResult.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestDefaultValidatorConfig(t *testing.T) {
	cfg := DefaultValidatorConfig()

	if !cfg.Enabled {
		t.Error("Expected Enabled to be true")
	}
	if cfg.RequireDNSSEC {
		t.Error("Expected RequireDNSSEC to be false")
	}
	if cfg.IgnoreTime {
		t.Error("Expected IgnoreTime to be false")
	}
	if cfg.MaxDelegationDepth != 20 {
		t.Errorf("Expected MaxDelegationDepth to be 20, got %d", cfg.MaxDelegationDepth)
	}
	if cfg.ClockSkew != 5*time.Minute {
		t.Errorf("Expected ClockSkew to be 5 minutes, got %v", cfg.ClockSkew)
	}
}

func TestNewValidator(t *testing.T) {
	// Test with nil anchors (should use built-in)
	v := NewValidator(DefaultValidatorConfig(), nil, nil)
	if v == nil {
		t.Fatal("NewValidator returned nil")
	}
	if v.trustAnchors == nil {
		t.Error("trustAnchors should not be nil")
	}

	// Test with custom anchors
	anchors := NewTrustAnchorStore()
	v2 := NewValidator(DefaultValidatorConfig(), anchors, nil)
	if v2.trustAnchors != anchors {
		t.Error("trustAnchors should use provided store")
	}
}

func TestValidatorValidateResponseDisabled(t *testing.T) {
	config := ValidatorConfig{Enabled: false}
	v := NewValidator(config, nil, nil)

	result, err := v.ValidateResponse(context.Background(), nil, "example.com.")
	if err != nil {
		t.Fatalf("ValidateResponse failed: %v", err)
	}
	if result != ValidationInsecure {
		t.Errorf("Expected INSECURE when disabled, got %s", result)
	}
}

func TestValidatorValidateResponseNilMessage(t *testing.T) {
	config := ValidatorConfig{Enabled: true}
	v := NewValidator(config, nil, nil)

	result, err := v.ValidateResponse(context.Background(), nil, "example.com.")
	if err == nil {
		t.Error("Expected error for nil message")
	}
	if result != ValidationBogus {
		t.Errorf("Expected BOGUS for nil message, got %s", result)
	}
}

func TestHasSignature(t *testing.T) {
	tests := []struct {
		name     string
		msg      *protocol.Message
		expected bool
	}{
		{
			name:     "empty message",
			msg:      &protocol.Message{},
			expected: false,
		},
		{
			name: "with RRSIG in answers",
			msg: &protocol.Message{
				Answers: []*protocol.ResourceRecord{
					{Type: protocol.TypeRRSIG},
				},
			},
			expected: true,
		},
		{
			name: "with NSEC in authorities",
			msg: &protocol.Message{
				Authorities: []*protocol.ResourceRecord{
					{Type: protocol.TypeNSEC},
				},
			},
			expected: true,
		},
		{
			name: "with NSEC3 in authorities",
			msg: &protocol.Message{
				Authorities: []*protocol.ResourceRecord{
					{Type: protocol.TypeNSEC3},
				},
			},
			expected: true,
		},
		{
			name: "no signatures",
			msg: &protocol.Message{
				Answers: []*protocol.ResourceRecord{
					{Type: protocol.TypeA},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasSignature(tt.msg)
			if result != tt.expected {
				t.Errorf("HasSignature() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestExtractRRSIGs(t *testing.T) {
	msg := &protocol.Message{
		Answers: []*protocol.ResourceRecord{
			{
				Type: protocol.TypeA,
				Data: &protocol.RDataA{},
			},
			{
				Type: protocol.TypeRRSIG,
				Data: &protocol.RDataRRSIG{TypeCovered: protocol.TypeA},
			},
			{
				Type: protocol.TypeRRSIG,
				Data: &protocol.RDataRRSIG{TypeCovered: protocol.TypeAAAA},
			},
		},
	}

	rrsigs := ExtractRRSIGs(msg, protocol.TypeA)
	if len(rrsigs) != 1 {
		t.Errorf("Expected 1 RRSIG for TypeA, got %d", len(rrsigs))
	}

	rrsigs = ExtractRRSIGs(msg, protocol.TypeAAAA)
	if len(rrsigs) != 1 {
		t.Errorf("Expected 1 RRSIG for TypeAAAA, got %d", len(rrsigs))
	}

	rrsigs = ExtractRRSIGs(msg, protocol.TypeMX)
	if len(rrsigs) != 0 {
		t.Errorf("Expected 0 RRSIG for TypeMX, got %d", len(rrsigs))
	}
}

func TestValidateTrustAnchor(t *testing.T) {
	// Create a trust anchor
	anchor := &TrustAnchor{
		Zone:       ".",
		KeyTag:     20326,
		Algorithm:  protocol.AlgorithmRSASHA256,
		DigestType: 2,
		Digest:     []byte{0x01, 0x02, 0x03, 0x04},
		ValidFrom:  time.Now().Add(-time.Hour),
	}

	// Create a matching DNSKEY
	dnskey := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmRSASHA256,
		PublicKey: []byte{0xAA, 0xBB, 0xCC},
	}

	// Calculate actual key tag
	tag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)
	anchor.KeyTag = tag // Update anchor with correct tag

	// Parse a test name for the resource record
	rootName, _ := protocol.ParseName(".")

	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	tests := []struct {
		name    string
		anchor  *TrustAnchor
		keys    []*protocol.ResourceRecord
		valid   bool
	}{
		{
			name:   "matching anchor",
			anchor: anchor,
			keys: []*protocol.ResourceRecord{
				{Name: rootName, Data: dnskey},
			},
			valid: false, // Will be false because digest won't match
		},
		{
			name:   "empty keys",
			anchor: anchor,
			keys:   []*protocol.ResourceRecord{},
			valid:  false,
		},
		{
			name:   "wrong type",
			anchor: anchor,
			keys: []*protocol.ResourceRecord{
				{Name: rootName, Data: &protocol.RDataA{}},
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.validateTrustAnchor(tt.anchor, tt.keys)
			if result != tt.valid {
				t.Errorf("validateTrustAnchor() = %v, want %v", result, tt.valid)
			}
		})
	}
}

func TestNameInRange(t *testing.T) {
	tests := []struct {
		name     string
		owner    string
		next     string
		query    string
		expected bool
	}{
		{
			name:     "name in range",
			query:    "b.example.com.",
			owner:    "a.example.com.",
			next:     "c.example.com.",
			expected: true,
		},
		{
			name:     "name before owner",
			query:    "a.example.com.",
			owner:    "b.example.com.",
			next:     "c.example.com.",
			expected: false,
		},
		{
			name:     "name after next",
			query:    "d.example.com.",
			owner:    "a.example.com.",
			next:     "c.example.com.",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := nameInRange(tt.query, tt.owner, tt.next)
			if result != tt.expected {
				t.Errorf("nameInRange() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGroupRecordsByRRSet(t *testing.T) {
	name1, _ := protocol.ParseName("example.com.")
	name2, _ := protocol.ParseName("www.example.com.")

	records := []*protocol.ResourceRecord{
		{Name: name1, Type: protocol.TypeA},
		{Name: name1, Type: protocol.TypeA},
		{Name: name1, Type: protocol.TypeAAAA},
		{Name: name2, Type: protocol.TypeA},
	}

	groups := groupRecordsByRRSet(records)

	// Should have 3 groups: example.com.|A, example.com.|AAAA, www.example.com.|A
	if len(groups) != 3 {
		t.Errorf("Expected 3 groups, got %d", len(groups))
	}
}
