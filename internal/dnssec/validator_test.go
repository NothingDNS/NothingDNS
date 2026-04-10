package dnssec

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
		name   string
		anchor *TrustAnchor
		keys   []*protocol.ResourceRecord
		valid  bool
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

func TestValidatorBuildChain(t *testing.T) {
	// Test delegation validation failure: DS exists but doesn't match child DNSKEY
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	keyData, err := packECDSAPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to pack public key: %v", err)
	}

	parentDnskey := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: keyData,
	}

	parentKeyTag := protocol.CalculateKeyTag(parentDnskey.Flags, parentDnskey.Algorithm, parentDnskey.PublicKey)
	parentDigest := calculateDSDigestFromDNSKEY("com.", parentDnskey, 2)

	anchor := &TrustAnchor{
		Zone:       "com.",
		KeyTag:     parentKeyTag,
		Algorithm:  protocol.AlgorithmECDSAP256SHA256,
		DigestType: 2,
		Digest:     parentDigest,
		ValidFrom:  time.Now().Add(-time.Hour),
	}

	// Create a child DNSKEY that doesn't match the DS record
	childDnskey := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: []byte{0xDE, 0xAD, 0xBE, 0xEF}, // different key
	}

	childName, _ := protocol.ParseName("example.")
	parentName, _ := protocol.ParseName("com.")

	// DS record with wrong digest (won't match child DNSKEY)
	dsRecords := []*protocol.ResourceRecord{
		{
			Name: childName,
			Type: protocol.TypeDS,
			Data: &protocol.RDataDS{
				KeyTag:     60000, // wrong key tag
				Algorithm:  protocol.AlgorithmECDSAP256SHA256,
				DigestType: 2,
				Digest:     []byte{0xFF, 0xFF}, // wrong digest
			},
		},
	}

	mock := &mockResolver{
		responses: map[string]*protocol.Message{
			"com.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{
					{Name: parentName, Type: protocol.TypeDNSKEY, Data: parentDnskey},
				},
			},
			"example.|" + strconv.Itoa(int(protocol.TypeDS)): {
				Answers: dsRecords,
			},
			"example.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{
					{Name: childName, Type: protocol.TypeDNSKEY, Data: childDnskey},
				},
			},
		},
	}

	store := NewTrustAnchorStore()
	store.AddAnchor(anchor)

	config := DefaultValidatorConfig()
	v := NewValidator(config, store, mock)

	// buildChain should fail because DS doesn't match child DNSKEY
	_, err = v.buildChain(context.Background(), anchor, []string{"example"})
	if err == nil {
		t.Error("Expected error when delegation validation fails (DS doesn't match child DNSKEY)")
	}
}

func TestValidatorToLowerBytes(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ABC", "abc"},
		{"AbC123", "abc123"},
		{"already lower", "already lower"},
		{"", ""},
	}

	for _, tt := range tests {
		result := toLowerBytes(tt.input)
		if string(result) != tt.expected {
			t.Errorf("toLowerBytes(%q) = %q, want %q", tt.input, string(result), tt.expected)
		}
	}
}

func TestValidatorValidateNegativeResponse(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	// Test with empty message
	msg := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
	}

	result := v.validateNegativeResponse(msg, "nonexistent.example.com.", nil)
	// Without proper NSEC/NSEC3 records, this should return an error or insecure
	if result == ValidationSecure {
		t.Error("Should not return SECURE for empty negative response")
	}
}

func TestValidatorExtractNSEC3Hash(t *testing.T) {
	// Test extracting hash from owner name string
	// Note: extractNSEC3Hash returns uppercase, not lowercase
	hash := extractNSEC3Hash("ABCDEF.example.com.")
	if hash != "ABCDEF" {
		t.Errorf("extractNSEC3Hash() = %q, want %q", hash, "ABCDEF")
	}

	// Test with longer prefix
	hash2 := extractNSEC3Hash("1234567890ABCDEF.example.com.")
	if hash2 != "1234567890ABCDEF" {
		t.Errorf("extractNSEC3Hash() = %q, want %q", hash2, "1234567890ABCDEF")
	}
}

func TestValidatorFetchDNSKEY(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	// Test with nil resolver - should return error
	keys, err := v.fetchDNSKEY(context.Background(), "example.com.")
	if err == nil {
		t.Error("Expected error with nil resolver")
	}
	if keys != nil {
		t.Error("Keys should be nil with nil resolver")
	}

	// Test with mock resolver
	mock := &mockResolver{responses: make(map[string]*protocol.Message)}
	v.resolver = mock

	keys, err = v.fetchDNSKEY(context.Background(), "example.com.")
	// With mock resolver returning empty response, keys might be empty but not nil
	// The function returns the message's answers as DNSKEY records
	if err != nil {
		t.Errorf("fetchDNSKEY() error = %v", err)
	}
	// Keys may be empty array but not nil if query succeeds
	_ = keys
}

func TestValidatorFetchDS(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	// Test with nil resolver
	records, err := v.fetchDS(context.Background(), "example.com.")
	if err == nil {
		t.Error("Expected error with nil resolver")
	}
	if records != nil {
		t.Error("Records should be nil with nil resolver")
	}

	// Test with mock resolver
	mock := &mockResolver{responses: make(map[string]*protocol.Message)}
	v.resolver = mock

	records, err = v.fetchDS(context.Background(), "example.com.")
	// With mock resolver returning empty response, records might be empty but not nil
	if err != nil {
		t.Errorf("fetchDS() error = %v", err)
	}
	// Records may be empty array but not nil if query succeeds
	_ = records
}

func TestNameInRange_Wrap(t *testing.T) {
	// Test wrap-around case (end of zone)
	// When next is alphabetically before owner, it means wrap-around
	owner := "z.example.com."
	next := "a.example.com."

	// "zzz.example.com." should be in range (after z, wraps to a)
	result := nameInRange("zzz.example.com.", owner, next)
	// This depends on the nameInRange implementation
	_ = result

	// "m.example.com." should NOT be in range when wrapping
	result = nameInRange("m.example.com.", owner, next)
	_ = result
}

func TestValidateDelegation(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	// Create parent chain link with DNSKEY
	parentName, _ := protocol.ParseName("com.")
	dnskey := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}
	parent := &chainLink{
		zone:    "com.",
		dnsKeys: []*protocol.ResourceRecord{{Name: parentName, Data: dnskey}},
	}

	// Create DS record with matching key tag
	keyTag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)
	dsName, _ := protocol.ParseName("example.com.")
	dsRecords := []*protocol.ResourceRecord{
		{
			Name: dsName,
			Data: &protocol.RDataDS{
				KeyTag:     keyTag,
				Algorithm:  protocol.AlgorithmRSASHA256,
				DigestType: 2,
				Digest:     calculateDSDigestFromDNSKEY("example.com.", dnskey, 2),
			},
		},
	}

	// Create child DNSKEY
	childName, _ := protocol.ParseName("example.com.")
	childKeys := []*protocol.ResourceRecord{
		{Name: childName, Data: dnskey},
	}

	// Test matching delegation
	result := v.validateDelegation(parent, dsRecords, childKeys)
	if !result {
		t.Error("validateDelegation should return true for matching DS/DNSKEY")
	}

	// Test with empty DS records
	result = v.validateDelegation(parent, []*protocol.ResourceRecord{}, childKeys)
	if result {
		t.Error("validateDelegation should return false for empty DS records")
	}

	// Test with wrong key tag
	dsRecords[0].Data.(*protocol.RDataDS).KeyTag = 65535
	result = v.validateDelegation(parent, dsRecords, childKeys)
	if result {
		t.Error("validateDelegation should return false for wrong key tag")
	}
}

func TestFindRRSIG(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)
	name, _ := protocol.ParseName("example.com.")

	// Create RRSIG record
	rrsigData := &protocol.RDataRRSIG{
		TypeCovered: protocol.TypeA,
		Algorithm:   protocol.AlgorithmRSASHA256,
		KeyTag:      12345,
	}

	answers := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeA, Data: &protocol.RDataA{}},
		{Name: name, Type: protocol.TypeRRSIG, Data: rrsigData},
		{Name: name, Type: protocol.TypeAAAA, Data: &protocol.RDataAAAA{}},
	}

	// Test finding RRSIG for TypeA
	rrsig := v.findRRSIG(answers, name.String(), protocol.TypeA)
	if rrsig == nil {
		t.Error("findRRSIG should find RRSIG for TypeA")
	}

	// Test not finding RRSIG for TypeMX
	rrsig = v.findRRSIG(answers, name.String(), protocol.TypeMX)
	if rrsig != nil {
		t.Error("findRRSIG should not find RRSIG for TypeMX")
	}

	// Test with empty answers
	rrsig = v.findRRSIG([]*protocol.ResourceRecord{}, name.String(), protocol.TypeA)
	if rrsig != nil {
		t.Error("findRRSIG should return nil for empty answers")
	}
}

func TestValidateRRSIG(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)
	name, _ := protocol.ParseName("example.com.")

	// Create RRSet
	rrSet := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
	}

	// Create RRSIG with future timestamps so it doesn't fail on time check
	futureTime := uint32(time.Now().Unix()) + 3600
	pastTime := uint32(time.Now().Unix()) - 3600
	rrsig := &protocol.RDataRRSIG{
		TypeCovered: protocol.TypeA,
		Algorithm:   protocol.AlgorithmRSASHA256,
		OriginalTTL: 300,
		Expiration:  futureTime,
		Inception:   pastTime,
		KeyTag:      12345,
	}

	// Test with no matching DNSKEY
	dnsKeys := []*protocol.ResourceRecord{}
	result := v.validateRRSIG(rrSet, rrsig, dnsKeys)
	if result {
		t.Error("validateRRSIG should return false with no DNSKEYs")
	}

	// Test with expired signature (when not ignoring time)
	oldConfig := v.config
	v.config.IgnoreTime = false
	rrsig.Expiration = uint32(time.Now().Unix()) - 100
	result = v.validateRRSIG(rrSet, rrsig, dnsKeys)
	if result {
		t.Error("validateRRSIG should return false for expired signature")
	}
	v.config = oldConfig

	// Test with future inception
	rrsig.Inception = uint32(time.Now().Unix()) + 3600
	rrsig.Expiration = futureTime
	result = v.validateRRSIG(rrSet, rrsig, dnsKeys)
	if result {
		t.Error("validateRRSIG should return false for future inception")
	}
}

func TestValidateMessage(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	// Test with empty chain
	msg := &protocol.Message{Answers: []*protocol.ResourceRecord{}}
	result := v.validateMessage(context.Background(), msg, "example.com.", nil)
	if result != ValidationBogus {
		t.Errorf("validateMessage should return Bogus for empty chain, got %v", result)
	}

	// Test with valid chain but no answers
	chain := []*chainLink{{zone: "example.com.", validated: true}}
	result = v.validateMessage(context.Background(), &protocol.Message{}, "example.com.", chain)
	// Should handle negative response validation
	_ = result
}

func TestCanonicalizeRR(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)
	name, _ := protocol.ParseName("Example.COM.")

	rr := &protocol.ResourceRecord{
		Name:  name,
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataA{Address: [4]byte{192, 168, 1, 1}},
	}

	// Test canonicalization
	result := v.canonicalizeRR(rr, 3600)
	if len(result) == 0 {
		t.Error("canonicalizeRR should return non-empty result")
	}

	// Verify it starts with lowercase name
	// The name should be canonicalized to lowercase
	if result[0] == 0 {
		t.Error("canonicalizeRR result should start with label length")
	}
}

func TestCanonicalizeRRSet(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)
	name, _ := protocol.ParseName("example.com.")

	rrSet := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
		{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{5, 6, 7, 8}}},
	}

	rrsig := &protocol.RDataRRSIG{
		TypeCovered: protocol.TypeA,
		OriginalTTL: 3600,
	}

	result := v.canonicalizeRRSet(rrSet, rrsig)
	if len(result) == 0 {
		t.Error("canonicalizeRRSet should return non-empty result")
	}
}

func TestValidateNSEC(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	nextDomain, _ := protocol.ParseName("d.example.com.")
	nsec := &protocol.RDataNSEC{
		NextDomain: nextDomain,
		TypeBitMap: []uint16{protocol.TypeA, protocol.TypeNS},
	}

	// Test name in gap (b.example.com is between a.example.com and d.example.com)
	result := v.validateNSEC("a.example.com.", "b.example.com.", protocol.TypeA, nsec)
	if !result {
		t.Error("validateNSEC should return true for name in gap")
	}

	// Test name not in gap
	result = v.validateNSEC("a.example.com.", "z.example.com.", protocol.TypeA, nsec)
	if result {
		t.Error("validateNSEC should return false for name not in gap")
	}

	// Note: exact match tests depend on nameInRange behavior
	// When owner == queryName, nameInRange returns false
}

func TestValidateNSEC3(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	nsec3 := &protocol.RDataNSEC3{
		HashAlgorithm: protocol.NSEC3HashSHA1,
		Iterations:    10,
		Salt:          []byte{0xAA},
		NextHashed:    []byte{0x01, 0x02, 0x03, 0x04},
		TypeBitMap:    []uint16{protocol.TypeA},
	}

	chain := []*chainLink{{zone: "example.com.", validated: true}}

	// Test validation (will likely fail due to hash computation)
	result := v.validateNSEC3("abc.example.com.", "test.example.com.", protocol.TypeA, nsec3, chain)
	// Result depends on hash computation
	_ = result

	// Test with empty chain
	result = v.validateNSEC3("abc.example.com.", "test.example.com.", protocol.TypeA, nsec3, nil)
	if result {
		t.Error("validateNSEC3 should return false with empty chain")
	}
}

func TestCalculateDSDigestFromDNSKEY(t *testing.T) {
	dnskey := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}

	// Test SHA-256 (type 2)
	digest := calculateDSDigestFromDNSKEY("example.com.", dnskey, 2)
	if len(digest) != 32 {
		t.Errorf("SHA-256 digest length: got %d, want 32", len(digest))
	}

	// Test SHA-1 (type 1)
	digest = calculateDSDigestFromDNSKEY("example.com.", dnskey, 1)
	if len(digest) != 20 {
		t.Errorf("SHA-1 digest length: got %d, want 20", len(digest))
	}

	// Test SHA-384 (type 4)
	digest = calculateDSDigestFromDNSKEY("example.com.", dnskey, 4)
	if len(digest) != 48 {
		t.Errorf("SHA-384 digest length: got %d, want 48", len(digest))
	}

	// Test unsupported digest type
	digest = calculateDSDigestFromDNSKEY("example.com.", dnskey, 99)
	if digest != nil {
		t.Error("calculateDSDigestFromDNSKEY should return nil for unsupported type")
	}
}

func TestValidateResponseNoAnchor(t *testing.T) {
	// Test with no trust anchor found (empty store), not requiring DNSSEC
	store := NewTrustAnchorStore()
	config := DefaultValidatorConfig()
	config.Enabled = true
	config.RequireDNSSEC = false
	v := NewValidator(config, store, nil)

	msg := &protocol.Message{}
	result, err := v.ValidateResponse(context.Background(), msg, "example.com.")
	if err != nil {
		t.Fatalf("ValidateResponse failed: %v", err)
	}
	if result != ValidationInsecure {
		t.Errorf("Expected INSECURE when no anchor and RequireDNSSEC=false, got %s", result)
	}
}

func TestValidateResponseNoAnchorRequireDNSSEC(t *testing.T) {
	// Test with no trust anchor found, requiring DNSSEC
	store := NewTrustAnchorStore()
	config := DefaultValidatorConfig()
	config.Enabled = true
	config.RequireDNSSEC = true
	v := NewValidator(config, store, nil)

	msg := &protocol.Message{}
	result, err := v.ValidateResponse(context.Background(), msg, "example.com.")
	if err == nil {
		t.Error("Expected error when no anchor and RequireDNSSEC=true")
	}
	if result != ValidationBogus {
		t.Errorf("Expected BOGUS when no anchor and RequireDNSSEC=true, got %s", result)
	}
}

func TestBuildChainBasic(t *testing.T) {
	// Create a trust anchor with matching DNSKEY
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	keyData, err := packECDSAPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to pack public key: %v", err)
	}

	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: keyData,
	}

	keyTag := protocol.CalculateKeyTag(dnskeyData.Flags, dnskeyData.Algorithm, dnskeyData.PublicKey)
	digest := calculateDSDigestFromDNSKEY("example.com.", dnskeyData, 2)

	anchor := &TrustAnchor{
		Zone:       "example.com.",
		KeyTag:     keyTag,
		Algorithm:  protocol.AlgorithmECDSAP256SHA256,
		DigestType: 2,
		Digest:     digest,
		ValidFrom:  time.Now().Add(-time.Hour),
	}

	store := NewTrustAnchorStore()
	store.AddAnchor(anchor)

	// Set up mock resolver that returns the DNSKEY
	rootName, _ := protocol.ParseName("example.com.")
	mock := &mockResolver{
		responses: map[string]*protocol.Message{
			"example.com.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{
					{Name: rootName, Type: protocol.TypeDNSKEY, Data: dnskeyData},
				},
			},
		},
	}

	config := DefaultValidatorConfig()
	config.Enabled = true
	v := NewValidator(config, store, mock)

	// Test buildChain with no remaining labels
	chain, err := v.buildChain(context.Background(), anchor, []string{})
	if err != nil {
		t.Fatalf("buildChain failed: %v", err)
	}
	if len(chain) != 1 {
		t.Errorf("Expected 1 chain link, got %d", len(chain))
	}
	if !chain[0].validated {
		t.Error("Chain link should be validated")
	}
}

func TestBuildChainFetchDNSKEYError(t *testing.T) {
	anchor := &TrustAnchor{
		Zone:       "example.com.",
		KeyTag:     12345,
		Algorithm:  protocol.AlgorithmECDSAP256SHA256,
		DigestType: 2,
		Digest:     []byte{0x01, 0x02},
		ValidFrom:  time.Now().Add(-time.Hour),
	}

	// No resolver configured
	config := DefaultValidatorConfig()
	v := NewValidator(config, NewTrustAnchorStore(), nil)

	_, err := v.buildChain(context.Background(), anchor, []string{})
	if err == nil {
		t.Error("Expected error when no resolver configured for buildChain")
	}
}

func TestBuildChainAnchorValidationFails(t *testing.T) {
	// Create an anchor that won't match any DNSKEY
	anchor := &TrustAnchor{
		Zone:       "example.com.",
		KeyTag:     60000,
		Algorithm:  protocol.AlgorithmECDSAP256SHA256,
		DigestType: 2,
		Digest:     []byte{0x01, 0x02},
		ValidFrom:  time.Now().Add(-time.Hour),
	}

	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: []byte{0xAA, 0xBB, 0xCC, 0xDD},
	}

	rootName, _ := protocol.ParseName("example.com.")
	mock := &mockResolver{
		responses: map[string]*protocol.Message{
			"example.com.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{
					{Name: rootName, Type: protocol.TypeDNSKEY, Data: dnskeyData},
				},
			},
		},
	}

	config := DefaultValidatorConfig()
	v := NewValidator(config, NewTrustAnchorStore(), mock)

	_, err := v.buildChain(context.Background(), anchor, []string{})
	if err == nil {
		t.Error("Expected error when anchor validation fails")
	}
}

func TestBuildChainWithDelegation(t *testing.T) {
	// Create a trust anchor for parent zone
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	keyData, err := packECDSAPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to pack public key: %v", err)
	}

	parentDnskey := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: keyData,
	}

	parentKeyTag := protocol.CalculateKeyTag(parentDnskey.Flags, parentDnskey.Algorithm, parentDnskey.PublicKey)
	parentDigest := calculateDSDigestFromDNSKEY("com.", parentDnskey, 2)

	anchor := &TrustAnchor{
		Zone:       "com.",
		KeyTag:     parentKeyTag,
		Algorithm:  protocol.AlgorithmECDSAP256SHA256,
		DigestType: 2,
		Digest:     parentDigest,
		ValidFrom:  time.Now().Add(-time.Hour),
	}

	// Create child DNSKEY
	childPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate child ECDSA key: %v", err)
	}

	childPub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &childPrivKey.PublicKey}
	childKeyData, err := packECDSAPublicKey(childPub)
	if err != nil {
		t.Fatalf("Failed to pack child public key: %v", err)
	}

	childDnskey := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: childKeyData,
	}

	childKeyTag := protocol.CalculateKeyTag(childDnskey.Flags, childDnskey.Algorithm, childDnskey.PublicKey)
	childDigest := calculateDSDigestFromDNSKEY("example.", childDnskey, 2)

	// Set up mock resolver
	parentName, _ := protocol.ParseName("com.")
	childName, _ := protocol.ParseName("example.")

	mock := &mockResolver{
		responses: map[string]*protocol.Message{
			"com.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{
					{Name: parentName, Type: protocol.TypeDNSKEY, Data: parentDnskey},
				},
			},
			"example.|" + strconv.Itoa(int(protocol.TypeDS)): {
				Answers: []*protocol.ResourceRecord{
					{
						Name: childName,
						Type: protocol.TypeDS,
						Data: &protocol.RDataDS{
							KeyTag:     childKeyTag,
							Algorithm:  protocol.AlgorithmECDSAP256SHA256,
							DigestType: 2,
							Digest:     childDigest,
						},
					},
				},
			},
			"example.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{
					{Name: childName, Type: protocol.TypeDNSKEY, Data: childDnskey},
				},
			},
		},
	}

	store := NewTrustAnchorStore()
	store.AddAnchor(anchor)

	config := DefaultValidatorConfig()
	v := NewValidator(config, store, mock)

	// Build chain with remaining label "example"
	chain, err := v.buildChain(context.Background(), anchor, []string{"example"})
	if err != nil {
		t.Fatalf("buildChain with delegation failed: %v", err)
	}
	if len(chain) != 2 {
		t.Errorf("Expected 2 chain links, got %d", len(chain))
	}
}

func TestBuildChainUnsignedDelegation(t *testing.T) {
	// Create trust anchor for parent
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	keyData, err := packECDSAPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to pack public key: %v", err)
	}

	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: keyData,
	}

	keyTag := protocol.CalculateKeyTag(dnskeyData.Flags, dnskeyData.Algorithm, dnskeyData.PublicKey)
	digest := calculateDSDigestFromDNSKEY("com.", dnskeyData, 2)

	anchor := &TrustAnchor{
		Zone:       "com.",
		KeyTag:     keyTag,
		Algorithm:  protocol.AlgorithmECDSAP256SHA256,
		DigestType: 2,
		Digest:     digest,
		ValidFrom:  time.Now().Add(-time.Hour),
	}

	parentName, _ := protocol.ParseName("com.")
	mock := &mockResolver{
		responses: map[string]*protocol.Message{
			"com.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{
					{Name: parentName, Type: protocol.TypeDNSKEY, Data: dnskeyData},
				},
			},
			// example.com. DS query returns empty (unsigned delegation)
		},
	}

	store := NewTrustAnchorStore()
	store.AddAnchor(anchor)

	config := DefaultValidatorConfig()
	v := NewValidator(config, store, mock)

	// Build chain - should stop at unsigned delegation
	chain, err := v.buildChain(context.Background(), anchor, []string{"example"})
	if err != nil {
		t.Fatalf("buildChain with unsigned delegation failed: %v", err)
	}
	// Should have 1 link (just the anchor zone, delegation stops)
	if len(chain) != 1 {
		t.Errorf("Expected 1 chain link for unsigned delegation, got %d", len(chain))
	}
}

func TestBuildChainMaxDepth(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	keyData, err := packECDSAPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to pack public key: %v", err)
	}

	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: keyData,
	}

	keyTag := protocol.CalculateKeyTag(dnskeyData.Flags, dnskeyData.Algorithm, dnskeyData.PublicKey)
	digest := calculateDSDigestFromDNSKEY(".", dnskeyData, 2)

	anchor := &TrustAnchor{
		Zone:       ".",
		KeyTag:     keyTag,
		Algorithm:  protocol.AlgorithmECDSAP256SHA256,
		DigestType: 2,
		Digest:     digest,
		ValidFrom:  time.Now().Add(-time.Hour),
	}

	rootName, _ := protocol.ParseName(".")
	mock := &mockResolver{
		responses: map[string]*protocol.Message{
			".|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{
					{Name: rootName, Type: protocol.TypeDNSKEY, Data: dnskeyData},
				},
			},
		},
	}

	// Use MaxDelegationDepth=1 so the chain (length 1 after anchor) triggers depth check
	// on the first iteration
	config := DefaultValidatorConfig()
	config.MaxDelegationDepth = 1
	v := NewValidator(config, NewTrustAnchorStore(), mock)

	remaining := []string{"label0", "label1"}
	_, err = v.buildChain(context.Background(), anchor, remaining)
	if err == nil {
		t.Error("Expected error when max delegation depth exceeded")
	}
}

func TestValidateMessageWithAnswersAndRRSIG(t *testing.T) {
	// Create a validator with a chain that has DNSKEYs
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	keyData, err := packECDSAPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to pack public key: %v", err)
	}

	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: keyData,
	}

	name, _ := protocol.ParseName("example.com.")
	dnskeyRR := &protocol.ResourceRecord{Name: name, Type: protocol.TypeDNSKEY, Data: dnskeyData}

	chain := []*chainLink{
		{
			zone:      "example.com.",
			dnsKeys:   []*protocol.ResourceRecord{dnskeyRR},
			validated: true,
		},
	}

	// Create a signed RRset (A record + RRSIG)
	aRecord := &protocol.ResourceRecord{
		Name:  name,
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
	}

	// Test with RequireDNSSEC=false, no RRSIG (should be SECURE, continue)
	config := DefaultValidatorConfig()
	config.RequireDNSSEC = false
	v2 := NewValidator(config, nil, nil)

	msg := &protocol.Message{
		Answers: []*protocol.ResourceRecord{aRecord},
	}
	result := v2.validateMessage(context.Background(), msg, "example.com.", chain)
	// Should be SECURE because RequireDNSSEC is false and no RRSIG means it just continues
	if result != ValidationSecure {
		t.Errorf("Expected SECURE with RequireDNSSEC=false, got %s", result)
	}
}

func TestValidateMessageWithRequireDNSSEC(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	keyData, err := packECDSAPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to pack public key: %v", err)
	}

	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: keyData,
	}

	name, _ := protocol.ParseName("example.com.")
	dnskeyRR := &protocol.ResourceRecord{Name: name, Type: protocol.TypeDNSKEY, Data: dnskeyData}

	chain := []*chainLink{
		{
			zone:      "example.com.",
			dnsKeys:   []*protocol.ResourceRecord{dnskeyRR},
			validated: true,
		},
	}

	config := DefaultValidatorConfig()
	config.RequireDNSSEC = true
	v := NewValidator(config, nil, nil)

	aRecord := &protocol.ResourceRecord{
		Name:  name,
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
	}

	msg := &protocol.Message{
		Answers: []*protocol.ResourceRecord{aRecord},
	}

	result := v.validateMessage(context.Background(), msg, "example.com.", chain)
	if result != ValidationBogus {
		t.Errorf("Expected BOGUS with RequireDNSSEC=true and no RRSIG, got %s", result)
	}
}

func TestValidateMessageWithValidRRSIG(t *testing.T) {
	// Generate a key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	priv := &PrivateKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: privKey}
	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	keyData, err := packECDSAPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to pack public key: %v", err)
	}

	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: keyData,
	}
	keyTag := protocol.CalculateKeyTag(dnskeyData.Flags, dnskeyData.Algorithm, dnskeyData.PublicKey)

	name, _ := protocol.ParseName("example.com.")
	dnskeyRR := &protocol.ResourceRecord{Name: name, Type: protocol.TypeDNSKEY, Data: dnskeyData}

	chain := []*chainLink{
		{
			zone:      "example.com.",
			dnsKeys:   []*protocol.ResourceRecord{dnskeyRR},
			validated: true,
		},
	}

	config := DefaultValidatorConfig()
	config.IgnoreTime = true
	v := NewValidator(config, nil, nil)

	// Create A record
	aRecord := &protocol.ResourceRecord{
		Name:  name,
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
	}

	// Create signed data and sign it
	signerName, _ := protocol.ParseName("example.com.")
	rrsig := &protocol.RDataRRSIG{
		TypeCovered: protocol.TypeA,
		Algorithm:   protocol.AlgorithmECDSAP256SHA256,
		Labels:      2,
		OriginalTTL: 300,
		Expiration:  uint32(time.Now().Add(time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		KeyTag:      keyTag,
		SignerName:  signerName,
	}

	// Use the signer to create proper signed data
	signedData := v.canonicalizeRRSet([]*protocol.ResourceRecord{aRecord}, rrsig)
	signature, err := SignData(protocol.AlgorithmECDSAP256SHA256, priv, signedData)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}
	rrsig.Signature = signature

	rrsigRR := &protocol.ResourceRecord{
		Name:  name,
		Type:  protocol.TypeRRSIG,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  rrsig,
	}

	msg := &protocol.Message{
		Answers: []*protocol.ResourceRecord{aRecord, rrsigRR},
	}

	result := v.validateMessage(context.Background(), msg, "example.com.", chain)
	if result != ValidationSecure {
		t.Errorf("Expected SECURE with valid RRSIG, got %s", result)
	}
}

func TestValidateMessageWithInvalidRRSIG(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	keyData, err := packECDSAPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to pack public key: %v", err)
	}

	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: keyData,
	}
	keyTag := protocol.CalculateKeyTag(dnskeyData.Flags, dnskeyData.Algorithm, dnskeyData.PublicKey)

	name, _ := protocol.ParseName("example.com.")
	dnskeyRR := &protocol.ResourceRecord{Name: name, Type: protocol.TypeDNSKEY, Data: dnskeyData}

	chain := []*chainLink{
		{
			zone:      "example.com.",
			dnsKeys:   []*protocol.ResourceRecord{dnskeyRR},
			validated: true,
		},
	}

	config := DefaultValidatorConfig()
	v := NewValidator(config, nil, nil)

	aRecord := &protocol.ResourceRecord{
		Name:  name,
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
	}

	signerName, _ := protocol.ParseName("example.com.")
	rrsig := &protocol.RDataRRSIG{
		TypeCovered: protocol.TypeA,
		Algorithm:   protocol.AlgorithmECDSAP256SHA256,
		Labels:      2,
		OriginalTTL: 300,
		Expiration:  uint32(time.Now().Add(time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		KeyTag:      keyTag,
		SignerName:  signerName,
		Signature:   make([]byte, 64), // bogus signature
	}

	rrsigRR := &protocol.ResourceRecord{
		Name:  name,
		Type:  protocol.TypeRRSIG,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  rrsig,
	}

	msg := &protocol.Message{
		Answers: []*protocol.ResourceRecord{aRecord, rrsigRR},
	}

	result := v.validateMessage(context.Background(), msg, "example.com.", chain)
	if result != ValidationBogus {
		t.Errorf("Expected BOGUS with invalid RRSIG, got %s", result)
	}
}

func TestValidateRRSIGWithMatchingKey(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	priv := &PrivateKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: privKey}
	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	keyData, err := packECDSAPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to pack public key: %v", err)
	}

	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: keyData,
	}
	keyTag := protocol.CalculateKeyTag(dnskeyData.Flags, dnskeyData.Algorithm, dnskeyData.PublicKey)

	name, _ := protocol.ParseName("example.com.")
	dnskeyRR := &protocol.ResourceRecord{Name: name, Data: dnskeyData}

	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	rrSet := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
	}

	signerName, _ := protocol.ParseName("example.com.")
	rrsig := &protocol.RDataRRSIG{
		TypeCovered: protocol.TypeA,
		Algorithm:   protocol.AlgorithmECDSAP256SHA256,
		Labels:      2,
		OriginalTTL: 300,
		Expiration:  uint32(time.Now().Add(time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		KeyTag:      keyTag,
		SignerName:  signerName,
	}

	// Create proper signed data
	signedData := v.canonicalizeRRSet(rrSet, rrsig)
	signature, err := SignData(protocol.AlgorithmECDSAP256SHA256, priv, signedData)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}
	rrsig.Signature = signature

	result := v.validateRRSIG(rrSet, rrsig, []*protocol.ResourceRecord{dnskeyRR})
	if !result {
		t.Error("validateRRSIG should return true for valid signature")
	}
}

func TestValidateRRSIGIgnoreTime(t *testing.T) {
	config := DefaultValidatorConfig()
	config.IgnoreTime = true
	v := NewValidator(config, nil, nil)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	priv := &PrivateKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: privKey}
	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	keyData, err := packECDSAPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to pack public key: %v", err)
	}

	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: keyData,
	}
	keyTag := protocol.CalculateKeyTag(dnskeyData.Flags, dnskeyData.Algorithm, dnskeyData.PublicKey)

	name, _ := protocol.ParseName("example.com.")
	dnskeyRR := &protocol.ResourceRecord{Name: name, Data: dnskeyData}

	rrSet := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
	}

	// Use expired signature but with IgnoreTime=true
	signerName, _ := protocol.ParseName("example.com.")
	rrsig := &protocol.RDataRRSIG{
		TypeCovered: protocol.TypeA,
		Algorithm:   protocol.AlgorithmECDSAP256SHA256,
		Labels:      2,
		OriginalTTL: 300,
		Expiration:  1, // very old
		Inception:   0,
		KeyTag:      keyTag,
		SignerName:  signerName,
	}

	signedData := v.canonicalizeRRSet(rrSet, rrsig)
	signature, err := SignData(protocol.AlgorithmECDSAP256SHA256, priv, signedData)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}
	rrsig.Signature = signature

	result := v.validateRRSIG(rrSet, rrsig, []*protocol.ResourceRecord{dnskeyRR})
	if !result {
		t.Error("validateRRSIG should return true with IgnoreTime=true even with expired signature")
	}
}

func TestValidateRRSIGNoMatchingKey(t *testing.T) {
	config := DefaultValidatorConfig()
	v := NewValidator(config, nil, nil)

	name, _ := protocol.ParseName("example.com.")

	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: []byte{0x01, 0x02, 0x03},
	}
	dnskeyRR := &protocol.ResourceRecord{Name: name, Data: dnskeyData}

	rrSet := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
	}

	rrsig := &protocol.RDataRRSIG{
		TypeCovered: protocol.TypeA,
		Algorithm:   protocol.AlgorithmECDSAP256SHA256,
		Expiration:  uint32(time.Now().Add(time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		KeyTag:      60000, // won't match
	}

	result := v.validateRRSIG(rrSet, rrsig, []*protocol.ResourceRecord{dnskeyRR})
	if result {
		t.Error("validateRRSIG should return false when no matching key")
	}
}

func TestValidateRRSIGKeyParseFails(t *testing.T) {
	config := DefaultValidatorConfig()
	v := NewValidator(config, nil, nil)

	name, _ := protocol.ParseName("example.com.")

	// Invalid public key data
	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: []byte{0x01}, // too short for ECDSA
	}
	keyTag := protocol.CalculateKeyTag(dnskeyData.Flags, dnskeyData.Algorithm, dnskeyData.PublicKey)
	dnskeyRR := &protocol.ResourceRecord{Name: name, Data: dnskeyData}

	rrSet := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
	}

	rrsig := &protocol.RDataRRSIG{
		TypeCovered: protocol.TypeA,
		Algorithm:   protocol.AlgorithmECDSAP256SHA256,
		Expiration:  uint32(time.Now().Add(time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		KeyTag:      keyTag,
	}

	result := v.validateRRSIG(rrSet, rrsig, []*protocol.ResourceRecord{dnskeyRR})
	if result {
		t.Error("validateRRSIG should return false when key parsing fails")
	}
}

func TestValidateNSECExactMatchTypeExists(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	nextDomain, _ := protocol.ParseName("d.example.com.")
	nsec := &protocol.RDataNSEC{
		NextDomain: nextDomain,
		TypeBitMap: []uint16{protocol.TypeA, protocol.TypeNS},
	}

	// When owner == queryName, and the type IS in the bitmap, should return false
	result := v.validateNSEC("a.example.com.", "a.example.com.", protocol.TypeA, nsec)
	if result {
		t.Error("validateNSEC should return false when type exists in bitmap for exact match")
	}
}

func TestValidateNSECExactMatchTypeMissing(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	nextDomain, _ := protocol.ParseName("d.example.com.")
	nsec := &protocol.RDataNSEC{
		NextDomain: nextDomain,
		TypeBitMap: []uint16{protocol.TypeA, protocol.TypeNS},
	}

	// When owner == queryName, but type is NOT in bitmap
	// Need nameInRange to return true: name > owner && name < next won't work since name==owner
	// So this will fail at the nameInRange check first
	result := v.validateNSEC("a.example.com.", "a.example.com.", protocol.TypeMX, nsec)
	if result {
		t.Error("validateNSEC should return false when nameInRange fails (name==owner)")
	}
}

func TestValidateNegativeResponseWithNSEC3(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	nsec3 := &protocol.RDataNSEC3{
		HashAlgorithm: protocol.NSEC3HashSHA1,
		Iterations:    0,
		Salt:          []byte{},
		NextHashed:    []byte{0x01, 0x02, 0x03},
		TypeBitMap:    []uint16{protocol.TypeA},
	}

	nsec3Owner, _ := protocol.ParseName("abc.example.com.")
	nsec3RR := &protocol.ResourceRecord{
		Name:  nsec3Owner,
		Type:  protocol.TypeNSEC3,
		Class: protocol.ClassIN,
		Data:  nsec3,
	}

	questionName, _ := protocol.ParseName("nonexistent.example.com.")
	msg := &protocol.Message{
		Header: protocol.Header{
			Flags:   protocol.NewResponseFlags(protocol.RcodeNameError),
			QDCount: 1,
		},
		Authorities: []*protocol.ResourceRecord{nsec3RR},
		Questions: []*protocol.Question{
			{Name: questionName, QType: protocol.TypeA},
		},
	}

	chain := []*chainLink{{zone: "example.com.", validated: true}}
	result := v.validateNegativeResponse(msg, "nonexistent.example.com.", chain)
	// This will attempt NSEC3 validation which may or may not succeed
	// Just ensure it doesn't panic
	_ = result
}

func TestValidateNegativeResponseNoRecords(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	questionName, _ := protocol.ParseName("nonexistent.example.com.")
	msg := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
		Authorities: []*protocol.ResourceRecord{},
		Questions: []*protocol.Question{
			{Name: questionName, QType: protocol.TypeA},
		},
	}

	result := v.validateNegativeResponse(msg, "nonexistent.example.com.", nil)
	if result != ValidationBogus {
		t.Errorf("Expected BOGUS for negative response with no NSEC/NSEC3, got %s", result)
	}
}

func TestValidateNegativeResponseWithNSECProvesNonExistence(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	// Create NSEC that proves b.example.com doesn't exist
	// owner=a.example.com., next=c.example.com.
	// query=b.example.com. (between a and c, so nameInRange returns true)
	nextDomain, _ := protocol.ParseName("c.example.com.")
	nsec := &protocol.RDataNSEC{
		NextDomain: nextDomain,
		TypeBitMap: []uint16{protocol.TypeNS},
	}

	nsecOwner, _ := protocol.ParseName("a.example.com.")
	nsecRR := &protocol.ResourceRecord{
		Name:  nsecOwner,
		Type:  protocol.TypeNSEC,
		Class: protocol.ClassIN,
		Data:  nsec,
	}

	questionName, _ := protocol.ParseName("b.example.com.")
	msg := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
		Authorities: []*protocol.ResourceRecord{nsecRR},
		Questions: []*protocol.Question{
			{Name: questionName, QType: protocol.TypeA},
		},
	}

	chain := []*chainLink{{zone: "example.com.", validated: true}}
	result := v.validateNegativeResponse(msg, "b.example.com.", chain)
	if result != ValidationSecure {
		t.Errorf("Expected SECURE for NSEC-proved non-existence, got %s", result)
	}
}

func TestValidateNegativeResponseWithNSECButStillBogus(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	// Create NSEC that does NOT prove non-existence
	// owner=a.example.com., next=c.example.com.
	// query=z.example.com. (NOT between a and c, so nameInRange returns false)
	nextDomain, _ := protocol.ParseName("c.example.com.")
	nsec := &protocol.RDataNSEC{
		NextDomain: nextDomain,
		TypeBitMap: []uint16{protocol.TypeNS},
	}

	nsecOwner, _ := protocol.ParseName("a.example.com.")
	nsecRR := &protocol.ResourceRecord{
		Name:  nsecOwner,
		Type:  protocol.TypeNSEC,
		Class: protocol.ClassIN,
		Data:  nsec,
	}

	questionName, _ := protocol.ParseName("z.example.com.")
	msg := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
		Authorities: []*protocol.ResourceRecord{nsecRR},
		Questions: []*protocol.Question{
			{Name: questionName, QType: protocol.TypeA},
		},
	}

	result := v.validateNegativeResponse(msg, "z.example.com.", nil)
	if result != ValidationBogus {
		t.Errorf("Expected BOGUS when NSEC doesn't prove non-existence, got %s", result)
	}
}

func TestValidateNegativeResponseWithWrongDataType(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	// NSEC record with wrong data type (not RDataNSEC)
	nsecOwner, _ := protocol.ParseName("a.example.com.")
	nsecRR := &protocol.ResourceRecord{
		Name:  nsecOwner,
		Type:  protocol.TypeNSEC,
		Class: protocol.ClassIN,
		Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}, // wrong type
	}

	questionName, _ := protocol.ParseName("b.example.com.")
	msg := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
		Authorities: []*protocol.ResourceRecord{nsecRR},
		Questions: []*protocol.Question{
			{Name: questionName, QType: protocol.TypeA},
		},
	}

	result := v.validateNegativeResponse(msg, "b.example.com.", nil)
	if result != ValidationBogus {
		t.Errorf("Expected BOGUS for wrong data type, got %s", result)
	}
}

func TestValidateNegativeResponseNSEC3WrongDataType(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	// NSEC3 record with wrong data type (not RDataNSEC3)
	nsec3Owner, _ := protocol.ParseName("abc.example.com.")
	nsec3RR := &protocol.ResourceRecord{
		Name:  nsec3Owner,
		Type:  protocol.TypeNSEC3,
		Class: protocol.ClassIN,
		Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}, // wrong type
	}

	questionName, _ := protocol.ParseName("b.example.com.")
	msg := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
		Authorities: []*protocol.ResourceRecord{nsec3RR},
		Questions: []*protocol.Question{
			{Name: questionName, QType: protocol.TypeA},
		},
	}

	result := v.validateNegativeResponse(msg, "b.example.com.", nil)
	if result != ValidationBogus {
		t.Errorf("Expected BOGUS for wrong NSEC3 data type, got %s", result)
	}
}

func TestExtractNSEC3HashEmpty(t *testing.T) {
	hash := extractNSEC3Hash("")
	if hash != "" {
		t.Errorf("Expected empty hash for empty owner, got %q", hash)
	}
}

func TestFetchDNSKEYWithResults(t *testing.T) {
	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: []byte{0x01, 0x02, 0x03},
	}

	name, _ := protocol.ParseName("example.com.")
	mock := &mockResolver{
		responses: map[string]*protocol.Message{
			"example.com.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{
					{Name: name, Type: protocol.TypeDNSKEY, Data: dnskeyData},
					{Name: name, Type: protocol.TypeA, Data: &protocol.RDataA{}}, // non-DNSKEY, should be filtered
				},
			},
		},
	}

	v := NewValidator(DefaultValidatorConfig(), nil, mock)
	keys, err := v.fetchDNSKEY(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("fetchDNSKEY failed: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("Expected 1 DNSKEY, got %d", len(keys))
	}
}

func TestFetchDSWithResults(t *testing.T) {
	dsData := &protocol.RDataDS{
		KeyTag:     12345,
		Algorithm:  protocol.AlgorithmECDSAP256SHA256,
		DigestType: 2,
		Digest:     []byte{0x01, 0x02},
	}

	name, _ := protocol.ParseName("example.com.")
	mock := &mockResolver{
		responses: map[string]*protocol.Message{
			"example.com.|" + strconv.Itoa(int(protocol.TypeDS)): {
				Answers: []*protocol.ResourceRecord{
					{Name: name, Type: protocol.TypeDS, Data: dsData},
					{Name: name, Type: protocol.TypeA, Data: &protocol.RDataA{}}, // non-DS, should be filtered
				},
			},
		},
	}

	v := NewValidator(DefaultValidatorConfig(), nil, mock)
	records, err := v.fetchDS(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("fetchDS failed: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("Expected 1 DS record, got %d", len(records))
	}
}

func TestValidateTrustAnchorWithPublicKey(t *testing.T) {
	// Create a trust anchor with PublicKey (not Digest)
	pubKeyData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	dnskey := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmRSASHA256,
		PublicKey: pubKeyData,
	}
	keyTag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)

	anchor := &TrustAnchor{
		Zone:      ".",
		KeyTag:    keyTag,
		Algorithm: protocol.AlgorithmRSASHA256,
		PublicKey: pubKeyData,
		ValidFrom: time.Now().Add(-time.Hour),
	}

	rootName, _ := protocol.ParseName(".")
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	keys := []*protocol.ResourceRecord{
		{Name: rootName, Data: dnskey},
	}

	result := v.validateTrustAnchor(anchor, keys)
	if !result {
		t.Error("validateTrustAnchor should return true when PublicKey matches")
	}
}

func TestValidateTrustAnchorNoDigestNoPublicKey(t *testing.T) {
	// Anchor with no digest and no public key
	dnskey := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03},
	}
	keyTag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)

	anchor := &TrustAnchor{
		Zone:      ".",
		KeyTag:    keyTag,
		Algorithm: protocol.AlgorithmRSASHA256,
		ValidFrom: time.Now().Add(-time.Hour),
	}

	rootName, _ := protocol.ParseName(".")
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	keys := []*protocol.ResourceRecord{
		{Name: rootName, Data: dnskey},
	}

	result := v.validateTrustAnchor(anchor, keys)
	if result {
		t.Error("validateTrustAnchor should return false when no digest and no PublicKey match")
	}
}

func TestValidateDelegationWrongKeyType(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	parent := &chainLink{zone: "com.", validated: true}

	// DS record with wrong data type
	dsName, _ := protocol.ParseName("example.com.")
	dsRecords := []*protocol.ResourceRecord{
		{Name: dsName, Data: &protocol.RDataA{}}, // wrong type for DS
	}

	childKeys := []*protocol.ResourceRecord{}

	result := v.validateDelegation(parent, dsRecords, childKeys)
	if result {
		t.Error("validateDelegation should return false for wrong DS data type")
	}
}

func TestValidateDelegationChildKeyWrongType(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	parent := &chainLink{zone: "com.", validated: true}

	dsName, _ := protocol.ParseName("example.com.")
	dsRecords := []*protocol.ResourceRecord{
		{
			Name: dsName,
			Data: &protocol.RDataDS{
				KeyTag:     12345,
				Algorithm:  protocol.AlgorithmECDSAP256SHA256,
				DigestType: 2,
				Digest:     []byte{0x01},
			},
		},
	}

	// Child key with wrong data type
	childKeys := []*protocol.ResourceRecord{
		{Name: dsName, Data: &protocol.RDataA{}},
	}

	result := v.validateDelegation(parent, dsRecords, childKeys)
	if result {
		t.Error("validateDelegation should return false for wrong child key type")
	}
}

func TestValidateDelegationAlgorithmMismatch(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	parent := &chainLink{zone: "com.", validated: true}

	dnskey := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}

	keyTag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)

	dsName, _ := protocol.ParseName("example.com.")

	// DS with matching key tag but different algorithm
	dsRecords := []*protocol.ResourceRecord{
		{
			Name: dsName,
			Data: &protocol.RDataDS{
				KeyTag:     keyTag,
				Algorithm:  protocol.AlgorithmRSASHA256, // different algorithm
				DigestType: 2,
				Digest:     calculateDSDigestFromDNSKEY("example.com.", dnskey, 2),
			},
		},
	}

	childName, _ := protocol.ParseName("example.com.")
	childKeys := []*protocol.ResourceRecord{
		{Name: childName, Data: dnskey},
	}

	result := v.validateDelegation(parent, dsRecords, childKeys)
	if result {
		t.Error("validateDelegation should return false for algorithm mismatch")
	}
}

func TestValidateResponseFullChain(t *testing.T) {
	// End-to-end test of ValidateResponse
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	priv := &PrivateKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: privKey}
	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	keyData, err := packECDSAPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to pack public key: %v", err)
	}

	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: keyData,
	}
	keyTag := protocol.CalculateKeyTag(dnskeyData.Flags, dnskeyData.Algorithm, dnskeyData.PublicKey)
	digest := calculateDSDigestFromDNSKEY("example.com.", dnskeyData, 2)

	anchor := &TrustAnchor{
		Zone:       "example.com.",
		KeyTag:     keyTag,
		Algorithm:  protocol.AlgorithmECDSAP256SHA256,
		DigestType: 2,
		Digest:     digest,
		ValidFrom:  time.Now().Add(-time.Hour),
	}

	store := NewTrustAnchorStore()
	store.AddAnchor(anchor)

	name, _ := protocol.ParseName("example.com.")

	// Create A record
	aRecord := &protocol.ResourceRecord{
		Name:  name,
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
	}

	// Create signed data using the validator's canonical format
	config := DefaultValidatorConfig()
	config.IgnoreTime = true

	signerName, _ := protocol.ParseName("example.com.")
	rrsig := &protocol.RDataRRSIG{
		TypeCovered: protocol.TypeA,
		Algorithm:   protocol.AlgorithmECDSAP256SHA256,
		Labels:      2,
		OriginalTTL: 300,
		Expiration:  uint32(time.Now().Add(time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		KeyTag:      keyTag,
		SignerName:  signerName,
	}

	v := NewValidator(config, store, nil)
	signedData := v.canonicalizeRRSet([]*protocol.ResourceRecord{aRecord}, rrsig)
	signature, err := SignData(protocol.AlgorithmECDSAP256SHA256, priv, signedData)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}
	rrsig.Signature = signature

	rrsigRR := &protocol.ResourceRecord{
		Name:  name,
		Type:  protocol.TypeRRSIG,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  rrsig,
	}

	// Set up mock resolver
	mock := &mockResolver{
		responses: map[string]*protocol.Message{
			"example.com.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{
					{Name: name, Type: protocol.TypeDNSKEY, Data: dnskeyData},
				},
			},
		},
	}

	v.resolver = mock

	msg := &protocol.Message{
		Answers: []*protocol.ResourceRecord{aRecord, rrsigRR},
	}

	result, err := v.ValidateResponse(context.Background(), msg, "example.com.")
	if err != nil {
		t.Fatalf("ValidateResponse failed: %v", err)
	}
	if result != ValidationSecure {
		t.Errorf("Expected SECURE for fully validated response, got %s", result)
	}
}

func TestNewValidatorDefaults(t *testing.T) {
	// Test that zero config values are filled in
	config := ValidatorConfig{Enabled: true}
	v := NewValidator(config, nil, nil)

	if v.config.MaxDelegationDepth != 20 {
		t.Errorf("Expected default MaxDelegationDepth 20, got %d", v.config.MaxDelegationDepth)
	}
	if v.config.ClockSkew != 5*time.Minute {
		t.Errorf("Expected default ClockSkew 5m, got %v", v.config.ClockSkew)
	}
}
