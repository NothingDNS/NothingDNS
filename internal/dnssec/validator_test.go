package dnssec

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strconv"
	"strings"
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
	resp, ok := m.responses[key]
	if !ok {
		// Return empty response for unknown queries
		return protocol.NewMessage(protocol.Header{
			ID:      1,
			Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
			QDCount: 1,
		}), nil
	}
	// Hand out a private copy: production resolvers return solely-owned
	// messages, and the fetch path now Releases what Query returns. The
	// stored fixture must survive repeated queries and must not have its
	// pooled *Name objects recycled out from under other fixtures.
	return cloneTestMessage(resp), nil
}

// cloneTestMessage builds a detached copy of a stored fixture message.
// Record shells and Names are duplicated (both are pooled and recycled by
// Release); RData pointers are shared — the DNSSEC rdata types these
// fixtures carry (DNSKEY, RRSIG, DS, NSEC3PARAM) have no case in
// protocol.releaseRData, so Release never pools or mutates them.
func cloneTestMessage(in *protocol.Message) *protocol.Message {
	out := protocol.NewMessage(in.Header)
	for _, q := range in.Questions {
		qc := &protocol.Question{QType: q.QType, QClass: q.QClass}
		if q.Name != nil {
			qc.Name = q.Name.Copy()
		}
		out.AddQuestion(qc)
	}
	for _, rr := range in.Answers {
		out.Answers = append(out.Answers, detachRecord(rr))
	}
	for _, rr := range in.Authorities {
		out.Authorities = append(out.Authorities, detachRecord(rr))
	}
	for _, rr := range in.Additionals {
		out.Additionals = append(out.Additionals, detachRecord(rr))
	}
	return out
}

// makeDNSKEYRRSIG signs a zone's DNSKEY RRset with its (KSK) private key and
// returns the RRSIG record. buildChain now requires the DNSKEY RRset to be
// self-signed by the DS/anchor-matched KSK, so mock DNSKEY responses must carry
// this signature.
func makeDNSKEYRRSIG(t *testing.T, zone string, priv *ecdsa.PrivateKey, dnskey *protocol.RDataDNSKEY, dnskeyRRs []*protocol.ResourceRecord) *protocol.ResourceRecord {
	t.Helper()
	signer := NewSigner(zone, DefaultSignerConfig())
	sk := &SigningKey{
		PrivateKey: &PrivateKey{Algorithm: dnskey.Algorithm, Key: priv},
		DNSKEY:     dnskey,
		KeyTag:     protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey),
		IsKSK:      true,
	}
	now := uint32(time.Now().Unix())
	rrsig, err := signer.SignRRSet(dnskeyRRs, sk, now-3600, now+3600)
	if err != nil {
		t.Fatalf("signing DNSKEY RRset for %s: %v", zone, err)
	}
	return rrsig
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
	_, _, err = v.buildChain(context.Background(), anchor, []string{"example"})
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
	records, _, err := v.fetchDS(context.Background(), "example.com.")
	if err == nil {
		t.Error("Expected error with nil resolver")
	}
	if records != nil {
		t.Error("Records should be nil with nil resolver")
	}

	// Test with mock resolver
	mock := &mockResolver{responses: make(map[string]*protocol.Message)}
	v.resolver = mock

	records, _, err = v.fetchDS(context.Background(), "example.com.")
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

func TestValidatorClockSkewSeconds(t *testing.T) {
	tests := []struct {
		name      string
		clockSkew time.Duration
		want      uint32
	}{
		{name: "negative", clockSkew: -5 * time.Minute, want: 0},
		{name: "zero", clockSkew: 0, want: 0},
		{name: "sub_second", clockSkew: 500 * time.Millisecond, want: 0},
		{name: "whole_seconds", clockSkew: 5 * time.Minute, want: 300},
		{name: "saturates_before_uint32_wrap", clockSkew: time.Duration(1<<63 - 1), want: ^uint32(0)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := validatorClockSkewSeconds(tc.clockSkew); got != tc.want {
				t.Fatalf("validatorClockSkewSeconds(%v) = %d, want %d", tc.clockSkew, got, tc.want)
			}
		})
	}
}

func TestRRSIGTimeValid(t *testing.T) {
	tests := []struct {
		name       string
		inception  uint32
		expiration uint32
		now        uint32
		skew       uint32
		want       bool
	}{
		{name: "current within validity", inception: 90, expiration: 110, now: 100, want: true},
		{name: "expired beyond skew", inception: 90, expiration: 97, now: 100, skew: 2, want: false},
		{name: "expiration within skew", inception: 90, expiration: 98, now: 100, skew: 2, want: true},
		{name: "future inception within skew", inception: 102, expiration: 110, now: 100, skew: 2, want: true},
		{name: "future inception beyond skew", inception: 103, expiration: 110, now: 100, skew: 2, want: false},
		{name: "valid across uint32 wrap", inception: ^uint32(0) - 1, expiration: 5, now: 1, want: true},
		{name: "expired across uint32 wrap beyond skew", inception: ^uint32(0) - 10, expiration: ^uint32(0) - 1, now: 3, skew: 2, want: false},
		{name: "expiration across uint32 wrap within skew", inception: ^uint32(0) - 10, expiration: ^uint32(0), now: 1, skew: 2, want: true},
		{name: "future inception across uint32 wrap within skew", inception: 0, expiration: 10, now: ^uint32(0), skew: 1, want: true},
		{name: "future inception across uint32 wrap beyond skew", inception: 1, expiration: 10, now: ^uint32(0), skew: 1, want: false},
		{name: "huge skew preserves previous permissive behavior", inception: 1, expiration: 2, now: 100, skew: 1 << 31, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rrsigTimeValid(tc.inception, tc.expiration, tc.now, tc.skew); got != tc.want {
				t.Fatalf("rrsigTimeValid(inception=%d, expiration=%d, now=%d, skew=%d) = %v, want %v",
					tc.inception, tc.expiration, tc.now, tc.skew, got, tc.want)
			}
		})
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
	result, err := v.canonicalizeRR(rr, 3600, 255)
	if err != nil {
		t.Fatalf("canonicalizeRR: %v", err)
	}
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
	signerName, _ := protocol.ParseName("example.com.")

	rrSet := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
		{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{5, 6, 7, 8}}},
	}

	rrsig := &protocol.RDataRRSIG{
		TypeCovered: protocol.TypeA,
		OriginalTTL: 3600,
		SignerName:  signerName,
	}

	result, err := v.canonicalizeRRSet(rrSet, rrsig)
	if err != nil {
		t.Fatalf("canonicalizeRRSet: %v", err)
	}
	if len(result) == 0 {
		t.Error("canonicalizeRRSet should return non-empty result")
	}
}

func TestCanonicalizeRRRejectsOversizedRDATA(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)
	name, _ := protocol.ParseName("oversized.example.com.")
	rr := &protocol.ResourceRecord{
		Name:  name,
		Type:  65000,
		Class: protocol.ClassIN,
		TTL:   300,
		Data: &protocol.RDataRaw{
			TypeVal: 65000,
			Data:    make([]byte, 0x10000),
		},
	}

	if _, err := v.canonicalizeRR(rr, 300, 255); err == nil {
		t.Fatal("expected oversized RDATA to fail")
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

	// Set up mock resolver that returns the DNSKEY + its self-signature
	rootName, _ := protocol.ParseName("example.com.")
	dnskeyRR := &protocol.ResourceRecord{Name: rootName, Type: protocol.TypeDNSKEY, Data: dnskeyData}
	dnskeySig := makeDNSKEYRRSIG(t, "example.com.", privKey, dnskeyData, []*protocol.ResourceRecord{dnskeyRR})
	mock := &mockResolver{
		responses: map[string]*protocol.Message{
			"example.com.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{dnskeyRR, dnskeySig},
			},
		},
	}

	config := DefaultValidatorConfig()
	config.Enabled = true
	v := NewValidator(config, store, mock)

	// Test buildChain with no remaining labels
	chain, _, err := v.buildChain(context.Background(), anchor, []string{})
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

func TestBuildChain_RejectsInjectedDNSKEY(t *testing.T) {
	// Security regression (audit CRITICAL): an on-path attacker who appends
	// their own DNSKEY to the fetched RRset must NOT have it trusted. The KSK's
	// RRSIG covers only the genuine RRset, so once the attacker's key is added
	// the self-signature no longer validates and the chain must be rejected.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &privKey.PublicKey}
	keyData, _ := packECDSAPublicKey(pub)
	dnskeyData := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: keyData,
	}
	anchor := &TrustAnchor{
		Zone:       "example.com.",
		KeyTag:     protocol.CalculateKeyTag(dnskeyData.Flags, dnskeyData.Algorithm, dnskeyData.PublicKey),
		Algorithm:  protocol.AlgorithmECDSAP256SHA256,
		DigestType: 2,
		Digest:     calculateDSDigestFromDNSKEY("example.com.", dnskeyData, 2),
		ValidFrom:  time.Now().Add(-time.Hour),
	}
	store := NewTrustAnchorStore()
	store.AddAnchor(anchor)

	rootName, _ := protocol.ParseName("example.com.")
	legitRR := &protocol.ResourceRecord{Name: rootName, Type: protocol.TypeDNSKEY, Data: dnskeyData}
	// RRSIG over ONLY the genuine key — exactly what a real signer publishes.
	sig := makeDNSKEYRRSIG(t, "example.com.", privKey, dnskeyData, []*protocol.ResourceRecord{legitRR})

	// Attacker forges and injects their own DNSKEY into the served RRset.
	evilPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	evilPub := &PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &evilPriv.PublicKey}
	evilData, _ := packECDSAPublicKey(evilPub)
	evilRR := &protocol.ResourceRecord{Name: rootName, Type: protocol.TypeDNSKEY, Data: &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: evilData,
	}}

	mock := &mockResolver{
		responses: map[string]*protocol.Message{
			"example.com.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{legitRR, evilRR, sig},
			},
		},
	}
	config := DefaultValidatorConfig()
	config.Enabled = true
	v := NewValidator(config, store, mock)

	if _, _, err := v.buildChain(context.Background(), anchor, []string{}); err == nil {
		t.Fatal("buildChain accepted a DNSKEY RRset with an injected key — DNSSEC bypass not prevented")
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

	_, _, err := v.buildChain(context.Background(), anchor, []string{})
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

	_, _, err := v.buildChain(context.Background(), anchor, []string{})
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

	parentDnskeyRR := &protocol.ResourceRecord{Name: parentName, Type: protocol.TypeDNSKEY, Data: parentDnskey}
	parentDnskeySig := makeDNSKEYRRSIG(t, "com.", privKey, parentDnskey, []*protocol.ResourceRecord{parentDnskeyRR})
	childDnskeyRR := &protocol.ResourceRecord{Name: childName, Type: protocol.TypeDNSKEY, Data: childDnskey}
	childDnskeySig := makeDNSKEYRRSIG(t, "example.", childPrivKey, childDnskey, []*protocol.ResourceRecord{childDnskeyRR})

	// The DS RRset lives in the parent zone, so it must carry an RRSIG by
	// the parent's key — buildChain rejects unsigned DS RRsets as forgeable.
	childDSRR := &protocol.ResourceRecord{
		Name: childName,
		Type: protocol.TypeDS,
		Data: &protocol.RDataDS{
			KeyTag:     childKeyTag,
			Algorithm:  protocol.AlgorithmECDSAP256SHA256,
			DigestType: 2,
			Digest:     childDigest,
		},
	}
	childDSSig := makeDNSKEYRRSIG(t, "com.", privKey, parentDnskey, []*protocol.ResourceRecord{childDSRR})

	mock := &mockResolver{
		responses: map[string]*protocol.Message{
			"com.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{parentDnskeyRR, parentDnskeySig},
			},
			"example.|" + strconv.Itoa(int(protocol.TypeDS)): {
				Answers: []*protocol.ResourceRecord{childDSRR, childDSSig},
			},
			"example.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{childDnskeyRR, childDnskeySig},
			},
		},
	}

	store := NewTrustAnchorStore()
	store.AddAnchor(anchor)

	config := DefaultValidatorConfig()
	v := NewValidator(config, store, mock)

	// Build chain with remaining label "example"
	chain, _, err := v.buildChain(context.Background(), anchor, []string{"example"})
	if err != nil {
		t.Fatalf("buildChain with delegation failed: %v", err)
	}
	if len(chain) != 2 {
		t.Errorf("Expected 2 chain links, got %d", len(chain))
	}
}

// TestBuildChain_EmptyDSNoProof_IsDowngradeAttack pins SECURITY-REPORT.md
// H-2: an empty DS answer with no NSEC/NSEC3 denial proof (and no
// RRSIG over that proof) must NOT be silently accepted as a "genuine
// unsigned delegation." Pre-fix, buildChain treated len(dsRecords)==0
// as Insecure outright — exactly the on-path DS-strip downgrade
// attack DNSSEC was meant to prevent. Post-fix the chain builder
// returns an error containing "downgrade-attack guard".
//
// (Historical name: this test was TestBuildChainUnsignedDelegation
// and asserted the buggy behaviour. The mock here is identical to
// the original — empty Answer for the DS query, no Authority NSEC,
// no RRSIG — because that mock IS the downgrade vector.)
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
	parentDnskeyRR := &protocol.ResourceRecord{Name: parentName, Type: protocol.TypeDNSKEY, Data: dnskeyData}
	parentDnskeySig := makeDNSKEYRRSIG(t, "com.", privKey, dnskeyData, []*protocol.ResourceRecord{parentDnskeyRR})
	mock := &mockResolver{
		responses: map[string]*protocol.Message{
			"com.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{parentDnskeyRR, parentDnskeySig},
			},
			// example.com. DS query returns empty (unsigned delegation)
		},
	}

	store := NewTrustAnchorStore()
	store.AddAnchor(anchor)

	config := DefaultValidatorConfig()
	v := NewValidator(config, store, mock)

	// Build chain — must reject the empty-DS response because the
	// parent supplied no authenticated denial proof. Silently
	// breaking the chain here is the H-2 downgrade vector.
	_, _, err = v.buildChain(context.Background(), anchor, []string{"example"})
	if err == nil {
		t.Fatal("expected downgrade-attack guard to reject empty DS with no denial proof, got nil error")
	}
	if !strings.Contains(err.Error(), "downgrade-attack guard") {
		t.Errorf("expected error to mention downgrade-attack guard, got: %v", err)
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
	_, _, err = v.buildChain(context.Background(), anchor, remaining)
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

	// Downgrade protection: the chain proves example.com. is SIGNED, and the
	// queried name's own RRset (example.com. A) arrives with NO RRSIG. Even
	// with RequireDNSSEC=false this must be BOGUS, not SECURE — a stripped
	// signature on the queried RRset of a signed zone is a downgrade attack.
	// (Insecure subtrees never reach validateMessage; ValidateResponse
	// short-circuits them to ValidationInsecure.)
	config := DefaultValidatorConfig()
	config.RequireDNSSEC = false
	v2 := NewValidator(config, nil, nil)

	msg := &protocol.Message{
		Answers: []*protocol.ResourceRecord{aRecord},
	}
	result := v2.validateMessage(context.Background(), msg, "example.com.", chain)
	if result != ValidationBogus {
		t.Errorf("Expected BOGUS for unsigned queried RRset in a signed zone (downgrade), got %s", result)
	}
}

// TestValidateMessage_LenientForNonQueriedOwner verifies the downgrade check is
// scoped to the QUERIED name. An unsigned RRset owned by a different name (e.g.
// a CNAME target served by another/unsigned zone) must NOT turn the whole
// response Bogus when RequireDNSSEC is off — otherwise legitimate CNAME-to-
// unsigned resolution would break across the DNS. But since that out-of-bailiwick
// RRset is not authenticated by this chain, the message is INSECURE (AD=0), not
// Secure — the validator must not stamp AD=1 over unvalidated data.
func TestValidateMessage_LenientForNonQueriedOwner(t *testing.T) {
	zoneName, _ := protocol.ParseName("example.com.")
	chain := []*chainLink{{
		zone:      "example.com.",
		dnsKeys:   []*protocol.ResourceRecord{{Name: zoneName, Type: protocol.TypeDNSKEY, Data: &protocol.RDataDNSKEY{}}},
		validated: true,
	}}

	otherName, _ := protocol.ParseName("target.elsewhere.net.")
	msg := &protocol.Message{
		Answers: []*protocol.ResourceRecord{{
			Name:  otherName,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{5, 6, 7, 8}},
		}},
	}

	config := DefaultValidatorConfig()
	config.RequireDNSSEC = false
	v := NewValidator(config, nil, nil)

	// Queried name is example.com.; the answer's only RRset is owned by
	// elsewhere.net. (outside the signed zone) and unsigned — stay lenient (not
	// Bogus) but do NOT claim AD: the correct verdict is INSECURE.
	if result := v.validateMessage(context.Background(), msg, "example.com.", chain); result != ValidationInsecure {
		t.Errorf("expected INSECURE (unauthenticated out-of-bailiwick data, no AD), got %s", result)
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
	signedData, err := v.canonicalizeRRSet([]*protocol.ResourceRecord{aRecord}, rrsig)
	if err != nil {
		t.Fatalf("canonicalizeRRSet: %v", err)
	}
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
	signedData, err := v.canonicalizeRRSet(rrSet, rrsig)
	if err != nil {
		t.Fatalf("canonicalizeRRSet: %v", err)
	}
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

	signedData, err := v.canonicalizeRRSet(rrSet, rrsig)
	if err != nil {
		t.Fatalf("canonicalizeRRSet: %v", err)
	}
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

	// owner == queryName and the type is NOT in the bitmap: the name exists
	// but the type doesn't — a valid NoData proof (RFC 4035 §3.1.3.1).
	result := v.validateNSEC("a.example.com.", "a.example.com.", protocol.TypeMX, nsec)
	if !result {
		t.Error("validateNSEC should accept an exact-match NSEC whose bitmap lacks the queried type (NoData proof)")
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

// TestValidateNegativeResponseWithNSECProvesNonExistence regresses
// SECURITY-REPORT-2026-05-23 NEW-H2: validateNegativeResponse must
// REJECT NSEC denial proofs that lack a verified RRSIG. The mock
// below supplies two well-formed NSEC range claims but no RRSIG
// and an empty-key chainLink — exactly the on-path-forgery shape
// the fix closes. Pre-fix this test asserted ValidationSecure
// (embedded the downgrade vector); post-fix it correctly asserts
// ValidationBogus.
//
// A separate "with valid signatures" test would need a full signed
// fixture (RRSIG generation, DNSKEY chain) — tracked as follow-up.
func TestValidateNegativeResponseWithNSECProvesNonExistence(t *testing.T) {
	// RFC 4035 §5.4 requires TWO NSEC proofs for NXDOMAIN: one that covers
	// the queried name AND one that covers the closest-encloser's wildcard
	// "*.<encloser>". A single NSEC is intentionally insufficient — the
	// validator was previously vulnerable to single-NSEC replay forgeries.
	//
	// Provide both proofs:
	//   NSEC 1 (name-cover):
	//     owner    a.example.com.
	//     next     c.example.com.
	//     covers   b.example.com. (queried name)
	//   NSEC 2 (wildcard-cover):
	//     owner    example.com.
	//     next     a.example.com.
	//     covers   *.example.com.  ('*' = 0x2A sorts below 'a' = 0x61)
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	nextA, _ := protocol.ParseName("c.example.com.")
	nsecName, _ := protocol.ParseName("a.example.com.")
	nsecName1 := &protocol.RDataNSEC{NextDomain: nextA, TypeBitMap: []uint16{protocol.TypeNS}}

	nextW, _ := protocol.ParseName("a.example.com.")
	nsecWild, _ := protocol.ParseName("example.com.")
	nsecName2 := &protocol.RDataNSEC{NextDomain: nextW, TypeBitMap: []uint16{protocol.TypeSOA, protocol.TypeNS}}

	rr1 := &protocol.ResourceRecord{Name: nsecName, Type: protocol.TypeNSEC, Class: protocol.ClassIN, Data: nsecName1}
	rr2 := &protocol.ResourceRecord{Name: nsecWild, Type: protocol.TypeNSEC, Class: protocol.ClassIN, Data: nsecName2}

	questionName, _ := protocol.ParseName("b.example.com.")
	msg := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
		Authorities: []*protocol.ResourceRecord{rr1, rr2},
		Questions: []*protocol.Question{
			{Name: questionName, QType: protocol.TypeA},
		},
	}

	// chainLink with no DNSKEYs — authenticatedDenialRRs cannot
	// validate any RRSIG, so every NSEC in Authority is dropped.
	chain := []*chainLink{{zone: "example.com.", validated: true}}
	result := v.validateNegativeResponse(msg, "b.example.com.", chain)
	if result != ValidationBogus {
		t.Errorf("NEW-H2 regression: unsigned NSEC denial accepted as %s, expected BOGUS", result)
	}
}

// TestValidateNegativeResponse_SingleNSECRejected confirms the regression
// fix: a single NSEC that only covers the name (no wildcard proof) must NOT
// be accepted as authenticated NXDOMAIN.
func TestValidateNegativeResponse_SingleNSECRejected(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

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
	if result := v.validateNegativeResponse(msg, "b.example.com.", chain); result != ValidationBogus {
		t.Errorf("single NSEC must NOT authenticate NXDOMAIN (RFC 4035 §5.4); got %s", result)
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

func TestAuthenticatedDenialRRsSkipsMalformedRecords(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)
	nsecOwner, _ := protocol.ParseName("a.example.com.")
	msg := &protocol.Message{
		Authorities: []*protocol.ResourceRecord{
			nil,
			{Type: protocol.TypeNSEC},
			{
				Name:  nsecOwner,
				Type:  protocol.TypeNSEC,
				Class: protocol.ClassIN,
				Data:  &protocol.RDataNSEC{},
			},
		},
	}
	chain := []*chainLink{
		{
			zone: "example.com.",
			dnsKeys: []*protocol.ResourceRecord{
				nil,
				{Type: protocol.TypeDNSKEY},
			},
		},
	}

	if got := v.authenticatedDenialRRs(msg, chain); len(got) != 0 {
		t.Fatalf("authenticatedDenialRRs returned %d records, want 0", len(got))
	}
}

func TestFindRRSIGSkipsMalformedRecords(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)
	if got := v.findRRSIG([]*protocol.ResourceRecord{
		nil,
		{Type: protocol.TypeRRSIG, Data: &protocol.RDataRRSIG{TypeCovered: protocol.TypeA}},
	}, "example.com.", protocol.TypeA); got != nil {
		t.Fatalf("findRRSIG returned %+v, want nil", got)
	}
}

func TestValidateNSEC3ClosestEncloserRejectsMalformedRecords(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)
	owner, _ := protocol.ParseName("abc.example.com.")
	valid := func() *protocol.ResourceRecord {
		return &protocol.ResourceRecord{
			Name:  owner,
			Type:  protocol.TypeNSEC3,
			Class: protocol.ClassIN,
			Data: &protocol.RDataNSEC3{
				HashAlgorithm: protocol.NSEC3HashSHA1,
				NextHashed:    []byte{0x01},
			},
		}
	}
	var typedNil *protocol.RDataNSEC3

	tests := []struct {
		name string
		rrs  []*protocol.ResourceRecord
	}{
		{name: "nil record", rrs: []*protocol.ResourceRecord{nil}},
		{name: "nil owner", rrs: []*protocol.ResourceRecord{{Type: protocol.TypeNSEC3, Data: &protocol.RDataNSEC3{HashAlgorithm: protocol.NSEC3HashSHA1}}}},
		{name: "typed nil data", rrs: []*protocol.ResourceRecord{{Name: owner, Type: protocol.TypeNSEC3, Data: typedNil}}},
		{name: "wrong data", rrs: []*protocol.ResourceRecord{{Name: owner, Type: protocol.TypeNSEC3, Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}}}},
		{name: "later nil record", rrs: []*protocol.ResourceRecord{valid(), nil}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := v.validateNSEC3ClosestEncloser("www.example.com.", tc.rrs); got {
				t.Fatal("validateNSEC3ClosestEncloser returned true for malformed records")
			}
		})
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
	records, _, err := v.fetchDS(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("fetchDS failed: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("Expected 1 DS record, got %d", len(records))
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
	signedData, err := v.canonicalizeRRSet([]*protocol.ResourceRecord{aRecord}, rrsig)
	if err != nil {
		t.Fatalf("canonicalizeRRSet: %v", err)
	}
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

	// Set up mock resolver. The DNSKEY RRset must carry its self-signature so
	// the chain can authenticate it (DS proves only the KSK).
	// Note: dnskeyRR gets its own Name — Query results are now Released by
	// the fetch path, which recycles each record's pooled *Name; aRecord and
	// rrsigRR (the response message) must not share it.
	dnskeyName, _ := protocol.ParseName("example.com.")
	dnskeyRR := &protocol.ResourceRecord{Name: dnskeyName, Type: protocol.TypeDNSKEY, Data: dnskeyData}
	dnskeySig := makeDNSKEYRRSIG(t, "example.com.", privKey, dnskeyData, []*protocol.ResourceRecord{dnskeyRR})
	mock := &mockResolver{
		responses: map[string]*protocol.Message{
			"example.com.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {
				Answers: []*protocol.ResourceRecord{dnskeyRR, dnskeySig},
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

// ============================================================================
// VULN-040: KeyTrap (CVE-2023-50387 family) caps
// ============================================================================

// validateMessage must reject responses with more signed RRsets than
// maxRRsetsValidated, regardless of whether signatures are required.
func TestValidateMessage_CapsRRsets_VULN040(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)
	chain := []*chainLink{{zone: "example.com.", validated: true}}

	// Build a message whose Answer section contains maxRRsetsValidated + 1
	// distinct RRsets. Each (name, type) pair is its own RRset, so naming
	// "a0.ex.", "a1.ex.", ... with type A yields the required count after
	// groupRecordsByRRSet.
	msg := &protocol.Message{}
	for i := 0; i <= maxRRsetsValidated; i++ {
		name, _ := protocol.ParseName("a" + strconv.Itoa(i) + ".ex.")
		msg.Answers = append(msg.Answers, &protocol.ResourceRecord{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   60,
			Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
		})
	}

	result := v.validateMessage(context.Background(), msg, "example.com.", chain)
	if result != ValidationBogus {
		t.Errorf("validateMessage(%d RRsets) = %v, want BOGUS (KeyTrap cap)",
			maxRRsetsValidated+1, result)
	}

	// Sanity: at exactly the cap, the same message shape does not hit the
	// guard (unsigned RRsets skipped when RequireDNSSEC=false).
	msg2 := &protocol.Message{}
	for i := 0; i < maxRRsetsValidated; i++ {
		name, _ := protocol.ParseName("b" + strconv.Itoa(i) + ".ex.")
		msg2.Answers = append(msg2.Answers, &protocol.ResourceRecord{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   60,
			Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
		})
	}
	if got := v.validateMessage(context.Background(), msg2, "example.com.", chain); got == ValidationBogus {
		t.Errorf("validateMessage(%d RRsets) = BOGUS, want non-BOGUS (cap should not trigger at exactly the limit)",
			maxRRsetsValidated)
	}
}

// validateNegativeResponse must stop scanning NSEC/NSEC3 records after
// maxNSECValidations and return BOGUS, even if a later record would match.
func TestValidateNegativeResponse_CapsNSEC_VULN040(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)

	// Pack Authority with (maxNSECValidations + 1) bogus NSEC records whose
	// owner/NextDomain ranges do not cover the query name, then append one
	// NSEC record that would match. A correct validator without the cap
	// would reach the matching one and return SECURE; with the cap it aborts.
	msg := &protocol.Message{}
	qname, _ := protocol.ParseName("victim.example.com.")
	q := &protocol.Question{
		Name:   qname,
		QType:  protocol.TypeAAAA,
		QClass: protocol.ClassIN,
	}
	msg.Questions = append(msg.Questions, q)

	bogusOwner, _ := protocol.ParseName("zzzz.other.com.")
	bogusNext, _ := protocol.ParseName("zzzz1.other.com.")
	for i := 0; i < maxNSECValidations+1; i++ {
		msg.Authorities = append(msg.Authorities, &protocol.ResourceRecord{
			Name:  bogusOwner,
			Type:  protocol.TypeNSEC,
			Class: protocol.ClassIN,
			TTL:   60,
			Data:  &protocol.RDataNSEC{NextDomain: bogusNext, TypeBitMap: nil},
		})
	}

	// Append a would-match NSEC: owner is the query name itself (exact match)
	// and the type bitmap does not include the queried type (NODATA proof).
	matchOwner, _ := protocol.ParseName("victim.example.com.")
	matchNext, _ := protocol.ParseName("zzzz.victim.example.com.")
	msg.Authorities = append(msg.Authorities, &protocol.ResourceRecord{
		Name:  matchOwner,
		Type:  protocol.TypeNSEC,
		Class: protocol.ClassIN,
		TTL:   60,
		Data:  &protocol.RDataNSEC{NextDomain: matchNext, TypeBitMap: nil},
	})

	result := v.validateNegativeResponse(msg, "victim.example.com.", nil)
	if result != ValidationBogus {
		t.Errorf("validateNegativeResponse with %d+1 NSEC records before a match = %v, want BOGUS (cap aborted scan)",
			maxNSECValidations, result)
	}
}

// validateDelegation must bail out when the DS × DNSKEY cross-product exceeds
// maxDelegationOps, even if a legitimate match exists past the cap.
