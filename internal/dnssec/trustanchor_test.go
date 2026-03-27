package dnssec

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestTrustAnchorIsValid(t *testing.T) {
	tests := []struct {
		name     string
		anchor   *TrustAnchor
		expected bool
	}{
		{
			name: "valid anchor",
			anchor: &TrustAnchor{
				Zone:       ".",
				KeyTag:     20326,
				Algorithm:  protocol.AlgorithmRSASHA256,
				DigestType: 2,
				Digest:     []byte{0x01, 0x02, 0x03},
				ValidFrom:  time.Now().Add(-time.Hour),
			},
			expected: true,
		},
		{
			name: "not yet valid",
			anchor: &TrustAnchor{
				Zone:       ".",
				KeyTag:     20326,
				Algorithm:  protocol.AlgorithmRSASHA256,
				DigestType: 2,
				Digest:     []byte{0x01, 0x02, 0x03},
				ValidFrom:  time.Now().Add(time.Hour),
			},
			expected: false,
		},
		{
			name: "expired anchor",
			anchor: &TrustAnchor{
				Zone:       ".",
				KeyTag:     20326,
				Algorithm:  protocol.AlgorithmRSASHA256,
				DigestType: 2,
				Digest:     []byte{0x01, 0x02, 0x03},
				ValidFrom:  time.Now().Add(-2 * time.Hour),
				ValidUntil: func() *time.Time {
					t := time.Now().Add(-time.Hour)
					return &t
				}(),
			},
			expected: false,
		},
		{
			name: "valid with future expiration",
			anchor: &TrustAnchor{
				Zone:       ".",
				KeyTag:     20326,
				Algorithm:  protocol.AlgorithmRSASHA256,
				DigestType: 2,
				Digest:     []byte{0x01, 0x02, 0x03},
				ValidFrom:  time.Now().Add(-time.Hour),
				ValidUntil: func() *time.Time {
					t := time.Now().Add(time.Hour)
					return &t
				}(),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.anchor.IsValid()
			if result != tt.expected {
				t.Errorf("IsValid() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestTrustAnchorMatchesDS(t *testing.T) {
	digest := []byte{0xE0, 0x6D, 0x44, 0xB8}

	anchor := &TrustAnchor{
		Zone:       ".",
		KeyTag:     20326,
		Algorithm:  protocol.AlgorithmRSASHA256,
		DigestType: 2,
		Digest:     digest,
	}

	tests := []struct {
		name     string
		ds       *protocol.RDataDS
		expected bool
	}{
		{
			name: "matching DS",
			ds: &protocol.RDataDS{
				KeyTag:     20326,
				Algorithm:  protocol.AlgorithmRSASHA256,
				DigestType: 2,
				Digest:     digest,
			},
			expected: true,
		},
		{
			name: "wrong key tag",
			ds: &protocol.RDataDS{
				KeyTag:     12345,
				Algorithm:  protocol.AlgorithmRSASHA256,
				DigestType: 2,
				Digest:     digest,
			},
			expected: false,
		},
		{
			name: "wrong algorithm",
			ds: &protocol.RDataDS{
				KeyTag:     20326,
				Algorithm:  protocol.AlgorithmECDSAP256SHA256,
				DigestType: 2,
				Digest:     digest,
			},
			expected: false,
		},
		{
			name: "wrong digest",
			ds: &protocol.RDataDS{
				KeyTag:     20326,
				Algorithm:  protocol.AlgorithmRSASHA256,
				DigestType: 2,
				Digest:     []byte{0xFF, 0xFF, 0xFF, 0xFF},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := anchor.MatchesDS(tt.ds)
			if result != tt.expected {
				t.Errorf("MatchesDS() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestTrustAnchorStore(t *testing.T) {
	store := NewTrustAnchorStore()

	anchor1 := &TrustAnchor{
		Zone:       ".",
		KeyTag:     20326,
		Algorithm:  protocol.AlgorithmRSASHA256,
		DigestType: 2,
		Digest:     []byte{0x01, 0x02},
		ValidFrom:  time.Now().Add(-time.Hour),
	}

	anchor2 := &TrustAnchor{
		Zone:       "example.com.",
		KeyTag:     12345,
		Algorithm:  protocol.AlgorithmECDSAP256SHA256,
		DigestType: 2,
		Digest:     []byte{0x03, 0x04},
		ValidFrom:  time.Now().Add(-time.Hour),
	}

	// Test AddAnchor
	store.AddAnchor(anchor1)
	store.AddAnchor(anchor2)

	// Test GetAnchorsForZone
	rootAnchors := store.GetAnchorsForZone(".")
	if len(rootAnchors) != 1 {
		t.Errorf("Expected 1 root anchor, got %d", len(rootAnchors))
	}
	if rootAnchors[0].KeyTag != 20326 {
		t.Errorf("Expected KeyTag 20326, got %d", rootAnchors[0].KeyTag)
	}

	exampleAnchors := store.GetAnchorsForZone("example.com.")
	if len(exampleAnchors) != 1 {
		t.Errorf("Expected 1 example.com anchor, got %d", len(exampleAnchors))
	}

	// Test FindClosestAnchor
	anchor, remaining := store.FindClosestAnchor("www.example.com.")
	if anchor == nil {
		t.Fatal("Expected to find anchor for www.example.com")
	}
	if anchor.Zone != "example.com." {
		t.Errorf("Expected zone example.com., got %s", anchor.Zone)
	}
	if len(remaining) != 1 || remaining[0] != "www" {
		t.Errorf("Expected remaining ['www'], got %v", remaining)
	}

	// Test FindClosestAnchor for root
	anchor, remaining = store.FindClosestAnchor("nonexistent.tld.")
	if anchor == nil {
		t.Fatal("Expected to find root anchor")
	}
	if anchor.Zone != "." {
		t.Errorf("Expected root zone, got %s", anchor.Zone)
	}

	// Test GetAllZones
	zones := store.GetAllZones()
	if len(zones) != 2 {
		t.Errorf("Expected 2 zones, got %d", len(zones))
	}

	// Test RemoveAnchor
	store.RemoveAnchor("example.com.", 12345)
	exampleAnchors = store.GetAnchorsForZone("example.com.")
	if len(exampleAnchors) != 0 {
		t.Errorf("Expected 0 example.com anchors after removal, got %d", len(exampleAnchors))
	}

	// Test Clear
	store.Clear()
	rootAnchors = store.GetAnchorsForZone(".")
	if len(rootAnchors) != 0 {
		t.Errorf("Expected 0 anchors after clear, got %d", len(rootAnchors))
	}
}

func TestTrustAnchorStoreWithBuiltIn(t *testing.T) {
	store := NewTrustAnchorStoreWithBuiltIn()

	anchors := store.GetAnchorsForZone(".")
	if len(anchors) != 2 {
		t.Errorf("Expected 2 built-in root anchors, got %d", len(anchors))
	}

	// Check that the 2024 anchor exists
	var found2024 bool
	for _, a := range anchors {
		if a.KeyTag == 20326 {
			found2024 = true
			if !a.IsValid() {
				t.Error("2024 root anchor should be valid")
			}
		}
	}
	if !found2024 {
		t.Error("2024 root anchor not found")
	}
}

func TestParseTrustAnchorXML(t *testing.T) {
	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="12345" source=".">
  <Zone>.</Zone>
  <KeyDigest id="1" validFrom="2024-01-01T00:00:00+00:00">
    <KeyTag>20326</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
  </KeyDigest>
  <KeyDigest id="2" validFrom="2024-01-01T00:00:00+00:00" validUntil="2025-01-01T00:00:00+00:00">
    <KeyTag>12345</KeyTag>
    <Algorithm>13</Algorithm>
    <DigestType>2</DigestType>
    <Digest>0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF</Digest>
  </KeyDigest>
</TrustAnchor>`

	anchors, err := ParseTrustAnchorXML([]byte(xmlData))
	if err != nil {
		t.Fatalf("ParseTrustAnchorXML failed: %v", err)
	}

	if len(anchors) != 2 {
		t.Errorf("Expected 2 anchors, got %d", len(anchors))
	}

	// Check first anchor
	a1 := anchors[0]
	if a1.Zone != "." {
		t.Errorf("Expected zone '.', got '%s'", a1.Zone)
	}
	if a1.KeyTag != 20326 {
		t.Errorf("Expected KeyTag 20326, got %d", a1.KeyTag)
	}
	if a1.Algorithm != 8 {
		t.Errorf("Expected Algorithm 8, got %d", a1.Algorithm)
	}
	if a1.DigestType != 2 {
		t.Errorf("Expected DigestType 2, got %d", a1.DigestType)
	}

	expectedDigest := []byte{
		0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39,
		0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65, 0xD0, 0x84,
		0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34,
		0x57, 0x10, 0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D,
	}
	if !bytes.Equal(a1.Digest, expectedDigest) {
		t.Errorf("Digest mismatch: got %x, want %x", a1.Digest, expectedDigest)
	}
	if a1.ValidUntil != nil {
		t.Error("First anchor should not have ValidUntil")
	}

	// Check second anchor has ValidUntil
	a2 := anchors[1]
	if a2.ValidUntil == nil {
		t.Error("Second anchor should have ValidUntil")
	}
}

func TestCanonicalZone(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{".", "."},
		{"example.com", "example.com."},
		{"EXAMPLE.COM", "example.com."},
		{"example.com.", "example.com."},
		{"sub.EXAMPLE.com", "sub.example.com."},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := canonicalZone(tt.input)
			if result != tt.expected {
				t.Errorf("canonicalZone(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBytesEqual(t *testing.T) {
	tests := []struct {
		a        []byte
		b        []byte
		expected bool
	}{
		{[]byte{1, 2, 3}, []byte{1, 2, 3}, true},
		{[]byte{1, 2, 3}, []byte{1, 2, 4}, false},
		{[]byte{1, 2, 3}, []byte{1, 2}, false},
		{[]byte{}, []byte{}, true},
		{nil, []byte{}, false},
	}

	for _, tt := range tests {
		result := bytesEqual(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("bytesEqual(%v, %v) = %v, want %v", tt.a, tt.b, result, tt.expected)
		}
	}
}

func TestJoinLabels(t *testing.T) {
	tests := []struct {
		labels   []string
		expected string
	}{
		{[]string{}, "."},
		{[]string{"com"}, "com."},
		{[]string{"example", "com"}, "example.com."},
		{[]string{"www", "example", "com"}, "www.example.com."},
	}

	for _, tt := range tests {
		result := joinLabels(tt.labels)
		if result != tt.expected {
			t.Errorf("joinLabels(%v) = %q, want %q", tt.labels, result, tt.expected)
		}
	}
}

func TestToLower(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"EXAMPLE.COM", "example.com"},
		{"Example.Com", "example.com"},
		{"example.com", "example.com"},
		{"123-ABC", "123-abc"},
	}

	for _, tt := range tests {
		result := toLower(tt.input)
		if result != tt.expected {
			t.Errorf("toLower(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestTrustAnchorMatchesDNSKEY(t *testing.T) {
	// Create an anchor with a public key
	pubKey := []byte{0x01, 0x02, 0x03, 0x04}
	anchor := &TrustAnchor{
		Zone:      "example.com.",
		KeyTag:    12345,
		Algorithm: protocol.AlgorithmRSASHA256,
		PublicKey: pubKey,
		ValidFrom: time.Now().Add(-time.Hour),
	}

	// Create matching DNSKEY - need correct key tag
	dnskey := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmRSASHA256,
		PublicKey: pubKey,
	}

	// Calculate actual key tag and update anchor
	tag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)
	anchor.KeyTag = tag

	// Test matching
	result := anchor.MatchesDNSKEY(dnskey)
	if !result {
		t.Error("MatchesDNSKEY should return true for matching DNSKEY")
	}

	// Test with nil PublicKey in anchor
	anchor2 := &TrustAnchor{
		Zone:      "example.com.",
		KeyTag:    tag,
		Algorithm: protocol.AlgorithmRSASHA256,
		PublicKey: nil,
	}
	if anchor2.MatchesDNSKEY(dnskey) {
		t.Error("MatchesDNSKEY should return false when anchor has nil PublicKey")
	}

	// Test with wrong algorithm
	dnskey2 := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: pubKey,
	}
	if anchor.MatchesDNSKEY(dnskey2) {
		t.Error("MatchesDNSKEY should return false for wrong algorithm")
	}
}

func TestCalculateDSDigestSHA1(t *testing.T) {
	dnskey := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone,
		Protocol:  3,
		Algorithm: protocol.AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
	}

	digest, err := calculateDSDigestSHA1("example.com.", dnskey)
	if err != nil {
		t.Fatalf("calculateDSDigestSHA1 failed: %v", err)
	}
	// SHA-1 produces 20 bytes
	if len(digest) != 20 {
		t.Errorf("Expected 20 bytes for SHA-1 digest, got %d", len(digest))
	}
}

func TestCalculateDSDigestSHA384(t *testing.T) {
	dnskey := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone,
		Protocol:  3,
		Algorithm: protocol.AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
	}

	digest, err := calculateDSDigestSHA384("example.com.", dnskey)
	if err != nil {
		t.Fatalf("calculateDSDigestSHA384 failed: %v", err)
	}
	// SHA-384 produces 48 bytes
	if len(digest) != 48 {
		t.Errorf("Expected 48 bytes for SHA-384 digest, got %d", len(digest))
	}
}

func TestParseXMLTime(t *testing.T) {
	tests := []struct {
		input    string
		hasError bool
	}{
		{"2024-01-01T00:00:00+00:00", false},
		{"2024-12-31T23:59:59Z", false},
		{"invalid-time", true},
		{"", true},
	}

	for _, tt := range tests {
		_, err := parseXMLTime(tt.input)
		if tt.hasError && err == nil {
			t.Errorf("parseXMLTime(%q) should return error", tt.input)
		}
		if !tt.hasError && err != nil {
			t.Errorf("parseXMLTime(%q) should not return error: %v", tt.input, err)
		}
	}
}

func TestDSFromDNSKEY(t *testing.T) {
	dnskey := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}

	// Test SHA-256 (type 2)
	ds, err := DSFromDNSKEY("example.com.", dnskey, 2)
	if err != nil {
		t.Fatalf("DSFromDNSKEY failed: %v", err)
	}
	if ds.Algorithm != protocol.AlgorithmRSASHA256 {
		t.Errorf("Algorithm mismatch: got %d", ds.Algorithm)
	}
	if ds.DigestType != 2 {
		t.Errorf("DigestType mismatch: got %d", ds.DigestType)
	}
	if len(ds.Digest) != 32 { // SHA-256 = 32 bytes
		t.Errorf("Expected 32 byte digest, got %d", len(ds.Digest))
	}

	// Test SHA-1 (type 1)
	ds1, err := DSFromDNSKEY("example.com.", dnskey, 1)
	if err != nil {
		t.Fatalf("DSFromDNSKEY(SHA1) failed: %v", err)
	}
	if len(ds1.Digest) != 20 { // SHA-1 = 20 bytes
		t.Errorf("Expected 20 byte digest for SHA-1, got %d", len(ds1.Digest))
	}

	// Test SHA-384 (type 4)
	ds384, err := DSFromDNSKEY("example.com.", dnskey, 4)
	if err != nil {
		t.Fatalf("DSFromDNSKEY(SHA384) failed: %v", err)
	}
	if len(ds384.Digest) != 48 { // SHA-384 = 48 bytes
		t.Errorf("Expected 48 byte digest for SHA-384, got %d", len(ds384.Digest))
	}

	// Test unsupported digest type
	_, err = DSFromDNSKEY("example.com.", dnskey, 99)
	if err == nil {
		t.Error("Expected error for unsupported digest type")
	}
}

func TestTrustAnchorStoreLoadFromFile(t *testing.T) {
	// Create a temporary XML file
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="test" source="test">
  <Zone>test.example.</Zone>
  <KeyDigest id="1" validFrom="2024-01-01T00:00:00+00:00">
    <KeyTag>12345</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
  </KeyDigest>
</TrustAnchor>`

	tmpFile, err := os.CreateTemp("", "trust-anchor-*.xml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(xmlContent); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	// Test LoadFromFile
	store := NewTrustAnchorStore()
	err = store.LoadFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	// Verify anchor was loaded
	anchors := store.GetAnchorsForZone("test.example.")
	if len(anchors) != 1 {
		t.Errorf("Expected 1 anchor, got %d", len(anchors))
	}
	if anchors[0].KeyTag != 12345 {
		t.Errorf("Expected KeyTag 12345, got %d", anchors[0].KeyTag)
	}

	// Test loading non-existent file
	err = store.LoadFromFile("/nonexistent/file.xml")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestTrustAnchorStoreLoadFromFileInvalidXML(t *testing.T) {
	// Create a temporary file with invalid XML
	tmpFile, err := os.CreateTemp("", "trust-anchor-invalid-*.xml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString("this is not valid XML"); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	store := NewTrustAnchorStore()
	err = store.LoadFromFile(tmpFile.Name())
	if err == nil {
		t.Error("Expected error for invalid XML")
	}
}

func TestTrustAnchorStoreLoadFromFileInvalidDigest(t *testing.T) {
	// Create a temporary XML file with invalid hex digest
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="test" source="test">
  <Zone>test.example.</Zone>
  <KeyDigest id="1" validFrom="2024-01-01T00:00:00+00:00">
    <KeyTag>12345</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>NOT-VALID-HEX</Digest>
  </KeyDigest>
</TrustAnchor>`

	tmpFile, err := os.CreateTemp("", "trust-anchor-baddigest-*.xml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(xmlContent); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	store := NewTrustAnchorStore()
	err = store.LoadFromFile(tmpFile.Name())
	if err == nil {
		t.Error("Expected error for invalid hex digest")
	}
}

func TestTrustAnchorStoreLoadFromFileInvalidTime(t *testing.T) {
	// Create a temporary XML file with invalid time
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="test" source="test">
  <Zone>test.example.</Zone>
  <KeyDigest id="1" validFrom="invalid-time">
    <KeyTag>12345</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
  </KeyDigest>
</TrustAnchor>`

	tmpFile, err := os.CreateTemp("", "trust-anchor-badtime-*.xml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(xmlContent); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	store := NewTrustAnchorStore()
	err = store.LoadFromFile(tmpFile.Name())
	if err == nil {
		t.Error("Expected error for invalid time format")
	}
}
