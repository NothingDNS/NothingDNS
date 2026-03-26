package transfer

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestKeyStore(t *testing.T) {
	ks := NewKeyStore()

	key := &TSIGKey{
		Name:      "test-key.",
		Algorithm: HmacSHA256,
		Secret:    []byte("test-secret-key-data"),
	}

	// Test AddKey and GetKey
	ks.AddKey(key)

	retrieved, ok := ks.GetKey("test-key.")
	if !ok {
		t.Fatal("Expected to find key")
	}

	if retrieved.Name != key.Name {
		t.Errorf("Expected name %s, got %s", key.Name, retrieved.Name)
	}

	if retrieved.Algorithm != key.Algorithm {
		t.Errorf("Expected algorithm %s, got %s", key.Algorithm, retrieved.Algorithm)
	}

	// Test case-insensitive lookup
	retrieved2, ok := ks.GetKey("TEST-KEY.")
	if !ok {
		t.Fatal("Expected case-insensitive lookup to work")
	}

	if retrieved2.Name != key.Name {
		t.Errorf("Case-insensitive lookup failed")
	}

	// Test RemoveKey
	ks.RemoveKey("test-key.")

	_, ok = ks.GetKey("test-key.")
	if ok {
		t.Error("Expected key to be removed")
	}
}

func TestParseTSIGKey(t *testing.T) {
	// Base64 encoded secret
	secretB64 := "c2VjcmV0LWtleS1kYXRh" // "secret-key-data"

	key, err := ParseTSIGKey("example.com.", HmacSHA256, secretB64)
	if err != nil {
		t.Fatalf("ParseTSIGKey() error = %v", err)
	}

	if key.Name != "example.com." {
		t.Errorf("Expected name example.com., got %s", key.Name)
	}

	if key.Algorithm != HmacSHA256 {
		t.Errorf("Expected algorithm %s, got %s", HmacSHA256, key.Algorithm)
	}

	expectedSecret := "secret-key-data"
	if string(key.Secret) != expectedSecret {
		t.Errorf("Expected secret %s, got %s", expectedSecret, string(key.Secret))
	}

	// Test invalid base64
	_, err = ParseTSIGKey("test.", HmacSHA256, "invalid!!!base64")
	if err == nil {
		t.Error("Expected error for invalid base64")
	}
}

func TestPackUnpackTSIGRecord(t *testing.T) {
	tsig := &TSIGRecord{
		Algorithm:  HmacSHA256,
		TimeSigned: time.Unix(1234567890, 0),
		Fudge:      300,
		MAC:        []byte("test-mac-data-123456789012"),
		OriginalID: 0x1234,
		Error:      TSIGErrNoError,
		OtherLen:   0,
		OtherData:  nil,
	}

	packed, err := PackTSIGRecord(tsig)
	if err != nil {
		t.Fatalf("PackTSIGRecord() error = %v", err)
	}

	if len(packed) == 0 {
		t.Error("Expected non-empty packed data")
	}

	// Unpack
	unpacked, n, err := UnpackTSIGRecord(packed, 0)
	if err != nil {
		t.Fatalf("UnpackTSIGRecord() error = %v", err)
	}

	if n != len(packed) {
		t.Errorf("Expected to consume %d bytes, consumed %d", len(packed), n)
	}

	if unpacked.Algorithm != tsig.Algorithm {
		t.Errorf("Expected algorithm %s, got %s", tsig.Algorithm, unpacked.Algorithm)
	}

	if !unpacked.TimeSigned.Equal(tsig.TimeSigned) {
		t.Errorf("Expected time %v, got %v", tsig.TimeSigned, unpacked.TimeSigned)
	}

	if unpacked.Fudge != tsig.Fudge {
		t.Errorf("Expected fudge %d, got %d", tsig.Fudge, unpacked.Fudge)
	}

	if !bytes.Equal(unpacked.MAC, tsig.MAC) {
		t.Errorf("Expected MAC %x, got %x", tsig.MAC, unpacked.MAC)
	}

	if unpacked.OriginalID != tsig.OriginalID {
		t.Errorf("Expected original ID %x, got %x", tsig.OriginalID, unpacked.OriginalID)
	}

	if unpacked.Error != tsig.Error {
		t.Errorf("Expected error %d, got %d", tsig.Error, unpacked.Error)
	}
}

func TestCalculateMAC(t *testing.T) {
	key := []byte("test-key-data-for-hmac")
	data := []byte("message to be authenticated")

	// Test HMAC-SHA256
	mac256, err := calculateMAC(key, data, HmacSHA256)
	if err != nil {
		t.Fatalf("calculateMAC(HmacSHA256) error = %v", err)
	}

	if len(mac256) != 32 { // SHA-256 produces 32 bytes
		t.Errorf("Expected 32 bytes for SHA-256, got %d", len(mac256))
	}

	// Test HMAC-SHA384
	mac384, err := calculateMAC(key, data, HmacSHA384)
	if err != nil {
		t.Fatalf("calculateMAC(HmacSHA384) error = %v", err)
	}

	if len(mac384) != 48 { // SHA-384 produces 48 bytes
		t.Errorf("Expected 48 bytes for SHA-384, got %d", len(mac384))
	}

	// Test HMAC-SHA512
	mac512, err := calculateMAC(key, data, HmacSHA512)
	if err != nil {
		t.Fatalf("calculateMAC(HmacSHA512) error = %v", err)
	}

	if len(mac512) != 64 { // SHA-512 produces 64 bytes
		t.Errorf("Expected 64 bytes for SHA-512, got %d", len(mac512))
	}

	// Verify different algorithms produce different MACs
	if bytes.Equal(mac256, mac384) || bytes.Equal(mac256, mac512) {
		t.Error("Different algorithms should produce different MACs")
	}

	// Test unsupported algorithm
	_, err = calculateMAC(key, data, "unsupported-alg")
	if err == nil {
		t.Error("Expected error for unsupported algorithm")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key := &TSIGKey{
		Name:      "test-key.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("a-256-bit-secret-key-for-testing!"),
	}

	// Create a simple query message
	msg := &protocol.Message{
		Header: protocol.Header{
			ID: 0x1234,
			Flags: protocol.Flags{
				RD: true,
			},
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}

	// Sign the message
	tsigRR, err := SignMessage(msg, key, 300)
	if err != nil {
		t.Fatalf("SignMessage() error = %v", err)
	}

	if tsigRR == nil {
		t.Fatal("Expected TSIG resource record")
	}

	if tsigRR.Type != protocol.TypeTSIG {
		t.Errorf("Expected type TSIG, got %d", tsigRR.Type)
	}

	if tsigRR.Class != protocol.ClassANY {
		t.Errorf("Expected class ANY, got %d", tsigRR.Class)
	}

	if tsigRR.TTL != 0 {
		t.Errorf("Expected TTL 0, got %d", tsigRR.TTL)
	}

	// Add TSIG to message
	msg.Additionals = append(msg.Additionals, tsigRR)

	// Verify the message
	err = VerifyMessage(msg, key, nil)
	if err != nil {
		t.Fatalf("VerifyMessage() error = %v", err)
	}

	// Verify with wrong key should fail
	wrongKey := &TSIGKey{
		Name:      "test-key.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("wrong-secret-key-for-testing!!!"),
	}

	err = VerifyMessage(msg, wrongKey, nil)
	if err == nil {
		t.Error("Expected verification to fail with wrong key")
	}
}

func TestVerifyWithTimeSkew(t *testing.T) {
	key := &TSIGKey{
		Name:      "test-key.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("a-256-bit-secret-key-for-testing!"),
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID: 0x1234,
			Flags: protocol.Flags{
				RD: true,
			},
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}

	// Create TSIG with old timestamp (beyond fudge)
	tsig := &TSIGRecord{
		Algorithm:  HmacSHA256,
		TimeSigned: time.Now().UTC().Add(-10 * time.Minute), // 10 minutes ago
		Fudge:      300,                                     // 5 minutes fudge
		MAC:        []byte("fake-mac"),
		OriginalID: 0x1234,
		Error:      TSIGErrNoError,
	}

	rdata, _ := PackTSIGRecord(tsig)
	keyName, _ := protocol.ParseName(key.Name)
	tsigRR := &protocol.ResourceRecord{
		Name:  keyName,
		Type:  protocol.TypeTSIG,
		Class: protocol.ClassANY,
		TTL:   0,
		Data:  &RDataTSIG{Raw: rdata},
	}
	msg.Additionals = append(msg.Additionals, tsigRR)

	// Verification should fail due to time skew
	err := VerifyMessage(msg, key, nil)
	if err == nil {
		t.Error("Expected verification to fail with time skew")
	}
}

func TestTSIGErrorString(t *testing.T) {
	tests := []struct {
		code     uint16
		expected string
	}{
		{TSIGErrNoError, "NOERROR"},
		{TSIGErrBadSig, "BADSIG"},
		{TSIGErrBadKey, "BADKEY"},
		{TSIGErrBadTime, "BADTIME"},
		{TSIGErrBadMode, "BADMODE"},
		{TSIGErrBadName, "BADNAME"},
		{TSIGErrBadAlgorithm, "BADALG"},
		{TSIGErrBadTrunc, "BADTRUNC"},
		{999, "UNKNOWN(999)"},
	}

	for _, tt := range tests {
		result := TSIGErrorString(tt.code)
		if result != tt.expected {
			t.Errorf("TSIGErrorString(%d) = %s, expected %s", tt.code, result, tt.expected)
		}
	}
}

func TestFindTSIGRecord(t *testing.T) {
	// Message without TSIG
	msg := &protocol.Message{
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}

	_, err := findTSIGRecord(msg)
	if err == nil {
		t.Error("Expected error when TSIG not found")
	}

	// Add a TSIG record
	keyName, _ := protocol.ParseName("key.example.com.")
	tsigRR := &protocol.ResourceRecord{
		Name:  keyName,
		Type:  protocol.TypeTSIG,
		Class: protocol.ClassANY,
		TTL:   0,
		Data:  &RDataTSIG{Raw: []byte("test")},
	}
	msg.Additionals = append(msg.Additionals, tsigRR)

	found, err := findTSIGRecord(msg)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if found.Type != protocol.TypeTSIG {
		t.Errorf("Expected TSIG type, got %d", found.Type)
	}
}

func TestRDataTSIGString(t *testing.T) {
	// Test with empty data
	rdata := &RDataTSIG{Raw: []byte{}}
	str := rdata.String()
	if str != "TSIG ()" {
		t.Errorf("Expected 'TSIG ()', got %s", str)
	}

	// Test with valid data
	tsig := &TSIGRecord{
		Algorithm:  HmacSHA256,
		TimeSigned: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Fudge:      300,
		MAC:        []byte("test-mac-data"),
		OriginalID: 0x1234,
		Error:      TSIGErrNoError,
	}
	packed, _ := PackTSIGRecord(tsig)
	rdata2 := &RDataTSIG{Raw: packed}

	str2 := rdata2.String()
	if !strings.Contains(str2, "hmac-sha256") {
		t.Errorf("Expected string to contain algorithm, got %s", str2)
	}
	if !strings.Contains(str2, "NOERROR") {
		t.Errorf("Expected string to contain error code, got %s", str2)
	}
}

// Helper functions
func mustParseName(s string) *protocol.Name {
	n, err := protocol.ParseName(s)
	if err != nil {
		panic(err)
	}
	return n
}
