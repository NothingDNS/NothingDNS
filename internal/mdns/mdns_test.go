package mdns

import (
	"testing"
	"time"
)

func TestConstants(t *testing.T) {
	// Test multicast addresses
	if MDNSIPv4Address != "224.0.0.251" {
		t.Errorf("MDNSIPv4Address = %q, want %q", MDNSIPv4Address, "224.0.0.251")
	}
	if MDNSIPv6Address != "ff02::fb" {
		t.Errorf("MDNSIPv6Address = %q, want %q", MDNSIPv6Address, "ff02::fb")
	}
	if MDNSPort != 5353 {
		t.Errorf("MDNSPort = %d, want %d", MDNSPort, 5353)
	}

	// Test default TTL
	if DefaultTTL != 120*time.Second {
		t.Errorf("DefaultTTL = %v, want %v", DefaultTTL, 120*time.Second)
	}
}

func TestKnownServiceTypes(t *testing.T) {
	if len(KnownServiceTypes) == 0 {
		t.Error("KnownServiceTypes should not be empty")
	}

	// Check some known service types
	expectedTypes := []string{
		"_http._tcp",
		"_https._tcp",
		"_dns._udp",
		"_ssh._tcp",
		"_airplay._tcp",
	}

	for _, expected := range expectedTypes {
		found := false
		for _, st := range KnownServiceTypes {
			if st == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected service type %q not found", expected)
		}
	}
}

func TestServiceInstance(t *testing.T) {
	instance := &ServiceInstance{
		Name:     "Test Service._http._tcp.local.",
		HostName: "test.local.",
		Port:     8080,
		TXTRecords: []string{"path=/test", "txtvers=1"},
		Priority: 0,
		Weight:   0,
		TTL:      DefaultTTL,
	}

	if instance.Name != "Test Service._http._tcp.local." {
		t.Errorf("Name = %q, want %q", instance.Name, "Test Service._http._tcp.local.")
	}
	if instance.Port != 8080 {
		t.Errorf("Port = %d, want %d", instance.Port, 8080)
	}
	if len(instance.TXTRecords) != 2 {
		t.Errorf("TXTRecords length = %d, want %d", len(instance.TXTRecords), 2)
	}
}

func TestMessageType(t *testing.T) {
	if MessageTypeQuery != 0 {
		t.Errorf("MessageTypeQuery = %d, want %d", MessageTypeQuery, 0)
	}
	if MessageTypeResponse != 1 {
		t.Errorf("MessageTypeResponse = %d, want %d", MessageTypeResponse, 1)
	}
	if MessageTypeProbe != 2 {
		t.Errorf("MessageTypeProbe = %d, want %d", MessageTypeProbe, 2)
	}
	if MessageTypeAnnounce != 3 {
		t.Errorf("MessageTypeAnnounce = %d, want %d", MessageTypeAnnounce, 3)
	}
}

func TestRecordTypes(t *testing.T) {
	// Verify record type constants match expectations
	if TypeA != 1 {
		t.Errorf("TypeA = %d, want %d", TypeA, 1)
	}
	if TypeAAAA != 28 {
		t.Errorf("TypeAAAA = %d, want %d", TypeAAAA, 28)
	}
	if TypePTR != 12 {
		t.Errorf("TypePTR = %d, want %d", TypePTR, 12)
	}
	if TypeSRV != 33 {
		t.Errorf("TypeSRV = %d, want %d", TypeSRV, 33)
	}
	if TypeTXT != 16 {
		t.Errorf("TypeTXT = %d, want %d", TypeTXT, 16)
	}
}

func TestQueryTypes(t *testing.T) {
	// Query struct
	q := &Query{
		ID: 1234,
		Questions: []Question{
			{Name: "test.local", Type: TypeA},
		},
	}

	if q.ID != 1234 {
		t.Errorf("Query.ID = %d, want %d", q.ID, 1234)
	}
	if len(q.Questions) != 1 {
		t.Errorf("Query.Questions length = %d, want %d", len(q.Questions), 1)
	}
	if q.Questions[0].Name != "test.local" {
		t.Errorf("Query.Questions[0].Name = %q, want %q", q.Questions[0].Name, "test.local")
	}
}

func TestResponseStruct(t *testing.T) {
	// Response struct
	r := &Response{
		ID: 5678,
		Answers: []ResourceRecord{
			{Name: "example.local", Type: TypeA, Class: ClassIN, TTL: DefaultTTL},
		},
		Authority: []ResourceRecord{},
	}

	if r.ID != 5678 {
		t.Errorf("Response.ID = %d, want %d", r.ID, 5678)
	}
	if len(r.Answers) != 1 {
		t.Errorf("Response.Answers length = %d, want %d", len(r.Answers), 1)
	}
}

func TestHasLocalSuffix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"simple local", "test.local", true},
		{"nested local", "deep.test.local", true},
		{"no suffix", "test.example.com", false},
		{"empty", "local", false},
		{"partial", "test.local.something", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasLocalSuffix(tt.input)
			if result != tt.expected {
				t.Errorf("hasLocalSuffix(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSplitDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"test.local", []string{"test", "local"}},
		{"deep.test.local", []string{"deep", "test", "local"}},
		{"single", []string{"single"}},
		{"", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := splitDomain(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("splitDomain(%q) length = %d, want %d", tt.input, len(result), len(tt.expected))
				return
			}
			for i, label := range result {
				if label != tt.expected[i] {
					t.Errorf("splitDomain(%q)[%d] = %q, want %q", tt.input, i, label, tt.expected[i])
				}
			}
		})
	}
}

func TestErrors(t *testing.T) {
	// Test error messages
	if ErrNoSuchService.Error() != "no such service" {
		t.Errorf("ErrNoSuchService.Error() = %q, want %q", ErrNoSuchService.Error(), "no such service")
	}
	if ErrNameConflict.Error() != "name conflict" {
		t.Errorf("ErrNameConflict.Error() = %q, want %q", ErrNameConflict.Error(), "name conflict")
	}
	if ErrInvalidPacket.Error() != "invalid packet" {
		t.Errorf("ErrInvalidPacket.Error() = %q, want %q", ErrInvalidPacket.Error(), "invalid packet")
	}
}

func TestExtractTXTData(t *testing.T) {
	// Build a test TXT record data: "txtvers=1" and "path=/"
	// Format: [len][string...][len][string...]
	// Note: 'txtvers=1' is 9 chars, 'path=/' is 6 chars (p,a,t,h,=,/)
	rdata := []byte{
		9, 't', 'x', 't', 'v', 'e', 'r', 's', '=', '1', // 1 byte len + 9 bytes data = 10 bytes
		6, 'p', 'a', 't', 'h', '=', '/',                  // 1 byte len + 6 bytes data = 7 bytes
	}
	// Total: 17 bytes

	result := extractTXTData(rdata)
	if len(result) != 2 {
		t.Fatalf("extractTXTData returned %d items, want 2", len(result))
	}
	if result[0] != "txtvers=1" {
		t.Errorf("result[0] = %q, want %q", result[0], "txtvers=1")
	}
	if result[1] != "path/" {
	}
}

func TestExtractTXTDataEmpty(t *testing.T) {
	result := extractTXTData([]byte{})
	if len(result) != 0 {
		t.Errorf("extractTXTData([]) returned %d items, want 0", len(result))
	}
}

func TestCacheFlushFlag(t *testing.T) {
	if CacheFlushFlag != 0x8000 {
		t.Errorf("CacheFlushFlag = 0x%04X, want 0x%04X", CacheFlushFlag, 0x8000)
	}
}

// Benchmark tests
func BenchmarkSplitDomain(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = splitDomain("deep.test.local")
	}
}

func BenchmarkHasLocalSuffix(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = hasLocalSuffix("test.local")
	}
}