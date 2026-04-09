package transfer

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestNewAXFRServer(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	server := NewAXFRServer(zones)

	if server == nil {
		t.Fatal("NewAXFRServer() returned nil")
	}

	if server.zones == nil {
		t.Error("zones map not initialized")
	}

	if server.keyStore == nil {
		t.Error("keyStore not initialized")
	}
}

func TestAXFRServer_AddRemoveZone(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	server := NewAXFRServer(zones)

	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:  "ns1.example.com.",
		RName:  "admin.example.com.",
		Serial: 2024010101,
	}

	server.AddZone(z)

	if _, ok := server.zones["example.com."]; !ok {
		t.Error("Zone not added correctly")
	}

	server.RemoveZone("example.com.")

	if _, ok := server.zones["example.com."]; ok {
		t.Error("Zone not removed correctly")
	}
}

func TestAXFRServer_IsAllowed(t *testing.T) {
	tests := []struct {
		name        string
		allowList   []string
		clientIP    string
		wantAllowed bool
	}{
		{
			name:        "no allowlist allows all",
			allowList:   nil,
			clientIP:    "192.168.1.1",
			wantAllowed: true,
		},
		{
			name:        "empty allowlist allows all",
			allowList:   []string{},
			clientIP:    "192.168.1.1",
			wantAllowed: true,
		},
		{
			name:        "allowed IP in network",
			allowList:   []string{"192.168.1.0/24"},
			clientIP:    "192.168.1.100",
			wantAllowed: true,
		},
		{
			name:        "disallowed IP not in network",
			allowList:   []string{"192.168.1.0/24"},
			clientIP:    "10.0.0.1",
			wantAllowed: false,
		},
		{
			name:        "multiple networks",
			allowList:   []string{"192.168.1.0/24", "10.0.0.0/8"},
			clientIP:    "10.1.2.3",
			wantAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts []AXFRServerOption
			if tt.allowList != nil {
				opts = append(opts, WithAllowList(tt.allowList))
			}

			server := NewAXFRServer(make(map[string]*zone.Zone), opts...)
			clientIP := net.ParseIP(tt.clientIP)

			got := server.IsAllowed(clientIP)
			if got != tt.wantAllowed {
				t.Errorf("IsAllowed() = %v, want %v", got, tt.wantAllowed)
			}
		})
	}
}

func TestAXFRServer_HandleAXFR_NoZone(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	server := NewAXFRServer(zones, WithAllowList([]string{"127.0.0.0/8"}))

	// Create AXFR request
	name, _ := protocol.ParseName("nonexistent.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeAXFR,
				QClass: protocol.ClassIN,
			},
		},
	}

	clientIP := net.ParseIP("127.0.0.1")
	_, _, err := server.HandleAXFR(req, clientIP)

	if err == nil {
		t.Error("Expected error for non-existent zone")
	}
}

func TestAXFRServer_HandleAXFR_NoSOA(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	server := NewAXFRServer(zones, WithAllowList([]string{"127.0.0.0/8"}))

	// Add zone without SOA
	z := zone.NewZone("example.com.")
	server.AddZone(z)

	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeAXFR,
				QClass: protocol.ClassIN,
			},
		},
	}

	clientIP := net.ParseIP("127.0.0.1")
	_, _, err := server.HandleAXFR(req, clientIP)

	if err == nil {
		t.Error("Expected error for zone without SOA")
	}
}

func TestAXFRServer_HandleAXFR_Success(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	server := NewAXFRServer(zones, WithAllowList([]string{"127.0.0.0/8"}))

	// Create zone with SOA and records
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}
	z.Records["example.com."] = []zone.Record{
		{Type: "A", TTL: 3600, RData: "192.0.2.1"},
		{Type: "NS", TTL: 3600, RData: "ns1.example.com."},
	}
	z.Records["www.example.com."] = []zone.Record{
		{Type: "A", TTL: 3600, RData: "192.0.2.2"},
	}

	server.AddZone(z)

	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeAXFR,
				QClass: protocol.ClassIN,
			},
		},
	}

	clientIP := net.ParseIP("127.0.0.1")
	records, _, err := server.HandleAXFR(req, clientIP)

	if err != nil {
		t.Fatalf("HandleAXFR() error = %v", err)
	}

	// Should have: SOA + 3 zone records + SOA = 5 total
	// (2 records at example.com. + 1 record at www.example.com.)
	if len(records) != 5 {
		t.Errorf("Expected 5 records, got %d", len(records))
	}

	// Check first record is SOA
	if records[0].Type != protocol.TypeSOA {
		t.Errorf("Expected first record to be SOA, got %d", records[0].Type)
	}

	// Check last record is SOA
	if records[len(records)-1].Type != protocol.TypeSOA {
		t.Errorf("Expected last record to be SOA, got %d", records[len(records)-1].Type)
	}
}

func TestAXFRServer_HandleAXFR_InvalidQueryType(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	server := NewAXFRServer(zones, WithAllowList([]string{"127.0.0.0/8"}))

	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:  "ns1.example.com.",
		RName:  "admin.example.com.",
		Serial: 2024010101,
	}
	server.AddZone(z)

	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeA, // Not AXFR
				QClass: protocol.ClassIN,
			},
		},
	}

	clientIP := net.ParseIP("127.0.0.1")
	_, _, err := server.HandleAXFR(req, clientIP)

	if err == nil {
		t.Error("Expected error for non-AXFR query type")
	}
}

func TestAXFRServer_HandleAXFR_NotAllowed(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	server := NewAXFRServer(zones, WithAllowList([]string{"192.168.1.0/24"}))

	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:  "ns1.example.com.",
		RName:  "admin.example.com.",
		Serial: 2024010101,
	}
	server.AddZone(z)

	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeAXFR,
				QClass: protocol.ClassIN,
			},
		},
	}

	// Client IP not in allowlist
	clientIP := net.ParseIP("10.0.0.1")
	_, _, err := server.HandleAXFR(req, clientIP)

	if err == nil {
		t.Error("Expected error for unauthorized client")
	}
}

func TestNewAXFRClient(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")

	if client == nil {
		t.Fatal("NewAXFRClient() returned nil")
	}

	if client.server != "ns1.example.com:53" {
		t.Errorf("Expected server ns1.example.com:53, got %s", client.server)
	}

	if client.timeout != 30*time.Second {
		t.Errorf("Expected default timeout 30s, got %v", client.timeout)
	}
}

func TestNewAXFRClient_WithOptions(t *testing.T) {
	ks := NewKeyStore()
	client := NewAXFRClient(
		"ns1.example.com:53",
		WithAXFRTimeout(60*time.Second),
		WithAXFRKeyStore(ks),
	)

	if client.timeout != 60*time.Second {
		t.Errorf("Expected timeout 60s, got %v", client.timeout)
	}

	if client.keyStore != ks {
		t.Error("KeyStore not set correctly")
	}
}

func TestParseRData_A(t *testing.T) {
	rdata, err := parseRData(protocol.TypeA, "192.0.2.1", "example.com.")
	if err != nil {
		t.Fatalf("parseRData(A) error = %v", err)
	}

	a, ok := rdata.(*protocol.RDataA)
	if !ok {
		t.Fatal("Expected *protocol.RDataA")
	}

	expected := net.ParseIP("192.0.2.1").To4()
	if !bytes.Equal(a.Address[:], expected) {
		t.Errorf("Expected IP %v, got %v", expected, a.Address[:])
	}
}

func TestParseRData_AAAA(t *testing.T) {
	rdata, err := parseRData(protocol.TypeAAAA, "2001:db8::1", "example.com.")
	if err != nil {
		t.Fatalf("parseRData(AAAA) error = %v", err)
	}

	aaaa, ok := rdata.(*protocol.RDataAAAA)
	if !ok {
		t.Fatal("Expected *protocol.RDataAAAA")
	}

	expected := net.ParseIP("2001:db8::1")
	if !bytes.Equal(aaaa.Address[:], expected) {
		t.Errorf("Expected IP %v, got %v", expected, aaaa.Address[:])
	}
}

func TestParseRData_CNAME(t *testing.T) {
	rdata, err := parseRData(protocol.TypeCNAME, "target.example.com.", "example.com.")
	if err != nil {
		t.Fatalf("parseRData(CNAME) error = %v", err)
	}

	cname, ok := rdata.(*protocol.RDataCNAME)
	if !ok {
		t.Fatal("Expected *protocol.RDataCNAME")
	}

	if cname.CName.String() != "target.example.com." {
		t.Errorf("Expected CNAME target.example.com., got %s", cname.CName.String())
	}
}

func TestParseRData_NS(t *testing.T) {
	rdata, err := parseRData(protocol.TypeNS, "ns1.example.com.", "example.com.")
	if err != nil {
		t.Fatalf("parseRData(NS) error = %v", err)
	}

	ns, ok := rdata.(*protocol.RDataNS)
	if !ok {
		t.Fatal("Expected *protocol.RDataNS")
	}

	if ns.NSDName.String() != "ns1.example.com." {
		t.Errorf("Expected NS ns1.example.com., got %s", ns.NSDName.String())
	}
}

func TestParseRData_MX(t *testing.T) {
	rdata, err := parseRData(protocol.TypeMX, "10 mail.example.com.", "example.com.")
	if err != nil {
		t.Fatalf("parseRData(MX) error = %v", err)
	}

	mx, ok := rdata.(*protocol.RDataMX)
	if !ok {
		t.Fatal("Expected *protocol.RDataMX")
	}

	if mx.Preference != 10 {
		t.Errorf("Expected preference 10, got %d", mx.Preference)
	}

	if mx.Exchange.String() != "mail.example.com." {
		t.Errorf("Expected exchange mail.example.com., got %s", mx.Exchange.String())
	}
}

func TestParseRData_TXT(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"\"hello world\"", "hello world"},
		{"hello world", "hello world"},
		{"\"v=spf1 include:_spf.example.com ~all\"", "v=spf1 include:_spf.example.com ~all"},
	}

	for _, tt := range tests {
		rdata, err := parseRData(protocol.TypeTXT, tt.input, "example.com.")
		if err != nil {
			t.Fatalf("parseRData(TXT) error = %v", err)
		}

		txt, ok := rdata.(*protocol.RDataTXT)
		if !ok {
			t.Fatal("Expected *protocol.RDataTXT")
		}

		if len(txt.Strings) == 0 || txt.Strings[0] != tt.expected {
			t.Errorf("Expected TXT %q, got %v", tt.expected, txt.Strings)
		}
	}
}

func TestParseRData_InvalidA(t *testing.T) {
	_, err := parseRData(protocol.TypeA, "not-an-ip", "example.com.")
	if err == nil {
		t.Error("Expected error for invalid IP")
	}
}

func TestHasTSIG(t *testing.T) {
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

	if hasTSIG(msg) {
		t.Error("Expected no TSIG")
	}

	// Message with TSIG
	keyName, _ := protocol.ParseName("key.example.com.")
	tsigRR := &protocol.ResourceRecord{
		Name:  keyName,
		Type:  protocol.TypeTSIG,
		Class: protocol.ClassANY,
		TTL:   0,
		Data:  &RDataTSIG{Raw: []byte("test")},
	}
	msg.Additionals = append(msg.Additionals, tsigRR)

	if !hasTSIG(msg) {
		t.Error("Expected TSIG")
	}
}

func TestGetTSIGKeyName(t *testing.T) {
	keyName, _ := protocol.ParseName("key.example.com.")
	tsigRR := &protocol.ResourceRecord{
		Name:  keyName,
		Type:  protocol.TypeTSIG,
		Class: protocol.ClassANY,
		TTL:   0,
		Data:  &RDataTSIG{Raw: []byte("test")},
	}

	msg := &protocol.Message{
		Additionals: []*protocol.ResourceRecord{tsigRR},
	}

	name, err := getTSIGKeyName(msg)
	if err != nil {
		t.Fatalf("getTSIGKeyName() error = %v", err)
	}

	if name != "key.example.com." {
		t.Errorf("Expected key.example.com., got %s", name)
	}

	// Message without TSIG
	msg2 := &protocol.Message{}
	_, err = getTSIGKeyName(msg2)
	if err == nil {
		t.Error("Expected error for message without TSIG")
	}
}

func TestCanonicalSort(t *testing.T) {
	records := []*protocol.ResourceRecord{
		{Name: mustParseName("www.example.com."), Type: protocol.TypeA},
		{Name: mustParseName("example.com."), Type: protocol.TypeNS},
		{Name: mustParseName("mail.example.com."), Type: protocol.TypeA},
		{Name: mustParseName("example.com."), Type: protocol.TypeSOA},
		{Name: mustParseName("www.example.com."), Type: protocol.TypeAAAA},
	}

	canonicalSort(records)

	// Check sorting order
	expected := []struct {
		name string
		typ  uint16
	}{
		{"example.com.", protocol.TypeNS},
		{"example.com.", protocol.TypeSOA},
		{"mail.example.com.", protocol.TypeA},
		{"www.example.com.", protocol.TypeA},
		{"www.example.com.", protocol.TypeAAAA},
	}

	for i, exp := range expected {
		if records[i].Name.String() != exp.name {
			t.Errorf("Record %d: expected name %s, got %s", i, exp.name, records[i].Name.String())
		}
		if records[i].Type != exp.typ {
			t.Errorf("Record %d: expected type %d, got %d", i, exp.typ, records[i].Type)
		}
	}
}

func TestGenerateMessageID(t *testing.T) {
	id1 := generateMessageID()
	id2 := generateMessageID()

	// IDs should be different (with high probability)
	// Small chance of collision, but extremely unlikely in test
	if id1 == id2 {
		t.Log("Warning: message ID collision (extremely unlikely)")
	}
}

func TestCanonicalName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"EXAMPLE.COM.", "example.com."},
		{"Example.Com.", "example.com."},
		{"example.com.", "example.com."},
		{"Sub.Example.COM.", "sub.example.com."},
	}

	for _, tt := range tests {
		got := canonicalName(tt.input)
		if got != tt.expected {
			t.Errorf("canonicalName(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestExtractMAC(t *testing.T) {
	// Create a TSIG record with a MAC
	tsig := &TSIGRecord{
		Algorithm:  HmacSHA256,
		TimeSigned: time.Now(),
		Fudge:      300,
		MAC:        []byte("test-mac-data"),
		OriginalID: 0x1234,
		Error:      TSIGErrNoError,
	}

	packed, _ := PackTSIGRecord(tsig)

	keyName, _ := protocol.ParseName("key.example.com.")
	tsigRR := &protocol.ResourceRecord{
		Name:  keyName,
		Type:  protocol.TypeTSIG,
		Class: protocol.ClassANY,
		TTL:   0,
		Data:  &RDataTSIG{Raw: packed},
	}

	msg := &protocol.Message{
		Additionals: []*protocol.ResourceRecord{tsigRR},
	}

	mac, err := extractMAC(msg)
	if err != nil {
		t.Fatalf("extractMAC() returned error: %v", err)
	}
	if !equalBytes(mac, tsig.MAC) {
		t.Errorf("Expected MAC %v, got %v", tsig.MAC, mac)
	}

	// Message without TSIG
	msg2 := &protocol.Message{}
	mac2, err := extractMAC(msg2)
	if err != nil {
		t.Fatalf("extractMAC() returned error for empty message: %v", err)
	}
	if mac2 != nil {
		t.Errorf("Expected nil MAC, got %v", mac2)
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestAXFRClient_buildAXFRRequest(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")

	req, err := client.buildAXFRRequest("example.com.", nil)
	if err != nil {
		t.Fatalf("buildAXFRRequest() error = %v", err)
	}

	if req.Header.QDCount != 1 {
		t.Errorf("Expected QDCount 1, got %d", req.Header.QDCount)
	}

	if len(req.Questions) != 1 {
		t.Fatal("Expected 1 question")
	}

	q := req.Questions[0]
	if q.QType != protocol.TypeAXFR {
		t.Errorf("Expected QType AXFR (%d), got %d", protocol.TypeAXFR, q.QType)
	}

	if q.QClass != protocol.ClassIN {
		t.Errorf("Expected QClass IN (%d), got %d", protocol.ClassIN, q.QClass)
	}

	// Test with TSIG key
	key := &TSIGKey{
		Name:      "key.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("a-256-bit-secret-key-for-testing!"),
	}

	req2, err := client.buildAXFRRequest("example.com.", key)
	if err != nil {
		t.Fatalf("buildAXFRRequest() with key error = %v", err)
	}

	if !hasTSIG(req2) {
		t.Error("Expected TSIG record in request")
	}
}
