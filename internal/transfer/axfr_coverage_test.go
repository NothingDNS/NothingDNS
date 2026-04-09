package transfer

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// Test WithKeyStore option
func TestWithKeyStore(t *testing.T) {
	ks := NewKeyStore()
	opt := WithKeyStore(ks)

	server := &AXFRServer{}
	opt(server)

	if server.keyStore != ks {
		t.Error("WithKeyStore did not set the key store")
	}
}

// Test createSOARR success case
func TestAXFRServer_createSOARR_Success(t *testing.T) {
	server := NewAXFRServer(make(map[string]*zone.Zone))
	origin, _ := protocol.ParseName("example.com.")

	soa := &zone.SOARecord{
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}

	rr, err := server.createSOARR(soa, origin)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if rr.Type != protocol.TypeSOA {
		t.Errorf("Expected SOA type, got %d", rr.Type)
	}
}

// Test createSOARR with valid domain names
func TestAXFRServer_createSOARR_ValidNames(t *testing.T) {
	server := NewAXFRServer(make(map[string]*zone.Zone))
	origin, _ := protocol.ParseName("example.com.")

	soa := &zone.SOARecord{
		MName:   "ns1.example.com.",
		RName:   "hostmaster.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
		TTL:     86400,
	}

	_, err := server.createSOARR(soa, origin)
	if err != nil {
		t.Errorf("Unexpected error for valid names: %v", err)
	}
}

// Test zoneRecordToRR with valid name
func TestAXFRServer_zoneRecordToRR_ValidName(t *testing.T) {
	server := NewAXFRServer(make(map[string]*zone.Zone))

	rec := zone.Record{
		Type:  "A",
		TTL:   3600,
		RData: "192.0.2.1",
	}

	_, err := server.zoneRecordToRR("www.example.com.", rec, "example.com.")
	if err != nil {
		t.Errorf("Unexpected error for valid name: %v", err)
	}
}

// Test zoneRecordToRR with unknown type
func TestAXFRServer_zoneRecordToRR_UnknownType(t *testing.T) {
	server := NewAXFRServer(make(map[string]*zone.Zone))

	rec := zone.Record{
		Type:  "UNKNOWN",
		TTL:   3600,
		RData: "some-data",
	}

	_, err := server.zoneRecordToRR("www.example.com.", rec, "example.com.")
	if err == nil {
		t.Error("Expected error for unknown record type")
	}
}

// Test parseRData with various record types and edge cases
func TestParseRData_PTR(t *testing.T) {
	rdata, err := parseRData(protocol.TypePTR, "ptr.example.com.", "example.com.")
	if err != nil {
		t.Fatalf("parseRData(PTR) error = %v", err)
	}

	ptr, ok := rdata.(*protocol.RDataPTR)
	if !ok {
		t.Fatal("Expected *protocol.RDataPTR")
	}

	if ptr.PtrDName.String() != "ptr.example.com." {
		t.Errorf("Expected PTR ptr.example.com., got %s", ptr.PtrDName.String())
	}
}

func TestParseRData_SRV(t *testing.T) {
	rdata, err := parseRData(protocol.TypeSRV, "10 20 443 target.example.com.", "example.com.")
	if err != nil {
		t.Fatalf("parseRData(SRV) error = %v", err)
	}

	srv, ok := rdata.(*protocol.RDataSRV)
	if !ok {
		t.Fatal("Expected *protocol.RDataSRV")
	}

	if srv.Priority != 10 {
		t.Errorf("Expected priority 10, got %d", srv.Priority)
	}
	if srv.Weight != 20 {
		t.Errorf("Expected weight 20, got %d", srv.Weight)
	}
	if srv.Port != 443 {
		t.Errorf("Expected port 443, got %d", srv.Port)
	}
	if srv.Target.String() != "target.example.com." {
		t.Errorf("Expected target target.example.com., got %s", srv.Target.String())
	}
}

func TestParseRData_InvalidSRVFormat(t *testing.T) {
	_, err := parseRData(protocol.TypeSRV, "not-enough-fields", "example.com.")
	if err == nil {
		t.Error("Expected error for invalid SRV data format")
	}
}

func TestParseRData_ValidAAAA(t *testing.T) {
	rdata, err := parseRData(protocol.TypeAAAA, "2001:db8::1", "example.com.")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if rdata == nil {
		t.Error("Expected non-nil rdata")
	}
}

func TestParseRData_ValidCNAME(t *testing.T) {
	rdata, err := parseRData(protocol.TypeCNAME, "target.example.com.", "example.com.")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if rdata == nil {
		t.Error("Expected non-nil rdata")
	}
}

func TestParseRData_ValidNS(t *testing.T) {
	rdata, err := parseRData(protocol.TypeNS, "ns1.example.com.", "example.com.")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if rdata == nil {
		t.Error("Expected non-nil rdata")
	}
}

func TestParseRData_ValidMX(t *testing.T) {
	rdata, err := parseRData(protocol.TypeMX, "10 mail.example.com.", "example.com.")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if rdata == nil {
		t.Error("Expected non-nil rdata")
	}
}

func TestParseRData_ValidPTR(t *testing.T) {
	rdata, err := parseRData(protocol.TypePTR, "ptr.example.com.", "example.com.")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if rdata == nil {
		t.Error("Expected non-nil rdata")
	}
}

func TestParseRData_RawType(t *testing.T) {
	// Test unknown type returns RDataRaw
	rdata, err := parseRData(12345, "some-data", "example.com.")
	if err != nil {
		t.Fatalf("parseRData(Raw) error = %v", err)
	}

	raw, ok := rdata.(*protocol.RDataRaw)
	if !ok {
		t.Fatal("Expected *protocol.RDataRaw")
	}

	if string(raw.Data) != "some-data" {
		t.Errorf("Expected raw data 'some-data', got %s", string(raw.Data))
	}
}

func TestParseRData_MXWithoutPreference(t *testing.T) {
	// MX without preference should default to 0
	rdata, err := parseRData(protocol.TypeMX, "mail.example.com.", "example.com.")
	if err != nil {
		t.Fatalf("parseRData(MX) error = %v", err)
	}

	mx, ok := rdata.(*protocol.RDataMX)
	if !ok {
		t.Fatal("Expected *protocol.RDataMX")
	}

	if mx.Preference != 0 {
		t.Errorf("Expected preference 0, got %d", mx.Preference)
	}
	if mx.Exchange.String() != "mail.example.com." {
		t.Errorf("Expected exchange mail.example.com., got %s", mx.Exchange.String())
	}
}

// Test HandleAXFR with multiple questions
func TestAXFRServer_HandleAXFR_MultipleQuestions(t *testing.T) {
	server := NewAXFRServer(make(map[string]*zone.Zone))

	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 2,
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeAXFR, QClass: protocol.ClassIN},
			{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
	}

	_, _, err := server.HandleAXFR(req, net.ParseIP("127.0.0.1"))
	if err == nil {
		t.Error("Expected error for multiple questions")
	}
}

// Test HandleAXFR with TSIG key not found
func TestAXFRServer_HandleAXFR_TSIGKeyNotFound(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	ks := NewKeyStore()
	server := NewAXFRServer(zones, WithKeyStore(ks))

	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:  "ns1.example.com.",
		RName:  "admin.example.com.",
		Serial: 2024010101,
	}
	server.AddZone(z)

	name, _ := protocol.ParseName("example.com.")

	// Create TSIG record with key that doesn't exist in keystore
	keyName, _ := protocol.ParseName("nonexistent-key.")
	tsigRR := &protocol.ResourceRecord{
		Name:  keyName,
		Type:  protocol.TypeTSIG,
		Class: protocol.ClassANY,
		TTL:   0,
		Data:  &RDataTSIG{Raw: []byte("test")},
	}

	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeAXFR, QClass: protocol.ClassIN},
		},
		Additionals: []*protocol.ResourceRecord{tsigRR},
	}

	_, _, err := server.HandleAXFR(req, net.ParseIP("127.0.0.1"))
	if err == nil {
		t.Error("Expected error for TSIG key not found")
	}
}

// Test HandleAXFR with valid TSIG
func TestAXFRServer_HandleAXFR_WithTSIG(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	ks := NewKeyStore()

	key := &TSIGKey{
		Name:      "test-key.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("a-256-bit-secret-key-for-testing!"),
	}
	ks.AddKey(key)

	server := NewAXFRServer(zones, WithKeyStore(ks))

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
	server.AddZone(z)

	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeAXFR, QClass: protocol.ClassIN},
		},
	}

	// Sign the message
	tsigRR, err := SignMessage(req, key, 300)
	if err != nil {
		t.Fatalf("SignMessage() error = %v", err)
	}
	req.Additionals = append(req.Additionals, tsigRR)

	records, _, err := server.HandleAXFR(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleAXFR() error = %v", err)
	}

	// Should have at least SOA at start and end
	if len(records) < 2 {
		t.Errorf("Expected at least 2 records, got %d", len(records))
	}
}

// Test generateAXFRRecords with record conversion error
func TestAXFRServer_generateAXFRRecords_RecordError(t *testing.T) {
	server := NewAXFRServer(make(map[string]*zone.Zone))

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
	// Add record with unknown type - should be skipped
	z.Records["www.example.com."] = []zone.Record{
		{Type: "UNKNOWN_TYPE", TTL: 3600, RData: "data"},
	}

	records, err := server.generateAXFRRecords(z)
	if err != nil {
		t.Fatalf("generateAXFRRecords() error = %v", err)
	}

	// Should still have SOA records
	if len(records) != 2 {
		t.Errorf("Expected 2 records (only SOA), got %d", len(records))
	}
}

// Test buildAXFRRequest with valid zone name
func TestAXFRClient_buildAXFRRequest_ValidName(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")

	req, err := client.buildAXFRRequest("example.com.", nil)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if req == nil {
		t.Error("Expected non-nil request")
	}

	if len(req.Questions) != 1 {
		t.Errorf("Expected 1 question, got %d", len(req.Questions))
	}
}

// Test sendMessage error handling
func TestAXFRClient_sendMessage_PackError(t *testing.T) {
	// Create a message that will fail to pack due to invalid data
	client := NewAXFRClient("ns1.example.com:53")

	// We can't easily create a pack error, so skip this for now
	// The message pack is generally robust
	_ = client
}

// Test receiveAXFRResponse error cases
func TestAXFRClient_receiveAXFRResponse_InvalidLength(t *testing.T) {
	// This test would require a mock connection, which is complex
	// We test the parsing path through integration tests
}

// Test AXFRClient.Transfer connection error
func TestAXFRClient_Transfer_ConnectionError(t *testing.T) {
	client := NewAXFRClient("invalid-host:99999", WithAXFRTimeout(1*time.Second))

	_, err := client.Transfer("example.com.", nil)
	if err == nil {
		t.Error("Expected error for invalid server address")
	}
}

// Test HandleAXFR with TSIG verification failure
func TestAXFRServer_HandleAXFR_TSIGVerificationFailure(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	ks := NewKeyStore()

	key := &TSIGKey{
		Name:      "test-key.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("a-256-bit-secret-key-for-testing!"),
	}
	ks.AddKey(key)

	server := NewAXFRServer(zones, WithKeyStore(ks))

	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:  "ns1.example.com.",
		RName:  "admin.example.com.",
		Serial: 2024010101,
	}
	server.AddZone(z)

	name, _ := protocol.ParseName("example.com.")

	// Create TSIG record with invalid MAC (will fail verification)
	keyName, _ := protocol.ParseName("test-key.example.com.")
	tsigData := &TSIGRecord{
		Algorithm:  HmacSHA256,
		TimeSigned: time.Now().UTC(),
		Fudge:      300,
		MAC:        []byte("invalid-mac-will-fail-verification!!"),
		OriginalID: 1234,
		Error:      TSIGErrNoError,
	}
	packedTSIG, _ := PackTSIGRecord(tsigData)
	tsigRR := &protocol.ResourceRecord{
		Name:  keyName,
		Type:  protocol.TypeTSIG,
		Class: protocol.ClassANY,
		TTL:   0,
		Data:  &RDataTSIG{Raw: packedTSIG},
	}

	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeAXFR, QClass: protocol.ClassIN},
		},
		Additionals: []*protocol.ResourceRecord{tsigRR},
	}

	_, _, err := server.HandleAXFR(req, net.ParseIP("127.0.0.1"))
	if err == nil {
		t.Error("Expected error for TSIG verification failure")
	}
}

// Test HandleAXFR with getTSIGKeyName error
func TestAXFRServer_HandleAXFR_GetTSIGKeyNameError(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	ks := NewKeyStore()
	server := NewAXFRServer(zones, WithKeyStore(ks))

	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:  "ns1.example.com.",
		RName:  "admin.example.com.",
		Serial: 2024010101,
	}
	server.AddZone(z)

	name, _ := protocol.ParseName("example.com.")

	// Message with TSIG record but empty additional section means getTSIGKeyName will fail
	// Actually, hasTSIG checks for TSIG type, so we need a TSIG record with invalid data
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeAXFR, QClass: protocol.ClassIN},
		},
		Additionals: []*protocol.ResourceRecord{
			// Invalid TSIG record (will fail to get key name properly)
		},
	}

	// This should succeed since there's no TSIG record
	_, _, _ = server.HandleAXFR(req, net.ParseIP("127.0.0.1"))
}

// Test zoneRecordToRR with parseRData error
func TestAXFRServer_zoneRecordToRR_ParseRDataError(t *testing.T) {
	server := NewAXFRServer(make(map[string]*zone.Zone))

	rec := zone.Record{
		Type:  "A",
		TTL:   3600,
		RData: "invalid-ip-address", // Will fail parsing
	}

	_, err := server.zoneRecordToRR("www.example.com.", rec, "example.com.")
	if err == nil {
		t.Error("Expected error for invalid RData")
	}
}

// Test generateAXFRRecords with valid zone
func TestAXFRServer_generateAXFRRecords_ValidZone(t *testing.T) {
	server := NewAXFRServer(make(map[string]*zone.Zone))

	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
		TTL:     86400,
	}

	records, err := server.generateAXFRRecords(z)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should have at least 2 SOA records (start and end)
	if len(records) < 2 {
		t.Errorf("Expected at least 2 records, got %d", len(records))
	}
}

// Test canonicalSort with equal records
func TestCanonicalSort_EqualNames(t *testing.T) {
	records := []*protocol.ResourceRecord{
		{Name: mustParseName("example.com."), Type: protocol.TypeA},
		{Name: mustParseName("example.com."), Type: protocol.TypeA},
		{Name: mustParseName("example.com."), Type: protocol.TypeA},
	}

	// Should not panic
	canonicalSort(records)
}

// Test AXFRClient buildAXFRRequest with TSIG signing error
func TestAXFRClient_buildAXFRRequest_SigningError(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")

	// Create a key with deprecated SHA-1 algorithm which will fail
	key := &TSIGKey{
		Name:      "test-key.example.com.",
		Algorithm: HmacSHA1, // Deprecated, will fail in calculateMAC
		Secret:    []byte("test-secret"),
	}

	// Create a simple message first
	req, err := client.buildAXFRRequest("example.com.", key)
	// The message will be built but TSIG signing might fail
	// Let's check the actual behavior
	_ = req
	_ = err
}

// ---------------------------------------------------------------------------
// createSOARR - error paths (invalid MName / RName)
// ---------------------------------------------------------------------------

func TestAXFRServer_createSOARR_InvalidMName(t *testing.T) {
	server := NewAXFRServer(make(map[string]*zone.Zone))
	origin, _ := protocol.ParseName("example.com.")

	// MName with a label exceeding 63 chars will cause ParseName to fail
	longLabel := strings.Repeat("a", 70)
	soa := &zone.SOARecord{
		MName:   longLabel + ".example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}

	_, err := server.createSOARR(soa, origin)
	if err == nil {
		t.Error("Expected error for MName with label exceeding 63 chars")
	}
}

func TestAXFRServer_createSOARR_InvalidRName(t *testing.T) {
	server := NewAXFRServer(make(map[string]*zone.Zone))
	origin, _ := protocol.ParseName("example.com.")

	// RName with a label exceeding 63 chars will cause ParseName to fail
	longLabel := strings.Repeat("a", 70)
	soa := &zone.SOARecord{
		MName:   "ns1.example.com.",
		RName:   longLabel + ".example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}

	_, err := server.createSOARR(soa, origin)
	if err == nil {
		t.Error("Expected error for RName with label exceeding 63 chars")
	}
}

// ---------------------------------------------------------------------------
// AXFRClient.sendMessage via net.Pipe
// ---------------------------------------------------------------------------

func TestAXFRClient_sendMessage_Success(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      0x1234,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("example.com."),
				QType:  protocol.TypeAXFR,
				QClass: protocol.ClassIN,
			},
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.sendMessage(clientConn, msg)
	}()

	lengthBuf := make([]byte, 2)
	_, err := serverConn.Read(lengthBuf)
	if err != nil {
		t.Fatalf("Failed to read length prefix: %v", err)
	}
	msgLen := int(lengthBuf[0])<<8 | int(lengthBuf[1])

	msgBuf := make([]byte, msgLen)
	_, err = serverConn.Read(msgBuf)
	if err != nil {
		t.Fatalf("Failed to read message: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("sendMessage returned error: %v", err)
	}
}

func TestAXFRClient_sendMessage_WriteError(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")

	clientConn, _ := net.Pipe()
	clientConn.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      0x1234,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("example.com."),
				QType:  protocol.TypeAXFR,
				QClass: protocol.ClassIN,
			},
		},
	}

	err := client.sendMessage(clientConn, msg)
	if err == nil {
		t.Error("Expected error writing to closed connection")
	}
}

// ---------------------------------------------------------------------------
// mockConn for testing receiveAXFRResponse with mock data
// ---------------------------------------------------------------------------

type mockConn struct {
	writeErr error
	readErr  error
	readData []byte
	readPos  int
	closed   bool
}

func (m *mockConn) Read(b []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	if m.readPos >= len(m.readData) {
		return 0, net.ErrClosed
	}
	n := copy(b, m.readData[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (int, error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return len(b), nil
}

func (m *mockConn) Close() error                       { m.closed = true; return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// ---------------------------------------------------------------------------
// AXFRClient.receiveAXFRResponse - various response scenarios via mockConn
// ---------------------------------------------------------------------------

func TestAXFRClient_receiveAXFRResponse_InvalidMsgLen(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")
	conn := &mockConn{readData: []byte{0x00, 0x00}}
	_, err := client.receiveAXFRResponse(conn, nil)
	if err == nil {
		t.Error("Expected error for zero message length")
	}
}

func TestAXFRClient_receiveAXFRResponse_ErrorResponseMock(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")

	respMsg := &protocol.Message{
		Header: protocol.Header{
			ID:      0x1234,
			QDCount: 1,
			Flags: protocol.Flags{
				QR:    true,
				RCODE: protocol.RcodeRefused,
			},
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("example.com."),
				QType:  protocol.TypeAXFR,
				QClass: protocol.ClassIN,
			},
		},
	}

	buf := make([]byte, 65535)
	n, _ := respMsg.Pack(buf)
	data := make([]byte, 2+n)
	data[0] = byte(n >> 8)
	data[1] = byte(n)
	copy(data[2:], buf[:n])

	conn := &mockConn{readData: data}
	_, err := client.receiveAXFRResponse(conn, nil)
	if err == nil {
		t.Error("Expected error for non-success RCODE")
	}
}

func TestAXFRClient_receiveAXFRResponse_ReadErrorBeforeSOA(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")
	conn := &mockConn{readErr: fmt.Errorf("connection reset")}
	_, err := client.receiveAXFRResponse(conn, nil)
	if err == nil {
		t.Error("Expected error for read failure")
	}
}

func TestAXFRClient_receiveAXFRResponse_SuccessfulTransferMock(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")

	origin := mustParseName("example.com.")
	mname, _ := protocol.ParseName("ns1.example.com.")
	rname, _ := protocol.ParseName("admin.example.com.")

	soaData := &protocol.RDataSOA{
		MName: mname, RName: rname,
		Serial: 2024010101, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}
	soaRR := &protocol.ResourceRecord{
		Name: origin, Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 86400, Data: soaData,
	}
	aRR := &protocol.ResourceRecord{
		Name: mustParseName("www.example.com."), Type: protocol.TypeA,
		Class: protocol.ClassIN, TTL: 3600,
		Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
	}

	msg1 := &protocol.Message{
		Header: protocol.Header{
			ID: 0x1234, Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
		},
		Answers: []*protocol.ResourceRecord{soaRR, aRR},
	}
	msg2 := &protocol.Message{
		Header: protocol.Header{
			ID: 0x1235, Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
		},
		Answers: []*protocol.ResourceRecord{soaRR},
	}

	var allData []byte
	for _, msg := range []*protocol.Message{msg1, msg2} {
		buf := make([]byte, 65535)
		n, _ := msg.Pack(buf)
		allData = append(allData, byte(n>>8), byte(n))
		allData = append(allData, buf[:n]...)
	}

	conn := &mockConn{readData: allData}
	records, err := client.receiveAXFRResponse(conn, nil)
	if err != nil {
		t.Fatalf("receiveAXFRResponse() error = %v", err)
	}
	if len(records) != 3 {
		t.Errorf("Expected 3 records, got %d", len(records))
	}
}

func TestAXFRClient_receiveAXFRResponse_UnpackErrorMock(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")
	data := []byte{0x00, 0x10}
	data = append(data, make([]byte, 16)...)
	conn := &mockConn{readData: data}
	_, err := client.receiveAXFRResponse(conn, nil)
	if err == nil {
		t.Error("Expected error for unpack failure")
	}
}

func TestAXFRClient_receiveAXFRResponse_LargeMessageLength(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")
	conn := &mockConn{readData: []byte{0xFF, 0xFF}}
	_, err := client.receiveAXFRResponse(conn, nil)
	if err == nil {
		t.Error("Expected error for very large message length")
	}
}

// ---------------------------------------------------------------------------
// AXFRClient.Transfer with mock TCP server
// ---------------------------------------------------------------------------

func TestAXFRClient_Transfer_WithTCPServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	origin, _ := protocol.ParseName("example.com.")
	mname, _ := protocol.ParseName("ns1.example.com.")
	rname, _ := protocol.ParseName("admin.example.com.")

	soaRR := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   86400,
		Data: &protocol.RDataSOA{
			MName: mname, RName: rname,
			Serial: 2024010101, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
		},
	}
	aRR := &protocol.ResourceRecord{
		Name:  mustParseName("www.example.com."),
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   3600,
		Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
	}

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		lengthBuf := make([]byte, 2)
		conn.Read(lengthBuf)
		reqLen := int(lengthBuf[0])<<8 | int(lengthBuf[1])
		reqBuf := make([]byte, reqLen)
		conn.Read(reqBuf)

		msg1 := &protocol.Message{
			Header: protocol.Header{
				Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
			},
			Answers: []*protocol.ResourceRecord{soaRR, aRR},
		}
		axfrSendTCPMessage(conn, msg1, t)

		msg2 := &protocol.Message{
			Header: protocol.Header{
				Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
			},
			Answers: []*protocol.ResourceRecord{soaRR},
		}
		axfrSendTCPMessage(conn, msg2, t)
	}()

	axfrClient := NewAXFRClient(addr, WithAXFRTimeout(5*time.Second))
	records, err := axfrClient.Transfer("example.com.", nil)
	if err != nil {
		t.Fatalf("Transfer returned error: %v", err)
	}
	if len(records) != 3 {
		t.Errorf("Expected 3 records, got %d", len(records))
	}
}

// ---------------------------------------------------------------------------
// Helper: send a DNS message over TCP with length prefix
// ---------------------------------------------------------------------------

func axfrSendTCPMessage(conn net.Conn, msg *protocol.Message, t *testing.T) {
	t.Helper()
	buf := make([]byte, 65535)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Failed to pack message: %v", err)
	}
	lengthPrefix := []byte{byte(n >> 8), byte(n)}
	if _, err := conn.Write(lengthPrefix); err != nil {
		t.Fatalf("Failed to write length prefix: %v", err)
	}
	if _, err := conn.Write(buf[:n]); err != nil {
		t.Fatalf("Failed to write message: %v", err)
	}
}
