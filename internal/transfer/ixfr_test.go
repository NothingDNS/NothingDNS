package transfer

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestNewIXFRServer(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	if server == nil {
		t.Fatal("NewIXFRServer() returned nil")
	}

	if server.axfrServer != axfrServer {
		t.Error("AXFR server not set correctly")
	}

	if server.journals == nil {
		t.Error("journals map not initialized")
	}

	if server.maxJournalSize != 100 {
		t.Errorf("Expected default maxJournalSize 100, got %d", server.maxJournalSize)
	}
}

func TestIXFRServer_SetMaxJournalSize(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	server.SetMaxJournalSize(50)

	if server.maxJournalSize != 50 {
		t.Errorf("Expected maxJournalSize 50, got %d", server.maxJournalSize)
	}
}

func TestIXFRServer_RecordChange(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)
	server.SetMaxJournalSize(3)

	zoneName := "example.com."

	// Record first change
	server.RecordChange(zoneName, 2024010101, 2024010102,
		[]zone.RecordChange{{Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "192.0.2.1"}},
		[]zone.RecordChange{},
	)

	// Record second change
	server.RecordChange(zoneName, 2024010102, 2024010103,
		[]zone.RecordChange{},
		[]zone.RecordChange{{Name: "old.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "192.0.2.2"}},
	)

	// Check journal has 2 entries
	if len(server.journals[zoneName]) != 2 {
		t.Errorf("Expected 2 journal entries, got %d", len(server.journals[zoneName]))
	}

	// Add more entries to test trimming
	server.RecordChange(zoneName, 2024010103, 2024010104, nil, nil)
	server.RecordChange(zoneName, 2024010104, 2024010105, nil, nil)

	// Check journal was trimmed to max size
	if len(server.journals[zoneName]) != 3 {
		t.Errorf("Expected 3 journal entries (trimmed), got %d", len(server.journals[zoneName]))
	}

	// Check oldest entry was removed
	if server.journals[zoneName][0].Serial != 2024010103 {
		t.Errorf("Expected oldest serial 2024010103, got %d", server.journals[zoneName][0].Serial)
	}
}

func TestIXFRServer_extractClientSerial(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	// Create IXFR request with SOA in Authority section
	origin, _ := protocol.ParseName("example.com.")
	mname, _ := protocol.ParseName("ns1.example.com.")
	rname, _ := protocol.ParseName("admin.example.com.")

	soaData := &protocol.RDataSOA{
		MName:   mname,
		RName:   rname,
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}

	soaRR := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   86400,
		Data:  soaData,
	}

	req := &protocol.Message{
		Header: protocol.Header{
			NSCount: 1,
		},
		Authorities: []*protocol.ResourceRecord{soaRR},
	}

	serial := server.extractClientSerial(req)
	if serial != 2024010101 {
		t.Errorf("Expected serial 2024010101, got %d", serial)
	}

	// Test request without SOA
	req2 := &protocol.Message{}
	serial2 := server.extractClientSerial(req2)
	if serial2 != 0 {
		t.Errorf("Expected serial 0 for request without SOA, got %d", serial2)
	}
}

func TestIXFRServer_generateSingleSOA(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

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

	records, err := server.generateSingleSOA(z)
	if err != nil {
		t.Fatalf("generateSingleSOA() error = %v", err)
	}

	if len(records) != 1 {
		t.Errorf("Expected 1 record, got %d", len(records))
	}

	if records[0].Type != protocol.TypeSOA {
		t.Errorf("Expected SOA record, got type %d", records[0].Type)
	}

	if soaData, ok := records[0].Data.(*protocol.RDataSOA); ok {
		if soaData.Serial != 2024010101 {
			t.Errorf("Expected serial 2024010101, got %d", soaData.Serial)
		}
	} else {
		t.Error("SOA data is not *protocol.RDataSOA")
	}
}

func TestIXFRServer_createSOAWithSerial(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

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

	rr := server.createSOAWithSerial(soa, origin, 2024010202)

	if rr.Type != protocol.TypeSOA {
		t.Errorf("Expected SOA type, got %d", rr.Type)
	}

	if soaData, ok := rr.Data.(*protocol.RDataSOA); ok {
		if soaData.Serial != 2024010202 {
			t.Errorf("Expected custom serial 2024010202, got %d", soaData.Serial)
		}
		// Check other fields preserved
		if soaData.MName.String() != "ns1.example.com." {
			t.Errorf("Expected MName ns1.example.com., got %s", soaData.MName.String())
		}
	} else {
		t.Error("SOA data is not *protocol.RDataSOA")
	}
}

func TestIXFRServer_changeToRR(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	change := zone.RecordChange{
		Name:  "www.example.com.",
		Type:  protocol.TypeA,
		TTL:   3600,
		RData: "192.0.2.1",
	}

	rr, err := server.changeToRR(change, "example.com.")
	if err != nil {
		t.Fatalf("changeToRR() error = %v", err)
	}

	if rr.Name.String() != "www.example.com." {
		t.Errorf("Expected name www.example.com., got %s", rr.Name.String())
	}

	if rr.Type != protocol.TypeA {
		t.Errorf("Expected type A, got %d", rr.Type)
	}

	if rr.TTL != 3600 {
		t.Errorf("Expected TTL 3600, got %d", rr.TTL)
	}

	if aData, ok := rr.Data.(*protocol.RDataA); ok {
		expected := net.ParseIP("192.0.2.1").To4()
		if !bytes.Equal(aData.Address[:], expected) {
			t.Errorf("Expected IP %v, got %v", expected, aData.Address[:])
		}
	} else {
		t.Error("Data is not *protocol.RDataA")
	}
}

func TestIXFRServer_generateIncrementalIXFR(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	// Create zone
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010103,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}

	// Add journal entries
	server.RecordChange("example.com.", 2024010101, 2024010102,
		[]zone.RecordChange{{Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "192.0.2.1"}},
		[]zone.RecordChange{},
	)
	server.RecordChange("example.com.", 2024010102, 2024010103,
		[]zone.RecordChange{{Name: "mail.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "192.0.2.2"}},
		[]zone.RecordChange{},
	)

	// Generate incremental IXFR from serial 2024010101
	records, err := server.generateIncrementalIXFR(z, 2024010101)
	if err != nil {
		t.Fatalf("generateIncrementalIXFR() error = %v", err)
	}

	// Expected format:
	// SOA(2024010103) +
	// SOA(2024010102) + added(www) +
	// SOA(2024010102) + added(mail) +
	// SOA(2024010103)
	expectedMinRecords := 6 // At minimum 6 records
	if len(records) < expectedMinRecords {
		t.Errorf("Expected at least %d records, got %d", expectedMinRecords, len(records))
	}

	// First record should be SOA with server serial
	if records[0].Type != protocol.TypeSOA {
		t.Errorf("Expected first record to be SOA, got %d", records[0].Type)
	}

	// Last record should be SOA with server serial
	if records[len(records)-1].Type != protocol.TypeSOA {
		t.Errorf("Expected last record to be SOA, got %d", records[len(records)-1].Type)
	}
}

func TestNewIXFRClient(t *testing.T) {
	client := NewIXFRClient("ns1.example.com:53")

	if client == nil {
		t.Fatal("NewIXFRClient() returned nil")
	}

	if client.server != "ns1.example.com:53" {
		t.Errorf("Expected server ns1.example.com:53, got %s", client.server)
	}

	if client.timeout != 30*time.Second {
		t.Errorf("Expected default timeout 30s, got %v", client.timeout)
	}
}

func TestNewIXFRClient_WithOptions(t *testing.T) {
	ks := NewKeyStore()
	client := NewIXFRClient(
		"ns1.example.com:53",
		WithIXFRTimeout(60*time.Second),
		WithIXFRKeyStore(ks),
	)

	if client.timeout != 60*time.Second {
		t.Errorf("Expected timeout 60s, got %v", client.timeout)
	}

	if client.keyStore != ks {
		t.Error("KeyStore not set correctly")
	}
}

func TestIXFRClient_buildIXFRRequest(t *testing.T) {
	client := NewIXFRClient("ns1.example.com:53")

	req, err := client.buildIXFRRequest("example.com.", 2024010101, nil)
	if err != nil {
		t.Fatalf("buildIXFRRequest() error = %v", err)
	}

	if req.Header.QDCount != 1 {
		t.Errorf("Expected QDCount 1, got %d", req.Header.QDCount)
	}

	if len(req.Questions) != 1 {
		t.Fatal("Expected 1 question")
	}

	q := req.Questions[0]
	if q.QType != protocol.TypeIXFR {
		t.Errorf("Expected QType IXFR (%d), got %d", protocol.TypeIXFR, q.QType)
	}

	// Check Authority section has SOA
	if req.Header.NSCount != 1 {
		t.Errorf("Expected NSCount 1 (SOA in Authority), got %d", req.Header.NSCount)
	}

	if len(req.Authorities) != 1 {
		t.Fatal("Expected 1 authority record (SOA)")
	}

	if req.Authorities[0].Type != protocol.TypeSOA {
		t.Errorf("Expected SOA in Authority section, got type %d", req.Authorities[0].Type)
	}

	if soaData, ok := req.Authorities[0].Data.(*protocol.RDataSOA); ok {
		if soaData.Serial != 2024010101 {
			t.Errorf("Expected SOA serial 2024010101, got %d", soaData.Serial)
		}
	} else {
		t.Error("Authority data is not *protocol.RDataSOA")
	}
}

func TestIXFRClient_ParseIXFRResponse(t *testing.T) {
	client := NewIXFRClient("ns1.example.com:53")

	// Test single SOA (no changes)
	origin, _ := protocol.ParseName("example.com.")
	mname, _ := protocol.ParseName("ns1.example.com.")
	rname, _ := protocol.ParseName("admin.example.com.")

	soaData := &protocol.RDataSOA{
		MName:   mname,
		RName:   rname,
		Serial:  2024010101,
		Refresh: 3600,
	}

	singleSOA := []*protocol.ResourceRecord{{
		Name:  origin,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   86400,
		Data:  soaData,
	}}

	resp, err := client.ParseIXFRResponse(singleSOA)
	if err != nil {
		t.Fatalf("ParseIXFRResponse() error = %v", err)
	}

	if resp.NewSerial != 2024010101 {
		t.Errorf("Expected NewSerial 2024010101, got %d", resp.NewSerial)
	}

	if resp.OldSerial != 2024010101 {
		t.Errorf("Expected OldSerial 2024010101, got %d", resp.OldSerial)
	}

	// Test AXFR format detection
	axfrRecords := []*protocol.ResourceRecord{
		{Name: origin, Type: protocol.TypeSOA, Data: soaData},
		{Name: origin, Type: protocol.TypeA, Data: &protocol.RDataA{}},
		{Name: origin, Type: protocol.TypeSOA, Data: soaData},
	}

	resp2, err := client.ParseIXFRResponse(axfrRecords)
	if err != nil {
		t.Fatalf("ParseIXFRResponse() error = %v", err)
	}

	if !resp2.IsAXFR {
		t.Error("Expected IsAXFR to be true")
	}
}

func TestIXFRServer_HandleIXFR_NoZone(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	// Create IXFR request
	name, _ := protocol.ParseName("nonexistent.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeIXFR,
				QClass: protocol.ClassIN,
			},
		},
	}

	clientIP := net.ParseIP("127.0.0.1")
	_, err := server.HandleIXFR(req, clientIP)

	if err == nil {
		t.Error("Expected error for non-existent zone")
	}
}

func TestIXFRServer_HandleIXFR_NoSOA(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	axfrServer := NewAXFRServer(zones)
	server := NewIXFRServer(axfrServer)

	// Add zone without SOA
	z := zone.NewZone("example.com.")
	zones["example.com."] = z

	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeIXFR,
				QClass: protocol.ClassIN,
			},
		},
	}

	clientIP := net.ParseIP("127.0.0.1")
	_, err := server.HandleIXFR(req, clientIP)

	if err == nil {
		t.Error("Expected error for zone without SOA")
	}
}

func TestIXFRServer_HandleIXFR_ClientUpToDate(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	axfrServer := NewAXFRServer(zones)
	server := NewIXFRServer(axfrServer)

	// Create zone
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
	}
	zones["example.com."] = z

	origin, _ := protocol.ParseName("example.com.")
	mname, _ := protocol.ParseName("ns1.example.com.")
	rname, _ := protocol.ParseName("admin.example.com.")

	soaData := &protocol.RDataSOA{
		MName:   mname,
		RName:   rname,
		Serial:  2024010101,
		Refresh: 3600,
	}

	soaRR := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   86400,
		Data:  soaData,
	}

	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
			NSCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeIXFR,
				QClass: protocol.ClassIN,
			},
		},
		Authorities: []*protocol.ResourceRecord{soaRR},
	}

	clientIP := net.ParseIP("127.0.0.1")
	records, err := server.HandleIXFR(req, clientIP)
	if err != nil {
		t.Fatalf("HandleIXFR() error = %v", err)
	}

	// Should return single SOA when client is up to date
	if len(records) != 1 {
		t.Errorf("Expected 1 record (single SOA), got %d", len(records))
	}

	if records[0].Type != protocol.TypeSOA {
		t.Errorf("Expected SOA record, got type %d", records[0].Type)
	}
}
