package transfer

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ---------------------------------------------------------------------------
// IXFRServer - HandleIXFR with no SOA record
// ---------------------------------------------------------------------------

func TestIXFRServer_HandleIXFR_NoSOA_Coverage(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	z := zone.NewZone("example.com.")
	// No SOA set
	z.SOA = nil
	server.zones["example.com."] = z

	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1001,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeIXFR, QClass: protocol.ClassIN},
		},
	}

	_, err := server.HandleIXFR(req, net.ParseIP("127.0.0.1"))
	if err == nil {
		t.Error("Expected error for zone with no SOA")
	}
}

// ---------------------------------------------------------------------------
// IXFRServer - HandleIXFR client serial is current (single SOA response)
// ---------------------------------------------------------------------------

func TestIXFRServer_HandleIXFR_UpToDate(t *testing.T) {
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
		TTL:     86400,
	}
	server.zones["example.com."] = z

	name, _ := protocol.ParseName("example.com.")
	// Include current serial in Authority section
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

	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1002,
			QDCount: 1,
			NSCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeIXFR, QClass: protocol.ClassIN},
		},
		Authorities: []*protocol.ResourceRecord{soaRR},
	}

	records, err := server.HandleIXFR(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleIXFR() error = %v", err)
	}
	// Should return single SOA record when up-to-date
	if len(records) != 1 {
		t.Errorf("Expected 1 record (single SOA), got %d", len(records))
	}
}

// ---------------------------------------------------------------------------
// IXFRServer - HandleIXFR with incremental changes available
// ---------------------------------------------------------------------------

func TestIXFRServer_HandleIXFR_IncrementalChanges(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010103,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
		TTL:     86400,
	}
	server.zones["example.com."] = z

	// Add journal entries
	server.RecordChange("example.com.", 2024010101, 2024010102,
		[]zone.RecordChange{
			{Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "192.0.2.1"},
		},
		[]zone.RecordChange{},
	)
	server.RecordChange("example.com.", 2024010102, 2024010103,
		[]zone.RecordChange{
			{Name: "mail.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "192.0.2.10"},
		},
		[]zone.RecordChange{
			{Name: "old.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "192.0.2.99"},
		},
	)

	name, _ := protocol.ParseName("example.com.")
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

	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1003,
			QDCount: 1,
			NSCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeIXFR, QClass: protocol.ClassIN},
		},
		Authorities: []*protocol.ResourceRecord{soaRR},
	}

	records, err := server.HandleIXFR(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleIXFR() error = %v", err)
	}
	// Should have records for incremental transfer
	if len(records) == 0 {
		t.Error("Expected non-zero records for incremental transfer")
	}
}

// ---------------------------------------------------------------------------
// IXFRServer - HandleIXFR with journal that doesn't cover client serial
// ---------------------------------------------------------------------------

func TestIXFRServer_HandleIXFR_JournalGap(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010105,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
		TTL:     86400,
	}
	server.zones["example.com."] = z

	// Add journal entries that don't cover the client serial
	server.RecordChange("example.com.", 2024010103, 2024010104,
		[]zone.RecordChange{
			{Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "192.0.2.1"},
		},
		[]zone.RecordChange{},
	)

	name, _ := protocol.ParseName("example.com.")
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

	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1004,
			QDCount: 1,
			NSCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeIXFR, QClass: protocol.ClassIN},
		},
		Authorities: []*protocol.ResourceRecord{soaRR},
	}

	// This should fall back to AXFR since journal doesn't cover the serial
	records, err := server.HandleIXFR(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Logf("HandleIXFR with journal gap: %v (expected fallback or error)", err)
	}
	_ = records
}

// ---------------------------------------------------------------------------
// IXFRServer - HandleIXFR not authorized
// ---------------------------------------------------------------------------

func TestIXFRServer_HandleIXFR_NotAuthorized(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	// Set allow list that doesn't include client
	_, network, _ := net.ParseCIDR("10.0.0.0/8")
	axfrServer.allowList = []net.IPNet{*network}
	server := NewIXFRServer(axfrServer)

	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1005,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeIXFR, QClass: protocol.ClassIN},
		},
	}

	_, err := server.HandleIXFR(req, net.ParseIP("192.168.1.1"))
	if err == nil {
		t.Error("Expected error for unauthorized client")
	}
}

// ---------------------------------------------------------------------------
// IXFRServer - HandleIXFR invalid query type
// ---------------------------------------------------------------------------

func TestIXFRServer_HandleIXFR_InvalidQueryType(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1006,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN}, // Wrong type
		},
	}

	_, err := server.HandleIXFR(req, net.ParseIP("127.0.0.1"))
	if err == nil {
		t.Error("Expected error for invalid query type")
	}
}

// ---------------------------------------------------------------------------
// IXFRServer - HandleIXFR zone not found
// ---------------------------------------------------------------------------

func TestIXFRServer_HandleIXFR_ZoneNotFound(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	name, _ := protocol.ParseName("nonexistent.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1007,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeIXFR, QClass: protocol.ClassIN},
		},
	}

	_, err := server.HandleIXFR(req, net.ParseIP("127.0.0.1"))
	if err == nil {
		t.Error("Expected error for zone not found")
	}
}

// ---------------------------------------------------------------------------
// IXFRServer - HandleIXFR with multiple questions
// ---------------------------------------------------------------------------

func TestIXFRServer_HandleIXFR_MultipleQuestions_Coverage(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1008,
			QDCount: 2,
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeIXFR, QClass: protocol.ClassIN},
			{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
	}

	_, err := server.HandleIXFR(req, net.ParseIP("127.0.0.1"))
	if err == nil {
		t.Error("Expected error for multiple questions")
	}
}

// ---------------------------------------------------------------------------
// IXFRClient - buildIXFRRequest tests
// ---------------------------------------------------------------------------

func TestIXFRClient_buildIXFRRequest_ValidName(t *testing.T) {
	client := NewIXFRClient("ns1.example.com:53")

	req, err := client.buildIXFRRequest("example.com.", 100, nil)
	if err != nil {
		t.Fatalf("buildIXFRRequest() error = %v", err)
	}
	if req == nil {
		t.Fatal("Expected non-nil request")
	}
	if len(req.Questions) != 1 {
		t.Errorf("Expected 1 question, got %d", len(req.Questions))
	}
}
