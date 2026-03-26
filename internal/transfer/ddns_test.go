package transfer

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestNewDynamicDNSHandler(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	handler := NewDynamicDNSHandler(zones)

	if handler == nil {
		t.Fatal("NewDynamicDNSHandler() returned nil")
	}

	if handler.zones == nil {
		t.Error("zones map not initialized")
	}

	if handler.keyStore == nil {
		t.Error("keyStore not initialized")
	}

	if handler.acl == nil {
		t.Error("acl map not initialized")
	}

	if handler.updateChan == nil {
		t.Error("updateChan not initialized")
	}
}

func TestDynamicDNSHandler_SetKeyStore(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	handler := NewDynamicDNSHandler(zones)

	ks := NewKeyStore()
	handler.SetKeyStore(ks)

	if handler.keyStore != ks {
		t.Error("SetKeyStore did not set the key store")
	}
}

func TestDynamicDNSHandler_AddACL(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	handler := NewDynamicDNSHandler(zones)

	_, network, _ := net.ParseCIDR("192.168.1.0/24")
	handler.AddACL("example.com.", network)

	networks, ok := handler.acl["example.com."]
	if !ok {
		t.Fatal("ACL not added for zone")
	}

	if len(networks) != 1 {
		t.Errorf("Expected 1 network, got %d", len(networks))
	}
}

func TestDynamicDNSHandler_IsAllowed(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	handler := NewDynamicDNSHandler(zones)

	// Test with no ACL (should allow all)
	if !handler.IsAllowed("example.com.", net.ParseIP("192.168.1.1")) {
		t.Error("Should allow all when no ACL set")
	}

	// Add ACL
	_, network, _ := net.ParseCIDR("10.0.0.0/8")
	handler.AddACL("example.com.", network)

	// Test allowed IP
	if !handler.IsAllowed("example.com.", net.ParseIP("10.1.2.3")) {
		t.Error("Should allow IP in allowed network")
	}

	// Test disallowed IP
	if handler.IsAllowed("example.com.", net.ParseIP("192.168.1.1")) {
		t.Error("Should not allow IP outside allowed network")
	}
}

func TestDynamicDNSHandler_GetUpdateChannel(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	handler := NewDynamicDNSHandler(zones)

	ch := handler.GetUpdateChannel()
	if ch == nil {
		t.Error("GetUpdateChannel() returned nil")
	}
}

func TestDynamicDNSHandler_HandleUpdate_NoZone(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	handler := NewDynamicDNSHandler(zones)

	// Create UPDATE request for non-existent zone
	name, _ := protocol.ParseName("nonexistent.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
			Flags: protocol.Flags{
				Opcode: protocol.OpcodeUpdate,
			},
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeSOA,
				QClass: protocol.ClassIN,
			},
		},
	}

	clientIP := net.ParseIP("127.0.0.1")
	resp, err := handler.HandleUpdate(req, clientIP)

	if err != nil {
		t.Fatalf("HandleUpdate() error = %v", err)
	}

	if resp == nil {
		t.Fatal("HandleUpdate() returned nil response")
	}

	// Should return NotZone
	if resp.Header.Flags.RCODE != protocol.RcodeNotZone {
		t.Errorf("Expected rcode NotZone (%d), got %d", protocol.RcodeNotZone, resp.Header.Flags.RCODE)
	}
}

func TestDynamicDNSHandler_HandleUpdate_NoTSIG(t *testing.T) {
	zones := make(map[string]*zone.Zone)

	// Add a zone
	z := zone.NewZone("example.com.")
	zones["example.com."] = z

	handler := NewDynamicDNSHandler(zones)

	// Create UPDATE request without TSIG
	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
			Flags: protocol.Flags{
				Opcode: protocol.OpcodeUpdate,
			},
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeSOA,
				QClass: protocol.ClassIN,
			},
		},
	}

	clientIP := net.ParseIP("127.0.0.1")
	resp, err := handler.HandleUpdate(req, clientIP)

	if err != nil {
		t.Fatalf("HandleUpdate() error = %v", err)
	}

	if resp == nil {
		t.Fatal("HandleUpdate() returned nil response")
	}

	// Should return Refused (no TSIG)
	if resp.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("Expected rcode Refused (%d), got %d", protocol.RcodeRefused, resp.Header.Flags.RCODE)
	}
}

func TestIsUpdateRequest(t *testing.T) {
	tests := []struct {
		name     string
		opcode   uint8
		qr       bool
		expected bool
	}{
		{"UPDATE request", protocol.OpcodeUpdate, false, true},
		{"UPDATE response", protocol.OpcodeUpdate, true, false},
		{"QUERY request", protocol.OpcodeQuery, false, false},
		{"NOTIFY request", protocol.OpcodeNotify, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &protocol.Message{
				Header: protocol.Header{
					Flags: protocol.Flags{
						Opcode: tt.opcode,
						QR:     tt.qr,
					},
				},
			}
			got := IsUpdateRequest(msg)
			if got != tt.expected {
				t.Errorf("IsUpdateRequest() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsUpdateResponse(t *testing.T) {
	tests := []struct {
		name     string
		opcode   uint8
		qr       bool
		expected bool
	}{
		{"UPDATE request", protocol.OpcodeUpdate, false, false},
		{"UPDATE response", protocol.OpcodeUpdate, true, true},
		{"QUERY response", protocol.OpcodeQuery, true, false},
		{"NOTIFY response", protocol.OpcodeNotify, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &protocol.Message{
				Header: protocol.Header{
					Flags: protocol.Flags{
						Opcode: tt.opcode,
						QR:     tt.qr,
					},
				},
			}
			got := IsUpdateResponse(msg)
			if got != tt.expected {
				t.Errorf("IsUpdateResponse() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestApplyUpdate_AddRecord(t *testing.T) {
	z := zone.NewZone("example.com.")

	update := &UpdateRequest{
		ZoneName: "example.com.",
		Updates: []UpdateOperation{
			{
				Name:      "www.example.com.",
				Type:      protocol.TypeA,
				TTL:       3600,
				RData:     "192.0.2.1",
				Operation: UpdateOpAdd,
			},
		},
	}

	if err := ApplyUpdate(z, update); err != nil {
		t.Fatalf("ApplyUpdate() error = %v", err)
	}

	// Verify record was added
	records := z.Records["www.example.com."]
	if len(records) != 1 {
		t.Errorf("Expected 1 record, got %d", len(records))
	}
}

func TestApplyUpdate_DeleteRRSet(t *testing.T) {
	z := zone.NewZone("example.com.")

	// Add a record first
	z.Records["www.example.com."] = []zone.Record{
		{Name: "www.example.com.", Type: "A", TTL: 3600, RData: "192.0.2.1"},
	}

	update := &UpdateRequest{
		ZoneName: "example.com.",
		Updates: []UpdateOperation{
			{
				Name:      "www.example.com.",
				Type:      protocol.TypeA,
				Operation: UpdateOpDeleteRRSet,
			},
		},
	}

	if err := ApplyUpdate(z, update); err != nil {
		t.Fatalf("ApplyUpdate() error = %v", err)
	}

	// Verify record was deleted
	records := z.Records["www.example.com."]
	if len(records) != 0 {
		t.Errorf("Expected 0 records, got %d", len(records))
	}
}

func TestParsePrerequisites(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	handler := NewDynamicDNSHandler(zones)

	// Create prerequisite records
	name, _ := protocol.ParseName("example.com.")
	prereqs := []*protocol.ResourceRecord{
		{
			Name:  name,
			Type:  protocol.TypeANY,
			Class: protocol.ClassANY,
		},
		{
			Name:  name,
			Type:  protocol.TypeANY,
			Class: protocol.ClassNONE,
		},
	}

	result := handler.parsePrerequisites(prereqs)

	if len(result) != 2 {
		t.Errorf("Expected 2 prerequisites, got %d", len(result))
	}

	if result[0].Condition != PrecondNameInUse {
		t.Errorf("Expected PrecondNameInUse, got %d", result[0].Condition)
	}

	if result[1].Condition != PrecondNameNotInUse {
		t.Errorf("Expected PrecondNameNotInUse, got %d", result[1].Condition)
	}
}

func TestParseUpdates(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	handler := NewDynamicDNSHandler(zones)

	// Create update records
	name, _ := protocol.ParseName("www.example.com.")
	updates := []*protocol.ResourceRecord{
		{
			Name:  name,
			Type:  protocol.TypeA,
			TTL:   3600,
			Class: protocol.ClassIN,
			Data:  &protocol.RDataA{},
		},
	}

	result, err := handler.parseUpdates(updates)
	if err != nil {
		t.Fatalf("parseUpdates() error = %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Expected 1 update, got %d", len(result))
	}

	if result[0].Operation != UpdateOpAdd {
		t.Errorf("Expected UpdateOpAdd, got %d", result[0].Operation)
	}
}

func TestZoneHelpers_NameExists(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.Records["www.example.com."] = []zone.Record{
		{Name: "www.example.com.", Type: "A", RData: "192.0.2.1"},
	}

	if !zoneNameExists(z, "www.example.com.") {
		t.Error("zoneNameExists should return true for existing name")
	}

	if zoneNameExists(z, "nonexistent.example.com.") {
		t.Error("zoneNameExists should return false for non-existing name")
	}
}

func TestZoneHelpers_TypeExists(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.Records["www.example.com."] = []zone.Record{
		{Name: "www.example.com.", Type: "A", RData: "192.0.2.1"},
	}

	if !zoneTypeExists(z, "www.example.com.", protocol.TypeA) {
		t.Error("zoneTypeExists should return true for existing type")
	}

	if zoneTypeExists(z, "www.example.com.", protocol.TypeAAAA) {
		t.Error("zoneTypeExists should return false for non-existing type")
	}
}
