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

func TestZoneNameExists(t *testing.T) {
	testZone := &zone.Zone{
		Origin:  "example.com.",
		Records: make(map[string][]zone.Record),
	}

	// Add some records
	testZone.Records["www.example.com."] = []zone.Record{
		{Name: "www", TTL: 300, Type: "A", RData: "192.168.1.1"},
	}

	// Test existing name
	result := zoneNameExists(testZone, "www.example.com.")
	if !result {
		t.Error("zoneNameExists should return true for existing name")
	}

	// Test non-existent name
	result = zoneNameExists(testZone, "nonexistent.example.com.")
	if result {
		t.Error("zoneNameExists should return false for non-existent name")
	}
}

func TestZoneTypeExists(t *testing.T) {
	testZone := &zone.Zone{
		Origin:  "example.com.",
		Records: make(map[string][]zone.Record),
	}

	// Add some records
	testZone.Records["www.example.com."] = []zone.Record{
		{Name: "www", TTL: 300, Type: "A", RData: "192.168.1.1"},
	}

	// Test existing type
	result := zoneTypeExists(testZone, "www.example.com.", protocol.TypeA)
	if !result {
		t.Error("zoneTypeExists should return true for existing type")
	}

	// Test non-existent type
	result = zoneTypeExists(testZone, "www.example.com.", protocol.TypeAAAA)
	if result {
		t.Error("zoneTypeExists should return false for non-existent type")
	}
}

func TestZoneDeleteRRSet(t *testing.T) {
	testZone := &zone.Zone{
		Origin:  "example.com.",
		Records: make(map[string][]zone.Record),
	}

	// Add some records
	testZone.Records["www.example.com."] = []zone.Record{
		{Name: "www", TTL: 300, Type: "A", RData: "192.168.1.1"},
		{Name: "www", TTL: 300, Type: "A", RData: "192.168.1.2"},
		{Name: "www", TTL: 300, Type: "AAAA", RData: "::1"},
	}

	zoneDeleteRRSet(testZone, "www.example.com.", protocol.TypeA)

	// Should only have AAAA record left
	if len(testZone.Records["www.example.com."]) != 1 {
		t.Errorf("Expected 1 record after RRSet deletion, got %d", len(testZone.Records["www.example.com."]))
	}
}

func TestZoneRecordExists(t *testing.T) {
	testZone := &zone.Zone{
		Origin:  "example.com.",
		Records: make(map[string][]zone.Record),
	}

	// Add some records
	testZone.Records["www.example.com."] = []zone.Record{
		{Name: "www", TTL: 300, Type: "A", RData: "192.168.1.1"},
	}

	// Test existing record
	result := zoneRecordExists(testZone, "www.example.com.", protocol.TypeA, "192.168.1.1")
	if !result {
		t.Error("zoneRecordExists should return true for existing record")
	}

	// Test non-existent record
	result = zoneRecordExists(testZone, "www.example.com.", protocol.TypeA, "10.0.0.1")
	if result {
		t.Error("zoneRecordExists should return false for non-existent record")
	}
}

func TestZoneDeleteRecord(t *testing.T) {
	testZone := &zone.Zone{
		Origin:  "example.com.",
		Records: make(map[string][]zone.Record),
	}

	// Add some records
	testZone.Records["www.example.com."] = []zone.Record{
		{Name: "www", TTL: 300, Type: "A", RData: "192.168.1.1"},
		{Name: "www", TTL: 300, Type: "A", RData: "192.168.1.2"},
	}

	zoneDeleteRecord(testZone, "www.example.com.", protocol.TypeA, "192.168.1.1")

	// Should have one record left
	if len(testZone.Records["www.example.com."]) != 1 {
		t.Errorf("Expected 1 record after deletion, got %d", len(testZone.Records["www.example.com."]))
	}
}

func TestZoneDeleteName(t *testing.T) {
	testZone := &zone.Zone{
		Origin:  "example.com.",
		Records: make(map[string][]zone.Record),
	}

	// Add some records
	testZone.Records["www.example.com."] = []zone.Record{
		{Name: "www", TTL: 300, Type: "A", RData: "192.168.1.1"},
		{Name: "www", TTL: 300, Type: "AAAA", RData: "::1"},
	}
	testZone.Records["ftp.example.com."] = []zone.Record{
		{Name: "ftp", TTL: 300, Type: "A", RData: "192.168.1.2"},
	}

	zoneDeleteName(testZone, "www.example.com.")

	// Should have ftp record left but not www
	if _, exists := testZone.Records["www.example.com."]; exists {
		t.Error("www.example.com. should be deleted")
	}
	if _, exists := testZone.Records["ftp.example.com."]; !exists {
		t.Error("ftp.example.com. should still exist")
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

func TestDynamicDNSHandler_checkPrerequisites(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	handler := NewDynamicDNSHandler(zones)

	// Create a zone with records
	z := zone.NewZone("example.com.")
	z.Records["www.example.com."] = []zone.Record{
		{Name: "www.example.com.", Type: "A", RData: "192.0.2.1"},
	}

	// Test YXDOMAIN - name must exist
	name1, _ := protocol.ParseName("www.example.com.")
	prereqs1 := []*protocol.ResourceRecord{
		{
			Name:  name1,
			Type:  protocol.TypeANY,
			Class: protocol.ClassANY,
		},
	}
	err := handler.checkPrerequisites(z, prereqs1)
	if err != nil {
		t.Errorf("checkPrerequisites(YXDOMAIN) should pass for existing name: %v", err)
	}

	// Test NXDOMAIN - name must not exist
	name2, _ := protocol.ParseName("nonexistent.example.com.")
	prereqs2 := []*protocol.ResourceRecord{
		{
			Name:  name2,
			Type:  protocol.TypeANY,
			Class: protocol.ClassNONE,
		},
	}
	err = handler.checkPrerequisites(z, prereqs2)
	if err != nil {
		t.Errorf("checkPrerequisites(NXDOMAIN) should pass for non-existing name: %v", err)
	}

	// Test YXRRSET - RRset must exist
	prereqs3 := []*protocol.ResourceRecord{
		{
			Name:  name1,
			Type:  protocol.TypeA,
			Class: protocol.ClassANY,
		},
	}
	err = handler.checkPrerequisites(z, prereqs3)
	if err != nil {
		t.Errorf("checkPrerequisites(YXRRSET) should pass for existing type: %v", err)
	}

	// Test NXRRSET - RRset must not exist
	prereqs4 := []*protocol.ResourceRecord{
		{
			Name:  name1,
			Type:  protocol.TypeAAAA,
			Class: protocol.ClassNONE,
		},
	}
	err = handler.checkPrerequisites(z, prereqs4)
	if err != nil {
		t.Errorf("checkPrerequisites(NXRRSET) should pass for non-existing type: %v", err)
	}

	// Test failing YXDOMAIN - name should exist but doesn't
	name3, _ := protocol.ParseName("absent.example.com.")
	prereqs5 := []*protocol.ResourceRecord{
		{
			Name:  name3,
			Type:  protocol.TypeANY,
			Class: protocol.ClassANY,
		},
	}
	err = handler.checkPrerequisites(z, prereqs5)
	if err == nil {
		t.Error("checkPrerequisites should fail when name doesn't exist")
	}

	// Test failing NXDOMAIN - name shouldn't exist but does
	prereqs6 := []*protocol.ResourceRecord{
		{
			Name:  name1,
			Type:  protocol.TypeANY,
			Class: protocol.ClassNONE,
		},
	}
	err = handler.checkPrerequisites(z, prereqs6)
	if err == nil {
		t.Error("checkPrerequisites should fail when name exists but shouldn't")
	}
}

func TestDynamicDNSHandler_HandleUpdate_WithUpdates(t *testing.T) {
	zones := make(map[string]*zone.Zone)

	// Add a zone
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:  "ns1.example.com.",
		RName:  "admin.example.com.",
		Serial: 2024010101,
	}
	zones["example.com."] = z

	// Create handler with TSIG key store
	handler := NewDynamicDNSHandler(zones)
	ks := NewKeyStore()
	ks.AddKey(&TSIGKey{
		Name:      "key.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("test-secret-key-12345678901234"),
	})
	handler.SetKeyStore(ks)

	// Create UPDATE request with TSIG
	name, _ := protocol.ParseName("example.com.")
	updateName, _ := protocol.ParseName("new.example.com.")

	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
			NSCount: 1,
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
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  updateName,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   3600,
				Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
			},
		},
	}

	// Sign the message
	tsigRR, _ := SignMessage(req, &TSIGKey{
		Name:      "key.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("test-secret-key-12345678901234"),
	}, 300)
	req.Additionals = append(req.Additionals, tsigRR)

	clientIP := net.ParseIP("127.0.0.1")
	resp, err := handler.HandleUpdate(req, clientIP)

	if err != nil {
		t.Fatalf("HandleUpdate() error = %v", err)
	}

	if resp == nil {
		t.Fatal("HandleUpdate() returned nil response")
	}
}

func TestApplyUpdate_DeleteName(t *testing.T) {
	z := zone.NewZone("example.com.")

	// Add records
	z.Records["www.example.com."] = []zone.Record{
		{Name: "www.example.com.", Type: "A", TTL: 3600, RData: "192.0.2.1"},
	}

	update := &UpdateRequest{
		ZoneName: "example.com.",
		Updates: []UpdateOperation{
			{
				Name:      "www.example.com.",
				Operation: UpdateOpDeleteName,
			},
		},
	}

	if err := ApplyUpdate(z, update); err != nil {
		t.Fatalf("ApplyUpdate() error = %v", err)
	}

	// Verify all records were deleted
	if len(z.Records["www.example.com."]) != 0 {
		t.Error("Expected all records to be deleted")
	}
}

func TestApplyUpdate_DeleteRecord(t *testing.T) {
	z := zone.NewZone("example.com.")

	// Add records
	z.Records["www.example.com."] = []zone.Record{
		{Name: "www.example.com.", Type: "A", TTL: 3600, RData: "192.0.2.1"},
		{Name: "www.example.com.", Type: "A", TTL: 3600, RData: "192.0.2.2"},
	}

	update := &UpdateRequest{
		ZoneName: "example.com.",
		Updates: []UpdateOperation{
			{
				Name:      "www.example.com.",
				Type:      protocol.TypeA,
				RData:     "192.0.2.1",
				Operation: UpdateOpDelete,
			},
		},
	}

	if err := ApplyUpdate(z, update); err != nil {
		t.Fatalf("ApplyUpdate() error = %v", err)
	}

	// Verify only one record was deleted
	records := z.Records["www.example.com."]
	if len(records) != 1 {
		t.Errorf("Expected 1 record, got %d", len(records))
	}
	if records[0].RData != "192.0.2.2" {
		t.Error("Wrong record was deleted")
	}
}

func TestCheckPrerequisiteOnZone(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.Records["www.example.com."] = []zone.Record{
		{Name: "www.example.com.", Type: "A", TTL: 3600, RData: "192.0.2.1"},
	}

	tests := []struct {
		name      string
		precond   UpdatePrerequisite
		wantError bool
	}{
		{
			name: "YXRRSET exists",
			precond: UpdatePrerequisite{
				Name:      "www.example.com.",
				Type:      protocol.TypeA,
				Condition: PrecondExists,
			},
			wantError: false,
		},
		{
			name: "YXRRSET not exists",
			precond: UpdatePrerequisite{
				Name:      "www.example.com.",
				Type:      protocol.TypeAAAA,
				Condition: PrecondExists,
			},
			wantError: true,
		},
		{
			name: "NXRRSET not exists",
			precond: UpdatePrerequisite{
				Name:      "www.example.com.",
				Type:      protocol.TypeAAAA,
				Condition: PrecondNotExists,
			},
			wantError: false,
		},
		{
			name: "NXRRSET exists",
			precond: UpdatePrerequisite{
				Name:      "www.example.com.",
				Type:      protocol.TypeA,
				Condition: PrecondNotExists,
			},
			wantError: true,
		},
		{
			name: "YXDOMAIN exists",
			precond: UpdatePrerequisite{
				Name:      "www.example.com.",
				Condition: PrecondNameInUse,
			},
			wantError: false,
		},
		{
			name: "YXDOMAIN not exists",
			precond: UpdatePrerequisite{
				Name:      "nonexistent.example.com.",
				Condition: PrecondNameInUse,
			},
			wantError: true,
		},
		{
			name: "NXDOMAIN not exists",
			precond: UpdatePrerequisite{
				Name:      "nonexistent.example.com.",
				Condition: PrecondNameNotInUse,
			},
			wantError: false,
		},
		{
			name: "NXDOMAIN exists",
			precond: UpdatePrerequisite{
				Name:      "www.example.com.",
				Condition: PrecondNameNotInUse,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkPrerequisiteOnZone(z, tt.precond)
			if tt.wantError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
