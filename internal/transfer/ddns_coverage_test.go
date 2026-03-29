package transfer

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// helper to build a zone populated with test records.
func newTestZoneWithRecords() *zone.Zone {
	z := zone.NewZone("example.com.")
	z.Records["www.example.com."] = []zone.Record{
		{Name: "www.example.com.", Type: "A", TTL: 3600, RData: "192.0.2.1"},
		{Name: "www.example.com.", Type: "A", TTL: 3600, RData: "192.0.2.2"},
		{Name: "www.example.com.", Type: "AAAA", TTL: 3600, RData: "2001:db8::1"},
	}
	return z
}

// ---------------------------------------------------------------------------
// HandleUpdate – non-UPDATE opcode
// ---------------------------------------------------------------------------

func TestHandleUpdate_NonUpdateOpcode(t *testing.T) {
	handler := NewDynamicDNSHandler(make(map[string]*zone.Zone))

	req := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{
				Opcode: protocol.OpcodeQuery, // not OpcodeUpdate
			},
		},
	}

	resp, err := handler.HandleUpdate(req, net.ParseIP("127.0.0.1"))
	if err == nil {
		t.Fatal("expected error for non-UPDATE opcode, got nil")
	}
	if resp != nil {
		t.Fatalf("expected nil response for non-UPDATE opcode, got %+v", resp)
	}
}

// ---------------------------------------------------------------------------
// HandleUpdate – format error (wrong number of questions)
// ---------------------------------------------------------------------------

func TestHandleUpdate_FormatError_WrongQuestionCount(t *testing.T) {
	z := zone.NewZone("example.com.")
	handler := NewDynamicDNSHandler(map[string]*zone.Zone{"example.com.": z})

	req := &protocol.Message{
		Header: protocol.Header{
			QDCount: 0,
			Flags:   protocol.Flags{Opcode: protocol.OpcodeUpdate},
		},
		Questions: []*protocol.Question{}, // empty – must have exactly 1
	}

	resp, err := handler.HandleUpdate(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeFormatError {
		t.Errorf("expected RcodeFormatError, got %d", resp.Header.Flags.RCODE)
	}
}

// ---------------------------------------------------------------------------
// HandleUpdate – ACL refusal
// ---------------------------------------------------------------------------

func TestHandleUpdate_ACLRefused(t *testing.T) {
	z := zone.NewZone("example.com.")
	handler := NewDynamicDNSHandler(map[string]*zone.Zone{"example.com.": z})

	// Allow only 10.0.0.0/8
	_, network, _ := net.ParseCIDR("10.0.0.0/8")
	handler.AddACL("example.com.", network)

	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			QDCount: 1,
			Flags:   protocol.Flags{Opcode: protocol.OpcodeUpdate},
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
	}

	resp, err := handler.HandleUpdate(req, net.ParseIP("192.168.1.1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected RcodeRefused for disallowed IP, got %d", resp.Header.Flags.RCODE)
	}
}

// ---------------------------------------------------------------------------
// parseUpdates – ClassNONE / ClassANY paths (delete name, delete RRSet, delete specific)
// ---------------------------------------------------------------------------

func TestParseUpdates_ClassNONE_DeleteName(t *testing.T) {
	handler := NewDynamicDNSHandler(make(map[string]*zone.Zone))
	name, _ := protocol.ParseName("www.example.com.")

	updates := []*protocol.ResourceRecord{
		{
			Name:  name,
			Class: protocol.ClassNONE,
			Type:  protocol.TypeANY, // ClassNONE + TypeANY => DeleteName
		},
	}

	result, err := handler.parseUpdates(updates)
	if err != nil {
		t.Fatalf("parseUpdates() error = %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 update, got %d", len(result))
	}
	if result[0].Operation != UpdateOpDeleteName {
		t.Errorf("expected UpdateOpDeleteName, got %d", result[0].Operation)
	}
}

func TestParseUpdates_ClassNONE_DeleteRRSet(t *testing.T) {
	handler := NewDynamicDNSHandler(make(map[string]*zone.Zone))
	name, _ := protocol.ParseName("www.example.com.")

	updates := []*protocol.ResourceRecord{
		{
			Name:  name,
			Class: protocol.ClassNONE,
			Type:  protocol.TypeA, // ClassNONE + non-TypeANY => DeleteRRSet
		},
	}

	result, err := handler.parseUpdates(updates)
	if err != nil {
		t.Fatalf("parseUpdates() error = %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 update, got %d", len(result))
	}
	if result[0].Operation != UpdateOpDeleteRRSet {
		t.Errorf("expected UpdateOpDeleteRRSet, got %d", result[0].Operation)
	}
}

func TestParseUpdates_ClassANY_DeleteSpecific(t *testing.T) {
	handler := NewDynamicDNSHandler(make(map[string]*zone.Zone))
	name, _ := protocol.ParseName("www.example.com.")

	updates := []*protocol.ResourceRecord{
		{
			Name:  name,
			Class: protocol.ClassANY,
			Type:  protocol.TypeA,
			Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
		},
	}

	result, err := handler.parseUpdates(updates)
	if err != nil {
		t.Fatalf("parseUpdates() error = %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 update, got %d", len(result))
	}
	if result[0].Operation != UpdateOpDelete {
		t.Errorf("expected UpdateOpDelete, got %d", result[0].Operation)
	}
	if result[0].RData == "" {
		t.Error("expected non-empty RData for ClassANY delete specific")
	}
}

func TestParseUpdates_ClassIN_Add(t *testing.T) {
	handler := NewDynamicDNSHandler(make(map[string]*zone.Zone))
	name, _ := protocol.ParseName("www.example.com.")

	updates := []*protocol.ResourceRecord{
		{
			Name:  name,
			Class: protocol.ClassIN,
			Type:  protocol.TypeA,
			TTL:   3600,
			Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
		},
	}

	result, err := handler.parseUpdates(updates)
	if err != nil {
		t.Fatalf("parseUpdates() error = %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 update, got %d", len(result))
	}
	if result[0].Operation != UpdateOpAdd {
		t.Errorf("expected UpdateOpAdd, got %d", result[0].Operation)
	}
	if result[0].TTL != 3600 {
		t.Errorf("expected TTL 3600, got %d", result[0].TTL)
	}
}

func TestParseUpdates_MultipleOperations(t *testing.T) {
	handler := NewDynamicDNSHandler(make(map[string]*zone.Zone))
	name, _ := protocol.ParseName("www.example.com.")

	updates := []*protocol.ResourceRecord{
		{ // Add
			Name: name, Class: protocol.ClassIN, Type: protocol.TypeA,
			TTL: 3600, Data: &protocol.RDataA{Address: [4]byte{10, 0, 0, 1}},
		},
		{ // DeleteName
			Name: name, Class: protocol.ClassNONE, Type: protocol.TypeANY,
		},
		{ // DeleteRRSet
			Name: name, Class: protocol.ClassNONE, Type: protocol.TypeA,
		},
		{ // Delete specific
			Name: name, Class: protocol.ClassANY, Type: protocol.TypeA,
			Data: &protocol.RDataA{Address: [4]byte{10, 0, 0, 2}},
		},
	}

	result, err := handler.parseUpdates(updates)
	if err != nil {
		t.Fatalf("parseUpdates() error = %v", err)
	}
	if len(result) != 4 {
		t.Fatalf("expected 4 updates, got %d", len(result))
	}

	expectedOps := []UpdateOpType{UpdateOpAdd, UpdateOpDeleteName, UpdateOpDeleteRRSet, UpdateOpDelete}
	for i, op := range expectedOps {
		if result[i].Operation != op {
			t.Errorf("update[%d]: expected op %d, got %d", i, op, result[i].Operation)
		}
	}
}

// ---------------------------------------------------------------------------
// parsePrerequisites – value-dependent (default class) case
// ---------------------------------------------------------------------------

func TestParsePrerequisites_ValueDependent(t *testing.T) {
	handler := NewDynamicDNSHandler(make(map[string]*zone.Zone))
	name, _ := protocol.ParseName("www.example.com.")

	prereqs := []*protocol.ResourceRecord{
		{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN, // default class triggers PrecondExistsValue
			Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
		},
	}

	result := handler.parsePrerequisites(prereqs)
	if len(result) != 1 {
		t.Fatalf("expected 1 prerequisite, got %d", len(result))
	}
	if result[0].Condition != PrecondExistsValue {
		t.Errorf("expected PrecondExistsValue, got %d", result[0].Condition)
	}
	if result[0].Class != protocol.ClassIN {
		t.Errorf("expected ClassIN, got %d", result[0].Class)
	}
}

func TestParsePrerequisites_AllConditions(t *testing.T) {
	handler := NewDynamicDNSHandler(make(map[string]*zone.Zone))
	name, _ := protocol.ParseName("www.example.com.")

	tests := []struct {
		name      string
		class     uint16
		rrType    uint16
		expected  PreconditionType
	}{
		{"NameInUse", protocol.ClassANY, protocol.TypeANY, PrecondNameInUse},
		{"Exists", protocol.ClassANY, protocol.TypeA, PrecondExists},
		{"NameNotInUse", protocol.ClassNONE, protocol.TypeANY, PrecondNameNotInUse},
		{"NotExists", protocol.ClassNONE, protocol.TypeA, PrecondNotExists},
		{"ValueDependent", protocol.ClassIN, protocol.TypeA, PrecondExistsValue},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prereqs := []*protocol.ResourceRecord{
				{Name: name, Class: tt.class, Type: tt.rrType},
			}
			result := handler.parsePrerequisites(prereqs)
			if len(result) != 1 {
				t.Fatalf("expected 1 prerequisite, got %d", len(result))
			}
			if result[0].Condition != tt.expected {
				t.Errorf("expected condition %d, got %d", tt.expected, result[0].Condition)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// checkPrerequisites – value-dependent prerequisite (default class case)
// ---------------------------------------------------------------------------

func TestCheckPrerequisites_ValueDependent(t *testing.T) {
	handler := NewDynamicDNSHandler(make(map[string]*zone.Zone))
	z := newTestZoneWithRecords()

	name, _ := protocol.ParseName("www.example.com.")

	// Existing record – should pass
	prereqsOK := []*protocol.ResourceRecord{
		{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
		},
	}
	if err := handler.checkPrerequisites(z, prereqsOK); err != nil {
		t.Errorf("checkPrerequisites should pass for existing record: %v", err)
	}

	// Non-existent record – should fail
	prereqsFail := []*protocol.ResourceRecord{
		{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			Data:  &protocol.RDataA{Address: [4]byte{10, 0, 0, 99}},
		},
	}
	if err := handler.checkPrerequisites(z, prereqsFail); err == nil {
		t.Error("checkPrerequisites should fail for non-existent record value")
	}
}

// ---------------------------------------------------------------------------
// checkPrerequisites – failing YXRRSET and failing NXRRSET
// ---------------------------------------------------------------------------

func TestCheckPrerequisites_FailingYXRRSet(t *testing.T) {
	handler := NewDynamicDNSHandler(make(map[string]*zone.Zone))
	z := newTestZoneWithRecords()

	name, _ := protocol.ParseName("www.example.com.")

	// YXRRSET – type must exist, but TypeMX doesn't exist
	prereqs := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeMX, Class: protocol.ClassANY},
	}
	if err := handler.checkPrerequisites(z, prereqs); err == nil {
		t.Error("expected error when YXRRSET type does not exist")
	}
}

func TestCheckPrerequisites_FailingNXRRSet(t *testing.T) {
	handler := NewDynamicDNSHandler(make(map[string]*zone.Zone))
	z := newTestZoneWithRecords()

	name, _ := protocol.ParseName("www.example.com.")

	// NXRRSET – type must not exist, but TypeA does exist
	prereqs := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeA, Class: protocol.ClassNONE},
	}
	if err := handler.checkPrerequisites(z, prereqs); err == nil {
		t.Error("expected error when NXRRSET type exists")
	}
}

// ---------------------------------------------------------------------------
// zoneNameExists – name without trailing dot (normalization path)
// ---------------------------------------------------------------------------

func TestZoneNameExists_WithoutTrailingDot(t *testing.T) {
	z := newTestZoneWithRecords()

	// "www" lacks trailing dot => normalization appends ".example.com."
	if !zoneNameExists(z, "www") {
		t.Error("zoneNameExists should return true for 'www' (normalizes to www.example.com.)")
	}

	// Non-existent short name
	if zoneNameExists(z, "nonexistent") {
		t.Error("zoneNameExists should return false for 'nonexistent'")
	}
}

func TestZoneNameExists_EmptyRecordsSlice(t *testing.T) {
	z := zone.NewZone("example.com.")
	// Put an empty slice – should return false (len == 0)
	z.Records["empty.example.com."] = []zone.Record{}

	if zoneNameExists(z, "empty.example.com.") {
		t.Error("zoneNameExists should return false when records slice is empty")
	}
}

// ---------------------------------------------------------------------------
// zoneTypeExists – non-existent name
// ---------------------------------------------------------------------------

func TestZoneTypeExists_NonExistentName(t *testing.T) {
	z := newTestZoneWithRecords()

	if zoneTypeExists(z, "absent.example.com.", protocol.TypeA) {
		t.Error("zoneTypeExists should return false for non-existent name")
	}
}

func TestZoneTypeExists_WithoutTrailingDot(t *testing.T) {
	z := newTestZoneWithRecords()

	// "www" normalizes to "www.example.com."
	if !zoneTypeExists(z, "www", protocol.TypeA) {
		t.Error("zoneTypeExists should return true for 'www' A record via normalization")
	}
	if zoneTypeExists(z, "www", protocol.TypeMX) {
		t.Error("zoneTypeExists should return false for 'www' MX record (type not present)")
	}
}

// ---------------------------------------------------------------------------
// zoneRecordExists – non-existent name
// ---------------------------------------------------------------------------

func TestZoneRecordExists_NonExistentName(t *testing.T) {
	z := newTestZoneWithRecords()

	if zoneRecordExists(z, "absent.example.com.", protocol.TypeA, "192.0.2.1") {
		t.Error("zoneRecordExists should return false for non-existent name")
	}
}

func TestZoneRecordExists_WithoutTrailingDot(t *testing.T) {
	z := newTestZoneWithRecords()

	// "www" normalizes to "www.example.com."
	if !zoneRecordExists(z, "www", protocol.TypeA, "192.0.2.1") {
		t.Error("zoneRecordExists should return true for 'www' A 192.0.2.1 via normalization")
	}
	if zoneRecordExists(z, "www", protocol.TypeA, "10.0.0.1") {
		t.Error("zoneRecordExists should return false for wrong rdata")
	}
}

// ---------------------------------------------------------------------------
// zoneDeleteRecord – name without trailing dot
// ---------------------------------------------------------------------------

func TestZoneDeleteRecord_WithoutTrailingDot(t *testing.T) {
	z := newTestZoneWithRecords()

	// Delete via short name "www"
	zoneDeleteRecord(z, "www", protocol.TypeA, "192.0.2.1")

	records := z.Records["www.example.com."]
	// Should have removed exactly one of the two A records
	if len(records) != 2 {
		t.Fatalf("expected 2 remaining records (1 A + 1 AAAA), got %d", len(records))
	}
	for _, r := range records {
		if r.Type == "A" && r.RData == "192.0.2.1" {
			t.Error("record 192.0.2.1 should have been deleted")
		}
	}
}

// ---------------------------------------------------------------------------
// zoneDeleteRRSet – name without trailing dot
// ---------------------------------------------------------------------------

func TestZoneDeleteRRSet_WithoutTrailingDot(t *testing.T) {
	z := newTestZoneWithRecords()

	zoneDeleteRRSet(z, "www", protocol.TypeA)

	records := z.Records["www.example.com."]
	if len(records) != 1 {
		t.Fatalf("expected 1 remaining record (AAAA), got %d", len(records))
	}
	if records[0].Type != "AAAA" {
		t.Errorf("expected remaining record type AAAA, got %s", records[0].Type)
	}
}

// ---------------------------------------------------------------------------
// zoneDeleteName – name without trailing dot (normalization path)
// ---------------------------------------------------------------------------

func TestZoneDeleteName_WithoutTrailingDot(t *testing.T) {
	z := newTestZoneWithRecords()

	zoneDeleteName(z, "www")

	if _, exists := z.Records["www.example.com."]; exists {
		t.Error("www.example.com. should be deleted after zoneDeleteName('www')")
	}
}

// ---------------------------------------------------------------------------
// ApplyUpdate – precondition failure
// ---------------------------------------------------------------------------

func TestApplyUpdate_PreconditionFailure_Exists(t *testing.T) {
	z := newTestZoneWithRecords()

	update := &UpdateRequest{
		ZoneName: "example.com.",
		Prerequisites: []UpdatePrerequisite{
			{
				Name:      "absent.example.com.",
				Type:      protocol.TypeA,
				Condition: PrecondExists, // requires RRset to exist
			},
		},
		Updates: []UpdateOperation{}, // no updates needed
	}

	err := ApplyUpdate(z, update)
	if err == nil {
		t.Fatal("expected error when prerequisite fails (RRset does not exist)")
	}
}

func TestApplyUpdate_PreconditionFailure_NotExists(t *testing.T) {
	z := newTestZoneWithRecords()

	update := &UpdateRequest{
		ZoneName: "example.com.",
		Prerequisites: []UpdatePrerequisite{
			{
				Name:      "www.example.com.",
				Type:      protocol.TypeA,
				Condition: PrecondNotExists, // requires RRset to NOT exist, but it does
			},
		},
	}

	err := ApplyUpdate(z, update)
	if err == nil {
		t.Fatal("expected error when prerequisite fails (RRset exists but should not)")
	}
}

func TestApplyUpdate_PreconditionFailure_NameInUse(t *testing.T) {
	z := newTestZoneWithRecords()

	update := &UpdateRequest{
		ZoneName: "example.com.",
		Prerequisites: []UpdatePrerequisite{
			{
				Name:      "absent.example.com.",
				Condition: PrecondNameInUse, // requires name to exist
			},
		},
	}

	err := ApplyUpdate(z, update)
	if err == nil {
		t.Fatal("expected error when prerequisite fails (name not in use)")
	}
}

func TestApplyUpdate_PreconditionFailure_NameNotInUse(t *testing.T) {
	z := newTestZoneWithRecords()

	update := &UpdateRequest{
		ZoneName: "example.com.",
		Prerequisites: []UpdatePrerequisite{
			{
				Name:      "www.example.com.",
				Condition: PrecondNameNotInUse, // requires name to NOT exist, but it does
			},
		},
	}

	err := ApplyUpdate(z, update)
	if err == nil {
		t.Fatal("expected error when prerequisite fails (name in use)")
	}
}

func TestApplyUpdate_PreconditionPass_ThenApply(t *testing.T) {
	z := newTestZoneWithRecords()

	update := &UpdateRequest{
		ZoneName: "example.com.",
		Prerequisites: []UpdatePrerequisite{
			{
				Name:      "www.example.com.",
				Type:      protocol.TypeA,
				Condition: PrecondExists, // RRset exists
			},
		},
		Updates: []UpdateOperation{
			{
				Name:      "www.example.com.",
				Type:      protocol.TypeA,
				TTL:       300,
				RData:     "10.0.0.1",
				Operation: UpdateOpAdd,
			},
		},
	}

	if err := ApplyUpdate(z, update); err != nil {
		t.Fatalf("ApplyUpdate() error = %v", err)
	}

	records := z.Records["www.example.com."]
	// originally 3 records + 1 new = 4
	if len(records) != 4 {
		t.Errorf("expected 4 records after add, got %d", len(records))
	}
}

// ---------------------------------------------------------------------------
// checkPrerequisiteOnZone – value-dependent (PrecondExistsValue)
// ---------------------------------------------------------------------------

func TestCheckPrerequisiteOnZone_ExistsValue(t *testing.T) {
	z := newTestZoneWithRecords()

	// PrecondExistsValue checks that a specific record exists with matching RData.
	// Test with matching record: www.example.com. A 192.0.2.1
	err := checkPrerequisiteOnZone(z, UpdatePrerequisite{
		Name:      "www.example.com.",
		Type:      protocol.TypeA,
		Condition: PrecondExistsValue,
		RData:     "192.0.2.1",
	})
	if err != nil {
		t.Errorf("PrecondExistsValue should succeed for existing record: %v", err)
	}

	// Test with non-matching RData
	err = checkPrerequisiteOnZone(z, UpdatePrerequisite{
		Name:      "www.example.com.",
		Type:      protocol.TypeA,
		Condition: PrecondExistsValue,
		RData:     "99.99.99.99",
	})
	if err == nil {
		t.Error("PrecondExistsValue should fail for non-existing record value")
	}
}

// ---------------------------------------------------------------------------
// HandleUpdate – full flow with ACL-allowed IP and TSIG
// ---------------------------------------------------------------------------

func TestHandleUpdate_Success_WithACLAndTSIG(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:  "ns1.example.com.",
		RName:  "admin.example.com.",
		Serial: 2024010101,
	}
	zones := map[string]*zone.Zone{"example.com.": z}

	handler := NewDynamicDNSHandler(zones)
	ks := NewKeyStore()
	key := &TSIGKey{
		Name:      "key.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("test-secret-key-12345678901234"),
	}
	ks.AddKey(key)
	handler.SetKeyStore(ks)

	// Allow the client IP
	_, network, _ := net.ParseCIDR("127.0.0.0/8")
	handler.AddACL("example.com.", network)

	name, _ := protocol.ParseName("example.com.")
	updateName, _ := protocol.ParseName("new.example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      5678,
			QDCount: 1,
			NSCount: 1,
			Flags:   protocol.Flags{Opcode: protocol.OpcodeUpdate},
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name: updateName, Type: protocol.TypeA,
				Class: protocol.ClassIN, TTL: 3600,
				Data: &protocol.RDataA{Address: [4]byte{10, 0, 0, 1}},
			},
		},
	}

	tsigRR, _ := SignMessage(req, key, 300)
	req.Additionals = append(req.Additionals, tsigRR)

	resp, err := handler.HandleUpdate(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleUpdate() error = %v", err)
	}
	if resp == nil {
		t.Fatal("HandleUpdate() returned nil response")
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected RcodeSuccess, got %d", resp.Header.Flags.RCODE)
	}
}

// ---------------------------------------------------------------------------
// HandleUpdate – TSIG key not found
// ---------------------------------------------------------------------------

func TestHandleUpdate_TSIGKeyNotFound(t *testing.T) {
	z := zone.NewZone("example.com.")
	zones := map[string]*zone.Zone{"example.com.": z}

	handler := NewDynamicDNSHandler(zones)
	ks := NewKeyStore()
	handler.SetKeyStore(ks)

	name, _ := protocol.ParseName("example.com.")

	// Build a TSIG record with a key name not in the store
	keyName, _ := protocol.ParseName("missing-key.example.com.")
	tsigRR := &protocol.ResourceRecord{
		Name:  keyName,
		Type:  protocol.TypeTSIG,
		Class: protocol.ClassANY,
		TTL:   0,
		Data:  &RDataTSIG{Raw: []byte("dummy")},
	}

	req := &protocol.Message{
		Header: protocol.Header{
			ID:      9999,
			QDCount: 1,
			Flags:   protocol.Flags{Opcode: protocol.OpcodeUpdate},
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
		Additionals: []*protocol.ResourceRecord{tsigRR},
	}

	resp, err := handler.HandleUpdate(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeNotAuth {
		t.Errorf("expected RcodeNotAuth, got %d", resp.Header.Flags.RCODE)
	}
}

// ---------------------------------------------------------------------------
// HandleUpdate – TSIG verification failure (bad MAC)
// ---------------------------------------------------------------------------

func TestHandleUpdate_TSIGVerificationFailure(t *testing.T) {
	z := zone.NewZone("example.com.")
	zones := map[string]*zone.Zone{"example.com.": z}

	handler := NewDynamicDNSHandler(zones)
	ks := NewKeyStore()
	ks.AddKey(&TSIGKey{
		Name:      "key.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("test-secret-key-12345678901234"),
	})
	handler.SetKeyStore(ks)

	name, _ := protocol.ParseName("example.com.")

	// Sign correctly, then tamper with the MAC
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1111,
			QDCount: 1,
			Flags:   protocol.Flags{Opcode: protocol.OpcodeUpdate},
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
	}
	goodKey := &TSIGKey{
		Name:      "key.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("test-secret-key-12345678901234"),
	}
	tsigRR, _ := SignMessage(req, goodKey, 300)

	// Corrupt the MAC in the raw TSIG data
	if rd, ok := tsigRR.Data.(*RDataTSIG); ok {
		for i := range rd.Raw {
			rd.Raw[i] ^= 0xFF // flip all bits
		}
	}

	req.Additionals = append(req.Additionals, tsigRR)

	resp, err := handler.HandleUpdate(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeNotAuth {
		t.Errorf("expected RcodeNotAuth for bad TSIG, got %d", resp.Header.Flags.RCODE)
	}
}

// ---------------------------------------------------------------------------
// HandleUpdate – prerequisite failure path
// ---------------------------------------------------------------------------

func TestHandleUpdate_PrerequisiteFailure(t *testing.T) {
	z := newTestZoneWithRecords()
	zones := map[string]*zone.Zone{"example.com.": z}

	handler := NewDynamicDNSHandler(zones)
	ks := NewKeyStore()
	key := &TSIGKey{
		Name:      "key.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("test-secret-key-12345678901234"),
	}
	ks.AddKey(key)
	handler.SetKeyStore(ks)

	name, _ := protocol.ParseName("example.com.")
	prereqName, _ := protocol.ParseName("absent.example.com.")

	req := &protocol.Message{
		Header: protocol.Header{
			ID:      2222,
			QDCount: 1,
			Flags:   protocol.Flags{Opcode: protocol.OpcodeUpdate},
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
		// Prerequisite: YXDOMAIN for a name that does NOT exist
		Answers: []*protocol.ResourceRecord{
			{Name: prereqName, Type: protocol.TypeANY, Class: protocol.ClassANY, TTL: 0, Data: &protocol.RDataA{}},
		},
	}

	tsigRR, _ := SignMessage(req, key, 300)
	req.Additionals = append(req.Additionals, tsigRR)

	resp, err := handler.HandleUpdate(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeNXRRSet {
		t.Errorf("expected RcodeNXRRSet for prerequisite failure, got %d", resp.Header.Flags.RCODE)
	}
}

// ---------------------------------------------------------------------------
// HandleUpdate – empty prerequisites (should succeed)
// ---------------------------------------------------------------------------

func TestHandleUpdate_EmptyPrerequisites(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:  "ns1.example.com.",
		RName:  "admin.example.com.",
		Serial: 2024010101,
	}
	zones := map[string]*zone.Zone{"example.com.": z}

	handler := NewDynamicDNSHandler(zones)
	ks := NewKeyStore()
	key := &TSIGKey{
		Name:      "key.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("test-secret-key-12345678901234"),
	}
	ks.AddKey(key)
	handler.SetKeyStore(ks)

	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      3333,
			QDCount: 1,
			Flags:   protocol.Flags{Opcode: protocol.OpcodeUpdate},
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
	}

	tsigRR, _ := SignMessage(req, key, 300)
	req.Additionals = append(req.Additionals, tsigRR)

	resp, err := handler.HandleUpdate(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected RcodeSuccess, got %d", resp.Header.Flags.RCODE)
	}
}
