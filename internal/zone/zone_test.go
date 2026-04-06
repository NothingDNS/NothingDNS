package zone

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/storage"
)

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com."},
		{"example.com.", "example.com."},
		{"", "."},
		{".", "."},
	}

	for _, tt := range tests {
		result := canonicalize(tt.input)
		if result != tt.expected {
			t.Errorf("canonicalize(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMakeAbsolute(t *testing.T) {
	tests := []struct {
		name     string
		origin   string
		expected string
	}{
		{"www", "example.com.", "www.example.com."},
		{"www.example.com.", "example.com.", "www.example.com."},
		{"", "example.com.", "example.com."},
		{"@", "example.com.", "example.com."},
	}

	for _, tt := range tests {
		result := makeAbsolute(tt.name, tt.origin)
		if result != tt.expected {
			t.Errorf("makeAbsolute(%q, %q) = %q, want %q", tt.name, tt.origin, result, tt.expected)
		}
	}
}

func TestParseTTL(t *testing.T) {
	tests := []struct {
		input    string
		expected uint32
		wantErr  bool
	}{
		{"3600", 3600, false},
		{"1H", 3600, false},
		{"1D", 86400, false},
		{"1W", 604800, false},
		{"1M", 60, false},
		{"1S", 1, false},
		{"2h30m", 0, true}, // Not supported in basic parser
		{"", 0, true},
		{"invalid", 0, true},
		// Overflow test: 4294967295 * 3600 (1H) exceeds uint32 max
		{"4294967295H", 0, true},
	}

	for _, tt := range tests {
		result, err := parseTTL(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseTTL(%q) expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseTTL(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if result != tt.expected {
			t.Errorf("parseTTL(%q) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}

func TestIsType(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"A", true},
		{"AAAA", true},
		{"CNAME", true},
		{"MX", true},
		{"NS", true},
		{"SOA", true},
		{"TXT", true},
		{"SRV", true},
		{"INVALID", false},
		{"", false},
	}

	for _, tt := range tests {
		result := isType(tt.input)
		if result != tt.expected {
			t.Errorf("isType(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestParseFields(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{
			"www 3600 IN A 192.0.2.1",
			[]string{"www", "3600", "IN", "A", "192.0.2.1"},
		},
		{
			`www IN TXT "hello world"`,
			[]string{"www", "IN", "TXT", "hello world"},
		},
		{
			"  www   3600   A   192.0.2.1  ",
			[]string{"www", "3600", "A", "192.0.2.1"},
		},
	}

	for _, tt := range tests {
		result := parseFields(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("parseFields(%q) = %v, want %v", tt.input, result, tt.expected)
			continue
		}
		for i := range result {
			if result[i] != tt.expected[i] {
				t.Errorf("parseFields(%q)[%d] = %q, want %q", tt.input, i, result[i], tt.expected[i])
			}
		}
	}
}

func TestNewZone(t *testing.T) {
	z := NewZone("example.com")
	if z.Origin != "example.com." {
		t.Errorf("expected origin 'example.com.', got %q", z.Origin)
	}
	if z.Records == nil {
		t.Error("expected Records map to be initialized")
	}
}

func TestParseFileBasic(t *testing.T) {
	zoneContent := `
$ORIGIN example.com.
$TTL 3600

@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400

@ 3600 IN NS ns1
@ 3600 IN NS ns2

ns1 3600 IN A 192.0.2.1
ns2 3600 IN A 192.0.2.2

www 3600 IN A 192.0.2.10
www 3600 IN AAAA 2001:db8::10

mail 3600 IN MX 10 mail1
mail 3600 IN MX 20 mail2
`

	z, err := ParseFile("test.zone", strings.NewReader(zoneContent))
	if err != nil {
		t.Fatalf("failed to parse zone: %v", err)
	}

	if z.Origin != "example.com." {
		t.Errorf("expected origin 'example.com.', got %q", z.Origin)
	}

	if z.DefaultTTL != 3600 {
		t.Errorf("expected default TTL 3600, got %d", z.DefaultTTL)
	}

	// Check SOA
	if z.SOA == nil {
		t.Fatal("expected SOA record")
	}
	if z.SOA.MName != "ns1.example.com." {
		t.Errorf("expected MName 'ns1.example.com.', got %q", z.SOA.MName)
	}
	if z.SOA.Serial != 2024010101 {
		t.Errorf("expected serial 2024010101, got %d", z.SOA.Serial)
	}

	// Check NS records
	if len(z.NS) != 2 {
		t.Errorf("expected 2 NS records, got %d", len(z.NS))
	}

	// Check A records
	wwwRecords := z.Lookup("www.example.com.", "A")
	if len(wwwRecords) != 1 {
		t.Errorf("expected 1 www A record, got %d", len(wwwRecords))
	}

	// Check AAAA records
	wwwAAAA := z.Lookup("www.example.com.", "AAAA")
	if len(wwwAAAA) != 1 {
		t.Errorf("expected 1 www AAAA record, got %d", len(wwwAAAA))
	}

	// Check MX records
	mailMX := z.Lookup("mail.example.com.", "MX")
	if len(mailMX) != 2 {
		t.Errorf("expected 2 mail MX records, got %d", len(mailMX))
	}
}

func TestParseFileWithComments(t *testing.T) {
	zoneContent := `
; This is a comment
$ORIGIN example.com.
$TTL 3600

; SOA record
@ IN SOA ns1 hostmaster 1 3600 900 604800 86400

; NS records
@ IN NS ns1 ; inline comment
@ IN NS ns2

; A records
www IN A 192.0.2.1
`

	z, err := ParseFile("test.zone", strings.NewReader(zoneContent))
	if err != nil {
		t.Fatalf("failed to parse zone: %v", err)
	}

	if z.Origin != "example.com." {
		t.Errorf("expected origin 'example.com.', got %q", z.Origin)
	}
}

func TestParseFileContinuation(t *testing.T) {
	zoneContent := `
$ORIGIN example.com.
$TTL 3600

@ IN SOA ns1 hostmaster (
    2024010101 ; serial
    3600       ; refresh
    900        ; retry
    604800     ; expire
    86400      ; minimum
)

@ IN NS ns1
`

	z, err := ParseFile("test.zone", strings.NewReader(zoneContent))
	if err != nil {
		t.Fatalf("failed to parse zone: %v", err)
	}

	if z.SOA == nil {
		t.Fatal("expected SOA record")
	}
	if z.SOA.Serial != 2024010101 {
		t.Errorf("expected serial 2024010101, got %d", z.SOA.Serial)
	}
}

func TestZoneValidate(t *testing.T) {
	tests := []struct {
		name    string
		zone    *Zone
		wantErr bool
	}{
		{
			name: "valid zone",
			zone: &Zone{
				Origin: "example.com.",
				SOA:    &SOARecord{Name: "example.com."},
				NS:     []NSRecord{{Name: "example.com."}},
			},
			wantErr: false,
		},
		{
			name: "missing origin",
			zone: &Zone{
				Origin: ".",
				SOA:    &SOARecord{},
				NS:     []NSRecord{{}},
			},
			wantErr: true,
		},
		{
			name: "missing SOA",
			zone: &Zone{
				Origin: "example.com.",
				NS:     []NSRecord{{}},
			},
			wantErr: true,
		},
		{
			name: "missing NS",
			zone: &Zone{
				Origin: "example.com.",
				SOA:    &SOARecord{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.zone.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestZoneLookup(t *testing.T) {
	z := NewZone("example.com")
	z.Records["www.example.com."] = []Record{
		{Type: "A", RData: "192.0.2.1"},
		{Type: "A", RData: "192.0.2.2"},
		{Type: "AAAA", RData: "2001:db8::1"},
	}

	// Test specific type lookup
	aRecords := z.Lookup("www.example.com.", "A")
	if len(aRecords) != 2 {
		t.Errorf("expected 2 A records, got %d", len(aRecords))
	}

	// Test AAAA lookup
	aaaaRecords := z.Lookup("www.example.com.", "AAAA")
	if len(aaaaRecords) != 1 {
		t.Errorf("expected 1 AAAA record, got %d", len(aaaaRecords))
	}

	// Test non-existent type
	mxRecords := z.Lookup("www.example.com.", "MX")
	if len(mxRecords) != 0 {
		t.Errorf("expected 0 MX records, got %d", len(mxRecords))
	}

	// Test case insensitivity
	upperRecords := z.Lookup("WWW.EXAMPLE.COM.", "a")
	if len(upperRecords) != 2 {
		t.Errorf("expected 2 records with case insensitive lookup, got %d", len(upperRecords))
	}
}

func TestParseFileErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name:    "invalid SOA",
			content: "$ORIGIN example.com.\n@ IN SOA ns1",
			wantErr: true,
		},
		{
			name:    "missing $ORIGIN argument",
			content: "$ORIGIN",
			wantErr: true,
		},
		{
			name:    "$INCLUDE file not found",
			content: "$ORIGIN example.com.\n$INCLUDE other.zone",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseFile("test.zone", strings.NewReader(tt.content))
			if tt.wantErr && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestManager_NewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.zones == nil {
		t.Error("zones map not initialized")
	}
	if m.files == nil {
		t.Error("files map not initialized")
	}
}

func TestManager_LoadZone(t *testing.T) {
	m := NewManager()

	z := NewZone("example.com.")
	z.SOA = &SOARecord{Name: "example.com."}
	z.NS = []NSRecord{{Name: "ns1.example.com."}}

	m.LoadZone(z, "/path/to/zone")

	// Test Get
	got, ok := m.Get("example.com.")
	if !ok {
		t.Fatal("expected to find zone")
	}
	if got.Origin != "example.com." {
		t.Errorf("expected origin example.com., got %s", got.Origin)
	}

	// Test Count
	if m.Count() != 1 {
		t.Errorf("expected count 1, got %d", m.Count())
	}
}

func TestManager_List(t *testing.T) {
	m := NewManager()

	z1 := NewZone("example.com.")
	z1.SOA = &SOARecord{Name: "example.com."}
	z1.NS = []NSRecord{{Name: "ns1.example.com."}}

	z2 := NewZone("test.com.")
	z2.SOA = &SOARecord{Name: "test.com."}
	z2.NS = []NSRecord{{Name: "ns1.test.com."}}

	m.LoadZone(z1, "/path/to/example.zone")
	m.LoadZone(z2, "/path/to/test.zone")

	list := m.List()
	if len(list) != 2 {
		t.Errorf("expected 2 zones, got %d", len(list))
	}

	// Verify it's a copy
	list["new.com."] = NewZone("new.com.")
	if m.Count() != 2 {
		t.Error("modifying List() result should not affect manager")
	}
}

func TestManager_Remove(t *testing.T) {
	m := NewManager()

	z := NewZone("example.com.")
	z.SOA = &SOARecord{Name: "example.com."}
	z.NS = []NSRecord{{Name: "ns1.example.com."}}

	m.LoadZone(z, "/path/to/zone")

	if m.Count() != 1 {
		t.Fatal("expected 1 zone before remove")
	}

	m.Remove("example.com.")

	if m.Count() != 0 {
		t.Errorf("expected 0 zones after remove, got %d", m.Count())
	}

	_, ok := m.Get("example.com.")
	if ok {
		t.Error("expected zone to be removed")
	}
}

func TestManager_Reload_NotFound(t *testing.T) {
	m := NewManager()

	err := m.Reload("nonexistent.com.")
	if err == nil {
		t.Error("expected error for non-existent zone")
	}
}

func TestZone_LookupAll(t *testing.T) {
	z := NewZone("example.com.")
	z.Records["www.example.com."] = []Record{
		{Type: "A", RData: "192.0.2.1"},
		{Type: "A", RData: "192.0.2.2"},
		{Type: "AAAA", RData: "2001:db8::1"},
		{Type: "MX", RData: "10 mail.example.com."},
	}

	// Test getting all record types
	records := z.LookupAll("www.example.com.")
	if len(records) != 4 {
		t.Errorf("expected 4 records, got %d", len(records))
	}

	// Test case insensitivity
	recordsUpper := z.LookupAll("WWW.EXAMPLE.COM.")
	if len(recordsUpper) != 4 {
		t.Errorf("expected 4 records with case insensitive lookup, got %d", len(recordsUpper))
	}

	// Test non-existent name
	recordsEmpty := z.LookupAll("nonexistent.example.com.")
	if len(recordsEmpty) != 0 {
		t.Errorf("expected 0 records for non-existent name, got %d", len(recordsEmpty))
	}
}

func TestManager_CreateZone(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("") // no file writing

	soa := &SOARecord{
		MName:   "ns1.example.com.",
		RName:   "hostmaster.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   900,
		Expire:  604800,
		Minimum: 86400,
	}
	nsRecords := []NSRecord{{NSDName: "ns1.example.com."}}

	err := m.CreateZone("example.com.", 3600, soa, nsRecords)
	if err != nil {
		t.Fatalf("CreateZone: %v", err)
	}

	// Verify zone was created
	z, ok := m.Get("example.com.")
	if !ok {
		t.Fatal("expected to find zone after CreateZone")
	}
	if z.Origin != "example.com." {
		t.Errorf("origin = %q, want example.com.", z.Origin)
	}
	if z.DefaultTTL != 3600 {
		t.Errorf("defaultTTL = %d, want 3600", z.DefaultTTL)
	}
	if z.SOA == nil {
		t.Fatal("expected SOA record")
	}
	if z.SOA.Serial != 2024010101 {
		t.Errorf("soa serial = %d, want 2024010101", z.SOA.Serial)
	}
	if len(z.NS) != 1 {
		t.Errorf("NS count = %d, want 1", len(z.NS))
	}

	// Test duplicate - should fail
	err = m.CreateZone("example.com.", 3600, soa, nsRecords)
	if err == nil {
		t.Error("expected error for duplicate zone")
	}

	// Test invalid origin
	err = m.CreateZone("", 3600, soa, nsRecords)
	if err == nil {
		t.Error("expected error for empty origin")
	}

	// Test missing SOA
	err = m.CreateZone("test.com.", 3600, nil, nsRecords)
	if err == nil {
		t.Error("expected error for nil SOA")
	}

	// Test missing NS
	err = m.CreateZone("test.com.", 3600, soa, nil)
	if err == nil {
		t.Error("expected error for nil NS records")
	}

	err = m.CreateZone("test.com.", 3600, soa, []NSRecord{})
	if err == nil {
		t.Error("expected error for empty NS records")
	}
}

func TestManager_AddRecord(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")

	// Create zone first
	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})

	// Add A record
	rec := Record{Name: "www.example.com.", TTL: 300, Type: "A", RData: "192.0.2.1"}
	err := m.AddRecord("example.com.", rec)
	if err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	// Verify
	records, err := m.GetRecords("example.com.", "www.example.com.")
	if err != nil {
		t.Fatalf("GetRecords: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("records count = %d, want 1", len(records))
	}
	if records[0].RData != "192.0.2.1" {
		t.Errorf("rdata = %q, want 192.0.2.1", records[0].RData)
	}

	// Test non-existent zone
	err = m.AddRecord("nonexistent.com.", rec)
	if err == nil {
		t.Error("expected error for non-existent zone")
	}
}

func TestManager_DeleteRecord(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")

	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})

	// Add then delete
	m.AddRecord("example.com.", Record{Name: "www.example.com.", Type: "A", RData: "192.0.2.1"})

	err := m.DeleteRecord("example.com.", "www.example.com.", "A")
	if err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}

	// Verify deleted
	records, _ := m.GetRecords("example.com.", "www.example.com.")
	if len(records) != 0 {
		t.Errorf("records count after delete = %d, want 0", len(records))
	}

	// Test non-existent
	err = m.DeleteRecord("example.com.", "nonexistent.example.com.", "A")
	if err == nil {
		t.Error("expected error for non-existent record")
	}
}

func TestManager_UpdateRecord(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")

	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})

	// Add record
	m.AddRecord("example.com.", Record{Name: "www.example.com.", Type: "A", RData: "192.0.2.1"})

	// Update it
	newRec := Record{Name: "www.example.com.", TTL: 600, Type: "A", RData: "192.0.2.2"}
	err := m.UpdateRecord("example.com.", "www.example.com.", "A", "192.0.2.1", newRec)
	if err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	records, _ := m.GetRecords("example.com.", "www.example.com.")
	if len(records) != 1 || records[0].RData != "192.0.2.2" {
		t.Errorf("updated record = %+v", records)
	}
}

func TestManager_DeleteZone(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")

	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})

	if m.Count() != 1 {
		t.Fatalf("count before delete = %d, want 1", m.Count())
	}

	err := m.DeleteZone("example.com.")
	if err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}

	if m.Count() != 0 {
		t.Errorf("count after delete = %d, want 0", m.Count())
	}

	// Test non-existent
	err = m.DeleteZone("nonexistent.com.")
	if err == nil {
		t.Error("expected error for non-existent zone")
	}
}

func TestManager_ExportZone(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")

	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})

	export, err := m.ExportZone("example.com.")
	if err != nil {
		t.Fatalf("ExportZone: %v", err)
	}
	if export == "" {
		t.Error("expected non-empty export")
	}

	// Non-existent should error
	_, err = m.ExportZone("nonexistent.com.")
	if err == nil {
		t.Error("expected error for non-existent zone")
	}
}

func TestManager_GetRecords(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")

	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})
	m.AddRecord("example.com.", Record{Name: "www.example.com.", Type: "A", RData: "192.0.2.1"})

	// Get specific name
	records, err := m.GetRecords("example.com.", "www.example.com.")
	if err != nil {
		t.Fatalf("GetRecords: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("www records = %d, want 1", len(records))
	}

	// Get all
	all, err := m.GetRecords("example.com.", "")
	if err != nil {
		t.Fatalf("GetRecords all: %v", err)
	}
	if len(all) < 2 { // SOA + NS + www
		t.Errorf("all records = %d, want >= 2", len(all))
	}
}

func TestManager_PersistZone(t *testing.T) {
	m := NewManager()

	// PersistZone with no zoneDir should return nil
	err := m.PersistZone("example.com.")
	if err != nil {
		t.Errorf("PersistZone with no zoneDir: %v", err)
	}
}

func TestIncrementSerial(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")
	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 2024010101}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})

	z, _ := m.Get("example.com.")
	oldSerial := z.SOA.Serial

	IncrementSerial(z)

	if z.SOA.Serial <= oldSerial {
		t.Errorf("serial did not increment: was %d, is %d", oldSerial, z.SOA.Serial)
	}
}

func TestNormalizeZoneName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com."},
		{"example.com.", "example.com."},
		{"EXAMPLE.COM", "example.com."},
		{" EXAMPLE.COM ", "example.com."},
		{"", ""},
		{".", "."},
	}

	for _, tt := range tests {
		result := normalizeZoneName(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeZoneName(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestKVPersistence_EnableDisable(t *testing.T) {
	m := NewManager()
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping KV test: %v", err)
	}
	defer kv.Close()

	kvp := NewKVPersistence(m, kv)
	kvp.Enable() // Should not panic
}

func TestKVPersistence_PersistZone_Disabled(t *testing.T) {
	m := NewManager()
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping KV test: %v", err)
	}
	defer kv.Close()

	kvp := NewKVPersistence(m, kv)
	err = kvp.PersistZone("example.com.")
	if err != nil {
		t.Errorf("PersistZone disabled: %v", err)
	}
}

func TestKVPersistence_PersistZone_Enabled(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")

	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping KV test: %v", err)
	}
	defer kv.Close()

	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})

	kvp := NewKVPersistence(m, kv)
	kvp.Enable()

	err = kvp.PersistZone("example.com.")
	if err != nil {
		t.Errorf("PersistZone enabled: %v", err)
	}
}

func TestKVPersistence_LoadFromKV_Disabled(t *testing.T) {
	m := NewManager()
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping KV test: %v", err)
	}
	defer kv.Close()

	kvp := NewKVPersistence(m, kv)

	z, found, err := kvp.LoadFromKV("example.com.")
	if err != nil {
		t.Errorf("LoadFromKV disabled: %v", err)
	}
	if found || z != nil {
		t.Errorf("expected not found when disabled")
	}
}

func TestKVPersistence_DeleteFromKV_Disabled(t *testing.T) {
	m := NewManager()
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping KV test: %v", err)
	}
	defer kv.Close()

	kvp := NewKVPersistence(m, kv)

	err = kvp.DeleteFromKV("example.com.")
	if err != nil {
		t.Errorf("DeleteFromKV disabled: %v", err)
	}
}

func TestKVPersistence_ListKVZones_Disabled(t *testing.T) {
	m := NewManager()
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping KV test: %v", err)
	}
	defer kv.Close()

	kvp := NewKVPersistence(m, kv)

	zones, err := kvp.ListKVZones()
	if err != nil {
		t.Errorf("ListKVZones disabled: %v", err)
	}
	if zones != nil {
		t.Errorf("expected nil when disabled")
	}
}

func TestKVPersistence_Manager(t *testing.T) {
	m := NewManager()
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping KV test: %v", err)
	}
	defer kv.Close()

	kvp := NewKVPersistence(m, kv)
	if kvp.Manager() != m {
		t.Error("Manager() did not return expected manager")
	}
}

func TestKVPersistence_zoneToStoredRecords(t *testing.T) {
	m := NewManager()
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping KV test: %v", err)
	}
	defer kv.Close()

	kvp := NewKVPersistence(m, kv)
	z := NewZone("example.com.")
	z.Records["www.example.com."] = []Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
	}

	records := kvp.zoneToStoredRecords(z)
	if len(records) != 1 {
		t.Fatalf("records count = %d, want 1", len(records))
	}
	if records["www.example.com."][0].RData != "192.0.2.1" {
		t.Errorf("rdata = %q, want 192.0.2.1", records["www.example.com."][0].RData)
	}
}

func TestKVPersistence_storedRecordsToZone(t *testing.T) {
	m := NewManager()
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping KV test: %v", err)
	}
	defer kv.Close()

	kvp := NewKVPersistence(m, kv)
	meta := storage.ZoneMeta{Origin: "example.com.", DefaultTTL: 3600}
	records := map[string][]storage.StoredRecord{
		"www.example.com.": {
			{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
		},
	}

	z := kvp.storedRecordsToZone(meta, records)
	if z.Origin != "example.com." {
		t.Errorf("origin = %q, want example.com.", z.Origin)
	}
	if z.DefaultTTL != 3600 {
		t.Errorf("defaultTTL = %d, want 3600", z.DefaultTTL)
	}
}

func TestKVPersistence_PersistAll_Disabled(t *testing.T) {
	m := NewManager()
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping KV test: %v", err)
	}
	defer kv.Close()

	kvp := NewKVPersistence(m, kv)

	err = kvp.PersistAll()
	if err != nil {
		t.Errorf("PersistAll disabled: %v", err)
	}
}
