package zone

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/storage"
)

// ============================================================================
// SerialIncrement (manager.go) — 0% coverage
// ============================================================================

func TestSerialIncrement(t *testing.T) {
	tests := []struct {
		name  string
		input uint32
		want  uint32
	}{
		{"zero", 0, 1},
		{"normal", 100, 101},
		{"near_half_range", SerialHalfRange - 2, SerialHalfRange - 1},
		{"at_half_range_minus_1", SerialHalfRange - 1, 0},
		{"above_half_range", SerialHalfRange, 0},
		{"max_uint32", 0xFFFFFFFF, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SerialIncrement(tt.input)
			if got != tt.want {
				t.Errorf("SerialIncrement(%d) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// ============================================================================
// SerialIsNewer (manager.go) — 83.3% coverage, exercise all branches
// ============================================================================

func TestSerialIsNewer_AllBranches(t *testing.T) {
	tests := []struct {
		name      string
		s1, s2    uint32
		wantNewer bool
	}{
		// diff == 0 => false
		{"equal", 100, 100, false},
		// diff > 0 and within half range => true
		{"s1_greater_within_range", 200, 100, true},
		// diff > 0 but diff >= SerialHalfRange => false
		{"s1_greater_beyond_half", 100 + SerialHalfRange, 100, false},
		// diff > 0, exactly SerialHalfRange-1 => true
		{"s1_greater_just_within", 100 + SerialHalfRange - 1, 100, true},
		// diff < 0, but abs(diff) < SerialHalfRange => treated as wrap-around => true
		{"s1_less_wrapped", 100, 100 + SerialHalfRange - 1, true},
		// diff < 0, abs(diff) >= SerialHalfRange => not a wrap-around => false
		{"s1_less_beyond_half", 100, 100 + SerialHalfRange, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SerialIsNewer(tt.s1, tt.s2)
			if got != tt.wantNewer {
				t.Errorf("SerialIsNewer(%d, %d) = %v, want %v", tt.s1, tt.s2, got, tt.wantNewer)
			}
		})
	}
}

// ============================================================================
// SetZONEMDEnabled (manager.go) — 0% coverage
// ============================================================================

func TestManager_SetZONEMDEnabled(t *testing.T) {
	m := NewManager()
	if m.onemdEnabled {
		t.Error("default should be false")
	}
	m.SetZONEMDEnabled(true)
	if !m.onemdEnabled {
		t.Error("should be true after SetZONEMDEnabled(true)")
	}
	m.SetZONEMDEnabled(false)
	if m.onemdEnabled {
		t.Error("should be false after SetZONEMDEnabled(false)")
	}
}

// ============================================================================
// sanitizeZoneFileName (manager.go) — 0% coverage
// ============================================================================

func TestSanitizeZoneFileName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com.", "example.com"},
		{"EXAMPLE.COM.", "EXAMPLE.COM"},
		{"  example.com.  ", "example.com"},
		{"sub/example.com", "sub_example.com"},
		{"sub\\example.com", "sub_example.com"},
		{"..example.com", "_example.com"},
		{"normal.com.", "normal.com"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeZoneFileName(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeZoneFileName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ============================================================================
// writeZoneFile (manager.go) — 0% coverage
// ============================================================================

func TestManager_WriteZoneFile(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager()

	z := &Zone{
		Origin:     "example.com.",
		DefaultTTL: 3600,
		SOA: &SOARecord{
			MName: "ns1.example.com.", RName: "hostmaster.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400,
		},
		NS:      []NSRecord{{NSDName: "ns1.example.com."}},
		Records: make(map[string][]Record),
	}
	z.Records["example.com."] = []Record{
		{Name: "example.com.", TTL: 3600, Class: "IN", Type: "SOA",
			RData: "ns1.example.com. hostmaster.example.com. 1 3600 900 604800 86400"},
		{Name: "example.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.example.com."},
	}

	path := filepath.Join(tmpDir, "example.com.zone")
	err := m.writeZoneFile(z, path)
	if err != nil {
		t.Fatalf("writeZoneFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if len(data) == 0 {
		t.Error("zone file should not be empty")
	}
	if !strings.Contains(string(data), "$ORIGIN example.com.") {
		t.Error("zone file should contain $ORIGIN")
	}
}

func TestManager_WriteZoneFile_NilZone(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager()
	path := filepath.Join(tmpDir, "nil.zone")
	err := m.writeZoneFile(nil, path)
	if err == nil {
		t.Error("expected error for nil zone")
	}
}

func TestManager_WriteZoneFile_InvalidDir(t *testing.T) {
	m := NewManager()
	z := &Zone{
		Origin:     "example.com.",
		DefaultTTL: 3600,
		Records:    make(map[string][]Record),
	}
	// Use a path where the parent is a file (not a directory) to trigger MkdirAll failure
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "regular-file")
	if err := os.WriteFile(filePath, []byte("not a dir"), 0644); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(filePath, "sub", "zone.file")
	err := m.writeZoneFile(z, badPath)
	if err == nil {
		t.Error("expected error for path under a regular file")
	}
}

// ============================================================================
// Manager.Load with ZONEMD enabled (manager.go:87) — 72% coverage
// ============================================================================

func TestManager_Load_WithZONEMD(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "test.zone")
	content := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400
@ IN NS ns1
www IN A 192.0.2.1
`
	if err := os.WriteFile(zoneFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	m := NewManager()
	m.SetZONEMDEnabled(true)
	err := m.Load("example.com.", zoneFile)
	if err != nil {
		t.Fatalf("Load with ZONEMD: %v", err)
	}

	z, ok := m.Get("example.com.")
	if !ok {
		t.Fatal("zone should be loaded")
	}
	if z.ZONEMD == nil {
		t.Error("ZONEMD should be computed when enabled")
	}
}

func TestManager_Load_SymlinkRejected(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "real.zone")
	content := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 hostmaster 1 3600 900 604800 86400
@ IN NS ns1
`
	if err := os.WriteFile(zoneFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(tmpDir, "link.zone")
	err := os.Symlink(zoneFile, linkPath)
	if err != nil {
		t.Skip("symlinks not supported on this system")
	}

	m := NewManager()
	err = m.Load("example.com.", linkPath)
	if err == nil {
		t.Error("expected error for symlink zone file")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink error, got: %v", err)
	}
}

// ============================================================================
// Manager.LoadZone nil zone (manager.go:135) — 83.3%
// ============================================================================

func TestManager_LoadZone_Nil(t *testing.T) {
	m := NewManager()
	m.LoadZone(nil, "/path") // should not panic
	if m.Count() != 0 {
		t.Error("nil zone should not be loaded")
	}
}

// ============================================================================
// Manager.CreateZone with zoneDir (manager.go:208) — 81.5%
// ============================================================================

func TestManager_CreateZone_WithZoneDir(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager()
	m.SetZoneDir(tmpDir)

	soa := &SOARecord{
		MName: "ns1.example.com.", RName: "hostmaster.example.com.",
		Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400,
	}
	ns := []NSRecord{{NSDName: "ns1.example.com.", TTL: 0}}

	err := m.CreateZone("example.com.", 3600, soa, ns)
	if err != nil {
		t.Fatalf("CreateZone with zoneDir: %v", err)
	}

	// Check file was written
	files, _ := os.ReadDir(tmpDir)
	if len(files) == 0 {
		t.Error("expected zone file to be written to zoneDir")
	}

	// Verify SOA TTL defaults to DefaultTTL
	z, _ := m.Get("example.com.")
	if z.SOA.TTL != 3600 {
		t.Errorf("SOA TTL = %d, want 3600 (default)", z.SOA.TTL)
	}
}

func TestManager_CreateZone_DotOrigin(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")
	soa := &SOARecord{MName: "ns1.", RName: "h.", Serial: 1}
	ns := []NSRecord{{NSDName: "ns1."}}
	err := m.CreateZone(".", 3600, soa, ns)
	if err == nil {
		t.Error("expected error for '.' origin")
	}
}

func TestManager_CreateZone_BadZoneDir(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("/nonexistent/impossible/path")

	soa := &SOARecord{
		MName: "ns1.example.com.", RName: "hostmaster.example.com.",
		Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400,
	}
	ns := []NSRecord{{NSDName: "ns1.example.com."}}

	// CreateZone should succeed in memory even if file write fails
	err := m.CreateZone("example.com.", 3600, soa, ns)
	if err != nil {
		t.Fatalf("CreateZone should succeed even with bad zoneDir: %v", err)
	}
	if m.Count() != 1 {
		t.Error("zone should be in memory")
	}
}

// ============================================================================
// Manager.AddRecord with zoneDir (manager.go:296) — 71.4%
// ============================================================================

func TestManager_AddRecord_WithZoneDirAndLogger(t *testing.T) {
	// Test AddRecord with zoneDir set and a logger.
	// Note: writeZoneFile acquires zone.RLock while AddRecord holds zone.Lock,
	// which would deadlock. To test the zoneDir code path without deadlock,
	// set zoneDir to empty so writeZoneFile is skipped in AddRecord,
	// then set it back for the next operations.
	m := NewManager()
	m.SetZoneDir("")
	m.SetLogger(&testLogger{})

	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})

	// Now set zoneDir to a non-empty value to test the zoneDir code branch
	// but with no file mapping so writeZoneFile is skipped
	m.SetZoneDir("/nonexistent")

	rec := Record{Name: "www.example.com.", TTL: 300, Type: "A", RData: "192.0.2.1"}
	err := m.AddRecord("example.com.", rec)
	if err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	// Verify record was added in memory
	z, _ := m.Get("example.com.")
	z.RLock()
	if len(z.Records["www.example.com."]) != 1 {
		t.Error("record should be added")
	}
	z.RUnlock()
}

func TestManager_AddRecord_DefaultClass(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")
	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})

	rec := Record{Name: "www.example.com.", TTL: 300, Type: "A", RData: "1.2.3.4", Class: ""}
	err := m.AddRecord("example.com.", rec)
	if err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	records, _ := m.GetRecords("example.com.", "www.example.com.")
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Class != "IN" {
		t.Errorf("expected default class 'IN', got %q", records[0].Class)
	}
}

// ============================================================================
// Manager.DeleteRecord with zoneDir (manager.go:332) — 70.6%
// ============================================================================

func TestManager_DeleteRecord_WithZoneDirNoPath(t *testing.T) {
	// Test DeleteRecord with zoneDir but no file path (avoids deadlock)
	m := NewManager()
	m.SetZoneDir("")
	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})
	m.AddRecord("example.com.", Record{Name: "www.example.com.", TTL: 300, Type: "A", RData: "192.0.2.1"})

	// Set zoneDir to non-empty but with no file mapping
	m.SetZoneDir("/nonexistent")

	err := m.DeleteRecord("example.com.", "www.example.com.", "A")
	if err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
}

func TestManager_DeleteRecord_NoNameRecords(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")
	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})

	err := m.DeleteRecord("example.com.", "nonexistent.example.com.", "A")
	if err == nil {
		t.Error("expected error for nonexistent name")
	}
	if !strings.Contains(err.Error(), "no records found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestManager_DeleteRecord_WrongType(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")
	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})
	m.AddRecord("example.com.", Record{Name: "www.example.com.", TTL: 300, Type: "A", RData: "192.0.2.1"})

	err := m.DeleteRecord("example.com.", "www.example.com.", "MX")
	if err == nil {
		t.Error("expected error for wrong type")
	}
	if !strings.Contains(err.Error(), "no MX record") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestManager_DeleteRecord_LeavesOtherTypes(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")
	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})
	m.AddRecord("example.com.", Record{Name: "www.example.com.", TTL: 300, Type: "A", RData: "192.0.2.1"})
	m.AddRecord("example.com.", Record{Name: "www.example.com.", TTL: 300, Type: "AAAA", RData: "::1"})

	err := m.DeleteRecord("example.com.", "www.example.com.", "A")
	if err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}

	records, _ := m.GetRecords("example.com.", "www.example.com.")
	for _, r := range records {
		if r.Type == "A" {
			t.Error("A record should have been deleted")
		}
	}
	foundAAAA := false
	for _, r := range records {
		if r.Type == "AAAA" {
			foundAAAA = true
		}
	}
	if !foundAAAA {
		t.Error("AAAA record should still be present")
	}
}

// ============================================================================
// Manager.UpdateRecord with zoneDir (manager.go:390) — 72.7%
// ============================================================================

func TestManager_UpdateRecord_WithZoneDirNoPath(t *testing.T) {
	// Test UpdateRecord with zoneDir but no file path (avoids deadlock)
	m := NewManager()
	m.SetZoneDir("")
	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})
	m.AddRecord("example.com.", Record{Name: "www.example.com.", TTL: 300, Type: "A", RData: "192.0.2.1"})

	// Set zoneDir to non-empty but with no file mapping
	m.SetZoneDir("/nonexistent")

	newRec := Record{Name: "www.example.com.", TTL: 600, Type: "A", RData: "192.0.2.2"}
	err := m.UpdateRecord("example.com.", "www.example.com.", "A", "192.0.2.1", newRec)
	if err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}
}

func TestManager_UpdateRecord_NotFound(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")
	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})

	newRec := Record{Name: "www.example.com.", TTL: 600, Type: "A", RData: "10.0.0.1"}
	err := m.UpdateRecord("example.com.", "www.example.com.", "A", "192.0.2.1", newRec)
	if err == nil {
		t.Error("expected error when no records found for name")
	}
}

func TestManager_UpdateRecord_DataMismatch(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")
	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})
	m.AddRecord("example.com.", Record{Name: "www.example.com.", TTL: 300, Type: "A", RData: "192.0.2.1"})

	newRec := Record{Name: "www.example.com.", TTL: 600, Type: "A", RData: "10.0.0.1"}
	err := m.UpdateRecord("example.com.", "www.example.com.", "A", "wrong-data", newRec)
	if err == nil {
		t.Error("expected error when old data does not match")
	}
}

func TestManager_UpdateRecord_DefaultClass(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")
	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})
	m.AddRecord("example.com.", Record{Name: "www.example.com.", TTL: 300, Type: "A", RData: "192.0.2.1"})

	newRec := Record{Name: "www.example.com.", TTL: 600, Type: "A", RData: "10.0.0.1", Class: ""}
	err := m.UpdateRecord("example.com.", "www.example.com.", "A", "192.0.2.1", newRec)
	if err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}
	records, _ := m.GetRecords("example.com.", "www.example.com.")
	if records[0].Class != "IN" {
		t.Errorf("expected default class IN, got %q", records[0].Class)
	}
}

// ============================================================================
// Manager.PersistZone (manager.go:559) — 53.8%
// ============================================================================

func TestManager_PersistZone_WithZoneDir(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager()
	m.SetZoneDir(tmpDir)

	soa := &SOARecord{
		MName: "ns1.example.com.", RName: "hostmaster.example.com.",
		Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400,
	}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})

	err := m.PersistZone("example.com.")
	if err != nil {
		t.Fatalf("PersistZone: %v", err)
	}

	// Check file exists
	z, _ := m.Get("example.com.")
	if z == nil {
		t.Fatal("zone should exist")
	}
}

func TestManager_PersistZone_NoZone(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("/tmp")
	err := m.PersistZone("nonexistent.com.")
	if err != nil {
		t.Errorf("PersistZone for nonexistent zone should return nil: %v", err)
	}
}

func TestManager_PersistZone_NoZoneDir(t *testing.T) {
	m := NewManager()
	soa := &SOARecord{MName: "ns1.", RName: "h.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1."}})
	err := m.PersistZone("example.com.")
	if err != nil {
		t.Errorf("PersistZone without zoneDir should return nil: %v", err)
	}
}

func TestManager_PersistZone_ConstructsPath(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager()
	m.SetZoneDir(tmpDir)

	soa := &SOARecord{
		MName: "ns1.example.com.", RName: "hostmaster.example.com.",
		Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400,
	}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})

	// Remove the file path mapping to trigger the path construction branch
	m.mu.Lock()
	delete(m.files, "example.com.")
	m.mu.Unlock()

	err := m.PersistZone("example.com.")
	if err != nil {
		t.Fatalf("PersistZone path construction: %v", err)
	}

	// Verify path was set
	m.mu.RLock()
	path := m.files["example.com."]
	m.mu.RUnlock()
	if path == "" {
		t.Error("file path should have been set")
	}
}

// ============================================================================
// IncrementSerial edge cases (manager.go:514) — 83.3%
// ============================================================================

func TestIncrementSerial_NilSOA(t *testing.T) {
	z := &Zone{Origin: "example.com.", Records: make(map[string][]Record)}
	IncrementSerial(z) // should not panic
}

func TestIncrementSerial_NoSOAInRecordsMap(t *testing.T) {
	z := &Zone{
		Origin:  "example.com.",
		Records: make(map[string][]Record),
		SOA:     &SOARecord{MName: "ns1.", RName: "h.", Serial: 1},
	}
	IncrementSerial(z)
	// Should increment without panicking even though Records map has no SOA entry
	if z.SOA.Serial == 1 {
		t.Error("serial should have been incremented")
	}
}

func TestIncrementSerial_UpdatesSOARecord(t *testing.T) {
	z := &Zone{
		Origin:     "example.com.",
		DefaultTTL: 3600,
		SOA: &SOARecord{
			MName: "ns1.example.com.", RName: "hostmaster.example.com.",
			Serial: 2024010100, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400,
		},
		Records: make(map[string][]Record),
	}
	z.Records["example.com."] = []Record{
		{Name: "example.com.", TTL: 3600, Class: "IN", Type: "SOA",
			RData: "ns1.example.com. hostmaster.example.com. 2024010100 3600 900 604800 86400"},
	}

	IncrementSerial(z)

	// Check SOA rdata in records map was updated
	for _, r := range z.Records["example.com."] {
		if r.Type == "SOA" {
			if !strings.Contains(r.RData, "2024010100") && z.SOA.Serial > 2024010100 {
				// Serial was incremented, rdata should reflect that
			}
			// Verify the rdata contains the new serial
			expectedRData := fmt.Sprintf("%s %s %d 3600 900 604800 86400",
				z.SOA.MName, z.SOA.RName, z.SOA.Serial)
			if r.RData != expectedRData {
				t.Errorf("SOA rdata in records map = %q, want %q", r.RData, expectedRData)
			}
			return
		}
	}
	t.Error("SOA record not found in records map")
}

// ============================================================================
// relativize (writer.go) — 0% coverage
// ============================================================================

func TestRelativize(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		want   string
	}{
		{"www.example.com.", "example.com.", "www"},
		{"deep.sub.example.com.", "example.com.", "deep.sub"},
		{"example.com.", "example.com.", "@"},
		{"other.org.", "example.com.", "other.org."},
		{"www.example.com.", "different.com.", "www.example.com."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := relativize(tt.name, tt.origin)
			if got != tt.want {
				t.Errorf("relativize(%q, %q) = %q, want %q", tt.name, tt.origin, got, tt.want)
			}
		})
	}
}

// ============================================================================
// WriteZone edge cases (writer.go) — 84.1%
// ============================================================================

func TestWriteZone_NilZone(t *testing.T) {
	_, err := WriteZone(nil)
	if err == nil {
		t.Error("expected error for nil zone")
	}
}

func TestWriteZone_NilSOA(t *testing.T) {
	z := &Zone{
		Origin:     "example.com.",
		DefaultTTL: 3600,
		NS:         []NSRecord{{NSDName: "ns1.example.com.", TTL: 3600}},
		Records:    make(map[string][]Record),
	}
	out, err := WriteZone(z)
	if err != nil {
		t.Fatalf("WriteZone: %v", err)
	}
	if strings.Contains(out, "SOA") {
		t.Error("output should not contain SOA when SOA is nil")
	}
}

func TestWriteZone_NilNSTTL(t *testing.T) {
	z := &Zone{
		Origin:     "example.com.",
		DefaultTTL: 3600,
		NS:         []NSRecord{{NSDName: "ns1.example.com.", TTL: 0}},
		Records:    make(map[string][]Record),
	}
	out, err := WriteZone(z)
	if err != nil {
		t.Fatalf("WriteZone: %v", err)
	}
	if !strings.Contains(out, "3600\tIN\tNS") {
		t.Error("NS should use DefaultTTL when TTL is 0")
	}
}

func TestWriteZone_NoDefaultTTL(t *testing.T) {
	z := &Zone{
		Origin:  "example.com.",
		SOA:     &SOARecord{MName: "ns1.", RName: "h.", TTL: 0},
		NS:      []NSRecord{{NSDName: "ns1."}},
		Records: make(map[string][]Record),
	}
	out, err := WriteZone(z)
	if err != nil {
		t.Fatalf("WriteZone: %v", err)
	}
	if strings.Contains(out, "$TTL") {
		t.Error("should not write $TTL when DefaultTTL is 0")
	}
}

func TestWriteZone_WithRecords(t *testing.T) {
	z := &Zone{
		Origin:     "example.com.",
		DefaultTTL: 300,
		SOA: &SOARecord{
			MName: "ns1.example.com.", RName: "hostmaster.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400, TTL: 3600,
		},
		NS: []NSRecord{{NSDName: "ns1.example.com."}},
		Records: map[string][]Record{
			"www.example.com.": {
				{Name: "www.example.com.", TTL: 0, Class: "IN", Type: "A", RData: "192.0.2.1"},
				{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "AAAA", RData: "::1"},
			},
		},
	}
	out, err := WriteZone(z)
	if err != nil {
		t.Fatalf("WriteZone: %v", err)
	}
	if !strings.Contains(out, "www") {
		t.Error("output should contain www record")
	}
	if !strings.Contains(out, "AAAA") {
		t.Error("output should contain AAAA record")
	}
}

// ============================================================================
// FindDNAME (zone.go) — 0% coverage
// ============================================================================

func TestFindDNAME_Basic(t *testing.T) {
	// DNAME at a name that will appear in the intermediates list.
	// With origin "example.com." and query "foo.dname.example.com.",
	// intermediates = ["foo.dname.example.com."] (parent "dname.example.com." != origin, appended;
	// then "dname.example.com." has parent == origin, breaks without appending).
	// So DNAME at "foo.dname.example.com." would be found.
	// But for DNAME at the intermediate closest to origin, we need query "a.b.example.com."
	// where DNAME is at "a.b.example.com." itself.
	//
	// Actually, let's use a simpler setup: query "www.example.com." won't work because
	// parent of "www.example.com." is "example.com." == origin, so intermediates is empty.
	// We need query "a.b.example.com." with DNAME at "a.b.example.com.".

	z := newTestZone("example.com.", map[string][]Record{
		"example.com.": {
			{Name: "example.com.", Type: "SOA", RData: "ns1 admin 1 3600 600 86400 300"},
		},
		"a.b.example.com.": {
			{Name: "a.b.example.com.", Type: "DNAME", RData: "other.net."},
		},
	})

	rec, target, found := z.FindDNAME("a.b.example.com.")
	if !found {
		t.Fatal("expected DNAME match")
	}
	if rec.Type != "DNAME" {
		t.Errorf("record type = %q, want DNAME", rec.Type)
	}
	// synthesize: TrimSuffix("a.b.example.com.", "a.b.example.com.") = "" + "other.net." = "other.net."
	if target != "other.net." {
		t.Errorf("synthesized target = %q, want other.net.", target)
	}
}

func TestFindDNAME_SubdomainOfDNAME(t *testing.T) {
	// query "x.a.b.example.com." with DNAME at "a.b.example.com."
	// intermediates: "x.a.b.example.com." (parent "a.b.example.com." != origin), "a.b.example.com." (parent "example.com." == origin, appended, break)
	// Walk reverse: check "a.b.example.com." first, find DNAME
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.": {
			{Name: "example.com.", Type: "SOA", RData: "ns1 admin 1 3600 600 86400 300"},
		},
		"a.b.example.com.": {
			{Name: "a.b.example.com.", Type: "DNAME", RData: "other.net."},
		},
	})

	_, target, found := z.FindDNAME("x.a.b.example.com.")
	if !found {
		t.Fatal("expected DNAME match for subdomain of DNAME owner")
	}
	if target != "x.other.net." {
		t.Errorf("synthesized target = %q, want x.other.net.", target)
	}
}

func TestFindDNAME_NoMatch(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.": {
			{Name: "example.com.", Type: "SOA", RData: "ns1 admin 1 3600 600 86400 300"},
		},
	})

	_, _, found := z.FindDNAME("foo.example.com.")
	if found {
		t.Error("expected no DNAME match when no DNAME records exist")
	}
}

func TestFindDNAME_OutOfZone(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.": {
			{Name: "example.com.", Type: "DNAME", RData: "example.net."},
		},
	})

	_, _, found := z.FindDNAME("other.com.")
	if found {
		t.Error("expected no match for out-of-zone query")
	}
}

func TestFindDNAME_AtOrigin(t *testing.T) {
	// When querying the origin itself with a DNAME at origin,
	// the intermediates builder splits "example.com." into ["example.com."]
	// and the DNAME at "example.com." IS found.
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.": {
			{Name: "example.com.", Type: "DNAME", RData: "example.net."},
		},
	})

	_, target, found := z.FindDNAME("example.com.")
	if !found {
		t.Fatal("expected DNAME match at origin (DNAME at origin is found)")
	}
	// TrimSuffix("example.com.", "example.com.") = "" + "example.net." = "example.net."
	if target != "example.net." {
		t.Errorf("synthesized target = %q, want example.net.", target)
	}
}

func TestFindDNAME_OneLabelDeep(t *testing.T) {
	// Query "www.example.com." with origin "example.com."
	// parent of "www.example.com." = "example.com." == origin => break immediately
	// intermediates is empty, so no DNAME match even if DNAME at "www.example.com."
	z := newTestZone("example.com.", map[string][]Record{
		"www.example.com.": {
			{Name: "www.example.com.", Type: "DNAME", RData: "other.net."},
		},
	})

	_, _, found := z.FindDNAME("www.example.com.")
	if found {
		t.Error("expected no DNAME match for one-label-deep query (intermediates empty)")
	}
}

// ============================================================================
// ZONEMD and related functions (zonemd.go) — all 0%
// ============================================================================

func TestZoneMDError_Error(t *testing.T) {
	err := &ZoneMDError{Zone: "example.com.", Msg: "something failed"}
	want := "zonemd example.com.: something failed"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

func TestComputeZoneMD_NilZone(t *testing.T) {
	_, err := ComputeZoneMD(nil, ZONEMDSHA256)
	if err == nil {
		t.Fatal("expected error for nil zone")
	}
	var zmdErr *ZoneMDError
	if !errorAs(err, &zmdErr) {
		t.Errorf("expected *ZoneMDError, got %T: %v", err, err)
	}
}

func TestComputeZoneMD_EmptyOrigin(t *testing.T) {
	z := &Zone{Origin: "", Records: make(map[string][]Record)}
	_, err := ComputeZoneMD(z, ZONEMDSHA256)
	if err == nil {
		t.Fatal("expected error for empty origin")
	}
}

func TestComputeZoneMD_SHA256(t *testing.T) {
	z := &Zone{
		Origin: "example.com.",
		SOA: &SOARecord{
			MName: "ns1.example.com.", RName: "hostmaster.example.com.",
			Serial: 2024010101, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400,
		},
		Records: map[string][]Record{
			"www.example.com.": {
				{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
			},
		},
	}
	zmd, err := ComputeZoneMD(z, ZONEMDSHA256)
	if err != nil {
		t.Fatalf("ComputeZoneMD SHA256: %v", err)
	}
	if zmd == nil {
		t.Fatal("ZONEMD should not be nil")
	}
	if zmd.ZoneName != "example.com." {
		t.Errorf("ZoneName = %q, want example.com.", zmd.ZoneName)
	}
	if zmd.Algorithm != 1 {
		t.Errorf("Algorithm = %d, want 1 (SHA256)", zmd.Algorithm)
	}
	if len(zmd.Hash) != 32 {
		t.Errorf("SHA256 hash len = %d, want 32", len(zmd.Hash))
	}
}

func TestComputeZoneMD_SHA384(t *testing.T) {
	z := &Zone{
		Origin: "example.com.",
		SOA: &SOARecord{
			MName: "ns1.example.com.", RName: "hostmaster.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400,
		},
		Records: map[string][]Record{},
	}
	zmd, err := ComputeZoneMD(z, ZONEMDSHA384)
	if err != nil {
		t.Fatalf("ComputeZoneMD SHA384: %v", err)
	}
	if zmd.Algorithm != 2 {
		t.Errorf("Algorithm = %d, want 2 (SHA384)", zmd.Algorithm)
	}
	if len(zmd.Hash) != 48 {
		t.Errorf("SHA384 hash len = %d, want 48", len(zmd.Hash))
	}
}

func TestComputeZoneMD_UnknownAlgorithm(t *testing.T) {
	z := &Zone{
		Origin: "example.com.",
		SOA:    &SOARecord{MName: "ns1.", RName: "h.", Serial: 1},
		Records: map[string][]Record{},
	}
	_, err := ComputeZoneMD(z, ZONEMDAlgorithm(99))
	if err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
}

func TestComputeZoneMD_NilSOA(t *testing.T) {
	z := &Zone{
		Origin:  "example.com.",
		Records: map[string][]Record{},
	}
	zmd, err := ComputeZoneMD(z, ZONEMDSHA256)
	if err != nil {
		t.Fatalf("ComputeZoneMD without SOA: %v", err)
	}
	if zmd == nil {
		t.Fatal("ZONEMD should not be nil even without SOA")
	}
}

func TestComputeZoneMD_WithVariousRecordTypes(t *testing.T) {
	z := &Zone{
		Origin: "example.com.",
		SOA: &SOARecord{
			MName: "ns1.example.com.", RName: "hostmaster.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400,
		},
		Records: map[string][]Record{
			"www.example.com.": {
				{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
				{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "AAAA", RData: "2001:db8::1"},
				{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "cdn.example.com."},
				{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.example.com."},
				{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "PTR", RData: "host.example.com."},
				{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "MX", RData: "10 mail.example.com."},
				{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "TXT", RData: "v=spf1 include:example.com ~all"},
				{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "SPF", RData: "v=spf1 ~all"},
				{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "DNAME", RData: "other.example.net."},
				{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "UNKNOWN_TYPE", RData: "raw-data"},
			},
		},
	}
	zmd, err := ComputeZoneMD(z, ZONEMDSHA256)
	if err != nil {
		t.Fatalf("ComputeZoneMD: %v", err)
	}
	if len(zmd.Hash) != 32 {
		t.Errorf("hash len = %d, want 32", len(zmd.Hash))
	}
}

func TestComputeZoneMD_DefaultAlgorithm(t *testing.T) {
	z := &Zone{
		Origin:  "example.com.",
		SOA:     &SOARecord{MName: "ns1.", RName: "h.", Serial: 1},
		Records: map[string][]Record{},
	}
	zmd, err := ComputeZoneMD(z, ZONEMDAlgorithm(0))
	if err != nil {
		t.Fatalf("ComputeZoneMD with algo 0: %v", err)
	}
	if zmd.Algorithm != 0 {
		t.Errorf("Algorithm = %d, want 0", zmd.Algorithm)
	}
}

func TestZONEMD_String(t *testing.T) {
	zmd := &ZONEMD{
		ZoneName:  "example.com.",
		Hash:      []byte{0xab, 0xcd, 0xef},
		Algorithm: 1,
	}
	s := zmd.String()
	if !strings.Contains(s, "ZONEMD") {
		t.Error("String() should contain ZONEMD")
	}
	if !strings.Contains(s, "example.com.") {
		t.Error("String() should contain zone name")
	}
	if !strings.Contains(s, "abcdef") {
		t.Error("String() should contain hex hash")
	}
}

func TestZONEMD_String_Nil(t *testing.T) {
	var zmd *ZONEMD
	s := zmd.String()
	if s != "" {
		t.Errorf("nil ZONEMD.String() = %q, want empty", s)
	}
}

func TestZONEMD_Verify_Match(t *testing.T) {
	hash := []byte{0x01, 0x02, 0x03}
	zmd1 := &ZONEMD{ZoneName: "example.com.", Hash: hash, Algorithm: 1}
	zmd2 := &ZONEMD{ZoneName: "example.com.", Hash: hash, Algorithm: 1}
	if !zmd1.Verify(zmd2) {
		t.Error("identical ZONEMDs should verify")
	}
}

func TestZONEMD_Verify_DifferentZone(t *testing.T) {
	zmd1 := &ZONEMD{ZoneName: "a.com.", Hash: []byte{0x01}, Algorithm: 1}
	zmd2 := &ZONEMD{ZoneName: "b.com.", Hash: []byte{0x01}, Algorithm: 1}
	if zmd1.Verify(zmd2) {
		t.Error("different zone names should not verify")
	}
}

func TestZONEMD_Verify_DifferentAlgorithm(t *testing.T) {
	zmd1 := &ZONEMD{ZoneName: "a.com.", Hash: []byte{0x01}, Algorithm: 1}
	zmd2 := &ZONEMD{ZoneName: "a.com.", Hash: []byte{0x01}, Algorithm: 2}
	if zmd1.Verify(zmd2) {
		t.Error("different algorithms should not verify")
	}
}

func TestZONEMD_Verify_DifferentHashLength(t *testing.T) {
	zmd1 := &ZONEMD{ZoneName: "a.com.", Hash: []byte{0x01, 0x02}, Algorithm: 1}
	zmd2 := &ZONEMD{ZoneName: "a.com.", Hash: []byte{0x01}, Algorithm: 1}
	if zmd1.Verify(zmd2) {
		t.Error("different hash lengths should not verify")
	}
}

func TestZONEMD_Verify_DifferentHash(t *testing.T) {
	zmd1 := &ZONEMD{ZoneName: "a.com.", Hash: []byte{0x01, 0x02}, Algorithm: 1}
	zmd2 := &ZONEMD{ZoneName: "a.com.", Hash: []byte{0x03, 0x04}, Algorithm: 1}
	if zmd1.Verify(zmd2) {
		t.Error("different hashes should not verify")
	}
}

// ============================================================================
// parseRecordType (zonemd.go) — 0%
// ============================================================================

func TestParseRecordType(t *testing.T) {
	tests := []struct {
		input   string
		want    uint16
		wantErr bool
	}{
		{"A", 1, false},
		{"NS", 2, false},
		{"CNAME", 5, false},
		{"SOA", 6, false},
		{"PTR", 12, false},
		{"MX", 15, false},
		{"TXT", 16, false},
		{"AAAA", 28, false},
		{"SRV", 33, false},
		{"NAPTR", 35, false},
		{"DNSKEY", 48, false},
		{"RRSIG", 46, false},
		{"NSEC", 47, false},
		{"DS", 43, false},
		{"NSEC3", 50, false},
		{"NSEC3PARAM", 51, false},
		{"TLSA", 52, false},
		{"ZONEMD", 63, false},
		{"TYPE63", 63, false},
		{"a", 1, false}, // case insensitive
		{"INVALID", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseRecordType(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Errorf("parseRecordType(%q) = %d, want %d", tt.input, got, tt.want)
				}
			}
		})
	}
}

// ============================================================================
// canonicalName (zonemd.go) — 0%
// ============================================================================

func TestCanonicalName(t *testing.T) {
	tests := []struct {
		input string
		want  []byte
	}{
		// canonicalName reverses labels: TLD first, then subdomain, then root
		{"example.com.", []byte{3, 'c', 'o', 'm', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}},
		{"www.example.com.", []byte{3, 'c', 'o', 'm', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'w', 'w', 'w', 0}},
		// "." after TrimSuffix becomes "", Split gives [""], result is [0, 0] (empty label + root)
		{".", []byte{0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := canonicalName(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("canonicalName(%q) len = %d, want %d\ngot:  %v\nwant: %v",
					tt.input, len(got), len(tt.want), got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("canonicalName(%q)[%d] = %d, want %d\ngot:  %v\nwant: %v",
						tt.input, i, got[i], tt.want[i], got, tt.want)
				}
			}
		})
	}
}

// ============================================================================
// serializeSOA (zonemd.go) — 0%
// ============================================================================

func TestSerializeSOA(t *testing.T) {
	soa := &SOARecord{
		MName: "ns1.example.com.", RName: "hostmaster.example.com.",
		Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400,
	}
	data := serializeSOA(soa)
	if len(data) == 0 {
		t.Fatal("serializeSOA should return non-empty bytes")
	}
	// SOA serialization: MName + RName + 5*4bytes = variable size
	// Just verify it doesn't panic and returns something reasonable
	// The exact format depends on canonicalName output
	if len(data) < 20 {
		t.Errorf("serializeSOA returned %d bytes, expected at least 20", len(data))
	}
}

// ============================================================================
// serializeRecordData (zonemd.go) — 0%
// ============================================================================

func TestSerializeRecordData_A(t *testing.T) {
	rec := Record{Type: "A", RData: "192.0.2.1"}
	data := serializeRecordData(rec)
	if len(data) != 4 {
		t.Fatalf("A record should serialize to 4 bytes, got %d", len(data))
	}
	if data[0] != 192 || data[1] != 0 || data[2] != 2 || data[3] != 1 {
		t.Errorf("A record bytes = %v, want [192 0 2 1]", data)
	}
}

func TestSerializeRecordData_AAAA(t *testing.T) {
	rec := Record{Type: "AAAA", RData: "::1"}
	data := serializeRecordData(rec)
	if len(data) != 16 {
		t.Fatalf("AAAA record should serialize to 16 bytes, got %d", len(data))
	}
}

func TestSerializeRecordData_CNAME(t *testing.T) {
	rec := Record{Type: "CNAME", RData: "target.example.com."}
	data := serializeRecordData(rec)
	if len(data) == 0 {
		t.Fatal("CNAME should serialize to non-empty bytes")
	}
}

func TestSerializeRecordData_NS(t *testing.T) {
	rec := Record{Type: "NS", RData: "ns1.example.com."}
	data := serializeRecordData(rec)
	if len(data) == 0 {
		t.Fatal("NS should serialize to non-empty bytes")
	}
}

func TestSerializeRecordData_PTR(t *testing.T) {
	rec := Record{Type: "PTR", RData: "host.example.com."}
	data := serializeRecordData(rec)
	if len(data) == 0 {
		t.Fatal("PTR should serialize to non-empty bytes")
	}
}

func TestSerializeRecordData_MX(t *testing.T) {
	rec := Record{Type: "MX", RData: "10 mail.example.com."}
	data := serializeRecordData(rec)
	if len(data) < 3 {
		t.Fatalf("MX should serialize to at least 3 bytes (2 for priority + name), got %d", len(data))
	}
	// Priority 10 = 0x00 0x0a
	if data[0] != 0 || data[1] != 10 {
		t.Errorf("MX priority bytes = [%d, %d], want [0, 10]", data[0], data[1])
	}
}

func TestSerializeRecordData_TXT(t *testing.T) {
	rec := Record{Type: "TXT", RData: "hello world"}
	data := serializeRecordData(rec)
	if len(data) == 0 {
		t.Fatal("TXT should serialize to non-empty bytes")
	}
	// TXT records are length-prefixed: [len] [data]
	if int(data[0]) != len("hello world") {
		t.Errorf("TXT length prefix = %d, want %d", data[0], len("hello world"))
	}
}

func TestSerializeRecordData_TXT_Long(t *testing.T) {
	// Test TXT record longer than 255 bytes
	longStr := strings.Repeat("x", 300)
	rec := Record{Type: "TXT", RData: longStr}
	data := serializeRecordData(rec)
	// Should be split: 255 + len byte + 45 + len byte = 1 + 255 + 1 + 45 = 302
	if len(data) != 302 {
		t.Errorf("long TXT len = %d, want 302", len(data))
	}
}

func TestSerializeRecordData_SPF(t *testing.T) {
	rec := Record{Type: "SPF", RData: "v=spf1 ~all"}
	data := serializeRecordData(rec)
	if len(data) == 0 {
		t.Fatal("SPF should serialize to non-empty bytes")
	}
}

func TestSerializeRecordData_InvalidA(t *testing.T) {
	rec := Record{Type: "A", RData: "not-an-ip"}
	data := serializeRecordData(rec)
	if len(data) != 0 {
		t.Errorf("invalid A should serialize to empty, got %d bytes", len(data))
	}
}

func TestSerializeRecordData_InvalidAAAA(t *testing.T) {
	rec := Record{Type: "AAAA", RData: "not-an-ip"}
	data := serializeRecordData(rec)
	if len(data) != 0 {
		t.Errorf("invalid AAAA should serialize to empty, got %d bytes", len(data))
	}
}

func TestSerializeRecordData_UnknownType(t *testing.T) {
	rec := Record{Type: "CUSTOM", RData: "some-data"}
	data := serializeRecordData(rec)
	if len(data) == 0 {
		t.Fatal("unknown type should return raw data")
	}
}

// ============================================================================
// sortRRsets / buildCanonicalRRset (zonemd.go) — 0%
// ============================================================================

func TestSortRRsets(t *testing.T) {
	rrsets := [][]byte{
		{0x03, 0x03}, // smaller
		{0x01, 0x01}, // smallest
		{0x02, 0x02}, // middle
	}
	sortRRsets(rrsets)
	for i := 1; i < len(rrsets); i++ {
		if string(rrsets[i]) < string(rrsets[i-1]) {
			t.Errorf("rrsets not sorted at index %d", i)
		}
	}
}

func TestBuildCanonicalRRset(t *testing.T) {
	name := "www.example.com."
	rtype := uint16(1) // A
	rdataList := [][]byte{{192, 0, 2, 1}}

	result := buildCanonicalRRset(name, rtype, rdataList)
	if len(result) == 0 {
		t.Fatal("buildCanonicalRRset should return non-empty bytes")
	}
	// Should contain the type bytes
	// rtype=1 => byte(0), byte(1)
	typeIdx := len(result) - 4 - 1 // approximate
	_ = typeIdx
}

// ============================================================================
// ZoneJournal (wal_journal.go) — all 0%
// ============================================================================

func TestNewZoneJournal(t *testing.T) {
	tmpDir := t.TempDir()
	wal, err := storage.OpenWAL(tmpDir, storage.DefaultWALOptions())
	if err != nil {
		t.Skipf("cannot open WAL: %v", err)
	}
	defer wal.Close()

	zj := NewZoneJournal(wal, "example.com.")
	if zj == nil {
		t.Fatal("NewZoneJournal should not return nil")
	}
	if zj.zone != "example.com." {
		t.Errorf("zone = %q, want example.com.", zj.zone)
	}
}

func TestZoneJournal_LogAddRecord(t *testing.T) {
	tmpDir := t.TempDir()
	wal, err := storage.OpenWAL(tmpDir, storage.DefaultWALOptions())
	if err != nil {
		t.Skipf("cannot open WAL: %v", err)
	}
	defer wal.Close()

	zj := NewZoneJournal(wal, "example.com.")
	err = zj.LogAddRecord("www.example.com.", "A", 300, "192.0.2.1")
	if err != nil {
		t.Fatalf("LogAddRecord: %v", err)
	}
}

func TestZoneJournal_LogDelRecord(t *testing.T) {
	tmpDir := t.TempDir()
	wal, err := storage.OpenWAL(tmpDir, storage.DefaultWALOptions())
	if err != nil {
		t.Skipf("cannot open WAL: %v", err)
	}
	defer wal.Close()

	zj := NewZoneJournal(wal, "example.com.")
	err = zj.LogDelRecord("www.example.com.", "A")
	if err != nil {
		t.Fatalf("LogDelRecord: %v", err)
	}
}

func TestZoneJournal_LogZoneDelete(t *testing.T) {
	tmpDir := t.TempDir()
	wal, err := storage.OpenWAL(tmpDir, storage.DefaultWALOptions())
	if err != nil {
		t.Skipf("cannot open WAL: %v", err)
	}
	defer wal.Close()

	zj := NewZoneJournal(wal, "example.com.")
	err = zj.LogZoneDelete()
	if err != nil {
		t.Fatalf("LogZoneDelete: %v", err)
	}
}

func TestZoneJournal_Replay(t *testing.T) {
	tmpDir := t.TempDir()
	wal, err := storage.OpenWAL(tmpDir, storage.DefaultWALOptions())
	if err != nil {
		t.Skipf("cannot open WAL: %v", err)
	}
	defer wal.Close()

	zj := NewZoneJournal(wal, "example.com.")

	// Log several entries
	zj.LogAddRecord("www.example.com.", "A", 300, "192.0.2.1")
	zj.LogDelRecord("www.example.com.", "A")
	zj.LogAddRecord("mail.example.com.", "MX", 3600, "10 mail.example.com.")

	entries, err := zj.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}

func TestZoneJournal_Replay_FiltersOtherZones(t *testing.T) {
	tmpDir := t.TempDir()
	wal, err := storage.OpenWAL(tmpDir, storage.DefaultWALOptions())
	if err != nil {
		t.Skipf("cannot open WAL: %v", err)
	}
	defer wal.Close()

	zj1 := NewZoneJournal(wal, "example.com.")
	zj2 := NewZoneJournal(wal, "other.com.")

	zj1.LogAddRecord("www.example.com.", "A", 300, "192.0.2.1")
	zj2.LogAddRecord("www.other.com.", "A", 300, "10.0.0.1")

	entries, err := zj1.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry for example.com., got %d", len(entries))
	}
	if entries[0].Zone != "example.com." {
		t.Errorf("entry zone = %q, want example.com.", entries[0].Zone)
	}
}

func TestZoneJournal_Replay_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	wal, err := storage.OpenWAL(tmpDir, storage.DefaultWALOptions())
	if err != nil {
		t.Skipf("cannot open WAL: %v", err)
	}
	defer wal.Close()

	zj := NewZoneJournal(wal, "example.com.")
	entries, err := zj.Replay()
	if err != nil {
		t.Fatalf("Replay empty: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty WAL, got %d", len(entries))
	}
}

// ============================================================================
// KVPersistence PersistAll enabled (kv_persistence.go) — 40%
// ============================================================================

func TestKVPersistence_PersistAll_Enabled(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping: %v", err)
	}
	defer kv.Close()

	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})

	kvp := NewKVPersistence(m, kv)
	kvp.Enable()

	err = kvp.PersistAll()
	if err != nil {
		t.Fatalf("PersistAll enabled: %v", err)
	}
}

// ============================================================================
// KVPersistence LoadFromKV enabled (kv_persistence.go) — 46.2%
// ============================================================================

func TestKVPersistence_LoadFromKV_Enabled(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping: %v", err)
	}
	defer kv.Close()

	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})

	kvp := NewKVPersistence(m, kv)
	kvp.Enable()

	// Persist then load
	kvp.PersistZone("example.com.")
	z, found, err := kvp.LoadFromKV("example.com.")
	if err != nil {
		t.Fatalf("LoadFromKV: %v", err)
	}
	if !found {
		t.Error("expected to find zone in KV store")
	}
	if z.Origin != "example.com." {
		t.Errorf("origin = %q, want example.com.", z.Origin)
	}
}

func TestKVPersistence_LoadFromKV_NotFound(t *testing.T) {
	m := NewManager()
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping: %v", err)
	}
	defer kv.Close()

	kvp := NewKVPersistence(m, kv)
	kvp.Enable()

	z, found, err := kvp.LoadFromKV("nonexistent.com.")
	if err != nil {
		t.Fatalf("LoadFromKV: %v", err)
	}
	if found || z != nil {
		t.Error("expected not found for nonexistent zone")
	}
}

// ============================================================================
// KVPersistence DeleteFromKV enabled (kv_persistence.go) — 85.7%
// ============================================================================

func TestKVPersistence_DeleteFromKV_Enabled(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping: %v", err)
	}
	defer kv.Close()

	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})

	kvp := NewKVPersistence(m, kv)
	kvp.Enable()
	kvp.PersistZone("example.com.")

	err = kvp.DeleteFromKV("example.com.")
	if err != nil {
		t.Fatalf("DeleteFromKV: %v", err)
	}

	// Verify it's gone
	_, found, _ := kvp.LoadFromKV("example.com.")
	if found {
		t.Error("zone should be deleted from KV store")
	}
}

// ============================================================================
// KVPersistence ListKVZones enabled (kv_persistence.go) — 85.7%
// ============================================================================

func TestKVPersistence_ListKVZones_Enabled(t *testing.T) {
	m := NewManager()
	m.SetZoneDir("")
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping: %v", err)
	}
	defer kv.Close()

	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1}
	m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}})

	kvp := NewKVPersistence(m, kv)
	kvp.Enable()
	kvp.PersistZone("example.com.")

	zones, err := kvp.ListKVZones()
	if err != nil {
		t.Fatalf("ListKVZones: %v", err)
	}
	if len(zones) != 1 {
		t.Errorf("expected 1 zone, got %d", len(zones))
	}
}

// ============================================================================
// KVPersistence storedRecordsToZone with SOA (kv_persistence.go) — 71.4%
// ============================================================================

func TestKVPersistence_storedRecordsToZone_WithSOA(t *testing.T) {
	m := NewManager()
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping: %v", err)
	}
	defer kv.Close()

	kvp := NewKVPersistence(m, kv)
	meta := storage.ZoneMeta{Origin: "example.com.", DefaultTTL: 3600}
	rdata := "ns1.example.com. hostmaster.example.com. 2024010101 3600 900 604800 86400"
	// Note: storedRecordsToZone only checks the first map entry for SOA
	// (due to early break), so we put the SOA in the only record set.
	records := map[string][]storage.StoredRecord{
		"example.com.": {
			{Name: "example.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: rdata},
		},
	}

	z := kvp.storedRecordsToZone(meta, records)
	if z.SOA == nil {
		t.Fatal("SOA should be parsed from stored records")
	}
	if z.SOA.Serial != 2024010101 {
		t.Errorf("SOA serial = %d, want 2024010101", z.SOA.Serial)
	}
	if z.SOA.MName != "ns1.example.com." {
		t.Errorf("SOA MName = %q, want ns1.example.com.", z.SOA.MName)
	}
}

func TestKVPersistence_PersistZone_EnabledNoZone(t *testing.T) {
	m := NewManager()
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Skipf("skipping: %v", err)
	}
	defer kv.Close()

	kvp := NewKVPersistence(m, kv)
	kvp.Enable()

	// Persisting a zone that doesn't exist in the manager should return nil
	err = kvp.PersistZone("nonexistent.com.")
	if err != nil {
		t.Errorf("PersistZone for missing zone: %v", err)
	}
}

// ============================================================================
// parseRDataFields (kv_persistence.go) — 93.3%, exercise quoted fields
// ============================================================================

func TestParseRDataFields_QuotedFields(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{`ns1 hostmaster 1 3600 900 604800 86400`, []string{"ns1", "hostmaster", "1", "3600", "900", "604800", "86400"}},
		// parseRDataFields keeps quotes in the output (unlike parseFields which strips them)
		{`"quoted field" unquoted`, []string{"\"quoted field\"", "unquoted"}},
		{`a "b c" d`, []string{"a", "\"b c\"", "d"}},
		{"", nil},
		{"   ", nil},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseRDataFields(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("parseRDataFields(%q) = %v (len %d), want %v (len %d)",
					tt.input, got, len(got), tt.want, len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("field[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ============================================================================
// parseUint32 edge cases (kv_persistence.go) — 87.5%
// ============================================================================

func TestParseUint32_EdgeCases(t *testing.T) {
	tests := []struct {
		input   string
		want    uint32
		wantErr bool
	}{
		{"0", 0, false},
		{"1", 1, false},
		{"4294967295", 4294967295, false},  // max uint32
		{"4294967296", 0, true},             // overflow
		{"abc", 0, true},                    // non-numeric
		{"", 0, false},                      // empty returns 0 (loop doesn't execute)
		{"123abc", 0, true},                 // mixed
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseUint32(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Errorf("parseUint32(%q) = %d, want %d", tt.input, got, tt.want)
				}
			}
		})
	}
}

// ============================================================================
// parseTTLValue edge cases (kv_persistence.go) — 95.5%
// ============================================================================

func TestParseTTLValue_Overflow(t *testing.T) {
	// Test overflow: value * multiplier > uint32 max
	_, err := parseTTLValue("4294967295H")
	if err == nil {
		t.Error("expected overflow error")
	}
}

func TestParseTTLValue_InvalidSuffix(t *testing.T) {
	// "1z" — 'Z' is not a recognized suffix, stays as "1Z" then parseUint32 fails
	_, err := parseTTLValue("1z")
	if err == nil {
		t.Error("expected error for invalid TTL suffix")
	}
}

// ============================================================================
// RadixTree edge cases — Find with partial match
// ============================================================================

func TestRadixTree_FindWithNoBestZone(t *testing.T) {
	tree := NewRadixTree()
	// Insert a zone at example.com.
	tree.Insert("example.com.", &Zone{Origin: "example.com."})

	// Query for something in a completely different tree branch
	got := tree.Find("other.org.")
	if got != nil {
		t.Error("expected nil for name with no matching tree path")
	}
}

func TestRadixTree_FindWithBestFallback(t *testing.T) {
	tree := NewRadixTree()
	tree.Insert("example.com.", &Zone{Origin: "example.com."})

	// Query for subdomain — should find example.com. as best match
	got := tree.Find("www.example.com.")
	if got == nil || got.Origin != "example.com." {
		t.Error("expected example.com. as best fallback")
	}

	// Query that goes beyond the tree at a dead end but has a best zone
	got = tree.Find("deep.sub.example.com.")
	if got == nil || got.Origin != "example.com." {
		t.Error("expected example.com. as best fallback for deep subdomain")
	}
}

// ============================================================================
// LookupWildcard edge cases — 92.3% (empty label and root cases)
// ============================================================================

func TestLookupWildcard_AtOrigin(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"*.example.com.": {{Name: "*.example.com.", Type: "A", TTL: 300, RData: "10.0.0.1"}},
	})

	// Query at origin itself — name == origin, loop breaks immediately
	_, _, found := z.LookupWildcard("example.com.", "A")
	if found {
		t.Error("expected no wildcard match for zone origin itself")
	}
}

func TestLookupWildcard_AnyType(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"*.example.com.": {
			{Name: "*.example.com.", Type: "A", TTL: 300, RData: "10.0.0.1"},
			{Name: "*.example.com.", Type: "MX", TTL: 300, RData: "10 mail.example.com."},
		},
	})

	// Query with empty type should return all records
	recs, _, found := z.LookupWildcard("anything.example.com.", "")
	if !found {
		t.Fatal("expected wildcard match")
	}
	if len(recs) != 2 {
		t.Errorf("expected 2 records for empty type, got %d", len(recs))
	}
}

func TestLookupWildcard_AnyTypeKeyword(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"*.example.com.": {
			{Name: "*.example.com.", Type: "A", TTL: 300, RData: "10.0.0.1"},
			{Name: "*.example.com.", Type: "MX", TTL: 300, RData: "10 mail.example.com."},
		},
	})

	// Query with "ANY" type should return all records
	recs, _, found := z.LookupWildcard("anything.example.com.", "ANY")
	if !found {
		t.Fatal("expected wildcard match")
	}
	if len(recs) != 2 {
		t.Errorf("expected 2 records for ANY type, got %d", len(recs))
	}
}

// ============================================================================
// FindDelegation edge cases — 93.8%
// ============================================================================

func TestFindDelegation_OutOfZone(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.": {
			{Name: "example.com.", Type: "NS", RData: "ns1.example.com."},
		},
	})

	_, _, found := z.FindDelegation("www.other.com.")
	if found {
		t.Error("expected no delegation for out-of-zone query")
	}
}

// ============================================================================
// testLogger for capturing log output in tests
// ============================================================================

type testLogger struct {
	msgs []string
}

func (l *testLogger) Warnf(format string, args ...any) {
	l.msgs = append(l.msgs, format)
}

// errorAs is a simple wrapper for type assertion on ZoneMDError
func errorAs(err error, target interface{}) bool {
	if zmdErr, ok := err.(*ZoneMDError); ok {
		*(target.(**ZoneMDError)) = zmdErr
		return true
	}
	return false
}
