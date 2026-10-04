package zone

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/storage"
)

// coverage_test.go adds tests for low-coverage functions in the zone package.
// Functions targeted (below 80% or 0%):
//   - Manager.Load: 0%
//   - handleControl: 76.5% (missing $TTL without arg, unknown directive, empty fields)
//   - parseSOA: 75% (missing invalid serial/ttl fields)
//   - parseFields: 80.8% (missing parenthesized fields, trailing content)
//   - parseRecord: 87.2% (continuation lines with lastOwner)

// ============================================================================
// Manager.Load
// ============================================================================

func TestManagerLoad(t *testing.T) {
	// Create a temporary zone file
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "test.zone")
	content := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400
@ IN NS ns1
@ IN NS ns2
www IN A 192.0.2.1
`
	if err := os.WriteFile(zoneFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp zone file: %v", err)
	}

	m := NewManager()
	err := m.Load("example.com.", zoneFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	z, ok := m.Get("example.com.")
	if !ok {
		t.Fatal("Get should find loaded zone")
	}
	if z.Origin != "example.com." {
		t.Errorf("Origin = %q, want %q", z.Origin, "example.com.")
	}
	if z.SOA == nil {
		t.Fatal("Zone should have SOA record")
	}
	if z.SOA.Serial != 2024010101 {
		t.Errorf("SOA Serial = %d, want %d", z.SOA.Serial, 2024010101)
	}
	wwwRecords := z.Lookup("www.example.com.", "A")
	if len(wwwRecords) != 1 {
		t.Errorf("www A records = %d, want 1", len(wwwRecords))
	}

	// Test Count after load
	if m.Count() != 1 {
		t.Errorf("Count = %d, want 1", m.Count())
	}
}

func TestManagerLoadFileNotFound(t *testing.T) {
	m := NewManager()
	err := m.Load("example.com.", "/nonexistent/path/zone.file")
	if err == nil {
		t.Error("Load should fail for nonexistent file")
	}
}

func TestManagerLoadInvalidZone(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "invalid.zone")
	content := `$ORIGIN example.com.
@ IN SOA ns1 hostmaster
`
	if err := os.WriteFile(zoneFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp zone file: %v", err)
	}

	m := NewManager()
	err := m.Load("example.com.", zoneFile)
	if err == nil {
		t.Error("Load should fail for invalid zone")
	}
}

func TestManagerLoadZoneValidationFails(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "novsoa.zone")
	// Zone file without SOA and NS (will fail validation)
	content := `$ORIGIN example.com.
www IN A 192.0.2.1
`
	if err := os.WriteFile(zoneFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp zone file: %v", err)
	}

	m := NewManager()
	err := m.Load("example.com.", zoneFile)
	if err == nil {
		t.Error("Load should fail when zone validation fails")
	}
}

// ============================================================================
// Manager.Reload success path
// ============================================================================

func TestManagerReloadSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "test.zone")
	content := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400
@ IN NS ns1
www IN A 192.0.2.1
`
	if err := os.WriteFile(zoneFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp zone file: %v", err)
	}

	m := NewManager()
	err := m.Load("example.com.", zoneFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Update the zone file with new serial
	updatedContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 hostmaster 2024010102 3600 900 604800 86400
@ IN NS ns1
www IN A 192.0.2.2
`
	if err := os.WriteFile(zoneFile, []byte(updatedContent), 0644); err != nil {
		t.Fatalf("Failed to update zone file: %v", err)
	}

	err = m.Reload("example.com.")
	if err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	z, _ := m.Get("example.com.")
	if z.SOA.Serial != 2024010102 {
		t.Errorf("After reload, Serial = %d, want 2024010102", z.SOA.Serial)
	}
}

// ============================================================================
// handleControl edge cases
// ============================================================================

func TestHandleControlEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name:    "empty line",
			content: "",
			wantErr: false,
		},
		{
			name:    "$TTL without value",
			content: "$TTL",
			wantErr: true,
		},
		{
			name:    "$TTL invalid value",
			content: "$TTL abc",
			wantErr: true,
		},
		{
			name:    "unknown directive",
			content: "$UNKNOWN something",
			wantErr: true,
		},
		{
			name:    "$ORIGIN without value",
			content: "$ORIGIN",
			wantErr: true,
		},
		{
			name:    "$INCLUDE file not found",
			content: "$INCLUDE other.zone",
			wantErr: true,
		},
		{
			name:    "$ORIGIN valid",
			content: "$ORIGIN test.com.",
			wantErr: false,
		},
		{
			name:    "$TTL valid",
			content: "$TTL 7200",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &parser{
				zone:     &Zone{Origin: ".", Records: make(map[string][]Record)},
				filename: "test",
			}
			err := p.handleControl(tt.content)
			if tt.wantErr && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// ============================================================================
// parseSOA error cases
// ============================================================================

func TestParseSOAErrorCases(t *testing.T) {
	tests := []struct {
		name   string
		rdata  string
		wantOk bool
	}{
		{
			name:   "too few fields",
			rdata:  "ns1 hostmaster 1",
			wantOk: false,
		},
		{
			name:   "invalid serial",
			rdata:  "ns1 hostmaster abc 3600 900 604800 86400",
			wantOk: false,
		},
		{
			name:   "invalid refresh",
			rdata:  "ns1 hostmaster 1 abc 900 604800 86400",
			wantOk: false,
		},
		{
			name:   "invalid retry",
			rdata:  "ns1 hostmaster 1 3600 abc 604800 86400",
			wantOk: false,
		},
		{
			name:   "invalid expire",
			rdata:  "ns1 hostmaster 1 3600 900 abc 86400",
			wantOk: false,
		},
		{
			name:   "invalid minimum",
			rdata:  "ns1 hostmaster 1 3600 900 604800 abc",
			wantOk: false,
		},
		{
			name:   "valid SOA",
			rdata:  "ns1 hostmaster 2024010101 3600 900 604800 86400",
			wantOk: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &parser{
				zone:     &Zone{Origin: "example.com.", Records: make(map[string][]Record)},
				filename: "test",
			}
			record := Record{RData: tt.rdata, TTL: 3600}
			err := p.parseSOA("example.com.", record)
			if tt.wantOk && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.wantOk && err == nil {
				t.Error("expected error but got none")
			}
		})
	}
}

// ============================================================================
// parseFields edge cases
// ============================================================================

func TestParseFieldsEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "only whitespace",
			input:    "   ",
			expected: []string{},
		},
		{
			name:     "parenthesized content",
			input:    "( content )",
			expected: []string{"content"},
		},
		{
			name:     "quoted with spaces inside",
			input:    `"v=spf1 include:example.com ~all"`,
			expected: []string{"v=spf1 include:example.com ~all"},
		},
		{
			name:     "mixed quoted and unquoted",
			input:    `name "quoted value" unquoted`,
			expected: []string{"name", "quoted value", "unquoted"},
		},
		{
			name:     "unclosed quote",
			input:    `"unclosed`,
			expected: []string{"unclosed"},
		},
		{
			name:     "multiple spaces between fields",
			input:    "a   b   c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "parentheses around multiple fields",
			input:    "a ( b c ) d",
			expected: []string{"a", "b", "c", "d"},
		},
		{
			name:     "quoted empty string",
			input:    `""`,
			expected: []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseFields(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("parseFields(%q) = %v (len %d), want %v (len %d)",
					tt.input, result, len(result), tt.expected, len(tt.expected))
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("parseFields(%q)[%d] = %q, want %q",
						tt.input, i, result[i], tt.expected[i])
				}
			}
		})
	}
}

// ============================================================================
// parseRecord continuation line
// ============================================================================

func TestParseRecordContinuationLine(t *testing.T) {
	// Tested through TestParseFileWithContinuationLine below
}

func TestParseFileWithContinuationLine(t *testing.T) {
	// The zone file has a line starting with a space/tab to indicate continuation
	zoneContent := "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400\n@ IN NS ns1\n IN A 192.0.2.2\n"
	z, err := ParseFile("test.zone", strings.NewReader(zoneContent))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	// Check that the continuation line record was parsed
	// Note: the continuation line behavior depends on whether parse() preserves
	// the leading whitespace before calling parseRecord
	_ = z
}

// TestParseFile_ContinuationOwnerInherited verifies RFC 1035 §5.1
// "the owner name of a record is the same as that of the previous
// resource record" behavior. The previous parser checked the leading
// whitespace with `strings.HasPrefix(text, " \t")` — a 2-char literal
// match that only matches space-then-tab, not the common cases of
// "all spaces" or "all tabs" indents. As a result every continuation
// line in a canonical BIND-style zone got the class field (IN) parsed
// as the owner name. Verify the fix by inspecting the parsed record's
// resolved name.
func TestParseFile_ContinuationOwnerInherited(t *testing.T) {
	zoneContent := strings.Join([]string{
		"$ORIGIN example.com.",
		"$TTL 3600",
		"@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400",
		"@ IN NS ns1",
		"www IN A 192.0.2.1",
		"    IN A 192.0.2.2", // space-indented continuation of "www"
		"\tIN A 192.0.2.3",   // tab-indented continuation of "www"
	}, "\n") + "\n"

	z, err := ParseFile("test.zone", strings.NewReader(zoneContent))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	// All three A records should live under www.example.com.
	records, ok := z.Records["www.example.com."]
	if !ok {
		t.Fatalf("no records under www.example.com.; got keys %v", keysOf(z.Records))
	}
	var aCount int
	for _, r := range records {
		if r.Type == "A" {
			aCount++
		}
	}
	if aCount != 3 {
		t.Errorf("expected 3 A records for www.example.com., got %d", aCount)
	}

	// And nothing should have landed under "in.example.com." (the bug
	// would have parsed the class field "IN" as the owner).
	if _, leaked := z.Records["in.example.com."]; leaked {
		t.Error("continuation lines wrongly created in.example.com. — owner-name detection broken")
	}
}

func keysOf(m map[string][]Record) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ============================================================================
// parseRecord with too few fields
// ============================================================================

func TestParseRecordTooFewFields(t *testing.T) {
	zoneContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400
@ IN NS ns1
;
`
	// Empty record lines (after comment removal) should be OK
	z, err := ParseFile("test.zone", strings.NewReader(zoneContent))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if z == nil {
		t.Fatal("Zone should not be nil")
	}
}

// ============================================================================
// parseRecord with unknown fields
// ============================================================================

func TestParseRecordWithUnknownFields(t *testing.T) {
	zoneContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400
@ IN NS ns1
unknown-field IN A 192.0.2.1
`
	z, err := ParseFile("test.zone", strings.NewReader(zoneContent))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	records := z.Lookup("unknown-field.example.com.", "A")
	if len(records) != 1 {
		t.Errorf("Expected 1 A record, got %d", len(records))
	}
}

// ============================================================================
// Validate with valid zone
// ============================================================================

func TestValidateValidZone(t *testing.T) {
	zoneContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400
@ IN NS ns1
`
	z, err := ParseFile("test.zone", strings.NewReader(zoneContent))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if err := z.Validate(); err != nil {
		t.Errorf("Valid zone should pass validation: %v", err)
	}
}

// ============================================================================
// Manager.LoadZone and Remove integration
// ============================================================================

func TestManagerLoadAndRemoveIntegration(t *testing.T) {
	m := NewManager()

	z1 := NewZone("a.com.")
	z1.SOA = &SOARecord{Name: "a.com."}
	z1.NS = []NSRecord{{Name: "ns1.a.com."}}

	z2 := NewZone("b.com.")
	z2.SOA = &SOARecord{Name: "b.com."}
	z2.NS = []NSRecord{{Name: "ns1.b.com."}}

	m.LoadZone(z1, "/a.zone")
	m.LoadZone(z2, "/b.zone")

	if m.Count() != 2 {
		t.Errorf("Count = %d, want 2", m.Count())
	}

	// Remove one
	m.Remove("a.com.")
	if m.Count() != 1 {
		t.Errorf("Count after remove = %d, want 1", m.Count())
	}

	if _, ok := m.Get("b.com."); !ok {
		t.Error("b.com. should still exist")
	}
	if _, ok := m.Get("a.com."); ok {
		t.Error("a.com. should be removed")
	}
}

// ============================================================================
// Manager.SetLogger and ListShared
// ============================================================================

func TestSetLogger(t *testing.T) {
	m := NewManager()
	if m.logger != nil {
		t.Error("Default logger should be nil")
	}

	// SetLogger should not panic
	m.SetLogger(nil)
}

func TestListShared(t *testing.T) {
	m := NewManager()
	if m.ListShared() == nil {
		t.Error("ListShared should return non-nil map")
	}

	// Load a zone and check ListShared
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "test.zone")
	content := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 hostmaster 1 3600 900 604800 86400
@ IN NS ns1
`
	if err := os.WriteFile(zoneFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp zone file: %v", err)
	}

	m.Load("example.com.", zoneFile)
	zones := m.ListShared()
	if len(zones) != 1 {
		t.Errorf("ListShared len = %d, want 1", len(zones))
	}
	if _, ok := zones["example.com."]; !ok {
		t.Error("example.com. should be in ListShared")
	}
}

// ============================================================================
// KVPersistence parseSOAFromRData
// ============================================================================

func TestParseSOAFromRData(t *testing.T) {
	soa := parseSOAFromRData("ns1 hostmaster 1 3600 900 604800 86400")
	if soa == nil {
		t.Fatal("parseSOAFromRData should not return nil")
	}
	if soa.Serial != 1 {
		t.Errorf("Serial = %d, want 1", soa.Serial)
	}
	if soa.Refresh != 3600 {
		t.Errorf("Refresh = %d, want 3600", soa.Refresh)
	}
	if soa.Retry != 900 {
		t.Errorf("Retry = %d, want 900", soa.Retry)
	}
	if soa.Expire != 604800 {
		t.Errorf("Expire = %d, want 604800", soa.Expire)
	}
	if soa.Minimum != 86400 {
		t.Errorf("Minimum = %d, want 86400", soa.Minimum)
	}
}

func TestParseSOAFromRDataWithInvalidData(t *testing.T) {
	// Invalid input should return nil
	soa := parseSOAFromRData("")
	if soa != nil {
		t.Fatal("parseSOAFromRData should return nil for empty input")
	}

	// Short input should also return nil
	soa = parseSOAFromRData("ns1.example.com. hostmaster.example.com. 1")
	if soa != nil {
		t.Fatal("parseSOAFromRData should return nil for short input")
	}
}

// ============================================================================
// parseTTLValue (KVPersistence)
// ============================================================================

func TestParseTTLValue(t *testing.T) {
	tests := []struct {
		input    string
		expected uint32
		wantErr  bool
	}{
		{"3600", 3600, false},
		{"7200", 7200, false},
		{"1h", 3600, false},
		{"30m", 1800, false},
		{"1d", 86400, false},
		{"1w", 604800, false},
		{"2H", 7200, false},
		{"30S", 30, false},
		{"1M", 60, false},
		{"", 0, true},
		{"invalid", 0, true},
		{"3600S", 3600, false}, // raw seconds with S suffix = 3600
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseTTLValue(tt.input)
			if tt.wantErr && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.wantErr && got != tt.expected {
				t.Errorf("parseTTLValue(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

// errorReader is a reader that returns an error after reading some data.
type errorReader struct {
	data      string
	readCount int
	err       error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	if r.readCount == 0 {
		n = copy(p, r.data)
		r.readCount++
		return n, nil
	}
	return 0, r.err
}

// newParserWithScanner is a helper that creates a parser with a primed
// bufio.Scanner. The scanner is advanced once so that scanner.Text() returns
// the given text, which is required by parseRecord's HasPrefix check.
func newParserWithScanner(rawLine string, zone *Zone) *parser {
	scanner := bufio.NewScanner(strings.NewReader(rawLine))
	scanner.Scan()
	return &parser{
		zone:     zone,
		filename: "test",
		lineNum:  1,
		scanner:  scanner,
	}
}

// ============================================================================
// parse() scanner.Err() returning non-nil (line 212-214)
// ============================================================================

func TestParseScannerError(t *testing.T) {
	reader := &errorReader{
		data: "$ORIGIN example.com.\n@ IN SOA ns1 hostmaster 1 3600 900 604800 86400\n",
		err:  errors.New("simulated read error"),
	}
	_, err := ParseFile("test.zone", reader)
	if err == nil {
		t.Error("expected error from scanner failure, got nil")
	}
	if !strings.Contains(err.Error(), "read error") {
		t.Errorf("expected 'read error' in message, got: %v", err)
	}
}

// ============================================================================
// parseRecord: line becomes empty after comment removal (line 264-266)
// ============================================================================

func TestParseRecordLineOnlyComment(t *testing.T) {
	p := newParserWithScanner("www IN A 1.2.3.4", &Zone{Origin: "example.com.", Records: make(map[string][]Record)})
	err := p.parseRecord("; this entire line is a comment")
	if err != nil {
		t.Errorf("expected nil error for comment-only line, got: %v", err)
	}
}

// ============================================================================
// parseRecord: single field - invalid record format (line 270-272)
// ============================================================================

func TestParseRecordSingleField(t *testing.T) {
	p := newParserWithScanner("just-one-field", &Zone{Origin: "example.com.", Records: make(map[string][]Record)})
	err := p.parseRecord("just-one-field")
	if err == nil {
		t.Error("expected error for single-field record")
	}
	if !strings.Contains(err.Error(), "invalid record format") {
		t.Errorf("expected 'invalid record format' error, got: %v", err)
	}
}

// ============================================================================
// parseRecord: continuation line with lastOwner (line 288-291)
// The check is strings.HasPrefix(p.scanner.Text(), " \t") so the raw scanner
// line must start with space+tab.
// ============================================================================

func TestParseRecordContinuationLineUsesLastOwner(t *testing.T) {
	rawLine := " \tIN A 192.0.2.1"
	zone := &Zone{Origin: "example.com.", Records: make(map[string][]Record)}
	p := newParserWithScanner(rawLine, zone)
	p.lastOwner = "www"

	err := p.parseRecord(strings.TrimSpace(rawLine))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records := p.zone.Records["www.example.com."]
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Type != "A" {
		t.Errorf("expected type A, got %s", records[0].Type)
	}
	if records[0].RData != "192.0.2.1" {
		t.Errorf("expected RData 192.0.2.1, got %s", records[0].RData)
	}
}

// ============================================================================
// parseRecord: continuation line via ParseFile (full integration)
// ============================================================================

func TestParseFileContinuationLineIntegration(t *testing.T) {
	// Line starting with space+tab triggers continuation in parseRecord.
	zoneContent := "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400\n@ IN NS ns1\n \tIN A 192.0.2.5\n"
	z, err := ParseFile("test.zone", strings.NewReader(zoneContent))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	// The continuation line should have used the last owner ("@")
	records := z.Lookup("example.com.", "A")
	if len(records) != 1 {
		t.Errorf("expected 1 A record for example.com. (continuation), got %d", len(records))
	}
}

// ============================================================================
// parseRecord: unknown field in field loop (line 312)
// ============================================================================

func TestParseRecordWithUnknownFieldBeforeType(t *testing.T) {
	p := newParserWithScanner("www xyz IN A 192.0.2.1", &Zone{Origin: "example.com.", Records: make(map[string][]Record)})
	// "xyz" is neither a valid TTL, a valid class, nor a valid record type.
	// The loop should consume it as an unknown field and continue.
	err := p.parseRecord("www xyz IN A 192.0.2.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records := p.zone.Records["www.example.com."]
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Type != "A" {
		t.Errorf("expected type A, got %s", records[0].Type)
	}
}

// ============================================================================
// parseRecord: missing record type (line 316-318)
// ============================================================================

func TestParseRecordMissingType(t *testing.T) {
	p := newParserWithScanner("www IN", &Zone{Origin: "example.com.", Records: make(map[string][]Record)})
	err := p.parseRecord("www IN")
	if err == nil {
		t.Error("expected error for missing record type")
	}
	if !strings.Contains(err.Error(), "missing record type") {
		t.Errorf("expected 'missing record type' error, got: %v", err)
	}
}

// ============================================================================
// parseRecord: no RData field (record.RData stays empty string)
// ============================================================================

func TestParseRecordNoRData(t *testing.T) {
	p := newParserWithScanner("www IN CNAME", &Zone{Origin: "example.com.", Records: make(map[string][]Record)})
	err := p.parseRecord("www IN CNAME")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records := p.zone.Records["www.example.com."]
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].RData != "" {
		t.Errorf("expected empty RData, got %q", records[0].RData)
	}
}

// ============================================================================
// parseFields: text before opening quote (line 430-433)
// ============================================================================

func TestParseFieldsTextBeforeQuote(t *testing.T) {
	result := parseFields(`textBefore"quoted value"after`)
	expected := []string{"textBefore", "quoted value", "after"}
	if len(result) != len(expected) {
		t.Fatalf("expected %d fields, got %d: %v", len(expected), len(result), result)
	}
	for i, v := range expected {
		if result[i] != v {
			t.Errorf("field[%d] = %q, want %q", i, result[i], v)
		}
	}
}

// ============================================================================
// parseFields: text before opening parenthesis (line 447-450)
// ============================================================================

func TestParseFieldsTextBeforeParen(t *testing.T) {
	// Parentheses are zone file continuation markers. "(" flushes current content
	// as a field; ")" is simply ignored. So "textBefore(content)after" produces
	// ["textBefore", "contentafter"] because ")" skips without flushing.
	result := parseFields(`textBefore(content)after`)
	expected := []string{"textBefore", "contentafter"}
	if len(result) != len(expected) {
		t.Fatalf("expected %d fields, got %d: %v", len(expected), len(result), result)
	}
	for i, v := range expected {
		if result[i] != v {
			t.Errorf("field[%d] = %q, want %q", i, result[i], v)
		}
	}
}

// ============================================================================
// parseRecord: default TTL used when record has TTL=0
// ============================================================================

func TestParseRecordUsesDefaultTTL(t *testing.T) {
	zone := &Zone{Origin: "example.com.", Records: make(map[string][]Record), DefaultTTL: 7200}
	p := newParserWithScanner("www IN A 192.0.2.1", zone)
	err := p.parseRecord("www IN A 192.0.2.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records := p.zone.Records["www.example.com."]
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].TTL != 7200 {
		t.Errorf("expected TTL 7200 (from DefaultTTL), got %d", records[0].TTL)
	}
}

// ============================================================================
// parseRecord: record with explicit TTL and class
// ============================================================================

func TestParseRecordExplicitTTLAndClass(t *testing.T) {
	zone := &Zone{Origin: "example.com.", Records: make(map[string][]Record), DefaultTTL: 300}
	p := newParserWithScanner("www 3600 IN A 192.0.2.1", zone)
	err := p.parseRecord("www 3600 IN A 192.0.2.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records := p.zone.Records["www.example.com."]
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].TTL != 3600 {
		t.Errorf("expected TTL 3600, got %d", records[0].TTL)
	}
	if records[0].Class != "IN" {
		t.Errorf("expected class IN, got %s", records[0].Class)
	}
}

// ============================================================================
// parseRecord: record with class before TTL
// ============================================================================

func TestParseRecordClassBeforeTTL(t *testing.T) {
	zone := &Zone{Origin: "example.com.", Records: make(map[string][]Record), DefaultTTL: 300}
	p := newParserWithScanner("www IN 3600 A 192.0.2.1", zone)
	err := p.parseRecord("www IN 3600 A 192.0.2.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records := p.zone.Records["www.example.com."]
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].TTL != 3600 {
		t.Errorf("expected TTL 3600, got %d", records[0].TTL)
	}
	if records[0].Class != "IN" {
		t.Errorf("expected class IN, got %s", records[0].Class)
	}
}

// ============================================================================
// parseRecord: record with non-IN class
// ============================================================================

func TestParseRecordNonINClass(t *testing.T) {
	zone := &Zone{Origin: "example.com.", Records: make(map[string][]Record)}
	p := newParserWithScanner("www CH A 192.0.2.1", zone)
	err := p.parseRecord("www CH A 192.0.2.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	records := p.zone.Records["www.example.com."]
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Class != "CH" {
		t.Errorf("expected class CH, got %s", records[0].Class)
	}
}

// ============================================================================
// Validate: zone with empty origin
// ============================================================================

func TestValidateEmptyOrigin(t *testing.T) {
	z := &Zone{
		Origin: "",
		SOA:    &SOARecord{Name: ""},
		NS:     []NSRecord{{Name: "ns1."}},
	}
	err := z.Validate()
	if err == nil {
		t.Error("expected error for empty origin")
	}
}

// ============================================================================
// Lookup: name without trailing dot
// ============================================================================

func TestLookupNameWithoutDot(t *testing.T) {
	z := NewZone("example.com.")
	z.Records["www.example.com."] = []Record{
		{Type: "A", RData: "192.0.2.1"},
	}
	records := z.Lookup("www.example.com", "A")
	if len(records) != 1 {
		t.Errorf("expected 1 record for name without trailing dot, got %d", len(records))
	}
}

// ============================================================================
// SerialIncrement (manager.go) — 0% coverage
// ============================================================================

// TestStripZoneComment verifies that BIND-style ';' comments are stripped
// only when they appear outside of quoted strings — so TXT records that
// legitimately contain semicolons inside quotes are preserved.
func TestStripZoneComment(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain_comment", "foo bar ; this is a comment", "foo bar "},
		{"no_comment", "foo bar baz", "foo bar baz"},
		{"semicolon_in_quotes", `"foo;bar" trailing`, `"foo;bar" trailing`},
		{"semicolon_inside_then_comment", `"foo;bar" ; trailing`, `"foo;bar" `},
		{"escaped_semicolon", `foo \; bar`, `foo \; bar`},
		{"unterminated_quote", `"foo;bar`, `"foo;bar`},
		{"empty", "", ""},
		{"only_comment", "; just a comment", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripZoneComment(tt.in)
			if got != tt.want {
				t.Errorf("stripZoneComment(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSerialIncrement(t *testing.T) {
	// RFC 1982 §3.1: arithmetic is mod 2^32 over the full uint32 range;
	// only 0xFFFFFFFF → 0 is a real wrap, not the half-range boundary.
	tests := []struct {
		name  string
		input uint32
		want  uint32
	}{
		{"zero", 0, 1},
		{"normal", 100, 101},
		{"near_half_range", SerialHalfRange - 2, SerialHalfRange - 1},
		{"at_half_range_minus_1", SerialHalfRange - 1, SerialHalfRange},
		{"above_half_range", SerialHalfRange, SerialHalfRange + 1},
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
	// RFC 1982 §3.2: s1 is newer than s2 iff
	//   (s1 > s2 AND s1-s2 < 2^31) OR (s1 < s2 AND s2-s1 > 2^31)
	tests := []struct {
		name      string
		s1, s2    uint32
		wantNewer bool
	}{
		// equal => false
		{"equal", 100, 100, false},
		// s1 > s2 and s1-s2 < 2^31 => s1 newer
		{"s1_greater_within_range", 200, 100, true},
		// s1 > s2 and s1-s2 == 2^31 => undefined, we treat as false
		{"s1_greater_at_half", 100 + SerialHalfRange, 100, false},
		// s1 > s2 and s1-s2 < 2^31 by 1 => s1 newer
		{"s1_greater_just_within", 100 + SerialHalfRange - 1, 100, true},
		// s1 < s2 and s2-s1 < 2^31 => s2 is newer, so s1 is NOT newer
		{"s1_less_direct_order", 100, 100 + SerialHalfRange - 1, false},
		// s1 < s2 and s2-s1 == 2^31 => undefined, we treat as false
		{"s1_less_at_half", 100, 100 + SerialHalfRange, false},
		// s1 < s2 and s2-s1 > 2^31 => wrap-around, s1 IS newer
		{"s1_wrap_newer", 0, 0xFFFFFFFF, true},
		// Symmetric: 0xFFFFFFFF NOT newer than 0 (0 is the wrapped-newer one)
		{"max_not_newer_than_zero", 0xFFFFFFFF, 0, false},
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

func TestSyncDir(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatalf("syncDir on temp dir: %v", err)
	}
}

func TestSyncDir_InvalidPath(t *testing.T) {
	err := syncDir(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("expected error for missing directory")
	}
	if !strings.Contains(err.Error(), "open dir") {
		t.Fatalf("error = %v, want open dir context", err)
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

func TestManager_Load_AllowsZoneDirWithDotDotInName(t *testing.T) {
	parent := t.TempDir()
	zoneDir := filepath.Join(parent, "zones..prod")
	if err := os.MkdirAll(zoneDir, 0755); err != nil {
		t.Fatal(err)
	}
	zoneFile := filepath.Join(zoneDir, "example.zone")
	content := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 hostmaster 1 3600 900 604800 86400
@ IN NS ns1
`
	if err := os.WriteFile(zoneFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	m := NewManager()
	m.SetZoneDir(zoneDir)
	if err := m.Load("example.com.", zoneFile); err != nil {
		t.Fatalf("Load should allow paths inside zone_dir even when directory name contains '..': %v", err)
	}
}

func TestManager_Load_RejectsOutsideZoneDir(t *testing.T) {
	parent := t.TempDir()
	zoneDir := filepath.Join(parent, "zones")
	outsideDir := filepath.Join(parent, "zones-sibling")
	if err := os.MkdirAll(zoneDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideDir, 0755); err != nil {
		t.Fatal(err)
	}
	zoneFile := filepath.Join(outsideDir, "example.zone")
	if err := os.WriteFile(zoneFile, []byte("$ORIGIN example.com.\n"), 0644); err != nil {
		t.Fatal(err)
	}

	m := NewManager()
	m.SetZoneDir(zoneDir)
	err := m.Load("example.com.", zoneFile)
	if err == nil {
		t.Fatal("Load should reject paths outside zone_dir")
	}
	if !strings.Contains(err.Error(), "outside zone_dir") {
		t.Fatalf("Load error = %v, want outside zone_dir", err)
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

func TestManager_DeleteZone_RemovesZoneDirFile(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager()
	m.SetZoneDir(tmpDir)

	soa := &SOARecord{
		MName: "ns1.example.com.", RName: "hostmaster.example.com.",
		Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400,
	}
	ns := []NSRecord{{NSDName: "ns1.example.com.", TTL: 0}}

	if err := m.CreateZone("example.com.", 3600, soa, ns); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}

	zonePath := filepath.Join(tmpDir, "example.com.zone")
	if _, err := os.Stat(zonePath); err != nil {
		t.Fatalf("expected zone file before delete: %v", err)
	}

	if err := m.DeleteZone("example.com."); err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}

	if _, err := os.Stat(zonePath); !os.IsNotExist(err) {
		t.Fatalf("zone file still exists after delete, stat err = %v", err)
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

func TestManager_RecordMutationsPersistWithZoneDir(t *testing.T) {
	dir := t.TempDir()
	m := NewManager()
	m.SetZoneDir(dir)

	soa := &SOARecord{
		MName:   "ns1.example.com.",
		RName:   "hostmaster.example.com.",
		Serial:  1,
		Refresh: 3600,
		Retry:   900,
		Expire:  604800,
		Minimum: 86400,
	}
	if err := m.CreateZone("example.com.", 3600, soa, []NSRecord{{NSDName: "ns1.example.com."}}); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}

	zonePath := filepath.Join(dir, "example.com.zone")
	mustFinish := func(name string, fn func() error) {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			done <- fn()
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not return; likely zone lock self-deadlock during persistence", name)
		}
	}
	mustContain := func(substr string) {
		t.Helper()
		content, err := os.ReadFile(zonePath)
		if err != nil {
			t.Fatalf("read zone file: %v", err)
		}
		if !strings.Contains(string(content), substr) {
			t.Fatalf("zone file does not contain %q:\n%s", substr, content)
		}
	}
	mustNotContain := func(substr string) {
		t.Helper()
		content, err := os.ReadFile(zonePath)
		if err != nil {
			t.Fatalf("read zone file: %v", err)
		}
		if strings.Contains(string(content), substr) {
			t.Fatalf("zone file unexpectedly contains %q:\n%s", substr, content)
		}
	}

	mustFinish("AddRecord", func() error {
		return m.AddRecord("example.com.", Record{Name: "www", TTL: 300, Type: "A", RData: "192.0.2.1"})
	})
	mustContain("www\t300\tIN\tA\t192.0.2.1")

	mustFinish("UpdateRecord", func() error {
		return m.UpdateRecord("example.com.", "www", "A", "192.0.2.1", Record{Name: "www", TTL: 300, Type: "A", RData: "192.0.2.2"})
	})
	mustContain("www\t300\tIN\tA\t192.0.2.2")
	mustNotContain("www\t300\tIN\tA\t192.0.2.1")

	mustFinish("DeleteRecord", func() error {
		return m.DeleteRecord("example.com.", "www", "A")
	})
	mustNotContain("www\t300\tIN\tA")
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

func TestWriteZone_QuotesCharacterStringRDataRoundTrip(t *testing.T) {
	dkim := `v=DKIM1; k=rsa; p=abc\"def\\ghi`
	spf := "v=spf1 include:_spf.example.com ~all"
	z := &Zone{
		Origin:     "example.com.",
		DefaultTTL: 300,
		Records: map[string][]Record{
			"_dmarc.example.com.": {
				{Name: "_dmarc.example.com.", TTL: 300, Class: "IN", Type: "TXT", RData: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
			},
			"selector._domainkey.example.com.": {
				{Name: "selector._domainkey.example.com.", TTL: 300, Class: "IN", Type: "TXT", RData: dkim},
			},
			"example.com.": {
				{Name: "example.com.", TTL: 300, Class: "IN", Type: "SPF", RData: spf},
			},
		},
	}

	out, err := WriteZone(z)
	if err != nil {
		t.Fatalf("WriteZone: %v", err)
	}
	if !strings.Contains(out, `TXT	"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"`) {
		t.Fatalf("TXT RDATA with semicolons was not quoted:\n%s", out)
	}

	parsed, err := ParseFile("roundtrip.zone", strings.NewReader(out))
	if err != nil {
		t.Fatalf("ParseFile round-trip: %v\n%s", err, out)
	}

	// Round 040: character-string RDATA is now stored in its canonical quoted
	// form, so the round trip is compared on the VALUE protocol.ParseRDataText
	// packs (what goes on the wire), not on the storage representation.
	roundTripValue := func(t *testing.T, z *Zone, owner, want string) {
		t.Helper()
		for _, r := range z.Records[owner] {
			if r.Type != "TXT" && r.Type != "SPF" && r.Type != "DKIM" {
				continue
			}
			rd := protocol.ParseRDataText(r.Type, r.RData)
			txt, ok := rd.(*protocol.RDataTXT)
			if !ok || txt == nil {
				t.Fatalf("%s: ParseRDataText(%s, %q) = %T, want *protocol.RDataTXT",
					owner, r.Type, r.RData, rd)
			}
			if len(txt.Strings) != 1 || txt.Strings[0] != want {
				t.Fatalf("%s round-trip value = %q (stored %q), want one string %q",
					owner, txt.Strings, r.RData, want)
			}
			return
		}
		t.Fatalf("%s: no character-string record stored after the round trip", owner)
	}
	wantDMARC := "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
	roundTripValue(t, parsed, "_dmarc.example.com.", wantDMARC)
	roundTripValue(t, parsed, "selector._domainkey.example.com.", dkim)
	roundTripValue(t, parsed, "example.com.", spf)
}

// ============================================================================
// FindDNAME (zone.go) — 0% coverage
// ============================================================================

func TestFindDNAME_Basic(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.": {
			{Name: "example.com.", Type: "SOA", RData: "ns1 admin 1 3600 600 86400 300"},
		},
		"a.b.example.com.": {
			{Name: "a.b.example.com.", Type: "DNAME", RData: "other.net."},
		},
	})

	rec, target, found := z.FindDNAME("x.a.b.example.com.")
	if !found {
		t.Fatal("expected DNAME match for subdomain below DNAME owner")
	}
	if rec.Type != "DNAME" {
		t.Errorf("record type = %q, want DNAME", rec.Type)
	}
	if target != "x.other.net." {
		t.Errorf("synthesized target = %q, want x.other.net.", target)
	}
}

func TestFindDNAME_SubdomainOfDNAME(t *testing.T) {
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

func TestFindDNAME_ReturnsAbsoluteOwnerForRelativeRecordName(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.": {
			{Name: "example.com.", Type: "SOA", RData: "ns1 admin 1 3600 600 86400 300"},
		},
		"a.b.example.com.": {
			{Name: "a.b", Type: "DNAME", RData: "other.net."},
		},
	})

	rec, target, found := z.FindDNAME("x.a.b.example.com.")
	if !found {
		t.Fatal("expected DNAME match for relative stored owner")
	}
	if rec.Name != "a.b.example.com." {
		t.Errorf("DNAME owner = %q, want absolute owner a.b.example.com.", rec.Name)
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

func TestFindDNAME_PartialLabelSuffixOutOfZone(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.": {
			{Name: "example.com.", Type: "DNAME", RData: "example.net."},
		},
	})

	_, _, found := z.FindDNAME("badexample.com.")
	if found {
		t.Error("expected no DNAME match for partial-label suffix outside zone")
	}
}

func TestFindDNAME_AtOrigin(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.": {
			{Name: "example.com.", Type: "DNAME", RData: "example.net."},
		},
	})

	_, _, found := z.FindDNAME("example.com.")
	if found {
		t.Fatal("DNAME must not synthesize for its exact owner name")
	}
}

func TestFindDNAME_OriginAppliesBelowOrigin(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.": {
			{Name: "example.com.", Type: "DNAME", RData: "example.net."},
		},
	})

	_, target, found := z.FindDNAME("www.example.com.")
	if !found {
		t.Fatal("expected DNAME at origin to apply below origin")
	}
	if target != "www.example.net." {
		t.Errorf("synthesized target = %q, want www.example.net.", target)
	}
}

func TestFindDNAME_OneLabelDeep(t *testing.T) {
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
		Origin:  "example.com.",
		SOA:     &SOARecord{MName: "ns1.", RName: "h.", Serial: 1},
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

func TestZONEMD_Verify_Nil(t *testing.T) {
	zmd := &ZONEMD{ZoneName: "a.com.", Hash: []byte{0x01}, Algorithm: 1}
	if zmd.Verify(nil) {
		t.Fatal("Verify(nil) should return false")
	}

	var nilZMD *ZONEMD
	if nilZMD.Verify(zmd) {
		t.Fatal("nil receiver Verify should return false")
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
		{"CAA", 257, false},
		{"URI", 256, false},
		{"SVCB", 64, false},
		{"HTTPS", 65, false},
		{"DNAME", 39, false},
		{"DKIM", 16, false},
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

func TestParseRecordTypeSupportsZoneRecordTypes(t *testing.T) {
	for rtype := range recordTypes {
		t.Run(rtype, func(t *testing.T) {
			got, err := parseRecordType(rtype)
			if err != nil {
				t.Fatalf("parseRecordType(%q) returned error: %v", rtype, err)
			}
			if got == 0 {
				t.Fatalf("parseRecordType(%q) returned zero type", rtype)
			}
			if rtype == "DKIM" && got != protocol.TypeTXT {
				t.Fatalf("parseRecordType(%q) = %d, want TXT type %d", rtype, got, protocol.TypeTXT)
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
		// Canonical wire form: owner-first, length-prefixed labels, lowercased,
		// single trailing root label (RFC 1035 §3.1 / RFC 8976). The previous
		// implementation reversed the labels (TLD-first), which never matched a
		// real ZONEMD digest.
		{"example.com.", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"www.example.com.", []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		// "." is the root: a single zero (the prior code wrongly produced [0,0]).
		{".", []byte{0}},
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

func TestSerializeRecordData_MXInvalidPriorityDoesNotCollideWithZero(t *testing.T) {
	// A malformed MX (unparseable priority) now serializes to empty rather than
	// canonical wire — but the key property still holds: it must NOT collide
	// with a valid zero-priority MX (which serializes to real wire bytes).
	invalid := serializeRecordData(Record{Type: "MX", RData: "bad mail.example.com."})
	validZero := serializeRecordData(Record{Type: "MX", RData: "0 mail.example.com."})

	if bytes.Equal(invalid, validZero) {
		t.Fatal("invalid MX priority serialized identically to valid zero priority")
	}
	if len(invalid) != 0 {
		t.Fatalf("malformed MX serialized to %d bytes, want empty (known type, unparseable)", len(invalid))
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

func TestSerializeRecordData_SPF_Long(t *testing.T) {
	longStr := strings.Repeat("x", 300)
	rec := Record{Type: "SPF", RData: longStr}
	data := serializeRecordData(rec)
	if len(data) != 302 {
		t.Fatalf("long SPF len = %d, want 302", len(data))
	}
	if data[0] != 255 {
		t.Fatalf("first SPF chunk length = %d, want 255", data[0])
	}
	if data[256] != 45 {
		t.Fatalf("second SPF chunk length = %d, want 45", data[256])
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
	ttl := uint32(3600)
	rdataList := [][]byte{{192, 0, 2, 1}}

	result, err := buildCanonicalRRset(name, rtype, ttl, rdataList)
	if err != nil {
		t.Fatalf("buildCanonicalRRset: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("buildCanonicalRRset should return non-empty bytes")
	}

	// RFC 8976 §3.3.2 layout for one RR:
	//   name(canonical wire) | type(2) | class(2) | ttl(4) | rdlen(2) | rdata
	// For "www.example.com." the canonical name wire form is
	// 3 'w' 'w' 'w' 7 'e' 'x' 'a' 'm' 'p' 'l' 'e' 3 'c' 'o' 'm' 0  → 17 bytes.
	const nameWireLen = 17
	if len(result) != nameWireLen+2+2+4+2+4 {
		t.Fatalf("expected %d bytes, got %d", nameWireLen+2+2+4+2+4, len(result))
	}
	if result[nameWireLen] != 0x00 || result[nameWireLen+1] != 0x01 {
		t.Errorf("type field not encoded correctly: %x %x", result[nameWireLen], result[nameWireLen+1])
	}
	if result[nameWireLen+2] != 0x00 || result[nameWireLen+3] != 0x01 {
		t.Errorf("class field (IN) not encoded correctly: %x %x", result[nameWireLen+2], result[nameWireLen+3])
	}
	// TTL = 3600 = 0x00 0x00 0x0E 0x10
	if result[nameWireLen+4] != 0x00 || result[nameWireLen+7] != 0x10 {
		t.Errorf("TTL field not encoded correctly")
	}
	if result[nameWireLen+8] != 0x00 || result[nameWireLen+9] != 0x04 {
		t.Errorf("rdlength != 4: %x %x", result[nameWireLen+8], result[nameWireLen+9])
	}
}

func TestBuildCanonicalRRsetRejectsOversizedRData(t *testing.T) {
	_, err := buildCanonicalRRset("www.example.com.", 16, 300, [][]byte{make([]byte, 0x10000)})
	if err == nil {
		t.Fatal("expected oversized RDATA to fail")
	}
}

func TestComputeZoneMDRejectsOversizedRData(t *testing.T) {
	z := &Zone{
		Origin: "example.com.",
		SOA: &SOARecord{
			MName: "ns1.example.com.", RName: "hostmaster.example.com.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400,
		},
		Records: map[string][]Record{
			"www.example.com.": {
				{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "TXT", RData: strings.Repeat("a", 0x10000)},
			},
		},
	}

	_, err := ComputeZoneMD(z, ZONEMDSHA256)
	if err == nil {
		t.Fatal("expected ComputeZoneMD to reject oversized RDATA")
	}
	var zmdErr *ZoneMDError
	if !errorAs(err, &zmdErr) {
		t.Fatalf("expected *ZoneMDError, got %T: %v", err, err)
	}
	if !strings.Contains(zmdErr.Msg, "rdata too large") {
		t.Fatalf("unexpected ZoneMDError message: %q", zmdErr.Msg)
	}
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
		{"4294967295", 4294967295, false}, // max uint32
		{"4294967296", 0, true},           // overflow
		{"abc", 0, true},                  // non-numeric
		{"", 0, false},                    // empty returns 0 (loop doesn't execute)
		{"123abc", 0, true},               // mixed
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
