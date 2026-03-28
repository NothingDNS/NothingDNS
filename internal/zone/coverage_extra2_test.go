package zone

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

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
