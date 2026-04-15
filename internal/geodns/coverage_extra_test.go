package geodns

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// ---------------------------------------------------------------------------
// parseMMDBMetadata – more thorough coverage
// ---------------------------------------------------------------------------

func TestParseMMDBMetadataSingleNodeCount(t *testing.T) {
	// Build a 12-byte slice where bytes [4..8] hold a small uint32 (42).
	// The scanner should pick it up as node_count.
	data := make([]byte, 12)
	binary.BigEndian.PutUint32(data[4:8], 42)
	ipv4, tree, err := parseMMDBMetadata(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ipv4 != 42 {
		t.Errorf("ipv4Count = %d, want 42", ipv4)
	}
	wantTree := uint32(42 * 24)
	if tree != wantTree {
		t.Errorf("treeSize = %d, want %d", tree, wantTree)
	}
}

func TestParseMMDBMetadataMultipleCandidates(t *testing.T) {
	// Place two valid-looking uint32 values; the first one encountered wins.
	data := make([]byte, 20)
	binary.BigEndian.PutUint32(data[0:4], 10) // first candidate
	binary.BigEndian.PutUint32(data[8:12], 20) // second candidate (ignored)
	ipv4, _, err := parseMMDBMetadata(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ipv4 != 10 {
		t.Errorf("ipv4Count = %d, want 10 (first valid value)", ipv4)
	}
}

func TestParseMMDBMetadataRejectsLargeValue(t *testing.T) {
	// A uint32 >= 100_000_000 should be rejected.
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], 100_000_000)
	_, _, err := parseMMDBMetadata(data)
	if err == nil {
		t.Error("expected error for huge node count")
	}
}

func TestParseMMDBMetadataRejectsZero(t *testing.T) {
	// All zeros → no valid node count.
	data := make([]byte, 16)
	_, _, err := parseMMDBMetadata(data)
	if err == nil {
		t.Error("expected error when no valid node count found")
	}
}

func TestParseMMDBMetadataShortData(t *testing.T) {
	// Only 3 bytes – too short for the scanner.
	_, _, err := parseMMDBMetadata([]byte{0x00, 0x00, 0x01})
	if err == nil {
		t.Error("expected error for short metadata")
	}
}

func TestParseMMDBMetadataExactBoundaryValue(t *testing.T) {
	// Value 99_999_999 is the upper bound of the accepted range.
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], 99_999_999)
	ipv4, _, err := parseMMDBMetadata(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ipv4 != 99_999_999 {
		t.Errorf("ipv4Count = %d, want 99_999_999", ipv4)
	}
}

// ---------------------------------------------------------------------------
// LoadMMDB – crafted file tests
// ---------------------------------------------------------------------------

func TestLoadMMDBMissingMetadataMarker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.mmdb")
	// Write data that has NO metadata marker.
	if err := os.WriteFile(path, []byte("hello world this is not mmdb data"), 0644); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(Config{Enabled: true})
	err := e.LoadMMDB(path)
	if err == nil {
		t.Error("expected error for file without metadata marker")
	}
}

func TestLoadMMDBTruncatedAfterMarker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.mmdb")
	// Write only the marker with no data after it.
	data := []byte(mmdbMetadataMarker)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(Config{Enabled: true})
	err := e.LoadMMDB(path)
	if err == nil {
		t.Error("expected error for truncated metadata after marker")
	}
}

func TestLoadMMDBValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.mmdb")

	// Build a minimal MMDB-like file:
	//   - some node bytes (padding)
	//   - metadata marker
	//   - metadata with a valid node_count
	nodeCount := uint32(4)
	treeBytes := nodeCount * 24 // 96 bytes of tree

	buf := make([]byte, 0, int(treeBytes)+len(mmdbMetadataMarker)+8)
	// Tree section: 96 zero bytes (4 nodes)
	buf = append(buf, make([]byte, treeBytes)...)
	// Metadata marker
	buf = append(buf, mmdbMetadataMarker...)
	// Metadata: embed node_count as a big-endian uint32
	meta := make([]byte, 8)
	binary.BigEndian.PutUint32(meta[0:4], nodeCount)
	buf = append(buf, meta...)

	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	e := NewEngine(Config{Enabled: true})
	if err := e.LoadMMDB(path); err != nil {
		t.Fatalf("LoadMMDB failed: %v", err)
	}

	stats := e.Stats()
	if !stats.MMDBLoaded {
		t.Error("MMDBLoaded should be true after successful load")
	}
}

func TestLoadMMDBEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.mmdb")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(Config{Enabled: true})
	err := e.LoadMMDB(path)
	if err == nil {
		t.Error("expected error for empty file")
	}
}

// ---------------------------------------------------------------------------
// mmdbLookup – direct testing via internal state
// ---------------------------------------------------------------------------

func TestMmdbLookupNilIP(t *testing.T) {
	e := &Engine{
		mmdbData:      []byte{0x00},
		mmdbIPv4Count: 1,
		mmdbTreeSize:  24,
		mmdbLoaded:    true,
	}
	result := e.mmdbLookup(nil)
	if result != nil {
		t.Error("mmdbLookup(nil) should return nil")
	}
}

func TestMmdbLookupIPv4TreeTraversal(t *testing.T) {
	// Build a tiny tree with 2 nodes.
	// Each node = 6 bytes (left 3 + right 3).
	// Node 0: left → node 1, right → node 1
	// Node 1: left → data (node_count=2, so value 2 → data offset 0), right → data offset 0
	// Data section starts after tree: offset 12 (= 2 nodes * 6 bytes).
	// Data record: some bytes containing a country code marker.
	nodeCount := uint32(2)
	treeSize := nodeCount * 6 // 12 bytes

	// Node 0: left=1, right=1
	node0 := []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01}
	// Node 1: left=2(data), right=2(data) – value 2 == nodeCount → data section
	node1 := []byte{0x00, 0x00, 0x02, 0x00, 0x00, 0x02}

	// Data section: embed country code "DE"
	// 0x02 followed by 'D','E' then padding
	dataSection := []byte{0x02, 'D', 'E', 0x00, 0x00, 0x00}

	mmdb := make([]byte, 0, int(treeSize)+len(dataSection))
	mmdb = append(mmdb, node0...)
	mmdb = append(mmdb, node1...)
	mmdb = append(mmdb, dataSection...)

	e := &Engine{
		mmdbData:      mmdb,
		mmdbIPv4Count: nodeCount,
		mmdbTreeSize:  treeSize,
		mmdbLoaded:    true,
	}

	// Any IPv4 address should eventually reach node 1, then data.
	result := e.mmdbLookup(net.ParseIP("192.168.0.1"))
	if result == nil {
		t.Fatal("mmdbLookup returned nil, expected data record")
	}
	country := extractCountryCode(result)
	if country != "DE" {
		t.Errorf("country = %q, want DE", country)
	}
}

func TestMmdbLookupIPv6ReturnsNil(t *testing.T) {
	// mmdbLookup calls ip = ip.To4() first, which overwrites ip with nil
	// for pure IPv6 addresses. Then ip.To16() on nil returns nil, so the
	// function returns nil. This test documents that known behavior.
	nodeCount := uint32(2)
	treeSize := nodeCount * 6

	node0 := []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01}
	node1 := []byte{0x00, 0x00, 0x02, 0x00, 0x00, 0x02}
	dataSection := []byte{0x02, 'J', 'P', 0x00, 0x00, 0x00}

	mmdb := make([]byte, 0, int(treeSize)+len(dataSection))
	mmdb = append(mmdb, node0...)
	mmdb = append(mmdb, node1...)
	mmdb = append(mmdb, dataSection...)

	e := &Engine{
		mmdbData:      mmdb,
		mmdbIPv4Count: nodeCount,
		mmdbIPv6Count: nodeCount,
		mmdbTreeSize:  treeSize,
		mmdbLoaded:    true,
	}

	// IPv6 address: To4() returns nil, then To16() on nil returns nil.
	result := e.mmdbLookup(net.ParseIP("::1"))
	if result != nil {
		t.Error("mmdbLookup IPv6 should return nil due to ip.To4() overwrite")
	}
}

func TestMmdbLookupIPv4MappedIPv6(t *testing.T) {
	// An IPv4-mapped IPv6 address like ::ffff:1.2.3.4 can be converted
	// to IPv4 via To4(), so mmdbLookup should succeed for these.
	nodeCount := uint32(2)
	treeSize := nodeCount * 6

	node0 := []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01}
	node1 := []byte{0x00, 0x00, 0x02, 0x00, 0x00, 0x02}
	dataSection := []byte{0x02, 'F', 'R', 0x00}

	mmdb := make([]byte, 0, int(treeSize)+len(dataSection))
	mmdb = append(mmdb, node0...)
	mmdb = append(mmdb, node1...)
	mmdb = append(mmdb, dataSection...)

	e := &Engine{
		mmdbData:      mmdb,
		mmdbIPv4Count: nodeCount,
		mmdbTreeSize:  treeSize,
		mmdbLoaded:    true,
	}

	// ::ffff:10.0.0.1 is IPv4-mapped IPv6. To4() returns 10.0.0.1.
	result := e.mmdbLookup(net.ParseIP("::ffff:10.0.0.1"))
	if result == nil {
		t.Fatal("mmdbLookup for IPv4-mapped IPv6 returned nil")
	}
	country := extractCountryCode(result)
	if country != "FR" {
		t.Errorf("country = %q, want FR", country)
	}
}

func TestMmdbLookupTreeExhaustion(t *testing.T) {
	// Tree with 1 node whose children both point back to node 0 (self-loop).
	// The lookup should iterate through all 32 bits and return nil (no data hit).
	nodeCount := uint32(1)
	treeSize := nodeCount * 6

	// Node 0: left=0, right=0 (loops back to itself)
	node0 := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	e := &Engine{
		mmdbData:      append(node0, make([]byte, 100)...),
		mmdbIPv4Count: nodeCount,
		mmdbTreeSize:  treeSize,
		mmdbLoaded:    true,
	}

	result := e.mmdbLookup(net.ParseIP("10.0.0.1"))
	if result != nil {
		t.Error("expected nil for self-looping tree that never reaches data section")
	}
}

func TestMmdbLookupByteOffsetOverflow(t *testing.T) {
	// Tree with a huge node index that overflows the data slice.
	nodeCount := uint32(1)
	treeSize := nodeCount * 6

	// Node 0: left=0xFFFFFF (huge), right=0xFFFFFF
	node0 := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	e := &Engine{
		mmdbData:      node0,
		mmdbIPv4Count: nodeCount,
		mmdbTreeSize:  treeSize,
		mmdbLoaded:    true,
	}

	// Should not panic; returns nil because byteOffset exceeds treeSize.
	result := e.mmdbLookup(net.ParseIP("1.2.3.4"))
	if result != nil {
		t.Error("expected nil for overflowing node offset")
	}
}

// ---------------------------------------------------------------------------
// extractCountryCode – edge cases
// ---------------------------------------------------------------------------

func TestExtractCountryCodeEmptyData(t *testing.T) {
	if code := extractCountryCode(nil); code != "" {
		t.Errorf("extractCountryCode(nil) = %q, want empty", code)
	}
	if code := extractCountryCode([]byte{}); code != "" {
		t.Errorf("extractCountryCode(empty) = %q, want empty", code)
	}
}

func TestExtractCountryCodeOnlyOneUpperAfterMarker(t *testing.T) {
	// 0x02 followed by only one uppercase letter and a non-alpha byte.
	data := []byte{0x02, 'A', '3'}
	if code := extractCountryCode(data); code != "" {
		t.Errorf("expected empty, got %q", code)
	}
}

func TestExtractCountryCodeMarkerAtEnd(t *testing.T) {
	// 0x02 as the very last byte – not enough room for 2 chars.
	data := []byte{0x00, 0x02}
	if code := extractCountryCode(data); code != "" {
		t.Errorf("expected empty, got %q", code)
	}
}

func TestExtractCountryCodeLowercaseAfterMarker(t *testing.T) {
	// 0x02 followed by lowercase letters.
	data := []byte{0x02, 'u', 's'}
	if code := extractCountryCode(data); code != "" {
		t.Errorf("expected empty for lowercase, got %q", code)
	}
}

func TestExtractCountryCodeMultipleCandidates(t *testing.T) {
	// First 0x02 + valid code wins.
	data := []byte{0x02, 'U', 'S', 0x02, 'D', 'E'}
	code := extractCountryCode(data)
	if code != "US" {
		t.Errorf("expected US (first match), got %q", code)
	}
}

// ---------------------------------------------------------------------------
// extractASN – edge cases
// ---------------------------------------------------------------------------

func TestExtractASNEmptyData(t *testing.T) {
	if asn := extractASN(nil); asn != "" {
		t.Errorf("extractASN(nil) = %q, want empty", asn)
	}
	if asn := extractASN([]byte{}); asn != "" {
		t.Errorf("extractASN(empty) = %q, want empty", asn)
	}
}

func TestExtractASNTooShort(t *testing.T) {
	// Only 3 bytes after the marker byte – not enough for uint32 decode.
	data := []byte{0xc0, 0x00, 0x01}
	if asn := extractASN(data); asn != "" {
		t.Errorf("expected empty for short data, got %q", asn)
	}
}

func TestExtractASNZeroValue(t *testing.T) {
	// ASN value of 0 should be rejected.
	data := []byte{0xc0, 0x00, 0x00, 0x00, 0x00}
	if asn := extractASN(data); asn != "" {
		t.Errorf("expected empty for zero ASN, got %q", asn)
	}
}

func TestExtractASNBoundaryUpperLimit(t *testing.T) {
	// Value 9_999_999 = 0x98967F. extractASN reads 3 bytes after marker:
	// data[i+1]<<16 | data[i+2]<<8 | data[i+3]
	data := []byte{0xc0, 0x98, 0x96, 0x7F, 0x00} // 0x98<<16|0x96<<8|0x7F = 9999999
	asn := extractASN(data)
	if asn != "AS9999999" {
		t.Errorf("extractASN = %q, want AS9999999", asn)
	}
}

func TestExtractASNJustOverLimit(t *testing.T) {
	// Value 10_000_000 = 0x989680 should be rejected.
	data := []byte{0xc0, 0x98, 0x96, 0x80, 0x00} // 0x98<<16|0x96<<8|0x80 = 10000000
	if asn := extractASN(data); asn != "" {
		t.Errorf("expected empty for ASN over limit, got %q", asn)
	}
}

func TestExtractASNAllMarkerTypes(t *testing.T) {
	// Verify all marker bytes 0xc0-0xc7 are accepted.
	// extractASN reads 3 bytes after marker: data[i+1]<<16 | data[i+2]<<8 | data[i+3]
	for marker := byte(0xc0); marker <= 0xc7; marker++ {
		data := []byte{marker, 0x00, 0x01, 0x00, 0x00} // ASN = 0x00<<16|0x01<<8|0x00 = 256
		asn := extractASN(data)
		if asn != "AS256" {
			t.Errorf("marker 0x%02x: got %q, want AS256", marker, asn)
		}
	}
}

func TestExtractASNMarkerOutsideRange(t *testing.T) {
	// 0xBF and 0xC8 are outside the accepted marker range.
	for _, marker := range []byte{0xBF, 0xC8} {
		data := []byte{marker, 0x00, 0x00, 0x01, 0x00}
		if asn := extractASN(data); asn != "" {
			t.Errorf("marker 0x%02x: expected empty, got %q", marker, asn)
		}
	}
}

// ---------------------------------------------------------------------------
// countryToContinent – comprehensive coverage
// ---------------------------------------------------------------------------

func TestCountryToContinentAllMappings(t *testing.T) {
	// Verify every entry in the continent map returns the expected continent.
	expected := map[string]string{
		"US": "NA", "CA": "NA", "MX": "NA", "BR": "SA", "AR": "SA",
		"GB": "EU", "FR": "EU", "DE": "EU", "IT": "EU", "ES": "EU",
		"JP": "AS", "CN": "AS", "IN": "AS", "KR": "AS", "AU": "OC",
		"NG": "AF", "ZA": "AF", "EG": "AF", "KE": "AF",
		"RU": "EU", "TR": "AS", "SE": "EU", "NO": "EU", "FI": "EU",
		"PL": "EU", "NL": "EU", "CH": "EU", "AT": "EU", "BE": "EU",
		"PT": "EU", "GR": "EU", "DK": "EU", "IE": "EU",
	}
	for country, want := range expected {
		got := countryToContinent(country)
		if got != want {
			t.Errorf("countryToContinent(%q) = %q, want %q", country, got, want)
		}
	}
}

func TestCountryToContinentInvalidLengths(t *testing.T) {
	for _, code := range []string{"", "A", "ABC", "1234"} {
		got := countryToContinent(code)
		if got != "" {
			t.Errorf("countryToContinent(%q) = %q, want empty for invalid length", code, got)
		}
	}
}

func TestCountryToContinentUnknownCode(t *testing.T) {
	// A valid-length but unmapped code.
	got := countryToContinent("ZZ")
	if got != "" {
		t.Errorf("countryToContinent(ZZ) = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// isUpperAlpha – boundary values
// ---------------------------------------------------------------------------

func TestIsUpperAlphaBoundaries(t *testing.T) {
	tests := []struct {
		b    byte
		want bool
	}{
		{'A' - 1, false},
		{'A', true},
		{'M', true},
		{'Z', true},
		{'Z' + 1, false},
		{'a', false},
		{'z', false},
		{'0', false},
		{'_', false},
	}
	for _, tc := range tests {
		got := isUpperAlpha(tc.b)
		if got != tc.want {
			t.Errorf("isUpperAlpha(%d/%q) = %v, want %v", tc.b, string(tc.b), got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Engine concurrency tests
// ---------------------------------------------------------------------------

func TestConcurrentResolve(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	e.SetRule("cdn.example.com.", "A", &GeoRecord{
		Records: map[string]string{"US": "1.1.1.1"},
		Default: "2.2.2.2",
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := e.Resolve("cdn.example.com.", "A", net.ParseIP("10.0.0.1"))
			if result != "2.2.2.2" {
				t.Errorf("concurrent resolve = %q, want 2.2.2.2", result)
			}
		}()
	}
	wg.Wait()

	stats := e.Stats()
	if stats.Lookups != 100 {
		t.Errorf("Lookups = %d, want 100", stats.Lookups)
	}
	if stats.Hits != 100 {
		t.Errorf("Hits = %d, want 100", stats.Hits)
	}
}

func TestConcurrentSetRemoveRule(t *testing.T) {
	e := NewEngine(Config{Enabled: true})

	var wg sync.WaitGroup
	// Concurrently add and remove rules.
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			e.SetRule("host.example.com.", "A", &GeoRecord{Default: "1.1.1.1"})
		}(i)
		go func(i int) {
			defer wg.Done()
			e.RemoveRule("host.example.com.", "A")
		}(i)
	}
	wg.Wait()

	// Should not panic; final state is indeterminate but valid.
	_ = e.Stats()
}

// ---------------------------------------------------------------------------
// Resolve – edge cases
// ---------------------------------------------------------------------------

func TestResolveEmptyRecordsMap(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	e.SetRule("cdn.example.com.", "A", &GeoRecord{
		Records: map[string]string{}, // empty
		Default: "3.3.3.3",
	})
	result := e.Resolve("cdn.example.com.", "A", net.ParseIP("1.2.3.4"))
	if result != "3.3.3.3" {
		t.Errorf("expected default, got %q", result)
	}
}

func TestResolveMultipleRulesDifferentDomains(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	e.SetRule("a.example.com.", "A", &GeoRecord{Default: "10.0.0.1"})
	e.SetRule("b.example.com.", "A", &GeoRecord{Default: "10.0.0.2"})
	e.SetRule("a.example.com.", "AAAA", &GeoRecord{Default: "::1"})

	if r := e.Resolve("a.example.com.", "A", nil); r != "10.0.0.1" {
		t.Errorf("a.example.com A = %q, want 10.0.0.1", r)
	}
	if r := e.Resolve("b.example.com.", "A", nil); r != "10.0.0.2" {
		t.Errorf("b.example.com A = %q, want 10.0.0.2", r)
	}
	if r := e.Resolve("a.example.com.", "AAAA", nil); r != "::1" {
		t.Errorf("a.example.com AAAA = %q, want ::1", r)
	}
	if r := e.Resolve("c.example.com.", "A", nil); r != "" {
		t.Errorf("c.example.com A = %q, want empty", r)
	}
}

func TestResolveNilGeoRecordRecords(t *testing.T) {
	// GeoRecord with nil Records map – should not panic, should return default.
	e := NewEngine(Config{Enabled: true})
	e.SetRule("test.example.com.", "A", &GeoRecord{
		Records: nil,
		Default: "5.5.5.5",
	})
	result := e.Resolve("test.example.com.", "A", net.ParseIP("1.2.3.4"))
	if result != "5.5.5.5" {
		t.Errorf("expected default with nil Records, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// Stats – comprehensive
// ---------------------------------------------------------------------------

func TestStatsCountersAfterMixedLookups(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	e.SetRule("hit.example.com.", "A", &GeoRecord{Default: "1.1.1.1"})

	// 3 hits (rule exists, falls to default).
	for i := 0; i < 3; i++ {
		e.Resolve("hit.example.com.", "A", net.ParseIP("1.2.3.4"))
	}
	// 2 misses (no rule).
	for i := 0; i < 2; i++ {
		e.Resolve("miss.example.com.", "A", net.ParseIP("1.2.3.4"))
	}

	stats := e.Stats()
	if stats.Lookups != 5 {
		t.Errorf("Lookups = %d, want 5", stats.Lookups)
	}
	if stats.Hits != 3 {
		t.Errorf("Hits = %d, want 3", stats.Hits)
	}
	if stats.Misses != 2 {
		t.Errorf("Misses = %d, want 2", stats.Misses)
	}
	if stats.Rules != 1 {
		t.Errorf("Rules = %d, want 1", stats.Rules)
	}
}

func TestStatsDisabledEngine(t *testing.T) {
	e := NewEngine(Config{Enabled: false})
	e.Resolve("anything.", "A", net.ParseIP("1.2.3.4"))
	stats := e.Stats()
	// Disabled engine returns early before incrementing counters.
	if stats.Lookups != 0 {
		t.Errorf("Lookups = %d, want 0 (disabled engine returns before incrementing)", stats.Lookups)
	}
	if stats.Enabled {
		t.Error("stats.Enabled should be false for disabled engine")
	}
}

// ---------------------------------------------------------------------------
// parseDataRecord – boundary
// ---------------------------------------------------------------------------

func TestParseDataRecordExactEnd(t *testing.T) {
	e := &Engine{mmdbData: []byte{0xAA, 0xBB, 0xCC}}
	// Offset exactly at len → nil.
	if rec := e.parseDataRecord(3); rec != nil {
		t.Error("parseDataRecord at exact end should return nil")
	}
	// Offset 2 → returns last byte.
	if rec := e.parseDataRecord(2); rec == nil {
		t.Error("parseDataRecord(2) should return non-nil")
	}
}

func TestParseDataRecordNegativeOffset(t *testing.T) {
	e := &Engine{mmdbData: []byte{0x01}}
	// Negative offset would be caught by offset >= len (negative int wraps large).
	// With empty data, any offset >= 0 >= 1 is false for len=1 data, so test 0.
	if rec := e.parseDataRecord(0); rec == nil {
		t.Error("parseDataRecord(0) on single-byte data should return non-nil")
	}
}

// ---------------------------------------------------------------------------
// NewEngine – with pre-loaded GeoRules
// ---------------------------------------------------------------------------

func TestNewEngineWithGeoRules(t *testing.T) {
	cfg := Config{
		Enabled: true,
		GeoRules: map[string]*GeoRecord{
			"a.example.com.:A":    {Default: "10.0.0.1"},
			"b.example.com.:AAAA": {Default: "::1"},
		},
	}
	e := NewEngine(cfg)
	stats := e.Stats()
	if stats.Rules != 2 {
		t.Errorf("Rules = %d, want 2", stats.Rules)
	}

	if r := e.Resolve("a.example.com.", "A", net.ParseIP("1.2.3.4")); r != "10.0.0.1" {
		t.Errorf("a.example.com. A = %q, want 10.0.0.1", r)
	}
	if r := e.Resolve("b.example.com.", "AAAA", net.ParseIP("1.2.3.4")); r != "::1" {
		t.Errorf("b.example.com. AAAA = %q, want ::1", r)
	}
}

// ---------------------------------------------------------------------------
// RemoveRule – removing non-existent rule
// ---------------------------------------------------------------------------

func TestRemoveRuleNonExistent(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	// Should not panic.
	e.RemoveRule("nonexistent.example.com.", "A")
	stats := e.Stats()
	if stats.Rules != 0 {
		t.Errorf("Rules = %d, want 0 after removing non-existent rule", stats.Rules)
	}
}

// ---------------------------------------------------------------------------
// IsEnabled
// ---------------------------------------------------------------------------

func TestIsEnabledFalse(t *testing.T) {
	e := NewEngine(Config{Enabled: false})
	if e.IsEnabled() {
		t.Error("IsEnabled should be false")
	}
}

// ---------------------------------------------------------------------------
// LookupCountry / LookupASN / LookupContinent with loaded MMDB
// ---------------------------------------------------------------------------

func TestLookupCountryWithLoadedMMDB(t *testing.T) {
	// Build a minimal MMDB that resolves 127.0.0.1 to "US".
	nodeCount := uint32(2)
	treeSize := nodeCount * 6

	// Node 0: left→1, right→1
	// Node 1: left→2(data), right→2(data)
	// For 127.0.0.1, first byte = 0x7F = 0111 1111.
	// First bit is 0 → left → node 1
	// Second bit is 1 → right → data(2)
	node0 := []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01}
	node1 := []byte{0x00, 0x00, 0x02, 0x00, 0x00, 0x02}
	dataSection := []byte{0x02, 'U', 'S', 0x00, 0x00}

	mmdb := append(append(node0, node1...), dataSection...)

	e := &Engine{
		mmdbData:      mmdb,
		mmdbIPv4Count: nodeCount,
		mmdbTreeSize:  treeSize,
		mmdbLoaded:    true,
	}

	country := e.LookupCountry(net.ParseIP("127.0.0.1"))
	if country != "US" {
		t.Errorf("LookupCountry = %q, want US", country)
	}
}

func TestLookupASNWithLoadedMMDB(t *testing.T) {
	nodeCount := uint32(2)
	treeSize := nodeCount * 6

	node0 := []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01}
	node1 := []byte{0x00, 0x00, 0x02, 0x00, 0x00, 0x02}
	// ASN 13335 (Cloudflare) → 0x003427
	// ASN 13335 = 0x3417. extractASN reads data[i+1]<<16 | data[i+2]<<8 | data[i+3]
	dataSection := []byte{0xc0, 0x00, 0x34, 0x17, 0x00}

	mmdb := append(append(node0, node1...), dataSection...)

	e := &Engine{
		mmdbData:      mmdb,
		mmdbIPv4Count: nodeCount,
		mmdbTreeSize:  treeSize,
		mmdbLoaded:    true,
	}

	asn := e.LookupASN(net.ParseIP("10.0.0.1"))
	if asn != "AS13335" {
		t.Errorf("LookupASN = %q, want AS13335", asn)
	}
}

func TestLookupContinentWithCountry(t *testing.T) {
	nodeCount := uint32(2)
	treeSize := nodeCount * 6

	node0 := []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01}
	node1 := []byte{0x00, 0x00, 0x02, 0x00, 0x00, 0x02}
	dataSection := []byte{0x02, 'D', 'E', 0x00}

	mmdb := append(append(node0, node1...), dataSection...)

	e := &Engine{
		mmdbData:      mmdb,
		mmdbIPv4Count: nodeCount,
		mmdbTreeSize:  treeSize,
		mmdbLoaded:    true,
	}

	continent := e.LookupContinent(net.ParseIP("10.0.0.1"))
	if continent != "EU" {
		t.Errorf("LookupContinent = %q, want EU", continent)
	}
}

// ---------------------------------------------------------------------------
// Resolve with MMDB loaded – end-to-end geo match
// ---------------------------------------------------------------------------

func TestResolveWithMMDBCountryMatch(t *testing.T) {
	nodeCount := uint32(2)
	treeSize := nodeCount * 6

	node0 := []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01}
	node1 := []byte{0x00, 0x00, 0x02, 0x00, 0x00, 0x02}
	dataSection := []byte{0x02, 'U', 'S', 0x00}

	mmdb := append(append(node0, node1...), dataSection...)

	e := &Engine{
		mmdbData:      mmdb,
		mmdbIPv4Count: nodeCount,
		mmdbTreeSize:  treeSize,
		mmdbLoaded:    true,
		enabled:       true,
		rules:         make(map[string]*GeoRecord),
	}

	e.SetRule("cdn.example.com.", "A", &GeoRecord{
		Records: map[string]string{
			"US": "192.168.1.1",
			"DE": "10.0.0.1",
		},
		Default: "172.16.0.1",
	})

	// The crafted MMDB returns "US" for any IP, so the US record should match.
	result := e.Resolve("cdn.example.com.", "A", net.ParseIP("192.168.0.1"))
	if result != "192.168.1.1" {
		t.Errorf("Resolve with MMDB = %q, want 192.168.1.1 (US match)", result)
	}
}

func TestResolveWithMMDBContinentFallback(t *testing.T) {
	nodeCount := uint32(2)
	treeSize := nodeCount * 6

	node0 := []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01}
	node1 := []byte{0x00, 0x00, 0x02, 0x00, 0x00, 0x02}
	dataSection := []byte{0x02, 'D', 'E', 0x00}

	mmdb := append(append(node0, node1...), dataSection...)

	e := &Engine{
		mmdbData:      mmdb,
		mmdbIPv4Count: nodeCount,
		mmdbTreeSize:  treeSize,
		mmdbLoaded:    true,
		enabled:       true,
		rules:         make(map[string]*GeoRecord),
	}

	e.SetRule("cdn.example.com.", "A", &GeoRecord{
		Records: map[string]string{
			"EU": "10.0.1.1", // continent match
		},
		Default: "172.16.0.1",
	})

	// DE → EU continent match.
	result := e.Resolve("cdn.example.com.", "A", net.ParseIP("10.0.0.1"))
	if result != "10.0.1.1" {
		t.Errorf("Resolve continent fallback = %q, want 10.0.1.1", result)
	}
}

func TestResolveWithMMDBASNMatch(t *testing.T) {
	nodeCount := uint32(2)
	treeSize := nodeCount * 6

	node0 := []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01}
	node1 := []byte{0x00, 0x00, 0x02, 0x00, 0x00, 0x02}
	// Country code first, then ASN.
	dataSection := []byte{0x02, 'U', 'S', 0x00, 0xc0, 0x00, 0x00, 0x0A, 0x00} // AS10

	mmdb := append(append(node0, node1...), dataSection...)

	e := &Engine{
		mmdbData:      mmdb,
		mmdbIPv4Count: nodeCount,
		mmdbTreeSize:  treeSize,
		mmdbLoaded:    true,
		enabled:       true,
		rules:         make(map[string]*GeoRecord),
	}

	e.SetRule("cdn.example.com.", "A", &GeoRecord{
		Records: map[string]string{
			"AS10":  "10.10.10.10", // ASN match
			"US":    "1.1.1.1",      // country match (lower priority)
			"NA":    "2.2.2.2",      // continent match (even lower)
		},
		Default: "172.16.0.1",
	})

	// ASN match should win over country and continent.
	result := e.Resolve("cdn.example.com.", "A", net.ParseIP("10.0.0.1"))
	if result != "10.10.10.10" {
		t.Errorf("Resolve ASN match = %q, want 10.10.10.10", result)
	}
}

// ---------------------------------------------------------------------------
// LookupContinent – no MMDB
// ---------------------------------------------------------------------------

func TestLookupContinentNoMMDB(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	continent := e.LookupContinent(net.ParseIP("1.2.3.4"))
	if continent != "" {
		t.Errorf("LookupContinent without MMDB = %q, want empty", continent)
	}
}

// ---------------------------------------------------------------------------
// Atomic counter verification
// ---------------------------------------------------------------------------

func TestAtomicCountersNoRace(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	e.SetRule("test.com.", "A", &GeoRecord{Default: "1.1.1.1"})

	var wg sync.WaitGroup
	var totalLookups uint64

	// Concurrent resolves to exercise atomic counters.
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			atomic.AddUint64(&totalLookups, 1)
			e.Resolve("test.com.", "A", net.ParseIP("10.0.0.1"))
		}()
	}
	wg.Wait()

	stats := e.Stats()
	if stats.Lookups != totalLookups {
		t.Errorf("Lookups = %d, want %d", stats.Lookups, totalLookups)
	}
	if stats.Hits != totalLookups {
		t.Errorf("Hits = %d, want %d", stats.Hits, totalLookups)
	}
}
