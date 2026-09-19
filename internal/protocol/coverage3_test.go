package protocol

// coverage3_test.go adds tests to improve coverage for remaining low-coverage functions.
// Targets:
//   - rdata_text.go: parseSOARData, parseSRVRData, parseCAARData, parseTXTRData,
//     parseHINFORData, parseRPRData, parseAFSDBRData, parseKXRData, parseCERTRData,
//     parseOPENPGPKEYRData, parseAPLRData, parseAPLItem, trimAPLAddress,
//     parseLOCRData + LOC helpers, parseHIPRData, parseIPSECKEYRData, parseURIRData,
//     parseNAPTRRData, parseQuotedRDataFields, parseSSHFPRData, parseTLSARData,
//     parseDHCIDRData, splitCharacterStrings, parseZONEMDRData, parseSVCBRData,
//     parseHTTPSRData, parseSVCBFields, parseSvcParams
//   - labels.go: HasPrefixName, CanonicalWireName, NewUnsafeName
//   - opt.go: NewEDNS0NSID, NewEDNS0NSIDFromBytes, UnpackEDNS0NSID, NewEDNS0Chain,
//     UnpackEDNS0Chain, wireNameToString
//   - record.go: Release method
//   - types_address.go LOC record: Type, Pack, Unpack, String, Len, Copy,
//     formatLOCPosition, formatLOCMeters, locPrecisionToCentimeters
//   - types_svcb.go: formatMandatoryValue, formatALPNValue, packNameUncompressed

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// rdata_text.go - parseSOARData (0%)
// ============================================================================

func TestParseSOARData(t *testing.T) {
	// Valid SOA
	rd := parseSOARData("ns1.example.com. admin.example.com. 2024010101 3600 600 86400 300")
	if rd == nil {
		t.Fatal("parseSOARData returned nil for valid input")
	}
	soa, ok := rd.(*RDataSOA)
	if !ok {
		t.Fatalf("parseSOARData returned %T, want *RDataSOA", rd)
	}
	if soa.MName == nil || soa.MName.String() != "ns1.example.com." {
		t.Errorf("MName = %v, want ns1.example.com.", soa.MName)
	}
	if soa.Serial != 2024010101 {
		t.Errorf("Serial = %d, want 2024010101", soa.Serial)
	}
	if soa.Refresh != 3600 {
		t.Errorf("Refresh = %d, want 3600", soa.Refresh)
	}

	// Too few fields (< 7)
	if rd := parseSOARData("ns1.example.com. admin.example.com."); rd != nil {
		t.Error("parseSOARData should return nil with < 7 fields")
	}

	// Invalid serial (non-numeric)
	if rd := parseSOARData("ns1.example.com. admin.example.com. bad 3600 600 86400 300"); rd != nil {
		t.Error("parseSOARData should return nil with non-numeric serial")
	}

	// Invalid refresh
	if rd := parseSOARData("ns1.example.com. admin.example.com. 1 bad 3 4 5"); rd != nil {
		t.Error("parseSOARData should return nil with non-numeric refresh")
	}

	// Empty string
	if rd := parseSOARData(""); rd != nil {
		t.Error("parseSOARData should return nil with empty string")
	}
}

// ============================================================================
// rdata_text.go - parseSRVRData (0%)
// ============================================================================

func TestParseSRVRData(t *testing.T) {
	rd := parseSRVRData("10 20 443 server.example.com.")
	if rd == nil {
		t.Fatal("parseSRVRData returned nil for valid input")
	}
	srv, ok := rd.(*RDataSRV)
	if !ok {
		t.Fatalf("parseSRVRData returned %T, want *RDataSRV", rd)
	}
	if srv.Priority != 10 || srv.Weight != 20 || srv.Port != 443 {
		t.Errorf("SRV fields mismatch: got %d/%d/%d", srv.Priority, srv.Weight, srv.Port)
	}

	if rd := parseSRVRData("10 20 443"); rd != nil {
		t.Error("parseSRVRData should return nil with < 4 fields")
	}
	if rd := parseSRVRData("bad 20 443 server.example.com."); rd != nil {
		t.Error("parseSRVRData should return nil with non-numeric priority")
	}
}

// ============================================================================
// rdata_text.go - parseCAARData (0%)
// ============================================================================

func TestParseCAARData(t *testing.T) {
	rd := parseCAARData("128 issue letsencrypt.org")
	if rd == nil {
		t.Fatal("parseCAARData returned nil for valid input")
	}
	caa, ok := rd.(*RDataCAA)
	if !ok {
		t.Fatalf("parseCAARData returned %T, want *RDataCAA", rd)
	}
	if caa.Flags != 128 || caa.Tag != "issue" || caa.Value != "letsencrypt.org" {
		t.Errorf("CAA fields mismatch: %d/%q/%q", caa.Flags, caa.Tag, caa.Value)
	}

	if rd := parseCAARData("128 issue"); rd != nil {
		t.Error("parseCAARData should return nil with < 3 fields")
	}
	if rd := parseCAARData("bad tag value"); rd != nil {
		t.Error("parseCAARData should return nil with non-numeric flags")
	}
}

// ============================================================================
// rdata_text.go - parseTXTRData (0%)
// ============================================================================

func TestParseTXTRData(t *testing.T) {
	rd := parseTXTRData("hello world")
	if rd == nil {
		t.Fatal("parseTXTRData returned nil for simple text")
	}
	txt, ok := rd.(*RDataTXT)
	if !ok {
		t.Fatalf("parseTXTRData returned %T, want *RDataTXT", rd)
	}
	if len(txt.Strings) == 0 {
		t.Fatal("TXT.Strings is empty")
	}

	// Quoted text
	rd = parseTXTRData(`"hello" "world"`)
	if rd == nil {
		t.Fatal("parseTXTRData returned nil for quoted text")
	}

	// Unbalanced quotes (should serve verbatim)
	rd = parseTXTRData(`"unbalanced`)
	if rd == nil {
		t.Fatal("parseTXTRData returned nil for unbalanced quotes")
	}
}

// ============================================================================
// rdata_text.go - splitCharacterStrings (0%)
// ============================================================================

func TestSplitCharacterStrings(t *testing.T) {
	result := splitCharacterStrings([]string{""})
	if len(result) != 1 || result[0] != "" {
		t.Errorf("splitCharacterStrings([\"\"]) = %v, want [\"\"]", result)
	}

	longField := strings.Repeat("a", 300)
	result = splitCharacterStrings([]string{longField})
	if len(result) != 2 || len(result[0]) != 255 || len(result[1]) != 45 {
		t.Errorf("splitCharacterStrings(300 chars) = %d strings [%d, %d], want 2 [255, 45]",
			len(result), len(result[0]), len(result[1]))
	}

	result = splitCharacterStrings(nil)
	if len(result) != 1 || result[0] != "" {
		t.Errorf("splitCharacterStrings(nil) = %v, want [\"\"]", result)
	}
}

// ============================================================================
// rdata_text.go - parseHINFORData (0%)
// ============================================================================

func TestParseHINFORData(t *testing.T) {
	rd := parseHINFORData(`"ARM" "Linux"`)
	if rd == nil {
		t.Fatal("parseHINFORData returned nil for valid input")
	}
	hinfo, ok := rd.(*RDataHINFO)
	if !ok {
		t.Fatalf("parseHINFORData returned %T, want *RDataHINFO", rd)
	}
	if hinfo.CPU != "ARM" || hinfo.OS != "Linux" {
		t.Errorf("HINFO fields: %q/%q", hinfo.CPU, hinfo.OS)
	}

	if rd := parseHINFORData("ARM"); rd != nil {
		t.Error("parseHINFORData should return nil with 1 field")
	}
	// HINFO without quotes — accepted as two whitespace-separated fields
	if rd := parseHINFORData("ARM Linux"); rd == nil {
		t.Error("parseHINFORData should accept unquoted two-field input")
	}
}

// ============================================================================
// rdata_text.go - parseRPRData (0%)
// ============================================================================

func TestParseRPRData(t *testing.T) {
	rd := parseRPRData("admin.example.com. contact.example.com.")
	if rd == nil {
		t.Fatal("parseRPRData returned nil for valid input")
	}
	rp, ok := rd.(*RDataRP)
	if !ok {
		t.Fatalf("parseRPRData returned %T, want *RDataRP", rd)
	}
	if rp.MBox == nil || rp.MBox.String() != "admin.example.com." {
		t.Errorf("MBox = %v", rp.MBox)
	}

	if rd := parseRPRData("admin.example.com."); rd != nil {
		t.Error("parseRPRData should return nil with 1 field")
	}
	if rd := parseRPRData("admin.example.com. contact.example.com. extra"); rd != nil {
		t.Error("parseRPRData should return nil with > 2 fields")
	}
	if rd := parseRPRData("invalid..name contact.example.com."); rd != nil {
		t.Error("parseRPRData should return nil with invalid mbox")
	}
}

// ============================================================================
// rdata_text.go - parseAFSDBRData (0%)
// ============================================================================

func TestParseAFSDBRData(t *testing.T) {
	rd := parseAFSDBRData("1 afsdb.example.com.")
	if rd == nil {
		t.Fatal("parseAFSDBRData returned nil for valid input")
	}
	afsdb, ok := rd.(*RDataAFSDB)
	if !ok {
		t.Fatalf("parseAFSDBRData returned %T, want *RDataAFSDB", rd)
	}
	if afsdb.Subtype != 1 {
		t.Errorf("Subtype = %d, want 1", afsdb.Subtype)
	}

	if rd := parseAFSDBRData("1"); rd != nil {
		t.Error("parseAFSDBRData should return nil with 1 field")
	}
	if rd := parseAFSDBRData("bad host.example.com."); rd != nil {
		t.Error("parseAFSDBRData should return nil with non-numeric subtype")
	}
}

// ============================================================================
// rdata_text.go - parseKXRData (0%)
// ============================================================================

func TestParseKXRData(t *testing.T) {
	rd := parseKXRData("10 exchanger.example.com.")
	if rd == nil {
		t.Fatal("parseKXRData returned nil for valid input")
	}
	kx, ok := rd.(*RDataKX)
	if !ok {
		t.Fatalf("parseKXRData returned %T, want *RDataKX", rd)
	}
	if kx.Preference != 10 {
		t.Errorf("Preference = %d, want 10", kx.Preference)
	}

	if rd := parseKXRData("10"); rd != nil {
		t.Error("parseKXRData should return nil with 1 field")
	}
	if rd := parseKXRData("bad exchanger.example.com."); rd != nil {
		t.Error("parseKXRData should return nil with non-numeric preference")
	}
}

// ============================================================================
// rdata_text.go - parseCERTRData (0%)
// ============================================================================

func TestParseCERTRData(t *testing.T) {
	certB64 := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03, 0x04})

	rd := parseCERTRData("5 12345 1 " + certB64)
	if rd == nil {
		t.Fatal("parseCERTRData returned nil for valid input")
	}
	cert, ok := rd.(*RDataCERT)
	if !ok {
		t.Fatalf("parseCERTRData returned %T, want *RDataCERT", rd)
	}
	if cert.CertType != 5 || cert.KeyTag != 12345 || cert.Algorithm != 1 {
		t.Errorf("CERT fields: %d/%d/%d", cert.CertType, cert.KeyTag, cert.Algorithm)
	}

	if rd := parseCERTRData("5 12345"); rd != nil {
		t.Error("parseCERTRData should return nil with < 4 fields")
	}
	if rd := parseCERTRData("bad 12345 1 " + certB64); rd != nil {
		t.Error("parseCERTRData should return nil with non-numeric cert-type")
	}
}

// ============================================================================
// rdata_text.go - parseOPENPGPKEYRData (0%)
// ============================================================================

func TestParseOPENPGPKEYRData(t *testing.T) {
	keyB64 := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03, 0x04, 0x05})

	rd := parseOPENPGPKEYRData(keyB64)
	if rd == nil {
		t.Fatal("parseOPENPGPKEYRData returned nil for valid input")
	}
	_, ok := rd.(*RDataOPENPGPKEY)
	if !ok {
		t.Fatalf("parseOPENPGPKEYRData returned %T, want *RDataOPENPGPKEY", rd)
	}

	if rd := parseOPENPGPKEYRData("not-valid-base64!!!"); rd != nil {
		t.Error("parseOPENPGPKEYRData should return nil with invalid base64")
	}
}

// ============================================================================
// rdata_text.go - parseAPLRData (0%)
// ============================================================================

func TestParseAPLRData(t *testing.T) {
	rd := parseAPLRData("1:192.0.2.0/24")
	if rd == nil {
		t.Fatal("parseAPLRData returned nil for valid IPv4")
	}
	_, ok := rd.(*RDataAPL)
	if !ok {
		t.Fatalf("parseAPLRData returned %T, want *RDataAPL", rd)
	}

	rd = parseAPLRData("2:2001:db8::/32")
	if rd == nil {
		t.Fatal("parseAPLRData returned nil for valid IPv6")
	}

	rd = parseAPLRData("!1:192.0.2.0/24")
	if rd == nil {
		t.Fatal("parseAPLRData returned nil for negated APL")
	}

	if rd := parseAPLRData(""); rd != nil {
		t.Error("parseAPLRData should return nil with empty input")
	}
	if rd := parseAPLRData("not-valid"); rd != nil {
		t.Error("parseAPLRData should return nil with invalid field")
	}
}

// ============================================================================
// rdata_text.go - parseAPLItem (0%)
// ============================================================================

func TestParseAPLItem(t *testing.T) {
	item, ok := parseAPLItem("!1:10.0.0.0/8")
	if !ok || !item.Negation || item.AddressFamily != 1 {
		t.Fatal("parseAPLItem failed for valid negated IPv4")
	}

	item, ok = parseAPLItem("2:2001:db8::/32")
	if !ok || item.Negation || item.AddressFamily != 2 {
		t.Fatal("parseAPLItem failed for valid IPv6")
	}

	_, ok = parseAPLItem("1:10.0.0.0/24/extra")
	if ok {
		t.Error("parseAPLItem should fail with extra content")
	}
	_, ok = parseAPLItem("1:10.0.0.0")
	if ok {
		t.Error("parseAPLItem should fail without prefix")
	}
	_, ok = parseAPLItem("0:10.0.0.0/24")
	if ok {
		t.Error("parseAPLItem should fail with AFI 0")
	}
	_, ok = parseAPLItem("3:10.0.0.0/24")
	if ok {
		t.Error("parseAPLItem should fail with AFI 3")
	}
	_, ok = parseAPLItem("1:10.0.0.0/33")
	if ok {
		t.Error("parseAPLItem should fail with prefix > 32")
	}
	_, ok = parseAPLItem("2:2001:db8::/129")
	if ok {
		t.Error("parseAPLItem should fail with prefix > 128")
	}
	_, ok = parseAPLItem("1:not-an-ip/24")
	if ok {
		t.Error("parseAPLItem should fail with invalid IP")
	}
	_, ok = parseAPLItem("notanumber:10.0.0.0/24")
	if ok {
		t.Error("parseAPLItem should fail with non-numeric AFI")
	}
	_, ok = parseAPLItem("1:10.0.0.0/bad")
	if ok {
		t.Error("parseAPLItem should fail with non-numeric prefix")
	}
}

// ============================================================================
// rdata_text.go - trimAPLAddress (0%)
// ============================================================================

func TestTrimAPLAddress(t *testing.T) {
	if r := trimAPLAddress([]byte{10, 0, 0, 0}); len(r) != 1 || r[0] != 10 {
		t.Errorf("trimAPLAddress([10,0,0,0]) = %v", r)
	}
	if r := trimAPLAddress([]byte{10, 20, 30, 40}); len(r) != 4 {
		t.Errorf("trimAPLAddress([10,20,30,40]) = %v", r)
	}
	if r := trimAPLAddress([]byte{0, 0, 0, 0}); len(r) != 0 {
		t.Errorf("trimAPLAddress([0,0,0,0]) = %v", r)
	}
	if r := trimAPLAddress([]byte{}); len(r) != 0 {
		t.Errorf("trimAPLAddress([]) = %v", r)
	}
}

// ============================================================================
// rdata_text.go - parseLOCRData (0%)
// ============================================================================

func TestParseLOCRData(t *testing.T) {
	rd := parseLOCRData("42 21 54.000 N 71 06 18.000 W -10m 200m 20m 200m")
	if rd == nil {
		t.Fatal("parseLOCRData returned nil for valid LOC")
	}
	loc, ok := rd.(*RDataLOC)
	if !ok {
		t.Fatalf("parseLOCRData returned %T, want *RDataLOC", rd)
	}
	if loc.Version != 0 {
		t.Errorf("Version = %d, want 0", loc.Version)
	}

	rd = parseLOCRData("42 N 71 W 0m")
	if rd == nil {
		t.Fatal("parseLOCRData returned nil for minimal LOC")
	}

	if rd := parseLOCRData("42 N 71 W"); rd != nil {
		t.Error("parseLOCRData should return nil with < 5 fields")
	}
	if rd := parseLOCRData("bad N 71 W 0m"); rd != nil {
		t.Error("parseLOCRData should return nil with invalid latitude")
	}

	rd = parseLOCRData("42 21 54.000 N 71 06 18.000 W -10m")
	if rd == nil {
		t.Fatal("parseLOCRData returned nil for LOC without precision")
	}
}

// ============================================================================
// rdata_text.go - parseLOCCoordinate (0%)
// ============================================================================

func TestParseLOCCoordinate(t *testing.T) {
	// Degrees only
	_, _, ok := parseLOCCoordinate([]string{"42", "N", "71", "W", "0m"}, 0, "N", "S", 90)
	if !ok {
		t.Fatal("parseLOCCoordinate returned !ok for simple case")
	}

	// Degrees and minutes
	_, _, ok = parseLOCCoordinate([]string{"42", "21", "N", "71", "W", "0m"}, 0, "N", "S", 90)
	if !ok {
		t.Fatal("parseLOCCoordinate returned !ok for degrees+minutes")
	}

	// Full DMS
	_, _, ok = parseLOCCoordinate([]string{"42", "21", "54", "N", "71", "W", "0m"}, 0, "N", "S", 90)
	if !ok {
		t.Fatal("parseLOCCoordinate returned !ok for full DMS")
	}

	// Negative hemisphere (South)
	_, _, ok = parseLOCCoordinate([]string{"42", "S", "71", "W", "0m"}, 0, "N", "S", 90)
	if !ok {
		t.Fatal("parseLOCCoordinate returned !ok for South hemisphere")
	}

	// No hemisphere
	_, _, ok = parseLOCCoordinate([]string{"42"}, 0, "N", "S", 90)
	if ok {
		t.Error("parseLOCCoordinate should fail without hemisphere")
	}

	// Degrees > max
	_, _, ok = parseLOCCoordinate([]string{"100", "N", "71", "W", "0m"}, 0, "N", "S", 90)
	if ok {
		t.Error("parseLOCCoordinate should fail with degrees > max")
	}

	// Minutes > 59
	_, _, ok = parseLOCCoordinate([]string{"42", "99", "N", "71", "W", "0m"}, 0, "N", "S", 90)
	if ok {
		t.Error("parseLOCCoordinate should fail with minutes > 59")
	}

	// Seconds >= 60
	_, _, ok = parseLOCCoordinate([]string{"42", "21", "99", "N", "71", "W", "0m"}, 0, "N", "S", 90)
	if ok {
		t.Error("parseLOCCoordinate should fail with seconds >= 60")
	}

	// Max degrees with non-zero minutes
	_, _, ok = parseLOCCoordinate([]string{"90", "1", "N", "71", "W", "0m"}, 0, "N", "S", 90)
	if ok {
		t.Error("parseLOCCoordinate should fail with max degrees and non-zero minutes")
	}
}

// ============================================================================
// rdata_text.go - parseLOCAltitude (0%)
// ============================================================================

func TestParseLOCAltitude(t *testing.T) {
	val, ok := parseLOCAltitude("100m")
	if !ok || val != 10000000+10000 {
		t.Fatalf("parseLOCAltitude(100m) = %d, want %d", val, 10000000+10000)
	}

	_, ok = parseLOCAltitude("-10m")
	if !ok {
		t.Fatal("parseLOCAltitude returned !ok for -10m")
	}

	_, ok = parseLOCAltitude("notanumber")
	if ok {
		t.Error("parseLOCAltitude should fail with non-numeric")
	}
	_, ok = parseLOCAltitude("")
	if ok {
		t.Error("parseLOCAltitude should fail with empty")
	}
}

// ============================================================================
// rdata_text.go - parseLOCPrecision (0%)
// ============================================================================

func TestParseLOCPrecision(t *testing.T) {
	val, ok := parseLOCPrecision("0m")
	if !ok || val != 0 {
		t.Errorf("parseLOCPrecision(0m) = %d, want 0", val)
	}

	_, ok = parseLOCPrecision("-1m")
	if ok {
		t.Error("parseLOCPrecision should fail with negative")
	}
	_, ok = parseLOCPrecision("999999999999999999m")
	if ok {
		t.Error("parseLOCPrecision should fail with very large value")
	}
}

// ============================================================================
// rdata_text.go - parseLOCMeters (0%)
// ============================================================================

func TestParseLOCMeters(t *testing.T) {
	_, ok := parseLOCMeters("100m", false)
	if !ok {
		t.Fatal("parseLOCMeters(100m) returned !ok")
	}

	_, ok = parseLOCMeters("-10m", true)
	if !ok {
		t.Fatal("parseLOCMeters(-10m) returned !ok")
	}
	_, ok = parseLOCMeters("-10m", false)
	if ok {
		t.Error("parseLOCMeters should fail with negative when not allowed")
	}
	_, ok = parseLOCMeters("100", false)
	if !ok {
		t.Fatal("parseLOCMeters(100) should work without m suffix")
	}
	_, ok = parseLOCMeters("", false)
	if ok {
		t.Error("parseLOCMeters should fail with empty string")
	}
	_, ok = parseLOCMeters("m", false)
	if ok {
		t.Error("parseLOCMeters should fail with just m")
	}
	_, ok = parseLOCMeters("badm", false)
	if ok {
		t.Error("parseLOCMeters should fail with non-numeric")
	}
}

// ============================================================================
// rdata_text.go - roundFloatToInt64 (0%)
// ============================================================================

func TestRoundFloatToInt64(t *testing.T) {
	if v := roundFloatToInt64(1.4); v != 1 {
		t.Errorf("roundFloatToInt64(1.4) = %d, want 1", v)
	}
	if v := roundFloatToInt64(1.5); v != 2 {
		t.Errorf("roundFloatToInt64(1.5) = %d, want 2", v)
	}
	if v := roundFloatToInt64(1.6); v != 2 {
		t.Errorf("roundFloatToInt64(1.6) = %d, want 2", v)
	}
	if v := roundFloatToInt64(-1.4); v != -1 {
		t.Errorf("roundFloatToInt64(-1.4) = %d, want -1", v)
	}
	if v := roundFloatToInt64(-1.5); v != -2 {
		t.Errorf("roundFloatToInt64(-1.5) = %d, want -2", v)
	}
}

// ============================================================================
// rdata_text.go - roundDiv10 (0%)
// ============================================================================

func TestRoundDiv10(t *testing.T) {
	if v := roundDiv10(14); v != 1 {
		t.Errorf("roundDiv10(14) = %d, want 1", v)
	}
	if v := roundDiv10(5); v != 1 {
		t.Errorf("roundDiv10(5) = %d, want 1", v)
	}
}

// ============================================================================
// rdata_text.go - parseUintFieldAt (0%)
// ============================================================================

func TestParseUintFieldAt(t *testing.T) {
	val, ok := parseUintFieldAt([]string{"123"}, 0, 16)
	if !ok || val != 123 {
		t.Errorf("parseUintFieldAt = %d, want 123", val)
	}
	_, ok = parseUintFieldAt([]string{}, 0, 16)
	if ok {
		t.Error("parseUintFieldAt should fail with empty fields")
	}
}

// ============================================================================
// rdata_text.go - isLOCHemisphere (0%)
// ============================================================================

func TestIsLOCHemisphere(t *testing.T) {
	if !isLOCHemisphere("N", "N", "S") {
		t.Error("isLOCHemisphere should return true for N")
	}
	if !isLOCHemisphere("n", "N", "S") {
		t.Error("isLOCHemisphere should be case-insensitive")
	}
	if isLOCHemisphere("E", "N", "S") {
		t.Error("isLOCHemisphere should return false for E")
	}
}

// ============================================================================
// rdata_text.go - parseHIPRData (0%)
// ============================================================================

func TestParseHIPRData(t *testing.T) {
	pubB64 := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03, 0x04})

	rd := parseHIPRData("2 aabbccdd " + pubB64)
	if rd == nil {
		t.Fatal("parseHIPRData returned nil for valid input")
	}
	hip, ok := rd.(*RDataHIP)
	if !ok {
		t.Fatalf("parseHIPRData returned %T, want *RDataHIP", rd)
	}
	if hip.PublicKeyAlgorithm != 2 {
		t.Errorf("PublicKeyAlgorithm = %d, want 2", hip.PublicKeyAlgorithm)
	}

	rd = parseHIPRData("2 aabbccdd " + pubB64 + " rvs1.example.com. rvs2.example.com.")
	if rd == nil {
		t.Fatal("parseHIPRData returned nil for HIP with RVS")
	}

	if rd := parseHIPRData("2 aabbccdd"); rd != nil {
		t.Error("parseHIPRData should return nil with < 3 fields")
	}
	if rd := parseHIPRData("bad aabbccdd " + pubB64); rd != nil {
		t.Error("parseHIPRData should return nil with non-numeric algorithm")
	}
	if rd := parseHIPRData("2 badhex!! " + pubB64); rd != nil {
		t.Error("parseHIPRData should return nil with invalid HIT hex")
	}
}

// ============================================================================
// rdata_text.go - parseIPSECKEYRData (0%)
// ============================================================================

func TestParseIPSECKEYRData(t *testing.T) {
	pubB64 := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03, 0x04})

	// Type 0 (no gateway)
	rd := parseIPSECKEYRData("10 0 1 . " + pubB64)
	if rd == nil {
		t.Fatal("parseIPSECKEYRData returned nil for type 0")
	}
	ipseckey, ok := rd.(*RDataIPSECKEY)
	if !ok {
		t.Fatalf("parseIPSECKEYRData returned %T, want *RDataIPSECKEY", rd)
	}
	if ipseckey.Precedence != 10 || ipseckey.GatewayType != 0 {
		t.Errorf("IPSECKEY fields: %d/%d", ipseckey.Precedence, ipseckey.GatewayType)
	}

	// Type 1 (IPv4 gateway)
	rd = parseIPSECKEYRData("10 1 1 192.0.2.1 " + pubB64)
	if rd == nil {
		t.Fatal("parseIPSECKEYRData returned nil for type 1")
	}

	// Type 2 (IPv6 gateway)
	rd = parseIPSECKEYRData("10 2 1 2001:db8::1 " + pubB64)
	if rd == nil {
		t.Fatal("parseIPSECKEYRData returned nil for type 2")
	}

	// Type 3 (domain name gateway)
	rd = parseIPSECKEYRData("10 3 1 gateway.example.com. " + pubB64)
	if rd == nil {
		t.Fatal("parseIPSECKEYRData returned nil for type 3")
	}

	// Too few fields
	if rd := parseIPSECKEYRData("10 0 1"); rd != nil {
		t.Error("parseIPSECKEYRData should return nil with < 5 fields")
	}

	// Type 0 with non-dot gateway
	if rd := parseIPSECKEYRData("10 0 1 gateway.example.com. " + pubB64); rd != nil {
		t.Error("parseIPSECKEYRData type 0 should reject non-dot gateway")
	}

	// Invalid precedence
	if rd := parseIPSECKEYRData("bad 0 1 . " + pubB64); rd != nil {
		t.Error("parseIPSECKEYRData should return nil with non-numeric precedence")
	}

	// Invalid gateway type
	if rd := parseIPSECKEYRData("10 4 1 . " + pubB64); rd != nil {
		t.Error("parseIPSECKEYRData should return nil with invalid gateway type")
	}
}

// ============================================================================
// rdata_text.go - parseURIRData (0%)
// ============================================================================

func TestParseURIRData(t *testing.T) {
	rd := parseURIRData(`10 20 "https://example.com"`)
	if rd == nil {
		t.Fatal("parseURIRData returned nil for valid input")
	}
	uri, ok := rd.(*RDataURI)
	if !ok {
		t.Fatalf("parseURIRData returned %T, want *RDataURI", rd)
	}
	if uri.Priority != 10 || uri.Weight != 20 || uri.Target != "https://example.com" {
		t.Errorf("URI fields: %d/%d/%q", uri.Priority, uri.Weight, uri.Target)
	}

	// Too few fields
	if rd := parseURIRData(`10 "https://example.com"`); rd != nil {
		t.Error("parseURIRData should return nil with < 3 fields")
	}

	// Invalid priority
	if rd := parseURIRData(`bad 20 "https://example.com"`); rd != nil {
		t.Error("parseURIRData should return nil with non-numeric priority")
	}
}

// ============================================================================
// rdata_text.go - parseNAPTRRData (0%)
// ============================================================================

func TestParseNAPTRRData(t *testing.T) {
	rd := parseNAPTRRData(`100 50 "U" "SIP+D2U" "!^.*$!sip:info@example.com!" .`)
	if rd == nil {
		t.Fatal("parseNAPTRRData returned nil for valid input")
	}
	naptr, ok := rd.(*RDataNAPTR)
	if !ok {
		t.Fatalf("parseNAPTRRData returned %T, want *RDataNAPTR", rd)
	}
	if naptr.Order != 100 || naptr.Preference != 50 || naptr.Flags != "U" {
		t.Errorf("NAPTR fields: %d/%d/%q", naptr.Order, naptr.Preference, naptr.Flags)
	}

	// Too few fields
	if rd := parseNAPTRRData(`100 50 "U"`); rd != nil {
		t.Error("parseNAPTRRData should return nil with < 6 fields")
	}

	// Invalid order
	if rd := parseNAPTRRData(`bad 50 "U" "SIP" "regex" .`); rd != nil {
		t.Error("parseNAPTRRData should return nil with non-numeric order")
	}
}

// ============================================================================
// rdata_text.go - parseQuotedRDataFields (0%)
// ============================================================================

func TestParseQuotedRDataFields(t *testing.T) {
	// Simple unquoted
	fields, ok := parseQuotedRDataFields("hello world")
	if !ok || len(fields) != 2 || fields[0] != "hello" || fields[1] != "world" {
		t.Errorf("parseQuotedRDataFields(hello world) = %v, %v", fields, ok)
	}

	// Quoted
	fields, ok = parseQuotedRDataFields(`"hello" "world"`)
	if !ok || len(fields) != 2 || fields[0] != "hello" || fields[1] != "world" {
		t.Errorf("parseQuotedRDataFields quoted = %v, %v", fields, ok)
	}

	// Unbalanced quotes
	_, ok = parseQuotedRDataFields(`"unbalanced`)
	if ok {
		t.Error("parseQuotedRDataFields should fail with unbalanced quotes")
	}

	// Escaped quote inside quoted string
	fields, ok = parseQuotedRDataFields(`"ab\"cd"`)
	if !ok || len(fields) != 1 || fields[0] != `ab"cd` {
		t.Errorf("parseQuotedRDataFields escaped = %v, %v", fields, ok)
	}

	// Trailing backslash inside quotes leaves quotes unclosed
	_, ok = parseQuotedRDataFields(`"test\`)
	if ok {
		t.Error("parseQuotedRDataFields should fail with trailing backslash")
	}

	// Mixed quoted/unquoted
	fields, ok = parseQuotedRDataFields(`hello "world"`)
	if !ok || len(fields) != 2 {
		t.Errorf("parseQuotedRDataFields mixed = %v, %v", fields, ok)
	}

	// Tab separated
	fields, ok = parseQuotedRDataFields("hello\tworld")
	if !ok || len(fields) != 2 {
		t.Errorf("parseQuotedRDataFields tab = %v, %v", fields, ok)
	}

	// Backslash outside quotes — function preserves the backslash literally
	fields, ok = parseQuotedRDataFields(`hello\ world`)
	// The backslash outside quotes acts as an escape, splitting at the space
	if !ok || len(fields) != 2 {
		t.Errorf("parseQuotedRDataFields backslash = %v, %v", fields, ok)
	}
}

// ============================================================================
// rdata_text.go - parseSSHFPRData (0%)
// ============================================================================

func TestParseSSHFPRData(t *testing.T) {
	rd := parseSSHFPRData("2 1 aabbccdd")
	if rd == nil {
		t.Fatal("parseSSHFPRData returned nil for valid input")
	}
	sshfp, ok := rd.(*RDataSSHFP)
	if !ok {
		t.Fatalf("parseSSHFPRData returned %T, want *RDataSSHFP", rd)
	}
	if sshfp.Algorithm != 2 || sshfp.FPType != 1 {
		t.Errorf("SSHFP fields: %d/%d", sshfp.Algorithm, sshfp.FPType)
	}

	if rd := parseSSHFPRData("2 1"); rd != nil {
		t.Error("parseSSHFPRData should return nil with < 3 fields")
	}
	if rd := parseSSHFPRData("bad 1 aabbccdd"); rd != nil {
		t.Error("parseSSHFPRData should return nil with non-numeric algorithm")
	}
	if rd := parseSSHFPRData("2 bad aabbccdd"); rd != nil {
		t.Error("parseSSHFPRData should return nil with non-numeric fp type")
	}
	if rd := parseSSHFPRData("2 1 invalidhex"); rd != nil {
		t.Error("parseSSHFPRData should return nil with invalid hex")
	}
}

// ============================================================================
// rdata_text.go - parseTLSARData (0%)
// ============================================================================

func TestParseTLSARData(t *testing.T) {
	rd := parseTLSARData("3 1 1 aabbccdd")
	if rd == nil {
		t.Fatal("parseTLSARData returned nil for valid input")
	}
	tlsa, ok := rd.(*RDataTLSA)
	if !ok {
		t.Fatalf("parseTLSARData returned %T, want *RDataTLSA", rd)
	}
	if tlsa.Usage != 3 || tlsa.Selector != 1 || tlsa.MatchingType != 1 {
		t.Errorf("TLSA fields: %d/%d/%d", tlsa.Usage, tlsa.Selector, tlsa.MatchingType)
	}

	if rd := parseTLSARData("3 1 1"); rd != nil {
		t.Error("parseTLSARData should return nil with < 4 fields")
	}
	if rd := parseTLSARData("bad 1 1 aabbccdd"); rd != nil {
		t.Error("parseTLSARData should return nil with non-numeric usage")
	}
}

// ============================================================================
// rdata_text.go - parseDHCIDRData (0%)
// ============================================================================

func TestParseDHCIDRData(t *testing.T) {
	dataB64 := base64.StdEncoding.EncodeToString([]byte{0xAA, 0xBB, 0xCC})

	rd := parseDHCIDRData(dataB64)
	if rd == nil {
		t.Fatal("parseDHCIDRData returned nil for valid input")
	}
	_, ok := rd.(*RDataDHCID)
	if !ok {
		t.Fatalf("parseDHCIDRData returned %T, want *RDataDHCID", rd)
	}

	if rd := parseDHCIDRData("not-valid-b64!!!"); rd != nil {
		t.Error("parseDHCIDRData should return nil with invalid base64")
	}
}

// ============================================================================
// rdata_text.go - parseZONEMDRData (0%)
// ============================================================================

func TestParseZONEMDRData(t *testing.T) {
	rd := parseZONEMDRData("2024010101 1 2 aabbccdd")
	if rd == nil {
		t.Fatal("parseZONEMDRData returned nil for valid input")
	}
	zonemd, ok := rd.(*RDataZONEMD)
	if !ok {
		t.Fatalf("parseZONEMDRData returned %T, want *RDataZONEMD", rd)
	}
	if zonemd.Serial != 2024010101 || zonemd.Scheme != 1 || zonemd.Algorithm != 2 {
		t.Errorf("ZONEMD fields: %d/%d/%d", zonemd.Serial, zonemd.Scheme, zonemd.Algorithm)
	}

	if rd := parseZONEMDRData("2024010101 1"); rd != nil {
		t.Error("parseZONEMDRData should return nil with < 4 fields")
	}
	if rd := parseZONEMDRData("bad 1 2 aabbccdd"); rd != nil {
		t.Error("parseZONEMDRData should return nil with non-numeric serial")
	}
}

// ============================================================================
// rdata_text.go - parseSVCBRData (0%)
// ============================================================================

func TestParseSVCBRData(t *testing.T) {
	rd := parseSVCBRData("1 svc.example.com. alpn=h2 port=443")
	if rd == nil {
		t.Fatal("parseSVCBRData returned nil for valid input")
	}
	svcb, ok := rd.(*RDataSVCB)
	if !ok {
		t.Fatalf("parseSVCBRData returned %T, want *RDataSVCB", rd)
	}
	if svcb.Priority != 1 {
		t.Errorf("Priority = %d, want 1", svcb.Priority)
	}

	// Alias mode (priority=0) with params should return nil
	if rd := parseSVCBRData("0 svc.example.com. alpn=h2"); rd != nil {
		t.Error("parseSVCBRData should return nil for alias mode with params")
	}

	// Invalid priority
	if rd := parseSVCBRData("bad svc.example.com."); rd != nil {
		t.Error("parseSVCBRData should return nil with non-numeric priority")
	}
}

// ============================================================================
// rdata_text.go - parseHTTPSRData (0%)
// ============================================================================

func TestParseHTTPSRData(t *testing.T) {
	rd := parseHTTPSRData("1 svc.example.com. alpn=h2")
	if rd == nil {
		t.Fatal("parseHTTPSRData returned nil for valid input")
	}
	_, ok := rd.(*RDataHTTPS)
	if !ok {
		t.Fatalf("parseHTTPSRData returned %T, want *RDataHTTPS", rd)
	}

	// Too few fields
	if rd := parseHTTPSRData("1"); rd != nil {
		t.Error("parseHTTPSRData should return nil with < 2 fields")
	}
}

// ============================================================================
// rdata_text.go - parseSVCBFields (0%)
// ============================================================================

func TestParseSVCBFields(t *testing.T) {
	// Valid
	_, _, _, ok := parseSVCBFields("1 svc.example.com. alpn=h2")
	if !ok {
		t.Fatal("parseSVCBFields returned !ok for valid input")
	}

	// Too few fields
	_, _, _, ok = parseSVCBFields("1")
	if ok {
		t.Error("parseSVCBFields should fail with < 2 fields")
	}

	// Invalid priority
	_, _, _, ok = parseSVCBFields("bad svc.example.com.")
	if ok {
		t.Error("parseSVCBFields should fail with non-numeric priority")
	}

	// Invalid param
	_, _, _, ok = parseSVCBFields("1 svc.example.com. =bad")
	if ok {
		t.Error("parseSVCBFields should fail with invalid param")
	}
}

// ============================================================================
// rdata_text.go - parseSvcParams (0%)
// ============================================================================

func TestParseSvcParams(t *testing.T) {
	// Empty
	params, ok := parseSvcParams(nil)
	if !ok || len(params) != 0 {
		t.Errorf("parseSvcParams(nil) = %v, %v", params, ok)
	}

	// Valid params
	params, ok = parseSvcParams([]string{"alpn=h2", "port=443"})
	if !ok || len(params) != 2 {
		t.Errorf("parseSvcParams = %v, %v", params, ok)
	}

	// Invalid param
	_, ok = parseSvcParams([]string{"=bad"})
	if ok {
		t.Error("parseSvcParams should fail with invalid param")
	}
}

// ============================================================================
// rdata_text.go - RDataPacksText (0%)
// ============================================================================

func TestRDataPacksText(t *testing.T) {
	if RDataPacksText(nil) {
		t.Error("RDataPacksText(nil) should return false")
	}

	// Valid RData
	soa := parseSOARData("ns1.example.com. admin.example.com. 1 3600 600 86400 300")
	if !RDataPacksText(soa) {
		t.Error("RDataPacksText should return true for valid SOA")
	}
}

// ============================================================================
// labels.go - HasPrefixName (0%)
// ============================================================================

func TestHasPrefixName(t *testing.T) {
	n, _ := ParseName("www.example.com.")

	// Nil prefix
	if !n.HasPrefixName(nil) {
		t.Error("HasPrefixName with nil prefix should return true")
	}

	// Matching prefix
	prefix, _ := ParseName("www.example.")
	if !n.HasPrefixName(prefix) {
		t.Error("HasPrefixName should return true for matching prefix")
	}

	// Non-matching prefix
	prefix2, _ := ParseName("mail.")
	if n.HasPrefixName(prefix2) {
		t.Error("HasPrefixName should return false for non-matching prefix")
	}
}

// ============================================================================
// labels.go - CanonicalWireName (0%)
// ============================================================================

func TestCanonicalWireName(t *testing.T) {
	// Simple name
	wire := CanonicalWireName("Example.Com")
	// Wire should be lowercase
	name, _, err := UnpackName(wire, 0)
	if err != nil {
		t.Fatalf("UnpackName of CanonicalWireName result failed: %v", err)
	}
	if name.String() != "example.com." {
		t.Errorf("CanonicalWireName(Example.Com) = %q, want example.com.", name.String())
	}

	// Root
	wire = CanonicalWireName(".")
	if len(wire) != 1 || wire[0] != 0 {
		t.Errorf("CanonicalWireName(.) = %v, want [0]", wire)
	}

	// Empty
	wire = CanonicalWireName("")
	if len(wire) != 1 || wire[0] != 0 {
		t.Errorf("CanonicalWireName('') = %v, want [0]", wire)
	}

	// With whitespace
	wire = CanonicalWireName("  Example.Com  ")
	name, _, err = UnpackName(wire, 0)
	if err != nil {
		t.Fatalf("UnpackName failed: %v", err)
	}
	if name.String() != "example.com." {
		t.Errorf("CanonicalWireName with whitespace = %q", name.String())
	}

	// Trailing dot
	wire = CanonicalWireName("Example.Com.")
	name, _, _ = UnpackName(wire, 0)
	if name.String() != "example.com." {
		t.Errorf("CanonicalWireName with trailing dot = %q", name.String())
	}

	// Multiple labels
	wire = CanonicalWireName("WWW.EXAMPLE.COM")
	name, _, _ = UnpackName(wire, 0)
	if name.String() != "www.example.com." {
		t.Errorf("CanonicalWireName(WWW.EXAMPLE.COM) = %q", name.String())
	}
}

// ============================================================================
// labels.go - NewUnsafeName (0%)
// ============================================================================

func TestNewUnsafeName(t *testing.T) {
	name := NewUnsafeName([]string{"test", "example", "com"}, true)
	if name == nil {
		t.Fatal("NewUnsafeName returned nil")
	}
	if name.String() != "test.example.com." {
		t.Errorf("NewUnsafeName = %q, want test.example.com.", name.String())
	}

	// Without FQDN
	name = NewUnsafeName([]string{"test"}, false)
	if name == nil {
		t.Fatal("NewUnsafeName returned nil")
	}
}

// ============================================================================
// opt.go - NewEDNS0NSID / NewEDNS0NSIDFromBytes / UnpackEDNS0NSID (0%)
// ============================================================================

func TestEDNS0NSID(t *testing.T) {
	// NewEDNS0NSID
	nsid := NewEDNS0NSID("ns1.example.com")
	if nsid == nil {
		t.Fatal("NewEDNS0NSID returned nil")
	}
	if string(nsid.NSID) != "ns1.example.com" {
		t.Errorf("NSID = %q, want ns1.example.com", string(nsid.NSID))
	}

	// NewEDNS0NSIDFromBytes
	nsid2 := NewEDNS0NSIDFromBytes([]byte{0x01, 0x02, 0x03})
	if nsid2 == nil {
		t.Fatal("NewEDNS0NSIDFromBytes returned nil")
	}
	if !bytes.Equal(nsid2.NSID, []byte{0x01, 0x02, 0x03}) {
		t.Errorf("NSID bytes = %v", nsid2.NSID)
	}

	// UnpackEDNS0NSID
	nsid3, err := UnpackEDNS0NSID([]byte{0xAA, 0xBB})
	if err != nil {
		t.Fatalf("UnpackEDNS0NSID error: %v", err)
	}
	if !bytes.Equal(nsid3.NSID, []byte{0xAA, 0xBB}) {
		t.Errorf("UnpackEDNS0NSID = %v", nsid3.NSID)
	}

	// ToEDNS0Option
	opt := nsid.ToEDNS0Option()
	if opt.Code != OptionCodeNSID {
		t.Errorf("Option code = %d, want %d", opt.Code, OptionCodeNSID)
	}
	if !bytes.Equal(opt.Data, []byte("ns1.example.com")) {
		t.Errorf("Option data = %v", opt.Data)
	}

	// Pack
	if p := nsid.Pack(); !bytes.Equal(p, []byte("ns1.example.com")) {
		t.Errorf("Pack = %v", p)
	}

	// String
	if s := nsid.String(); s != "ns1.example.com" {
		t.Errorf("String = %q", s)
	}

	// Nil methods
	var nilNSID *EDNS0NSID
	if nilNSID.Pack() != nil {
		t.Error("nil NSID Pack should return nil")
	}
	if nilNSID.String() != "" {
		t.Error("nil NSID String should return empty")
	}
	if nilNSID.ToEDNS0Option().Code != OptionCodeNSID {
		t.Error("nil NSID ToEDNS0Option should produce an option")
	}
}

// ============================================================================
// opt.go - NewEDNS0Chain / UnpackEDNS0Chain / wireNameToString (0%)
// ============================================================================

func TestEDNS0Chain(t *testing.T) {
	// NewEDNS0Chain
	chain := NewEDNS0Chain([]string{"ns1.example.com", "ns2.example.com"})
	if chain == nil {
		t.Fatal("NewEDNS0Chain returned nil")
	}
	if len(chain.ChainNS) != 2 {
		t.Errorf("ChainNS length = %d, want 2", len(chain.ChainNS))
	}

	// Pack
	packed := chain.Pack()
	if len(packed) == 0 {
		t.Error("Pack returned empty")
	}

	// UnpackEDNS0Chain
	unpacked, err := UnpackEDNS0Chain(packed)
	if err != nil {
		t.Fatalf("UnpackEDNS0Chain error: %v", err)
	}
	if len(unpacked.ChainNS) != 2 {
		t.Errorf("Unpacked ChainNS = %v", unpacked.ChainNS)
	}

	// ToEDNS0Option
	opt := chain.ToEDNS0Option()
	if opt.Code != OptionCodeChain {
		t.Errorf("Option code = %d, want %d", opt.Code, OptionCodeChain)
	}

	// String
	s := chain.String()
	if !strings.Contains(s, "ns1.example.com") {
		t.Errorf("String = %q", s)
	}

	// Nil chain
	var nilChain *EDNS0Chain
	if nilChain.Pack() != nil {
		t.Error("nil Chain Pack should return nil")
	}
	if nilChain.String() != "" {
		t.Error("nil Chain String should return empty")
	}
	if nilChain.ToEDNS0Option().Code != OptionCodeChain {
		t.Error("nil Chain ToEDNS0Option should produce an option")
	}

	// Empty data
	_, err = UnpackEDNS0Chain(nil)
	if err == nil {
		t.Error("UnpackEDNS0Chain should fail with nil data")
	}
	_, err = UnpackEDNS0Chain([]byte{})
	if err == nil {
		t.Error("UnpackEDNS0Chain should fail with empty data")
	}
}

// ============================================================================
// opt.go - wireNameToString (0%)
// ============================================================================

func TestWireNameToString(t *testing.T) {
	// Simple name
	wire := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm'}
	s := wireNameToString(wire)
	if s != "www.example.com." {
		t.Errorf("wireNameToString = %q, want www.example.com.", s)
	}

	// Single label
	s = wireNameToString([]byte{3, 'c', 'o', 'm'})
	if s != "com." {
		t.Errorf("wireNameToString single = %q, want com.", s)
	}

	// Empty
	s = wireNameToString(nil)
	if s != "" {
		t.Errorf("wireNameToString(nil) = %q, want empty", s)
	}

	s = wireNameToString([]byte{})
	if s != "" {
		t.Errorf("wireNameToString([]) = %q, want empty", s)
	}

	// Truncated data (partial label)
	s = wireNameToString([]byte{3, 'w', 'w'}) // length says 3 but only 2 bytes
	if s != "." {
		t.Errorf("wireNameToString truncated = %q, want .", s)
	}
}

// ============================================================================
// record.go - Release method (0%)
// ============================================================================

func TestResourceRecordRelease(t *testing.T) {
	name, _ := ParseName("example.com.")
	rr := &ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{192, 168, 1, 1}},
	}

	// Release should not panic
	rr.Release()
	// Calling Release twice should not panic either
	rr.Release()
}

func TestNameRelease(t *testing.T) {
	name, _ := ParseName("example.com.")
	name.Release()

	// Nil release should not panic
	var nilName *Name
	nilName.Release()
}

// ============================================================================
// types_address.go - LOC record methods (0%)
// ============================================================================

func TestRDataLOCType(t *testing.T) {
	loc := &RDataLOC{}
	if loc.Type() != TypeLOC {
		t.Errorf("Type() = %d, want %d", loc.Type(), TypeLOC)
	}
}

func TestRDataLOCPackUnpackRoundTrip(t *testing.T) {
	original := &RDataLOC{
		Version:        0,
		Size:           0x12,
		HorizPrecision: 0x16,
		VertPrecision:  0x13,
		Latitude:       2147483648 + 42165400, // 42°21'54"N
		Longitude:      2147483648 - 71061800, // 71°06'18"W
		Altitude:       10000100,              // 100m + 10000000
	}

	buf := make([]byte, original.Len())
	n, err := original.Pack(buf, 0)
	if err != nil {
		t.Fatalf("LOC.Pack error: %v", err)
	}
	if n != original.Len() {
		t.Errorf("Packed = %d, want %d", n, original.Len())
	}

	unpacked := &RDataLOC{}
	n2, err := unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("LOC.Unpack error: %v", err)
	}
	if n2 != n {
		t.Errorf("Unpacked = %d, want %d", n2, n)
	}

	if unpacked.Version != original.Version {
		t.Errorf("Version = %d, want %d", unpacked.Version, original.Version)
	}
	if unpacked.Size != original.Size {
		t.Errorf("Size = %d, want %d", unpacked.Size, original.Size)
	}
	if unpacked.Latitude != original.Latitude {
		t.Errorf("Latitude = %d, want %d", unpacked.Latitude, original.Latitude)
	}
}

func TestRDataLOCPackTooSmall(t *testing.T) {
	loc := &RDataLOC{
		Version: 0,
		Size:    1, HorizPrecision: 2, VertPrecision: 3,
		Latitude: 1 << 31, Longitude: 1 << 31, Altitude: 10000100,
	}

	// Each of these should fail
	_, err := loc.Pack(make([]byte, 0), 0)
	if err == nil {
		t.Error("LOC.Pack should fail with empty buf")
	}

	_, err = loc.Pack(make([]byte, 3), 0)
	if err == nil {
		t.Error("LOC.Pack should fail with buf size 3")
	}
}

func TestRDataLOCUnpackTruncated(t *testing.T) {
	loc := &RDataLOC{}
	// Need at least 16 bytes
	_, err := loc.Unpack([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, 0, 15)
	if err == nil {
		t.Error("LOC.Unpack should fail with < 16 bytes")
	}
}

func TestRDataLOCString(t *testing.T) {
	loc := &RDataLOC{
		Version:        0,
		Size:           0x12,
		HorizPrecision: 0x16,
		VertPrecision:  0x13,
		Latitude:       2147483648 + 42165400,
		Longitude:      2147483648 - 71061800,
		Altitude:       10000100,
	}
	s := loc.String()
	if s == "" {
		t.Error("LOC.String() returned empty")
	}

	// Nil
	var nilLoc *RDataLOC
	if nilLoc.String() != "" {
		t.Error("nil LOC.String() should return empty")
	}
}

func TestRDataLOCCopy(t *testing.T) {
	original := &RDataLOC{
		Version:        0,
		Size:           1,
		HorizPrecision: 2,
		VertPrecision:  3,
		Latitude:       100,
		Longitude:      200,
		Altitude:       300,
	}
	copied := original.Copy().(*RDataLOC)
	if copied.Version != original.Version ||
		copied.Size != original.Size ||
		copied.Latitude != original.Latitude {
		t.Error("Copy mismatch")
	}

	// Nil copy
	var nilLoc *RDataLOC
	if nilLoc.Copy() != nil {
		t.Error("nil LOC.Copy() should return nil")
	}
}

func TestRDataLOCLen(t *testing.T) {
	loc := &RDataLOC{Version: 0, Size: 1, HorizPrecision: 2, VertPrecision: 3, Latitude: 1, Longitude: 2, Altitude: 3}
	if l := loc.Len(); l != 16 {
		t.Errorf("Len() = %d, want 16", l)
	}

	var nilLoc *RDataLOC
	if nilLoc.Len() != 0 {
		t.Error("nil LOC.Len() should return 0")
	}
}

// ============================================================================
// types_address.go - formatLOCPosition (0%)
// ============================================================================

func TestFormatLOCPosition(t *testing.T) {
	// This function formats a millisecond offset from the equator (base 2^31)
	// into "degrees minutes seconds" format

	// Positive latitude (north): 1° = 3600000 ms
	s := formatLOCPosition(3600000) // 1°N
	if !strings.Contains(s, "1 0 0") {
		t.Errorf("formatLOCPosition(1°) = %q, want containing 1 0 0", s)
	}

	// Multiple degrees
	s = formatLOCPosition(7200000) // 2°N
	if !strings.Contains(s, "2 0 0") {
		t.Errorf("formatLOCPosition(2°) = %q, want containing 2 0 0", s)
	}

	// Degrees and minutes
	s = formatLOCPosition(3660000) // 1°1'0"
	if !strings.Contains(s, "1 1 0") {
		t.Errorf("formatLOCPosition(1°1') = %q, want containing 1 1 0", s)
	}

	// Full DMS
	s = formatLOCPosition(3725500) // 1°2'5.5"
	if !strings.Contains(s, "1 2 5.500") {
		t.Errorf("formatLOCPosition(DMS) = %q, want containing 1 2 5.500", s)
	}

	// Zero (equator)
	s = formatLOCPosition(0)
	if s != "0 0 0" {
		t.Errorf("formatLOCPosition(equator) = %q, want 0 0 0", s)
	}

	// Integer seconds (no milliseconds)
	s = formatLOCPosition(3660000) // 1°1'0" with 0 remaining ms
	if !strings.Contains(s, "1 1 0") {
		t.Errorf("formatLOCPosition(1°1') = %q", s)
	}
}

// ============================================================================
// types_address.go - formatLOCMeters (0%)
// ============================================================================

func TestFormatLOCMeters(t *testing.T) {
	// Positive
	s := formatLOCMeters(10000) // 100m
	if s != "100.00m" && s != "100m" {
		t.Logf("formatLOCMeters(10000) = %q", s)
	}

	// Zero
	s = formatLOCMeters(0)
	if s == "" {
		t.Error("formatLOCMeters(0) should not be empty")
	}
}

// ============================================================================
// types_svcb.go - formatMandatoryValue (85.7% -> 100%)
// ============================================================================

func TestFormatMandatoryValue(t *testing.T) {
	// Single key
	s := formatMandatoryValue([]byte{0x00, 0x01})
	if s != "alpn" {
		t.Errorf("formatMandatoryValue([0,1]) = %q, want alpn", s)
	}

	// Multiple keys
	s = formatMandatoryValue([]byte{0x00, 0x01, 0x00, 0x03})
	if s != "alpn,port" {
		t.Errorf("formatMandatoryValue([0,1,0,3]) = %q, want alpn,port", s)
	}

	// Unknown key
	s = formatMandatoryValue([]byte{0xFF, 0xFF})
	if s != "key65535" {
		t.Errorf("formatMandatoryValue([255,255]) = %q, want key65535", s)
	}

	// Odd length
	s = formatMandatoryValue([]byte{0x00})
	if s != "" {
		t.Errorf("formatMandatoryValue([0]) = %q, want empty", s)
	}
}

// ============================================================================
// types_svcb.go - formatALPNValue (83.3% -> 100%)
// ============================================================================

func TestFormatALPNValue(t *testing.T) {
	// Single protocol — strconv.Quote wraps result in quotes
	s := formatALPNValue([]byte{2, 'h', '2'})
	if s != `"h2"` {
		t.Errorf("formatALPNValue([2, h2]) = %q, want \"h2\"", s)
	}

	// Multiple protocols
	s = formatALPNValue([]byte{2, 'h', '2', 2, 'h', '3'})
	if s != `"h2,h3"` {
		t.Errorf("formatALPNValue([2,h2,2,h3]) = %q, want \"h2,h3\"", s)
	}

	// Empty
	s = formatALPNValue(nil)
	if s != `""` {
		t.Errorf("formatALPNValue(nil) = %q, want empty quoted", s)
	}

	// Zero-length protocol
	s = formatALPNValue([]byte{0x00})
	if s != `""` {
		t.Errorf("formatALPNValue([0]) = %q, want empty quoted", s)
	}

	// Truncated protocol
	s = formatALPNValue([]byte{0x03, 'h', '2'})
	if s != `""` {
		t.Errorf("formatALPNValue([3, h2]) = %q, want empty quoted", s)
	}
}

// ============================================================================
// types_svcb.go - packNameUncompressed (83.3% -> 100%)
// ============================================================================

func TestPackNameUncompressed(t *testing.T) {
	name, _ := ParseName("example.com.")
	buf := make([]byte, 256)
	n, err := packNameUncompressed(name, buf, 0)
	if err != nil {
		t.Fatalf("packNameUncompressed error: %v", err)
	}
	if n != name.WireLength() {
		t.Errorf("packed = %d, want %d", n, name.WireLength())
	}

	// Nil name
	n, err = packNameUncompressed(nil, buf, 0)
	if err != nil {
		t.Fatalf("packNameUncompressed nil error: %v", err)
	}
	if n != 1 {
		t.Errorf("packNameUncompressed nil = %d, want 1", n)
	}

	// Buffer too small
	_, err = packNameUncompressed(name, make([]byte, 1), 0)
	if err == nil {
		t.Error("packNameUncompressed should fail with tiny buffer")
	}
}

// ============================================================================
// RDataOPT methods - nil receiver edge cases (edge case coverage)
// ============================================================================

func TestRDataOPTNilReceiver(t *testing.T) {
	var nilOpt *RDataOPT

	if nilOpt.Type() != TypeOPT {
		t.Errorf("nil OPT Type = %d, want %d", nilOpt.Type(), TypeOPT)
	}
	if nilOpt.Len() != 0 {
		t.Errorf("nil OPT Len() = %d, want 0", nilOpt.Len())
	}
	if nilOpt.String() != "" {
		t.Errorf("nil OPT String = %q, want empty", nilOpt.String())
	}
	if nilOpt.Copy() != nil {
		t.Error("nil OPT Copy should return nil")
	}

	// AddOption/GetOption/RemoveOption should not panic
	nilOpt.AddOption(1, []byte{})
	if nilOpt.GetOption(1) != nil {
		t.Error("nil OPT GetOption should return nil")
	}
	nilOpt.RemoveOption(1)
}

// ============================================================================
// EDNS0ClientSubnet nil receiver methods (0% coverage)
// ============================================================================

func TestEDNS0ClientSubnetNilReceiver(t *testing.T) {
	var nilECS *EDNS0ClientSubnet

	if nilECS.Pack() != nil {
		t.Error("nil ECS Pack should return nil")
	}
	if nilECS.String() != "" {
		t.Error("nil ECS String should return empty")
	}
	if nilECS.IP() != nil {
		t.Error("nil ECS IP should return nil")
	}
}

// ============================================================================
// EDNS0ExtendedError nil receiver and edge cases (0% coverage)
// ============================================================================

func TestEDNS0ExtendedErrorUnpackNil(t *testing.T) {
	_, err := UnpackEDNS0ExtendedError([]byte{0})
	if err == nil {
		t.Error("UnpackEDNS0ExtendedError should fail with < 2 bytes")
	}
}

func TestEDNS0ExtendedErrorPackNil(t *testing.T) {
	var nilEEE *EDNS0ExtendedError
	if nilEEE.Pack() != nil {
		t.Error("nil ExtendedError Pack should return nil")
	}
}

func TestEDNS0ExtendedErrorStringNil(t *testing.T) {
	var nilEEE *EDNS0ExtendedError
	if nilEEE.String() != "" {
		t.Error("nil ExtendedError String should return empty")
	}
}

// ============================================================================
// EDNS0Header - ParseEDNS0Header with nil (0% coverage)
// ============================================================================

func TestParseEDNS0HeaderNil(t *testing.T) {
	if ParseEDNS0Header(nil) != nil {
		t.Error("ParseEDNS0Header(nil) should return nil")
	}

	// Non-OPT record
	rr := &ResourceRecord{Type: TypeA}
	if ParseEDNS0Header(rr) != nil {
		t.Error("ParseEDNS0Header with TypeA should return nil")
	}
}

// ============================================================================
// ResourceRecord - Cover nil receiver edge cases
// ============================================================================

func TestResourceRecordNilReceiver(t *testing.T) {
	var nilRR *ResourceRecord

	// WireLength on nil
	if nilRR.WireLength() != 0 {
		t.Errorf("nil RR WireLength = %d, want 0", nilRR.WireLength())
	}

	// Pack on nil
	_, err := nilRR.Pack(nil, 0, nil)
	if err == nil {
		t.Error("nil RR Pack should return error")
	}

	// String on nil
	if nilRR.String() != "<nil resource record>" {
		t.Errorf("nil RR String = %q", nilRR.String())
	}

	// Copy on nil
	if nilRR.Copy() != nil {
		t.Error("nil RR Copy should return nil")
	}

	// IsExpired on nil
	if !nilRR.IsExpired(time.Now()) {
		t.Error("nil RR IsExpired should return true")
	}

	// RemainingTTL on nil
	if nilRR.RemainingTTL(time.Now()) != 0 {
		t.Error("nil RR RemainingTTL should return 0")
	}
}

// The CAA value's quotes are presentation syntax: `0 issue "letsencrypt.org"`
// must put letsencrypt.org on the wire, not "letsencrypt.org" with quotes.
func TestParseCAARData_QuotedValue(t *testing.T) {
	tests := []struct{ in, want string }{
		{`0 issue "letsencrypt.org"`, "letsencrypt.org"},
		{`0 issue letsencrypt.org`, "letsencrypt.org"},
		{`0 issue "ca.example.net; account=230123"`, "ca.example.net; account=230123"},
		{`0 iodef "mailto:security@example.com"`, "mailto:security@example.com"},
		{`0 issue ";"`, ";"},
	}
	for _, tt := range tests {
		rd, ok := parseCAARData(tt.in).(*RDataCAA)
		if !ok {
			t.Fatalf("parseCAARData(%q) = nil", tt.in)
		}
		if rd.Value != tt.want {
			t.Errorf("parseCAARData(%q).Value = %q, want %q", tt.in, rd.Value, tt.want)
		}
		if got := rd.String(); got != `0 `+rd.Tag+` "`+tt.want+`"` {
			t.Errorf("String() = %q", got)
		}
	}
	if parseCAARData(`0 issue "unterminated`) != nil {
		t.Error("unbalanced quotes must be rejected")
	}
}
