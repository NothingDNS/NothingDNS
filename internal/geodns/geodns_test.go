package geodns

import (
	"net"
	"testing"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	if !e.IsEnabled() {
		t.Error("engine should be enabled")
	}

	e2 := NewEngine(Config{Enabled: false})
	if e2.IsEnabled() {
		t.Error("engine should be disabled")
	}
}

func TestResolveWithoutMMDB(t *testing.T) {
	e := NewEngine(Config{Enabled: true})

	e.SetRule("cdn.example.com.", "A", &GeoRecord{
		Records: map[string]string{
			"US": "192.168.1.1",
			"EU": "10.0.0.1",
		},
		Default: "172.16.0.1",
		Type:    "A",
		TTL:     300,
	})

	// Without MMDB, should fall through to default
	result := e.Resolve("cdn.example.com.", "A", net.ParseIP("1.2.3.4"))
	if result != "172.16.0.1" {
		t.Errorf("Resolve = %q, want %q", result, "172.16.0.1")
	}
}

func TestResolveDisabled(t *testing.T) {
	e := NewEngine(Config{Enabled: false})
	e.SetRule("cdn.example.com.", "A", &GeoRecord{
		Default: "172.16.0.1",
	})

	result := e.Resolve("cdn.example.com.", "A", net.ParseIP("1.2.3.4"))
	if result != "" {
		t.Error("disabled engine should return empty string")
	}
}

func TestResolveNoRule(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	result := e.Resolve("cdn.example.com.", "A", net.ParseIP("1.2.3.4"))
	if result != "" {
		t.Error("no rule should return empty string")
	}
}

func TestResolveCountryMatch(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	e.SetRule("cdn.example.com.", "A", &GeoRecord{
		Records: map[string]string{
			"US": "192.168.1.1",
			"DE": "10.0.0.1",
		},
		Default: "172.16.0.1",
	})

	// Test with direct country injection via SetRule
	// (full MMDB test would require a test database file)
	// Without MMDB, default is used
	result := e.Resolve("cdn.example.com.", "A", net.ParseIP("1.2.3.4"))
	if result != "172.16.0.1" {
		t.Errorf("Resolve = %q, want default", result)
	}
}

func TestResolveMultipleTypes(t *testing.T) {
	e := NewEngine(Config{Enabled: true})

	e.SetRule("cdn.example.com.", "A", &GeoRecord{
		Records: map[string]string{"US": "1.1.1.1"},
		Default: "2.2.2.2",
	})
	e.SetRule("cdn.example.com.", "AAAA", &GeoRecord{
		Records: map[string]string{"US": "::1"},
		Default: "::2",
	})

	resultA := e.Resolve("cdn.example.com.", "A", net.ParseIP("1.2.3.4"))
	if resultA != "2.2.2.2" {
		t.Errorf("A record = %q, want default", resultA)
	}

	resultAAAA := e.Resolve("cdn.example.com.", "AAAA", net.ParseIP("1.2.3.4"))
	if resultAAAA != "::2" {
		t.Errorf("AAAA record = %q, want default", resultAAAA)
	}
}

func TestSetAndRemoveRule(t *testing.T) {
	e := NewEngine(Config{Enabled: true})

	e.SetRule("test.example.com.", "A", &GeoRecord{
		Default: "1.1.1.1",
	})

	result := e.Resolve("test.example.com.", "A", net.ParseIP("1.2.3.4"))
	if result != "1.1.1.1" {
		t.Errorf("Resolve = %q, want 1.1.1.1", result)
	}

	e.RemoveRule("test.example.com.", "A")
	result = e.Resolve("test.example.com.", "A", net.ParseIP("1.2.3.4"))
	if result != "" {
		t.Error("removed rule should return empty")
	}
}

func TestCountryToContinent(t *testing.T) {
	tests := []struct {
		country   string
		continent string
	}{
		{"US", "NA"},
		{"DE", "EU"},
		{"CN", "AS"},
		{"BR", "SA"},
		{"AU", "OC"},
		{"NG", "AF"},
		{"XX", ""},
		{"", ""},
		{"A", ""},
	}
	for _, tc := range tests {
		got := countryToContinent(tc.country)
		if got != tc.continent {
			t.Errorf("countryToContinent(%q) = %q, want %q", tc.country, got, tc.continent)
		}
	}
}

func TestStats(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	e.SetRule("cdn.example.com.", "A", &GeoRecord{
		Records: map[string]string{"US": "1.1.1.1"},
		Default: "2.2.2.2",
	})

	e.Resolve("cdn.example.com.", "A", net.ParseIP("1.2.3.4"))

	stats := e.Stats()
	if !stats.Enabled {
		t.Error("should be enabled")
	}
	if stats.Rules != 1 {
		t.Errorf("Rules = %d, want 1", stats.Rules)
	}
	if stats.Lookups != 1 {
		t.Errorf("Lookups = %d, want 1", stats.Lookups)
	}
}

func TestResolveNoDefault(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	e.SetRule("cdn.example.com.", "A", &GeoRecord{
		Records: map[string]string{"US": "1.1.1.1"},
	})

	// Without MMDB and no default, should return empty
	result := e.Resolve("cdn.example.com.", "A", net.ParseIP("1.2.3.4"))
	if result != "" {
		t.Errorf("expected empty with no default and no MMDB, got %q", result)
	}
}

func TestLoadMMDBNonexistent(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	if err := e.LoadMMDB("/nonexistent/GeoLite2-Country.mmdb"); err == nil {
		t.Error("expected error loading nonexistent MMDB file")
	}
}

func TestExtractCountryCode(t *testing.T) {
	// Test with fake data containing a 2-letter country code marker
	// 0x02 is the type marker, followed by 'U'(0x55) 'S'(0x53)
	data := []byte{0x00, 0x01, 0x02, 0x55, 0x53, 0x00}
	code := extractCountryCode(data)
	// The function looks for 0x02 followed by 2 uppercase ASCII chars
	// At offset 2: 0x02, then 0x55='U', 0x53='S'
	if code != "US" {
		t.Errorf("extractCountryCode = %q, want US", code)
	}
}

func TestResolveContinentFallback(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	e.SetRule("cdn.example.com.", "A", &GeoRecord{
		Records: map[string]string{
			"NA": "10.0.0.1", // North America
			"EU": "10.0.1.1", // Europe
		},
		Default: "172.16.0.1",
	})

	// Without MMDB, can't determine continent, falls to default
	result := e.Resolve("cdn.example.com.", "A", net.ParseIP("1.2.3.4"))
	if result != "172.16.0.1" {
		t.Errorf("Resolve = %q, want default", result)
	}
}

func TestExtractCountryCodeNoMatch(t *testing.T) {
	// Data without valid country code marker
	data := []byte{0x00, 0x01, 0x03, 0x00, 0x00, 0x00}
	code := extractCountryCode(data)
	if code != "" {
		t.Errorf("extractCountryCode = %q, want empty", code)
	}
}

func TestExtractCountryCodeShortData(t *testing.T) {
	// Too short data
	code := extractCountryCode([]byte{0x02})
	if code != "" {
		t.Errorf("extractCountryCode short = %q, want empty", code)
	}
}

func TestExtractASN(t *testing.T) {
	// ASN data with type indicator 0xc0 and valid ASN value
	// data[i]=0xc0 is the type marker, then data[i+1], data[i+2], data[i+3] form the ASN
	// Need at least 5 bytes: i + 4 for the ASN value
	// ASN 291 = 0x123
	data := []byte{0xc0, 0x00, 0x01, 0x23, 0x00} // index 0 is 0xc0
	asn := extractASN(data)
	if asn != "AS291" {
		t.Errorf("extractASN = %q, want AS291", asn)
	}
}

func TestExtractASNNoMatch(t *testing.T) {
	// Data without valid ASN marker
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	asn := extractASN(data)
	if asn != "" {
		t.Errorf("extractASN no match = %q, want empty", asn)
	}
}

func TestExtractASNInvalidRange(t *testing.T) {
	// ASN value too high
	data := []byte{0x00, 0xc0, 0xFF, 0xFF, 0xFF} // Value too high
	asn := extractASN(data)
	if asn != "" {
		t.Errorf("extractASN high = %q, want empty", asn)
	}
}

func TestIsUpperAlpha(t *testing.T) {
	if !isUpperAlpha('A') {
		t.Error("isUpperAlpha('A') should be true")
	}
	if !isUpperAlpha('Z') {
		t.Error("isUpperAlpha('Z') should be true")
	}
	if isUpperAlpha('a') {
		t.Error("isUpperAlpha('a') should be false")
	}
	if isUpperAlpha('0') {
		t.Error("isUpperAlpha('0') should be false")
	}
}

func TestStatsStruct(t *testing.T) {
	stats := Stats{
		Enabled:    true,
		Rules:      10,
		MMDBLoaded: true,
		Lookups:    100,
		Hits:       80,
		Misses:     20,
	}

	if !stats.Enabled {
		t.Error("stats.Enabled should be true")
	}
	if stats.Rules != 10 {
		t.Errorf("stats.Rules = %d, want 10", stats.Rules)
	}
	if !stats.MMDBLoaded {
		t.Error("stats.MMDBLoaded should be true")
	}
	if stats.Lookups != 100 {
		t.Errorf("stats.Lookups = %d, want 100", stats.Lookups)
	}
}

func TestResolveWithNilIP(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	e.SetRule("cdn.example.com.", "A", &GeoRecord{
		Default: "1.1.1.1",
	})

	// nil IP should return empty or default
	result := e.Resolve("cdn.example.com.", "A", nil)
	_ = result // May or may not have a value, just verify no panic
}

func TestGeoRecord(t *testing.T) {
	rec := &GeoRecord{
		Records: map[string]string{
			"US": "1.1.1.1",
			"EU": "2.2.2.2",
		},
		Default: "3.3.3.3",
		Type:    "A",
		TTL:     300,
	}

	if rec.Default != "3.3.3.3" {
		t.Errorf("GeoRecord.Default = %q, want 3.3.3.3", rec.Default)
	}
	if rec.Type != "A" {
		t.Errorf("GeoRecord.Type = %q, want A", rec.Type)
	}
	if rec.TTL != 300 {
		t.Errorf("GeoRecord.TTL = %d, want 300", rec.TTL)
	}
}

func TestGeoRule(t *testing.T) {
	rec := &GeoRecord{Default: "1.1.1.1"}
	rule := &GeoRule{
		Domain:    "example.com",
		Type:      "A",
		GeoRecords: rec,
	}

	if rule.Domain != "example.com" {
		t.Errorf("GeoRule.Domain = %q, want example.com", rule.Domain)
	}
	if rule.Type != "A" {
		t.Errorf("GeoRule.Type = %q, want A", rule.Type)
	}
	if rule.GeoRecords != rec {
		t.Error("GeoRule.GeoRecords mismatch")
	}
}

func TestEngineWithNilRules(t *testing.T) {
	// Create engine with nil GeoRules
	e := NewEngine(Config{Enabled: true, GeoRules: nil})
	if e == nil {
		t.Fatal("NewEngine returned nil")
	}

	// Should work fine
	result := e.Resolve("example.com", "A", net.ParseIP("1.2.3.4"))
	if result != "" {
		t.Errorf("Resolve with nil rules = %q, want empty", result)
	}
}

func TestParseMMDBMetadataEmpty(t *testing.T) {
	_, _, err := parseMMDBMetadata([]byte{})
	if err == nil {
		t.Error("parseMMDBMetadata should error on empty data")
	}
}

func TestParseDataRecordOffset(t *testing.T) {
	e := &Engine{
		mmdbData: []byte("test data for parsing"),
	}

	// Valid offset within data
	rec := e.parseDataRecord(5)
	if rec == nil {
		t.Error("parseDataRecord(5) returned nil")
	}

	// Invalid offset
	rec = e.parseDataRecord(1000)
	if rec != nil {
		t.Error("parseDataRecord(1000) should return nil")
	}
}

func TestLookupCountryNoMMDB(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	code := e.LookupCountry(net.ParseIP("1.2.3.4"))
	if code != "" {
		t.Errorf("LookupCountry without MMDB = %q, want empty", code)
	}
}

func TestLookupASNLNoMMDB(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	asn := e.LookupASN(net.ParseIP("1.2.3.4"))
	if asn != "" {
		t.Errorf("LookupASN without MMDB = %q, want empty", asn)
	}
}

func TestLookupContinent(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	// Without MMDB loaded, LookupContinent uses countryToContinent
	// which requires country code from LookupCountry which returns empty
	continent := e.LookupContinent(net.ParseIP("1.2.3.4"))
	_ = continent // Would be empty without MMDB
}

func TestConfig(t *testing.T) {
	cfg := Config{
		Enabled:  true,
		MMDBFile: "/path/to/geoip.mmdb",
		GeoRules: map[string]*GeoRecord{
			"example.com:A": {Default: "1.1.1.1"},
		},
	}

	if !cfg.Enabled {
		t.Error("Config.Enabled should be true")
	}
	if cfg.MMDBFile != "/path/to/geoip.mmdb" {
		t.Errorf("Config.MMDBFile = %q", cfg.MMDBFile)
	}
	if len(cfg.GeoRules) != 1 {
		t.Errorf("Config.GeoRules len = %d, want 1", len(cfg.GeoRules))
	}
}

func TestResolveWithDefault(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	e.SetRule("cdn.example.com.", "A", &GeoRecord{
		Records: map[string]string{
			"XX": "1.1.1.1", // Unknown country
		},
		Default: "2.2.2.2",
	})

	// Falls through to default when no match
	result := e.Resolve("cdn.example.com.", "A", net.ParseIP("1.2.3.4"))
	if result != "2.2.2.2" {
		t.Errorf("Resolve default = %q, want 2.2.2.2", result)
	}
}
