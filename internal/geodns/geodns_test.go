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
