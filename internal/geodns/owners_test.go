package geodns

import (
	"slices"
	"testing"
)

func TestEngineOwnersAndNames(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	v0 := e.Version()
	e.SetRule("Geo.Example.com.", "A", &GeoRecord{Default: "192.0.2.1"})
	e.SetRule("geo.example.com", "AAAA", &GeoRecord{Default: "2001:db8::1"})
	if e.Version() == v0 {
		t.Fatal("Version did not change on SetRule")
	}
	types := e.Owners()["geo.example.com"]
	slices.Sort(types)
	if !slices.Equal(types, []string{"A", "AAAA"}) {
		t.Fatalf("Owners = %v", e.Owners())
	}
	for name, want := range map[string]bool{
		"geo.example.com.": true, "example.com.": true, "com": true,
		"other.example.com.": false, "x.geo.example.com.": false,
	} {
		if got := e.HasNameAtOrBelow(name); got != want {
			t.Errorf("HasNameAtOrBelow(%q) = %v, want %v", name, got, want)
		}
	}
	v1 := e.Version()
	e.RemoveRule("geo.example.com.", "A")
	if e.Version() == v1 {
		t.Fatal("Version did not change on RemoveRule")
	}

	off := NewEngine(Config{Enabled: false})
	off.SetRule("geo.example.com.", "A", &GeoRecord{Default: "192.0.2.1"})
	if off.HasNameAtOrBelow("geo.example.com.") || off.Owners() != nil {
		t.Fatal("a disabled engine answers for no name")
	}
}
