package filter

import (
	"net"
	"testing"
)

func TestNewSplitHorizon_Basic(t *testing.T) {
	sh, err := NewSplitHorizon([]ViewConfig{
		{
			Name:         "internal",
			MatchClients: []string{"10.0.0.0/8", "192.168.0.0/16"},
			ZoneFiles:    []string{"zones/internal.zone"},
		},
		{
			Name:         "external",
			MatchClients: []string{"any"},
			ZoneFiles:    []string{"zones/external.zone"},
		},
	})
	if err != nil {
		t.Fatalf("NewSplitHorizon: %v", err)
	}

	names := sh.ViewNames()
	if len(names) != 2 {
		t.Fatalf("got %d views, want 2", len(names))
	}
	if names[0] != "internal" || names[1] != "external" {
		t.Errorf("names = %v, want [internal external]", names)
	}
}

func TestSelectView_InternalClient(t *testing.T) {
	sh, err := NewSplitHorizon([]ViewConfig{
		{
			Name:         "internal",
			MatchClients: []string{"10.0.0.0/8", "192.168.0.0/16"},
		},
		{
			Name:         "external",
			MatchClients: []string{"any"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		ip   string
		want string
	}{
		{"10.0.0.1", "internal"},
		{"10.255.255.255", "internal"},
		{"192.168.1.100", "internal"},
		{"8.8.8.8", "external"},
		{"1.1.1.1", "external"},
		{"172.16.0.1", "external"}, // not in internal CIDRs
	}

	for _, tt := range tests {
		v := sh.SelectView(net.ParseIP(tt.ip))
		if v == nil {
			t.Errorf("SelectView(%s) = nil, want %s", tt.ip, tt.want)
			continue
		}
		if v.Name != tt.want {
			t.Errorf("SelectView(%s) = %s, want %s", tt.ip, v.Name, tt.want)
		}
	}
}

func TestSelectView_IPv6(t *testing.T) {
	sh, err := NewSplitHorizon([]ViewConfig{
		{
			Name:         "ipv6-internal",
			MatchClients: []string{"fd00::/8"},
		},
		{
			Name:         "default",
			MatchClients: []string{"any"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	v := sh.SelectView(net.ParseIP("fd00::1"))
	if v == nil || v.Name != "ipv6-internal" {
		t.Errorf("fd00::1 should match ipv6-internal, got %v", v)
	}

	v = sh.SelectView(net.ParseIP("2001:db8::1"))
	if v == nil || v.Name != "default" {
		t.Errorf("2001:db8::1 should match default, got %v", v)
	}
}

func TestSelectView_NoMatch(t *testing.T) {
	sh, err := NewSplitHorizon([]ViewConfig{
		{
			Name:         "restricted",
			MatchClients: []string{"10.0.0.0/24"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	v := sh.SelectView(net.ParseIP("192.168.1.1"))
	if v != nil {
		t.Errorf("expected nil for non-matching IP, got %s", v.Name)
	}
}

func TestSelectView_NilIP(t *testing.T) {
	sh, err := NewSplitHorizon([]ViewConfig{
		{Name: "default", MatchClients: []string{"any"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	v := sh.SelectView(nil)
	if v != nil {
		t.Error("expected nil for nil IP")
	}
}

func TestSelectView_FirstMatchWins(t *testing.T) {
	sh, err := NewSplitHorizon([]ViewConfig{
		{
			Name:         "narrow",
			MatchClients: []string{"10.0.0.0/24"},
		},
		{
			Name:         "broad",
			MatchClients: []string{"10.0.0.0/8"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	v := sh.SelectView(net.ParseIP("10.0.0.50"))
	if v == nil || v.Name != "narrow" {
		t.Errorf("expected narrow (first match), got %v", v)
	}

	v = sh.SelectView(net.ParseIP("10.1.0.1"))
	if v == nil || v.Name != "broad" {
		t.Errorf("expected broad for 10.1.0.1, got %v", v)
	}
}

func TestNewSplitHorizon_BareIP(t *testing.T) {
	sh, err := NewSplitHorizon([]ViewConfig{
		{
			Name:         "single",
			MatchClients: []string{"10.0.0.1"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	v := sh.SelectView(net.ParseIP("10.0.0.1"))
	if v == nil || v.Name != "single" {
		t.Errorf("bare IP should match, got %v", v)
	}

	v = sh.SelectView(net.ParseIP("10.0.0.2"))
	if v != nil {
		t.Errorf("bare IP should not match different IP, got %s", v.Name)
	}
}

func TestNewSplitHorizon_InvalidCIDR(t *testing.T) {
	_, err := NewSplitHorizon([]ViewConfig{
		{
			Name:         "bad",
			MatchClients: []string{"not-a-cidr"},
		},
	})
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestNewSplitHorizon_InvalidCIDRFormat(t *testing.T) {
	_, err := NewSplitHorizon([]ViewConfig{
		{
			Name:         "bad",
			MatchClients: []string{"999.999.999.999/8"},
		},
	})
	if err == nil {
		t.Error("expected error for invalid CIDR format")
	}
}

func TestNewSplitHorizon_Empty(t *testing.T) {
	sh, err := NewSplitHorizon(nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := sh.SelectView(net.ParseIP("1.2.3.4")); v != nil {
		t.Error("expected nil for empty views")
	}
}

func TestViewZoneFiles(t *testing.T) {
	sh, err := NewSplitHorizon([]ViewConfig{
		{
			Name:         "internal",
			MatchClients: []string{"10.0.0.0/8"},
			ZoneFiles:    []string{"zones/internal/example.com.zone", "zones/internal/corp.zone"},
		},
		{
			Name:         "external",
			MatchClients: []string{"any"},
			ZoneFiles:    []string{"zones/external/example.com.zone"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	v := sh.SelectView(net.ParseIP("10.0.0.1"))
	if v == nil {
		t.Fatal("expected internal view")
	}
	if len(v.ZoneFiles) != 2 {
		t.Errorf("internal view zone files = %d, want 2", len(v.ZoneFiles))
	}

	v = sh.SelectView(net.ParseIP("8.8.8.8"))
	if v == nil {
		t.Fatal("expected external view")
	}
	if len(v.ZoneFiles) != 1 {
		t.Errorf("external view zone files = %d, want 1", len(v.ZoneFiles))
	}
}

func TestViews_ReturnsCopy(t *testing.T) {
	sh, err := NewSplitHorizon([]ViewConfig{
		{Name: "a", MatchClients: []string{"any"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	views := sh.Views()
	views[0] = nil // mutate the copy
	// Original should be intact
	if sh.Views()[0] == nil {
		t.Error("Views() should return a copy, not a reference")
	}
}

func TestSelectView_BareIPv6(t *testing.T) {
	sh, err := NewSplitHorizon([]ViewConfig{
		{
			Name:         "single6",
			MatchClients: []string{"::1"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	v := sh.SelectView(net.ParseIP("::1"))
	if v == nil || v.Name != "single6" {
		t.Errorf("bare IPv6 should match, got %v", v)
	}
}
