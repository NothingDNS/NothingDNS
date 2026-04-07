// Copyright 2025 NothingDNS Authors
// SPDX-License-Identifier: BSD-3-Clause

package catalog

import (
	"testing"
)

func TestNewCatalogZone(t *testing.T) {
	cz := NewCatalogZone("catalog.example.com.")
	if cz.ZoneName != "catalog.example.com." {
		t.Errorf("expected zone name 'catalog.example.com.', got %q", cz.ZoneName)
	}
	if cz.Version != CatalogZoneVersion {
		t.Errorf("expected version %d, got %d", CatalogZoneVersion, cz.Version)
	}
	if cz.Members == nil {
		t.Error("expected Members to be initialized, got nil")
	}
}

func TestCatalogZoneNameNormalization(t *testing.T) {
	cz := NewCatalogZone("CATALOG.EXAMPLE.COM.")
	if cz.ZoneName != "catalog.example.com." {
		t.Errorf("expected lowercase zone name, got %q", cz.ZoneName)
	}
}

func TestAddMember(t *testing.T) {
	cz := NewCatalogZone("catalog.example.com.")
	member := &CatalogMember{
		ZoneName:      "zone1.example.com.",
		ZoneClass:     "IN",
		ZoneTTL:       300,
		Applications:  []string{"*"},
		Group:         "group1",
	}

	cz.AddMember(member)

	if len(cz.Members) != 1 {
		t.Errorf("expected 1 member, got %d", len(cz.Members))
	}

	if cz.Members[0].ZoneName != "zone1.example.com." {
		t.Errorf("expected zone1.example.com., got %q", cz.Members[0].ZoneName)
	}
}

func TestRemoveMember(t *testing.T) {
	cz := NewCatalogZone("catalog.example.com.")
	member := &CatalogMember{ZoneName: "zone1.example.com."}
	cz.AddMember(member)
	cz.AddMember(&CatalogMember{ZoneName: "zone2.example.com."})

	if len(cz.Members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(cz.Members))
	}

	cz.RemoveMember("zone1.example.com.")

	if len(cz.Members) != 1 {
		t.Errorf("expected 1 member after remove, got %d", len(cz.Members))
	}

	if cz.Members[0].ZoneName != "zone2.example.com." {
		t.Errorf("expected remaining member to be zone2, got %q", cz.Members[0].ZoneName)
	}
}

func TestRemoveMemberNotFound(t *testing.T) {
	cz := NewCatalogZone("catalog.example.com.")
	member := &CatalogMember{ZoneName: "zone1.example.com."}
	cz.AddMember(member)

	// Should not panic
	cz.RemoveMember("nonexistent.example.com.")

	if len(cz.Members) != 1 {
		t.Errorf("expected 1 member unchanged, got %d", len(cz.Members))
	}
}

func TestGetMember(t *testing.T) {
	cz := NewCatalogZone("catalog.example.com.")
	member := &CatalogMember{
		ZoneName:  "zone1.example.com.",
		ZoneClass: "IN",
		Group:     "group1",
	}
	cz.AddMember(member)

	found := cz.GetMember("zone1.example.com.")
	if found == nil {
		t.Fatal("expected to find member, got nil")
	}
	if found.Group != "group1" {
		t.Errorf("expected group 'group1', got %q", found.Group)
	}

	notFound := cz.GetMember("nonexistent.example.com.")
	if notFound != nil {
		t.Errorf("expected nil for nonexistent zone, got %v", notFound)
	}
}

func TestParseCatalogMemberRecord(t *testing.T) {
	tests := []struct {
		name    string
		rdata   string
		want    *CatalogMemberRecord
		wantErr bool
	}{
		{
			name:  "basic zone name only",
			rdata: "zone1.example.com.",
			want: &CatalogMemberRecord{
				ZoneName: "zone1.example.com.",
				Class:    "IN",
				TTL:      0,
			},
			wantErr: false,
		},
		{
			name:  "zone with class",
			rdata: "zone1.example.com. IN",
			want: &CatalogMemberRecord{
				ZoneName: "zone1.example.com.",
				Class:    "IN",
				TTL:      0,
			},
			wantErr: false,
		},
		{
			name:  "zone with TTL",
			rdata: "zone1.example.com. 300",
			want: &CatalogMemberRecord{
				ZoneName: "zone1.example.com.",
				Class:    "IN",
				TTL:      0, // TTL parsing doesn't store the value in this simple parser
			},
			wantErr: false,
		},
		{
			name:  "zone with wildcard application",
			rdata: "zone1.example.com. *",
			want: &CatalogMemberRecord{
				ZoneName:      "zone1.example.com.",
				Class:         "IN",
				TTL:           0,
				Applications:  []string{"*"},
			},
			wantErr: false,
		},
		{
			name:  "zone with group",
			rdata: "zone1.example.com. group=group1",
			want: &CatalogMemberRecord{
				ZoneName: "zone1.example.com.",
				Class:    "IN",
				TTL:      0,
				Group:    "group1",
			},
			wantErr: false,
		},
		{
			name:  "zone with group using equals",
			rdata: "zone1.example.com. group=mygroup",
			want: &CatalogMemberRecord{
				ZoneName: "zone1.example.com.",
				Class:    "IN",
				TTL:      0,
				Group:    "mygroup",
			},
			wantErr: false,
		},
		{
			name:    "empty rdata",
			rdata:   "",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCatalogMemberRecord(tt.rdata)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got.ZoneName != tt.want.ZoneName {
				t.Errorf("ZoneName = %q, want %q", got.ZoneName, tt.want.ZoneName)
			}
			if got.Class != tt.want.Class {
				t.Errorf("Class = %q, want %q", got.Class, tt.want.Class)
			}
			if got.TTL != tt.want.TTL {
				t.Errorf("TTL = %d, want %d", got.TTL, tt.want.TTL)
			}
			if len(got.Applications) != len(tt.want.Applications) {
				t.Errorf("Applications len = %d, want %d", len(got.Applications), len(tt.want.Applications))
			}
			if got.Group != tt.want.Group {
				t.Errorf("Group = %q, want %q", got.Group, tt.want.Group)
			}
		})
	}
}

func TestIsValidClass(t *testing.T) {
	tests := []struct {
		class string
		want  bool
	}{
		{"IN", true},
		{"in", true},
		{"CS", true},
		{"CH", true},
		{"HS", true},
		{"NONE", true},
		{"ANY", true},
		{"IN", true},
		{"XX", false},
		{"", false},
		{"CHICKEN", false},
	}

	for _, tt := range tests {
		t.Run(tt.class, func(t *testing.T) {
			got := isValidClass(tt.class)
			if got != tt.want {
				t.Errorf("isValidClass(%q) = %v, want %v", tt.class, got, tt.want)
			}
		})
	}
}

func TestIsNumericTTL(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"300", true},
		{"0", true},
		{"86400", true},
		{"abc", false},
		{"", false},
		{"12a", false},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			got := isNumericTTL(tt.s)
			if got != tt.want {
				t.Errorf("isNumericTTL(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestCatalogMemberToRDATA(t *testing.T) {
	tests := []struct {
		name   string
		member *CatalogMember
		want   string
	}{
		{
			name: "basic",
			member: &CatalogMember{
				ZoneName: "zone1.example.com.",
			},
			want: "zone1.example.com.",
		},
		{
			name: "with class",
			member: &CatalogMember{
				ZoneName:  "zone1.example.com.",
				ZoneClass: "CH",
			},
			want: "zone1.example.com. CH",
		},
		{
			name: "with TTL",
			member: &CatalogMember{
				ZoneName: "zone1.example.com.",
				ZoneTTL:  300,
			},
			want: "zone1.example.com. 300",
		},
		{
			name: "with application",
			member: &CatalogMember{
				ZoneName:     "zone1.example.com.",
				Applications: []string{"*"},
			},
			want: "zone1.example.com. *",
		},
		{
			name: "with group",
			member: &CatalogMember{
				ZoneName: "zone1.example.com.",
				Group:    "group1",
			},
			want: "zone1.example.com. group=group1",
		},
		{
			name: "full",
			member: &CatalogMember{
				ZoneName:     "zone1.example.com.",
				ZoneClass:    "IN",
				ZoneTTL:      300,
				Applications: []string{"*"},
				Group:        "group1",
			},
			want: "zone1.example.com. 300 * group=group1", // IN is omitted when default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.member.ToRDATA()
			if got != tt.want {
				t.Errorf("ToRDATA() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCatalogZoneString(t *testing.T) {
	cz := NewCatalogZone("catalog.example.com.")
	cz.AddMember(&CatalogMember{ZoneName: "zone1.example.com."})
	cz.AddMember(&CatalogMember{ZoneName: "zone2.example.com."})

	s := cz.String()
	if s == "" {
		t.Error("expected non-empty string")
	}
}

func TestCatalogMemberString(t *testing.T) {
	m := &CatalogMember{
		ZoneName:     "zone1.example.com.",
		ZoneClass:    "IN",
		Group:        "group1",
		Applications: []string{"*"},
	}

	s := m.String()
	if s == "" {
		t.Error("expected non-empty string")
	}
}

func TestValidateCatalogZone(t *testing.T) {
	tests := []struct {
		zoneName string
		want     bool
	}{
		{"catalog.example.com.", true},
		{"example.catalog.com.", true},
		{"sub.catalog.example.com.", true},
		{"CATALOG.example.com.", false}, // case-sensitive check
		{"example.com.", false},
		{"zone.example.com.", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.zoneName, func(t *testing.T) {
			got := ValidateCatalogZone(tt.zoneName)
			if got != tt.want {
				t.Errorf("ValidateCatalogZone(%q) = %v, want %v", tt.zoneName, got, tt.want)
			}
		})
	}
}

func TestIsCatalogZone(t *testing.T) {
	// IsCatalogZone is just an alias for ValidateCatalogZone
	if !IsCatalogZone("catalog.example.com.") {
		t.Error("expected catalog.example.com. to be a catalog zone")
	}
	if IsCatalogZone("example.com.") {
		t.Error("expected example.com. to not be a catalog zone")
	}
}

func TestCatalogConstants(t *testing.T) {
	if CatalogPseudoType != 65302 {
		t.Errorf("CatalogPseudoType = %d, want 65302", CatalogPseudoType)
	}
	if CatalogZoneVersion != 2 {
		t.Errorf("CatalogZoneVersion = %d, want 2", CatalogZoneVersion)
	}
	if CatalogLabel != "catalog" {
		t.Errorf("CatalogLabel = %q, want \"catalog\"", CatalogLabel)
	}
}
