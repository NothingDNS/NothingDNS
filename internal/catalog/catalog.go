// Package catalog implements DNS Catalog Zones as specified in RFC 9432.
// Catalog Zones provide a mechanism for distributing zone configuration
// across a set of DNS servers in a standardized way.
package catalog

import (
	"fmt"
	"strings"
)

// Catalog Zone constants
const (
	// CatalogPseudoType is the pseudo TYPE value for catalog zones (65302).
	CatalogPseudoType = 65302

	// CatalogZoneVersion is the version of the catalog zone format.
	CatalogZoneVersion = 2

	// Well-known label for catalog zones
	CatalogLabel = "catalog"
)

// CatalogZone represents a catalog zone with its members.
type CatalogZone struct {
	// ZoneName is the name of the catalog zone (e.g., "catalog.example.com.")
	ZoneName string

	// Version is the catalog format version
	Version uint32

	// Members is a list of zone members in the catalog
	Members []*CatalogMember
}

// CatalogMember represents a zone member in the catalog.
type CatalogMember struct {
	// ZoneName is the name of the member zone
	ZoneName string

	// ZoneClass is the class of the zone (usually "IN")
	ZoneClass string

	// ZoneTTL is the TTL for the member record
	ZoneTTL uint32

	// Applications is a list of application identifiers that should serve this zone
	Applications []string

	// Group is an optional group identifier for the member
	Group string
}

// NewCatalogZone creates a new catalog zone with the given name.
func NewCatalogZone(name string) *CatalogZone {
	return &CatalogZone{
		ZoneName: strings.ToLower(name),
		Version:  CatalogZoneVersion,
		Members:  make([]*CatalogMember, 0),
	}
}

// AddMember adds a zone member to the catalog.
func (cz *CatalogZone) AddMember(member *CatalogMember) {
	cz.Members = append(cz.Members, member)
}

// RemoveMember removes a zone member by name.
func (cz *CatalogZone) RemoveMember(zoneName string) {
	for i, m := range cz.Members {
		if m.ZoneName == zoneName {
			cz.Members = append(cz.Members[:i], cz.Members[i+1:]...)
			return
		}
	}
}

// GetMember returns a member by zone name.
func (cz *CatalogZone) GetMember(zoneName string) *CatalogMember {
	for _, m := range cz.Members {
		if m.ZoneName == zoneName {
			return m
		}
	}
	return nil
}

// CatalogMemberRecord represents a catalog member MRT (Member Record Type) RRset.
type CatalogMemberRecord struct {
	// ZoneName is the name of the member zone
	ZoneName string

	// Class is the DNS class (default "IN")
	Class string

	// TTL is the TTL for the record
	TTL uint32

	// Applications lists the application identifiers
	Applications []string

	// Group is an optional group label
	Group string
}

// ParseCatalogMemberRecord parses a catalog member record from its RDATA.
// Format: zone-name [class] [ttl] [*] [group "group-name"]
func ParseCatalogMemberRecord(rdata string) (*CatalogMemberRecord, error) {
	rec := &CatalogMemberRecord{
		Class: "IN",
		TTL:   0,
	}

	// Simple parsing - handle space-separated fields
	parts := strings.Fields(rdata)
	if len(parts) < 1 {
		return nil, fmt.Errorf("catalog member record: missing zone name")
	}

	rec.ZoneName = parts[0]

	// Check for optional class, ttl, applications, group
	for i := 1; i < len(parts); i++ {
		part := parts[i]
		if part == "*" {
			rec.Applications = append(rec.Applications, "*")
		} else if strings.HasPrefix(part, "group=") {
			rec.Group = strings.TrimPrefix(part, "group=")
		} else if strings.HasPrefix(part, "\"") && strings.HasSuffix(part, "\"") {
			// Quoted group name
			rec.Group = strings.Trim(part, "\"")
		} else if isValidClass(part) {
			rec.Class = part
		}
	}

	return rec, nil
}

// isValidClass checks if a string is a valid DNS class.
func isValidClass(s string) bool {
	switch strings.ToUpper(s) {
	case "IN", "CS", "CH", "HS", "NONE", "ANY":
		return true
	default:
		return false
	}
}

// isNumericTTL checks if a string looks like a numeric TTL.
func isNumericTTL(s string) bool {
	// Simple check - if all digits, likely a TTL
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// ToRDATA converts a catalog member to its RDATA string representation.
func (m *CatalogMember) ToRDATA() string {
	rdata := m.ZoneName

	if m.ZoneClass != "" && m.ZoneClass != "IN" {
		rdata += " " + m.ZoneClass
	}

	if m.ZoneTTL > 0 {
		rdata += fmt.Sprintf(" %d", m.ZoneTTL)
	}

	for _, app := range m.Applications {
		rdata += " " + app
	}

	if m.Group != "" {
		rdata += fmt.Sprintf(" group=%s", m.Group)
	}

	return rdata
}

// CatalogZonesConfig represents the configuration for managing catalog zones.
type CatalogZonesConfig struct {
	// CatalogZoneName is the name of the catalog zone
	CatalogZoneName string

	// PrimaryZone is the zone to serve as primary for catalog updates
	PrimaryZone string

	// AllowMemberUpdates controls whether member changes are allowed
	AllowMemberUpdates bool
}

// String returns a string representation of the catalog zone.
func (cz *CatalogZone) String() string {
	return fmt.Sprintf("CatalogZone{name=%s version=%d members=%d}",
		cz.ZoneName, cz.Version, len(cz.Members))
}

// String returns a string representation of a catalog member.
func (m *CatalogMember) String() string {
	return fmt.Sprintf("Member{zone=%s class=%s group=%s apps=%v}",
		m.ZoneName, m.ZoneClass, m.Group, m.Applications)
}

// ValidateCatalogZone checks if a zone appears to be a valid catalog zone.
func ValidateCatalogZone(zoneName string) bool {
	labels := strings.Split(zoneName, ".")
	for _, label := range labels {
		if label == CatalogLabel {
			return true
		}
	}
	return false
}

// IsCatalogZone checks if the given zone name is a catalog zone.
// Catalog zones typically have "catalog" as a label in their name.
func IsCatalogZone(zoneName string) bool {
	return ValidateCatalogZone(zoneName)
}
