package zone

import (
	"strings"
	"testing"
)

// TestCreateZoneRejectsReservedNames locks in the VULN-008 partial mitigation.
// Creating a zone for an IANA TLD or arpa. root would let an operator shadow
// global DNS for every downstream client, and is almost never intended.
func TestCreateZoneRejectsReservedNames(t *testing.T) {
	reserved := []string{
		"com.", "net.", "org.", "io.", "tr.",
		"COM.", // case-insensitive — normalizeZoneName lowercases
	}
	m := NewManager()
	soa := &SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400,
	}
	ns := []NSRecord{{NSDName: "ns1.example.com."}}

	for _, name := range reserved {
		err := m.CreateZone(name, 3600, soa, ns)
		if err == nil {
			t.Errorf("CreateZone(%q): expected rejection, got nil error", name)
			continue
		}
		if !strings.Contains(err.Error(), "reserved") {
			t.Errorf("CreateZone(%q): expected 'reserved' in error, got %v", name, err)
		}
	}
}

// TestCreateZoneAllowsDocumentationNames confirms RFC 6761 test-designated
// zones are NOT blocked by the reserved list (they are meant for testing).
func TestCreateZoneAllowsDocumentationNames(t *testing.T) {
	allowed := []string{
		"example.com.", "example.", "test.", "invalid.", "localhost.",
		"arpa.", "in-addr.arpa.", "ip6.arpa.",
	}
	soa := &SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400,
	}
	ns := []NSRecord{{NSDName: "ns1.example.com."}}

	for _, name := range allowed {
		m := NewManager()
		if err := m.CreateZone(name, 3600, soa, ns); err != nil {
			t.Errorf("CreateZone(%q) should succeed, got %v", name, err)
		}
	}
}
