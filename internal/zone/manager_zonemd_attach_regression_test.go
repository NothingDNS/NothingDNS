package zone

import (
	"strings"
	"testing"
)

const f720ZoneText = "$ORIGIN example.test.\n$TTL 300\n@ IN SOA ns1 h 1 1 1 1 1\n@ IN NS ns1\nns1 IN A 192.0.2.1\n"

// F720: every entry point into the manager attaches a ZONEMD when digests are
// enabled, not only Load (which the server's start-up never calls).
func TestManagerAttachesZONEMDOnLoadZoneAndCreateZone(t *testing.T) {
	parse := func(text string) *Zone {
		z, err := ParseFile("t", strings.NewReader(text))
		if err != nil {
			t.Fatal(err)
		}
		return z
	}

	m := NewManager()
	m.SetZONEMDEnabled(true)
	z := parse(f720ZoneText)
	m.LoadZone(z, "")
	if z.ZONEMD == nil || z.ZONEMD.Algorithm != 1 || len(z.ZONEMD.Hash) != 48 {
		t.Fatalf("LoadZone: ZONEMD = %+v", z.ZONEMD)
	}

	if err := m.CreateZone("created.test.", 300,
		&SOARecord{MName: "ns1.created.test.", RName: "h.created.test.", Serial: 1, Refresh: 1, Retry: 1, Expire: 1, Minimum: 1},
		[]NSRecord{{NSDName: "ns1.created.test."}}); err != nil {
		t.Fatal(err)
	}
	cz, _ := m.Get("created.test.")
	if cz.ZONEMD == nil {
		t.Fatal("CreateZone: no ZONEMD")
	}

	// disabled: nothing attached
	off := NewManager()
	oz := parse(f720ZoneText)
	off.LoadZone(oz, "")
	if oz.ZONEMD != nil {
		t.Fatal("ZONEMD attached while disabled")
	}

	// a zone file that carries its own apex ZONEMD keeps that one (no duplicate)
	own := parse(f720ZoneText + "@ IN ZONEMD 1 1 1 " + strings.Repeat("ab", 48) + "\n")
	m.LoadZone(own, "")
	if own.ZONEMD != nil {
		t.Fatal("generated ZONEMD attached next to the zone's own ZONEMD RR")
	}
}
