package transfer

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func f717Count(recs []*protocol.ResourceRecord) int {
	n := 0
	for _, r := range recs {
		if r.Type == protocol.TypeZONEMD {
			n++
		}
	}
	return n
}

func TestF717XoTStreamsZONEMD(t *testing.T) {
	z, err := zone.ParseFile("t", strings.NewReader("$ORIGIN example.test.\n$TTL 300\n@ IN SOA ns1 h 1 1 1 1 1\n@ IN NS ns1\nns1 IN A 192.0.2.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	zm, err := zone.ComputeZoneMD(z, zone.ZONEMDSHA384)
	if err != nil {
		t.Fatal(err)
	}
	z.ZONEMD = zm

	axfr, err := NewAXFRServer(nil).generateAXFRRecords(z)
	if err != nil {
		t.Fatal(err)
	}
	if f717Count(axfr) != 1 {
		t.Fatalf("CONTROL FAILED: plain AXFR has %d ZONEMD", f717Count(axfr))
	}
	xot, err := (&XoTServer{}).generateAXFRRecords(z)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("EXPECTED: 1 ZONEMD in the XoT AXFR | ACTUAL: %d\n", f717Count(xot))
	if f717Count(xot) != 1 {
		fmt.Println("PROBLEM CONFIRMED")
		t.Fatal("XoT AXFR lacks ZONEMD")
	}
	fmt.Println("PROBLEM NOT REPRODUCED")
}

func f717Zone(t *testing.T, withZONEMD bool) *zone.Zone {
	z, err := zone.ParseFile("t", strings.NewReader("$ORIGIN example.test.\n$TTL 300\n@ IN SOA ns1 h 1 1 1 1 1\n@ IN NS ns1\nns1 IN A 192.0.2.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if withZONEMD {
		zm, _ := zone.ComputeZoneMD(z, zone.ZONEMDSHA384)
		z.ZONEMD = zm
	}
	return z
}

func TestF717XoTZONEMDPlacementFreshnessAndAbsence(t *testing.T) {
	z := f717Zone(t, true)
	z.Lock()
	z.Records["www.example.test."] = append(z.Records["www.example.test."], zone.Record{Name: "www.example.test.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.9"})
	z.SOA.Serial = 2
	z.Unlock()
	recs, err := (&XoTServer{}).generateAXFRRecords(z)
	if err != nil {
		t.Fatal(err)
	}
	n := len(recs)
	zm, ok := recs[n-2].Data.(*protocol.RDataZONEMD)
	if recs[n-2].Type != protocol.TypeZONEMD || !ok || recs[n-1].Type != protocol.TypeSOA {
		t.Fatalf("ZONEMD must sit just before the closing SOA")
	}
	want, _ := zone.ComputeZoneMD(z, zone.ZONEMDSHA384)
	if string(zm.Digest) != string(want.Hash) || zm.Serial != 2 {
		t.Fatalf("stale ZONEMD over XoT: serial=%d", zm.Serial)
	}
	// IXFR with no usable client serial falls back to the full stream.
	full, err := (&XoTServer{}).generateIXFRRecords(z, 0)
	if err != nil {
		t.Fatal(err)
	}
	if f717Count(full) != 1 {
		t.Fatalf("IXFR fallback has %d ZONEMD", f717Count(full))
	}
	// a zone without ZONEMD streams none
	plain, err := (&XoTServer{}).generateAXFRRecords(f717Zone(t, false))
	if err != nil {
		t.Fatal(err)
	}
	if f717Count(plain) != 0 {
		t.Fatal("ZONEMD invented for a zone without one")
	}
}
