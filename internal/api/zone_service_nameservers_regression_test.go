package api

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestF715ZoneDetailNameservers(t *testing.T) {
	m := zone.NewManager()
	// control: a zone-file zone
	pz, err := zone.ParseFile("p.zone", strings.NewReader("$ORIGIN parsed.test.\n$TTL 60\n@ IN SOA ns1 h 1 1 1 1 1\n@ IN NS ns1.parsed.test.\n"))
	if err != nil {
		t.Fatal(err)
	}
	m.LoadZone(pz, "")
	// transferred-style zone: built as slave.applyFullZone does (records only)
	tz := zone.NewZone("xfer.test.")
	tz.SOA = &zone.SOARecord{Name: "xfer.test.", TTL: 60, MName: "ns1.xfer.test.", RName: "h.xfer.test.", Serial: 1}
	tz.Records["xfer.test."] = []zone.Record{
		{Name: "xfer.test.", Type: "SOA", TTL: 60, RData: "ns1.xfer.test. h.xfer.test. 1 1 1 1 1"},
		{Name: "xfer.test.", Type: "NS", TTL: 60, RData: "ns1.xfer.test."},
	}
	m.LoadZone(tz, "")

	svc := NewZoneService(m)
	c, _ := svc.GetZone("parsed.test.")
	if len(c.Nameservers) != 1 {
		t.Fatalf("CONTROL FAILED: %v", c.Nameservers)
	}
	d, _ := svc.GetZone("xfer.test.")
	fmt.Printf("EXPECTED: [ns1.xfer.test.] | ACTUAL: %v\n", d.Nameservers)
	if len(d.Nameservers) != 1 {
		fmt.Println("PROBLEM CONFIRMED")
		t.Fatal("nameservers missing")
	}
	fmt.Println("PROBLEM NOT REPRODUCED")
}

func TestF715ZoneDetailNameserversFollowRecords(t *testing.T) {
	m := zone.NewManager()
	pz, err := zone.ParseFile("p.zone", strings.NewReader("$ORIGIN parsed.test.\n$TTL 60\n@ IN SOA ns1 h 1 1 1 1 1\n@ IN NS ns1.parsed.test.\nsub IN NS ns.other.test.\n"))
	if err != nil {
		t.Fatal(err)
	}
	m.LoadZone(pz, "")
	svc := NewZoneService(m)
	d, _ := svc.GetZone("parsed.test.")
	if len(d.Nameservers) != 1 || d.Nameservers[0] != "ns1.parsed.test." {
		t.Fatalf("delegation NS must not be listed: %v", d.Nameservers)
	}
}
