package transfer

// F587/F588 (P2-H1): a transferred zone keeps its SOA in both places the zone
// model holds it — z.SOA and the apex SOA RR in z.Records — and an incremental
// IXFR installs the target SOA with all its fields, not only the serial.

import (
	"fmt"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func f588SOARR(t *testing.T, serial uint32, changed bool) *protocol.ResourceRecord {
	t.Helper()
	rr := mkSOARR(t, serial)
	if changed {
		rr.TTL = 600
		d := rr.Data.(*protocol.RDataSOA)
		d.MName = mkName(t, "ns2.example.com.")
		d.Refresh, d.Minimum = 1800, 60
	}
	return rr
}

// apexSOARecords returns the RDATA of every SOA RR at the zone apex.
func apexSOARecords(z *zone.Zone) []string {
	var out []string
	for _, r := range z.Records[z.Origin] {
		if r.Type == "SOA" {
			out = append(out, r.RData)
		}
	}
	return out
}

func soaDesc(s *zone.SOARecord) string {
	return fmt.Sprintf("%s %d %s %s %d %d %d %d %d", s.Name, s.TTL, s.MName, s.RName, s.Serial, s.Refresh, s.Retry, s.Expire, s.Minimum)
}

func TestSlaveTransfer_F587_ApexSOARecord(t *testing.T) {
	sm := &SlaveManager{}
	sz := newTestSlaveZone(t)
	full := []*protocol.ResourceRecord{
		mkSOARR(t, 100),
		mkARR(t, "example.com.", 192, 0, 2, 1),
		mkARR(t, "a.example.com.", 192, 0, 2, 10),
		mkSOARR(t, 100),
	}
	if err := sm.applyTransferredZone(sz, full); err != nil {
		t.Fatal(err)
	}
	z := sz.GetZone()
	want := "ns1.example.com. admin.example.com. 100 7200 3600 1209600 3600"
	if got := apexSOARecords(z); len(got) != 1 || got[0] != want {
		t.Fatalf("after AXFR: apex SOA RRs = %q, want [%q]", got, want)
	}
	if got := soaDesc(z.SOA); got != "example.com. 3600 ns1.example.com. admin.example.com. 100 7200 3600 1209600 3600" {
		t.Fatalf("after AXFR: z.SOA = %s", got)
	}
	if !zoneHas(z, "example.com.", "A", "192.0.2.1") {
		t.Fatal("apex A lost")
	}
	// The zone's own lookup answers the apex SOA query positively.
	if res := z.Lookup("example.com.", "SOA"); len(res) != 1 {
		t.Fatalf("Lookup(apex, SOA) = %v", res)
	}

	// IXFR 100 → 101: exactly one apex SOA RR, carrying the new serial, and
	// z.SOA in step with it.
	ixfr := []*protocol.ResourceRecord{
		mkSOARR(t, 101),
		mkSOARR(t, 100), mkARR(t, "a.example.com.", 192, 0, 2, 10),
		mkSOARR(t, 101), mkARR(t, "a.example.com.", 192, 0, 2, 11),
		mkSOARR(t, 101),
	}
	if err := sm.applyTransferredZone(sz, ixfr); err != nil {
		t.Fatal(err)
	}
	z = sz.GetZone()
	want = "ns1.example.com. admin.example.com. 101 7200 3600 1209600 3600"
	if got := apexSOARecords(z); len(got) != 1 || got[0] != want {
		t.Fatalf("after IXFR: apex SOA RRs = %q, want [%q]", got, want)
	}
	if z.SOA.Serial != 101 || !zoneHas(z, "a.example.com.", "A", "192.0.2.11") || !zoneHas(z, "example.com.", "A", "192.0.2.1") {
		t.Fatalf("after IXFR: serial=%d records=%v", z.SOA.Serial, z.Records)
	}
}

func TestSlaveTransfer_F588_IXFRInstallsWholeSOA(t *testing.T) {
	sm := &SlaveManager{}
	sz := newTestSlaveZone(t)
	if err := sm.applyTransferredZone(sz, []*protocol.ResourceRecord{f588SOARR(t, 100, false), mkARR(t, "a.example.com.", 192, 0, 2, 1), f588SOARR(t, 100, false)}); err != nil {
		t.Fatal(err)
	}
	ixfr := []*protocol.ResourceRecord{
		f588SOARR(t, 101, true),
		f588SOARR(t, 100, false), mkARR(t, "a.example.com.", 192, 0, 2, 1),
		f588SOARR(t, 101, true), mkARR(t, "a.example.com.", 192, 0, 2, 2),
		f588SOARR(t, 101, true),
	}
	if err := sm.applyTransferredZone(sz, ixfr); err != nil {
		t.Fatal(err)
	}
	z := sz.GetZone()
	if got, want := soaDesc(z.SOA), "example.com. 600 ns2.example.com. admin.example.com. 101 1800 3600 1209600 60"; got != want {
		t.Fatalf("z.SOA after IXFR = %s, want %s", got, want)
	}
	if got, want := apexSOARecords(z), "ns2.example.com. admin.example.com. 101 1800 3600 1209600 60"; len(got) != 1 || got[0] != want {
		t.Fatalf("apex SOA RRs = %q, want [%q]", got, want)
	}
	for _, r := range z.Records[z.Origin] {
		if r.Type == "SOA" && r.TTL != 600 {
			t.Fatalf("apex SOA RR TTL = %d, want 600", r.TTL)
		}
	}
	// Refresh timers follow the new SOA.
	if timers, ok := zoneSOATimers(z); !ok || timers.refresh.Seconds() != 1800 {
		t.Fatalf("zoneSOATimers = %+v ok=%v", timers, ok)
	}
}
