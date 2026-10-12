package transfer

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// F696: a transfer carrying owners outside the zone (a master bug or a
// compromised master) was stored verbatim, then written to the zone file,
// re-served over AXFR and signed into the denial chain. zone.Manager.AddRecord
// already refuses such data; the slave path did not.
func TestSlaveTransferDropsOutOfZoneRecords(t *testing.T) {
	sm := &SlaveManager{}
	sz := newTestSlaveZone(t)
	full := []*protocol.ResourceRecord{
		mkSOARR(t, 100),
		mkARR(t, "www.example.com.", 192, 0, 2, 10),
		mkARR(t, "victim.org.", 192, 0, 2, 66),
		mkARR(t, "notexample.com.", 192, 0, 2, 67),
		mkSOARR(t, 100),
	}
	if err := sm.applyTransferredZone(sz, full); err != nil {
		t.Fatal(err)
	}
	z := sz.GetZone()
	if !zoneHas(z, "www.example.com.", "A", "192.0.2.10") {
		t.Fatalf("in-zone record lost: %+v", z.Records)
	}
	for _, n := range []string{"victim.org.", "notexample.com."} {
		if len(z.Records[n]) != 0 {
			t.Errorf("out-of-zone owner %s stored", n)
		}
	}

	inc := []*protocol.ResourceRecord{
		mkSOARR(t, 101), mkSOARR(t, 100), mkSOARR(t, 101),
		mkARR(t, "evil.org.", 192, 0, 2, 68),
		mkARR(t, "new.example.com.", 192, 0, 2, 30),
		mkSOARR(t, 101),
	}
	if err := sm.applyTransferredZone(sz, inc); err != nil {
		t.Fatal(err)
	}
	z = sz.GetZone()
	if len(z.Records["evil.org."]) != 0 {
		t.Errorf("IXFR stored out-of-zone owner evil.org.")
	}
	if !zoneHas(z, "new.example.com.", "A", "192.0.2.30") {
		t.Errorf("in-zone IXFR addition lost")
	}
}
