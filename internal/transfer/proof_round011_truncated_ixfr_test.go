// Round-011 proof: a truncated IXFR stream is applied as if complete,
// corrupting the slave zone and committing the full serial.
//
// Contract (RFC 1995 §4): "The first and the last RR of the response is the
// SOA record of the zone", and "An IXFR client should only replace an older
// version with a newer version after all the differences have been
// successfully processed." A stream that ends mid-diff is NOT a completed
// transfer and must be rejected, leaving the slave at its current serial so
// the next retry re-fetches.
//
// Two halves make this reachable:
//
//  1. receiveIXFRResponse (internal/transfer/ixfr.go:596) treats a read error
//     as normal termination once soaCount >= 2, so a master that dies
//     mid-diff yields the partial record list with no error.
//
//  2. applyIncrementalIXFR (internal/transfer/slave.go:543) validates the
//     LEADING SOA and the base serial, then walks records[1:len-1] treating
//     the final element as the trailing SOA — but never checks that the final
//     element actually IS one. It then commits targetSOA.Serial
//     (records[0]) as the zone's new serial.
//
// CLAIM:  a truncated stream must be rejected; the zone must keep its old
//
//	serial and its old record. Currently it is applied: the serial
//	jumps to 3, the deleted record is removed, and the record the
//	truncated tail never delivered is missing — a silently corrupt
//	zone that will never be re-fetched because the serial now matches.
//
// CONTROL: the same diff WITH its trailing SOA applies correctly, so the fix
//
//	cannot be "reject everything".
package transfer

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func round011SOA(t *testing.T, origin string, serial uint32) *protocol.ResourceRecord {
	t.Helper()
	n, err := protocol.ParseName(origin)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", origin, err)
	}
	mn, _ := protocol.ParseName("ns1." + origin)
	rn, _ := protocol.ParseName("hostmaster." + origin)
	return &protocol.ResourceRecord{
		Name: n, Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 3600,
		Data: &protocol.RDataSOA{
			MName: mn, RName: rn, Serial: serial,
			Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 300,
		},
	}
}

func round011A(t *testing.T, owner string, a, b, c, d byte) *protocol.ResourceRecord {
	t.Helper()
	n, err := protocol.ParseName(owner)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", owner, err)
	}
	return &protocol.ResourceRecord{
		Name: n, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataA{Address: [4]byte{a, b, c, d}},
	}
}

// round011Slave builds a SlaveManager with one slave zone at serial 1 that
// currently holds old.example.com. A 192.0.2.1.
func round011Slave(t *testing.T) (*SlaveManager, *SlaveZone) {
	t.Helper()
	sm := NewSlaveManager(nil)
	sz, err := NewSlaveZone(SlaveZoneConfig{
		ZoneName: "example.com.",
		Masters:  []string{"127.0.0.1:5354"},
	})
	if err != nil {
		t.Fatalf("NewSlaveZone: %v", err)
	}
	base := zone.NewZone("example.com.")
	base.SOA = &zone.SOARecord{
		Name: "example.com.", TTL: 3600, MName: "ns1.example.com.",
		RName: "hostmaster.example.com.", Serial: 1,
		Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 300,
	}
	base.Records["old.example.com."] = []zone.Record{{
		Name: "old.example.com.", Type: "A", TTL: 300, Class: "IN", RData: "192.0.2.1",
	}}
	sz.UpdateZone(base, 1)
	sm.slaveZones["example.com."] = sz
	return sm, sz
}

// TestApplyTransferredZone_TruncatedIXFRIsRejected is the CLAIM.
func TestApplyTransferredZone_TruncatedIXFRIsRejected(t *testing.T) {
	sm, sz := round011Slave(t)

	// A complete RFC 1995 IXFR for one difference sequence is:
	//   SOA(new) SOA(old) <deleted> SOA(new) <added> SOA(new)
	// The master died before the terminating SOA(new) arrived, so the
	// stream stops after the addition.
	truncated := []*protocol.ResourceRecord{
		round011SOA(t, "example.com.", 3),              // leading: server's current serial
		round011SOA(t, "example.com.", 1),              // diff base = client's serial
		round011A(t, "old.example.com.", 192, 0, 2, 1), // deletion
		round011SOA(t, "example.com.", 3),              // switch to additions
		round011A(t, "new.example.com.", 192, 0, 2, 2), // addition
	}

	err := sm.applyTransferredZone(sz, truncated)
	if err == nil {
		t.Fatalf("truncated IXFR stream was applied as complete: a transfer that "+
			"never delivered its terminating SOA (RFC 1995 §4) must be rejected so the "+
			"next retry re-fetches it. Slave now at serial %d, records %v",
			sz.GetLastSerial(), zoneNames(sz.GetZone()))
	}
	if got := sz.GetLastSerial(); got != 1 {
		t.Fatalf("after rejecting a truncated transfer the slave serial must stay 1, got %d", got)
	}
}

// TestApplyTransferredZone_CompleteIXFRIsApplied is the CONTROL: the same diff
// WITH its trailing SOA must still apply, so the fix cannot reject everything.
func TestApplyTransferredZone_CompleteIXFRIsApplied(t *testing.T) {
	sm, sz := round011Slave(t)

	complete := []*protocol.ResourceRecord{
		round011SOA(t, "example.com.", 3),              // leading: server's current serial
		round011SOA(t, "example.com.", 1),              // diff base = client's serial
		round011A(t, "old.example.com.", 192, 0, 2, 1), // deletion
		round011SOA(t, "example.com.", 3),              // switch to additions
		round011A(t, "new.example.com.", 192, 0, 2, 2), // addition
		round011SOA(t, "example.com.", 3),              // terminating SOA — the transfer is complete
	}

	if err := sm.applyTransferredZone(sz, complete); err != nil {
		t.Fatalf("control: a complete IXFR stream must apply, got error: %v", err)
	}
	if got := sz.GetLastSerial(); got != 3 {
		t.Fatalf("control: serial = %d, want 3", got)
	}
	z := sz.GetZone()
	if _, ok := z.Records["new.example.com."]; !ok {
		t.Fatalf("control: new.example.com. missing after a complete IXFR; records %v", zoneNames(z))
	}
	if _, ok := z.Records["old.example.com."]; ok {
		t.Fatalf("control: old.example.com. should have been deleted; records %v", zoneNames(z))
	}
}

func zoneNames(z *zone.Zone) []string {
	if z == nil {
		return nil
	}
	var out []string
	for name := range z.Records {
		out = append(out, name)
	}
	return out
}
