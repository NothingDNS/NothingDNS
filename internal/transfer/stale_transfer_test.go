package transfer

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestApplyTransferredZoneRejectsStaleTransfers guards the slave receive
// path: applyTransferredZone must refuse zone transfers whose serial is not
// newer than the one the slave already holds (RFC 1982 arithmetic via
// serialIsNewer), and incremental diffs must match the generation the slave
// actually holds (RFC 1995 §4 base-serial continuity). Before the guards,
// stale or replayed transfers rolled the zone back and mismatched-generation
// deltas corrupted it — serialIsNewer was consulted only on the NOTIFY and
// trigger sides, never on the apply side.

// proofSOA builds an SOA record at the given serial for the fixtures below.
func proofSOA(origin *protocol.Name, serial uint32) *protocol.ResourceRecord {
	mname, _ := protocol.ParseName("ns1.example.com.")
	rname, _ := protocol.ParseName("admin.example.com.")
	return &protocol.ResourceRecord{
		Name: origin, Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 60,
		Data: &protocol.RDataSOA{MName: mname, RName: rname, Serial: serial, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 60},
	}
}

// proofFull builds a full AXFR-style stream (SOA…data…SOA) at the given serial.
func proofFull(serial uint32, addr [4]byte) []*protocol.ResourceRecord {
	origin, _ := protocol.ParseName("example.com.")
	soa := proofSOA(origin, serial)
	a := &protocol.ResourceRecord{
		Name: origin, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataA{Address: addr},
	}
	return []*protocol.ResourceRecord{soa, a, soa}
}

func TestApplyTransferredZoneRejectsStaleTransfers(t *testing.T) {
	sm := NewSlaveManager(nil)

	// commit seeds a slave at the given serial through the real apply path.
	commit := func(t *testing.T, sz *SlaveZone, serial uint32) {
		t.Helper()
		if err := sm.applyTransferredZone(sz, proofFull(serial, [4]byte{192, 0, 2, 10})); err != nil {
			t.Fatalf("apply(serial %d): %v", serial, err)
		}
	}

	t.Run("stale_full_transfer_refused", func(t *testing.T) {
		sz := &SlaveZone{Config: SlaveZoneConfig{ZoneName: "example.com."}}
		commit(t, sz, 100)

		err := sm.applyTransferredZone(sz, proofFull(50, [4]byte{192, 0, 2, 11}))
		if err == nil {
			t.Error("stale transfer at serial 50 was applied over serial 100")
		}
		if sz.GetLastSerial() != 100 {
			t.Errorf("zone rolled back: LastSerial = %d, want 100", sz.GetLastSerial())
		}
	})

	t.Run("stale_lone_soa_refused", func(t *testing.T) {
		sz := &SlaveZone{Config: SlaveZoneConfig{ZoneName: "example.com."}}
		commit(t, sz, 100)

		lone := proofFull(50, [4]byte{192, 0, 2, 10})[:1] // lone SOA at stale serial 50
		if err := sm.applyTransferredZone(sz, lone); err == nil {
			t.Error("stale lone SOA at serial 50 was accepted")
		}
		if sz.GetLastSerial() != 100 {
			t.Errorf("LastSerial regressed to %d, want 100", sz.GetLastSerial())
		}
	})

	t.Run("generation_mismatched_ixfr_refused", func(t *testing.T) {
		sz := &SlaveZone{Config: SlaveZoneConfig{ZoneName: "example.com."}}
		commit(t, sz, 100)

		// A delta computed for base serial 99, not the held 100 — RFC 1995
		// shape: SOA(new=110), SOA(old=99), deletion, SOA(new=110).
		origin, _ := protocol.ParseName("example.com.")
		delta := []*protocol.ResourceRecord{
			proofSOA(origin, 110),
			proofSOA(origin, 99),
			{Name: origin, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 10}}},
			proofSOA(origin, 110),
		}
		if err := sm.applyTransferredZone(sz, delta); err == nil {
			t.Error("generation-mismatched IXFR (base 99) was applied over serial 100")
		}
		if sz.GetLastSerial() != 100 {
			t.Errorf("serial advanced to %d on a mismatched delta, want 100", sz.GetLastSerial())
		}
	})

	t.Run("fresh_slave_accepts_any_serial", func(t *testing.T) {
		sz := &SlaveZone{Config: SlaveZoneConfig{ZoneName: "example.com."}} // LastSerial 0: never transferred

		if err := sm.applyTransferredZone(sz, proofFull(50, [4]byte{192, 0, 2, 10})); err != nil {
			t.Errorf("fresh slave refused serial 50: %v", err)
		}
		if sz.GetLastSerial() != 50 {
			t.Errorf("fresh slave serial = %d, want 50", sz.GetLastSerial())
		}
	})

	t.Run("newer_transfer_applies", func(t *testing.T) {
		sz := &SlaveZone{Config: SlaveZoneConfig{ZoneName: "example.com."}}
		commit(t, sz, 100)

		if err := sm.applyTransferredZone(sz, proofFull(110, [4]byte{192, 0, 2, 12})); err != nil {
			t.Errorf("newer transfer at serial 110 refused: %v", err)
		}
		if sz.GetLastSerial() != 110 {
			t.Errorf("newer transfer serial = %d, want 110", sz.GetLastSerial())
		}
	})

	t.Run("equal_serial_lone_soa_refreshes", func(t *testing.T) {
		sz := &SlaveZone{Config: SlaveZoneConfig{ZoneName: "example.com."}}
		commit(t, sz, 100)

		// The master's "you are current" response: a lone SOA at the held
		// serial must refresh without being refused as stale.
		lone := proofFull(100, [4]byte{192, 0, 2, 10})[:1]
		if err := sm.applyTransferredZone(sz, lone); err != nil {
			t.Errorf("equal-serial lone SOA refused: %v", err)
		}
		if sz.GetLastSerial() != 100 {
			t.Errorf("serial = %d, want 100", sz.GetLastSerial())
		}
	})
}
