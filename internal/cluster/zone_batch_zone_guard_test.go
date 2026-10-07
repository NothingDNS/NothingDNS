package cluster

// F582 (P2-G5): the whole-zone batch guard (ZoneBatchPrecondition.Zone, v2
// payload) rejects a batch after any content change anywhere in the zone,
// ignores the serial (replicas bump it from their own clocks on
// single-record writes), and is applied identically on every replica.

import (
	"errors"
	"testing"

	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestZoneContentFingerprint_F582(t *testing.T) {
	m, _ := f497Manager(t)
	c := f497Cluster(m)
	fp, err := c.ZoneContentFingerprint("a.example.")
	if err != nil {
		t.Fatal(err)
	}
	z, _ := m.Get("a.example.")
	z.Lock()
	z.SOA.Serial += 7 // serial-only change: same content
	z.Unlock()
	if again, _ := c.ZoneContentFingerprint("a.example."); again != fp {
		t.Fatal("whole-zone fingerprint depends on the SOA serial")
	}
	if err := m.AddRecord("a.example.", zone.Record{Name: "other", Type: "A", TTL: 60, RData: "192.0.2.99"}); err != nil {
		t.Fatal(err)
	}
	if again, _ := c.ZoneContentFingerprint("a.example."); again == fp {
		t.Fatal("whole-zone fingerprint unchanged after a write to an unrelated name")
	}
	if _, err := c.ZoneContentFingerprint("missing.example."); err == nil {
		t.Fatal("fingerprint of an unknown zone succeeded")
	}
}

func TestApplyZoneBatch_F582_ZoneGuard(t *testing.T) {
	ops := []ZoneOp{{Op: ZoneOpAdd, Name: "new", Type: "A", TTL: 60, RData: "192.0.2.50"}}
	ref, _ := f497Manager(t)
	fp, err := f497Cluster(ref).ZoneContentFingerprint("a.example.")
	if err != nil {
		t.Fatal(err)
	}
	payload := zoneBatchPayload{V: zoneBatchVersionZoneGuard, ID: "g1", Ops: ops, Names: []string{"new"}, Fingerprint: fp, Zone: true, SerialDate: 2099010100}

	// Applied on unchanged replicas, even with differing serials.
	for i := 0; i < 2; i++ {
		m, _ := f497Manager(t)
		if i == 1 {
			z, _ := m.Get("a.example.")
			z.Lock()
			z.SOA.Serial += 3
			z.Unlock()
		}
		if err := f497Cluster(m).applyZoneBatch("a.example.", &payload); err != nil {
			t.Fatalf("replica %d: %v", i, err)
		}
		if got := f497Rdatas(m, "new", "A"); len(got) != 1 {
			t.Fatalf("replica %d: new A = %v", i, got)
		}
	}
	// Rejected after a write to an unrelated name (the per-name guard over
	// "new" alone would accept it).
	m, _ := f497Manager(t)
	if err := m.AddRecord("a.example.", zone.Record{Name: "unrelated", Type: "A", TTL: 60, RData: "192.0.2.77"}); err != nil {
		t.Fatal(err)
	}
	if err := f497Cluster(m).applyZoneBatch("a.example.", &payload); !errors.Is(err, ErrZoneBatchConflict) {
		t.Fatalf("err = %v, want ErrZoneBatchConflict", err)
	}
	if got := f497Rdatas(m, "new", "A"); len(got) != 0 {
		t.Fatalf("rejected batch applied: new A = %v", got)
	}
	// A v2 payload without the zone guard, or v1 with it, is not a known
	// shape: rejected deterministically.
	bad := payload
	bad.Zone = false
	if err := f497Cluster(ref).applyZoneBatch("a.example.", &bad); !errors.Is(err, ErrZoneBatchUnsupported) {
		t.Fatalf("v2 without zone guard: err = %v", err)
	}
	bad = payload
	bad.V = zoneBatchVersion
	if err := f497Cluster(ref).applyZoneBatch("a.example.", &bad); !errors.Is(err, ErrZoneBatchUnsupported) {
		t.Fatalf("v1 with zone guard: err = %v", err)
	}
	if got := f497Rdatas(ref, "new", "A"); len(got) != 0 {
		t.Fatalf("unsupported payload applied: new A = %v", got)
	}
}
