package zone

// Round-7/10 regression guard: UpdateRecord did not validate the new record's
// RData, while AddRecord did (and the DDNS pre-pass validates every add and
// update op). An update with injection-shaped RDATA — e.g. an A record whose
// address embeds a newline followed by another resource record — was accepted,
// stored in the zone, and written verbatim into the zone file on the next
// persist, injecting a live record into the authoritative zone.

import (
	"strings"
	"testing"
)

func newUpdateTestManager(t *testing.T) *Manager {
	t.Helper()
	m := NewManager()
	err := m.CreateZone("example.com.", 300, &SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300,
	}, []NSRecord{{NSDName: "ns1.example.com."}})
	if err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
	// Seed the safe record through the validated add path.
	if err := m.AddRecord("example.com.", Record{
		Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A",
		RData: "192.0.2.1",
	}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	return m
}

func TestUpdateRecordRejectsInjectionShapedRData(t *testing.T) {
	m := newUpdateTestManager(t)

	injected := "192.0.2.1\nmail.example.com. 300 IN A 6.6.6.6"
	err := m.UpdateRecord("example.com.", "www.example.com.", "A", "192.0.2.1", Record{
		Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A",
		RData: injected,
	})

	// Contract parity with AddRecord and the DDNS pre-pass: the update must
	// be rejected, not silently applied.
	if err == nil {
		t.Fatalf("FAIL: an injection-shaped RDATA was accepted by UpdateRecord")
	}

	// The zone must be unchanged: the original safe RData intact, no newline.
	z, ok := m.Get("example.com.")
	if !ok {
		t.Fatalf("the zone vanished")
	}
	z.RLock()
	recs := z.Records["www.example.com."]
	z.RUnlock()
	if len(recs) != 1 {
		t.Fatalf("FAIL: the record count changed: %d", len(recs))
	}
	if recs[0].RData != "192.0.2.1" {
		t.Fatalf("FAIL: the record was overwritten with the injection-shaped RDATA: %q", recs[0].RData)
	}
	if strings.Contains(recs[0].RData, "\n") {
		t.Fatalf("FAIL: the zone record contains the injected newline")
	}
}

func TestUpdateRecordAcceptsSafeRData(t *testing.T) {
	m := newUpdateTestManager(t)

	err := m.UpdateRecord("example.com.", "www.example.com.", "A", "192.0.2.1", Record{
		Name: "www.example.com.", TTL: 600, Class: "IN", Type: "A",
		RData: "192.0.2.2",
	})
	if err != nil {
		t.Fatalf("a safe update was rejected: %v", err)
	}

	z, ok := m.Get("example.com.")
	if !ok {
		t.Fatalf("the zone vanished")
	}
	z.RLock()
	recs := z.Records["www.example.com."]
	z.RUnlock()
	if len(recs) != 1 || recs[0].RData != "192.0.2.2" {
		t.Fatalf("FAIL: the safe update did not land: %+v", recs)
	}
}
