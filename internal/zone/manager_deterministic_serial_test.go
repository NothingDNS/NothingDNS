package zone

import "testing"

func TestManagerDeterministicSerials(t *testing.T) {
	soaSerial := func(m *Manager) uint32 {
		z, _ := m.Get("example.com.")
		z.RLock()
		defer z.RUnlock()
		return z.SOA.Serial
	}
	mutate := func(m *Manager) {
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		must(m.AddRecord("example.com.", Record{Name: "a", Type: "A", TTL: 60, RData: "192.0.2.1"}))
		must(m.AddRecord("example.com.", Record{Name: "a", Type: "A", TTL: 60, RData: "192.0.2.2"}))
		must(m.UpdateRecord("example.com.", "a", "A", "192.0.2.2", Record{Name: "a", Type: "A", TTL: 60, RData: "192.0.2.3"}))
		must(m.DeleteRecordData("example.com.", "a", "A", "192.0.2.1"))
		must(m.DeleteRecord("example.com.", "a", "A"))
	}

	// Enabled: five mutations add exactly five, whatever day it is.
	m, _, _ := newDeleteRecordDataManager(t)
	m.SetDeterministicSerials(true)
	start := soaSerial(m)
	mutate(m)
	if got := soaSerial(m); got != start+5 {
		t.Fatalf("deterministic: serial %d after 5 mutations from %d, want %d", got, start, start+5)
	}

	// Control: by default a serial older than today's date jumps to the
	// YYYYMMDDNN form.
	m, _, _ = newDeleteRecordDataManager(t)
	start = soaSerial(m)
	mutate(m)
	if got := soaSerial(m); got <= start+5 {
		t.Fatalf("default: serial %d after 5 mutations from %d, want the date-style jump", got, start)
	}
}
