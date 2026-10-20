package zone

import "testing"

func rrsetTTLs(t *testing.T, m *Manager, name, rtype string) []uint32 {
	t.Helper()
	recs, _ := m.GetRecords("example.com.", name)
	var out []uint32
	for _, r := range recs {
		if r.Type == rtype {
			out = append(out, r.TTL)
		}
	}
	return out
}

// RFC 2181 §5.2: every RR of an RRset carries the same TTL. A change made
// through the manager (REST API, Raft apply, gossip) applies its TTL to the
// whole RRset, as a DDNS add already does (F716).
func TestManagerKeepsRRsetTTLUniform(t *testing.T) {
	m, _, _ := newDeleteRecordDataManager(t)

	if err := m.AddRecord("example.com.", Record{Name: "www", Type: "A", TTL: 300, RData: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if err := m.AddRecord("example.com.", Record{Name: "www", Type: "TXT", TTL: 777, RData: "\"other type\""}); err != nil {
		t.Fatal(err)
	}
	if err := m.AddRecord("example.com.", Record{Name: "www", Type: "A", TTL: 60, RData: "192.0.2.2"}); err != nil {
		t.Fatal(err)
	}
	for _, ttl := range rrsetTTLs(t, m, "www", "A") {
		if ttl != 60 {
			t.Fatalf("FAIL: after adding an A with TTL 60 the RRset TTLs are %v, want all 60", rrsetTTLs(t, m, "www", "A"))
		}
	}

	if err := m.UpdateRecord("example.com.", "www", "A", "192.0.2.2",
		Record{Name: "www", Type: "A", TTL: 120, RData: "192.0.2.3"}); err != nil {
		t.Fatal(err)
	}
	for _, ttl := range rrsetTTLs(t, m, "www", "A") {
		if ttl != 120 {
			t.Fatalf("FAIL: after updating one A to TTL 120 the RRset TTLs are %v, want all 120", rrsetTTLs(t, m, "www", "A"))
		}
	}

	// Control: another RRset at the same name keeps its own TTL.
	if got := rrsetTTLs(t, m, "www", "TXT"); len(got) != 1 || got[0] != 777 {
		t.Fatalf("control: TXT TTLs = %v, want [777]", got)
	}
}
