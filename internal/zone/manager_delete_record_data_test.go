package zone

import (
	"os"
	"path/filepath"
	"testing"
)

// newDeleteRecordDataManager creates example.com. in a temporary zone_dir
// (so every mutation is persisted to the zone file) and counts mutation-hook
// notifications (the KV-persistence / query-routing hook).
func newDeleteRecordDataManager(t *testing.T) (*Manager, string, *int) {
	t.Helper()
	dir := t.TempDir()
	m := NewManager()
	m.SetZoneDir(dir)
	soa := &SOARecord{TTL: 3600, MName: "ns1.example.com.", RName: "hostmaster.example.com.",
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300}
	if err := m.CreateZone("example.com.", 3600, soa, []NSRecord{{TTL: 3600, NSDName: "ns1.example.com."}}); err != nil {
		t.Fatal(err)
	}
	hooks := 0
	m.SetMutationHook(func(string, bool) { hooks++ })
	return m, filepath.Join(dir, "example.com.zone"), &hooks
}

func mustAdd(t *testing.T, m *Manager, name, rtype, data string) {
	t.Helper()
	if err := m.AddRecord("example.com.", Record{Name: name, Type: rtype, TTL: 300, RData: data}); err != nil {
		t.Fatalf("AddRecord %s %s %s: %v", name, rtype, data, err)
	}
}

func rdataOf(t *testing.T, m *Manager, name, rtype string) []string {
	t.Helper()
	recs, _ := m.GetRecords("example.com.", name)
	var out []string
	for _, r := range recs {
		if r.Type == rtype {
			out = append(out, r.RData)
		}
	}
	return out
}

func serialOf(t *testing.T, m *Manager) uint32 {
	t.Helper()
	z, ok := m.Get("example.com.")
	if !ok {
		t.Fatal("zone missing")
	}
	z.RLock()
	defer z.RUnlock()
	return z.SOA.Serial
}

// F417: deleting one RR of a multi-record RRset removes exactly that RR, bumps
// the serial, persists the zone file and notifies the mutation hook.
func TestManager_F417_DeleteRecordDataRemovesOnlyThatRR(t *testing.T) {
	m, path, hooks := newDeleteRecordDataManager(t)
	mustAdd(t, m, "www", "A", "192.0.2.1")
	mustAdd(t, m, "www", "A", "192.0.2.2")
	mustAdd(t, m, "www", "AAAA", "2001:db8::1")
	before, hooksBefore := serialOf(t, m), *hooks

	// Owner name case-insensitive and absolute/relative equivalent.
	if err := m.DeleteRecordData("EXAMPLE.com", "WWW.Example.COM.", "a", "192.0.2.1"); err != nil {
		t.Fatalf("DeleteRecordData: %v", err)
	}
	if got := rdataOf(t, m, "www", "A"); len(got) != 1 || got[0] != "192.0.2.2" {
		t.Fatalf("A RRset after delete = %v, want [192.0.2.2]", got)
	}
	if got := rdataOf(t, m, "www", "AAAA"); len(got) != 1 {
		t.Fatalf("AAAA RRset touched: %v", got)
	}
	if after := serialOf(t, m); after == before {
		t.Fatalf("serial not bumped (%d)", after)
	}
	if *hooks != hooksBefore+1 {
		t.Fatalf("mutation hook fired %d times, want 1", *hooks-hooksBefore)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	pz, err := ParseFile(path, f)
	f.Close()
	if err != nil {
		t.Fatalf("persisted zone file does not parse: %v", err)
	}
	var persisted []string
	for _, r := range pz.Records["www.example.com."] {
		if r.Type == "A" {
			persisted = append(persisted, r.RData)
		}
	}
	if len(persisted) != 1 || persisted[0] != "192.0.2.2" {
		t.Fatalf("persisted A RRset = %v, want [192.0.2.2]", persisted)
	}

	// Removing the last records at a name drops the owner entirely.
	if err := m.DeleteRecordData("example.com.", "www", "A", "192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteRecordData("example.com.", "www", "AAAA", "2001:DB8:0::1"); err != nil {
		t.Fatalf("canonical AAAA match: %v", err)
	}
	z, _ := m.Get("example.com.")
	z.RLock()
	_, still := z.Records["www.example.com."]
	z.RUnlock()
	if still {
		t.Fatal("empty owner left behind in z.Records")
	}
}

// F417: a miss or an empty rdata is an error and mutates nothing.
func TestManager_F417_DeleteRecordDataMissIsNoOp(t *testing.T) {
	m, _, hooks := newDeleteRecordDataManager(t)
	mustAdd(t, m, "www", "A", "192.0.2.1")
	mustAdd(t, m, "www", "A", "192.0.2.2")
	before, hooksBefore := serialOf(t, m), *hooks
	for _, tc := range [][3]string{
		{"www", "A", "192.0.2.9"},    // no such RDATA
		{"www", "AAAA", "192.0.2.1"}, // wrong type
		{"nope", "A", "192.0.2.1"},   // no such owner
		{"www", "A", "  "},           // empty data
	} {
		if err := m.DeleteRecordData("example.com.", tc[0], tc[1], tc[2]); err == nil {
			t.Fatalf("DeleteRecordData(%v) = nil, want error", tc)
		}
	}
	if err := m.DeleteRecordData("missing.example.", "www", "A", "192.0.2.1"); err == nil {
		t.Fatal("missing zone accepted")
	}
	if got := rdataOf(t, m, "www", "A"); len(got) != 2 {
		t.Fatalf("A RRset = %v, want both records", got)
	}
	if serialOf(t, m) != before || *hooks != hooksBefore {
		t.Fatal("a failed delete bumped the serial or fired the mutation hook")
	}
}

// F417: canonical RDATA comparison — names case-insensitive, text exact.
func TestRDataEqual_F417(t *testing.T) {
	for _, tc := range []struct {
		rtype, a, b string
		want        bool
	}{
		{"A", "192.0.2.1", " 192.0.2.1 ", true},
		{"A", "192.0.2.1", "192.0.2.10", false},
		{"AAAA", "2001:db8::1", "2001:DB8:0:0::1", true},
		{"MX", "10 mail.example.com.", "10 MAIL.Example.COM.", true},
		{"MX", "10 mail.example.com.", "20 mail.example.com.", false},
		{"CNAME", "Target.Example.net.", "target.example.net.", true},
		{"SRV", "1 2 443 h.example.com.", "1 2 443 H.EXAMPLE.COM.", true},
		{"TXT", `"Hello"`, `"hello"`, false},
		{"TXT", `"v=spf1 -all"`, `"v=spf1 -all"`, true},
		{"CAA", `0 issue "letsencrypt.org"`, `0 issue "letsencrypt.org"`, true},
		{"A", "not-an-ip", "not-an-ip", true},
		{"A", "not-an-ip", "NOT-AN-IP", false},
	} {
		if got := RDataEqual(tc.rtype, tc.a, tc.b); got != tc.want {
			t.Errorf("RDataEqual(%s, %q, %q) = %v, want %v", tc.rtype, tc.a, tc.b, got, tc.want)
		}
	}
}
