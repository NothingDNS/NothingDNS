package zone

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func u32(v uint32) *uint32 { return &v }
func str(v string) *string { return &v }

func soaTestManager(t *testing.T) (*Manager, string, *atomic.Int32) {
	t.Helper()
	m := NewManager()
	dir := t.TempDir()
	m.SetZoneDir(dir)
	m.SetDeterministicSerials(true)
	soa := &SOARecord{TTL: 3600, MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 7,
		Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400}
	if err := m.CreateZone("example.com.", 3600, soa, []NSRecord{{TTL: 3600, NSDName: "ns1.example.com."}}); err != nil {
		t.Fatal(err)
	}
	n := &atomic.Int32{}
	m.SetMutationHook(func(string, bool) { n.Add(1) })
	return m, filepath.Join(dir, "example.com.zone"), n
}

// #19: UpdateSOA changes only the fields it is given, bumps the serial,
// rewrites the apex SOA record and the zone file, and fires the hook.
func TestUpdateSOA_ChangesFieldsAndBumpsSerial(t *testing.T) {
	m, path, hooks := soaTestManager(t)

	got, err := m.UpdateSOA("Example.COM", SOAUpdate{
		RName: str("dns@example.org"), Minimum: u32(300), TTL: u32(600),
	})
	if err != nil {
		t.Fatalf("UpdateSOA: %v", err)
	}
	want := SOARecord{TTL: 600, MName: "ns1.example.com.", RName: "dns.example.org.", Serial: 8,
		Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300}
	if got != want {
		t.Fatalf("UpdateSOA = %+v, want %+v", got, want)
	}
	if hooks.Load() != 1 {
		t.Fatalf("mutation hook fired %d times, want 1", hooks.Load())
	}
	if read, _ := m.SOA("example.com"); read != want {
		t.Fatalf("SOA() = %+v, want %+v", read, want)
	}

	recs, _ := m.GetRecords("example.com.", "@")
	found := false
	for _, r := range recs {
		if r.Type == "SOA" {
			found = true
			if r.TTL != 600 || r.RData != "ns1.example.com. dns.example.org. 8 3600 600 604800 300" {
				t.Fatalf("apex SOA record = %d %q", r.TTL, r.RData)
			}
		}
	}
	if !found {
		t.Fatal("apex SOA record missing")
	}

	// The written zone file reloads with the new SOA.
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := ParseFile(path, f)
	if err != nil {
		t.Fatalf("zone file no longer parses: %v", err)
	}
	if z.SOA.RName != "dns.example.org." || z.SOA.Minimum != 300 || z.SOA.Serial != 8 {
		t.Fatalf("reloaded SOA = %+v", z.SOA)
	}
	for _, r := range z.Records[z.Origin] {
		if r.Type == "SOA" && r.TTL != 600 {
			t.Fatalf("reloaded SOA TTL = %d, want 600", r.TTL)
		}
	}
}

func TestUpdateSOA_RejectsInvalidAndChangesNothing(t *testing.T) {
	m, _, hooks := soaTestManager(t)
	before, _ := m.SOA("example.com.")

	for name, u := range map[string]SOAUpdate{
		"empty":                {},
		"retry not < refresh":  {Retry: u32(3600)},
		"expire not > refresh": {Expire: u32(3600)},
		"zero refresh":         {Refresh: u32(0)},
		"ttl too large":        {TTL: u32(1 << 31)},
		"minimum too large":    {Minimum: u32(1<<32 - 1)},
		"empty mname":          {MName: str(" ")},
		"empty rname":          {RName: str("")},
		"dotted local part":    {RName: str("john.doe@example.com")},
		"hostile mname":        {MName: str("ns1;x.example.com.")},
		"empty label":          {MName: str("ns1..example.com.")},
	} {
		if _, err := m.UpdateSOA("example.com.", u); err == nil {
			t.Errorf("%s: UpdateSOA accepted %+v", name, u)
		}
	}
	if after, _ := m.SOA("example.com."); after != before {
		t.Fatalf("rejected updates changed the SOA: %+v -> %+v", before, after)
	}
	if hooks.Load() != 0 {
		t.Fatalf("rejected updates fired the hook %d times", hooks.Load())
	}

	if _, err := m.UpdateSOA("missing.example.", SOAUpdate{Minimum: u32(300)}); !errors.Is(err, ErrZoneNotFound) {
		t.Fatalf("missing zone: err = %v, want ErrZoneNotFound", err)
	}
}

// A relative MName is made absolute against the zone origin, as for a new
// zone's nameservers.
func TestUpdateSOA_RelativeMName(t *testing.T) {
	m, _, _ := soaTestManager(t)
	got, err := m.UpdateSOA("example.com.", SOAUpdate{MName: str("ns2")})
	if err != nil {
		t.Fatal(err)
	}
	if got.MName != "ns2.example.com." {
		t.Fatalf("MName = %q", got.MName)
	}
}

func TestValidateSOA_Defaults(t *testing.T) {
	soa := &SOARecord{MName: "ns1.example.com.", RName: "hostmaster.example.com.", TTL: 3600,
		Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400}
	if err := ValidateSOA(soa); err != nil {
		t.Fatalf("default SOA rejected: %v", err)
	}
	soa.RName = "hostmaster.example.com"
	if err := ValidateSOA(soa); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative rname: err = %v", err)
	}
}
