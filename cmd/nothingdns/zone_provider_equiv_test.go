package main

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/zone"
)

// refIsSubdomain is the original allocating implementation.
func refIsSubdomain(child, parent string) bool {
	child = canonicalize(child)
	parent = canonicalize(parent)
	if parent == "." {
		return true
	}
	if child == parent {
		return true
	}
	return strings.HasSuffix(child, "."+parent)
}

func TestIsSubdomainMatchesReference(t *testing.T) {
	names := []string{"", ".", "com", "com.", "COM.", "example.com.", "Example.Com", "a.example.com.",
		"www.a.example.com", "xexample.com.", "example.com.x.", "ample.com.", "b.ample.com.", " example.com. ", "e.com."}
	for _, c := range names {
		for _, p := range names {
			if got, want := isSubdomain(c, p), refIsSubdomain(c, p); got != want {
				t.Errorf("isSubdomain(%q, %q) = %v, want %v", c, p, got, want)
			}
		}
	}
}

// The manager and kv providers iterate in place instead of copying the zone
// map; the merged answer must equal what a copy-and-filter gives.
func TestMultiZoneProviderFindZonesMatchesCopyAndFilter(t *testing.T) {
	mgr := zone.NewManager()
	static := map[string]*zone.Zone{}
	for i := 0; i < 20; i++ {
		origin := fmt.Sprintf("z%d.zt.org.", i)
		mustCreate(t, mgr, origin)
	}
	mustCreate(t, mgr, "zt.org.")
	static["Static.Org"] = zone.NewZone("static.org.") // deliberately non-canonical key
	static["zt.org."] = mustGet(t, mgr, "zt.org.")

	tree := zone.NewRadixTree()
	tree.Insert("z3.zt.org.", mustGet(t, mgr, "z3.zt.org."))
	mp := NewMultiZoneProvider(static, mgr, nil, tree)

	ref := func(q string) []string {
		seen := map[string]bool{}
		var out []string
		add := func(origin string) {
			if !seen[origin] {
				seen[origin] = true
				out = append(out, origin)
			}
		}
		for o := range static {
			if refIsSubdomain(q, o) {
				add(o)
			}
		}
		for o := range mgr.List() {
			if refIsSubdomain(q, o) {
				add(o)
			}
		}
		if best := tree.Find(q); best != nil {
			add(best.Origin)
		}
		sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) || len(out[i]) == len(out[j]) && out[i] < out[j] })
		return out
	}
	for _, q := range []string{"www.z3.zt.org.", "z3.zt.org.", "z19.zt.org", "a.b.zt.org.", "zt.org.",
		"nope.org.", "x.static.org.", "STATIC.ORG.", "."} {
		var got []string
		for _, m := range mp.FindZones(q) {
			got = append(got, m.Origin)
		}
		sort.Slice(got, func(i, j int) bool { return len(got[i]) > len(got[j]) || len(got[i]) == len(got[j]) && got[i] < got[j] })
		want := ref(q)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("FindZones(%q) = %v, want %v", q, got, want)
		}
	}
}

func mustCreate(tb testing.TB, m *zone.Manager, origin string) {
	tb.Helper()
	soa := &zone.SOARecord{MName: "ns." + origin, RName: "h." + origin, Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}
	if err := m.CreateZone(origin, 300, soa, testNS); err != nil {
		tb.Fatalf("CreateZone(%s): %v", origin, err)
	}
}

var testNS = []zone.NSRecord{{NSDName: "ns1.zt.org."}}

func mustGet(t *testing.T, m *zone.Manager, origin string) *zone.Zone {
	t.Helper()
	z, ok := m.Get(origin)
	if !ok {
		t.Fatalf("zone %s missing", origin)
	}
	return z
}

func BenchmarkMultiZoneProviderFindZones(b *testing.B) {
	mgr := zone.NewManager()
	for i := 0; i < 50; i++ {
		origin := fmt.Sprintf("z%d.zt.org.", i)
		mustCreate(b, mgr, origin)
	}
	mp := NewMultiZoneProvider(nil, mgr, nil, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(mp.FindZones("www.z7.zt.org.")) != 1 {
			b.Fatal("wrong match count")
		}
	}
}

// FindZones runs for every query: it may allocate the result slice and
// nothing else (no per-provider slice, closure or captured variable).
func TestFindZonesAllocations(t *testing.T) {
	mgr := zone.NewManager()
	for i := 0; i < 10; i++ {
		mustCreate(t, mgr, fmt.Sprintf("z%d.zt.org.", i))
	}
	mp := NewMultiZoneProvider(nil, mgr, nil, nil)

	hit := testing.AllocsPerRun(200, func() {
		if len(mp.FindZones("www.z3.zt.org.")) != 1 {
			t.Fatal("expected one match")
		}
	})
	if hit > 1 {
		t.Errorf("matching query allocates %v times, want <= 1", hit)
	}
	miss := testing.AllocsPerRun(200, func() {
		if mp.FindZones("www.other.example.") != nil {
			t.Fatal("expected no match")
		}
	})
	if miss != 0 {
		t.Errorf("non-matching query allocates %v times, want 0", miss)
	}
}
