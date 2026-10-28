package zone

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

// GetRecords without a name lists the whole zone in a fixed order — apex
// first, then by owner name — so a listing capped by the API shows the same
// records every time (F763).
func TestGetRecordsAllIsOrdered(t *testing.T) {
	m := NewManager()
	soa := &SOARecord{Name: "o.test.", TTL: 300, MName: "ns1.o.test.", RName: "h.o.test.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}
	if err := m.CreateZone("o.test", 300, soa, []NSRecord{{Name: "o.test.", TTL: 300, NSDName: "ns1.o.test."}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		if err := m.AddRecord("o.test", Record{Name: fmt.Sprintf("h%02d.o.test.", (i*7)%40), Type: "A", TTL: 300, Class: "IN", RData: fmt.Sprintf("192.0.2.%d", i+1)}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := m.GetRecords("o.test", "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, _ := m.GetRecords("o.test", "")
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("listing order changed between calls (round %d)", i)
		}
	}
	if first[0].Name != "o.test." {
		t.Errorf("first owner %q, want the apex", first[0].Name)
	}
	var rest []string
	for _, r := range first {
		if r.Name != "o.test." {
			rest = append(rest, r.Name)
		}
	}
	if !sort.StringsAreSorted(rest) {
		t.Errorf("owners after the apex are not sorted: %v", rest)
	}
}
