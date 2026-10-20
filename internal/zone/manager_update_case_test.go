package zone

import (
	"sort"
	"testing"
)

// TXT data is case-sensitive. UpdateRecord located the record to change with a
// case-insensitive text match, so with two TXT records that differ only in case
// it rewrote whichever came first, not the one named by old_data. (Add and
// DeleteRecordData already compare with RDataEqual, which keeps them apart.)
func TestUpdateRecordMatchesOldDataCaseSensitively(t *testing.T) {
	m, _, _ := newDeleteRecordDataManager(t)
	for _, data := range []string{`"Hello"`, `"hello"`} {
		if err := m.AddRecord("example.com.", Record{Name: "txt", Type: "TXT", TTL: 300, RData: data}); err != nil {
			t.Fatalf("add %s: %v", data, err)
		}
	}

	err := m.UpdateRecord("example.com.", "txt", "TXT", `"hello"`,
		Record{Name: "txt", Type: "TXT", TTL: 300, RData: `"bye"`})
	if err != nil {
		t.Fatal(err)
	}

	got := rdataOf(t, m, "txt", "TXT")
	sort.Strings(got)
	want := []string{`"Hello"`, `"bye"`}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("FAIL: TXT data after updating \"hello\" = %v, want %v", got, want)
	}

	// Control: a name-only type still matches regardless of case.
	if err := m.AddRecord("example.com.", Record{Name: "alias", Type: "CNAME", TTL: 300, RData: "Target.Example.com."}); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateRecord("example.com.", "alias", "CNAME", "target.example.com.",
		Record{Name: "alias", Type: "CNAME", TTL: 300, RData: "new.example.com."}); err != nil {
		t.Fatalf("control: CNAME update by differently-cased old data: %v", err)
	}
}
