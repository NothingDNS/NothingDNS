package transfer

import (
	"testing"
	"time"
)

func TestKVJournalStoreSeparatesSanitizationCollisions(t *testing.T) {
	store := NewKVJournalStore(t.TempDir())
	if store.zoneDir("a.b.") == store.zoneDir("a_b.") {
		t.Fatal("distinct zone names share a journal directory")
	}
	if err := store.SaveEntry("a.b.", &IXFRJournalEntry{Serial: 1, Timestamp: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveEntry("a_b.", &IXFRJournalEntry{Serial: 2, Timestamp: time.Unix(2, 0)}); err != nil {
		t.Fatal(err)
	}

	entries, err := store.LoadEntries("a.b.")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Serial != 1 {
		t.Fatalf("a.b. journal crossed zone boundary: %#v", entries)
	}
}
