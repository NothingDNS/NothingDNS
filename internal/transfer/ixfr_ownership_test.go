package transfer

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestIXFRServerRecordChangeOwnsInputSlices(t *testing.T) {
	server := NewIXFRServer(nil)
	added := []zone.RecordChange{{Name: "added.example.", RData: "192.0.2.1"}}
	deleted := []zone.RecordChange{{Name: "deleted.example.", RData: "192.0.2.2"}}

	server.RecordChange("example.", 1, 2, added, deleted)
	added[0] = zone.RecordChange{Name: "mutated-added.example.", RData: "203.0.113.1"}
	deleted[0] = zone.RecordChange{Name: "mutated-deleted.example.", RData: "203.0.113.2"}

	entry := server.journals["example."][0]
	if got := entry.Added[0].Name; got != "added.example." {
		t.Fatalf("recorded addition changed with caller slice: got %q", got)
	}
	if got := entry.Deleted[0].Name; got != "deleted.example." {
		t.Fatalf("recorded deletion changed with caller slice: got %q", got)
	}
}
