package protocol

import (
	"reflect"
	"runtime/debug"
	"testing"
)

// TestResourceRecordDoubleReleaseDoesNotAliasPooledStructs guards the
// ResourceRecord.Release ownership contract: Release can run twice on one
// shared *ResourceRecord (records aliased across messages or sections, and
// both messages are Released). The struct must NOT be recycled into
// resourceRecordPool — the double Put aliased the struct across unrelated
// acquisitions (consumer 2 observed consumer 1's Type and TTL) until struct
// recycling was removed.
func TestResourceRecordDoubleReleaseDoesNotAliasPooledStructs(t *testing.T) {
	// Determinism: keep sync.Pool state stable for the acquisition probes.
	old := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(old)

	rr, err := NewResourceRecord("shared.example.com.", TypeA, ClassIN, 300, &RDataA{Address: [4]byte{192, 0, 2, 1}})
	if err != nil {
		t.Fatalf("NewResourceRecord: %v", err)
	}

	rr.Release() // owner A — its message's Release
	rr.Release() // owner B — the shared pointer's second Release

	ra, err := NewResourceRecord("a.example.com.", TypeA, ClassIN, 300, &RDataA{Address: [4]byte{203, 0, 113, 10}})
	if err != nil {
		t.Fatalf("NewResourceRecord(a): %v", err)
	}
	rb, err := NewResourceRecord("b.example.com.", TypeAAAA, ClassIN, 300, &RDataAAAA{Address: [16]byte{0x20, 0x01, 0xdb, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})
	if err != nil {
		t.Fatalf("NewResourceRecord(b): %v", err)
	}

	if reflect.ValueOf(ra).Pointer() == reflect.ValueOf(rb).Pointer() {
		t.Fatal("double Release aliased resourceRecordPool structs: two acquisitions share one *ResourceRecord")
	}

	// No cross-owner clobber through an aliased struct.
	ra.Type = TypeTXT
	ra.TTL = 77
	if rb.Type != TypeAAAA || rb.TTL != 300 {
		t.Errorf("rb.Type = %d, rb.TTL = %d; consumer 2 observes consumer 1's write", rb.Type, rb.TTL)
	}
}
