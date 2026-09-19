package protocol

import (
	"reflect"
	"runtime/debug"
	"testing"
)

// TestQuestionDoubleReleaseDoesNotAliasPooledStructs guards the
// Question.Release ownership contract: Release can run twice on one shared
// *Question — reply() and the BADCOOKIE/DoH-WS writers attach the query's
// Questions slice to the response, and both messages are Released. The
// struct must NOT be recycled into questionPool: the double Put aliased the
// struct across unrelated acquisitions (consumer 2 observed consumer 1's
// QType) until struct recycling was removed.
func TestQuestionDoubleReleaseDoesNotAliasPooledStructs(t *testing.T) {
	// Determinism: keep sync.Pool state stable for the acquisition probes.
	old := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(old)

	q, err := NewQuestion("shared.example.com.", TypeA, ClassIN)
	if err != nil {
		t.Fatalf("NewQuestion: %v", err)
	}

	q.Release() // owner A — the query message's Release
	q.Release() // owner B — the response's Release (shared Questions slice)

	qa, err := NewQuestion("a.example.com.", TypeA, ClassIN)
	if err != nil {
		t.Fatalf("NewQuestion(a): %v", err)
	}
	qb, err := NewQuestion("b.example.com.", TypeAAAA, ClassIN)
	if err != nil {
		t.Fatalf("NewQuestion(b): %v", err)
	}

	if reflect.ValueOf(qa).Pointer() == reflect.ValueOf(qb).Pointer() {
		t.Fatal("double Release aliased question structs: two acquisitions share one *Question")
	}

	// No cross-consumer clobber through an aliased struct.
	qa.QType = TypeTXT
	if qb.QType != TypeAAAA {
		t.Errorf("qb.QType = %d, want %d (consumer 2 observes consumer 1's write)", qb.QType, TypeAAAA)
	}
}
