package raft

import (
	"encoding/json"
	"testing"
)

// F499: internal/cluster replicates atomic zone batches as a "create_zone"
// ZoneCommand carrying the batch in Metadata, because a new command type would
// make the ledger return "unknown command type" — which applyWithRetry retries
// forever on a node that predates the batch. Pin that the ledger accepts the
// envelope as a no-op (so this and older ledgers never wedge on it) and still
// rejects genuinely unknown types.
func TestZoneStateMachine_F499_BatchEnvelopeIsLedgerNoOp(t *testing.T) {
	sm := NewZoneStateMachine()
	env, err := json.Marshal(ZoneCommand{Type: "create_zone", Zone: "a.example.",
		Metadata: json.RawMessage(`{"zone_batch":{"v":1,"id":"x","ops":[{"op":"add","name":"www","type":"A","rdata":"192.0.2.9"}]}}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := sm.Apply(entry{Index: 1, Term: 1, Type: EntryNormal, Command: env}); err != nil {
		t.Fatalf("ledger rejected the batch envelope: %v", err)
	}
	if got := sm.GetZones(); len(got) != 0 {
		t.Fatalf("ledger modelled the envelope: zones=%v", got)
	}
	var decoded ZoneCommand
	if err := json.Unmarshal(env, &decoded); err != nil || len(decoded.Metadata) == 0 {
		t.Fatalf("Metadata not carried through the wire encoding: %v %s", err, decoded.Metadata)
	}
	unknown, _ := json.Marshal(ZoneCommand{Type: "zone_batch", Zone: "a.example."})
	if err := sm.Apply(entry{Index: 2, Term: 1, Type: EntryNormal, Command: unknown}); err == nil {
		t.Fatal("ledger accepted an unknown command type")
	}
}
