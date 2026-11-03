package raft

import "testing"

func TestZoneStateMachineGetRecordsReturnsDeepCopy(t *testing.T) {
	sm := NewZoneStateMachine()
	if err := sm.applyCommand(ZoneCommand{
		Type:   "add_record",
		Zone:   "example.test.",
		Name:   "www.example.test.",
		RRType: 1,
		TTL:    300,
		RData:  []string{"192.0.2.10"},
	}); err != nil {
		t.Fatalf("applyCommand: %v", err)
	}

	got := sm.GetRecords("example.test.")
	if len(got) != 1 || len(got[0].RData) == 0 {
		t.Fatalf("unexpected records: %#v", got)
	}
	got[0].RData[0] = 'X'

	again := sm.GetRecords("example.test.")
	if got := string(again[0].RData); got != "192.0.2.10" {
		t.Fatalf("caller mutation changed state-machine data: got %q", got)
	}
}
