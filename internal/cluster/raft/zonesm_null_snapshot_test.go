package raft

import "testing"

func TestZoneStateMachineRestoreRejectsNullSnapshot(t *testing.T) {
	cases := map[string]string{
		"null root":        `null`,
		"null zone":        `{"broken.test.":null}`,
		"null records map": `{"broken.test.":{"Zone":"broken.test.","Records":null,"Modified":false}}`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			sm := NewZoneStateMachine()
			if err := sm.applyCommand(ZoneCommand{
				Type:   "add_record",
				Zone:   "stable.test.",
				Name:   "www.stable.test.",
				RRType: 1,
				RData:  []string{"192.0.2.20"},
			}); err != nil {
				t.Fatalf("seed state: %v", err)
			}

			if err := sm.Restore([]byte(input)); err == nil {
				t.Fatal("accepted snapshot containing null state")
			}
			if got := sm.GetRecords("stable.test."); len(got) != 1 {
				t.Fatalf("failed restore changed prior state: %#v", got)
			}
		})
	}
}
