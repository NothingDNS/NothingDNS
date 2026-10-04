package raft

import (
	"bytes"
	"testing"
)

func TestSnapshotterZeroIndexRoundTrip(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[encrypted], func(t *testing.T) {
			var key []byte
			if encrypted {
				key = bytes.Repeat([]byte{1}, 32)
			}
			s, err := NewSnapshotterEncrypted(t.TempDir(), key)
			if err != nil {
				t.Fatal(err)
			}
			empty, err := s.Load()
			if err != nil || empty != nil {
				t.Fatalf("empty load=%v, %v", empty, err)
			}
			want := &Snapshot{Index: 0, Data: []byte("initial state"), Membership: []NodeID{"node1"}}
			if err = s.Save(want); err != nil {
				t.Fatal(err)
			}
			got, err := s.Load()
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || got.Index != 0 || !bytes.Equal(got.Data, want.Data) {
				t.Fatalf("zero snapshot=%v", got)
			}
			for _, index := range []Index{2, 1} {
				if err = s.Save(&Snapshot{Index: index, Data: []byte("later state")}); err != nil {
					t.Fatal(err)
				}
			}
			got, err = s.Load()
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || got.Index != 2 {
				t.Fatalf("latest snapshot=%v, want index 2", got)
			}
		})
	}
}
