package raft

import (
	"bytes"
	"testing"
)

func TestReadSnapshotRejectsTrailingData(t *testing.T) {
	snapshotter, err := NewSnapshotter(t.TempDir())
	if err != nil {
		t.Fatalf("NewSnapshotter: %v", err)
	}

	var encoded bytes.Buffer
	if err := snapshotter.writePlainSnapshot(&encoded, &Snapshot{
		Index:      7,
		Term:       3,
		LastIndex:  7,
		LastTerm:   3,
		Data:       []byte("state"),
		Membership: []NodeID{"node-a"},
	}); err != nil {
		t.Fatalf("writePlainSnapshot: %v", err)
	}

	encoded.WriteByte(0xff)
	if _, err := snapshotter.readSnapshot(bytes.NewReader(encoded.Bytes())); err == nil {
		t.Fatal("accepted snapshot with trailing data")
	}
}
