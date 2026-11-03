package raft

import (
	"os"
	"testing"
)

func TestLoadHardState_TrailingDataRejected(t *testing.T) {
	dir := t.TempDir()
	if err := saveHardState(dir, HardState{CurrentTerm: 7, VotedFor: "node-2"}); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(hardStatePath(dir), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0xff}); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := loadHardState(dir); err == nil {
		t.Fatal("accepted hardstate with trailing data")
	}
}
