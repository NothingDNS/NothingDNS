package raft

import (
	"os"
	"path/filepath"
	"testing"
)

// writeRound035CorruptHardState writes a hardstate file whose magic does not
// match hardStateMagic (0x52485354 "RHST"), which loadHardState must report
// as corruption.
func writeRound035CorruptHardState(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	bad := []byte("BADMAGIC-rest-of-an-old-hardstate-file")
	if err := os.WriteFile(filepath.Join(dir, hardStateFileName), bad, 0600); err != nil {
		t.Fatal(err)
	}
}

// TestRound035CorruptHardStateRefusesBoot pins the fail-closed boot contract
// (Raft §5.1/§5.4): a node whose durable (term, votedFor) pair is unreadable
// must NOT boot as a fresh node. Booting fresh forgets the previous term's
// vote and can grant a second vote in that same term — a split-brain hazard.
// Contract basis: raft/wal.go treats durable-state corruption as fatal
// (ErrWALCorrupt, etcd-style); persistHardStateLocked fails Raft transitions
// closed; hardstate_test.go pins loadHardState returning errors on corrupt
// files. NewNode previously swallowed that error (`if hs, err := ...; err == nil`)
// and silently booted at term 0.
func TestRound035CorruptHardStateRefusesBoot(t *testing.T) {
	dir := t.TempDir()
	writeRound035CorruptHardState(t, dir)

	n, err := NewNode(Config{NodeID: "n1", DataDir: dir}, nil, nil)
	if err == nil {
		t.Fatalf("FAIL: NewNode booted on corrupt hardstate (term=%d votedFor=%q) — must refuse boot (election-safety)", n.currentTerm, n.votedFor)
	}
	if n != nil {
		t.Fatalf("FAIL: NewNode returned a node alongside an error: %v", err)
	}
}

// TestRound035MissingHardStateBootsFresh_Control: a fresh data dir has no
// hardstate file — boot must succeed with zeroed term and no vote.
func TestRound035MissingHardStateBootsFresh_Control(t *testing.T) {
	dir := t.TempDir()

	n, err := NewNode(Config{NodeID: "n1", DataDir: dir}, nil, nil)
	if err != nil {
		t.Fatalf("FAIL: fresh dir must boot without error: %v", err)
	}
	if n.currentTerm != 0 || n.votedFor != "" {
		t.Fatalf("FAIL: fresh boot must be term 0 / empty vote, got term=%d votedFor=%q", n.currentTerm, n.votedFor)
	}
}

// TestRound035ValidHardStateIsRestored_Control: a well-formed hardstate file
// must still be restored — the fail-closed fix must not turn every boot into
// a refusal.
func TestRound035ValidHardStateIsRestored_Control(t *testing.T) {
	dir := t.TempDir()
	if err := saveHardState(dir, HardState{CurrentTerm: 7, VotedFor: "candidate-9"}); err != nil {
		t.Fatalf("seed hardstate: %v", err)
	}

	n, err := NewNode(Config{NodeID: "n1", DataDir: dir}, nil, nil)
	if err != nil {
		t.Fatalf("FAIL: valid hardstate must boot without error: %v", err)
	}
	if n.currentTerm != 7 || n.votedFor != "candidate-9" {
		t.Fatalf("FAIL: hardstate not restored: term=%d votedFor=%q, want 7/candidate-9", n.currentTerm, n.votedFor)
	}
}
