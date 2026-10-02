package raft

// HardState persistence is the foundation of Raft election safety;
// it must survive crashes intact. These tests exercise the
// load/save round-trip, the empty-dataDir guard, the
// missing-file = zero-state convention, and the magic-mismatch
// rejection (which is the corruption-detection backstop).

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHardStatePath(t *testing.T) {
	got := hardStatePath("/tmp/foo")
	want := filepath.Join("/tmp/foo", "raft-hardstate.bin")
	if got != want {
		t.Errorf("hardStatePath = %q, want %q", got, want)
	}
}

func TestLoadHardState_MissingFile_ReturnsZeroState(t *testing.T) {
	dir := t.TempDir()
	hs, err := loadHardState(dir)
	if err != nil {
		t.Fatalf("loadHardState fresh dir: %v", err)
	}
	if hs.CurrentTerm != 0 || hs.VotedFor != "" {
		t.Errorf("fresh-dir HardState = %+v, want zero", hs)
	}
}

func TestLoadHardState_EmptyDataDir_Skips(t *testing.T) {
	hs, err := loadHardState("")
	if err != nil {
		t.Fatalf("empty dataDir should return zero, not error: %v", err)
	}
	if hs.CurrentTerm != 0 || hs.VotedFor != "" {
		t.Errorf("HardState = %+v, want zero", hs)
	}
}

func TestSaveAndLoadHardState_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	orig := HardState{CurrentTerm: 42, VotedFor: "node-7"}
	if err := saveHardState(dir, orig); err != nil {
		t.Fatalf("saveHardState: %v", err)
	}
	got, err := loadHardState(dir)
	if err != nil {
		t.Fatalf("loadHardState: %v", err)
	}
	if got != orig {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, orig)
	}
}

func TestWriteHardStateCompletesPartialWrites(t *testing.T) {
	dir := t.TempDir()
	orig := HardState{CurrentTerm: 99, VotedFor: "node-partial"}
	writer := &chunkedWriter{maxWrite: 2}

	if err := writeHardState(writer, orig); err != nil {
		t.Fatalf("writeHardState: %v", err)
	}
	if writer.calls < 2 {
		t.Fatalf("chunked writer should require multiple writes, got %d", writer.calls)
	}
	if err := os.WriteFile(hardStatePath(dir), writer.buf.Bytes(), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := loadHardState(dir)
	if err != nil {
		t.Fatalf("loadHardState: %v", err)
	}
	if got != orig {
		t.Fatalf("HardState = %+v, want %+v", got, orig)
	}
}

func TestSaveHardState_EmptyVotedFor(t *testing.T) {
	// votedFor == "" must serialize as zero-length and round-trip.
	dir := t.TempDir()
	orig := HardState{CurrentTerm: 1}
	if err := saveHardState(dir, orig); err != nil {
		t.Fatalf("saveHardState: %v", err)
	}
	got, err := loadHardState(dir)
	if err != nil {
		t.Fatalf("loadHardState: %v", err)
	}
	if got != orig {
		t.Errorf("round-trip with empty votedFor: got %+v, want %+v", got, orig)
	}
}

func TestSaveHardState_EmptyDataDir_Refused(t *testing.T) {
	// saveHardState refuses to silently no-op on an empty dataDir;
	// that would mask configuration bugs that lose election safety.
	if err := saveHardState("", HardState{CurrentTerm: 1}); err == nil {
		t.Error("expected error for empty dataDir")
	}
}

func TestSaveHardState_VotedForLengthLimit(t *testing.T) {
	dir := t.TempDir()
	maxVotedFor := strings.Repeat("n", maxHardStateVotedForLen)
	if err := saveHardState(dir, HardState{CurrentTerm: 1, VotedFor: NodeID(maxVotedFor)}); err != nil {
		t.Fatalf("saveHardState should accept max-length votedFor: %v", err)
	}
	got, err := loadHardState(dir)
	if err != nil {
		t.Fatalf("loadHardState max-length votedFor: %v", err)
	}
	if got.VotedFor != NodeID(maxVotedFor) {
		t.Fatalf("VotedFor length %d, want %d", len(got.VotedFor), len(maxVotedFor))
	}

	tooLong := strings.Repeat("n", maxHardStateVotedForLen+1)
	err = saveHardState(dir, HardState{CurrentTerm: 2, VotedFor: NodeID(tooLong)})
	if err == nil {
		t.Fatal("saveHardState accepted votedFor value that loadHardState rejects")
	}
	if !strings.Contains(err.Error(), "hardstate votedFor too large") {
		t.Fatalf("saveHardState error = %v, want votedFor too large", err)
	}

	got, err = loadHardState(dir)
	if err != nil {
		t.Fatalf("loadHardState after rejected save: %v", err)
	}
	if got.CurrentTerm != 1 || got.VotedFor != NodeID(maxVotedFor) {
		t.Fatalf("rejected save should not replace prior hardstate, got %+v", got)
	}
}

func TestSaveHardState_ReturnsParentDirFsyncError(t *testing.T) {
	originalSyncParentDir := syncHardStateParentDir
	syncHardStateParentDir = func(string) error {
		return errors.New("dir sync failed")
	}
	t.Cleanup(func() { syncHardStateParentDir = originalSyncParentDir })

	err := saveHardState(t.TempDir(), HardState{CurrentTerm: 1, VotedFor: "node-1"})
	if err == nil {
		t.Fatal("saveHardState should return parent directory fsync error")
	}
	if !strings.Contains(err.Error(), "fsync hardstate dir") {
		t.Fatalf("saveHardState error should include parent directory fsync context, got: %v", err)
	}
}

func TestVoteRequestRejectsWhenHardStatePersistenceFails(t *testing.T) {
	originalSyncParentDir := syncHardStateParentDir
	syncHardStateParentDir = func(string) error {
		return errors.New("dir sync failed")
	}
	t.Cleanup(func() { syncHardStateParentDir = originalSyncParentDir })

	node, _ := NewNode(Config{
		NodeID:  "node-1",
		DataDir: t.TempDir(),
	}, nil, nil)

	resp := node.HandleVoteRequest(VoteRequest{
		Term:         1,
		CandidateID:  "candidate-1",
		LastLogIndex: 0,
		LastLogTerm:  0,
	})
	if resp.VoteGranted {
		t.Fatal("vote should not be granted when HardState cannot be made durable")
	}
	if node.currentTerm != 0 {
		t.Fatalf("currentTerm = %d, want unchanged 0", node.currentTerm)
	}
	if node.votedFor != "" {
		t.Fatalf("votedFor = %q, want unchanged empty value", node.votedFor)
	}
}

func TestLoadHardState_MagicMismatch_Rejected(t *testing.T) {
	dir := t.TempDir()
	// Drop a file with the right name but wrong magic.
	path := hardStatePath(dir)
	if err := os.WriteFile(path, []byte("XXXX\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := loadHardState(dir); err == nil {
		t.Error("expected error for bad magic")
	}
}

func TestLoadHardState_TruncatedHeader_Rejected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(hardStatePath(dir), []byte("RHST"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := loadHardState(dir); err == nil {
		t.Error("expected error for truncated header")
	}
}

func TestLoadHardState_TruncatedVotedFor_Rejected(t *testing.T) {
	dir := t.TempDir()
	// Magic + term=0 + votedForLen=10 but no body bytes.
	body := []byte{
		'R', 'H', 'S', 'T',
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 10,
	}
	if err := os.WriteFile(hardStatePath(dir), body, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := loadHardState(dir); err == nil {
		t.Error("expected error for truncated votedFor body")
	}
}

func TestSaveHardState_Overwrite(t *testing.T) {
	// Save twice — the second must overwrite the first atomically.
	dir := t.TempDir()
	if err := saveHardState(dir, HardState{CurrentTerm: 1, VotedFor: "a"}); err != nil {
		t.Fatalf("saveHardState 1: %v", err)
	}
	if err := saveHardState(dir, HardState{CurrentTerm: 2, VotedFor: "b"}); err != nil {
		t.Fatalf("saveHardState 2: %v", err)
	}
	got, err := loadHardState(dir)
	if err != nil {
		t.Fatalf("loadHardState: %v", err)
	}
	if got.CurrentTerm != 2 || got.VotedFor != "b" {
		t.Errorf("after overwrite: %+v, want {2 b}", got)
	}
}
