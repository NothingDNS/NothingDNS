package raft

// Durability tests for the WAL-backed log persister: proposed and
// replicated entries must survive on disk, and a conflicting append must
// rewrite the WAL tail rather than leave stale entries to replay.

import (
	"testing"
)

func openTestWAL(t *testing.T) *WAL {
	t.Helper()
	wal, err := NewWAL(t.TempDir())
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	t.Cleanup(func() { wal.Close() })
	return wal
}

func TestWAL_TruncateAfter(t *testing.T) {
	wal := openTestWAL(t)
	for i := 1; i <= 5; i++ {
		if err := wal.Write(entry{Index: Index(i), Term: 1, Command: []byte{byte(i)}}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := wal.TruncateAfter(3); err != nil {
		t.Fatalf("TruncateAfter: %v", err)
	}
	got, err := wal.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("after truncate len = %d, want 3", len(got))
	}
	for i, e := range got {
		if e.Index != Index(i+1) {
			t.Errorf("entry %d index = %d, want %d", i, e.Index, i+1)
		}
	}
	// New appends land after the kept prefix.
	if err := wal.Write(entry{Index: 4, Term: 2, Command: []byte("new4")}); err != nil {
		t.Fatalf("Write after truncate: %v", err)
	}
	got, _ = wal.ReadAll()
	if len(got) != 4 || got[3].Term != 2 || string(got[3].Command) != "new4" {
		t.Fatalf("post-truncate append not durable: %+v", got)
	}
}

// TestWAL_RewriteDurableAcrossReopen verifies the atomic rewrite (temp+rename)
// actually replaces the canonical WAL file on disk: a fresh NewWAL on the same
// directory must read back exactly the kept entries. The previous in-place
// Truncate(0)+re-append could lose committed entries on a crash mid-rewrite.
func TestWAL_RewriteDurableAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	wal, err := NewWAL(dir)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	for i := 1; i <= 6; i++ {
		if err := wal.Write(entry{Index: Index(i), Term: 1, Command: []byte{byte(i)}}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	// Drop the prefix subsumed by a snapshot (keep indexes > 3).
	if err := wal.CompactBefore(3); err != nil {
		t.Fatalf("CompactBefore: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen the same directory: the renamed file must hold only the suffix.
	reopened, err := NewWAL(dir)
	if err != nil {
		t.Fatalf("reopen NewWAL: %v", err)
	}
	defer reopened.Close()
	got, err := reopened.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll after reopen: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("after compact+reopen len = %d, want 3 (indexes 4,5,6)", len(got))
	}
	for i, e := range got {
		if e.Index != Index(i+4) {
			t.Errorf("entry %d index = %d, want %d", i, e.Index, i+4)
		}
	}
}

func TestNode_ProposePersistsToWAL(t *testing.T) {
	wal := openTestWAL(t)
	n, _ := NewNode(Config{NodeID: "leader"}, nil, &mockTransport{})
	defer n.Stop()
	n.SetLogPersister(wal)
	n.mu.Lock()
	n.state = StateLeader
	n.currentTerm = 1
	n.mu.Unlock()

	for _, c := range []string{"a", "b", "c"} {
		if err := n.Propose([]byte(c), EntryNormal); err != nil {
			t.Fatalf("Propose(%q): %v", c, err)
		}
	}

	got, err := wal.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("WAL has %d entries, want 3", len(got))
	}
	for i, want := range []string{"a", "b", "c"} {
		if string(got[i].Command) != want {
			t.Errorf("WAL entry %d = %q, want %q", i, got[i].Command, want)
		}
		if got[i].Index != Index(i+1) {
			t.Errorf("WAL entry %d index = %d, want %d", i, got[i].Index, i+1)
		}
	}
}

func TestNode_ConflictingAppendRewritesWAL(t *testing.T) {
	wal := openTestWAL(t)
	n, _ := NewNode(Config{NodeID: "follower"}, nil, &mockTransport{})
	defer n.Stop()
	n.SetLogPersister(wal)
	n.mu.Lock()
	n.currentTerm = 1
	n.mu.Unlock()

	// Initial append of two term-1 entries.
	resp := n.HandleAppendRequest(AppendRequest{
		Term: 1, LeaderID: "l", PrevLogIndex: 0,
		Entries: []entry{{Index: 1, Term: 1, Command: []byte("x1")}, {Index: 2, Term: 1, Command: []byte("x2")}},
	})
	if !resp.Success {
		t.Fatal("initial append should succeed")
	}

	// A new leader (term 2) overwrites index 2 with a different entry.
	resp = n.HandleAppendRequest(AppendRequest{
		Term: 2, LeaderID: "l2", PrevLogIndex: 1, PrevLogTerm: 1,
		Entries: []entry{{Index: 2, Term: 2, Command: []byte("y2")}},
	})
	if !resp.Success {
		t.Fatal("conflicting append should succeed after reconciliation")
	}

	got, err := wal.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("WAL has %d entries, want 2", len(got))
	}
	if got[1].Term != 2 || string(got[1].Command) != "y2" {
		t.Errorf("WAL index 2 = {term:%d cmd:%q}, want {2 y2}", got[1].Term, got[1].Command)
	}
}
