package raft

// Regressions for the R22 snapshot handler / boot audit:
//
//   - F157: bootstrapState must refuse to boot on an unreadable snapshot, a
//     failed restore, or a WAL tail that does not continue the snapshot.
//   - F158: InstallSnapshot must keep the log entries following a snapshot
//     whose last entry (index, term) it already holds, and must drop a
//     conflicting tail from the WAL as well as from memory.
//   - F159: takeSnapshot must not compact the WAL when Snapshotter.Save fails.
//   - F160: a current-term InstallSnapshot is leader contact.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nothingdns/nothingdns/internal/util"
)

// --- F157 ---

// r22PrepareBootDir leaves a data dir with WAL entries 1..12 compacted through
// 10 and, when withSnapshot, a snapshot at 10 (encrypted with key if set).
func r22PrepareBootDir(t *testing.T, withSnapshot bool, snapKey string) string {
	t.Helper()
	dir := t.TempDir()
	ci, err := NewClusterIntegration("n1", nil, nil, "127.0.0.1:0", dir, "", snapKey, nil, util.DefaultLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer ci.Stop()
	for i := Index(1); i <= 12; i++ {
		if err := ci.wal.Write(entry{Index: i, Term: 1, Type: EntryNormal, Command: []byte("{}")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := ci.wal.Sync(); err != nil {
		t.Fatal(err)
	}
	if withSnapshot {
		if err := ci.snapshotter.Save(&Snapshot{Index: 10, Term: 1, LastIndex: 10, LastTerm: 1, Data: []byte(`{"z.|a|A":"192.0.2.1"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := ci.wal.CompactBefore(10); err != nil {
		t.Fatal(err)
	}
	return dir
}

func r22Boot(t *testing.T, dir string, restore func([]byte) error) (*ClusterIntegration, *testZoneStore, error) {
	t.Helper()
	st := newTestZoneStore()
	ci, err := NewClusterIntegration("n1", nil, nil, "127.0.0.1:0", dir, "", "", nil, util.DefaultLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ci.Stop() })
	if restore == nil {
		restore = st.restore
	}
	ci.SetSnapshotFns(st.snapshot, restore)
	return ci, st, ci.bootstrapState()
}

func TestBootstrapState_RefusesInconsistentSnapshotState(t *testing.T) {
	t.Run("intact snapshot boots", func(t *testing.T) {
		ci, st, err := r22Boot(t, r22PrepareBootDir(t, true, ""), nil)
		if err != nil {
			t.Fatalf("bootstrapState: %v", err)
		}
		if ci.node.lastSnapshot != 10 || ci.node.lastIndex() != 12 || ci.appliedIndex != 10 || len(st.m) != 1 {
			t.Fatalf("got lastSnapshot=%d lastIndex=%d applied=%d store=%v", ci.node.lastSnapshot, ci.node.lastIndex(), ci.appliedIndex, st.m)
		}
	})
	t.Run("fresh data dir boots", func(t *testing.T) {
		ci, _, err := r22Boot(t, t.TempDir(), nil)
		if err != nil || ci.node.lastIndex() != 0 {
			t.Fatalf("err=%v lastIndex=%d", err, ci.node.lastIndex())
		}
	})
	t.Run("truncated snapshot file", func(t *testing.T) {
		dir := r22PrepareBootDir(t, true, "")
		if err := os.Truncate(filepath.Join(dir, "snapshots", snapFilename(10)), 20); err != nil {
			t.Fatal(err)
		}
		if _, _, err := r22Boot(t, dir, nil); err == nil {
			t.Fatal("booted over an unreadable snapshot")
		}
	})
	t.Run("encrypted snapshot without key", func(t *testing.T) {
		dir := r22PrepareBootDir(t, true, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
		if _, _, err := r22Boot(t, dir, nil); err == nil {
			t.Fatal("booted over an undecryptable snapshot")
		}
	})
	t.Run("restore failure", func(t *testing.T) {
		dir := r22PrepareBootDir(t, true, "")
		if _, _, err := r22Boot(t, dir, func([]byte) error { return errors.New("injected") }); err == nil {
			t.Fatal("booted although the snapshot state was never restored")
		}
	})
	t.Run("snapshot missing over compacted WAL", func(t *testing.T) {
		if _, _, err := r22Boot(t, r22PrepareBootDir(t, false, ""), nil); err == nil {
			t.Fatal("booted with a log gap after index 0")
		}
	})
	t.Run("gap inside WAL tail", func(t *testing.T) {
		dir := t.TempDir()
		w, err := NewWAL(filepath.Join(dir, "raft-wal"))
		if err != nil {
			t.Fatal(err)
		}
		for _, i := range []Index{1, 2, 4} {
			if err := w.Write(entry{Index: i, Term: 1}); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if _, _, err := r22Boot(t, dir, nil); err == nil {
			t.Fatal("booted with a log gap at index 3")
		}
	})
}

// --- F158 ---

type r22FailTruncate struct{ logPersister }

func (r22FailTruncate) TruncateAfter(Index) error { return errors.New("injected truncate failure") }

func TestInstallSnapshot_RetainsMatchingSuffixDropsConflicting(t *testing.T) {
	install := func(ci *ClusterIntegration, internal bool, req SnapshotRequest) bool {
		if internal {
			ci.node.handleSnapshotRequest(req)
			ci.node.mu.Lock()
			defer ci.node.mu.Unlock()
			return ci.node.lastSnapshot == req.LastIndex
		}
		return ci.node.HandleSnapshotRequest(req).Success
	}
	for _, internal := range []bool{false, true} {
		name := "rpc"
		if internal {
			name = "internal"
		}
		t.Run(name, func(t *testing.T) {
			setup := func(t *testing.T) (*ClusterIntegration, string) {
				dir := t.TempDir()
				ci := f172NewFollower(t, dir, newTestZoneStore())
				t.Cleanup(func() { _ = ci.Stop() })
				r := ci.node.HandleAppendRequest(AppendRequest{Term: 1, LeaderID: f172Peer, Entries: f172Entries(1, 15), LeaderCommit: 5})
				if !r.Success || r.MatchIndex != 15 {
					t.Fatalf("setup append: %+v", r)
				}
				return ci, dir
			}
			data := []byte(`{"z.|a|A":"192.0.2.1"}`)
			cases := []struct {
				name                  string
				snapIndex             Index
				snapTerm              Term
				wantLast, wantRestart Index
			}{
				{"matching entry inside log keeps suffix", 10, 1, 15, 15},
				{"matching entry at log end", 15, 1, 15, 15},
				{"conflicting term drops suffix everywhere", 10, 2, 10, 10},
				{"snapshot past log", 20, 1, 20, 20},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					ci, dir := setup(t)
					if !install(ci, internal, SnapshotRequest{Term: 1, LeaderID: f172Peer, LastIndex: tc.snapIndex, LastTerm: tc.snapTerm, Data: data}) {
						t.Fatal("install refused")
					}
					ci.node.mu.Lock()
					last, commit := ci.node.lastIndex(), ci.node.commitIndex
					var suffixTerm Term
					if last > tc.snapIndex {
						suffixTerm, _ = ci.node.entryTerm(last)
					}
					ci.node.mu.Unlock()
					if last != tc.wantLast || commit != tc.snapIndex {
						t.Fatalf("lastIndex=%d commit=%d, want %d/%d", last, commit, tc.wantLast, tc.snapIndex)
					}
					if last > tc.snapIndex && suffixTerm != 1 {
						t.Fatalf("retained suffix has term %d", suffixTerm)
					}
					if tc.wantLast == 15 {
						// The follower still holds 13..15: a candidate ending at
						// 12 is not up to date, one ending at 15 is.
						if v := ci.node.HandleVoteRequest(VoteRequest{Term: 2, CandidateID: "c", LastLogIndex: 12, LastLogTerm: 1}); v.VoteGranted {
							t.Fatal("granted vote to a candidate missing acknowledged entries")
						}
						if v := ci.node.HandleVoteRequest(VoteRequest{Term: 3, CandidateID: "d", LastLogIndex: 15, LastLogTerm: 1}); !v.VoteGranted {
							t.Fatal("refused an up-to-date candidate")
						}
					}
					_ = ci.Stop()
					if got := f172Restart(t, dir, newTestZoneStore(), tc.wantRestart).lastIndex; got != tc.wantRestart {
						t.Fatalf("after restart lastIndex=%d, want %d", got, tc.wantRestart)
					}
				})
			}
			t.Run("conflict truncate failure refuses install", func(t *testing.T) {
				ci, _ := setup(t)
				ci.node.mu.Lock()
				ci.node.persister = r22FailTruncate{ci.node.persister}
				ci.node.mu.Unlock()
				install(ci, internal, SnapshotRequest{Term: 1, LeaderID: f172Peer, LastIndex: 10, LastTerm: 2, Data: data})
				ci.node.mu.Lock()
				defer ci.node.mu.Unlock()
				if ci.node.lastSnapshot != 0 || ci.node.lastIndex() != 15 {
					t.Fatalf("lastSnapshot=%d lastIndex=%d after refused install", ci.node.lastSnapshot, ci.node.lastIndex())
				}
			})
		})
	}
}

// --- F159 ---

func TestTakeSnapshot_SaveFailureKeepsWAL(t *testing.T) {
	dir := t.TempDir()
	st := newTestZoneStore()
	ci, err := NewClusterIntegration("n1", nil, nil, "127.0.0.1:0", dir, "", "", nil, util.DefaultLogger())
	if err != nil {
		t.Fatal(err)
	}
	ci.SetSnapshotFns(st.snapshot, st.restore)
	ci.node.mu.Lock()
	ci.node.currentTerm, ci.node.state = 1, StateLeader
	for i := Index(1); i <= 5; i++ {
		e := entry{Index: i, Term: 1, Type: EntryNormal, Command: []byte("{}")}
		ci.node.log = append(ci.node.log, e)
		if err := ci.wal.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	ci.node.commitIndex, ci.node.lastApplied = 5, 5
	ci.node.mu.Unlock()
	if err := ci.wal.Sync(); err != nil {
		t.Fatal(err)
	}
	ci.appliedIndex = 5

	realDir := ci.snapshotter.snapshotsDir
	ci.snapshotter.snapshotsDir = filepath.Join(dir, "no-such-dir") // Save fails
	ci.takeSnapshot()
	ci.snapshotter.snapshotsDir = realDir
	ci.node.mu.Lock()
	ls, li := ci.node.lastSnapshot, ci.node.lastIndex()
	ci.node.mu.Unlock()
	if ls != 0 || li != 5 {
		t.Fatalf("after failed Save: lastSnapshot=%d lastIndex=%d, want 0/5", ls, li)
	}
	if es, err := ci.wal.ReadAll(); err != nil || len(es) != 5 {
		t.Fatalf("WAL after failed Save: %d entries, err=%v; want 5", len(es), err)
	}

	// The next attempt succeeds and compacts as usual.
	ci.takeSnapshot()
	ci.node.mu.Lock()
	ls = ci.node.lastSnapshot
	ci.node.mu.Unlock()
	if ls != 5 {
		t.Fatalf("after successful Save: lastSnapshot=%d, want 5", ls)
	}
	_ = ci.Stop()

	ci2, _, err := r22Boot(t, dir, nil)
	if err != nil || ci2.node.lastSnapshot != 5 || ci2.node.lastIndex() != 5 {
		t.Fatalf("restart: err=%v lastSnapshot=%d lastIndex=%d", err, ci2.node.lastSnapshot, ci2.node.lastIndex())
	}
}

// --- F160 ---

func TestInstallSnapshot_IsLeaderContact(t *testing.T) {
	newNode := func(t *testing.T, st State) *Node {
		n, err := NewNode(Config{NodeID: "f1"}, []NodeID{"ldr", "c"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		n.currentTerm, n.state = 3, st
		return n
	}
	reset := func(n *Node) bool {
		select {
		case <-n.electionResetCh:
			return true
		default:
			return false
		}
	}
	reqs := map[string]SnapshotRequest{
		"first chunk":        {Term: 3, LeaderID: "ldr", LastIndex: 50, LastTerm: 3, Total: 8, Data: []byte("abcd")},
		"whole snapshot":     {Term: 3, LeaderID: "ldr", LastIndex: 50, LastTerm: 3, Data: []byte("{}")},
		"duplicate (stale)":  {Term: 3, LeaderID: "ldr", LastIndex: 0, LastTerm: 0},
		"higher term":        {Term: 4, LeaderID: "ldr", LastIndex: 50, LastTerm: 4, Data: []byte("{}")},
		"internal handler":   {Term: 3, LeaderID: "ldr", LastIndex: 50, LastTerm: 3, Data: []byte("{}")},
		"older term ignored": {Term: 2, LeaderID: "old", LastIndex: 50, LastTerm: 2, Data: []byte("{}")},
	}
	for name, req := range reqs {
		for _, st := range []State{StateFollower, StateCandidate} {
			t.Run(name+"/"+st.String(), func(t *testing.T) {
				n := newNode(t, st)
				if name == "internal handler" {
					n.handleSnapshotRequest(req)
				} else {
					n.HandleSnapshotRequest(req)
				}
				gotReset := reset(n)
				if name == "older term ignored" {
					if gotReset || n.state != st || n.leaderID != "" {
						t.Fatalf("stale-term snapshot counted as contact: reset=%v state=%s leader=%q", gotReset, n.state, n.leaderID)
					}
					return
				}
				if !gotReset || n.state != StateFollower || n.leaderID != "ldr" {
					t.Fatalf("reset=%v state=%s leader=%q; want true/Follower/ldr", gotReset, n.state, n.leaderID)
				}
			})
		}
	}
}
