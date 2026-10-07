package raft

// F172 regression: a snapshot a follower receives via InstallSnapshot must be
// persisted before the install compacts the WAL. Otherwise a restarted
// follower boots with lastSnapshot=0 over a WAL that begins after the
// snapshot index, misaligning every log index (it reports a short log and can
// grant votes to candidates missing committed entries) and losing the
// snapshot's state-machine contents.

import (
	"errors"
	"testing"

	"github.com/nothingdns/nothingdns/internal/util"
)

const f172Peer NodeID = "ldr"

func f172NewFollower(t *testing.T, dir string, st *testZoneStore) *ClusterIntegration {
	t.Helper()
	ci, err := NewClusterIntegration("f1", []NodeID{f172Peer}, map[NodeID]string{f172Peer: "127.0.0.1:1"},
		"127.0.0.1:0", dir, "", "", nil, util.DefaultLogger())
	if err != nil {
		t.Fatalf("NewClusterIntegration: %v", err)
	}
	ci.SetApplyHook(func(c ZoneCommand) { st.apply(c) })
	ci.SetSnapshotFns(st.snapshot, st.restore)
	return ci
}

func f172Entries(from, to Index) []entry {
	cmd := []byte(`{"type":"add_record","zone":"z.","name":"a","rrtype_str":"A","rdata":["192.0.2.1"]}`)
	var es []entry
	for i := from; i <= to; i++ {
		es = append(es, entry{Index: i, Term: 1, Type: EntryNormal, Command: cmd})
	}
	return es
}

func f172Append(t *testing.T, ci *ClusterIntegration, prev Index, from, to Index) {
	t.Helper()
	prevTerm := Term(0)
	if prev > 0 {
		prevTerm = 1
	}
	r := ci.node.HandleAppendRequest(AppendRequest{Term: 1, LeaderID: f172Peer, PrevLogIndex: prev, PrevLogTerm: prevTerm,
		Entries: f172Entries(from, to), LeaderCommit: to})
	if !r.Success {
		t.Fatalf("append %d..%d after %d refused: %+v", from, to, prev, r)
	}
}

type f172State struct {
	lastSnapshot, lastIndex Index
	lastTerm                Term
	tailOK                  bool
}

func f172Restart(t *testing.T, dir string, st *testZoneStore, wantTail Index) f172State {
	t.Helper()
	ci := f172NewFollower(t, dir, st)
	defer ci.Stop()
	ci.bootstrapState()
	ci.node.mu.Lock()
	defer ci.node.mu.Unlock()
	s := f172State{lastSnapshot: ci.node.lastSnapshot, lastIndex: ci.node.lastIndex()}
	s.lastTerm, s.tailOK = ci.node.entryTerm(wantTail)
	return s
}

func TestFollowerInstallSnapshot_PersistedAcrossRestart(t *testing.T) {
	for _, internal := range []bool{false, true} {
		name := "rpc"
		if internal {
			name = "internal"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			st := newTestZoneStore()
			ci := f172NewFollower(t, dir, st)
			f172Append(t, ci, 0, 1, 3)
			req := SnapshotRequest{Term: 1, LeaderID: f172Peer, Data: []byte(`{"snap|key|A":"192.0.2.99"}`), LastIndex: 10, LastTerm: 1}
			if internal {
				ci.node.handleSnapshotRequest(req)
			} else if r := ci.node.HandleSnapshotRequest(req); !r.Success {
				t.Fatal("snapshot refused")
			}
			f172Append(t, ci, 10, 11, 12)
			// A second, later snapshot supersedes the first.
			req2 := SnapshotRequest{Term: 1, LeaderID: f172Peer, Data: []byte(`{"snap2|key|A":"192.0.2.98"}`), LastIndex: 20, LastTerm: 1}
			if internal {
				ci.node.handleSnapshotRequest(req2)
			} else if r := ci.node.HandleSnapshotRequest(req2); !r.Success {
				t.Fatal("second snapshot refused")
			}
			f172Append(t, ci, 20, 21, 22)
			// A delayed duplicate of the first snapshot must not regress the
			// persisted one.
			if r := ci.node.HandleSnapshotRequest(req); !r.Success {
				t.Fatal("duplicate snapshot not ACKed")
			}
			if err := ci.Stop(); err != nil {
				t.Fatal(err)
			}

			st2 := newTestZoneStore()
			s := f172Restart(t, dir, st2, 22)
			if s.lastSnapshot != 20 || s.lastIndex != 22 || !s.tailOK || s.lastTerm != 1 {
				t.Fatalf("after restart: lastSnapshot=%d lastIndex=%d entryTerm(22)=(%d,%v); want 20, 22, (1,true)",
					s.lastSnapshot, s.lastIndex, s.lastTerm, s.tailOK)
			}
			if v, ok := st2.get("snap2|key|A"); !ok || v != "192.0.2.98" {
				t.Fatalf("snapshot state not restored at boot (present=%v val=%q)", ok, v)
			}
			if _, ok := st2.get("snap|key|A"); ok {
				t.Fatal("restore merged a superseded snapshot's state")
			}
		})
	}
}

func TestFollowerInstallSnapshot_SaveFailureRefusesInstall(t *testing.T) {
	dir := t.TempDir()
	st := newTestZoneStore()
	ci := f172NewFollower(t, dir, st)
	defer ci.Stop()
	f172Append(t, ci, 0, 1, 3)
	ci.node.snapshotSaver = func(*Snapshot) error { return errors.New("injected disk failure") }

	r := ci.node.HandleSnapshotRequest(SnapshotRequest{Term: 1, LeaderID: f172Peer, Data: []byte(`{"k|k|A":"v"}`), LastIndex: 10, LastTerm: 1})
	if r.Success {
		t.Fatal("install ACKed although the snapshot could not be persisted")
	}
	ci.node.mu.Lock()
	ls, li := ci.node.lastSnapshot, ci.node.lastIndex()
	ci.node.mu.Unlock()
	if ls != 0 || li != 3 {
		t.Fatalf("failed install mutated node state: lastSnapshot=%d lastIndex=%d", ls, li)
	}
	if _, ok := st.get("k|k|A"); ok {
		t.Fatal("failed install restored the state machine")
	}
	walEntries, err := ci.wal.ReadAll()
	if err != nil || len(walEntries) != 3 {
		t.Fatalf("failed install compacted the WAL: %d entries, err=%v", len(walEntries), err)
	}
}
