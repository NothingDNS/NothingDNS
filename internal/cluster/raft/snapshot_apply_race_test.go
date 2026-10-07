package raft

// F174 regression: the apply loop applies a collected batch of committed
// entries outside the node lock. An InstallSnapshot that lands mid-batch
// restores the zone store to the snapshot state, which already contains and
// supersedes the rest of the batch. The loop used to keep applying the stale
// remainder on top of the restored store (resurrecting records the cluster
// had since deleted) and to rewind appliedIndex below the snapshot.
//
// Ordering is gated with channels only: the apply hook for entry 1 blocks
// until the test has completed the snapshot install, and commitCh is made
// unbuffered so a send returns only once the loop is idle again.

import (
	"errors"
	"fmt"
	"testing"

	"github.com/nothingdns/nothingdns/internal/util"
)

type f174Case struct {
	name          string
	install       bool
	failRestore   bool // the snapshot's restore fails: nothing is superseded
	mutateBefore  bool // entry 1's store mutation lands before the install
	wantStore     map[string]string
	wantApplied   Index
	wantHookCalls int
}

func TestApplyLoop_SnapshotInstalledMidBatch(t *testing.T) {
	snapState := map[string]string{"z.|z|A": "192.0.2.3"}
	all := map[string]string{"z.|x|A": "192.0.2.1", "z.|y|A": "192.0.2.1", "z.|w|A": "192.0.2.1"}
	for _, tc := range []f174Case{
		{name: "no snapshot (control)", wantStore: all, wantApplied: 3, wantHookCalls: 3},
		{name: "install while entry 1 mutation pending", install: true, wantStore: snapState, wantApplied: 5, wantHookCalls: 1},
		{name: "install after entry 1 mutation", install: true, mutateBefore: true, wantStore: snapState, wantApplied: 5, wantHookCalls: 1},
		{name: "failed install supersedes nothing", install: true, failRestore: true, wantStore: all, wantApplied: 3, wantHookCalls: 3},
	} {
		t.Run(tc.name, func(t *testing.T) { f174RunCase(t, tc) })
	}
}

func f174RunCase(t *testing.T, tc f174Case) {
	st := newTestZoneStore()
	ci, err := NewClusterIntegration("f1", []NodeID{"ldr"}, map[NodeID]string{"ldr": "127.0.0.1:1"},
		"127.0.0.1:0", t.TempDir(), "", "", nil, util.DefaultLogger())
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	calls := 0 // only touched by the apply loop until it has stopped
	ci.SetApplyHook(func(c ZoneCommand) {
		calls++
		if calls == 1 {
			if tc.mutateBefore {
				st.apply(c)
			}
			close(entered)
			<-release
			if !tc.mutateBefore {
				st.apply(c)
			}
			return
		}
		st.apply(c)
	})
	restore := st.restore
	if tc.failRestore {
		restore = func([]byte) error { return errors.New("injected restore failure") }
	}
	ci.SetSnapshotFns(st.snapshot, restore)

	add := func(i Index, name string) entry {
		return entry{Index: i, Term: 1, Type: EntryNormal,
			Command: []byte(fmt.Sprintf(`{"type":"add_record","zone":"z.","name":%q,"rrtype_str":"A","rdata":["192.0.2.1"]}`, name))}
	}
	if r := ci.node.HandleAppendRequest(AppendRequest{Term: 1, LeaderID: "ldr",
		Entries: []entry{add(1, "x"), add(2, "y"), add(3, "w")}, LeaderCommit: 3}); !r.Success {
		t.Fatal("append refused")
	}
	ci.node.commitCh = make(chan Commit)
	ci.wg.Add(1)
	go ci.applyLoop()
	ci.node.commitCh <- Commit{}
	<-entered

	if tc.install {
		r := ci.node.HandleSnapshotRequest(SnapshotRequest{Term: 1, LeaderID: "ldr", LastIndex: 5, LastTerm: 1,
			Data: []byte(`{"z.|z|A":"192.0.2.3"}`)})
		if r.Success == tc.failRestore {
			t.Fatalf("snapshot install success=%v, want %v", r.Success, !tc.failRestore)
		}
	}
	close(release)
	ci.node.commitCh <- Commit{} // returns once the batch is drained
	ci.node.commitCh <- Commit{} // and once the follow-up collection is done
	if err := ci.Stop(); err != nil {
		t.Fatal(err)
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.m) != len(tc.wantStore) {
		t.Fatalf("store=%v, want %v", st.m, tc.wantStore)
	}
	for k, v := range tc.wantStore {
		if st.m[k] != v {
			t.Fatalf("store=%v, want %v", st.m, tc.wantStore)
		}
	}
	if ci.appliedIndex != tc.wantApplied {
		t.Fatalf("appliedIndex=%d, want %d", ci.appliedIndex, tc.wantApplied)
	}
	if calls != tc.wantHookCalls {
		t.Fatalf("apply hook ran %d times, want %d", calls, tc.wantHookCalls)
	}
}
