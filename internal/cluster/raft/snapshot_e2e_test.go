package raft

// End-to-end snapshot test over the real TCP transport: a leader holds state
// that never went through the Raft log (a "disk-loaded" zone), takes a
// snapshot, and a FRESH follower that joins afterwards receives the full state
// via InstallSnapshot — proving both the InstallSnapshot send/receive path and
// that out-of-log (disk) state replicates to a new node.

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// testZoneStore is a minimal stand-in for the real zone store, exercising the
// snapshot pipeline without pulling in the zone package.
type testZoneStore struct {
	mu sync.Mutex
	m  map[string]string
}

func newTestZoneStore() *testZoneStore { return &testZoneStore{m: map[string]string{}} }

func key(cmd ZoneCommand) string { return cmd.Zone + "|" + cmd.Name + "|" + cmd.RRTypeStr }

func (s *testZoneStore) apply(cmd ZoneCommand) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch cmd.Type {
	case "add_record":
		if len(cmd.RData) > 0 {
			s.m[key(cmd)] = cmd.RData[0]
		}
	case "del_record":
		delete(s.m, key(cmd))
	}
}

func (s *testZoneStore) snapshot() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Marshal(s.m)
}

func (s *testZoneStore) restore(data []byte) error {
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	s.mu.Lock()
	s.m = m
	s.mu.Unlock()
	return nil
}

func (s *testZoneStore) get(k string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	return v, ok
}

func (s *testZoneStore) putRaw(k, v string) { // simulate disk-loaded state (not via Raft)
	s.mu.Lock()
	s.m[k] = v
	s.mu.Unlock()
}

func TestSnapshot_FreshFollowerGetsFullStateViaInstallSnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-node RPC snapshot test skipped in -short mode")
	}

	addrs := []string{freeTCPAddr(t), freeTCPAddr(t), freeTCPAddr(t)}
	ids := []NodeID{NodeID(addrs[0]), NodeID(addrs[1]), NodeID(addrs[2])}
	stores := map[NodeID]*testZoneStore{}
	cis := map[NodeID]*ClusterIntegration{}

	for i, id := range ids {
		var peers []NodeID
		for _, o := range ids {
			if o != id {
				peers = append(peers, o)
			}
		}
		ci, err := NewClusterIntegration(id, peers, nil, addrs[i], t.TempDir(), "", "", nil, util.DefaultLogger())
		if err != nil {
			t.Fatalf("NewClusterIntegration %s: %v", id, err)
		}
		st := newTestZoneStore()
		stores[id] = st
		ci.SetApplyHook(func(c ZoneCommand) { st.apply(c) })
		ci.SetSnapshotFns(st.snapshot, st.restore)
		cis[id] = ci
	}
	defer func() {
		for _, ci := range cis {
			ci.Stop()
		}
	}()

	for _, id := range ids {
		if err := cis[id].Start(); err != nil {
			t.Fatalf("start %s: %v", id, err)
		}
	}

	// Wait for a leader and commit a record through it. An early election can
	// still be settling (a split vote or a stepped-down leader), so retry
	// against whichever node currently leads.
	const diskKey = "example.com.|disk|A"
	var leader *ClusterIntegration
	var leaderID NodeID
	var proposeErr error
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		leader = nil
		for _, id := range ids {
			if cis[id].IsLeader() {
				leader, leaderID = cis[id], id
			}
		}
		if leader == nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}

		// 1) A zone that exists on the leader but NEVER went through Raft (as
		//    if loaded from disk at boot) — present ONLY on the leader's store.
		stores[leaderID].putRaw(diskKey, "192.0.2.9")

		// 2) A normal record via Raft so the applied index advances.
		proposeErr = leader.ProposeZoneChangeWait(ZoneCommand{
			Type: "add_record", Zone: "example.com.", Name: "www", RRTypeStr: "A", RData: []string{"192.0.2.10"},
		}, 5*time.Second)
		if proposeErr == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if leader == nil {
		t.Fatal("no leader elected")
	}
	if proposeErr != nil {
		t.Fatalf("propose: %v", proposeErr)
	}
	// A retry may have seeded the disk-only key on a node that lost the lead;
	// it must exist only on the final leader so the follower can get it
	// solely through InstallSnapshot.
	for _, id := range ids {
		if id != leaderID {
			st := stores[id]
			st.mu.Lock()
			delete(st.m, diskKey)
			st.mu.Unlock()
		}
	}

	// 3) Snapshot (captures disk zone + applied record) and compact the log.
	leader.takeSnapshot()

	// 4) Pick a follower and simulate it having fallen behind the snapshot
	//    (e.g. its log was lost): reset the leader's view of it to before the
	//    snapshot. The leader can no longer bridge the gap with AppendEntries
	//    (those entries are compacted away) — it must use InstallSnapshot.
	var followerID NodeID
	for _, id := range ids {
		if id != leaderID {
			followerID = id
			break
		}
	}
	ln := leader.node
	ln.mu.Lock()
	ln.nextIndex[followerID] = 1
	ln.matchIndex[followerID] = 0
	term := ln.currentTerm
	ln.mu.Unlock()
	ln.replicateTo(followerID, term)

	// 5) The follower must end up with the disk-loaded zone — which exists in
	//    no Raft log entry, so it could ONLY have arrived via the snapshot.
	caught := false
	wd := time.Now().Add(8 * time.Second)
	for time.Now().Before(wd) {
		if dz, ok := stores[followerID].get(diskKey); ok && dz == "192.0.2.9" {
			caught = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !caught {
		dz, ok := stores[followerID].get(diskKey)
		t.Fatalf("follower %s never received the disk zone via InstallSnapshot (present=%v val=%q)", followerID, ok, dz)
	}
}
