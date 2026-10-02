package raft

// A real multi-node Raft harness: several Node instances wired together by
// an in-process transport that routes RPCs straight to peer handlers. This
// exercises the full pipeline — election, AppendEntries replication,
// nextIndex/matchIndex convergence and commit advancement — across nodes,
// which the per-method unit tests cannot. It is the regression backstop for
// the replication-correctness rewrite (PrevLogIndex/MatchIndex/LeaderCommit).

import (
	"context"
	"sync"
	"testing"
	"time"
)

// inMemTransport connects registered Node instances. A node that is not
// registered (or has been deregistered) is unreachable in BOTH directions:
// targets refuse the RPC, and a deregistered node's own outbound RPCs are
// dropped — modelling a crashed/partitioned node, not a half-open link.
type inMemTransport struct {
	mu    sync.RWMutex
	nodes map[NodeID]*Node
}

func newInMemTransport() *inMemTransport {
	return &inMemTransport{nodes: make(map[NodeID]*Node)}
}

func (t *inMemTransport) register(id NodeID, n *Node) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nodes[id] = n
}

func (t *inMemTransport) lookup(peerID NodeID) *Node {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.nodes[peerID]
}

func (t *inMemTransport) SendRequestVote(_ context.Context, peerID NodeID, req VoteRequest) (*VoteResponse, error) {
	n := t.lookup(peerID)
	if n == nil {
		return nil, context.Canceled
	}
	resp := n.HandleVoteRequest(req)
	return &resp, nil
}

func (t *inMemTransport) SendAppendEntries(_ context.Context, peerID NodeID, req AppendRequest) (*AppendResponse, error) {
	n := t.lookup(peerID)
	if n == nil {
		return nil, context.Canceled
	}
	resp := n.HandleAppendRequest(req)
	return &resp, nil
}

func (t *inMemTransport) SendSnapshot(_ context.Context, peerID NodeID, req SnapshotRequest) (*SnapshotResponse, error) {
	n := t.lookup(peerID)
	if n == nil {
		return nil, context.Canceled
	}
	resp := n.HandleSnapshotRequest(req)
	return &resp, nil
}

// newClusterNode builds one node whose peer set is every other id. Fails the
// test if construction fails (e.g. unreadable HardState — fail-closed boot).
func newClusterNode(t *testing.T, id NodeID, ids []NodeID, tr *inMemTransport) *Node {
	peers := make([]NodeID, 0, len(ids)-1)
	for _, other := range ids {
		if other != id {
			peers = append(peers, other)
		}
	}
	cfg := DefaultConfig()
	cfg.NodeID = id
	cfg.HeartbeatInterval = 15 * time.Millisecond
	cfg.ElectionTimeout = 60 * time.Millisecond
	n, err := NewNode(cfg, peers, tr)
	if err != nil {
		t.Fatalf("newClusterNode(%s): %v", id, err)
	}
	return n
}

// waitForLeader polls until exactly one node reports StateLeader, returning
// it. Fails the test on timeout.
func waitForLeader(t *testing.T, nodes []*Node, timeout time.Duration) *Node {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var leaders []*Node
		for _, n := range nodes {
			if n.State() == StateLeader {
				leaders = append(leaders, n)
			}
		}
		if len(leaders) == 1 {
			return leaders[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no single leader elected within %s", timeout)
	return nil
}

// lastIndexUnderLock exposes the snapshot-aware last index for tests.
func (n *Node) lastIndexUnderLock() Index {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.lastIndex()
}

// logCopy reads a node's log under the node lock.
func logCopy(n *Node) []entry {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]entry, len(n.log))
	copy(out, n.log)
	return out
}

// waitUntil polls cond every 5ms until it holds or the timeout elapses.
func waitUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

func TestCluster_ElectsSingleLeader(t *testing.T) {
	ids := []NodeID{"n1", "n2", "n3"}
	tr := newInMemTransport()
	var nodes []*Node
	for _, id := range ids {
		n := newClusterNode(t, id, ids, tr)
		tr.register(id, n)
		nodes = append(nodes, n)
	}
	for _, n := range nodes {
		n.Start()
	}
	defer func() {
		for _, n := range nodes {
			n.Stop()
		}
	}()

	leader := waitForLeader(t, nodes, 3*time.Second)

	// waitForLeader returns as soon as one node becomes leader; followers may
	// still be processing the first heartbeat. Wait for their observable
	// leadership state to catch up before asserting.
	if !waitUntil(3*time.Second, func() bool {
		leaderTerm := leader.Term()
		for _, n := range nodes {
			if n == leader {
				continue
			}
			if n.State() != StateFollower {
				return false
			}
			if n.LeaderID() != leader.config.NodeID {
				return false
			}
			if n.Term() < leaderTerm {
				return false
			}
		}
		return true
	}) {
		for _, n := range nodes {
			t.Logf("%s state=%s leader=%q term=%d", n.config.NodeID, n.State(), n.LeaderID(), n.Term())
		}
		t.Fatalf("followers did not converge on leader %q", leader.config.NodeID)
	}

	// All non-leaders must be followers and agree the cluster has one leader
	// at a term >= the leader's.
	leaderTerm := leader.Term()
	for _, n := range nodes {
		if n == leader {
			continue
		}
		if st := n.State(); st != StateFollower {
			t.Errorf("%s state = %s, want Follower", n.config.NodeID, st)
		}
		if lt := n.LeaderID(); lt != leader.config.NodeID {
			t.Errorf("%s sees leader %q, want %q", n.config.NodeID, lt, leader.config.NodeID)
		}
		if n.Term() < leaderTerm {
			t.Errorf("%s term %d < leader term %d", n.config.NodeID, n.Term(), leaderTerm)
		}
	}
}

func TestCluster_ReplicatesAndCommits(t *testing.T) {
	ids := []NodeID{"n1", "n2", "n3"}
	tr := newInMemTransport()
	var nodes []*Node
	for _, id := range ids {
		n := newClusterNode(t, id, ids, tr)
		tr.register(id, n)
		nodes = append(nodes, n)
	}
	for _, n := range nodes {
		n.Start()
	}
	defer func() {
		for _, n := range nodes {
			n.Stop()
		}
	}()

	leader := waitForLeader(t, nodes, 3*time.Second)

	// Propose three commands. Each must replicate to a quorum and commit
	// on every node.
	cmds := [][]byte{[]byte("alpha"), []byte("bravo"), []byte("charlie")}
	for _, c := range cmds {
		if err := leader.Propose(c, EntryNormal); err != nil {
			t.Fatalf("Propose(%q) failed: %v", c, err)
		}
	}

	// The leader appended a no-op on election (index 1) plus our three
	// commands; the highest index is therefore >= 4.
	target := leader.lastIndexUnderLock()
	if target < 4 {
		t.Fatalf("leader last index = %d, want >= 4", target)
	}

	ok := waitUntil(3*time.Second, func() bool {
		for _, n := range nodes {
			if n.CommitIndex() < target {
				return false
			}
		}
		return true
	})
	if !ok {
		for _, n := range nodes {
			t.Logf("%s commitIndex=%d lastIndex=%d", n.config.NodeID, n.CommitIndex(), n.lastIndexUnderLock())
		}
		t.Fatal("not all nodes reached the target commit index")
	}

	// Every node's committed log prefix must be byte-identical to the
	// leader's — the core safety property.
	leaderLog := logCopy(leader)
	for _, n := range nodes {
		nl := logCopy(n)
		for i := 0; i < int(target); i++ {
			if nl[i].Term != leaderLog[i].Term || string(nl[i].Command) != string(leaderLog[i].Command) {
				t.Errorf("%s log[%d] = {term:%d cmd:%q}, leader = {term:%d cmd:%q}",
					n.config.NodeID, i, nl[i].Term, nl[i].Command, leaderLog[i].Term, leaderLog[i].Command)
			}
		}
	}
}

func TestCluster_RecoveredFollowerCatchesUp(t *testing.T) {
	ids := []NodeID{"n1", "n2", "n3"}
	tr := newInMemTransport()
	nodeByID := map[NodeID]*Node{}
	for _, id := range ids {
		nodeByID[id] = newClusterNode(t, id, ids, tr)
	}

	// Bring up only two nodes — still a quorum of three. The third is
	// created but unregistered (unreachable), modelling a crashed node.
	up := []*Node{nodeByID["n1"], nodeByID["n2"]}
	tr.register("n1", nodeByID["n1"])
	tr.register("n2", nodeByID["n2"])
	for _, n := range up {
		n.Start()
	}
	defer func() {
		for _, id := range ids {
			nodeByID[id].Stop()
		}
	}()

	leader := waitForLeader(t, up, 3*time.Second)

	for _, c := range [][]byte{[]byte("x"), []byte("y"), []byte("z")} {
		if err := leader.Propose(c, EntryNormal); err != nil {
			t.Fatalf("Propose failed: %v", err)
		}
	}
	target := leader.lastIndexUnderLock()

	// Commit proceeds on the two-node quorum despite n3 being absent.
	if !waitUntil(3*time.Second, func() bool { return leader.CommitIndex() >= target }) {
		t.Fatalf("leader did not commit with quorum present (commit=%d target=%d)", leader.CommitIndex(), target)
	}

	// Now the crashed node recovers: register and start it. The leader's
	// heartbeats must back its nextIndex up and stream the whole log to it.
	laggard := nodeByID["n3"]
	tr.register("n3", laggard)
	laggard.Start()

	ok := waitUntil(5*time.Second, func() bool {
		return laggard.CommitIndex() >= target && laggard.lastIndexUnderLock() >= target
	})
	if !ok {
		t.Fatalf("recovered follower did not catch up: commit=%d last=%d target=%d",
			laggard.CommitIndex(), laggard.lastIndexUnderLock(), target)
	}

	leaderLog := logCopy(leader)
	lagLog := logCopy(laggard)
	for i := 0; i < int(target); i++ {
		if lagLog[i].Term != leaderLog[i].Term || string(lagLog[i].Command) != string(leaderLog[i].Command) {
			t.Errorf("recovered log[%d] diverged from leader", i)
		}
	}
}
