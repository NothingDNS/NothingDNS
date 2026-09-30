// Round-007 regression: the Raft broadcast functions must not iterate the
// peer map outside n.mu, because a membership change replaces n.peers under
// that same lock. Unlocked iteration races with the replacement and triggers
// Go's "fatal error: concurrent map iteration and map write".
//
// HISTORY. The original version of this file shipped two tests against a
// test-local `minimalNode` stand-in, one of which ("..._PreFix") deliberately
// iterated its own map without the lock in order to demonstrate the pre-fix
// pattern. That made the test fail under `-race` by construction, forever,
// regardless of production code: it manufactured a race inside the test
// rather than exercising raft. It was also the sole reason the `race` CI job
// stayed red.
//
// Those stand-ins are gone. The test below drives the REAL production method
// on a REAL *Node, raced against the REAL replacement pattern that
// membership.go uses (`n.peers = <new map>` under n.mu). If someone
// reintroduces unlocked iteration into (*Node).snapshotPeerIDs, this test
// fails under `-race`; with the lock in place it is clean.
package raft

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// peerSetFor builds a small peer map. gen varies the membership so the
// writer below is genuinely mutating the map, not rewriting an identical one.
func peerSetFor(gen int) map[NodeID]*Peer {
	return map[NodeID]*Peer{
		"p1": {ID: "p1", Addr: "10.0.0.1:7000"},
		"p2": {ID: "p2", Addr: "10.0.0.2:7000"},
		NodeID("gen" + strconv.Itoa(gen)): {
			ID:   NodeID("gen" + strconv.Itoa(gen)),
			Addr: "10.0.0." + strconv.Itoa(gen%200+3) + ":7000",
		},
	}
}

// TestProofRound007_SnapshotPeerIDsDuringMembershipChange exercises the real
// (*Node).snapshotPeerIDs concurrently with real membership changes, exactly
// the interleaving that used to crash the process. It is the regression guard
// for 29a68cb ("snapshot peer IDs in broadcast functions to avoid
// map-iteration race").
func TestProofRound007_SnapshotPeerIDsDuringMembershipChange(t *testing.T) {
	n := &Node{peers: peerSetFor(0)}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	start := make(chan struct{})

	// Reader: the real production method the three broadcasts rely on.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, id := range n.snapshotPeerIDs() {
				_ = id
			}
		}
	}()

	// Writer: mirrors membership.go, which swaps in a brand-new map under n.mu.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for gen := 1; ; gen++ {
			select {
			case <-stop:
				return
			default:
			}
			n.mu.Lock()
			n.peers = peerSetFor(gen)
			n.mu.Unlock()
		}
	}()

	// Release both goroutines together so reader and writer actually overlap.
	close(start)
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	// The map must still be internally consistent and reachable afterwards;
	// an unlocked iteration would also risk tripping the runtime's
	// concurrent-map-access guard.
	n.mu.Lock()
	_, hasP1 := n.peers["p1"]
	n.mu.Unlock()
	if !hasP1 {
		t.Fatal("peer map lost p1 after concurrent snapshot/membership churn")
	}
}
