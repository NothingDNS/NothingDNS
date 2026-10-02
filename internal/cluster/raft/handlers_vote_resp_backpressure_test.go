package raft

import (
	"testing"
	"time"
)

// TestHandleVoteRequestDoesNotDeadlockOnFullVoteRespChannel is a regression
// test for the bounded voteRespCh.
//
// voteRespCh has capacity 10 and its only consumer is runCandidate, so a node
// that is a follower never drains it. handleVoteRequest used to send its five
// responses with a blocking `n.voteRespCh <- resp` while holding n.mu. Once
// the buffer filled — i.e. after 11 vote requests reached a follower — the
// handler blocked while holding n.mu, wedging the node: every other n.mu
// holder (and therefore the whole state machine) stalled behind it.
//
// The fix routes all five sends through sendVoteResponseLocked, which uses the
// same non-blocking send-and-drop as the transport path in sendVoteRequest
// (handlers.go). Dropping is safe: an uncollected vote response belongs to a
// campaign this node is not running, and the candidate's election timeout
// expires it.
//
// The test drives the REAL path: Start() puts the node in runFollower, which
// receives from voteCh (state.go) and calls handleVoteRequest under n.mu.
// Nothing here calls the unexported handler directly.
func TestHandleVoteRequestDoesNotDeadlockOnFullVoteRespChannel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "follower"
	// Long election timeout: the node must stay a follower for the whole
	// test, so it keeps consuming voteCh and never becomes a candidate (the
	// only state that would drain voteRespCh and mask the deadlock).
	cfg.HeartbeatInterval = 15 * time.Millisecond
	cfg.ElectionTimeout = 10 * time.Second

	node, _ := NewNode(cfg, []NodeID{"leader"}, &mockTransport{})
	node.Start()
	defer node.Stop()

	// Sanity: confirm the node really is a follower, otherwise the test
	// would be exercising runCandidate rather than the follower path.
	deadline := time.Now().Add(2 * time.Second)
	for node.State() != StateFollower && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := node.State(); got != StateFollower {
		t.Fatalf("node is %v, want StateFollower", got)
	}

	// Inject well past the capacity-10 voteRespCh. Every request uses a
	// stale term (0) against a node whose currentTerm is >= 0, so the
	// handler takes the early "reply false if term < currentTerm" path
	// and returns a response on every call — the branch that used to block.
	const injections = 40
	for i := 0; i < injections; i++ {
		node.voteCh <- VoteRequest{
			Term:         0,
			CandidateID:  "candidate",
			LastLogIndex: 0,
			LastLogTerm:  0,
		}
	}

	// The real assertion: the node must still be able to take n.mu. Before
	// the fix, handleVoteRequest held n.mu forever on the 11th+ response,
	// so this Lock would hang and the test would trip its own deadline.
	// Reading state under the lock also proves the mutex is genuinely
	// usable, not merely released.
	acquired := make(chan bool, 1)
	go func() {
		node.mu.Lock()
		follower := node.state == StateFollower
		node.mu.Unlock()
		acquired <- follower
	}()

	select {
	case follower := <-acquired:
		// Expected: n.mu is still acquirable, so no handler is wedged.
		if !follower {
			t.Errorf("node state = %v, want StateFollower", node.state)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("node deadlocked: n.mu was never released after " +
			"vote requests overfilled the bounded voteRespCh " +
			"(handleVoteRequest blocked on a full channel while holding n.mu)")
	}

	// Control: the node is still functional, not merely unlockable. It
	// must still process a further vote request and answer on the channel.
	// Before the fix this is the same hang; after it, the response arrives
	// (or is harmlessly dropped once the buffer is full again).
	select {
	case node.voteCh <- VoteRequest{Term: 0, CandidateID: "candidate"}:
	case <-time.After(5 * time.Second):
		t.Fatal("folder stopped consuming voteCh: runFollower is wedged")
	}

	// Let the follower loop drain, then confirm it is still a live follower
	// and that its term was never advanced by these stale-term requests.
	if !waitUntil(2*time.Second, func() bool { return node.State() == StateFollower }) {
		t.Fatalf("node left follower state: %v", node.State())
	}
	node.mu.Lock()
	term := node.currentTerm
	node.mu.Unlock()
	if term > 1 {
		t.Errorf("currentTerm = %d, want <= 1: stale term-0 requests must not advance the term", term)
	}
}
