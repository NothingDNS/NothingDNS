package raft

import (
	"testing"
	"time"
)

// buildStaleVoteNode builds a real Node parked in candidacy at `term`, with
// a nil transport so broadcastVoteRequest sends nothing and no stray vote
// responses can arrive. votedFor is pre-set to self so setVotedForLocked
// short-circuits without needing a persister (DataDir is "" so
// persistHardStateLocked is a no-op anyway).
func buildStaleVoteNode(t *testing.T, term Term) *Node {
	t.Helper()
	cfg := DefaultConfig()
	cfg.NodeID = "n1"
	cfg.ElectionTimeout = 30 * time.Second // long: the timer must not fire
	cfg.HeartbeatInterval = 20 * time.Millisecond

	n, _ := NewNode(cfg, []NodeID{"peer1"}, nil)
	n.currentTerm = term
	n.votedFor = cfg.NodeID
	n.state = StateCandidate
	return n
}

func waitState(t *testing.T, n *Node, want State, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		n.mu.Lock()
		s := n.state
		n.mu.Unlock()
		if s == want {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// TestRunCandidateIgnoresStaleTermVote drives the REAL (*Node).runCandidate.
//
// Raft §5.2 counts votes only for the term in which they were granted.
// voteRespCh is never drained between elections, so a granted response left
// over from a previous candidacy (resp.Term < current term) must be ignored.
// Before the fix, runCandidate rejected only higher terms, so a stale grant
// fell through to `voteCount++` and could win an election on a tally that
// never existed in that term — two leaders in the same term.
func TestRunCandidateIgnoresStaleTermVote(t *testing.T) {
	const term = Term(7)

	// --- DEFECT: a stale grant from term 6 must not win the term-7 election ---
	n1 := buildStaleVoteNode(t, term)
	go n1.runCandidate()

	// Let runCandidate reach its receive loop before injecting.
	time.Sleep(50 * time.Millisecond)
	n1.voteRespCh <- VoteResponse{Term: term - 1, VoteGranted: true}

	if waitState(t, n1, StateLeader, 400*time.Millisecond) {
		n1.mu.Lock()
		got := n1.state
		n1.mu.Unlock()
		close(n1.stopCh)
		t.Fatalf("FAIL: stale-term vote counted — node became %v in term %d after "+
			"only its own self-vote (quorum is 2). A grant from term %d must not "+
			"count toward term %d; that allows two leaders in one term.",
			got, term, term-1, term)
	}
	close(n1.stopCh)

	// --- CONTROL: a current-term grant MUST still be counted ---
	// Without this, a harness that simply drops every response would pass the
	// defect check above, so the control proves the receive loop is live.
	n2 := buildStaleVoteNode(t, term)
	go n2.runCandidate()
	time.Sleep(50 * time.Millisecond)
	n2.voteRespCh <- VoteResponse{Term: term, VoteGranted: true}

	if !waitState(t, n2, StateLeader, 500*time.Millisecond) {
		close(n2.stopCh)
		t.Fatalf("FAIL: control — a legitimate term-%d grant was not counted, so the "+
			"receive loop is not running and this harness cannot detect the defect", term)
	}
	close(n2.stopCh)
	t.Logf("PASS: stale term-%d grant ignored; current-term grant correctly won the election", term-1)
}
