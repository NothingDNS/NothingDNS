package raft

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 1. State.String unknown branch
// ---------------------------------------------------------------------------

func TestStateStringUnknown(t *testing.T) {
	s := State(99)
	if got := s.String(); got != "Unknown" {
		t.Errorf("State(99).String() = %q, want %q", got, "Unknown")
	}
}

// ---------------------------------------------------------------------------
// 2. NewNode fills zero-valued config fields
// ---------------------------------------------------------------------------

func TestNewNodeZeroConfigFields(t *testing.T) {
	cfg := Config{NodeID: "n1"}
	node := NewNode(cfg, []NodeID{"n2"}, &mockTransport{})
	defer node.Stop()

	node.mu.Lock()
	defer node.mu.Unlock()
	if node.config.HeartbeatInterval != 150*time.Millisecond {
		t.Errorf("HeartbeatInterval = %v, want 150ms", node.config.HeartbeatInterval)
	}
	if node.config.ElectionTimeout != 1000*time.Millisecond {
		t.Errorf("ElectionTimeout = %v, want 1s", node.config.ElectionTimeout)
	}
	if node.config.MaxLogEntries != 128 {
		t.Errorf("MaxLogEntries = %d, want 128", node.config.MaxLogEntries)
	}
}

// ---------------------------------------------------------------------------
// 3. Node.CommitIndex / ApplyCh / CommitCh accessors
// ---------------------------------------------------------------------------

func TestNodeCommitIndexInitial(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	defer n.Stop()
	if ci := n.CommitIndex(); ci != 0 {
		t.Errorf("CommitIndex = %d, want 0", ci)
	}
}

func TestNodeApplyCh(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	defer n.Stop()
	if ch := n.ApplyCh(); ch == nil {
		t.Error("ApplyCh returned nil")
	}
}

func TestNodeCommitCh(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	defer n.Stop()
	if ch := n.CommitCh(); ch == nil {
		t.Error("CommitCh returned nil")
	}
}

// ---------------------------------------------------------------------------
// 4. lastLogInfo on empty and non-empty logs
// ---------------------------------------------------------------------------

func TestLastLogInfoEmpty(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	defer n.Stop()
	idx, trm := n.lastLogInfo()
	if idx != 0 || trm != 0 {
		t.Errorf("lastLogInfo() = (%d, %d), want (0, 0)", idx, trm)
	}
}

func TestLastLogInfoNonEmpty(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.log = []entry{{Index: 5, Term: 3}}
	n.mu.Unlock()
	idx, trm := n.lastLogInfo()
	if idx != 5 || trm != 3 {
		t.Errorf("lastLogInfo() = (%d, %d), want (5, 3)", idx, trm)
	}
}

// ---------------------------------------------------------------------------
// 5. isLogUpToDate variations
// ---------------------------------------------------------------------------

func TestIsLogUpToDate(t *testing.T) {
	tests := []struct {
		name            string
		log             []entry
		candidateIdx    Index
		candidateTerm   Term
		expectUpToDate  bool
	}{
		{"same_term_longer_candidate", []entry{{Index: 2, Term: 1}}, 3, 1, true},
		{"same_term_shorter_candidate", []entry{{Index: 5, Term: 1}}, 3, 1, false},
		{"higher_candidate_term", []entry{{Index: 10, Term: 1}}, 1, 2, true},
		{"lower_candidate_term", []entry{{Index: 1, Term: 2}}, 5, 1, false},
		{"equal_last_entry", []entry{{Index: 3, Term: 2}}, 3, 2, true},
		{"empty_receiver_log", nil, 1, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
			defer n.Stop()
			n.mu.Lock()
			n.log = tt.log
			n.mu.Unlock()
			got := n.isLogUpToDate(tt.candidateIdx, tt.candidateTerm)
			if got != tt.expectUpToDate {
				t.Errorf("isLogUpToDate(%d,%d) = %v, want %v", tt.candidateIdx, tt.candidateTerm, got, tt.expectUpToDate)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 6. HandleSnapshotRequest
// ---------------------------------------------------------------------------

func TestHandleSnapshotRequestStaleTerm(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.currentTerm = 5
	n.log = []entry{{Index: 1, Term: 1}}
	n.mu.Unlock()

	n.HandleSnapshotRequest(SnapshotRequest{Term: 3, LastIndex: 100, LastTerm: 3})

	n.mu.Lock()
	defer n.mu.Unlock()
	// Should not have changed anything
	if n.lastSnapshot != 0 {
		t.Error("snapshot should not have been installed for stale term")
	}
	if len(n.log) != 1 {
		t.Error("log should not have been cleared for stale term")
	}
}

func TestHandleSnapshotRequestValidInstall(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.currentTerm = 1
	n.log = []entry{{Index: 1, Term: 1}, {Index: 2, Term: 1}}
	n.mu.Unlock()

	n.HandleSnapshotRequest(SnapshotRequest{Term: 2, LeaderID: "leader", LastIndex: 50, LastTerm: 2})

	n.mu.Lock()
	defer n.mu.Unlock()
	if n.currentTerm != 2 {
		t.Errorf("term = %d, want 2", n.currentTerm)
	}
	if n.state != StateFollower {
		t.Errorf("state = %v, want Follower", n.state)
	}
	if n.lastSnapshot != 50 {
		t.Errorf("lastSnapshot = %d, want 50", n.lastSnapshot)
	}
	if n.lastApplied != 50 {
		t.Errorf("lastApplied = %d, want 50", n.lastApplied)
	}
	if n.commitIndex != 50 {
		t.Errorf("commitIndex = %d, want 50", n.commitIndex)
	}
	if len(n.log) != 0 {
		t.Errorf("log len = %d, want 0", len(n.log))
	}
	if n.votedFor != "" {
		t.Errorf("votedFor = %q, want empty", n.votedFor)
	}
}

// ---------------------------------------------------------------------------
// 7. HandleAppendRequest: commit index advancement and term update
// ---------------------------------------------------------------------------

func TestHandleAppendRequestCommitIndexAdvance(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.currentTerm = 1
	n.log = []entry{{Index: 1, Term: 1}, {Index: 2, Term: 1}, {Index: 3, Term: 1}}
	n.commitIndex = 0
	n.mu.Unlock()

	resp := n.HandleAppendRequest(AppendRequest{
		Term:         1,
		LeaderID:     "leader",
		PrevLogIndex: 3,
		PrevLogTerm:  1,
		LeaderCommit: 2,
	})
	if !resp.Success {
		t.Fatal("expected success")
	}
	if n.CommitIndex() != 2 {
		t.Errorf("commitIndex = %d, want 2", n.CommitIndex())
	}
}

func TestHandleAppendRequestCommitIndexClamp(t *testing.T) {
	// LeaderCommit exceeds log length => clamp to log length
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.currentTerm = 1
	n.log = []entry{{Index: 1, Term: 1}}
	n.commitIndex = 0
	n.mu.Unlock()

	resp := n.HandleAppendRequest(AppendRequest{
		Term:         1,
		LeaderID:     "leader",
		PrevLogIndex: 1,
		PrevLogTerm:  1,
		LeaderCommit: 50,
	})
	if !resp.Success {
		t.Fatal("expected success")
	}
	if n.CommitIndex() != 1 {
		t.Errorf("commitIndex = %d, want 1 (clamped to log length)", n.CommitIndex())
	}
}

func TestHandleAppendRequestHigherTermConversion(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.currentTerm = 1
	n.state = StateCandidate
	n.votedFor = "n1"
	n.mu.Unlock()

	resp := n.HandleAppendRequest(AppendRequest{
		Term:     5,
		LeaderID: "leader",
	})
	// Response term is set from n.currentTerm before update, so it reflects old term
	if !resp.Success {
		t.Error("expected success (no prevLogIndex, term updated)")
	}
	n.mu.Lock()
	s := n.state
	term := n.currentTerm
	vf := n.votedFor
	n.mu.Unlock()
	if s != StateFollower {
		t.Errorf("state = %v, want Follower", s)
	}
	if term != 5 {
		t.Errorf("term = %d, want 5", term)
	}
	if vf != "" {
		t.Errorf("votedFor = %q, want empty", vf)
	}
}

func TestHandleAppendRequestOverwriteConflicting(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.currentTerm = 1
	n.log = []entry{
		{Index: 1, Term: 1},
		{Index: 2, Term: 1},
		{Index: 3, Term: 1},
	}
	n.mu.Unlock()

	resp := n.HandleAppendRequest(AppendRequest{
		Term:         1,
		LeaderID:     "leader",
		PrevLogIndex: 1,
		PrevLogTerm:  1,
		Entries:      []entry{{Index: 2, Term: 2, Command: []byte("new")}},
	})
	if !resp.Success {
		t.Fatal("expected success")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.log) != 2 {
		t.Fatalf("log len = %d, want 2", len(n.log))
	}
	if n.log[1].Term != 2 {
		t.Errorf("log[1].Term = %d, want 2", n.log[1].Term)
	}
}

// ---------------------------------------------------------------------------
// 8. HandleVoteRequest: higher term converts to follower and resets vote
// ---------------------------------------------------------------------------

func TestHandleVoteRequestHigherTermConversion(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.currentTerm = 2
	n.state = StateCandidate
	n.votedFor = "n1"
	n.mu.Unlock()

	resp := n.HandleVoteRequest(VoteRequest{
		Term:         5,
		CandidateID:  "n2",
		LastLogIndex: 10,
		LastLogTerm:  5,
	})
	if !resp.VoteGranted {
		t.Error("expected vote to be granted")
	}
	n.mu.Lock()
	s := n.state
	term := n.currentTerm
	vf := n.votedFor
	n.mu.Unlock()
	if s != StateFollower {
		t.Errorf("state = %v, want Follower", s)
	}
	if term != 5 {
		t.Errorf("term = %d, want 5", term)
	}
	if vf != "n2" {
		t.Errorf("votedFor = %q, want %q", vf, "n2")
	}
}

// ---------------------------------------------------------------------------
// 9. maybeAdvanceCommitIndex
// ---------------------------------------------------------------------------

func TestMaybeAdvanceCommitIndex(t *testing.T) {
	// maybeAdvanceCommitIndex uses `break` after setting commitIndex, so it only
	// advances to the FIRST index with quorum. To commit index 3, call it 3 times
	// or structure the log so only index 3 has quorum.
	n := NewNode(Config{NodeID: "leader"}, []NodeID{"f1", "f2"}, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.state = StateLeader
	n.currentTerm = 1
	n.log = []entry{
		{Index: 1, Term: 1, Command: []byte("a")},
		{Index: 2, Term: 1, Command: []byte("b")},
		{Index: 3, Term: 1, Command: []byte("c")},
	}
	n.matchIndex["f1"] = 3
	n.matchIndex["f2"] = 3
	n.mu.Unlock()

	// First call commits index 1 (breaks after first quorum)
	n.maybeAdvanceCommitIndex()
	if ci := n.CommitIndex(); ci != 1 {
		t.Errorf("after 1st call: commitIndex = %d, want 1", ci)
	}
	// Second call commits index 2
	n.maybeAdvanceCommitIndex()
	if ci := n.CommitIndex(); ci != 2 {
		t.Errorf("after 2nd call: commitIndex = %d, want 2", ci)
	}
	// Third call commits index 3
	n.maybeAdvanceCommitIndex()
	if ci := n.CommitIndex(); ci != 3 {
		t.Errorf("after 3rd call: commitIndex = %d, want 3", ci)
	}
}

func TestMaybeAdvanceCommitIndexNotLeader(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, []NodeID{"f1"}, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.state = StateFollower
	n.currentTerm = 1
	n.log = []entry{{Index: 1, Term: 1}}
	n.matchIndex["f1"] = 1
	n.mu.Unlock()

	n.maybeAdvanceCommitIndex()
	// Should not advance since not leader
	if ci := n.CommitIndex(); ci != 0 {
		t.Errorf("commitIndex = %d, want 0 (not leader)", ci)
	}
}

func TestMaybeAdvanceCommitIndexOnlyCurrentTerm(t *testing.T) {
	// Entries from previous term should not be committed via replica count
	n := NewNode(Config{NodeID: "leader"}, []NodeID{"f1"}, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.state = StateLeader
	n.currentTerm = 2
	n.log = []entry{
		{Index: 1, Term: 1, Command: []byte("a")},
		{Index: 2, Term: 1, Command: []byte("b")},
	}
	n.matchIndex["f1"] = 2
	n.mu.Unlock()

	n.maybeAdvanceCommitIndex()
	// Should not advance commit past entries from previous term
	if ci := n.CommitIndex(); ci != 0 {
		t.Errorf("commitIndex = %d, want 0 (entries from old term)", ci)
	}
}

func TestMaybeAdvanceCommitIndexNoQuorum(t *testing.T) {
	// With 5 peers: len(peers)/2 = 2, need replicas > 2 (i.e. >= 3)
	// Leader counts as 1, so need at least 2 peers matching.
	// If only leader matches, replicas = 1, which is not > 2.
	n := NewNode(Config{NodeID: "leader"}, []NodeID{"f1", "f2", "f3", "f4", "f5"}, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.state = StateLeader
	n.currentTerm = 1
	n.log = []entry{{Index: 1, Term: 1, Command: []byte("a")}}
	n.matchIndex["f1"] = 0
	n.matchIndex["f2"] = 0
	n.matchIndex["f3"] = 0
	n.matchIndex["f4"] = 0
	n.matchIndex["f5"] = 0
	n.mu.Unlock()

	n.maybeAdvanceCommitIndex()
	if ci := n.CommitIndex(); ci != 0 {
		t.Errorf("commitIndex = %d, want 0 (no quorum)", ci)
	}
}

// ---------------------------------------------------------------------------
// 10. handleAppendResponse
// ---------------------------------------------------------------------------

func TestHandleAppendResponseSuccess(t *testing.T) {
	n := NewNode(Config{NodeID: "leader"}, []NodeID{"f1"}, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.state = StateLeader
	n.currentTerm = 1
	n.matchIndex["f1"] = 0
	n.nextIndex["f1"] = 2
	n.log = []entry{{Index: 1, Term: 1}, {Index: 2, Term: 1}}
	n.mu.Unlock()

	n.handleAppendResponse(AppendResponse{
		Term:        1,
		Success:     true,
		From:        "f1",
		MatchIndex:  2,
	})

	n.mu.Lock()
	mi := n.matchIndex["f1"]
	ni := n.nextIndex["f1"]
	n.mu.Unlock()
	if mi != 2 {
		t.Errorf("matchIndex[f1] = %d, want 2", mi)
	}
	_ = ni
}

func TestHandleAppendResponseFailureDecrementsNextIndex(t *testing.T) {
	n := NewNode(Config{NodeID: "leader"}, []NodeID{"f1"}, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.state = StateLeader
	n.currentTerm = 1
	n.nextIndex["f1"] = 5
	n.matchIndex["f1"] = 0
	n.mu.Unlock()

	n.handleAppendResponse(AppendResponse{
		Term:    1,
		Success: false,
		From:    "f1",
	})

	n.mu.Lock()
	ni := n.nextIndex["f1"]
	n.mu.Unlock()
	if ni != 4 {
		t.Errorf("nextIndex[f1] = %d, want 4", ni)
	}
}

func TestHandleAppendResponseHigherTerm(t *testing.T) {
	n := NewNode(Config{NodeID: "leader"}, []NodeID{"f1"}, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.state = StateLeader
	n.currentTerm = 1
	n.nextIndex["f1"] = 1
	n.mu.Unlock()

	n.handleAppendResponse(AppendResponse{
		Term:    5,
		Success: false,
		From:    "f1",
	})

	n.mu.Lock()
	s := n.state
	term := n.currentTerm
	n.mu.Unlock()
	if s != StateFollower {
		t.Errorf("state = %v, want Follower", s)
	}
	if term != 5 {
		t.Errorf("term = %d, want 5", term)
	}
}

func TestHandleAppendResponseNotLeader(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, []NodeID{"f1"}, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.state = StateFollower
	n.currentTerm = 1
	n.mu.Unlock()

	// Should be no-op
	n.handleAppendResponse(AppendResponse{Term: 1, Success: true, From: "f1"})
	if n.State() != StateFollower {
		t.Error("state should remain Follower")
	}
}

func TestHandleAppendResponseNextIndexFloor(t *testing.T) {
	// nextIndex should not go below 1
	n := NewNode(Config{NodeID: "leader"}, []NodeID{"f1"}, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.state = StateLeader
	n.currentTerm = 1
	n.nextIndex["f1"] = 1
	n.matchIndex["f1"] = 0
	n.mu.Unlock()

	n.handleAppendResponse(AppendResponse{Term: 1, Success: false, From: "f1"})

	n.mu.Lock()
	ni := n.nextIndex["f1"]
	n.mu.Unlock()
	if ni != 1 {
		t.Errorf("nextIndex[f1] = %d, want 1 (floor)", ni)
	}
}

// ---------------------------------------------------------------------------
// 11. becomeFollower / becomeLeader
// ---------------------------------------------------------------------------

func TestBecomeFollower(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, []NodeID{"f1"}, &mockTransport{})
	n.mu.Lock()
	n.state = StateCandidate
	n.currentTerm = 3
	n.votedFor = "n1"
	n.mu.Unlock()

	n.becomeFollower(5)

	n.mu.Lock()
	defer n.mu.Unlock()
	if n.state != StateFollower {
		t.Errorf("state = %v, want Follower", n.state)
	}
	if n.currentTerm != 5 {
		t.Errorf("term = %d, want 5", n.currentTerm)
	}
	if n.votedFor != "" {
		t.Errorf("votedFor = %q, want empty", n.votedFor)
	}
	// Check leadership channel
	select {
	case ls := <-n.leadershipCh:
		if ls.State != StateFollower || ls.Term != 5 {
			t.Errorf("leadership state = %+v, want {Follower 5}", ls)
		}
	default:
		t.Error("expected leadership state on channel")
	}
}

func TestBecomeLeaderInitializesTracking(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, []NodeID{"f1", "f2"}, &mockTransport{})
	n.mu.Lock()
	n.currentTerm = 2
	n.log = []entry{{Index: 1, Term: 1}, {Index: 2, Term: 2}}
	n.mu.Unlock()

	n.becomeLeader(2)

	n.mu.Lock()
	defer n.mu.Unlock()
	if n.state != StateLeader {
		t.Errorf("state = %v, want Leader", n.state)
	}
	// nextIndex should be len(log)+1 = 3
	if n.nextIndex["f1"] != 3 {
		t.Errorf("nextIndex[f1] = %d, want 3", n.nextIndex["f1"])
	}
	if n.nextIndex["f2"] != 3 {
		t.Errorf("nextIndex[f2] = %d, want 3", n.nextIndex["f2"])
	}
	// matchIndex should be 0
	if n.matchIndex["f1"] != 0 {
		t.Errorf("matchIndex[f1] = %d, want 0", n.matchIndex["f1"])
	}
	// Should have appended a no-op entry
	if len(n.log) < 3 {
		t.Errorf("log len = %d, want >= 3 (no-op appended)", len(n.log))
	}
	select {
	case ls := <-n.leadershipCh:
		if ls.State != StateLeader || ls.Term != 2 {
			t.Errorf("leadership state = %+v, want {Leader 2}", ls)
		}
	default:
		t.Error("expected leadership state on channel")
	}
}

// ---------------------------------------------------------------------------
// 12. AddPeer / RemovePeer edge cases
// ---------------------------------------------------------------------------

func TestAddPeerAlreadyExists(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, []NodeID{"n2"}, &mockTransport{})
	defer n.Stop()
	err := n.AddPeer("n2", "addr")
	if err != nil {
		t.Errorf("AddPeer existing peer should return nil, got %v", err)
	}
}

func TestAddPeerSelf(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	defer n.Stop()
	err := n.AddPeer("n1", "addr")
	if err == nil {
		t.Error("AddPeer self should return error")
	}
}

func TestAddPeerDuringJointConfig(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, []NodeID{"n2"}, &mockTransport{})
	defer n.Stop()
	// Set up a joint config
	n.mu.Lock()
	n.jointConfig = &JointConfig{}
	n.mu.Unlock()
	err := n.AddPeer("n3", "addr")
	if err == nil {
		t.Error("AddPeer during joint config should return error")
	}
}

func TestRemovePeerNonexistent(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, []NodeID{"n2"}, &mockTransport{})
	defer n.Stop()
	err := n.RemovePeer("n99")
	if err != nil {
		t.Errorf("RemovePeer nonexistent should return nil, got %v", err)
	}
}

func TestRemovePeerSelf(t *testing.T) {
	// Include self in the peers list so the self-check is reached
	n := NewNode(Config{NodeID: "n1"}, []NodeID{"n1", "n2"}, &mockTransport{})
	defer n.Stop()
	err := n.RemovePeer("n1")
	if err == nil {
		t.Error("RemovePeer self should return error")
	}
}

func TestRemovePeerDuringJointConfig(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, []NodeID{"n2"}, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.jointConfig = &JointConfig{}
	n.mu.Unlock()
	err := n.RemovePeer("n2")
	if err == nil {
		t.Error("RemovePeer during joint config should return error")
	}
}

func TestAddPeerTracking(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, []NodeID{"n2"}, &mockTransport{})
	defer n.Stop()
	err := n.AddPeer("n3", "127.0.0.1:9000")
	if err != nil {
		t.Fatalf("AddPeer failed: %v", err)
	}
	n.mu.Lock()
	ni := n.nextIndex["n3"]
	mi := n.matchIndex["n3"]
	n.mu.Unlock()
	if ni == 0 {
		t.Error("nextIndex[n3] should be set after AddPeer")
	}
	if mi != 0 {
		t.Errorf("matchIndex[n3] = %d, want 0", mi)
	}
}

// ---------------------------------------------------------------------------
// 13. ProposeConfChange
// ---------------------------------------------------------------------------

func TestProposeConfChangeNotLeader(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	defer n.Stop()
	err := n.ProposeConfChange(&JointConfigProposal{Type: EntryAddNode, PeerID: "n2", PeerAddr: "a"})
	if err == nil {
		t.Error("ProposeConfChange should fail when not leader")
	}
}

func TestProposeConfChangeAddNode(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, []NodeID{"n2"}, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.state = StateLeader
	n.currentTerm = 1
	n.mu.Unlock()

	err := n.ProposeConfChange(&JointConfigProposal{
		Type:     EntryAddNode,
		PeerID:   "n3",
		PeerAddr: "127.0.0.1:9000",
	})
	if err != nil {
		t.Fatalf("ProposeConfChange failed: %v", err)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.jointConfig == nil {
		t.Error("jointConfig should be set")
	}
	if len(n.log) != 1 {
		t.Errorf("log len = %d, want 1", len(n.log))
	}
	if n.log[0].Type != EntryAddNode {
		t.Errorf("entry type = %d, want EntryAddNode", n.log[0].Type)
	}
	if n.nextIndex["n3"] == 0 {
		t.Error("nextIndex[n3] should be initialized")
	}
}

func TestProposeConfChangeRemoveNode(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, []NodeID{"n2", "n3"}, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.state = StateLeader
	n.currentTerm = 1
	n.mu.Unlock()

	err := n.ProposeConfChange(&JointConfigProposal{
		Type:   EntryRemoveNode,
		PeerID: "n3",
	})
	if err != nil {
		t.Fatalf("ProposeConfChange failed: %v", err)
	}
	n.mu.Lock()
	jc := n.jointConfig
	n.mu.Unlock()
	if jc == nil {
		t.Fatal("jointConfig should be set")
	}
	if _, ok := jc.NewPeers["n3"]; ok {
		t.Error("n3 should not be in NewPeers")
	}
	if _, ok := jc.OldPeers["n3"]; !ok {
		t.Error("n3 should still be in OldPeers")
	}
}

// ---------------------------------------------------------------------------
// 14. advanceJointConfig edge case
// ---------------------------------------------------------------------------

func TestAdvanceJointConfigNil(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	defer n.Stop()
	// Should be a no-op
	n.advanceJointConfig()
}

func TestAdvanceJointConfigUpdatesPeers(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, []NodeID{"n2"}, &mockTransport{})
	defer n.Stop()
	newPeers := map[NodeID]*Peer{
		"n1": {ID: "n1"},
		"n2": {ID: "n2"},
		"n3": {ID: "n3", Addr: "addr3"},
	}
	n.mu.Lock()
	n.jointConfig = NewJointConfig(n.peers, newPeers)
	n.jointConfigIdx = 1
	n.pendingConfChange = &JointConfigProposal{Type: EntryAddNode, PeerID: "n3"}
	n.mu.Unlock()

	n.advanceJointConfig()

	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.peers) != 3 {
		t.Errorf("peers = %d, want 3", len(n.peers))
	}
	if n.jointConfig != nil {
		t.Error("jointConfig should be nil after advance")
	}
	if n.jointConfigIdx != 0 {
		t.Error("jointConfigIdx should be 0 after advance")
	}
	if n.pendingConfChange != nil {
		t.Error("pendingConfChange should be nil after advance")
	}
}

// ---------------------------------------------------------------------------
// 15. encodeJointConfig / decode roundtrip
// ---------------------------------------------------------------------------

func TestEncodeJointConfig(t *testing.T) {
	old := map[NodeID]*Peer{
		"n1": {ID: "n1", Addr: "a1"},
		"n2": {ID: "n2", Addr: "a2"},
	}
	newP := map[NodeID]*Peer{
		"n1": {ID: "n1", Addr: "a1"},
		"n2": {ID: "n2", Addr: "a2"},
		"n3": {ID: "n3", Addr: "a3"},
	}
	data, err := encodeJointConfig(NewJointConfig(old, newP))
	if err != nil {
		t.Fatalf("encodeJointConfig failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("encoded data should not be empty")
	}

	// Manually verify structure by decoding
	r := bytes.NewReader(data)

	var oldCount uint32
	if err := binary.Read(r, binary.BigEndian, &oldCount); err != nil {
		t.Fatalf("read old count: %v", err)
	}
	if oldCount != 2 {
		t.Errorf("old count = %d, want 2", oldCount)
	}

	var newCount uint32
	// Skip old peers
	for i := uint32(0); i < oldCount; i++ {
		var idLen uint32
		binary.Read(r, binary.BigEndian, &idLen)
		idBuf := make([]byte, idLen)
		r.Read(idBuf)
		var addrLen uint32
		binary.Read(r, binary.BigEndian, &addrLen)
		addrBuf := make([]byte, addrLen)
		r.Read(addrBuf)
	}
	if err := binary.Read(r, binary.BigEndian, &newCount); err != nil {
		t.Fatalf("read new count: %v", err)
	}
	if newCount != 3 {
		t.Errorf("new count = %d, want 3", newCount)
	}
}

// ---------------------------------------------------------------------------
// 16. newElectionTimer randomness
// ---------------------------------------------------------------------------

func TestNewElectionTimerDuration(t *testing.T) {
	n := NewNode(Config{NodeID: "n1", ElectionTimeout: 500 * time.Millisecond}, nil, &mockTransport{})
	defer n.Stop()

	// Verify timers are created and fire within expected bounds
	fired := 0
	for i := 0; i < 5; i++ {
		timer := n.newElectionTimer()
		select {
		case <-timer.C:
			fired++
		case <-time.After(3 * time.Second):
			t.Error("election timer did not fire within 3s")
		}
	}
	if fired != 5 {
		t.Errorf("fired = %d, want 5", fired)
	}
}

// ---------------------------------------------------------------------------
// 17. LockedRand
// ---------------------------------------------------------------------------

func TestLockedRandInt63n(t *testing.T) {
	r := NewLockedRand()
	for i := 0; i < 100; i++ {
		v := r.Int63n(1000)
		if v < 0 || v >= 1000 {
			t.Errorf("Int63n(1000) = %d, want [0,1000)", v)
		}
	}
}

func TestLockedRandInt63nZero(t *testing.T) {
	r := NewLockedRand()
	v := r.Int63n(0)
	if v != 0 {
		t.Errorf("Int63n(0) = %d, want 0", v)
	}
}

func TestLockedRandInt63nNegative(t *testing.T) {
	r := NewLockedRand()
	v := r.Int63n(-5)
	if v != 0 {
		t.Errorf("Int63n(-5) = %d, want 0", v)
	}
}

func TestLockedRandConcurrent(t *testing.T) {
	r := NewLockedRand()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				r.Int63n(10000)
			}
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// 18. Snapshotter Save+Load roundtrip with membership
// ---------------------------------------------------------------------------

func TestSnapshotterSaveLoadRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	sn, err := NewSnapshotter(tmpDir)
	if err != nil {
		t.Fatalf("NewSnapshotter failed: %v", err)
	}

	snap := &Snapshot{
		Index:      42,
		Term:       3,
		LastIndex:  41,
		LastTerm:   3,
		Data:       []byte("snapshot payload data"),
		Membership: []NodeID{"node1", "node2", "node3"},
	}
	if err := sn.Save(snap); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := sn.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load returned nil")
	}
	if loaded.Index != 42 {
		t.Errorf("Index = %d, want 42", loaded.Index)
	}
	if loaded.Term != 3 {
		t.Errorf("Term = %d, want 3", loaded.Term)
	}
	if loaded.LastIndex != 41 {
		t.Errorf("LastIndex = %d, want 41", loaded.LastIndex)
	}
	if loaded.LastTerm != 3 {
		t.Errorf("LastTerm = %d, want 3", loaded.LastTerm)
	}
	if string(loaded.Data) != "snapshot payload data" {
		t.Errorf("Data = %q, want %q", loaded.Data, "snapshot payload data")
	}
	if len(loaded.Membership) != 3 {
		t.Fatalf("Membership len = %d, want 3", len(loaded.Membership))
	}
	for i, id := range []NodeID{"node1", "node2", "node3"} {
		if loaded.Membership[i] != id {
			t.Errorf("Membership[%d] = %q, want %q", i, loaded.Membership[i], id)
		}
	}
}

func TestSnapshotterSaveEmptyMembership(t *testing.T) {
	tmpDir := t.TempDir()
	sn, err := NewSnapshotter(tmpDir)
	if err != nil {
		t.Fatalf("NewSnapshotter failed: %v", err)
	}

	snap := &Snapshot{
		Index:      1,
		Term:       1,
		LastIndex:  0,
		LastTerm:   0,
		Data:       []byte{},
		Membership: nil,
	}
	if err := sn.Save(snap); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := sn.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load returned nil")
	}
	if len(loaded.Membership) != 0 {
		t.Errorf("Membership len = %d, want 0", len(loaded.Membership))
	}
	if len(loaded.Data) != 0 {
		t.Errorf("Data len = %d, want 0", len(loaded.Data))
	}
}

func TestSnapshotterIgnoresNonSnapshotFiles(t *testing.T) {
	tmpDir := t.TempDir()
	sn, err := NewSnapshotter(tmpDir)
	if err != nil {
		t.Fatalf("NewSnapshotter failed: %v", err)
	}

	// Write non-snapshot files
	os.WriteFile(tmpDir+"/random.txt", []byte("junk"), 0644)
	os.WriteFile(tmpDir+"/abc", []byte("junk"), 0644)

	loaded, err := sn.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded != nil {
		t.Error("expected nil when only non-snapshot files exist")
	}
}

func TestSnapshotterCreatesDir(t *testing.T) {
	tmpDir := t.TempDir()
	deepDir := tmpDir + "/deep/nested/dir"
	sn, err := NewSnapshotter(deepDir)
	if err != nil {
		t.Fatalf("NewSnapshotter should create dirs: %v", err)
	}
	if sn == nil {
		t.Fatal("NewSnapshotter returned nil")
	}
}

// ---------------------------------------------------------------------------
// 19. WAL entry with empty command
// ---------------------------------------------------------------------------

func TestWALEmptyCommand(t *testing.T) {
	tmpDir := t.TempDir()
	wal, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatalf("NewWAL failed: %v", err)
	}
	defer wal.Close()

	e := entry{Index: 1, Term: 1, Command: nil, Type: EntryNoOp}
	if err := wal.Write(e); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	entries, err := wal.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries len = %d, want 1", len(entries))
	}
	if entries[0].Command != nil {
		t.Errorf("Command = %v, want nil", entries[0].Command)
	}
	if entries[0].Type != EntryNoOp {
		t.Errorf("Type = %d, want %d", entries[0].Type, EntryNoOp)
	}
}

func TestWALDifferentEntryTypes(t *testing.T) {
	tmpDir := t.TempDir()
	wal, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatalf("NewWAL failed: %v", err)
	}
	defer wal.Close()

	types := []EntryType{EntryNormal, EntryNoOp, EntryAddNode, EntryRemoveNode, EntryJointComplete}
	for i, et := range types {
		e := entry{Index: Index(i + 1), Term: 1, Command: []byte("cmd"), Type: et}
		if err := wal.Write(e); err != nil {
			t.Fatalf("Write entry type %d failed: %v", et, err)
		}
	}

	entries, err := wal.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	for i, et := range types {
		if entries[i].Type != et {
			t.Errorf("entries[%d].Type = %d, want %d", i, entries[i].Type, et)
		}
	}
}

// ---------------------------------------------------------------------------
// 20. ZoneStateMachine: add_record without RData
// ---------------------------------------------------------------------------

func TestZoneStateMachineAddRecordNoRData(t *testing.T) {
	zsm := NewZoneStateMachine()
	cmd := ZoneCommand{Type: "add_record", Zone: "z.", Name: "n.", RRType: 1, TTL: 300}
	err := zsm.Apply(entry{Command: mustMarshalJSON(cmd)})
	if err == nil {
		t.Error("expected error when add_record has no RData")
	}
}

func TestZoneStateMachineGetRecordsNonexistent(t *testing.T) {
	zsm := NewZoneStateMachine()
	recs := zsm.GetRecords("nonexistent.")
	if recs != nil {
		t.Errorf("expected nil for nonexistent zone, got %v", recs)
	}
}

func TestZoneStateMachineRestoreInvalidJSON(t *testing.T) {
	zsm := NewZoneStateMachine()
	err := zsm.Restore([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON restore")
	}
}

func TestZoneStateMachineMultipleRecordsSameKey(t *testing.T) {
	zsm := NewZoneStateMachine()
	for i := 0; i < 5; i++ {
		cmd := ZoneCommand{
			Type:   "add_record",
			Zone:   "example.com.",
			Name:   "www.example.com.",
			RRType: 1,
			TTL:    300,
			RData:  []string{fmt.Sprintf("10.0.0.%d", i)},
		}
		if err := zsm.Apply(entry{Command: mustMarshalJSON(cmd)}); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
	}
	recs := zsm.GetRecords("example.com.")
	if len(recs) != 5 {
		t.Errorf("expected 5 records (same key appended), got %d", len(recs))
	}
}

// ---------------------------------------------------------------------------
// 21. JointConfig: edge cases
// ---------------------------------------------------------------------------

func TestHasQuorumOldAndNewOldConfigFails(t *testing.T) {
	old := map[NodeID]*Peer{"a": {}, "b": {}, "c": {}}
	newP := map[NodeID]*Peer{"d": {}, "e": {}}
	jc := NewJointConfig(old, newP)

	// Only 1 old peer matches (need quorum 2)
	matchIndex := map[NodeID]Index{"a": 10, "d": 10, "e": 10}
	if jc.HasQuorumOldAndNew(matchIndex, 10) {
		t.Error("should return false when old config lacks quorum")
	}
}

func TestQuorumForConfigSinglePeer(t *testing.T) {
	peers := map[NodeID]*Peer{"n1": {}}
	jc := &JointConfig{OldPeers: peers}
	if q := jc.QuorumForConfig(peers); q != 1 {
		t.Errorf("quorum for 1 peer = %d, want 1", q)
	}
}

// ---------------------------------------------------------------------------
// 22. Peer struct
// ---------------------------------------------------------------------------

func TestPeerFields(t *testing.T) {
	p := &Peer{ID: "node1", Addr: "10.0.0.1:9000"}
	if p.ID != "node1" {
		t.Errorf("ID = %q, want %q", p.ID, "node1")
	}
	if p.Addr != "10.0.0.1:9000" {
		t.Errorf("Addr = %q, want %q", p.Addr, "10.0.0.1:9000")
	}
}

// ---------------------------------------------------------------------------
// 23. TCPTransport getConn with existing connection
// ---------------------------------------------------------------------------

func TestTCPTransportGetConnExisting(t *testing.T) {
	tp := NewTCPTransport()
	// Simulate existing connection
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	tp.mu.Lock()
	tp.conns["n1"] = client
	tp.mu.Unlock()

	conn, err := tp.getConn("n1")
	if err != nil {
		t.Fatalf("getConn failed: %v", err)
	}
	if conn != client {
		t.Error("getConn should return existing connection")
	}
}

// ---------------------------------------------------------------------------
// 24. Commit and Apply structs
// ---------------------------------------------------------------------------

func TestCommitStruct(t *testing.T) {
	c := Commit{Entries: []entry{{Index: 1, Term: 1}, {Index: 2, Term: 1}}}
	if len(c.Entries) != 2 {
		t.Errorf("Entries len = %d, want 2", len(c.Entries))
	}
}

func TestApplyStruct(t *testing.T) {
	a := Apply{Entry: entry{Index: 5, Term: 3}}
	if a.Entry.Index != 5 {
		t.Errorf("Entry.Index = %d, want 5", a.Entry.Index)
	}
}

func TestLeadershipStateStruct(t *testing.T) {
	ls := LeadershipState{State: StateLeader, Term: 7}
	if ls.State != StateLeader || ls.Term != 7 {
		t.Errorf("LeadershipState = %+v, want {Leader 7}", ls)
	}
}

// ---------------------------------------------------------------------------
// 25. Snapshot struct
// ---------------------------------------------------------------------------

func TestSnapshotStruct(t *testing.T) {
	s := Snapshot{
		Index:      10,
		Term:       2,
		LastIndex:  9,
		LastTerm:   2,
		Data:       []byte("data"),
		Membership: []NodeID{"a", "b"},
	}
	if s.Index != 10 || len(s.Membership) != 2 {
		t.Errorf("Snapshot = %+v", s)
	}
}

// ---------------------------------------------------------------------------
// 26. RPC message types constants
// ---------------------------------------------------------------------------

func TestMessageTypeConstants(t *testing.T) {
	if msgTypeVoteRequest != 1 {
		t.Errorf("msgTypeVoteRequest = %d, want 1", msgTypeVoteRequest)
	}
	if msgTypeVoteResponse != 2 {
		t.Errorf("msgTypeVoteResponse = %d, want 2", msgTypeVoteResponse)
	}
	if msgTypeAppendRequest != 3 {
		t.Errorf("msgTypeAppendRequest = %d, want 3", msgTypeAppendRequest)
	}
	if msgTypeAppendResponse != 4 {
		t.Errorf("msgTypeAppendResponse = %d, want 4", msgTypeAppendResponse)
	}
	if msgTypeSnapshot != 5 {
		t.Errorf("msgTypeSnapshot = %d, want 5", msgTypeSnapshot)
	}
}

// ---------------------------------------------------------------------------
// 27. writeRPCMessage / readRPCMessage via RPCServer
// ---------------------------------------------------------------------------

func TestRPCServerWriteReadMessage(t *testing.T) {
	srv := &RPCServer{}
	var buf bytes.Buffer

	req := VoteRequest{Term: 3, CandidateID: "c1", LastLogIndex: 10, LastLogTerm: 2}
	if err := srv.writeMessage(&buf, msgTypeVoteRequest, req); err != nil {
		t.Fatalf("writeMessage failed: %v", err)
	}

	// Read msgType
	var mt uint8
	if err := binary.Read(&buf, binary.BigEndian, &mt); err != nil {
		t.Fatalf("read msgType: %v", err)
	}
	if mt != msgTypeVoteRequest {
		t.Errorf("msgType = %d, want %d", mt, msgTypeVoteRequest)
	}

	var decoded VoteRequest
	if err := srv.readMessage(&buf, &decoded); err != nil {
		t.Fatalf("readMessage failed: %v", err)
	}
	if decoded.Term != 3 || decoded.CandidateID != "c1" {
		t.Errorf("decoded = %+v, want Term=3 CandidateID=c1", decoded)
	}
}

func TestRPCServerWriteReadAppendResponse(t *testing.T) {
	srv := &RPCServer{}
	var buf bytes.Buffer

	resp := AppendResponse{Term: 5, Success: true, From: "f1", MatchIndex: 42, Commitment: 99}
	if err := srv.writeMessage(&buf, msgTypeAppendResponse, resp); err != nil {
		t.Fatalf("writeMessage failed: %v", err)
	}

	var mt uint8
	binary.Read(&buf, binary.BigEndian, &mt)
	if mt != msgTypeAppendResponse {
		t.Errorf("msgType = %d, want %d", mt, msgTypeAppendResponse)
	}

	var decoded AppendResponse
	if err := srv.readMessage(&buf, &decoded); err != nil {
		t.Fatalf("readMessage failed: %v", err)
	}
	if decoded.Term != 5 || !decoded.Success || decoded.MatchIndex != 42 || decoded.Commitment != 99 {
		t.Errorf("decoded = %+v", decoded)
	}
}

func TestRPCServerWriteReadSnapshotRequest(t *testing.T) {
	srv := &RPCServer{}
	var buf bytes.Buffer

	req := SnapshotRequest{
		Term:     1,
		LeaderID: "leader",
		Data:     []byte("snap-data"),
		LastIndex: 100,
		LastTerm:  5,
	}
	if err := srv.writeMessage(&buf, msgTypeSnapshot, req); err != nil {
		t.Fatalf("writeMessage failed: %v", err)
	}

	var mt uint8
	binary.Read(&buf, binary.BigEndian, &mt)
	if mt != msgTypeSnapshot {
		t.Errorf("msgType = %d, want %d", mt, msgTypeSnapshot)
	}

	var decoded SnapshotRequest
	if err := srv.readMessage(&buf, &decoded); err != nil {
		t.Fatalf("readMessage failed: %v", err)
	}
	if decoded.LastIndex != 100 || decoded.LastTerm != 5 || string(decoded.Data) != "snap-data" {
		t.Errorf("decoded = %+v", decoded)
	}
}

// ---------------------------------------------------------------------------
// 28. Propose when leader with nil command
// ---------------------------------------------------------------------------

func TestProposeLeaderNilCommand(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.state = StateLeader
	n.currentTerm = 1
	n.mu.Unlock()

	err := n.Propose(nil, EntryNoOp)
	if err != nil {
		t.Fatalf("Propose failed: %v", err)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.log) != 1 {
		t.Fatalf("log len = %d, want 1", len(n.log))
	}
	if n.log[0].Command != nil {
		t.Errorf("Command = %v, want nil", n.log[0].Command)
	}
}

func TestProposeLeaderWithCommand(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	defer n.Stop()
	n.mu.Lock()
	n.state = StateLeader
	n.currentTerm = 1
	n.mu.Unlock()

	cmd := []byte("my command data")
	err := n.Propose(cmd, EntryNormal)
	if err != nil {
		t.Fatalf("Propose failed: %v", err)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.log) != 1 {
		t.Fatalf("log len = %d, want 1", len(n.log))
	}
	if string(n.log[0].Command) != "my command data" {
		t.Errorf("Command = %q, want %q", n.log[0].Command, "my command data")
	}
	if n.log[0].Type != EntryNormal {
		t.Errorf("Type = %d, want EntryNormal", n.log[0].Type)
	}
	if n.log[0].Term != 1 {
		t.Errorf("Term = %d, want 1", n.log[0].Term)
	}
	if n.log[0].Index != 1 {
		t.Errorf("Index = %d, want 1", n.log[0].Index)
	}
}

// ---------------------------------------------------------------------------
// 29. sendCommitted edge cases
// ---------------------------------------------------------------------------

func TestSendCommittedNoUnapplied(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	n.mu.Lock()
	n.commitIndex = 0
	n.lastApplied = 0
	n.mu.Unlock()
	// Should not panic or send anything
	n.sendCommitted()
}

func TestSendCommittedSnapshotOffset(t *testing.T) {
	// With lastSnapshot=5, log has entries for indices 6 and 7.
	// Boundary check: end <= len(log) + lastSnapshot
	// commitIndex=6 -> end=7, len(log)+lastSnapshot = 2+5 = 7, 7 <= 7 passes.
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	n.mu.Lock()
	n.lastSnapshot = 5
	n.lastApplied = 5
	n.commitIndex = 6
	n.log = []entry{
		{Index: 6, Term: 1, Command: []byte("a")},
		{Index: 7, Term: 1, Command: []byte("b")},
	}
	n.mu.Unlock()

	n.sendCommitted()

	n.mu.Lock()
	defer n.mu.Unlock()
	if n.lastApplied != 6 {
		t.Errorf("lastApplied = %d, want 6", n.lastApplied)
	}
	// Verify commit channel received the entry
	select {
	case c := <-n.commitCh:
		if len(c.Entries) != 1 {
			t.Errorf("commit entries len = %d, want 1", len(c.Entries))
		}
	default:
		t.Error("expected commit on channel")
	}
}

func TestSendCommittedChannelFull(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	// Fill the commit channel
	for i := 0; i < cap(n.commitCh); i++ {
		n.commitCh <- Commit{}
	}
	n.mu.Lock()
	n.commitIndex = 1
	n.lastApplied = 0
	n.log = []entry{{Index: 1, Term: 1}}
	n.mu.Unlock()
	// Should not block
	n.sendCommitted()
}

// ---------------------------------------------------------------------------
// 30. ClusterStats struct
// ---------------------------------------------------------------------------

func TestClusterStats(t *testing.T) {
	cs := ClusterStats{
		NodeID:       "n1",
		State:        "Leader",
		Term:         5,
		CommitIndex:  10,
		AppliedIndex: 8,
		IsLeader:     true,
	}
	if cs.NodeID != "n1" || !cs.IsLeader || cs.Term != 5 {
		t.Errorf("ClusterStats = %+v", cs)
	}
}

// ---------------------------------------------------------------------------
// 31. ZoneCommand with all fields
// ---------------------------------------------------------------------------

func TestZoneCommandAllFields(t *testing.T) {
	cmd := ZoneCommand{
		Type:     "add_record",
		Zone:     "example.com.",
		Name:     "www.example.com.",
		RRType:   1,
		TTL:      300,
		RData:    []string{"192.168.1.1"},
		Priority: 10,
		Metadata: json.RawMessage(`{"key":"value"}`),
	}
	data, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var decoded ZoneCommand
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if decoded.Priority != 10 {
		t.Errorf("Priority = %d, want 10", decoded.Priority)
	}
	if string(decoded.Metadata) != `{"key":"value"}` {
		t.Errorf("Metadata = %s, want {\"key\":\"value\"}", decoded.Metadata)
	}
}

// ---------------------------------------------------------------------------
// 32. NewJointConfig
// ---------------------------------------------------------------------------

func TestNewJointConfigCreation(t *testing.T) {
	old := map[NodeID]*Peer{"a": {ID: "a"}}
	newP := map[NodeID]*Peer{"a": {ID: "a"}, "b": {ID: "b"}}
	jc := NewJointConfig(old, newP)
	if len(jc.OldPeers) != 1 {
		t.Errorf("OldPeers len = %d, want 1", len(jc.OldPeers))
	}
	if len(jc.NewPeers) != 2 {
		t.Errorf("NewPeers len = %d, want 2", len(jc.NewPeers))
	}
}

// ---------------------------------------------------------------------------
// 33. EntryType constants values
// ---------------------------------------------------------------------------

func TestEntryTypeValues(t *testing.T) {
	if EntryNormal != 0 {
		t.Errorf("EntryNormal = %d, want 0", EntryNormal)
	}
	if EntryNoOp != 1 {
		t.Errorf("EntryNoOp = %d, want 1", EntryNoOp)
	}
	if EntryAddNode != 2 {
		t.Errorf("EntryAddNode = %d, want 2", EntryAddNode)
	}
	if EntryRemoveNode != 3 {
		t.Errorf("EntryRemoveNode = %d, want 3", EntryRemoveNode)
	}
	if EntryJointComplete != 4 {
		t.Errorf("EntryJointComplete = %d, want 4", EntryJointComplete)
	}
}

// ---------------------------------------------------------------------------
// 34. Index and Term type aliases
// ---------------------------------------------------------------------------

func TestIndexTermTypes(t *testing.T) {
	var idx Index = 42
	var trm Term = 7
	if uint64(idx) != 42 {
		t.Errorf("Index(42) != 42")
	}
	if uint64(trm) != 7 {
		t.Errorf("Term(7) != 7")
	}
}

// ---------------------------------------------------------------------------
// 35. Node.Stop without Start should not panic
// ---------------------------------------------------------------------------

func TestNodeStopWithoutStart(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	// Stop on unstarted node — close(stopCh) then wg.Wait()
	// The run() goroutine was never started, so wg counter is 0.
	// close(stopCh) will work fine, and wg.Wait() returns immediately.
	n.Stop()
}

// ---------------------------------------------------------------------------
// 36. sendVoteRequest / sendAppendRequest with nil transport
// ---------------------------------------------------------------------------

func TestSendVoteRequestNilTransport(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, nil)
	// Should not panic
	n.sendVoteRequest("peer", VoteRequest{Term: 1})
}

func TestSendAppendRequestNilTransport(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, nil)
	// Should not panic
	n.sendAppendRequest("peer", AppendRequest{Term: 1})
}

// ---------------------------------------------------------------------------
// 37. WAL re-open appends to existing file
// ---------------------------------------------------------------------------

func TestWALReopen(t *testing.T) {
	tmpDir := t.TempDir()
	wal, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatalf("NewWAL failed: %v", err)
	}
	wal.Write(entry{Index: 1, Term: 1, Command: []byte("first")})
	wal.Close()

	// Reopen and write more
	wal2, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatalf("NewWAL reopen failed: %v", err)
	}
	wal2.Write(entry{Index: 2, Term: 1, Command: []byte("second")})

	entries, err := wal2.ReadAll()
	wal2.Close()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("entries len = %d, want 2", len(entries))
	}
	if string(entries[0].Command) != "first" {
		t.Errorf("entries[0].Command = %q, want %q", entries[0].Command, "first")
	}
	if string(entries[1].Command) != "second" {
		t.Errorf("entries[1].Command = %q, want %q", entries[1].Command, "second")
	}
}

// ---------------------------------------------------------------------------
// 38. ZoneData struct
// ---------------------------------------------------------------------------

func TestZoneDataStruct(t *testing.T) {
	zd := &ZoneData{
		Zone:     "example.com.",
		Records:  map[string][]RecordEntry{"www.example.com.:1": {{Name: "www", RRType: 1, TTL: 300, RData: []byte("1.2.3.4")}}},
		Modified: true,
	}
	if zd.Zone != "example.com." {
		t.Errorf("Zone = %q", zd.Zone)
	}
	if !zd.Modified {
		t.Error("Modified should be true")
	}
}

// ---------------------------------------------------------------------------
// 39. RecordEntry struct
// ---------------------------------------------------------------------------

func TestRecordEntryStruct(t *testing.T) {
	re := RecordEntry{Name: "www", RRType: 1, TTL: 300, RData: []byte("1.2.3.4")}
	if re.Name != "www" || re.RRType != 1 || re.TTL != 300 || string(re.RData) != "1.2.3.4" {
		t.Errorf("RecordEntry = %+v", re)
	}
}

// ---------------------------------------------------------------------------
// 40. JointConfigProposal struct
// ---------------------------------------------------------------------------

func TestJointConfigProposalStruct(t *testing.T) {
	jcp := JointConfigProposal{
		Type:     EntryAddNode,
		PeerID:   "n3",
		PeerAddr: "addr",
		Proposed: time.Now(),
	}
	if jcp.PeerID != "n3" {
		t.Errorf("PeerID = %q, want %q", jcp.PeerID, "n3")
	}
}

// ---------------------------------------------------------------------------
// 41. Concurrent ZoneStateMachine operations
// ---------------------------------------------------------------------------

func TestZoneStateMachineConcurrentApply(t *testing.T) {
	zsm := NewZoneStateMachine()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				cmd := ZoneCommand{
					Type:   "add_record",
					Zone:   "concurrent.test.",
					Name:   fmt.Sprintf("r%d-%d.concurrent.test.", id, j),
					RRType: 1,
					TTL:    300,
					RData:  []string{fmt.Sprintf("10.%d.%d.1", id, j)},
				}
				zsm.Apply(entry{Command: mustMarshalJSON(cmd)})
			}
		}(i)
	}
	wg.Wait()
	recs := zsm.GetRecords("concurrent.test.")
	if len(recs) != 500 {
		t.Errorf("records = %d, want 500", len(recs))
	}
}

// ---------------------------------------------------------------------------
// 42. handleVoteRequest internal (via channel)
// ---------------------------------------------------------------------------

func TestHandleVoteRequestInternalRejectStaleTerm(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	n.mu.Lock()
	n.currentTerm = 5
	n.mu.Unlock()

	// Send via channel and drain the response
	go func() {
		n.voteCh <- VoteRequest{Term: 3, CandidateID: "c1", LastLogIndex: 1, LastLogTerm: 1}
	}()

	// The internal handler runs via runFollower/runCandidate, but we can test the
	// handler function directly — already tested via HandleVoteRequest exported.
	// Instead, test that the response channel receives the right answer:
	n.handleVoteRequest(VoteRequest{Term: 3, CandidateID: "c1"})

	resp := <-n.voteRespCh
	if resp.VoteGranted {
		t.Error("should not grant vote for stale term")
	}
	if resp.Term != 5 {
		t.Errorf("response term = %d, want 5", resp.Term)
	}
}

// ---------------------------------------------------------------------------
// 43. handleAppendRequest internal (via channel)
// ---------------------------------------------------------------------------

func TestHandleAppendRequestInternal(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	n.mu.Lock()
	n.currentTerm = 1
	n.log = []entry{{Index: 1, Term: 1}}
	n.mu.Unlock()

	n.handleAppendRequest(AppendRequest{
		Term:         2,
		LeaderID:     "leader",
		PrevLogIndex: 0,
		PrevLogTerm:  0,
		Entries:      []entry{{Index: 1, Term: 2}},
	})

	resp := <-n.appendRespCh
	if !resp.Success {
		t.Error("expected success")
	}
	n.mu.Lock()
	term := n.currentTerm
	n.mu.Unlock()
	if term != 2 {
		t.Errorf("term = %d, want 2", term)
	}
}

// ---------------------------------------------------------------------------
// 44. handleSnapshotRequest internal
// ---------------------------------------------------------------------------

func TestHandleSnapshotRequestInternal(t *testing.T) {
	n := NewNode(Config{NodeID: "n1"}, nil, &mockTransport{})
	n.mu.Lock()
	n.currentTerm = 1
	n.log = []entry{{Index: 1, Term: 1}}
	n.mu.Unlock()

	n.handleSnapshotRequest(SnapshotRequest{
		Term:     2,
		LeaderID: "leader",
		LastIndex: 10,
		LastTerm:  2,
	})

	n.mu.Lock()
	defer n.mu.Unlock()
	if n.lastSnapshot != 10 {
		t.Errorf("lastSnapshot = %d, want 10", n.lastSnapshot)
	}
	if len(n.log) != 0 {
		t.Errorf("log should be cleared after snapshot install")
	}
}

