package raft

import (
	"testing"
	"time"
)

// mockTransport implements Transport for testing.
type mockTransport struct {
	sendVoteCalled     int
	sendAppendCalled  int
	voteResp          *VoteResponse
	appendResp        *AppendResponse
	voteRespErr       error
	appendRespErr     error
}

func (m *mockTransport) SendRequestVote(peerID NodeID, req VoteRequest) (*VoteResponse, error) {
	m.sendVoteCalled++
	return m.voteResp, m.voteRespErr
}

func (m *mockTransport) SendAppendEntries(peerID NodeID, req AppendRequest) (*AppendResponse, error) {
	m.sendAppendCalled++
	return m.appendResp, m.appendRespErr
}

func (m *mockTransport) SendSnapshot(peerID NodeID, req SnapshotRequest) error {
	return nil
}

func TestNewNode(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "node1"
	config.HeartbeatInterval = 50 * time.Millisecond
	config.ElectionTimeout = 150 * time.Millisecond

	node := NewNode(config, []NodeID{"node2", "node3"}, transport)

	if node == nil {
		t.Fatal("NewNode returned nil")
	}
	if node.State() != StateFollower {
		t.Errorf("expected initial state StateFollower, got %v", node.State())
	}
	if node.Term() != 0 {
		t.Errorf("expected initial term 0, got %v", node.Term())
	}
	if len(node.peers) != 2 {
		t.Errorf("expected 2 peers, got %d", len(node.peers))
	}
	if node.nextIndex["node2"] != 0 {
		t.Errorf("expected nextIndex 0 for node2, got %v", node.nextIndex["node2"])
	}
}

func TestNodeStartStop(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "node1"

	node := NewNode(config, nil, transport)

	// Test that node can be created and stopped without starting
	// (Start would require proper async handling for election timeouts)
	node.Stop()
}

func TestHandleVoteRequest(t *testing.T) {
	tests := []struct {
		name        string
		nodeTerm    Term
		votedFor    NodeID
		candidateTerm Term
		lastLogIdx  Index
		lastLogTerm Term
		wantGranted bool
		wantTerm    Term
	}{
		{
			name:        "vote for candidate with newer term",
			nodeTerm:    1,
			votedFor:    "",
			candidateTerm: 2,
			lastLogIdx:  1,
			lastLogTerm: 1,
			wantGranted: true,
			wantTerm:    2,
		},
		{
			name:        "reject candidate with older term",
			nodeTerm:    3,
			votedFor:    "",
			candidateTerm: 2,
			lastLogIdx:  1,
			lastLogTerm: 1,
			wantGranted: false,
			wantTerm:    3,
		},
		{
			name:        "reject already voted for different candidate",
			nodeTerm:    2,
			votedFor:    "node3",
			candidateTerm: 2,
			lastLogIdx:  1,
			lastLogTerm: 1,
			wantGranted: false,
			wantTerm:    2,
		},
		{
			name:        "allow vote for same candidate again",
			nodeTerm:    2,
			votedFor:    "node2",
			candidateTerm: 2,
			lastLogIdx:  1,
			lastLogTerm: 1,
			wantGranted: true,
			wantTerm:    2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &mockTransport{}
			config := DefaultConfig()
			config.NodeID = "node1"

			node := NewNode(config, nil, transport)
			node.mu.Lock()
			node.currentTerm = tt.nodeTerm
			node.votedFor = tt.votedFor
			node.mu.Unlock()

			req := VoteRequest{
				Term:         tt.candidateTerm,
				CandidateID:  "node2",
				LastLogIndex: tt.lastLogIdx,
				LastLogTerm:  tt.lastLogTerm,
			}

			resp := node.HandleVoteRequest(req)

			if resp.VoteGranted != tt.wantGranted {
				t.Errorf("VoteGranted = %v, want %v", resp.VoteGranted, tt.wantGranted)
			}
			if resp.Term != tt.wantTerm {
				t.Errorf("Term = %v, want %v", resp.Term, tt.wantTerm)
			}
		})
	}
}

func TestHandleAppendRequest(t *testing.T) {
	tests := []struct {
		name       string
		nodeTerm   Term
		log        []entry
		prevIdx    Index
		prevTerm   Term
		entries    []entry
		leaderComm Index
		leaderTerm Term // Leader's term (different from node's term for stale tests)
		wantSucc   bool
		wantTerm   Term
	}{
		{
			name:       "successful append",
			nodeTerm:   1,
			leaderTerm: 1,
			log:        []entry{{Index: 1, Term: 1}},
			prevIdx:    1,
			prevTerm:   1,
			entries:     []entry{{Index: 2, Term: 1, Command: []byte("test")}},
			leaderComm: 1,
			wantSucc:   true,
			wantTerm:   1,
		},
		{
			name:       "reject stale term",
			nodeTerm:   3,
			leaderTerm: 2, // Leader has older term than follower
			log:        []entry{},
			prevIdx:    0,
			prevTerm:   0,
			entries:     []entry{{Index: 1, Term: 2}},
			leaderComm: 0,
			wantSucc:   false,
			wantTerm:   3,
		},
		{
			name:       "reject inconsistent prev log",
			nodeTerm:   1,
			leaderTerm: 1,
			log:        []entry{{Index: 1, Term: 2}}, // term mismatch
			prevIdx:    1,
			prevTerm:   1,
			entries:     []entry{{Index: 2, Term: 1}},
			leaderComm: 1,
			wantSucc:   false,
			wantTerm:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &mockTransport{}
			config := DefaultConfig()
			config.NodeID = "node1"

			node := NewNode(config, nil, transport)
			node.mu.Lock()
			node.currentTerm = tt.nodeTerm
			node.log = tt.log
			node.mu.Unlock()

			req := AppendRequest{
				Term:         tt.leaderTerm,
				LeaderID:     "node2",
				PrevLogIndex: tt.prevIdx,
				PrevLogTerm:  tt.prevTerm,
				Entries:      tt.entries,
				LeaderCommit: tt.leaderComm,
			}

			resp := node.HandleAppendRequest(req)

			if resp.Success != tt.wantSucc {
				t.Errorf("Success = %v, want %v", resp.Success, tt.wantSucc)
			}
			if resp.Term != tt.wantTerm {
				t.Errorf("Term = %v, want %v", resp.Term, tt.wantTerm)
			}
		})
	}
}

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateLeader, "Leader"},
		{StateFollower, "Follower"},
		{StateCandidate, "Candidate"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("State.String() = %v, want %v", got, tt.want)
		}
	}
}

func TestNodePeers(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "node1"

	node := NewNode(config, []NodeID{"node2", "node3", "node4"}, transport)

	if len(node.peers) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(node.peers))
	}

	// AddPeer with joint consensus - creates joint config but doesn't update peers until commit
	err := node.AddPeer("node5", "127.0.0.1:9005")
	if err != nil {
		t.Fatalf("AddPeer failed: %v", err)
	}
	// With joint consensus, peers map still shows old config until joint is committed
	if len(node.peers) != 3 {
		t.Errorf("expected 3 peers before joint commit, got %d", len(node.peers))
	}
	// But joint config is created
	if node.jointConfig == nil {
		t.Error("expected joint config to be created")
	}

	// Simulate joint commit and advance
	node.commitIndex = node.jointConfigIdx
	node.advanceJointConfig()
	if len(node.peers) != 4 {
		t.Errorf("expected 4 peers after joint commit, got %d", len(node.peers))
	}

	// Test RemovePeer with joint consensus
	err = node.RemovePeer("node2")
	if err != nil {
		t.Fatalf("RemovePeer failed: %v", err)
	}
	if len(node.peers) != 4 {
		t.Errorf("expected 4 peers before joint commit, got %d", len(node.peers))
	}

	node.commitIndex = node.jointConfigIdx
	node.advanceJointConfig()
	if len(node.peers) != 3 {
		t.Errorf("expected 3 peers after remove joint commit, got %d", len(node.peers))
	}
}

func TestPropose(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "node1"

	node := NewNode(config, []NodeID{"node2"}, transport)

	// Propose returns error when not leader (expected)
	err := node.Propose([]byte("test command"), EntryNormal)
	if err == nil {
		t.Error("Propose should return error when not leader")
	}

	node.Stop()
}

func TestLeadershipCh(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "node1"

	node := NewNode(config, []NodeID{"node2"}, transport)

	ch := node.LeadershipCh()
	if ch == nil {
		t.Error("LeadershipCh returned nil channel")
	}
}
