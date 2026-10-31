package raft

import "testing"

// A leader deposed by a newer term seen in an AppendEntries response steps
// down without a leadership notification. It must stop reporting itself as
// leader, both through IsLeader and as the known leader ID.
func TestDeposedLeaderStopsReportingLeadership(t *testing.T) {
	n, _ := NewNode(Config{NodeID: "n1"}, []NodeID{"n2", "n3"}, &mockTransport{})
	ci := &ClusterIntegration{node: n, nodeID: "n1"}

	n.mu.Lock()
	n.currentTerm = 4
	n.mu.Unlock()
	n.becomeLeader(4)
	if !ci.IsLeader() || ci.GetLeaderID() != "n1" {
		t.Fatalf("after election: IsLeader=%v leader=%q, want true n1", ci.IsLeader(), ci.GetLeaderID())
	}

	n.handleAppendResponse(AppendResponse{Term: 5, From: "n2"})

	if ci.IsLeader() {
		t.Error("IsLeader = true after a newer term deposed the node")
	}
	if got := ci.GetLeaderID(); got != "" {
		t.Errorf("GetLeaderID = %q after step-down, want \"\" until the new leader is heard", got)
	}
	if st := ci.Stats(); st.IsLeader || st.State != "Follower" || st.Term != 5 {
		t.Errorf("Stats = %+v, want Follower term 5, not leader", st)
	}

	n.mu.Lock()
	n.appendEntriesLocked(AppendRequest{Term: 5, LeaderID: "n2"})
	n.mu.Unlock()
	if got := ci.GetLeaderID(); got != "n2" {
		t.Errorf("GetLeaderID = %q after the new leader's AppendEntries, want n2", got)
	}
}

// A vote request for a newer term clears the leader known from the old term.
func TestNewerTermVoteRequestForgetsOldLeader(t *testing.T) {
	n, _ := NewNode(Config{NodeID: "n1"}, []NodeID{"n2", "n3"}, &mockTransport{})
	n.mu.Lock()
	n.currentTerm = 3
	n.mu.Unlock()
	n.mu.Lock()
	n.appendEntriesLocked(AppendRequest{Term: 3, LeaderID: "n2"})
	n.mu.Unlock()
	if n.LeaderID() != "n2" {
		t.Fatalf("leader = %q, want n2", n.LeaderID())
	}

	n.mu.Lock()
	if err := n.advanceTermLocked(4); err != nil {
		t.Fatal(err)
	}
	n.mu.Unlock()
	if got := n.LeaderID(); got != "" {
		t.Errorf("leader = %q after term 4 began, want \"\"", got)
	}
}
