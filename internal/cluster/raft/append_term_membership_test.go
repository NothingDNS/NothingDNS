package raft

import (
	"errors"
	"testing"
)

// TestHandleAppendResponse_IgnoresStaleTerm verifies that an AppendEntries
// success from an earlier term does not advance matchIndex. Previously the
// handler only guarded resp.Term > currentTerm, so a delayed success from a
// prior leadership stint could over-advance matchIndex and falsely commit.
func TestHandleAppendResponse_IgnoresStaleTerm(t *testing.T) {
	config := DefaultConfig()
	config.NodeID = "node1"
	node, _ := NewNode(config, []NodeID{"p"}, &mockTransport{})

	node.mu.Lock()
	node.state = StateLeader
	node.currentTerm = 5
	node.matchIndex["p"] = 2
	node.nextIndex["p"] = 3
	node.mu.Unlock()

	// Stale success from term 4 must be ignored.
	node.handleAppendResponse(AppendResponse{Term: 4, Success: true, From: "p", MatchIndex: 100})
	node.mu.Lock()
	got := node.matchIndex["p"]
	node.mu.Unlock()
	if got != 2 {
		t.Fatalf("stale-term response advanced matchIndex to %d, want 2 (unchanged)", got)
	}

	// A current-term success DOES advance matchIndex.
	node.handleAppendResponse(AppendResponse{Term: 5, Success: true, From: "p", MatchIndex: 7})
	node.mu.Lock()
	got = node.matchIndex["p"]
	node.mu.Unlock()
	if got != 7 {
		t.Fatalf("current-term response set matchIndex to %d, want 7", got)
	}
}

// TestMembershipChanges_FailClosed verifies runtime AddNode/RemoveNode return
// ErrMembershipChangeUnsupported instead of corrupting the log via the
// incomplete joint-consensus path.
func TestMembershipChanges_FailClosed(t *testing.T) {
	dir := t.TempDir()
	ci, err := NewClusterIntegration("n1", nil, nil, freeTCPAddr(t), dir, "", "", nil, nil)
	if err != nil {
		t.Fatalf("NewClusterIntegration: %v", err)
	}

	if err := ci.AddNode("n2", "127.0.0.1:9999"); !errors.Is(err, ErrMembershipChangeUnsupported) {
		t.Errorf("AddNode error = %v, want ErrMembershipChangeUnsupported", err)
	}
	if err := ci.RemoveNode("n2"); !errors.Is(err, ErrMembershipChangeUnsupported) {
		t.Errorf("RemoveNode error = %v, want ErrMembershipChangeUnsupported", err)
	}
}
