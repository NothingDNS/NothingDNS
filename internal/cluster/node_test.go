package cluster

import (
	"testing"
	"time"
)

func TestNodeState_String(t *testing.T) {
	tests := []struct {
		state NodeState
		want  string
	}{
		{NodeStateUnknown, "unknown"},
		{NodeStateAlive, "alive"},
		{NodeStateSuspect, "suspect"},
		{NodeStateDead, "dead"},
		{NodeState(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("NodeState.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNode_IsAlive(t *testing.T) {
	tests := []struct {
		name string
		state NodeState
		want bool
	}{
		{"alive", NodeStateAlive, true},
		{"suspect", NodeStateSuspect, false},
		{"dead", NodeStateDead, false},
		{"unknown", NodeStateUnknown, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Node{State: tt.state}
			if got := n.IsAlive(); got != tt.want {
				t.Errorf("Node.IsAlive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNode_String(t *testing.T) {
	n := &Node{
		ID:   "test-node",
		Addr: "192.168.1.1",
		Port: 7946,
	}

	want := "test-node@192.168.1.1:7946"
	if got := n.String(); got != want {
		t.Errorf("Node.String() = %v, want %v", got, want)
	}
}

func TestNewNodeList(t *testing.T) {
	self := &Node{
		ID:    "self",
		Addr:  "127.0.0.1",
		Port:  7946,
		State: NodeStateAlive,
	}

	nl := NewNodeList(self)

	if nl.Count() != 1 {
		t.Errorf("Expected 1 node, got %d", nl.Count())
	}

	if got := nl.GetSelf(); got != self {
		t.Error("GetSelf() did not return self node")
	}
}

func TestNodeList_Add(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	// Add new node
	node1 := &Node{ID: "node1", State: NodeStateAlive, Version: 1}
	if !nl.Add(node1) {
		t.Error("Add() should return true for new node")
	}

	if nl.Count() != 2 {
		t.Errorf("Expected 2 nodes, got %d", nl.Count())
	}

	// Try to add with lower version (should not update)
	node1Old := &Node{ID: "node1", State: NodeStateDead, Version: 0}
	if nl.Add(node1Old) {
		t.Error("Add() should return false for older version")
	}

	// Verify state didn't change
	if n, _ := nl.Get("node1"); n.State != NodeStateAlive {
		t.Error("Node should still be alive")
	}

	// Add with higher version (should update)
	node1New := &Node{ID: "node1", State: NodeStateDead, Version: 2}
	if !nl.Add(node1New) {
		t.Error("Add() should return true for newer version")
	}

	if n, _ := nl.Get("node1"); n.State != NodeStateDead {
		t.Error("Node should be dead after update")
	}
}

func TestNodeList_UpdateState(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	// Add a node
	node1 := &Node{ID: "node1", State: NodeStateAlive}
	nl.Add(node1)

	// Update state
	if !nl.UpdateState("node1", NodeStateSuspect) {
		t.Error("UpdateState() should return true for existing node")
	}

	if n, _ := nl.Get("node1"); n.State != NodeStateSuspect {
		t.Errorf("Expected state suspect, got %v", n.State)
	}

	// Try to update self (should fail)
	if nl.UpdateState("self", NodeStateDead) {
		t.Error("UpdateState() should return false for self")
	}

	// Try to update non-existent node
	if nl.UpdateState("nonexistent", NodeStateDead) {
		t.Error("UpdateState() should return false for non-existent node")
	}
}

func TestNodeList_GetAlive(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	// Add nodes in different states
	nl.Add(&Node{ID: "alive1", State: NodeStateAlive})
	nl.Add(&Node{ID: "alive2", State: NodeStateAlive})
	nl.Add(&Node{ID: "suspect", State: NodeStateSuspect})
	nl.Add(&Node{ID: "dead", State: NodeStateDead})

	alive := nl.GetAlive()
	if len(alive) != 2 {
		t.Errorf("Expected 2 alive nodes (excluding self), got %d", len(alive))
	}

	for _, n := range alive {
		if n.ID == "self" {
			t.Error("GetAlive() should not include self")
		}
		if !n.IsAlive() {
			t.Errorf("Node %s should be alive", n.ID)
		}
	}
}

func TestNodeList_AliveCount(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	nl.Add(&Node{ID: "node1", State: NodeStateAlive})
	nl.Add(&Node{ID: "node2", State: NodeStateSuspect})
	nl.Add(&Node{ID: "node3", State: NodeStateDead})

	// AliveCount includes self
	if got := nl.AliveCount(); got != 2 {
		t.Errorf("AliveCount() = %d, want 2 (self + node1)", got)
	}
}

func TestNodeList_MarkSeen(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	node1 := &Node{ID: "node1", State: NodeStateAlive, LastSeen: time.Now().Add(-1 * time.Hour)}
	nl.Add(node1)

	oldSeen := node1.LastSeen
	time.Sleep(10 * time.Millisecond)
	nl.MarkSeen("node1")

	if n, _ := nl.Get("node1"); !n.LastSeen.After(oldSeen) {
		t.Error("LastSeen should be updated")
	}
}

func TestNodeList_Remove(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	nl.Add(&Node{ID: "node1", State: NodeStateAlive})
	nl.Remove("node1")

	if nl.Count() != 1 {
		t.Errorf("Expected 1 node after removal, got %d", nl.Count())
	}

	if _, ok := nl.Get("node1"); ok {
		t.Error("Node should not exist after removal")
	}
}

func TestGenerateNodeID(t *testing.T) {
	id1 := GenerateNodeID()
	id2 := GenerateNodeID()

	if id1 == "" {
		t.Error("GenerateNodeID() should not return empty string")
	}

	if id1 == id2 {
		t.Error("GenerateNodeID() should generate unique IDs")
	}

	// Should be hex encoded (16 characters for 8 bytes)
	if len(id1) != 16 {
		t.Errorf("Expected ID length 16, got %d", len(id1))
	}
}

func TestGetLocalIP(t *testing.T) {
	ip, err := GetLocalIP()
	if err != nil {
		t.Fatalf("GetLocalIP() error = %v", err)
	}

	if ip == "" {
		t.Error("GetLocalIP() should not return empty string")
	}

	// Should be a valid IP address
	if ip == "127.0.0.1" {
		// This is expected if no non-loopback interface exists
		t.Log("GetLocalIP() returned loopback - no non-loopback interface found")
	}
}

func TestNodeList_GetRandom(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	// With no other nodes, should return nil
	if got := nl.GetRandom(nil); got != nil {
		t.Error("GetRandom() should return nil when no other nodes exist")
	}

	// Add some nodes
	nl.Add(&Node{ID: "node1", State: NodeStateAlive})
	nl.Add(&Node{ID: "node2", State: NodeStateAlive})
	nl.Add(&Node{ID: "node3", State: NodeStateSuspect})

	// Should return an alive node
	got := nl.GetRandom(nil)
	if got == nil {
		t.Fatal("GetRandom() should not return nil")
	}

	if got.ID == "self" {
		t.Error("GetRandom() should not return self")
	}

	if !got.IsAlive() {
		t.Error("GetRandom() should return an alive node")
	}

	// Test with exclusion
	got = nl.GetRandom([]string{"node1", "node2"})
	if got != nil {
		t.Error("GetRandom() should return nil when all nodes excluded")
	}
}
