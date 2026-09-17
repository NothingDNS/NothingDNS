package raft

// End-to-end test of the ClusterIntegration apply pipeline: a proposed zone
// change must commit, flow through the apply loop, and fire the apply hook
// (which projects committed commands onto the real zone store) before
// ProposeZoneChangeWait returns. Combined with the 3-node replication harness
// (harness_test.go), this proves zone writes are governed by Raft end to end.

import (
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

func TestClusterIntegration_ProposeAppliesViaHook(t *testing.T) {
	dir := t.TempDir()
	ci, err := NewClusterIntegration("n1", nil, nil, "127.0.0.1:0", dir, "", "", nil, util.DefaultLogger())
	if err != nil {
		t.Fatalf("NewClusterIntegration: %v", err)
	}

	var mu sync.Mutex
	var applied []ZoneCommand
	ci.SetApplyHook(func(cmd ZoneCommand) {
		mu.Lock()
		applied = append(applied, cmd)
		mu.Unlock()
	})

	if err := ci.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer ci.Stop()

	// Single node with no peers becomes leader on its own (randomized 1s+
	// election timeout; generous deadline for loaded CI runners).
	deadline := time.Now().Add(10 * time.Second)
	for !ci.IsLeader() {
		if time.Now().After(deadline) {
			t.Fatal("node did not become leader")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cmd := ZoneCommand{
		Type: "add_record", Zone: "example.com.", Name: "www",
		RRTypeStr: "A", Class: "IN", TTL: 300, RData: []string{"192.0.2.1"},
	}
	if err := ci.ProposeZoneChangeWait(cmd, 5*time.Second); err != nil {
		t.Fatalf("ProposeZoneChangeWait: %v", err)
	}

	// By the time the wait returns, the apply hook must already have run for
	// this command (that is the contract the API write path relies on).
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, c := range applied {
		if c.Type == "add_record" && c.Zone == "example.com." && c.Name == "www" && c.RRTypeStr == "A" {
			found = true
		}
	}
	if !found {
		t.Fatalf("apply hook never received the committed add_record (got %d cmds: %+v)", len(applied), applied)
	}
}
