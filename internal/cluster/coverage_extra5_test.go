package cluster

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/util"
)

// ---------------------------------------------------------------------------
// 1. NodeHealthStats.HealthScore() — table-driven tests for all penalty tiers
// ---------------------------------------------------------------------------

func TestNodeHealthStats_HealthScore(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name  string
		stats NodeHealthStats
		want  int
	}{
		{
			name:  "zero LastUpdated returns default 50",
			stats: NodeHealthStats{},
			want:  50,
		},
		{
			name: "perfect health is 100",
			stats: NodeHealthStats{
				LatencyMs:     10,
				CPUPercent:    5,
				MemoryPercent: 30,
				ActiveConns:   50,
				LastUpdated:   now,
			},
			want: 100,
		},
		// --- latency penalties ---
		{
			name: "latency >500ms penalised -50",
			stats: NodeHealthStats{
				LatencyMs:     600,
				CPUPercent:    5,
				MemoryPercent: 30,
				ActiveConns:   50,
				LastUpdated:   now,
			},
			want: 50,
		},
		{
			name: "latency >200ms penalised -25",
			stats: NodeHealthStats{
				LatencyMs:     250,
				CPUPercent:    5,
				MemoryPercent: 30,
				ActiveConns:   50,
				LastUpdated:   now,
			},
			want: 75,
		},
		{
			name: "latency >100ms penalised -10",
			stats: NodeHealthStats{
				LatencyMs:     150,
				CPUPercent:    5,
				MemoryPercent: 30,
				ActiveConns:   50,
				LastUpdated:   now,
			},
			want: 90,
		},
		{
			name: "latency boundary 100 no penalty",
			stats: NodeHealthStats{
				LatencyMs:     100,
				CPUPercent:    5,
				MemoryPercent: 30,
				ActiveConns:   50,
				LastUpdated:   now,
			},
			want: 100,
		},
		// --- CPU penalties ---
		{
			name: "cpu >80 penalised -40",
			stats: NodeHealthStats{
				LatencyMs:     10,
				CPUPercent:    90,
				MemoryPercent: 30,
				ActiveConns:   50,
				LastUpdated:   now,
			},
			want: 60,
		},
		{
			name: "cpu >60 penalised -20",
			stats: NodeHealthStats{
				LatencyMs:     10,
				CPUPercent:    70,
				MemoryPercent: 30,
				ActiveConns:   50,
				LastUpdated:   now,
			},
			want: 80,
		},
		{
			name: "cpu >40 penalised -10",
			stats: NodeHealthStats{
				LatencyMs:     10,
				CPUPercent:    50,
				MemoryPercent: 30,
				ActiveConns:   50,
				LastUpdated:   now,
			},
			want: 90,
		},
		// --- memory penalties ---
		{
			name: "memory >85 penalised -30",
			stats: NodeHealthStats{
				LatencyMs:     10,
				CPUPercent:    5,
				MemoryPercent: 90,
				ActiveConns:   50,
				LastUpdated:   now,
			},
			want: 70,
		},
		{
			name: "memory >70 penalised -15",
			stats: NodeHealthStats{
				LatencyMs:     10,
				CPUPercent:    5,
				MemoryPercent: 75,
				ActiveConns:   50,
				LastUpdated:   now,
			},
			want: 85,
		},
		// --- connection penalties ---
		{
			name: "conns >800 penalised -30",
			stats: NodeHealthStats{
				LatencyMs:     10,
				CPUPercent:    5,
				MemoryPercent: 30,
				ActiveConns:   900,
				LastUpdated:   now,
			},
			want: 70,
		},
		{
			name: "conns >500 penalised -15",
			stats: NodeHealthStats{
				LatencyMs:     10,
				CPUPercent:    5,
				MemoryPercent: 30,
				ActiveConns:   600,
				LastUpdated:   now,
			},
			want: 85,
		},
		{
			name: "conns >300 penalised -5",
			stats: NodeHealthStats{
				LatencyMs:     10,
				CPUPercent:    5,
				MemoryPercent: 30,
				ActiveConns:   400,
				LastUpdated:   now,
			},
			want: 95,
		},
		// --- cumulative penalties: everything severe, score clamped to 0 ---
		{
			name: "all severe clamped to 0",
			stats: NodeHealthStats{
				LatencyMs:     600,  // -50
				CPUPercent:    90,   // -40
				MemoryPercent: 90,   // -30
				ActiveConns:   900,  // -30
				LastUpdated:   now,
			},
			want: 0, // 100 - 50 - 40 - 30 - 30 = -50, clamped to 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.stats.HealthScore()
			if got != tt.want {
				t.Errorf("HealthScore() = %d, want %d", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2. NodeList.UpdateHealth — field propagation
// ---------------------------------------------------------------------------

func TestNodeList_UpdateHealth_ExistingNode(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	other := &Node{ID: "other", State: NodeStateAlive}
	nl.Add(other)

	health := NodeHealthStats{
		QueriesPerSecond: 123.4,
		LatencyMs:        5.6,
		CPUPercent:       42.0,
		MemoryPercent:    60.0,
		ActiveConns:      200,
		LastUpdated:      time.Now(),
	}

	ok := nl.UpdateHealth("other", health)
	if !ok {
		t.Fatal("UpdateHealth should return true for existing node")
	}

	node, found := nl.Get("other")
	if !found {
		t.Fatal("node should exist")
	}

	if node.Health.QueriesPerSecond != 123.4 {
		t.Errorf("QueriesPerSecond = %f, want 123.4", node.Health.QueriesPerSecond)
	}
	if node.Health.LatencyMs != 5.6 {
		t.Errorf("LatencyMs = %f, want 5.6", node.Health.LatencyMs)
	}
	if node.Health.CPUPercent != 42.0 {
		t.Errorf("CPUPercent = %f, want 42.0", node.Health.CPUPercent)
	}
	if node.Health.MemoryPercent != 60.0 {
		t.Errorf("MemoryPercent = %f, want 60.0", node.Health.MemoryPercent)
	}
	if node.Health.ActiveConns != 200 {
		t.Errorf("ActiveConns = %d, want 200", node.Health.ActiveConns)
	}
	if node.Health.LastUpdated.IsZero() {
		t.Error("LastUpdated should be set")
	}
	// LastSeen should also be refreshed
	if node.LastSeen.IsZero() {
		t.Error("LastSeen should have been updated")
	}
}

func TestNodeList_UpdateHealth_NonExistentNode(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	ok := nl.UpdateHealth("ghost", NodeHealthStats{})
	if ok {
		t.Error("UpdateHealth should return false for non-existent node")
	}
}

func TestNodeList_UpdateHealth_SelfNode(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	health := NodeHealthStats{
		LatencyMs:   12.0,
		LastUpdated: time.Now(),
	}

	ok := nl.UpdateHealth("self", health)
	if !ok {
		t.Fatal("UpdateHealth should succeed for self node")
	}

	node, _ := nl.Get("self")
	if node.Health.LatencyMs != 12.0 {
		t.Errorf("self Health.LatencyMs = %f, want 12.0", node.Health.LatencyMs)
	}
}

// ---------------------------------------------------------------------------
// 3. NodeList.GetBest — weighted-random health-based node selection
// ---------------------------------------------------------------------------

func TestNodeList_GetBest_EmptyList(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	// Only self in list, no other alive nodes
	got := nl.GetBest(nil)
	if got != nil {
		t.Error("GetBest() should return nil when no other alive nodes exist")
	}
}

func TestNodeList_GetBest_SingleAliveNode(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	other := &Node{
		ID:    "other",
		State: NodeStateAlive,
		Health: NodeHealthStats{
			LatencyMs:     10,
			CPUPercent:    20,
			MemoryPercent: 30,
			ActiveConns:   50,
			LastUpdated:   time.Now(),
		},
	}
	nl.Add(other)

	got := nl.GetBest(nil)
	if got == nil {
		t.Fatal("GetBest() should return the single alive node")
	}
	if got.ID != "other" {
		t.Errorf("GetBest() returned node %s, want other", got.ID)
	}
}

func TestNodeList_GetBest_ExcludesDrainingNodes(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	draining := &Node{ID: "draining", State: NodeStateDraining}
	nl.Add(draining)

	got := nl.GetBest(nil)
	if got != nil {
		t.Error("GetBest() should return nil when only draining nodes are available")
	}
}

func TestNodeList_GetBest_ExcludesDeadNodes(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	dead := &Node{ID: "dead", State: NodeStateDead}
	nl.Add(dead)

	got := nl.GetBest(nil)
	if got != nil {
		t.Error("GetBest() should return nil when only dead nodes are available")
	}
}

func TestNodeList_GetBest_MultipleNodes(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	now := time.Now()

	// healthy node
	n1 := &Node{
		ID:    "healthy",
		State: NodeStateAlive,
		Health: NodeHealthStats{
			LatencyMs:     5,
			CPUPercent:    10,
			MemoryPercent: 20,
			ActiveConns:   30,
			LastUpdated:   now,
		},
	}
	// unhealthy node
	n2 := &Node{
		ID:    "unhealthy",
		State: NodeStateAlive,
		Health: NodeHealthStats{
			LatencyMs:     600,
			CPUPercent:    90,
			MemoryPercent: 90,
			ActiveConns:   900,
			LastUpdated:   now,
		},
	}
	nl.Add(n1)
	nl.Add(n2)

	// With many iterations the healthy node should be chosen far more often.
	healthyCount := 0
	unhealthyCount := 0
	for i := 0; i < 200; i++ {
		got := nl.GetBest(nil)
		if got == nil {
			t.Fatal("GetBest() should not return nil with alive nodes")
		}
		switch got.ID {
		case "healthy":
			healthyCount++
		case "unhealthy":
			unhealthyCount++
		}
	}

	// The healthy node (score 100) should be selected much more often than
	// the unhealthy node (score 0).
	if healthyCount <= unhealthyCount {
		t.Errorf("expected healthy node to be selected more often: healthy=%d unhealthy=%d", healthyCount, unhealthyCount)
	}
}

func TestNodeList_GetBest_WithExclusion(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	n1 := &Node{ID: "node1", State: NodeStateAlive}
	n2 := &Node{ID: "node2", State: NodeStateAlive}
	nl.Add(n1)
	nl.Add(n2)

	// Exclude node1
	got := nl.GetBest([]string{"node1"})
	if got == nil {
		t.Fatal("GetBest() should still return node2")
	}
	if got.ID != "node2" {
		t.Errorf("GetBest() returned %s, want node2", got.ID)
	}

	// Exclude both
	got = nl.GetBest([]string{"node1", "node2"})
	if got != nil {
		t.Error("GetBest() should return nil when all excluded")
	}
}

// ---------------------------------------------------------------------------
// 4. NodeList.GetAllWithHealth
// ---------------------------------------------------------------------------

func TestNodeList_GetAllWithHealth(t *testing.T) {
	self := &Node{
		ID:    "self",
		State: NodeStateAlive,
		Health: NodeHealthStats{
			LatencyMs:   5.0,
			LastUpdated: time.Now(),
		},
	}
	nl := NewNodeList(self)

	other := &Node{
		ID:    "other",
		State: NodeStateAlive,
		Health: NodeHealthStats{
			CPUPercent:  55.0,
			LastUpdated: time.Now(),
		},
	}
	nl.Add(other)

	nodes := nl.GetAllWithHealth()
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}

	found := map[string]bool{}
	for _, n := range nodes {
		found[n.ID] = true
		if n.ID == "self" && n.Health.LatencyMs != 5.0 {
			t.Errorf("self LatencyMs = %f, want 5.0", n.Health.LatencyMs)
		}
		if n.ID == "other" && n.Health.CPUPercent != 55.0 {
			t.Errorf("other CPUPercent = %f, want 55.0", n.Health.CPUPercent)
		}
	}
	if !found["self"] || !found["other"] {
		t.Error("GetAllWithHealth() should include self and other nodes")
	}
}

func TestNodeList_GetAllWithHealth_EmptyHealth(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	nodes := nl.GetAllWithHealth()
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	// Health should be zero-valued
	if nodes[0].Health.LastUpdated.IsZero() == false {
		t.Error("expected zero-valued LastUpdated when no health set")
	}
}

// ---------------------------------------------------------------------------
// 5. Node.IsDraining
// ---------------------------------------------------------------------------

func TestNode_IsDraining(t *testing.T) {
	tests := []struct {
		name  string
		state NodeState
		want  bool
	}{
		{"alive", NodeStateAlive, false},
		{"suspect", NodeStateSuspect, false},
		{"dead", NodeStateDead, false},
		{"unknown", NodeStateUnknown, false},
		{"draining", NodeStateDraining, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Node{State: tt.state}
			if got := n.IsDraining(); got != tt.want {
				t.Errorf("IsDraining() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 6. Cluster.GetLeader / Cluster.IsLeader — thin wrappers around gossip state
// ---------------------------------------------------------------------------

func TestCluster_GetLeader_NoGossip(t *testing.T) {
	// Construct a Cluster directly without gossip to hit the nil-gossip branch.
	c := &Cluster{
		config:    Config{NodeID: "solo"},
		consensus: ConsensusSWIM,
		// gossip is nil
	}

	leaderID, ok := c.GetLeader()
	if ok {
		t.Error("GetLeader() ok should be false when gossip is nil")
	}
	if leaderID != "" {
		t.Errorf("leaderID = %q, want empty", leaderID)
	}
}

func TestCluster_IsLeader_NoGossip(t *testing.T) {
	c := &Cluster{
		config:    Config{NodeID: "solo"},
		consensus: ConsensusSWIM,
	}

	if c.IsLeader() {
		t.Error("IsLeader() should return false when gossip is nil")
	}
}

func TestCluster_GetLeader_WithGossip(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:              true,
		NodeID:               "leader-test",
		BindAddr:             "127.0.0.1",
		GossipPort:           49001,
		AllowInsecureCluster: true, // test: no encryption key required
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Initially no leader elected
	leaderID, ok := c.GetLeader()
	if ok && leaderID != "" {
		t.Logf("GetLeader() returned leader=%s (may have been elected), ok=%v", leaderID, ok)
	}

	// Manually set the leader in the gossip protocol for deterministic test
	c.gossip.leaderMu.Lock()
	c.gossip.currentLeader = "leader-test"
	c.gossip.isLeader = true
	c.gossip.leaderMu.Unlock()

	leaderID, ok = c.GetLeader()
	if !ok {
		t.Error("GetLeader() ok should be true after setting leader")
	}
	if leaderID != "leader-test" {
		t.Errorf("leaderID = %q, want leader-test", leaderID)
	}

	if !c.IsLeader() {
		t.Error("IsLeader() should return true after setting isLeader")
	}
}

// ---------------------------------------------------------------------------
// 7. Cluster.DetectSplitBrain
// ---------------------------------------------------------------------------

func TestCluster_DetectSplitBrain_NoGossip(t *testing.T) {
	c := &Cluster{
		config:    Config{NodeID: "solo"},
		consensus: ConsensusSWIM,
	}

	if c.DetectSplitBrain() {
		t.Error("DetectSplitBrain() should return false when gossip is nil")
	}
}

func TestCluster_DetectSplitBrain_NotLeader(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:              true,
		NodeID:               "sb-not-leader",
		BindAddr:             "127.0.0.1",
		GossipPort:           49002,
		AllowInsecureCluster: true, // test: no encryption key required
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Not the leader, so DetectSplitBrain should return false
	if c.DetectSplitBrain() {
		t.Error("DetectSplitBrain() should return false when this node is not leader")
	}
}

func TestCluster_DetectSplitBrain_AsLeader_NoSplit(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:              true,
		NodeID:               "sb-leader",
		BindAddr:             "127.0.0.1",
		GossipPort:           49003,
		AllowInsecureCluster: true, // test: no encryption key required
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Set as leader, electionTerm == leaderTerm (no split brain)
	c.gossip.leaderMu.Lock()
	c.gossip.isLeader = true
	c.gossip.currentLeader = "sb-leader"
	c.gossip.leaderTerm = 5
	c.gossip.electionTerm = 5
	c.gossip.leaderMu.Unlock()

	if c.DetectSplitBrain() {
		t.Error("DetectSplitBrain() should return false when electionTerm == leaderTerm")
	}
}

func TestCluster_DetectSplitBrain_AsLeader_SplitDetected(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:              true,
		NodeID:               "sb-split",
		BindAddr:             "127.0.0.1",
		GossipPort:           49004,
		AllowInsecureCluster: true, // test: no encryption key required
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Set as leader but electionTerm > leaderTerm => split brain
	c.gossip.leaderMu.Lock()
	c.gossip.isLeader = true
	c.gossip.currentLeader = "sb-split"
	c.gossip.leaderTerm = 3
	c.gossip.electionTerm = 7
	c.gossip.leaderMu.Unlock()

	if !c.DetectSplitBrain() {
		t.Error("DetectSplitBrain() should return true when electionTerm > leaderTerm")
	}

	// After split brain detected, leadership should be revoked
	c.gossip.leaderMu.RLock()
	isLeader := c.gossip.isLeader
	leader := c.gossip.currentLeader
	c.gossip.leaderMu.RUnlock()

	if isLeader {
		t.Error("isLeader should be false after split brain detection")
	}
	if leader != "" {
		t.Errorf("currentLeader should be empty after split brain, got %q", leader)
	}
}

// ---------------------------------------------------------------------------
// 8. Cluster.StartDraining / Cluster.CompleteDraining
// ---------------------------------------------------------------------------

func TestCluster_StartDraining_NotStarted(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:              true,
		NodeID:               "drain-not-started",
		BindAddr:             "127.0.0.1",
		GossipPort:           49005,
		AllowInsecureCluster: true, // test: no encryption key required
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Do NOT start the cluster

	err = c.StartDraining()
	if err == nil {
		t.Error("StartDraining() should return error when cluster not started")
	}
}

func TestCluster_StartDraining_Succeeds(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:              true,
		NodeID:               "drain-start",
		BindAddr:             "127.0.0.1",
		GossipPort:           49006,
		AllowInsecureCluster: true, // test: no encryption key required
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer c.Stop()

	err = c.StartDraining()
	if err != nil {
		t.Fatalf("StartDraining() error = %v", err)
	}

	// Note: UpdateState skips self (id == nl.self.ID check), so the local
	// self node state is NOT changed to draining. The draining state is
	// communicated to OTHER nodes via gossip. We verify that StartDraining()
	// returned no error and that the call completed without panic.
	self := c.nodeList.GetSelf()
	if self == nil {
		t.Fatal("self node should exist")
	}
}

func TestCluster_CompleteDraining_LeaveCluster(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "drain-leave",
		BindAddr:   "127.0.0.1",
		GossipPort: 49007,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer c.Stop()

	// Start draining
	if err := c.StartDraining(); err != nil {
		t.Fatalf("StartDraining() error = %v", err)
	}

	// Complete draining with leaveCluster=true
	err = c.CompleteDraining(true)
	if err != nil {
		t.Fatalf("CompleteDraining(true) error = %v", err)
	}

	// Self node should have been removed from nodeList
	_, found := c.nodeList.Get("drain-leave")
	if found {
		t.Error("self node should have been removed from nodeList after CompleteDraining(true)")
	}
}

func TestCluster_CompleteDraining_StayInCluster(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "drain-stay",
		BindAddr:   "127.0.0.1",
		GossipPort: 49008,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer c.Stop()

	// Start draining
	if err := c.StartDraining(); err != nil {
		t.Fatalf("StartDraining() error = %v", err)
	}

	// Complete draining with leaveCluster=false — back to alive
	err = c.CompleteDraining(false)
	if err != nil {
		t.Fatalf("CompleteDraining(false) error = %v", err)
	}

	// Self node should still exist and be alive
	self := c.nodeList.GetSelf()
	if self == nil {
		t.Fatal("self node should still exist")
	}
	if self.State != NodeStateAlive {
		t.Errorf("self node state = %v, want Alive", self.State)
	}
}

func TestCluster_CompleteDraining_WithoutPriorStart(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "drain-nostart",
		BindAddr:   "127.0.0.1",
		GossipPort: 49009,
	}

	c, _ := New(cfg, logger, dnsCache)
	// Cluster not started, gossip is nil

	// CompleteDraining should not panic with nil gossip
	err := c.CompleteDraining(false)
	if err != nil {
		t.Errorf("CompleteDraining(false) should not error: %v", err)
	}

	err = c.CompleteDraining(true)
	if err != nil {
		t.Errorf("CompleteDraining(true) should not error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 9. splitKey — small helper splitting "type:name" into parts
// ---------------------------------------------------------------------------

func TestSplitKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want []string
	}{
		{
			name: "standard split",
			key:  "www.example.com/A",
			want: []string{"www.example.com", "A"},
		},
		{
			name: "no slash returns single element",
			key:  "nodelimiter",
			want: []string{"nodelimiter"},
		},
		{
			name: "empty string",
			key:  "",
			want: []string{""},
		},
		{
			name: "slash at start",
			key:  "/A",
			want: []string{"", "A"},
		},
		{
			name: "slash at end",
			key:  "www/",
			want: []string{"www", ""},
		},
		{
			name: "multiple slashes splits on first",
			key:  "www.example.com/MX/10",
			want: []string{"www.example.com", "MX/10"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitKey(tt.key)
			if len(got) != len(tt.want) {
				t.Fatalf("splitKey(%q) returned %d parts, want %d", tt.key, len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("part[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cluster.UpdateNodeHealth
// ---------------------------------------------------------------------------

func TestCluster_UpdateNodeHealth(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "health-update-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 49010,
	}

	c, _ := New(cfg, logger, dnsCache)

	health := NodeHealthStats{
		QueriesPerSecond: 500.0,
		LatencyMs:        2.5,
		CPUPercent:       30.0,
		MemoryPercent:    45.0,
		ActiveConns:      120,
		LastUpdated:      time.Now(),
	}

	c.UpdateNodeHealth(health)

	// Verify local health stored on the Cluster
	if c.localHealth.QueriesPerSecond != 500.0 {
		t.Errorf("localHealth.QueriesPerSecond = %f, want 500.0", c.localHealth.QueriesPerSecond)
	}

	// Verify health propagated to the nodeList
	node, ok := c.nodeList.Get("health-update-node")
	if !ok {
		t.Fatal("self node should exist in nodeList")
	}
	if node.Health.LatencyMs != 2.5 {
		t.Errorf("node Health.LatencyMs = %f, want 2.5", node.Health.LatencyMs)
	}
}

// ---------------------------------------------------------------------------
// Cluster.GetNodesWithHealth
// ---------------------------------------------------------------------------

func TestCluster_GetNodesWithHealth(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "health-list-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 49011,
	}

	c, _ := New(cfg, logger, dnsCache)

	// Set health on self
	now := time.Now()
	c.UpdateNodeHealth(NodeHealthStats{
		LatencyMs:   8.0,
		LastUpdated: now,
	})

	nodes := c.GetNodesWithHealth()
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}

	if nodes[0].Health.LatencyMs != 8.0 {
		t.Errorf("node Health.LatencyMs = %f, want 8.0", nodes[0].Health.LatencyMs)
	}
}

// ---------------------------------------------------------------------------
// Cluster.GetNodeForQuery
// ---------------------------------------------------------------------------

func TestCluster_GetNodeForQuery(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "query-self",
		BindAddr:   "127.0.0.1",
		GossipPort: 49012,
	}

	c, _ := New(cfg, logger, dnsCache)

	// Add a remote alive node
	c.nodeList.Add(&Node{
		ID:       "query-other",
		State:    NodeStateAlive,
		Addr:     "127.0.0.1",
		LastSeen: time.Now(),
	})

	// Without excluding self, the other node should be returned
	got := c.GetNodeForQuery(false)
	if got == nil {
		t.Fatal("GetNodeForQuery(false) should return the other alive node")
	}
	if got.ID != "query-other" {
		t.Errorf("GetNodeForQuery(false) returned %s, want query-other", got.ID)
	}

	// With excludeSelf=true, only other alive nodes are considered (same result here)
	got = c.GetNodeForQuery(true)
	if got == nil {
		t.Fatal("GetNodeForQuery(true) should return the other alive node")
	}
	if got.ID != "query-other" {
		t.Errorf("GetNodeForQuery(true) returned %s, want query-other", got.ID)
	}
}

func TestCluster_GetNodeForQuery_NoAliveNodes(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "query-solo",
		BindAddr:   "127.0.0.1",
		GossipPort: 49013,
	}

	c, _ := New(cfg, logger, dnsCache)

	// Only self in cluster, no other alive nodes
	got := c.GetNodeForQuery(false)
	if got != nil {
		t.Error("GetNodeForQuery(false) should return nil when only self exists")
	}

	got = c.GetNodeForQuery(true)
	if got != nil {
		t.Error("GetNodeForQuery(true) should return nil when only self exists")
	}
}

// ---------------------------------------------------------------------------
// Cluster.BroadcastClusterMetrics
// ---------------------------------------------------------------------------

func TestCluster_BroadcastClusterMetrics_NotStarted(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "metrics-not-started",
		BindAddr:   "127.0.0.1",
		GossipPort: 49014,
	}

	c, _ := New(cfg, logger, dnsCache)
	// Not started — should silently return
	c.BroadcastClusterMetrics(100, 50, 50, 10.5, 25.0, 300, 60)
}

func TestCluster_GetClusterMetrics_NoGossip(t *testing.T) {
	c := &Cluster{
		config:    Config{NodeID: "solo"},
		consensus: ConsensusSWIM,
	}

	metrics := c.GetClusterMetrics()
	if metrics.QueriesTotal != 0 {
		t.Errorf("expected zero metrics, got QueriesTotal=%d", metrics.QueriesTotal)
	}
}

// ---------------------------------------------------------------------------
// Node.IsAlive verifies draining nodes are excluded
// ---------------------------------------------------------------------------

func TestNode_IsAlive_DrainingExcluded(t *testing.T) {
	n := &Node{State: NodeStateDraining}
	if n.IsAlive() {
		t.Error("draining node should not be considered alive")
	}
}
