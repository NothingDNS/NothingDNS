package cluster

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/util"
)

// ---------------------------------------------------------------------------
// UpdateNodeHealth with started cluster
// ---------------------------------------------------------------------------

func TestCluster_UpdateNodeHealth_Started(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "health-node",
		BindAddr:   "127.0.0.1",
		GossipPort: pickFreePort(),
		CacheSync:  true,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer c.Stop()

	health := NodeHealthStats{
		QueriesPerSecond: 150.5,
		LatencyMs:        10.0,
		CPUPercent:       50.0,
		MemoryPercent:    65.0,
		ActiveConns:      100,
	}

	// Should not panic — broadcasts health stats
	c.UpdateNodeHealth(health)

	c.mu.RLock()
	got := c.localHealth
	c.mu.RUnlock()

	if got.QueriesPerSecond != 150.5 {
		t.Errorf("localHealth.QueriesPerSecond = %f, want 150.5", got.QueriesPerSecond)
	}
}

func TestCluster_UpdateNodeHealth_NotStarted(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "health-node",
		BindAddr:   "127.0.0.1",
		GossipPort: pickFreePort(),
		CacheSync:  true,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	health := NodeHealthStats{
		QueriesPerSecond: 99.0,
	}

	// Should not panic even when not started
	c.UpdateNodeHealth(health)

	c.mu.RLock()
	got := c.localHealth
	c.mu.RUnlock()

	if got.QueriesPerSecond != 99.0 {
		t.Errorf("localHealth.QueriesPerSecond = %f, want 99.0", got.QueriesPerSecond)
	}
}

// ---------------------------------------------------------------------------
// BroadcastClusterMetrics with started cluster
// ---------------------------------------------------------------------------

func TestCluster_BroadcastClusterMetrics_Started(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "metrics-node",
		BindAddr:   "127.0.0.1",
		GossipPort: pickFreePort(),
		CacheSync:  true,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer c.Stop()

	// Should not panic — broadcasts metrics
	c.BroadcastClusterMetrics(10000, 8000, 2000, 500.5, 5.5, 25.0, 3600)
}

func TestCluster_BroadcastClusterMetrics_NotStartedV2(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "metrics-node",
		BindAddr:   "127.0.0.1",
		GossipPort: pickFreePort(),
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Should not panic — early return since not started
	c.BroadcastClusterMetrics(0, 0, 0, 0, 0, 0, 0)
}

// ---------------------------------------------------------------------------
// GetClusterMetrics with gossip
// ---------------------------------------------------------------------------

func TestCluster_GetClusterMetrics_WithGossip(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "metrics-node",
		BindAddr:   "127.0.0.1",
		GossipPort: pickFreePort(),
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// gossip is initialized but not started — should return empty payload
	m := c.GetClusterMetrics()
	if m.QueriesTotal != 0 {
		t.Errorf("expected empty metrics, got QueriesTotal=%d", m.QueriesTotal)
	}
}

// ---------------------------------------------------------------------------
// Stats with gossip (non-raft) mode
// ---------------------------------------------------------------------------

func TestCluster_Stats_GossipMode(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "stats-node",
		BindAddr:   "127.0.0.1",
		GossipPort: pickFreePort(),
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	stats := c.Stats()
	if stats.NodeID != "stats-node" {
		t.Errorf("NodeID = %q, want stats-node", stats.NodeID)
	}
	if stats.ConsensusMode != ConsensusSWIM {
		t.Errorf("ConsensusMode = %q, want %q", stats.ConsensusMode, ConsensusSWIM)
	}
	if stats.NodeCount != 1 {
		t.Errorf("NodeCount = %d, want 1", stats.NodeCount)
	}
	if stats.AliveCount != 1 {
		t.Errorf("AliveCount = %d, want 1", stats.AliveCount)
	}
	// Single node, not started → IsHealthy = true
	if !stats.IsHealthy {
		t.Error("expected IsHealthy=true for non-started cluster")
	}
	// GossipStats should be populated (zero-value struct, not nil)
	_ = stats.GossipStats
}

// ---------------------------------------------------------------------------
// InvalidateCache with different paths
// ---------------------------------------------------------------------------

func TestCluster_InvalidateCache_CacheSyncDisabled(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "cache-node",
		BindAddr:   "127.0.0.1",
		GossipPort: pickFreePort(),
		CacheSync:  false, // disabled
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Should return nil when CacheSync is disabled
	err = c.InvalidateCache([]string{"key1", "key2"})
	if err != nil {
		t.Errorf("expected nil when CacheSync disabled, got %v", err)
	}
}

func TestCluster_InvalidateCache_GossipMode(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "cache-node",
		BindAddr:   "127.0.0.1",
		GossipPort: pickFreePort(),
		CacheSync:  true,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Not started — gossip.BroadcastCacheInvalidation will fail
	// but InvalidateCache should still attempt the call
	_ = c.InvalidateCache([]string{"key1"})
}

// ---------------------------------------------------------------------------
// StartDraining / CompleteDraining
// ---------------------------------------------------------------------------

func TestCluster_StartDraining_NotStartedV2(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "drain-node",
		BindAddr:   "127.0.0.1",
		GossipPort: pickFreePort(),
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = c.StartDraining()
	if err == nil {
		t.Error("expected error when cluster not started")
	}
}

func TestCluster_CompleteDraining_LeaveClusterV2(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "drain-node",
		BindAddr:   "127.0.0.1",
		GossipPort: pickFreePort(),
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// leaveCluster=true — removes self from node list
	err = c.CompleteDraining(true)
	if err != nil {
		t.Fatalf("CompleteDraining(true) error = %v", err)
	}

	// Node should be removed
	if c.nodeList.Count() != 0 {
		t.Errorf("expected 0 nodes after leave, got %d", c.nodeList.Count())
	}
}

func TestCluster_CompleteDraining_Resume(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:     "drain-node",
		BindAddr:   "127.0.0.1",
		GossipPort: pickFreePort(),
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// leaveCluster=false — should set state back to Alive
	err = c.CompleteDraining(false)
	if err != nil {
		t.Fatalf("CompleteDraining(false) error = %v", err)
	}

	self := c.nodeList.GetSelf()
	if self == nil {
		t.Fatal("expected self node to still exist")
	}
	if self.State != NodeStateAlive {
		t.Errorf("expected state=Alive after resume, got %s", self.State)
	}
}
