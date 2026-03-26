package cluster

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/util"
)

func TestNew(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17946, // Use high port to avoid conflicts
		Region:     "us-east",
		Zone:       "us-east-1a",
		Weight:     100,
		SeedNodes:  []string{},
		CacheSync:  true,
		HTTPAddr:   "127.0.0.1:8080",
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Start and then stop to test started state
	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer c.Stop()

	if c == nil {
		t.Fatal("New() returned nil")
	}

	if c.config.NodeID != "test-node" {
		t.Errorf("Expected NodeID test-node, got %s", c.config.NodeID)
	}

	if !c.started {
		t.Error("Expected cluster to be marked as started")
	}

	if c.GetNodeID() != "test-node" {
		t.Errorf("GetNodeID() = %s, want test-node", c.GetNodeID())
	}
}

func TestNew_AutoGenerateNodeID(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "", // Empty - should auto-generate
		BindAddr:   "127.0.0.1",
		GossipPort: 17947,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if c.GetNodeID() == "" {
		t.Error("Expected auto-generated NodeID, got empty string")
	}

	if len(c.GetNodeID()) != 16 { // 8 bytes hex encoded = 16 chars
		t.Errorf("Expected NodeID length 16, got %d", len(c.GetNodeID()))
	}
}

func TestNew_AutoDetectBindAddr(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "", // Empty - should auto-detect
		GossipPort: 17948,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if c.config.BindAddr == "" {
		t.Error("Expected auto-detected BindAddr, got empty string")
	}
}

func TestCluster_GetNodes(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17949,
	}

	c, _ := New(cfg, logger, dnsCache)

	nodes := c.GetNodes()
	if len(nodes) != 1 {
		t.Errorf("Expected 1 node (self), got %d", len(nodes))
	}

	if nodes[0].ID != "test-node" {
		t.Errorf("Expected node ID test-node, got %s", nodes[0].ID)
	}
}

func TestCluster_GetAliveNodes(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17950,
	}

	c, _ := New(cfg, logger, dnsCache)

	// Initially just self, so GetAliveNodes should return empty
	alive := c.GetAliveNodes()
	if len(alive) != 0 {
		t.Errorf("Expected 0 alive nodes (excluding self), got %d", len(alive))
	}
}

func TestCluster_GetNodeCount(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17951,
	}

	c, _ := New(cfg, logger, dnsCache)

	if count := c.GetNodeCount(); count != 1 {
		t.Errorf("Expected node count 1, got %d", count)
	}

	if count := c.GetAliveCount(); count != 1 {
		t.Errorf("Expected alive count 1, got %d", count)
	}
}

func TestCluster_IsHealthy(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17952,
	}

	c, _ := New(cfg, logger, dnsCache)

	// Single node is always healthy
	if !c.IsHealthy() {
		t.Error("Single node cluster should be healthy")
	}
}

func TestCluster_IsHealthy_NotStarted(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17953,
	}

	c, _ := New(cfg, logger, dnsCache)
	c.Stop()

	// When stopped (not started), should still be healthy (single node mode)
	if !c.IsHealthy() {
		t.Error("Single node mode (stopped) should be healthy")
	}
}

func TestCluster_Stats(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17954,
	}

	c, _ := New(cfg, logger, dnsCache)

	stats := c.Stats()

	if stats.NodeID != "test-node" {
		t.Errorf("Expected NodeID test-node, got %s", stats.NodeID)
	}

	if stats.NodeCount != 1 {
		t.Errorf("Expected NodeCount 1, got %d", stats.NodeCount)
	}

	if stats.AliveCount != 1 {
		t.Errorf("Expected AliveCount 1, got %d", stats.AliveCount)
	}

	if !stats.IsHealthy {
		t.Error("Expected IsHealthy to be true")
	}
}

func TestCluster_AddRemoveEventHandler(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17955,
	}

	c, _ := New(cfg, logger, dnsCache)

	joinCalled := false
	handler := &EventHandlerFunc{
		OnJoinFunc: func(*Node) {
			joinCalled = true
		},
	}

	c.AddEventHandler(handler)

	if len(c.handlers) != 1 {
		t.Errorf("Expected 1 handler, got %d", len(c.handlers))
	}

	// Test that the handler works
	handler.OnNodeJoin(&Node{ID: "test"})
	if !joinCalled {
		t.Error("Handler should have been called")
	}

	// Remove handler
	c.RemoveEventHandler(handler)

	if len(c.handlers) != 0 {
		t.Errorf("Expected 0 handlers after removal, got %d", len(c.handlers))
	}
}

func TestCluster_InvalidateCacheLocal(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{
		Capacity:   1000,
		DefaultTTL: time.Hour,
	}
	dnsCache := cache.New(cacheCfg)

	// Add an entry to cache
	dnsCache.Set("test-key", nil, 3600)

	if dnsCache.Stats().Size != 1 {
		t.Fatal("Cache should have 1 entry")
	}

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17956,
		CacheSync:  true,
	}

	c, _ := New(cfg, logger, dnsCache)

	// Invalidate locally
	c.InvalidateCacheLocal([]string{"test-key"})

	if dnsCache.Stats().Size != 0 {
		t.Error("Cache should be empty after invalidation")
	}
}

func TestCluster_InvalidateCache_Disabled(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17957,
		CacheSync:  false, // Disabled
	}

	c, _ := New(cfg, logger, dnsCache)

	// Should return nil when cache sync is disabled
	err := c.InvalidateCache([]string{"test-key"})
	if err != nil {
		t.Errorf("Expected nil error when cache sync disabled, got %v", err)
	}
}

func TestCacheSyncEvent_Struct(t *testing.T) {
	event := CacheSyncEvent{
		Type:      "invalidate",
		Keys:      []string{"key1", "key2"},
		Source:    "node1",
		Timestamp: time.Now(),
	}

	if event.Type != "invalidate" {
		t.Errorf("Expected type invalidate, got %s", event.Type)
	}

	if len(event.Keys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(event.Keys))
	}

	if event.Source != "node1" {
		t.Errorf("Expected source node1, got %s", event.Source)
	}
}

func TestConfig_Values(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		NodeID:     "node1",
		BindAddr:   "192.168.1.1",
		BindPort:   7946,
		GossipPort: 7947,
		Region:     "us-west",
		Zone:       "us-west-2a",
		Weight:     50,
		SeedNodes:  []string{"192.168.1.2:7946", "192.168.1.3:7946"},
		CacheSync:  true,
		HTTPAddr:   "192.168.1.1:8080",
	}

	if !cfg.Enabled {
		t.Error("Expected Enabled to be true")
	}

	if cfg.NodeID != "node1" {
		t.Errorf("Expected NodeID node1, got %s", cfg.NodeID)
	}

	if len(cfg.SeedNodes) != 2 {
		t.Errorf("Expected 2 seed nodes, got %d", len(cfg.SeedNodes))
	}
}
