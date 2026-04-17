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
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
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
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
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
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
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
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
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
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
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
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
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
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
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
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
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
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
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
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
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
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
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
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
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
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
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

func TestCluster_IsStarted(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17958,
	}

	c, _ := New(cfg, logger, dnsCache)

	// Not started initially
	if c.IsStarted() {
		t.Error("Expected IsStarted to be false initially")
	}

	// Start the cluster
	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Now should be started
	if !c.IsStarted() {
		t.Error("Expected IsStarted to be true after Start()")
	}

	// Stop the cluster
	c.Stop()

	// Should be false after stop
	if c.IsStarted() {
		t.Error("Expected IsStarted to be false after Stop()")
	}
}

func TestCluster_Start_AlreadyStarted(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17959,
	}

	c, _ := New(cfg, logger, dnsCache)

	if err := c.Start(); err != nil {
		t.Fatalf("First Start() error = %v", err)
	}
	defer c.Stop()

	// Try to start again
	err := c.Start()
	if err == nil {
		t.Error("Expected error when starting already started cluster")
	}
}

func TestCluster_Stop_NotStarted(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17960,
	}

	c, _ := New(cfg, logger, dnsCache)

	// Stop without starting should not error
	err := c.Stop()
	if err != nil {
		t.Errorf("Stop() on non-started cluster should not error, got %v", err)
	}
}

func TestCluster_InvalidateCacheLocal_NilCache(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17961,
	}

	c, _ := New(cfg, logger, nil) // nil cache

	// Should not panic with nil cache
	c.InvalidateCacheLocal([]string{"test-key"})
}

func TestEventHandlerFunc_AllMethods(t *testing.T) {
	leaveCalled := false
	updateCalled := false
	cacheInvalidCalled := false

	handler := &EventHandlerFunc{
		OnLeaveFunc: func(n *Node) {
			leaveCalled = true
		},
		OnUpdateFunc: func(n *Node) {
			updateCalled = true
		},
		OnCacheInvalidFunc: func(keys []string) {
			cacheInvalidCalled = true
		},
	}

	// Test OnNodeLeave
	handler.OnNodeLeave(&Node{ID: "test-leave"})
	if !leaveCalled {
		t.Error("OnNodeLeave should have called OnLeaveFunc")
	}

	// Test OnNodeUpdate
	handler.OnNodeUpdate(&Node{ID: "test-update"})
	if !updateCalled {
		t.Error("OnNodeUpdate should have called OnUpdateFunc")
	}

	// Test OnCacheInvalid
	handler.OnCacheInvalid([]string{"key1"})
	if !cacheInvalidCalled {
		t.Error("OnCacheInvalid should have called OnCacheInvalidFunc")
	}
}

func TestEventHandlerFunc_NilFunctions(t *testing.T) {
	// Test with nil functions - should not panic
	handler := &EventHandlerFunc{}

	handler.OnNodeJoin(&Node{ID: "test"})
	handler.OnNodeLeave(&Node{ID: "test"})
	handler.OnNodeUpdate(&Node{ID: "test"})
	handler.OnCacheInvalid([]string{"key"})
	// If we get here without panic, test passes
}

func TestCluster_HandleNodeJoin(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17962,
	}

	c, _ := New(cfg, logger, dnsCache)

	joinCalled := false
	c.AddEventHandler(&EventHandlerFunc{
		OnJoinFunc: func(n *Node) {
			joinCalled = true
			if n.ID != "new-node" {
				t.Errorf("Expected node ID new-node, got %s", n.ID)
			}
		},
	})

	// Call handleNodeJoin directly
	c.handleNodeJoin(&Node{ID: "new-node", Addr: "192.168.1.1"})

	if !joinCalled {
		t.Error("Handler should have been called for node join")
	}
}

func TestCluster_HandleNodeLeave(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17963,
	}

	c, _ := New(cfg, logger, dnsCache)

	leaveCalled := false
	c.AddEventHandler(&EventHandlerFunc{
		OnLeaveFunc: func(n *Node) {
			leaveCalled = true
			if n.ID != "leaving-node" {
				t.Errorf("Expected node ID leaving-node, got %s", n.ID)
			}
		},
	})

	// Call handleNodeLeave directly
	c.handleNodeLeave(&Node{ID: "leaving-node", Addr: "192.168.1.2"})

	if !leaveCalled {
		t.Error("Handler should have been called for node leave")
	}
}

func TestCluster_HandleNodeUpdate(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17964,
	}

	c, _ := New(cfg, logger, dnsCache)

	updateCalled := false
	c.AddEventHandler(&EventHandlerFunc{
		OnUpdateFunc: func(n *Node) {
			updateCalled = true
			if n.ID != "updated-node" {
				t.Errorf("Expected node ID updated-node, got %s", n.ID)
			}
		},
	})

	// Call handleNodeUpdate directly
	c.handleNodeUpdate(&Node{ID: "updated-node", State: NodeStateAlive})

	if !updateCalled {
		t.Error("Handler should have been called for node update")
	}
}

func TestCluster_HandleCacheInvalid(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{
		Capacity:   1000,
		DefaultTTL: time.Hour,
	}
	dnsCache := cache.New(cacheCfg)

	// Add entry to cache
	dnsCache.Set("key1", nil, 3600)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17965,
		CacheSync:  true,
	}

	c, _ := New(cfg, logger, dnsCache)

	cacheInvalidCalled := false
	c.AddEventHandler(&EventHandlerFunc{
		OnCacheInvalidFunc: func(keys []string) {
			cacheInvalidCalled = true
			if len(keys) != 1 || keys[0] != "key1" {
				t.Errorf("Expected keys [key1], got %v", keys)
			}
		},
	})

	// Call handleCacheInvalid directly
	c.handleCacheInvalid([]string{"key1"})

	if !cacheInvalidCalled {
		t.Error("Handler should have been called for cache invalidation")
	}

	// Verify cache was actually invalidated
	if dnsCache.Stats().Size != 0 {
		t.Error("Cache should be empty after invalidation")
	}
}

func TestCluster_RemoveEventHandler_NotFound(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17966,
	}

	c, _ := New(cfg, logger, dnsCache)

	handler1 := &EventHandlerFunc{
		OnJoinFunc: func(*Node) {},
	}
	handler2 := &EventHandlerFunc{
		OnJoinFunc: func(*Node) {},
	}

	c.AddEventHandler(handler1)

	// Try to remove handler that was never added
	c.RemoveEventHandler(handler2)

	// Should still have 1 handler
	if len(c.handlers) != 1 {
		t.Errorf("Expected 1 handler, got %d", len(c.handlers))
	}
}

func TestCluster_Stats_Started(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 17967,
	}

	c, _ := New(cfg, logger, dnsCache)

	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer c.Stop()

	stats := c.Stats()

	if stats.NodeID != "test-node" {
		t.Errorf("Expected NodeID test-node, got %s", stats.NodeID)
	}
}
