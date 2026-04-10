package cluster

import (
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/util"
)

func TestCluster_Start_WithSeedNodes(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 27946,
		SeedNodes:  []string{"invalid-seed-address:99999"}, // Will fail to join
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

	// Should have started even though seed node join failed
	if !c.IsStarted() {
		t.Error("Expected cluster to be started")
	}
}

func TestCluster_Start_WithSuccessfulSeedJoin(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	// Create a second gossip protocol to act as a seed node
	self := &Node{ID: "seed-node", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	seedCfg := DefaultGossipConfig()
	seedCfg.BindPort = 27947
	seedGp, _ := NewGossipProtocol(seedCfg, nl)
	if err := seedGp.Start(); err != nil {
		t.Fatalf("Failed to start seed: %v", err)
	}
	defer seedGp.Stop()

	cfg := Config{
		Enabled:    true,
		NodeID:     "joiner-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 27948,
		SeedNodes:  []string{"127.0.0.1:27947"},
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

	if !c.IsStarted() {
		t.Error("Expected cluster to be started")
	}
}

func TestCluster_cacheSyncLoop(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 27949,
		CacheSync:  true,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Send a cache sync event to exercise the cacheSyncLoop
	c.cacheSyncChan <- CacheSyncEvent{
		Type: "invalidate",
		Keys: []string{"key1", "key2"},
	}

	// Allow some time for processing
	time.Sleep(200 * time.Millisecond)

	c.Stop()
}

func TestCluster_cacheSyncLoop_WithBroadcastError(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 27970,
		CacheSync:  true,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Stop the gossip protocol so broadcast fails, triggering the Warnf path
	c.gossip.Stop()

	// Send a cache sync event - broadcast will fail since gossip is stopped
	c.cacheSyncChan <- CacheSyncEvent{
		Type: "invalidate",
		Keys: []string{"key3", "key4"},
	}

	// Allow some time for processing
	time.Sleep(200 * time.Millisecond)

	c.Stop()
}

func TestCluster_InvalidateCache_Enabled(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 27950,
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

	// Add a remote node so BroadcastCacheInvalidation has a target
	remoteNode := &Node{
		ID:       "remote-node",
		Addr:     "127.0.0.1",
		State:    NodeStateAlive,
		LastSeen: time.Now(),
	}
	c.nodeList.Add(remoteNode)

	// Call InvalidateCache with CacheSync enabled - this exercises the gossip path
	err = c.InvalidateCache([]string{"key1", "key2"})
	if err != nil {
		t.Errorf("InvalidateCache() error = %v", err)
	}
}

func TestGossipProtocol_probeNodes_AliveToSuspect(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	// Create a node that was seen a long time ago (alive but overdue)
	aliveNode := &Node{
		ID:       "alive-node",
		State:    NodeStateAlive,
		Addr:     "127.0.0.1",
		LastSeen: time.Now().Add(-10 * time.Second),
	}
	nl := NewNodeList(self)
	nl.Add(aliveNode)

	cfg := DefaultGossipConfig()
	cfg.BindPort = 27951
	cfg.SuspicionMult = 1
	cfg.ProbeInterval = 1 * time.Second

	gp, _ := NewGossipProtocol(cfg, nl)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	gp.probeNodes()

	// Node should be marked suspect
	node, ok := nl.Get("alive-node")
	if !ok {
		t.Fatal("Node should exist")
	}
	if node.State != NodeStateSuspect {
		t.Errorf("Expected node state Suspect, got %v", node.State)
	}
}

func TestGossipProtocol_probeNodes_DeadNodeRemoval(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	// Create a dead node last seen a very long time ago
	deadNode := &Node{
		ID:       "dead-node",
		State:    NodeStateDead,
		Addr:     "127.0.0.1",
		LastSeen: time.Now().Add(-100 * time.Second),
	}
	nl := NewNodeList(self)
	nl.Add(deadNode)

	cfg := DefaultGossipConfig()
	cfg.BindPort = 27952
	cfg.ProbeInterval = 1 * time.Second

	gp, _ := NewGossipProtocol(cfg, nl)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	gp.probeNodes()

	// Dead node should be removed
	_, ok := nl.Get("dead-node")
	if ok {
		t.Error("Dead node should have been removed")
	}
}

func TestGossipProtocol_handleMessage_AllTypes(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 27953

	gp, _ := NewGossipProtocol(cfg, nl)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	// Test MessageTypeAck
	ack := AckPayload{NodeID: "other-node", Version: 1}
	ackBytes, _ := encodePayload(ack)
	ackData, _ := encodeMessage(MessageTypeAck, ackBytes)
	gp.handleMessage(ackData, from)

	// Test MessageTypeGossip
	gossipPayload := GossipPayload{
		Nodes: []NodeInfo{
			{ID: "new-node", Addr: "192.168.1.1", Port: 7946, State: NodeStateAlive, Version: 1},
		},
	}
	gossipBytes, _ := encodePayload(gossipPayload)
	gossipData, _ := encodeMessage(MessageTypeGossip, gossipBytes)
	gp.handleMessage(gossipData, from)

	// Test MessageTypeCacheInvalidate
	cachePayload := CacheInvalidatePayload{
		Keys:      []string{"key1"},
		Source:    "other-node",
		Timestamp: time.Now(),
	}
	cacheBytes, _ := encodePayload(cachePayload)
	cacheData, _ := encodeMessage(MessageTypeCacheInvalidate, cacheBytes)
	gp.handleMessage(cacheData, from)
}

func TestGossipProtocol_handleMessage_InvalidPayload(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	// Test handlePing with invalid payload - should not panic
	msg := Message{Type: MessageTypePing, Payload: []byte{0xFF, 0xFE}}
	data, _ := encodeMessage(msg.Type, msg.Payload)
	gp.handleMessage(data, from)

	// Test handleAck with invalid payload
	msg = Message{Type: MessageTypeAck, Payload: []byte{0xFF, 0xFE}}
	data, _ = encodeMessage(msg.Type, msg.Payload)
	gp.handleMessage(data, from)

	// Test handleGossip with invalid payload
	msg = Message{Type: MessageTypeGossip, Payload: []byte{0xFF, 0xFE}}
	data, _ = encodeMessage(msg.Type, msg.Payload)
	gp.handleMessage(data, from)

	// Test handleCacheInvalidate with invalid payload
	msg = Message{Type: MessageTypeCacheInvalidate, Payload: []byte{0xFF, 0xFE}}
	data, _ = encodeMessage(msg.Type, msg.Payload)
	gp.handleMessage(data, from)
}

func TestGossipProtocol_gossip_NoOtherNodes(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 27954
	cfg.GossipNodes = 3

	gp, _ := NewGossipProtocol(cfg, nl)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	// gossip with no other nodes - should not panic
	gp.gossip()
}

func TestGossipProtocol_Join_ResolveError(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 27955

	gp, _ := NewGossipProtocol(cfg, nl)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	// Invalid address format should fail at resolve
	err := gp.Join("not-a-valid-address:port:extra")
	if err == nil {
		t.Error("Expected error for invalid address")
	}
}

func TestGossipProtocol_BroadcastCacheInvalidation_NoAliveNodes(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 27956

	gp, _ := NewGossipProtocol(cfg, nl)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	// No other alive nodes - should succeed with no sends
	err := gp.BroadcastCacheInvalidation([]string{"key1"})
	if err != nil {
		t.Errorf("BroadcastCacheInvalidation() error = %v", err)
	}
}

func TestCluster_Start_NoCacheSync(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 27957,
		CacheSync:  false, // CacheSync disabled
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer c.Stop()

	if !c.IsStarted() {
		t.Error("Expected cluster to be started")
	}
}

func TestCluster_HandleCacheInvalid_NilCache(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 27958,
	}

	c, _ := New(cfg, logger, nil)

	// Should not panic with nil cache
	c.handleCacheInvalid([]string{"key1"})
}

func TestCluster_HandleCacheInvalid_WithEventHandler(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 27959,
	}

	c, _ := New(cfg, logger, dnsCache)

	cacheInvalidCalled := false
	c.AddEventHandler(&EventHandlerFunc{
		OnCacheInvalidFunc: func(keys []string) {
			cacheInvalidCalled = true
		},
	})

	c.handleCacheInvalid([]string{"key1"})

	if !cacheInvalidCalled {
		t.Error("Event handler should have been called for cache invalidation")
	}
}

func TestGossipProtocol_handlePing_InvalidPayload(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	// Create a message with invalid payload
	msg := Message{
		Type:    MessageTypePing,
		Payload: []byte{0xFF, 0xFE, 0xFD},
	}

	// Should not panic
	gp.handlePing(msg, from)
}

func TestGossipProtocol_handleAck_InvalidPayload(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	msg := Message{
		Type:    MessageTypeAck,
		Payload: []byte{0xFF, 0xFE, 0xFD},
	}

	gp.handleAck(msg, from)
}

func TestGossipProtocol_handleGossip_InvalidPayload(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	msg := Message{
		Type:    MessageTypeGossip,
		Payload: []byte{0xFF, 0xFE, 0xFD},
	}

	gp.handleGossip(msg, from)
}

func TestGossipProtocol_handleCacheInvalidate_InvalidPayload(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	msg := Message{
		Type:    MessageTypeCacheInvalidate,
		Payload: []byte{0xFF, 0xFE, 0xFD},
	}

	gp.handleCacheInvalidate(msg, from)
}

func TestGossipProtocol_handleGossip_SelfNode(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	// Gossip with self node - should be skipped
	gossipPayload := GossipPayload{
		Nodes: []NodeInfo{
			{ID: "self", Addr: "192.168.1.1", Port: 7946, State: NodeStateAlive, Version: 2},
		},
	}
	gossipBytes, _ := encodePayload(gossipPayload)
	msg := Message{
		Type:    MessageTypeGossip,
		Payload: gossipBytes,
	}

	gp.handleGossip(msg, from)

	// Self node should not be changed
	node := nl.GetSelf()
	if node.Addr != "127.0.0.1" {
		t.Errorf("Self node should not be updated, got addr %s", node.Addr)
	}
}

func TestGossipProtocol_handleGossip_OldVersion(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	existingNode := &Node{ID: "existing", State: NodeStateAlive, Version: 5, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	nl.Add(existingNode)

	cfg := DefaultGossipConfig()
	gp, _ := NewGossipProtocol(cfg, nl)

	updateCalled := false
	gp.SetCallbacks(
		nil, nil,
		func(*Node) { updateCalled = true },
		nil,
		nil,
		nil,
	)

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	// Gossip with older version - should NOT trigger update
	gossipPayload := GossipPayload{
		Nodes: []NodeInfo{
			{ID: "existing", Addr: "192.168.1.1", Port: 7946, State: NodeStateSuspect, Version: 3},
		},
	}
	gossipBytes, _ := encodePayload(gossipPayload)
	msg := Message{
		Type:    MessageTypeGossip,
		Payload: gossipBytes,
	}

	gp.handleGossip(msg, from)

	if updateCalled {
		t.Error("Update callback should not have been called for older version")
	}
}

func TestCluster_IsHealthy_WithNodes(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 27960,
	}

	c, _ := New(cfg, logger, dnsCache)

	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer c.Stop()

	// Add some alive remote nodes
	c.nodeList.Add(&Node{ID: "node1", State: NodeStateAlive, Addr: "127.0.0.1"})
	c.nodeList.Add(&Node{ID: "node2", State: NodeStateAlive, Addr: "127.0.0.1"})

	// With 3 nodes (1 self alive + 2 remote alive), majority is 2, alive is 3
	if !c.IsHealthy() {
		t.Error("Cluster with majority alive should be healthy")
	}
}

func TestCluster_IsHealthy_Unhealthy(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 27961,
	}

	c, _ := New(cfg, logger, dnsCache)

	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer c.Stop()

	// Add nodes in suspect/dead state
	c.nodeList.Add(&Node{ID: "node1", State: NodeStateDead, Addr: "127.0.0.1"})
	c.nodeList.Add(&Node{ID: "node2", State: NodeStateDead, Addr: "127.0.0.1"})
	c.nodeList.Add(&Node{ID: "node3", State: NodeStateDead, Addr: "127.0.0.1"})

	// With 4 total nodes, majority is 3, but only 1 is alive (self)
	if c.IsHealthy() {
		t.Error("Cluster without majority alive should be unhealthy")
	}
}

func TestCluster_Stop_Twice(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 27962,
	}

	c, _ := New(cfg, logger, dnsCache)

	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	c.Stop()

	// Stopping again should not panic (though cacheSyncChan is already closed)
	// The second Stop call checks !c.started and returns nil
	err := c.Stop()
	if err != nil {
		t.Errorf("Second Stop() should return nil, got %v", err)
	}
}
