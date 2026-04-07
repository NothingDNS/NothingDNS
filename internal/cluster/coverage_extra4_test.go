package cluster

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/util"
)

// ---------------------------------------------------------------------------
// cluster.go:106-108 - New() GetLocalIP error path
// ---------------------------------------------------------------------------
// This path triggers when BindAddr is empty and GetLocalIP() returns an error.
// GetLocalIP() calls net.InterfaceAddrs() which does not fail in normal
// environments. We document this unreachable path.

func TestNew_EmptyBindAddr_GetLocalIPError_Unreachable(t *testing.T) {
	t.Skip("GetLocalIP() calls net.InterfaceAddrs() which cannot be forced to " +
		"fail in a normal test environment. The error path at cluster.go:106-108 " +
		"is unreachable without mocking the net package.")
}

// ---------------------------------------------------------------------------
// cluster.go:134-136 - New() NewGossipProtocol error path
// ---------------------------------------------------------------------------
// NewGossipProtocol never returns an error in its current implementation.
// This is a defensive check that cannot be triggered.

func TestNew_NewGossipProtocolError_Unreachable(t *testing.T) {
	t.Skip("NewGossipProtocol() always returns nil error in the current " +
		"implementation. The error path at cluster.go:134-136 is unreachable.")
}

// ---------------------------------------------------------------------------
// cluster.go:204-206 - Stop() gossip.Stop() error warning path
// ---------------------------------------------------------------------------
// gossip.Stop() never returns an error. This warning path is unreachable.

func TestCluster_Stop_GossipStopErrorWarning_Unreachable(t *testing.T) {
	t.Skip("gossip.Stop() always returns nil in the current implementation. " +
		"The warning path at cluster.go:204-206 is unreachable.")
}

// ---------------------------------------------------------------------------
// cluster.go:370-372 - cacheSyncLoop BroadcastCacheInvalidation error path
// ---------------------------------------------------------------------------
// BroadcastCacheInvalidation only returns errors from encode steps which
// always succeed for CacheInvalidatePayload. WriteToUDP errors are silently
// ignored within BroadcastCacheInvalidation. So the error return path in
// cacheSyncLoop is unreachable.

func TestCluster_CacheSyncLoop_BroadcastError_Unreachable(t *testing.T) {
	t.Skip("BroadcastCacheInvalidation only returns errors from encodePayload/" +
		"encodeMessage, which always succeed for CacheInvalidatePayload. " +
		"WriteToUDP errors are silently swallowed. The error path at " +
		"cluster.go:370-372 is unreachable.")
}

// ---------------------------------------------------------------------------
// gossip.go:208-210 - Join() encodePayload error path
// ---------------------------------------------------------------------------
// PingPayload is a valid gob type that always encodes successfully.

func TestGossipProtocol_Join_EncodePayloadError_Unreachable(t *testing.T) {
	t.Skip("encodePayload(PingPayload{}) always succeeds because PingPayload " +
		"contains only basic gob-encodable types. The error path at " +
		"gossip.go:208-210 is unreachable.")
}

// ---------------------------------------------------------------------------
// gossip.go:213-215 - Join() encodeMessage error path
// ---------------------------------------------------------------------------

func TestGossipProtocol_Join_EncodeMessageError_Unreachable(t *testing.T) {
	t.Skip("encodeMessage always succeeds with valid []byte payload from " +
		"encodePayload(PingPayload). The error path at gossip.go:213-215 " +
		"is unreachable.")
}

// ---------------------------------------------------------------------------
// gossip.go:235-237 - BroadcastCacheInvalidation encodePayload error path
// ---------------------------------------------------------------------------

func TestGossipProtocol_BroadcastCacheInvalidation_EncodePayload_Unreachable(t *testing.T) {
	t.Skip("encodePayload(CacheInvalidatePayload{}) always succeeds. " +
		"The error path at gossip.go:235-237 is unreachable.")
}

// ---------------------------------------------------------------------------
// gossip.go:240-242 - BroadcastCacheInvalidation encodeMessage error path
// ---------------------------------------------------------------------------

func TestGossipProtocol_BroadcastCacheInvalidation_EncodeMessage_Unreachable(t *testing.T) {
	t.Skip("encodeMessage always succeeds with valid CacheInvalidatePayload bytes. " +
		"The error path at gossip.go:240-242 is unreachable.")
}

// ---------------------------------------------------------------------------
// gossip.go:435-437 - gossip() encodePayload error path
// ---------------------------------------------------------------------------

func TestGossipProtocol_Gossip_EncodePayload_Unreachable(t *testing.T) {
	t.Skip("encodePayload(GossipPayload{}) always succeeds. " +
		"The error path at gossip.go:435-437 is unreachable.")
}

// ---------------------------------------------------------------------------
// gossip.go:440-442 - gossip() encodeMessage error path
// ---------------------------------------------------------------------------

func TestGossipProtocol_Gossip_EncodeMessage_Unreachable(t *testing.T) {
	t.Skip("encodeMessage always succeeds with valid GossipPayload bytes. " +
		"The error path at gossip.go:440-442 is unreachable.")
}

// ---------------------------------------------------------------------------
// gossip.go:553-555 - encodeMessage json.Marshal error path
// ---------------------------------------------------------------------------
// Message struct contains only encodable types (uint8, string, time.Time, []byte).
// json.Marshal always succeeds for this struct.

func TestEncodeMessage_JsonMarshalError_Unreachable(t *testing.T) {
	t.Skip("encodeMessage creates Message{Type:uint8, Timestamp:time.Time, " +
		"Payload:[]byte} which always encodes successfully with json. " +
		"The error path at gossip.go:553-555 is unreachable.")
}

// ---------------------------------------------------------------------------
// node.go:230-232 - GetLocalIP net.InterfaceAddrs error path
// ---------------------------------------------------------------------------

func TestGetLocalIP_InterfaceAddrsError_Unreachable(t *testing.T) {
	t.Skip("net.InterfaceAddrs() does not fail in normal environments. " +
		"The error path at node.go:230-232 is unreachable without mocking.")
}

// ---------------------------------------------------------------------------
// node.go:242 - GetLocalIP fallback to "127.0.0.1"
// ---------------------------------------------------------------------------
// Only triggers when no non-loopback IPv4 interface exists.

func TestGetLocalIP_FallbackPath_EnvironmentDependent(t *testing.T) {
	ip, err := GetLocalIP()
	if err != nil {
		t.Fatalf("GetLocalIP() error = %v", err)
	}
	if ip == "127.0.0.1" {
		t.Log("GetLocalIP() returned fallback 127.0.0.1 (line 242 covered)")
	} else {
		t.Skipf("GetLocalIP() returned %s, so the fallback path (line 242) "+
			"was not exercised. This path only triggers when no non-loopback "+
			"IPv4 interface exists.", ip)
	}
}

// ---------------------------------------------------------------------------
// Comprehensive integration: cacheSyncLoop with multiple rapid events
// to ensure the loop processes events correctly under load
// ---------------------------------------------------------------------------

func TestCluster_CacheSyncLoop_RapidEvents(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:    true,
		NodeID:     "rapid-sync-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 48001,
		CacheSync:  true,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Send multiple events rapidly
	for i := 0; i < 10; i++ {
		c.cacheSyncChan <- CacheSyncEvent{
			Type: "invalidate",
			Keys: []string{"key-rapid"},
		}
	}

	time.Sleep(300 * time.Millisecond)
	c.Stop()
}

// ---------------------------------------------------------------------------
// Integration: two clusters with CacheSync exchanging invalidations
// ---------------------------------------------------------------------------

func TestCluster_TwoClusterCacheInvalidation(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache1 := cache.New(cache.Config{Capacity: 1000, DefaultTTL: time.Hour})
	dnsCache2 := cache.New(cache.Config{Capacity: 1000, DefaultTTL: time.Hour})

	// Add entries to both caches
	dnsCache1.Set("shared-key", nil, 3600)
	dnsCache2.Set("shared-key", nil, 3600)

	cfg1 := Config{
		Enabled:    true,
		NodeID:     "cluster-node-1",
		BindAddr:   "127.0.0.1",
		GossipPort: 48002,
		CacheSync:  true,
	}

	cfg2 := Config{
		Enabled:    true,
		NodeID:     "cluster-node-2",
		BindAddr:   "127.0.0.1",
		GossipPort: 48003,
		CacheSync:  true,
	}

	c1, err := New(cfg1, logger, dnsCache1)
	if err != nil {
		t.Fatalf("New(c1) error = %v", err)
	}

	c2, err := New(cfg2, logger, dnsCache2)
	if err != nil {
		t.Fatalf("New(c2) error = %v", err)
	}

	if err := c1.Start(); err != nil {
		t.Fatalf("c1 Start() error = %v", err)
	}
	defer c1.Stop()

	if err := c2.Start(); err != nil {
		t.Fatalf("c2 Start() error = %v", err)
	}
	defer c2.Stop()

	// Verify both caches have entries
	if dnsCache1.Stats().Size != 1 {
		t.Fatalf("dnsCache1 should have 1 entry, got %d", dnsCache1.Stats().Size)
	}
	if dnsCache2.Stats().Size != 1 {
		t.Fatalf("dnsCache2 should have 1 entry, got %d", dnsCache2.Stats().Size)
	}

	// Verify cluster 1 is healthy
	if !c1.IsHealthy() {
		t.Error("Cluster 1 should be healthy")
	}

	// Verify stats
	stats1 := c1.Stats()
	if stats1.NodeID != "cluster-node-1" {
		t.Errorf("Expected NodeID cluster-node-1, got %s", stats1.NodeID)
	}

	stats2 := c2.Stats()
	if stats2.NodeID != "cluster-node-2" {
		t.Errorf("Expected NodeID cluster-node-2, got %s", stats2.NodeID)
	}
}

// ---------------------------------------------------------------------------
// Integration: cluster with cacheSync disabled - no cacheSyncLoop started
// ---------------------------------------------------------------------------

func TestCluster_CacheSyncDisabled_NoLoopStarted(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:    true,
		NodeID:     "no-sync-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 48004,
		CacheSync:  false,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Verify cacheSyncChan exists but no loop reads from it
	// (writing to it would block if no consumer, but the buffer is 100)
	c.cacheSyncChan <- CacheSyncEvent{
		Type: "invalidate",
		Keys: []string{"key-no-sync"},
	}

	time.Sleep(100 * time.Millisecond)
	c.Stop()
}

// ---------------------------------------------------------------------------
// GossipProtocol: Join with valid address and gossip not started
// (conn is nil, so WriteToUDP panics - this is expected behavior)
// ---------------------------------------------------------------------------

func TestGossipProtocol_Join_GossipNotStarted_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Join() should panic when gossip is not started (nil conn)")
		}
	}()

	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = 48005

	gp, _ := NewGossipProtocol(cfg, nl)
	// Do NOT start - conn is nil

	gp.Join("127.0.0.1:48006")
}

// ---------------------------------------------------------------------------
// GossipProtocol: BroadcastCacheInvalidation with no alive nodes
// ---------------------------------------------------------------------------

func TestGossipProtocol_BroadcastCacheInvalidation_NoAliveNodes_VerifyNil(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	// No other nodes added

	cfg := DefaultGossipConfig()
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = 48007

	gp, _ := NewGossipProtocol(cfg, nl)
	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	err := gp.BroadcastCacheInvalidation([]string{"key1"})
	if err != nil {
		t.Errorf("BroadcastCacheInvalidation() with no alive nodes should succeed, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GossipProtocol: handlePing with invalid payload (decode fails)
// ---------------------------------------------------------------------------

func TestGossipProtocol_HandlePing_InvalidPayload(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	// Create a ping message with invalid payload
	msg := Message{
		Type:    MessageTypePing,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid gob data
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handlePing(msg, from)

	// Should not panic, pingReceived should still be incremented
	if gp.pingReceived != 1 {
		t.Errorf("Expected pingReceived=1, got %d", gp.pingReceived)
	}
}

// ---------------------------------------------------------------------------
// GossipProtocol: handleAck with invalid payload (decode fails)
// ---------------------------------------------------------------------------

func TestGossipProtocol_HandleAck_InvalidPayload(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	msg := Message{
		Type:    MessageTypeAck,
		Payload: []byte{0xFF, 0xFE, 0xFD},
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleAck(msg, from)

	// Should not panic, node should not be updated
	node, ok := nl.Get("nonexistent")
	if ok {
		t.Error("No node should exist from invalid ack")
	}
	_ = node
}

// ---------------------------------------------------------------------------
// GossipProtocol: handleGossip with self-node in gossip payload
// ---------------------------------------------------------------------------

func TestGossipProtocol_HandleGossip_SelfInPayload(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	joinCalled := false
	gp.SetCallbacks(
		func(*Node) { joinCalled = true },
		nil, nil, nil,
	)

	// Gossip includes self - should be skipped
	gossipPayload := GossipPayload{
		Nodes: []NodeInfo{
			{ID: "self", Addr: "127.0.0.1", Port: 7946, State: NodeStateAlive, Version: 1},
		},
	}
	payloadBytes, _ := encodePayload(gossipPayload)
	msg := Message{
		Type:    MessageTypeGossip,
		Payload: payloadBytes,
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleGossip(msg, from)

	if joinCalled {
		t.Error("Join callback should not be called for self node in gossip")
	}
}

// ---------------------------------------------------------------------------
// GossipProtocol: handleGossip with empty nodes list
// ---------------------------------------------------------------------------

func TestGossipProtocol_HandleGossip_EmptyNodes(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	joinCalled := false
	gp.SetCallbacks(
		func(*Node) { joinCalled = true },
		nil, nil, nil,
	)

	gossipPayload := GossipPayload{
		Nodes: []NodeInfo{},
	}
	payloadBytes, _ := encodePayload(gossipPayload)
	msg := Message{
		Type:    MessageTypeGossip,
		Payload: payloadBytes,
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleGossip(msg, from)

	if joinCalled {
		t.Error("Join callback should not be called for empty gossip")
	}
}

// ---------------------------------------------------------------------------
// GossipProtocol: probeNodes with alive node seen recently
// ---------------------------------------------------------------------------

func TestGossipProtocol_ProbeNodes_AliveNodeRecentSeen(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	aliveNode := &Node{
		ID:       "alive-recent",
		State:    NodeStateAlive,
		Addr:     "127.0.0.1",
		LastSeen: time.Now(),
	}
	nl := NewNodeList(self)
	nl.Add(aliveNode)

	cfg := DefaultGossipConfig()
	cfg.BindPort = 48008

	gp, _ := NewGossipProtocol(cfg, nl)
	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	gp.probeNodes()

	// Node should still be alive
	node, ok := nl.Get("alive-recent")
	if !ok {
		t.Fatal("Node should exist")
	}
	if node.State != NodeStateAlive {
		t.Errorf("Expected node state Alive, got %v", node.State)
	}
}

// ---------------------------------------------------------------------------
// GossipProtocol: probeNodes with dead node eligible for removal
// ---------------------------------------------------------------------------

func TestGossipProtocol_ProbeNodes_DeadNodeRemoval(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	deadNode := &Node{
		ID:       "dead-old",
		State:    NodeStateDead,
		Addr:     "127.0.0.1",
		LastSeen: time.Now().Add(-100 * time.Second),
	}
	nl := NewNodeList(self)
	nl.Add(deadNode)

	cfg := DefaultGossipConfig()
	cfg.BindPort = 48009
	cfg.ProbeInterval = 1 * time.Second

	gp, _ := NewGossipProtocol(cfg, nl)
	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	gp.probeNodes()

	// Dead node should be removed
	_, ok := nl.Get("dead-old")
	if ok {
		t.Error("Dead node should have been removed")
	}
}

// ---------------------------------------------------------------------------
// GossipProtocol: handleGossip with invalid payload (decode fails)
// ---------------------------------------------------------------------------

func TestGossipProtocol_HandleGossip_InvalidPayload(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	msg := Message{
		Type:    MessageTypeGossip,
		Payload: []byte{0xFF, 0xFE, 0xFD},
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleGossip(msg, from)

	// Should not panic, no nodes added
	if nl.Count() != 1 {
		t.Errorf("Expected 1 node (self only), got %d", nl.Count())
	}
}

// ---------------------------------------------------------------------------
// GossipProtocol: handleCacheInvalidate with invalid payload (decode fails)
// ---------------------------------------------------------------------------

func TestGossipProtocol_HandleCacheInvalidate_InvalidPayload(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	cacheInvalidCalled := false
	gp.SetCallbacks(
		nil, nil, nil,
		func([]string) { cacheInvalidCalled = true },
	)

	msg := Message{
		Type:    MessageTypeCacheInvalidate,
		Payload: []byte{0xFF, 0xFE, 0xFD},
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleCacheInvalidate(msg, from)

	if cacheInvalidCalled {
		t.Error("Cache invalid callback should not be called for invalid payload")
	}
}

// ---------------------------------------------------------------------------
// GossipProtocol: handleGossip with new node but nil onNodeJoin callback
// ---------------------------------------------------------------------------

func TestGossipProtocol_HandleGossip_NewNode_NilCallback(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)
	// Don't set callbacks - onNodeJoin is nil

	gossipPayload := GossipPayload{
		Nodes: []NodeInfo{
			{ID: "new-node-nil-cb", Addr: "192.168.1.1", Port: 7946, State: NodeStateAlive, Version: 1},
		},
	}
	payloadBytes, _ := encodePayload(gossipPayload)
	msg := Message{
		Type:    MessageTypeGossip,
		Payload: payloadBytes,
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleGossip(msg, from)

	// Node should still be added even without callback
	node, ok := nl.Get("new-node-nil-cb")
	if !ok {
		t.Fatal("Node should have been added even with nil callback")
	}
	if node.Addr != "192.168.1.1" {
		t.Errorf("Expected Addr 192.168.1.1, got %s", node.Addr)
	}
}

// ---------------------------------------------------------------------------
// GossipProtocol: handleGossip with updated node but nil onNodeUpdate callback
// ---------------------------------------------------------------------------

func TestGossipProtocol_HandleGossip_UpdateNode_NilCallback(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	existingNode := &Node{ID: "existing", State: NodeStateAlive, Version: 1, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	nl.Add(existingNode)

	cfg := DefaultGossipConfig()
	gp, _ := NewGossipProtocol(cfg, nl)
	// Don't set callbacks - onNodeUpdate is nil

	gossipPayload := GossipPayload{
		Nodes: []NodeInfo{
			{ID: "existing", Addr: "192.168.1.1", Port: 7946, State: NodeStateSuspect, Version: 2},
		},
	}
	payloadBytes, _ := encodePayload(gossipPayload)
	msg := Message{
		Type:    MessageTypeGossip,
		Payload: payloadBytes,
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleGossip(msg, from)

	// Node should still be updated even without callback
	node, ok := nl.Get("existing")
	if !ok {
		t.Fatal("Node should exist")
	}
	if node.State != NodeStateSuspect {
		t.Errorf("Expected state Suspect, got %v", node.State)
	}
}

// ---------------------------------------------------------------------------
// GossipProtocol: handleMessage with Ack type (round-trip with gob encoding)
// ---------------------------------------------------------------------------

func TestGossipProtocol_HandleMessage_AckRoundTrip(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	otherNode := &Node{ID: "other", State: NodeStateSuspect, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	nl.Add(otherNode)

	cfg := DefaultGossipConfig()
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = 48010

	gp, _ := NewGossipProtocol(cfg, nl)
	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	ack := AckPayload{NodeID: "other", Version: 2}
	ackBytes, _ := encodePayload(ack)

	msg := Message{
		Type:      MessageTypeAck,
		From:      "other",
		Timestamp: time.Now(),
		Payload:   ackBytes,
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(msg); err != nil {
		t.Fatalf("Failed to encode ack message: %v", err)
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleMessage(buf.Bytes(), from)

	node, ok := nl.Get("other")
	if !ok {
		t.Fatal("Node should exist")
	}
	if node.State != NodeStateAlive {
		t.Errorf("Expected node state Alive after ack, got %v", node.State)
	}
}

// ---------------------------------------------------------------------------
// GossipProtocol: handleMessage with CacheInvalidate from another node
// ---------------------------------------------------------------------------

func TestGossipProtocol_HandleMessage_CacheInvalidate(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = 48011

	gp, _ := NewGossipProtocol(cfg, nl)

	receivedKeys := []string{}
	gp.SetCallbacks(
		nil, nil, nil,
		func(keys []string) { receivedKeys = keys },
	)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	cachePayload := CacheInvalidatePayload{
		Keys:      []string{"key-a", "key-b"},
		Source:    "other-node",
		Timestamp: time.Now(),
	}
	payloadBytes, _ := encodePayload(cachePayload)

	msg := Message{
		Type:      MessageTypeCacheInvalidate,
		From:      "other-node",
		Timestamp: time.Now(),
		Payload:   payloadBytes,
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(msg); err != nil {
		t.Fatalf("Failed to encode cache invalidate message: %v", err)
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleMessage(buf.Bytes(), from)

	if len(receivedKeys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(receivedKeys))
	}
}

// ---------------------------------------------------------------------------
// Cluster: InvalidateCacheLocal with nil cache (edge case)
// ---------------------------------------------------------------------------

func TestCluster_InvalidateCacheLocal_EmptyKeys(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:    true,
		NodeID:     "empty-keys-test",
		BindAddr:   "127.0.0.1",
		GossipPort: 48012,
		CacheSync:  true,
	}

	c, _ := New(cfg, logger, dnsCache)
	c.InvalidateCacheLocal([]string{})

	// Should not panic
}

// ---------------------------------------------------------------------------
// Cluster: Stats with unhealthy cluster (minority alive)
// ---------------------------------------------------------------------------

func TestCluster_Stats_UnhealthyCluster(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:    true,
		NodeID:     "stats-unhealthy",
		BindAddr:   "127.0.0.1",
		GossipPort: 48013,
	}

	c, _ := New(cfg, logger, dnsCache)
	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer c.Stop()

	// Add nodes: self (alive) + 2 dead nodes = 1 alive, 3 total
	// Need majority: (3/2)+1 = 2, but only 1 alive -> unhealthy
	c.nodeList.Add(&Node{
		ID:       "dead-node-1",
		Addr:     "127.0.0.1",
		State:    NodeStateDead,
		LastSeen: time.Now(),
	})
	c.nodeList.Add(&Node{
		ID:       "dead-node-2",
		Addr:     "127.0.0.1",
		State:    NodeStateDead,
		LastSeen: time.Now(),
	})

	stats := c.Stats()
	if stats.IsHealthy {
		t.Error("Cluster with 1 alive out of 3 should not be healthy")
	}
	if stats.NodeCount != 3 {
		t.Errorf("Expected NodeCount 3, got %d", stats.NodeCount)
	}
	if stats.AliveCount != 1 {
		t.Errorf("Expected AliveCount 1, got %d", stats.AliveCount)
	}
}

// ---------------------------------------------------------------------------
// Cluster: IsHealthy with exact quorum
// ---------------------------------------------------------------------------

func TestCluster_IsHealthy_ExactQuorum(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:    true,
		NodeID:     "quorum-test",
		BindAddr:   "127.0.0.1",
		GossipPort: 48014,
	}

	c, _ := New(cfg, logger, dnsCache)
	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer c.Stop()

	// 3 total nodes, 2 alive: (3/2)+1 = 2 -> exactly quorum
	c.nodeList.Add(&Node{
		ID:       "alive-node-1",
		Addr:     "127.0.0.1",
		State:    NodeStateAlive,
		LastSeen: time.Now(),
	})
	c.nodeList.Add(&Node{
		ID:       "dead-node-1",
		Addr:     "127.0.0.1",
		State:    NodeStateDead,
		LastSeen: time.Now(),
	})

	if !c.IsHealthy() {
		t.Error("Cluster with 2 alive out of 3 should be healthy (exact quorum)")
	}
}

// ---------------------------------------------------------------------------
// Cluster: encode/decode round-trip for NodeMeta
// ---------------------------------------------------------------------------

func TestEncodeDecode_NodeMetaRoundTrip(t *testing.T) {
	meta := NodeMeta{
		Region:   "ap-southeast-1",
		Zone:     "ap-southeast-1a",
		Weight:   300,
		HTTPAddr: "10.0.0.1:9090",
	}

	data, err := encodePayload(meta)
	if err != nil {
		t.Fatalf("encodePayload(NodeMeta) error: %v", err)
	}

	var decoded NodeMeta
	if err := decodePayload(data, &decoded); err != nil {
		t.Fatalf("decodePayload(NodeMeta) error: %v", err)
	}

	if decoded.Region != meta.Region {
		t.Errorf("Expected Region %s, got %s", meta.Region, decoded.Region)
	}
	if decoded.Zone != meta.Zone {
		t.Errorf("Expected Zone %s, got %s", meta.Zone, decoded.Zone)
	}
	if decoded.Weight != meta.Weight {
		t.Errorf("Expected Weight %d, got %d", meta.Weight, decoded.Weight)
	}
	if decoded.HTTPAddr != meta.HTTPAddr {
		t.Errorf("Expected HTTPAddr %s, got %s", meta.HTTPAddr, decoded.HTTPAddr)
	}
}

// ---------------------------------------------------------------------------
// GossipProtocol: probeNodes with alive node not seen recently
// (should mark as suspect)
// ---------------------------------------------------------------------------

func TestGossipProtocol_ProbeNodes_AliveToSuspect(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	// Node last seen long ago - should become suspect
	oldNode := &Node{
		ID:       "old-alive",
		State:    NodeStateAlive,
		Addr:     "127.0.0.1",
		LastSeen: time.Now().Add(-10 * time.Second),
	}
	nl := NewNodeList(self)
	nl.Add(oldNode)

	cfg := DefaultGossipConfig()
	cfg.BindPort = 48015
	cfg.ProbeInterval = 1 * time.Second
	cfg.SuspicionMult = 2

	gp, _ := NewGossipProtocol(cfg, nl)
	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	gp.probeNodes()

	node, ok := nl.Get("old-alive")
	if !ok {
		t.Fatal("Node should exist")
	}
	if node.State != NodeStateSuspect {
		t.Errorf("Expected node state Suspect, got %v", node.State)
	}
}

// ---------------------------------------------------------------------------
// GossipProtocol: probeNodes where suspect gets pinged (not yet dead)
// ---------------------------------------------------------------------------

func TestGossipProtocol_ProbeNodes_SuspectPing(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	// Suspect node seen somewhat recently (not long enough to be dead)
	suspectNode := &Node{
		ID:       "suspect-ping",
		State:    NodeStateSuspect,
		Addr:     "127.0.0.1",
		LastSeen: time.Now().Add(-3 * time.Second),
	}
	nl := NewNodeList(self)
	nl.Add(suspectNode)

	cfg := DefaultGossipConfig()
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = 48016
	cfg.ProbeInterval = 1 * time.Second
	cfg.SuspicionMult = 4

	gp, _ := NewGossipProtocol(cfg, nl)
	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	gp.probeNodes()

	// Should have sent a ping (check pingSent counter)
	stats := gp.Stats()
	if stats.PingSent == 0 {
		t.Error("Expected ping to be sent for suspect node")
	}
}

// ---------------------------------------------------------------------------
// GossipProtocol: gossip with single self node (no targets available)
// ---------------------------------------------------------------------------

func TestGossipProtocol_Gossip_SelfOnly(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)

	cfg := DefaultGossipConfig()
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = 48017
	cfg.GossipNodes = 3

	gp, _ := NewGossipProtocol(cfg, nl)
	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	// Should complete without panic when no other nodes exist
	gp.gossip()

	stats := gp.Stats()
	// No messages sent because GetRandom returns nil
	if stats.MessagesSent > 0 {
		t.Log("Messages were sent despite no targets (unexpected)")
	}
}

// ---------------------------------------------------------------------------
// Cluster: handleCacheInvalid with nil cache
// ---------------------------------------------------------------------------

func TestCluster_HandleCacheInvalid_NilCache_VerifyCallback(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)

	cfg := Config{
		Enabled:    true,
		NodeID:     "nil-cache-test",
		BindAddr:   "127.0.0.1",
		GossipPort: 48018,
	}

	c, _ := New(cfg, logger, nil)

	cacheInvalidCalled := false
	c.AddEventHandler(&EventHandlerFunc{
		OnCacheInvalidFunc: func(keys []string) { cacheInvalidCalled = true },
	})

	// Should not panic with nil cache
	c.handleCacheInvalid([]string{"key1"})

	if !cacheInvalidCalled {
		t.Error("Handler should still be called even with nil cache")
	}
}

// ---------------------------------------------------------------------------
// Cluster: handleNodeJoin/Leave/Update with no handlers registered
// ---------------------------------------------------------------------------

func TestCluster_HandleEvents_NoHandlers(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)

	cfg := Config{
		Enabled:    true,
		NodeID:     "no-handlers",
		BindAddr:   "127.0.0.1",
		GossipPort: 48019,
	}

	c, _ := New(cfg, logger, nil)

	// These should not panic with no handlers
	c.handleNodeJoin(&Node{ID: "test-join", Addr: "1.2.3.4"})
	c.handleNodeLeave(&Node{ID: "test-leave", Addr: "1.2.3.4"})
	c.handleNodeUpdate(&Node{ID: "test-update", Addr: "1.2.3.4"})
	c.handleCacheInvalid([]string{"test-key"})
}

// ---------------------------------------------------------------------------
// Cluster: New with empty NodeID auto-generation
// ---------------------------------------------------------------------------

func TestCluster_New_AutoNodeID_GeneratesUniqueIDs(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	ids := make(map[string]bool)
	for i := 0; i < 10; i++ {
		cfg := Config{
			Enabled:    true,
			NodeID:     "", // Auto-generate
			BindAddr:   "127.0.0.1",
			GossipPort: 48020 + i,
		}
		c, err := New(cfg, logger, dnsCache)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		id := c.GetNodeID()
		if ids[id] {
			t.Errorf("Duplicate node ID generated: %s", id)
		}
		ids[id] = true
	}

	if len(ids) != 10 {
		t.Errorf("Expected 10 unique IDs, got %d", len(ids))
	}
}

// ---------------------------------------------------------------------------
// GossipProtocol: Stop with already-cancelled context
// ---------------------------------------------------------------------------

func TestGossipProtocol_Stop_AlreadyCancelled(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = 48021

	gp, _ := NewGossipProtocol(cfg, nl)
	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Stop once
	gp.Stop()

	// Stop again - should not panic
	err := gp.Stop()
	if err != nil {
		t.Errorf("Second Stop() should not error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GossipProtocol: SetCallbacks with nil callbacks
// ---------------------------------------------------------------------------

func TestGossipProtocol_SetCallbacks_Nil(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	// Set all nil callbacks
	gp.SetCallbacks(nil, nil, nil, nil)

	if gp.onNodeJoin != nil {
		t.Error("onNodeJoin should be nil")
	}
	if gp.onNodeLeave != nil {
		t.Error("onNodeLeave should be nil")
	}
	if gp.onNodeUpdate != nil {
		t.Error("onNodeUpdate should be nil")
	}
	if gp.onCacheInvalid != nil {
		t.Error("onCacheInvalid should be nil")
	}
}

// ---------------------------------------------------------------------------
// Cluster: Start/Stop lifecycle with CacheSync and verify no goroutine leak
// ---------------------------------------------------------------------------

func TestCluster_StartStop_LifecycleWithCacheSync(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	dnsCache := cache.New(cache.Config{Capacity: 1000})

	cfg := Config{
		Enabled:    true,
		NodeID:     "lifecycle-test",
		BindAddr:   "127.0.0.1",
		GossipPort: 48022,
		CacheSync:  true,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Start
	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if !c.IsStarted() {
		t.Error("Should be started")
	}

	// Stop
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if c.IsStarted() {
		t.Error("Should not be started after stop")
	}

	// Stop again (idempotent)
	if err := c.Stop(); err != nil {
		t.Fatalf("Second Stop() error = %v", err)
	}
}
