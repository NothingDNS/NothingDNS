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
// gossip.go: encodeMessage - verify all message types encode correctly
// ---------------------------------------------------------------------------

func TestEncodeMessage_AllTypes(t *testing.T) {
	for _, msgType := range []MessageType{
		MessageTypePing,
		MessageTypeAck,
		MessageTypeGossip,
		MessageTypeCacheInvalidate,
		MessageTypeCacheUpdate,
	} {
		data, err := encodeMessage(msgType, []byte("payload"))
		if err != nil {
			t.Errorf("encodeMessage(type=%d) failed: %v", msgType, err)
		}
		if len(data) == 0 {
			t.Errorf("encodeMessage(type=%d) returned empty data", msgType)
		}
	}
}

// ---------------------------------------------------------------------------
// gossip.go: Join() - full success path with two live gossip protocols
// ---------------------------------------------------------------------------

func TestGossipProtocol_Join_SuccessWithPeer(t *testing.T) {
	self := &Node{ID: "joiner", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = 37001

	gp, _ := NewGossipProtocol(cfg, nl)
	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	// Create a seed node to receive the ping
	seedSelf := &Node{ID: "seed", State: NodeStateAlive, Addr: "127.0.0.1"}
	seedNl := NewNodeList(seedSelf)
	seedCfg := DefaultGossipConfig()
	seedCfg.BindAddr = "127.0.0.1"
	seedCfg.BindPort = 37002
	seedGp, _ := NewGossipProtocol(seedCfg, seedNl)
	if err := seedGp.Start(); err != nil {
		t.Fatalf("seed Start() error = %v", err)
	}
	defer seedGp.Stop()

	err := gp.Join("127.0.0.1:37002")
	if err != nil {
		t.Fatalf("Join() error = %v", err)
	}

	stats := gp.Stats()
	if stats.PingSent == 0 {
		t.Error("Expected ping to be sent during Join()")
	}

	time.Sleep(100 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// gossip.go: BroadcastCacheInvalidation - with alive nodes exercising send loop
// ---------------------------------------------------------------------------

func TestGossipProtocol_BroadcastCacheInvalidation_SendLoop(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	other := &Node{ID: "other", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	nl.Add(other)

	cfg := DefaultGossipConfig()
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = 37003

	gp, _ := NewGossipProtocol(cfg, nl)
	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	err := gp.BroadcastCacheInvalidation([]string{"key1", "key2", "key3"})
	if err != nil {
		t.Fatalf("BroadcastCacheInvalidation() error = %v", err)
	}

	stats := gp.Stats()
	if stats.MessagesSent == 0 {
		t.Error("Expected messages to be sent during BroadcastCacheInvalidation")
	}
}

// ---------------------------------------------------------------------------
// gossip.go: gossip() - with multiple alive nodes exercising random target selection
// ---------------------------------------------------------------------------

func TestGossipProtocol_Gossip_MultipleRandomTargets(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	node1 := &Node{ID: "node1", State: NodeStateAlive, Addr: "127.0.0.1"}
	node2 := &Node{ID: "node2", State: NodeStateAlive, Addr: "127.0.0.1"}
	node3 := &Node{ID: "node3", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	nl.Add(node1)
	nl.Add(node2)
	nl.Add(node3)

	cfg := DefaultGossipConfig()
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = 37004
	cfg.GossipNodes = 5 // Request more than available to exercise all iterations

	gp, _ := NewGossipProtocol(cfg, nl)
	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	gp.gossip()

	stats := gp.Stats()
	if stats.MessagesSent == 0 {
		t.Error("Expected messages to be sent during gossip with multiple nodes")
	}
}

// ---------------------------------------------------------------------------
// cluster.go: cacheSyncLoop - invalidate event with closed gossip conn
// (exercises the BroadcastCacheInvalidation call even though it returns nil)
// ---------------------------------------------------------------------------

func TestCluster_CacheSyncLoop_InvalidateWithClosedConn(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 37005,
		CacheSync:  true,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Close the gossip connection before sending invalidate
	c.gossip.conn.Close()

	c.cacheSyncChan <- CacheSyncEvent{
		Type: "invalidate",
		Keys: []string{"key-fail-1", "key-fail-2"},
	}

	time.Sleep(200 * time.Millisecond)
	c.Stop()
}

// ---------------------------------------------------------------------------
// cluster.go: cacheSyncLoop - multiple event types
// ---------------------------------------------------------------------------

func TestCluster_CacheSyncLoop_VariedEventTypes(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 37006,
		CacheSync:  true,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	c.cacheSyncChan <- CacheSyncEvent{Type: "update", Keys: []string{"key-update"}}
	c.cacheSyncChan <- CacheSyncEvent{Type: "invalidate", Keys: []string{"key-invalidate"}}
	c.cacheSyncChan <- CacheSyncEvent{Type: "unknown_type", Keys: []string{"key-unknown"}}

	time.Sleep(200 * time.Millisecond)
	c.Stop()
}

// ---------------------------------------------------------------------------
// gossip.go: Join() - address resolution error
// ---------------------------------------------------------------------------

func TestGossipProtocol_Join_BadAddressResolve(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = 37007

	gp, _ := NewGossipProtocol(cfg, nl)
	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	err := gp.Join("256.256.256.256:99999")
	if err == nil {
		t.Error("Join() should fail with unresolvable address")
	}
}

// ---------------------------------------------------------------------------
// gossip.go: two-node ping/ack round-trip integration
// ---------------------------------------------------------------------------

func TestGossipProtocol_TwoNodePingAck(t *testing.T) {
	self1 := &Node{ID: "node-a", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl1 := NewNodeList(self1)
	cfg1 := DefaultGossipConfig()
	cfg1.BindAddr = "127.0.0.1"
	cfg1.BindPort = 37008

	self2 := &Node{ID: "node-b", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl2 := NewNodeList(self2)
	nl2.Add(&Node{ID: "node-a", State: NodeStateAlive, Addr: "127.0.0.1"})
	cfg2 := DefaultGossipConfig()
	cfg2.BindAddr = "127.0.0.1"
	cfg2.BindPort = 37009

	gp1, _ := NewGossipProtocol(cfg1, nl1)
	gp2, _ := NewGossipProtocol(cfg2, nl2)

	if err := gp1.Start(); err != nil {
		t.Fatalf("gp1 Start() error = %v", err)
	}
	defer gp1.Stop()

	if err := gp2.Start(); err != nil {
		t.Fatalf("gp2 Start() error = %v", err)
	}
	defer gp2.Stop()

	err := gp1.Join("127.0.0.1:37009")
	if err != nil {
		t.Fatalf("Join() error = %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	stats1 := gp1.Stats()
	if stats1.PingSent == 0 {
		t.Error("gp1 should have sent a ping")
	}
}

// ---------------------------------------------------------------------------
// gossip.go: gossip() - with only self, target==nil break path
// ---------------------------------------------------------------------------

func TestGossipProtocol_Gossip_NoTargets(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)

	cfg := DefaultGossipConfig()
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = 37010
	cfg.GossipNodes = 5

	gp, _ := NewGossipProtocol(cfg, nl)
	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	gp.gossip()
	// Should complete without panic, no messages sent to nil target
}

// ---------------------------------------------------------------------------
// encodeMessage/decodeMessage round-trip for PingPayload and AckPayload
// ---------------------------------------------------------------------------

func TestEncodeDecode_RoundTripPingAck(t *testing.T) {
	ping := PingPayload{NodeID: "node1", Version: 42}
	pingBytes, err := encodePayload(ping)
	if err != nil {
		t.Fatalf("encodePayload(ping) error: %v", err)
	}
	msgData, err := encodeMessage(MessageTypePing, pingBytes)
	if err != nil {
		t.Fatalf("encodeMessage(ping) error: %v", err)
	}

	var msg Message
	if err := decodeMessageRaw(msgData, &msg); err != nil {
		t.Fatalf("decodeMessage error: %v", err)
	}
	if msg.Type != MessageTypePing {
		t.Errorf("Expected type Ping, got %v", msg.Type)
	}

	var decodedPing PingPayload
	if err := decodePayload(msg.Payload, &decodedPing); err != nil {
		t.Fatalf("decodePayload(ping) error: %v", err)
	}
	if decodedPing.NodeID != "node1" || decodedPing.Version != 42 {
		t.Errorf("Ping round-trip failed: got %+v", decodedPing)
	}

	ack := AckPayload{NodeID: "node2", Version: 7}
	ackBytes, err := encodePayload(ack)
	if err != nil {
		t.Fatalf("encodePayload(ack) error: %v", err)
	}
	ackMsgData, err := encodeMessage(MessageTypeAck, ackBytes)
	if err != nil {
		t.Fatalf("encodeMessage(ack) error: %v", err)
	}

	var ackMsg Message
	if err := decodeMessageRaw(ackMsgData, &ackMsg); err != nil {
		t.Fatalf("decodeMessageRaw(ack) error: %v", err)
	}
	if ackMsg.Type != MessageTypeAck {
		t.Errorf("Expected type Ack, got %v", ackMsg.Type)
	}

	var decodedAck AckPayload
	if err := decodePayload(ackMsg.Payload, &decodedAck); err != nil {
		t.Fatalf("decodePayload(ack) error: %v", err)
	}
	if decodedAck.NodeID != "node2" || decodedAck.Version != 7 {
		t.Errorf("Ack round-trip failed: got %+v", decodedAck)
	}
}

// ---------------------------------------------------------------------------
// cluster.go: Start with both failing and succeeding seed nodes
// ---------------------------------------------------------------------------

func TestCluster_Start_MixedSeedResults(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	seedSelf := &Node{ID: "seed", State: NodeStateAlive, Addr: "127.0.0.1"}
	seedNl := NewNodeList(seedSelf)
	seedCfg := DefaultGossipConfig()
	seedCfg.BindAddr = "127.0.0.1"
	seedCfg.BindPort = 37011
	seedGp, _ := NewGossipProtocol(seedCfg, seedNl)
	if err := seedGp.Start(); err != nil {
		t.Fatalf("seed Start() error = %v", err)
	}
	defer seedGp.Stop()

	cfg := Config{
		Enabled:    true,
		NodeID:     "joiner",
		BindAddr:   "127.0.0.1",
		GossipPort: 37012,
		SeedNodes: []string{
			"invalid-host:99999",
			"127.0.0.1:37011",
		},
		CacheSync: true,
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
		t.Error("Cluster should be started")
	}
}

// ---------------------------------------------------------------------------
// cluster.go: Stop - normal path with CacheSync enabled
// ---------------------------------------------------------------------------

func TestCluster_Stop_CacheSyncEnabled(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 37013,
		CacheSync:  true,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if !c.IsStarted() {
		t.Fatal("Cluster should be started")
	}

	err = c.Stop()
	if err != nil {
		t.Errorf("Stop() error = %v", err)
	}

	if c.IsStarted() {
		t.Error("Cluster should not be started after Stop()")
	}
}

// ---------------------------------------------------------------------------
// gossip.go: handleMessage ignores gossip from self (via gob-encoded message)
// ---------------------------------------------------------------------------

func TestGossipProtocol_HandleMessage_SelfFromGob(t *testing.T) {
	self := &Node{ID: "self-gob-test", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = 37014

	gp, _ := NewGossipProtocol(cfg, nl)

	joinCalled := false
	gp.SetCallbacks(
		func(*Node) { joinCalled = true },
		nil, nil, nil,
	)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	gossipPayload := GossipPayload{
		Nodes: []NodeInfo{
			{ID: "new-node", Addr: "192.168.1.1", Port: 7946, State: NodeStateAlive, Version: 1},
		},
	}
	payloadBytes, _ := encodePayload(gossipPayload)

	msg := Message{
		Type:      MessageTypeGossip,
		From:      "self-gob-test",
		Timestamp: time.Now(),
		Payload:   payloadBytes,
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(msg); err != nil {
		t.Fatalf("Failed to encode message: %v", err)
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleMessage(buf.Bytes(), from)

	if joinCalled {
		t.Error("handleMessage should have ignored message from self")
	}
}

// ---------------------------------------------------------------------------
// cluster.go: New - with all config fields populated (region, zone, weight, http)
// ---------------------------------------------------------------------------

func TestCluster_New_FullMetadata(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "full-meta-node",
		BindAddr:   "127.0.0.1",
		BindPort:   8080,
		GossipPort: 37015,
		Region:     "eu-west-1",
		Zone:       "eu-west-1a",
		Weight:     250,
		SeedNodes:  []string{},
		CacheSync:  true,
		HTTPAddr:   "127.0.0.1:9090",
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if c.GetNodeID() != "full-meta-node" {
		t.Errorf("Expected NodeID full-meta-node, got %s", c.GetNodeID())
	}

	self := c.nodeList.GetSelf()
	if self.Meta.Region != "eu-west-1" {
		t.Errorf("Expected Region eu-west-1, got %s", self.Meta.Region)
	}
	if self.Meta.Zone != "eu-west-1a" {
		t.Errorf("Expected Zone eu-west-1a, got %s", self.Meta.Zone)
	}
	if self.Meta.Weight != 250 {
		t.Errorf("Expected Weight 250, got %d", self.Meta.Weight)
	}
	if self.Meta.HTTPAddr != "127.0.0.1:9090" {
		t.Errorf("Expected HTTPAddr 127.0.0.1:9090, got %s", self.Meta.HTTPAddr)
	}
	if self.Port != 37015 {
		t.Errorf("Expected Port 37015, got %d", self.Port)
	}
}

// ---------------------------------------------------------------------------
// cluster.go: InvalidateCache with CacheSync enabled and remote nodes
// ---------------------------------------------------------------------------

func TestCluster_InvalidateCache_WithRemoteNodes(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 37016,
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
	c.nodeList.Add(&Node{
		ID:       "remote-node",
		Addr:     "127.0.0.1",
		State:    NodeStateAlive,
		LastSeen: time.Now(),
	})

	err = c.InvalidateCache([]string{"key1", "key2"})
	if err != nil {
		t.Errorf("InvalidateCache() error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// node.go: GetLocalIP - verify returns a valid IP
// ---------------------------------------------------------------------------

func TestGetLocalIP_ValidOutput(t *testing.T) {
	ip, err := GetLocalIP()
	if err != nil {
		t.Fatalf("GetLocalIP() error = %v", err)
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Errorf("GetLocalIP() returned invalid IP: %s", ip)
	}
	t.Logf("GetLocalIP() returned: %s", ip)
}
