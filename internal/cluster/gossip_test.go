package cluster

import (
	"testing"
	"time"
)

func TestDefaultGossipConfig(t *testing.T) {
	cfg := DefaultGossipConfig()

	if cfg.BindAddr != "0.0.0.0" {
		t.Errorf("Expected BindAddr 0.0.0.0, got %s", cfg.BindAddr)
	}

	if cfg.BindPort != 7946 {
		t.Errorf("Expected BindPort 7946, got %d", cfg.BindPort)
	}

	if cfg.GossipInterval != 200*time.Millisecond {
		t.Errorf("Expected GossipInterval 200ms, got %v", cfg.GossipInterval)
	}

	if cfg.ProbeInterval != 1*time.Second {
		t.Errorf("Expected ProbeInterval 1s, got %v", cfg.ProbeInterval)
	}

	if cfg.ProbeTimeout != 500*time.Millisecond {
		t.Errorf("Expected ProbeTimeout 500ms, got %v", cfg.ProbeTimeout)
	}

	if cfg.GossipNodes != 3 {
		t.Errorf("Expected GossipNodes 3, got %d", cfg.GossipNodes)
	}
}

func TestNewGossipProtocol(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatalf("NewGossipProtocol() error = %v", err)
	}

	if gp == nil {
		t.Fatal("NewGossipProtocol() returned nil")
	}

	if gp.config.BindPort != cfg.BindPort {
		t.Error("Config not properly set")
	}

	if gp.nodeList != nl {
		t.Error("NodeList not properly set")
	}
}

func TestGossipProtocol_SetCallbacks(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	gp, _ := NewGossipProtocol(cfg, nl)

	joinCalled := false
	leaveCalled := false
	updateCalled := false
	cacheInvalidCalled := false

	gp.SetCallbacks(
		func(*Node) { joinCalled = true },
		func(*Node) { leaveCalled = true },
		func(*Node) { updateCalled = true },
		func([]string) { cacheInvalidCalled = true },
	)

	// Test callbacks are set
	if gp.onNodeJoin == nil {
		t.Error("onNodeJoin callback not set")
	}

	if gp.onNodeLeave == nil {
		t.Error("onNodeLeave callback not set")
	}

	if gp.onNodeUpdate == nil {
		t.Error("onNodeUpdate callback not set")
	}

	if gp.onCacheInvalid == nil {
		t.Error("onCacheInvalid callback not set")
	}

	// Trigger callbacks to verify they work
	gp.onNodeJoin(&Node{})
	gp.onNodeLeave(&Node{})
	gp.onNodeUpdate(&Node{})
	gp.onCacheInvalid([]string{})

	if !joinCalled {
		t.Error("onNodeJoin callback not invoked")
	}

	if !leaveCalled {
		t.Error("onNodeLeave callback not invoked")
	}

	if !updateCalled {
		t.Error("onNodeUpdate callback not invoked")
	}

	if !cacheInvalidCalled {
		t.Error("onCacheInvalid callback not invoked")
	}
}

func TestGossipProtocol_Stats(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	gp, _ := NewGossipProtocol(cfg, nl)

	// Initial stats should be zero
	stats := gp.Stats()
	if stats.MessagesSent != 0 {
		t.Errorf("Expected 0 messages sent, got %d", stats.MessagesSent)
	}
	if stats.MessagesReceived != 0 {
		t.Errorf("Expected 0 messages received, got %d", stats.MessagesReceived)
	}
	if stats.PingSent != 0 {
		t.Errorf("Expected 0 pings sent, got %d", stats.PingSent)
	}
	if stats.PingReceived != 0 {
		t.Errorf("Expected 0 pings received, got %d", stats.PingReceived)
	}
}

func TestEncodeDecodeMessage(t *testing.T) {
	// Test ping payload
	ping := PingPayload{
		NodeID:  "test-node",
		Version: 42,
	}

	payloadBytes, err := encodePayload(ping)
	if err != nil {
		t.Fatalf("encodePayload() error = %v", err)
	}

	data, err := encodeMessage(MessageTypePing, payloadBytes)
	if err != nil {
		t.Fatalf("encodeMessage() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("encodeMessage() returned empty data")
	}

	// Decode the message
	var msg Message
	if err := decodeMessage(data, &msg); err != nil {
		t.Fatalf("decodeMessage() error = %v", err)
	}

	if msg.Type != MessageTypePing {
		t.Errorf("Expected message type Ping, got %v", msg.Type)
	}

	// Decode payload
	var decodedPing PingPayload
	if err := decodePayload(msg.Payload, &decodedPing); err != nil {
		t.Fatalf("decodePayload() error = %v", err)
	}

	if decodedPing.NodeID != ping.NodeID {
		t.Errorf("Expected NodeID %s, got %s", ping.NodeID, decodedPing.NodeID)
	}

	if decodedPing.Version != ping.Version {
		t.Errorf("Expected Version %d, got %d", ping.Version, decodedPing.Version)
	}
}

func TestEncodeDecodeGossipPayload(t *testing.T) {
	payload := GossipPayload{
		Nodes: []NodeInfo{
			{
				ID:      "node1",
				Addr:    "192.168.1.1",
				Port:    7946,
				State:   NodeStateAlive,
				Version: 1,
				Meta: NodeMeta{
					Region: "us-east",
					Zone:   "us-east-1a",
					Weight: 100,
				},
			},
			{
				ID:      "node2",
				Addr:    "192.168.1.2",
				Port:    7946,
				State:   NodeStateSuspect,
				Version: 2,
			},
		},
	}

	payloadBytes, err := encodePayload(payload)
	if err != nil {
		t.Fatalf("encodePayload() error = %v", err)
	}

	data, err := encodeMessage(MessageTypeGossip, payloadBytes)
	if err != nil {
		t.Fatalf("encodeMessage() error = %v", err)
	}

	var msg Message
	if err := decodeMessage(data, &msg); err != nil {
		t.Fatalf("decodeMessage() error = %v", err)
	}

	if msg.Type != MessageTypeGossip {
		t.Errorf("Expected message type Gossip, got %v", msg.Type)
	}

	var decoded GossipPayload
	if err := decodePayload(msg.Payload, &decoded); err != nil {
		t.Fatalf("decodePayload() error = %v", err)
	}

	if len(decoded.Nodes) != 2 {
		t.Errorf("Expected 2 nodes, got %d", len(decoded.Nodes))
	}

	if decoded.Nodes[0].ID != "node1" {
		t.Errorf("Expected first node ID node1, got %s", decoded.Nodes[0].ID)
	}

	if decoded.Nodes[0].Meta.Region != "us-east" {
		t.Errorf("Expected region us-east, got %s", decoded.Nodes[0].Meta.Region)
	}

	if decoded.Nodes[1].State != NodeStateSuspect {
		t.Errorf("Expected second node state Suspect, got %v", decoded.Nodes[1].State)
	}
}

func TestEncodeDecodeCacheInvalidatePayload(t *testing.T) {
	payload := CacheInvalidatePayload{
		Keys:      []string{"key1", "key2", "key3"},
		Source:    "node1",
		Timestamp: time.Now(),
	}

	payloadBytes, err := encodePayload(payload)
	if err != nil {
		t.Fatalf("encodePayload() error = %v", err)
	}

	data, err := encodeMessage(MessageTypeCacheInvalidate, payloadBytes)
	if err != nil {
		t.Fatalf("encodeMessage() error = %v", err)
	}

	var msg Message
	if err := decodeMessage(data, &msg); err != nil {
		t.Fatalf("decodeMessage() error = %v", err)
	}

	if msg.Type != MessageTypeCacheInvalidate {
		t.Errorf("Expected message type CacheInvalidate, got %v", msg.Type)
	}

	var decoded CacheInvalidatePayload
	if err := decodePayload(msg.Payload, &decoded); err != nil {
		t.Fatalf("decodePayload() error = %v", err)
	}

	if len(decoded.Keys) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(decoded.Keys))
	}

	if decoded.Source != "node1" {
		t.Errorf("Expected source node1, got %s", decoded.Source)
	}
}

func TestMessageType_Constants(t *testing.T) {
	// Verify message type constants
	if MessageTypePing != 0 {
		t.Errorf("Expected MessageTypePing = 0, got %d", MessageTypePing)
	}
	if MessageTypeAck != 1 {
		t.Errorf("Expected MessageTypeAck = 1, got %d", MessageTypeAck)
	}
	if MessageTypeGossip != 2 {
		t.Errorf("Expected MessageTypeGossip = 2, got %d", MessageTypeGossip)
	}
	if MessageTypeCacheInvalidate != 3 {
		t.Errorf("Expected MessageTypeCacheInvalidate = 3, got %d", MessageTypeCacheInvalidate)
	}
	if MessageTypeCacheUpdate != 4 {
		t.Errorf("Expected MessageTypeCacheUpdate = 4, got %d", MessageTypeCacheUpdate)
	}
}
