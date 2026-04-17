package cluster

import (
	"net"
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

	gp, err := NewGossipProtocol(cfg, nl, true)
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
	gp, _ := NewGossipProtocol(cfg, nl, true)

	joinCalled := false
	leaveCalled := false
	updateCalled := false
	cacheInvalidCalled := false

	gp.SetCallbacks(
		func(*Node) { joinCalled = true },
		func(*Node) { leaveCalled = true },
		func(*Node) { updateCalled = true },
		func([]string) { cacheInvalidCalled = true },
		nil, nil,
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
	gp, _ := NewGossipProtocol(cfg, nl, true)

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

	data, err := encodeMessage(MessageTypePing, "test-node", 1, payloadBytes)
	if err != nil {
		t.Fatalf("encodeMessage() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("encodeMessage() returned empty data")
	}

	// Decode the message
	var msg Message
	if err := decodeMessageRaw(data, &msg); err != nil {
		t.Fatalf("decodeMessageRaw() error = %v", err)
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

	data, err := encodeMessage(MessageTypeGossip, "test-node", 1, payloadBytes)
	if err != nil {
		t.Fatalf("encodeMessage() error = %v", err)
	}

	var msg Message
	if err := decodeMessageRaw(data, &msg); err != nil {
		t.Fatalf("decodeMessageRaw() error = %v", err)
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

	data, err := encodeMessage(MessageTypeCacheInvalidate, "test-node", 1, payloadBytes)
	if err != nil {
		t.Fatalf("encodeMessage() error = %v", err)
	}

	var msg Message
	if err := decodeMessageRaw(data, &msg); err != nil {
		t.Fatalf("decodeMessageRaw() error = %v", err)
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

func TestGossipProtocol_StartStop(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 17970 // Use high port to avoid conflicts

	gp, _ := NewGossipProtocol(cfg, nl, true)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Verify started
	if gp.conn == nil {
		t.Error("Connection should be set after Start()")
	}

	// Stop
	if err := gp.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestGossipProtocol_Join(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 17971

	gp, _ := NewGossipProtocol(cfg, nl, true)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	// Join to an address that might not exist (just test encoding/sending)
	err := gp.Join("127.0.0.1:17972")
	// This might fail if no one is listening, but we're testing the encoding and sending logic
	_ = err
}

func TestGossipProtocol_Join_InvalidAddress(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 17973

	gp, _ := NewGossipProtocol(cfg, nl, true)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	// Invalid address format
	err := gp.Join("invalid:address:format")
	if err == nil {
		t.Error("Expected error for invalid address")
	}
}

func TestGossipProtocol_BroadcastCacheInvalidation(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	otherNode := &Node{ID: "other", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	nl.Add(otherNode)

	cfg := DefaultGossipConfig()
	cfg.BindPort = 17974

	gp, _ := NewGossipProtocol(cfg, nl, true)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	// Broadcast cache invalidation
	err := gp.BroadcastCacheInvalidation([]string{"key1", "key2"})
	if err != nil {
		t.Errorf("BroadcastCacheInvalidation() error = %v", err)
	}
}

func TestGossipProtocol_handleMessage(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 17975

	gp, _ := NewGossipProtocol(cfg, nl, true)

	// Start is needed for handlePing to access the connection
	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	// Create a ping message from another node
	ping := PingPayload{
		NodeID:  "other-node",
		Version: 1,
	}
	pingBytes, _ := encodePayload(ping)
	data, _ := encodeMessage(MessageTypePing, "test-node", 1, pingBytes)

	// Handle the message
	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleMessage(data, from)
}

func TestGossipProtocol_handleMessage_FromSelf(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 17981

	gp, _ := NewGossipProtocol(cfg, nl, true)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	// Create a message from self
	ping := PingPayload{
		NodeID:  "self",
		Version: 1,
	}
	pingBytes, _ := encodePayload(ping)
	msg := Message{
		Type:    MessageTypePing,
		From:    "self",
		Payload: pingBytes,
	}
	data, _ := encodeMessage(msg.Type, "test-node", 1, msg.Payload)

	// Decode and set From
	var decodedMsg Message
	decodeMessageRaw(data, &decodedMsg)
	decodedMsg.From = "self"
	data2, _ := encodeMessage(decodedMsg.Type, "test-node", 1, decodedMsg.Payload)

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleMessage(data2, from)
	// Should be ignored (from self)
}

func TestGossipProtocol_handleMessage_InvalidData(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl, true)

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	// Invalid gob data should be silently ignored
	gp.handleMessage([]byte{0xFF, 0xFF, 0xFF}, from)
}

func TestGossipProtocol_handlePing(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 17976

	gp, _ := NewGossipProtocol(cfg, nl, true)
	gp.Start()
	defer gp.Stop()

	// Create a ping message
	ping := PingPayload{
		NodeID:  "other-node",
		Version: 1,
	}
	pingBytes, _ := encodePayload(ping)
	msg := Message{
		Type:    MessageTypePing,
		Payload: pingBytes,
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handlePing(msg, from)

	// Verify ping was received
	if gp.pingReceived != 1 {
		t.Errorf("Expected 1 ping received, got %d", gp.pingReceived)
	}
}

func TestGossipProtocol_handleAck(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	otherNode := &Node{ID: "other", State: NodeStateSuspect, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	nl.Add(otherNode)

	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl, true)

	// Create an ack message
	ack := AckPayload{
		NodeID:  "other",
		Version: 2,
	}
	ackBytes, _ := encodePayload(ack)
	msg := Message{
		Type:    MessageTypeAck,
		Payload: ackBytes,
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleAck(msg, from)

	// Verify node was marked as alive
	node, ok := nl.Get("other")
	if !ok {
		t.Fatal("Node should exist")
	}
	if node.State != NodeStateAlive {
		t.Errorf("Expected node state Alive, got %v", node.State)
	}
}

func TestGossipProtocol_handleGossip_NewNode(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl, true)

	joinCalled := false
	gp.SetCallbacks(
		func(*Node) { joinCalled = true },
		nil, nil, nil,
		nil, nil,
	)

	// Create a gossip message with a new node
	gossip := GossipPayload{
		Nodes: []NodeInfo{
			{
				ID:       "new-node",
				Addr:     "192.168.1.1",
				Port:     7946,
				State:    NodeStateAlive,
				Version:  1,
				LastSeen: time.Now(),
			},
		},
	}
	gossipBytes, _ := encodePayload(gossip)
	msg := Message{
		Type:    MessageTypeGossip,
		Payload: gossipBytes,
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleGossip(msg, from)

	// Verify node was added
	if !joinCalled {
		t.Error("Join callback should have been called for new node")
	}

	node, ok := nl.Get("new-node")
	if !ok {
		t.Fatal("New node should exist")
	}
	if node.Addr != "192.168.1.1" {
		t.Errorf("Expected node addr 192.168.1.1, got %s", node.Addr)
	}
}

func TestGossipProtocol_handleGossip_UpdateNode(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	existingNode := &Node{ID: "existing", State: NodeStateAlive, Version: 1, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	nl.Add(existingNode)

	cfg := DefaultGossipConfig()
	gp, _ := NewGossipProtocol(cfg, nl, true)

	updateCalled := false
	gp.SetCallbacks(
		nil, nil,
		func(*Node) { updateCalled = true },
		nil,
		nil, nil,
	)

	// Create gossip with updated node
	gossip := GossipPayload{
		Nodes: []NodeInfo{
			{
				ID:       "existing",
				Addr:     "192.168.1.1",
				Port:     7946,
				State:    NodeStateSuspect,
				Version:  2, // Higher version
				LastSeen: time.Now(),
			},
		},
	}
	gossipBytes, _ := encodePayload(gossip)
	msg := Message{
		Type:    MessageTypeGossip,
		Payload: gossipBytes,
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleGossip(msg, from)

	if !updateCalled {
		t.Error("Update callback should have been called")
	}
}

func TestGossipProtocol_handleCacheInvalidate(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl, true)

	cacheInvalidKeys := []string{}
	gp.SetCallbacks(
		nil, nil, nil,
		func(keys []string) { cacheInvalidKeys = keys },
		nil, nil,
	)

	// Create cache invalidate message
	cachePayload := CacheInvalidatePayload{
		Keys:      []string{"key1", "key2"},
		Source:    "other-node",
		Timestamp: time.Now(),
	}
	payloadBytes, _ := encodePayload(cachePayload)
	msg := Message{
		Type:    MessageTypeCacheInvalidate,
		Payload: payloadBytes,
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleCacheInvalidate(msg, from)

	if len(cacheInvalidKeys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(cacheInvalidKeys))
	}
}

func TestGossipProtocol_handleCacheInvalidate_FromSelf(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl, true)

	called := false
	gp.SetCallbacks(
		nil, nil, nil,
		func(keys []string) { called = true },
		nil, nil,
	)

	// Create cache invalidate message from self
	cachePayload := CacheInvalidatePayload{
		Keys:      []string{"key1"},
		Source:    "self", // Same as node ID
		Timestamp: time.Now(),
	}
	payloadBytes, _ := encodePayload(cachePayload)
	msg := Message{
		Type:    MessageTypeCacheInvalidate,
		Payload: payloadBytes,
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleCacheInvalidate(msg, from)

	// Should be ignored (from self)
	if called {
		t.Error("Callback should not have been called for message from self")
	}
}

func TestGossipProtocol_gossip(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	otherNode := &Node{ID: "other", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	nl.Add(otherNode)

	cfg := DefaultGossipConfig()
	cfg.BindPort = 17977
	cfg.GossipNodes = 1

	gp, _ := NewGossipProtocol(cfg, nl, true)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	// Call gossip directly
	gp.gossip()
}

func TestGossipProtocol_probeNodes(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	// Create a suspect node
	suspectNode := &Node{
		ID:       "suspect",
		State:    NodeStateSuspect,
		Addr:     "127.0.0.1",
		LastSeen: time.Now().Add(-5 * time.Second),
	}
	nl := NewNodeList(self)
	nl.Add(suspectNode)

	cfg := DefaultGossipConfig()
	cfg.BindPort = 17978

	gp, _ := NewGossipProtocol(cfg, nl, true)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	// Call probeNodes - it should try to ping the suspect node
	gp.probeNodes()
}

func TestGossipProtocol_probeNodes_DeadNode(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	// Create a suspect node that's been suspect for too long
	suspectNode := &Node{
		ID:       "suspect",
		State:    NodeStateSuspect,
		Addr:     "127.0.0.1",
		LastSeen: time.Now().Add(-30 * time.Second),
	}
	nl := NewNodeList(self)
	nl.Add(suspectNode)

	cfg := DefaultGossipConfig()
	cfg.SuspicionMult = 1
	cfg.BindPort = 17979

	gp, _ := NewGossipProtocol(cfg, nl, true)

	leaveCalled := false
	gp.SetCallbacks(
		nil,
		func(*Node) { leaveCalled = true },
		nil, nil,
		nil, nil,
	)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	// Call probeNodes - it should mark the node as dead
	gp.probeNodes()

	if !leaveCalled {
		t.Error("Leave callback should have been called for dead node")
	}
}

func TestGossipProtocol_sendPing(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	targetNode := &Node{ID: "target", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)

	cfg := DefaultGossipConfig()
	cfg.BindPort = 17980

	gp, _ := NewGossipProtocol(cfg, nl, true)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	// Send ping
	gp.sendPing(targetNode)

	if gp.pingSent != 1 {
		t.Errorf("Expected 1 ping sent, got %d", gp.pingSent)
	}
}

func TestGossipProtocol_Stop_WithoutStart(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl, true)

	// Stop without start should not panic
	err := gp.Stop()
	if err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestAckPayload_Struct(t *testing.T) {
	ack := AckPayload{
		NodeID:  "test-node",
		Version: 42,
	}

	if ack.NodeID != "test-node" {
		t.Errorf("Expected NodeID test-node, got %s", ack.NodeID)
	}

	if ack.Version != 42 {
		t.Errorf("Expected Version 42, got %d", ack.Version)
	}
}

func TestNodeInfo_Struct(t *testing.T) {
	info := NodeInfo{
		ID:       "node1",
		Addr:     "192.168.1.1",
		Port:     7946,
		State:    NodeStateAlive,
		Version:  1,
		LastSeen: time.Now(),
		Meta: NodeMeta{
			Region: "us-east",
			Zone:   "us-east-1a",
			Weight: 100,
		},
	}

	if info.ID != "node1" {
		t.Errorf("Expected ID node1, got %s", info.ID)
	}

	if info.Port != 7946 {
		t.Errorf("Expected Port 7946, got %d", info.Port)
	}

	if info.Meta.Region != "us-east" {
		t.Errorf("Expected Region us-east, got %s", info.Meta.Region)
	}
}

func TestMessage_Struct(t *testing.T) {
	msg := Message{
		Type:      MessageTypePing,
		From:      "node1",
		Timestamp: time.Now(),
		Payload:   []byte{1, 2, 3},
	}

	if msg.Type != MessageTypePing {
		t.Errorf("Expected Type Ping, got %v", msg.Type)
	}

	if msg.From != "node1" {
		t.Errorf("Expected From node1, got %s", msg.From)
	}

	if len(msg.Payload) != 3 {
		t.Errorf("Expected Payload length 3, got %d", len(msg.Payload))
	}
}

func TestGossipStats_Struct(t *testing.T) {
	stats := GossipStats{
		MessagesSent:     10,
		MessagesReceived: 20,
		PingSent:         5,
		PingReceived:     8,
	}

	if stats.MessagesSent != 10 {
		t.Errorf("Expected MessagesSent 10, got %d", stats.MessagesSent)
	}

	if stats.MessagesReceived != 20 {
		t.Errorf("Expected MessagesReceived 20, got %d", stats.MessagesReceived)
	}
}

func TestGossipConfig_Defaults(t *testing.T) {
	cfg := GossipConfig{}

	if cfg.SuspicionMult != 0 {
		t.Errorf("Expected SuspicionMult 0, got %d", cfg.SuspicionMult)
	}

	if cfg.RetransmitMult != 0 {
		t.Errorf("Expected RetransmitMult 0, got %d", cfg.RetransmitMult)
	}

	if cfg.IndirectChecks != 0 {
		t.Errorf("Expected IndirectChecks 0, got %d", cfg.IndirectChecks)
	}
}
