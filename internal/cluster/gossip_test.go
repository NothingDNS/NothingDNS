package cluster

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"sync/atomic"
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

func TestNewGossipProtocolNormalizesInvalidConfig(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := GossipConfig{
		BindPort:       pickFreePort(),
		GossipInterval: -time.Millisecond,
		ProbeInterval:  -time.Second,
		ProbeTimeout:   -time.Second,
		SuspicionMult:  -1,
		RetransmitMult: -1,
		GossipNodes:    -1,
		IndirectChecks: -1,
	}

	gp, err := NewGossipProtocol(cfg, nl, true)
	if err != nil {
		t.Fatalf("NewGossipProtocol() error = %v", err)
	}

	if gp.config.BindAddr != "0.0.0.0" {
		t.Fatalf("BindAddr = %q, want 0.0.0.0", gp.config.BindAddr)
	}
	if gp.config.GossipInterval != 200*time.Millisecond {
		t.Fatalf("GossipInterval = %v, want 200ms", gp.config.GossipInterval)
	}
	if gp.config.ProbeInterval != time.Second {
		t.Fatalf("ProbeInterval = %v, want 1s", gp.config.ProbeInterval)
	}
	if gp.config.ProbeTimeout != 500*time.Millisecond {
		t.Fatalf("ProbeTimeout = %v, want 500ms", gp.config.ProbeTimeout)
	}
	if gp.config.SuspicionMult != 4 {
		t.Fatalf("SuspicionMult = %d, want 4", gp.config.SuspicionMult)
	}
	if gp.config.RetransmitMult != 4 {
		t.Fatalf("RetransmitMult = %d, want 4", gp.config.RetransmitMult)
	}
	if gp.config.GossipNodes != 3 {
		t.Fatalf("GossipNodes = %d, want 3", gp.config.GossipNodes)
	}
	if gp.config.IndirectChecks != 3 {
		t.Fatalf("IndirectChecks = %d, want 3", gp.config.IndirectChecks)
	}
	if gp.config.ProtocolVersion != 1 {
		t.Fatalf("ProtocolVersion = %d, want 1", gp.config.ProtocolVersion)
	}

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := gp.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
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

	// Create an ack message. handleAck now enforces
	// msg.From == ack.NodeID — set both so this represents the
	// legitimate flow (impostor coverage lives in
	// TestGossipProtocol_handleAck_Impostor below).
	ack := AckPayload{
		NodeID:  "other",
		Version: 2,
	}
	ackBytes, _ := encodePayload(ack)
	msg := Message{
		Type:    MessageTypeAck,
		From:    "other",
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

// TestGossipProtocol_handleAck_Impostor guards the fix for the
// impostor reanimation vector: handleAck must reject an Ack whose
// payload claims a different node than the AEAD-authenticated
// msg.From. Without that check, a compromised gossip-keyring peer
// could keep "victim" pinned to NodeStateAlive even after it
// actually died, defeating SWIM failure detection.
func TestGossipProtocol_handleAck_Impostor(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	other := &Node{ID: "other", State: NodeStateSuspect, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	nl.Add(other)

	gp, _ := NewGossipProtocol(DefaultGossipConfig(), nl, true)

	ack := AckPayload{NodeID: "other"}
	ackBytes, _ := encodePayload(ack)
	msg := Message{
		Type:    MessageTypeAck,
		From:    "impostor", // claims to be "other" but isn't
		Payload: ackBytes,
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleAck(msg, from)

	// other should NOT have been reanimated from Suspect to Alive.
	node, ok := nl.Get("other")
	if !ok {
		t.Fatal("Node should exist")
	}
	if node.State == NodeStateAlive {
		t.Errorf("Impostor Ack was accepted: state moved to Alive")
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

	// Create cache invalidate message. handleCacheInvalidate now
	// enforces msg.From == payload.Source — set both so this
	// represents the legitimate flow (impostor coverage lives in
	// TestGossipProtocol_handleCacheInvalidate_Impostor below).
	cachePayload := CacheInvalidatePayload{
		Keys:      []string{"key1", "key2"},
		Source:    "other-node",
		Timestamp: time.Now(),
	}
	payloadBytes, _ := encodePayload(cachePayload)
	msg := Message{
		Type:    MessageTypeCacheInvalidate,
		From:    "other-node",
		Payload: payloadBytes,
	}

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleCacheInvalidate(msg, from)

	if len(cacheInvalidKeys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(cacheInvalidKeys))
	}
}

// TestGossipProtocol_handleCacheInvalidate_Impostor guards the
// chosen-prefix cache-bust path: handleCacheInvalidate must reject
// any CacheInvalidate frame whose payload.Source disagrees with the
// AEAD-authenticated msg.From. Without that check, a compromised
// gossip-keyring peer could spoof Source="victim" and force every
// observer to evict targeted DNS cache entries.
func TestGossipProtocol_handleCacheInvalidate_Impostor(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	gp, _ := NewGossipProtocol(DefaultGossipConfig(), nl, true)

	var called bool
	gp.SetCallbacks(nil, nil, nil, func(keys []string) { called = true }, nil, nil)

	cachePayload := CacheInvalidatePayload{
		Keys:   []string{"bank.com:A"},
		Source: "other-node",
	}
	payloadBytes, _ := encodePayload(cachePayload)
	msg := Message{
		Type:    MessageTypeCacheInvalidate,
		From:    "impostor", // claims Source="other-node" but isn't
		Payload: payloadBytes,
	}
	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	gp.handleCacheInvalidate(msg, from)

	if called {
		t.Errorf("Impostor CacheInvalidate was accepted: callback fired")
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

func TestGossipProtocol_DecodeMessage_ReplayRejected(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 17982

	gp, _ := NewGossipProtocol(cfg, nl, true)
	gp.Start()
	defer gp.Stop()

	// Manually set a sequence for a peer
	gp.sequenceMu.Lock()
	gp.sequences["peer-node"] = 10
	gp.sequenceMu.Unlock()

	// Create a message with sequence <= last seen (replay)
	msg := Message{
		Type:            MessageTypePing,
		From:            "peer-node",
		Timestamp:       time.Now(),
		Payload:         []byte{1, 2, 3},
		ProtocolVersion: 1,
		Sequence:        5, // seq 5 <= last seen 10 → replay
	}

	data, _ := json.Marshal(msg)
	err := gp.decodeMessage(data, &Message{})
	if err == nil {
		t.Error("Expected replay to be rejected, got nil error")
	}
}

func TestGossipProtocol_DecodeMessage_NewSeqAccepted(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 17983

	gp, _ := NewGossipProtocol(cfg, nl, true)
	gp.Start()
	defer gp.Stop()

	// Set high-water mark
	gp.sequenceMu.Lock()
	gp.sequences["peer-node"] = 10
	gp.sequenceMu.Unlock()

	// Create a message with sequence > last seen (new, not replay)
	msg := Message{
		Type:            MessageTypePing,
		From:            "peer-node",
		Timestamp:       time.Now(),
		Payload:         []byte{1, 2, 3},
		ProtocolVersion: 1,
		Sequence:        15, // seq 15 > last seen 10 → accepted
	}

	data, _ := json.Marshal(msg)
	var decoded Message
	err := gp.decodeMessage(data, &decoded)
	if err != nil {
		t.Errorf("Expected message to be accepted, got error: %v", err)
	}

	// Verify high-water mark was updated
	gp.sequenceMu.Lock()
	lastSeq := gp.sequences["peer-node"]
	gp.sequenceMu.Unlock()
	if lastSeq != 15 {
		t.Errorf("Expected high-water mark 15, got %d", lastSeq)
	}
}

func TestGossipProtocol_DecodeMessage_ZeroSeqSkipsCheck(t *testing.T) {
	// ProtocolVersion 0 messages (legacy) have Sequence=0 and skip replay check
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 17984

	gp, _ := NewGossipProtocol(cfg, nl, true)
	gp.Start()
	defer gp.Stop()

	// Set high-water mark
	gp.sequenceMu.Lock()
	gp.sequences["legacy-peer"] = 100
	gp.sequenceMu.Unlock()

	// Legacy message: ProtocolVersion=0, Sequence=0
	msg := Message{
		Type:            MessageTypePing,
		From:            "legacy-peer",
		Timestamp:       time.Now(),
		Payload:         []byte{1, 2, 3},
		ProtocolVersion: 0, // legacy
		Sequence:        0, // zero seq (default for legacy nodes)
	}

	data, _ := json.Marshal(msg)
	var decoded Message
	err := gp.decodeMessage(data, &decoded)
	if err != nil {
		t.Errorf("Expected legacy message to be accepted despite zero seq, got error: %v", err)
	}
}

func TestGossipProtocol_SendMessageRejectsPartialDatagram(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	gp, err := NewGossipProtocol(DefaultGossipConfig(), nl, true)
	if err != nil {
		t.Fatalf("NewGossipProtocol: %v", err)
	}
	conn := &partialGossipUDPConn{maxWrite: 1}
	gp.conn = conn

	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7946}
	err = gp.sendMessage(MessageTypePing, []byte{1, 2, 3}, dst)
	if err != io.ErrShortWrite {
		t.Fatalf("sendMessage error = %v, want %v", err, io.ErrShortWrite)
	}
	if sent := atomic.LoadUint64(&gp.messagesSent); sent != 0 {
		t.Fatalf("messagesSent = %d, want 0 for failed datagram", sent)
	}
	if conn.writes != 1 {
		t.Fatalf("sendMessage should not retry UDP datagrams, got %d writes", conn.writes)
	}
}

type partialGossipUDPConn struct {
	maxWrite int
	writes   int
}

func (c *partialGossipUDPConn) ReadFromUDP([]byte) (int, *net.UDPAddr, error) {
	return 0, nil, io.EOF
}

func (c *partialGossipUDPConn) WriteToUDP(p []byte, _ *net.UDPAddr) (int, error) {
	c.writes++
	if c.maxWrite <= 0 {
		return 0, nil
	}
	if c.maxWrite < len(p) {
		return c.maxWrite, nil
	}
	return len(p), nil
}

func (c *partialGossipUDPConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *partialGossipUDPConn) Close() error {
	return nil
}

func TestGossipProtocol_EncryptedRoundTrip(t *testing.T) {
	// Regression: encrypted gossip previously dropped EVERY message — the
	// sender sealed with an AAD while the receiver tried a nil-AAD decrypt
	// first, which can never open an AAD-sealed ciphertext. A message encrypted
	// the way sendMessage does it must now decode successfully with fields intact.
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 17986
	cfg.EncryptionKey = make([]byte, 32)
	rand.Read(cfg.EncryptionKey)

	gp, _ := NewGossipProtocol(cfg, nl, true)
	gp.Start()
	defer gp.Stop()

	msg := Message{
		Type:            MessageTypePing,
		From:            "peer-node",
		Timestamp:       time.Now(),
		Payload:         []byte{1, 2, 3},
		ProtocolVersion: cfg.ProtocolVersion,
		Sequence:        7,
	}
	data, _ := json.Marshal(msg)
	encrypted, err := gp.encrypt(data) // same path sendMessage now uses
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(encrypted) <= len(data) {
		t.Fatalf("ciphertext should include nonce+tag, got %d <= %d", len(encrypted), len(data))
	}

	var decoded Message
	if err := gp.decodeMessage(encrypted, &decoded); err != nil {
		t.Fatalf("decodeMessage rejected a validly-encrypted message: %v", err)
	}
	if decoded.From != "peer-node" || decoded.Type != MessageTypePing || decoded.Sequence != 7 {
		t.Fatalf("round-trip corrupted fields: %+v", decoded)
	}

	// A tampered ciphertext must still be rejected.
	bad := append([]byte(nil), encrypted...)
	bad[len(bad)-1] ^= 0xff
	if err := gp.decodeMessage(bad, &Message{}); err == nil {
		t.Error("tampered ciphertext was accepted")
	}
}

func TestGossipProtocol_DecodeMessage_AADBindingFailure(t *testing.T) {
	// This test verifies that decodeMessage with encryption rejects wrong AAD.
	// We test the AAD verification path by checking that decryptWithAAD is called.
	// Since we can't easily inject a wrong AAD without modifying the protocol,
	// we verify the code path exists by checking error handling.
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 17985
	cfg.EncryptionKey = make([]byte, 32) // 32-byte key for AES-256
	rand.Read(cfg.EncryptionKey)

	gp, _ := NewGossipProtocol(cfg, nl, true)
	gp.Start()
	defer gp.Stop()

	// Create a message and encrypt it
	msg := Message{
		Type:            MessageTypePing,
		From:            "peer-node",
		Timestamp:       time.Now(),
		Payload:         []byte{1, 2, 3},
		ProtocolVersion: 1,
		Sequence:        1,
	}
	data, _ := json.Marshal(msg)
	encrypted, _ := gp.encryptWithAAD(data, []byte("wrong-aad"))

	var decoded Message
	err := gp.decodeMessage(encrypted, &decoded)
	// decryptWithAAD with wrong AAD should fail
	if err == nil {
		t.Error("Expected AAD verification to fail with wrong AAD, got nil")
	}
}

type recordingGossipUDPConn struct {
	lastAddr *net.UDPAddr
}

func (c *recordingGossipUDPConn) ReadFromUDP([]byte) (int, *net.UDPAddr, error) {
	return 0, nil, io.EOF
}

func (c *recordingGossipUDPConn) WriteToUDP(p []byte, addr *net.UDPAddr) (int, error) {
	copy := *addr
	c.lastAddr = &copy
	return len(p), nil
}

func (c *recordingGossipUDPConn) SetReadDeadline(time.Time) error { return nil }
func (c *recordingGossipUDPConn) Close() error                    { return nil }

func TestGossipProtocol_UsesAdvertisedPeerPort(t *testing.T) {
	const (
		localPort = 17990
		peerPort  = 17991
	)

	newProtocol := func() (*GossipProtocol, *Node) {
		self := &Node{ID: "self", Addr: "127.0.0.1", Port: localPort, State: NodeStateAlive}
		peer := &Node{ID: "peer", Addr: "127.0.0.1", Port: peerPort, State: NodeStateAlive}
		nodes := NewNodeList(self)
		nodes.Add(peer)
		cfg := DefaultGossipConfig()
		cfg.BindPort = localPort
		cfg.GossipNodes = 1
		gp, err := NewGossipProtocol(cfg, nodes, true)
		if err != nil {
			t.Fatalf("NewGossipProtocol: %v", err)
		}
		return gp, peer
	}

	for _, test := range []struct {
		name string
		send func(*GossipProtocol, *Node)
	}{
		{name: "gossip", send: func(gp *GossipProtocol, _ *Node) { gp.gossip() }},
		{name: "ping", send: func(gp *GossipProtocol, peer *Node) { gp.sendPing(peer) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			gp, peer := newProtocol()
			conn := &recordingGossipUDPConn{}
			gp.conn = conn

			test.send(gp, peer)
			if conn.lastAddr == nil {
				t.Fatal("expected a UDP datagram")
			}
			if conn.lastAddr.Port != peerPort {
				t.Fatalf("destination port = %d, want advertised peer port %d", conn.lastAddr.Port, peerPort)
			}
		})
	}
}

func TestGossipProtocol_BroadcastCacheInvalidationUsesPeerPort(t *testing.T) {
	reservePort := func() int {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("reserve UDP port: %v", err)
		}
		defer conn.Close()
		return conn.LocalAddr().(*net.UDPAddr).Port
	}

	senderPort := reservePort()
	receiverPort := reservePort()
	if senderPort == receiverPort {
		t.Fatal("reserved the same UDP port for both gossip nodes")
	}

	senderSelf := &Node{ID: "sender", Addr: "127.0.0.1", Port: senderPort, State: NodeStateAlive}
	receiverSelf := &Node{ID: "receiver", Addr: "127.0.0.1", Port: receiverPort, State: NodeStateAlive}

	newProtocol := func(self, peer *Node, port int) *GossipProtocol {
		nodes := NewNodeList(self)
		nodes.Add(peer)
		cfg := DefaultGossipConfig()
		cfg.BindAddr = "127.0.0.1"
		cfg.BindPort = port
		cfg.GossipInterval = time.Hour
		cfg.ProbeInterval = time.Hour
		gp, err := NewGossipProtocol(cfg, nodes, true)
		if err != nil {
			t.Fatalf("NewGossipProtocol: %v", err)
		}
		return gp
	}

	sender := newProtocol(senderSelf, receiverSelf, senderPort)
	receiver := newProtocol(receiverSelf, senderSelf, receiverPort)
	received := make(chan []string, 1)
	receiver.SetCallbacks(nil, nil, nil, func(keys []string) { received <- keys }, nil, nil)

	if err := receiver.Start(); err != nil {
		t.Fatalf("start receiver: %v", err)
	}
	defer receiver.Stop()
	if err := sender.Start(); err != nil {
		t.Fatalf("start sender: %v", err)
	}
	defer sender.Stop()

	if err := sender.BroadcastCacheInvalidation([]string{"cache-key"}); err != nil {
		t.Fatalf("BroadcastCacheInvalidation: %v", err)
	}
	select {
	case keys := <-received:
		if len(keys) != 1 || keys[0] != "cache-key" {
			t.Fatalf("received keys = %v, want [cache-key]", keys)
		}
	case <-time.After(time.Second):
		t.Fatalf("cache invalidation did not arrive at peer UDP port %d", receiverPort)
	}
}
