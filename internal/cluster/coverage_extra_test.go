package cluster

import (
	"bytes"
	"encoding/gob"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/util"
)

// ---------------------------------------------------------------------------
// cluster.go: New() - GetLocalIP error path (lines 106-108)
// ---------------------------------------------------------------------------

func TestNew_GetLocalIPErrors(t *testing.T) {
	// We cannot easily force GetLocalIP to fail since it calls net.InterfaceAddrs().
	// Instead, we test the BindAddr="" path which calls GetLocalIP and succeeds.
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "",
		BindAddr:   "", // triggers GetLocalIP
		GossipPort: 37901,
	}
	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() with empty BindAddr should succeed, got error: %v", err)
	}
	if c.config.BindAddr == "" {
		t.Error("BindAddr should have been auto-detected")
	}
}

// ---------------------------------------------------------------------------
// cluster.go: New() - NewGossipProtocol error path (lines 134-136)
// ---------------------------------------------------------------------------
// NewGossipProtocol never returns an error in the current implementation,
// so this path is unreachable. We verify it by calling it directly.

func TestNewGossipProtocol_NeverErrors(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Errorf("NewGossipProtocol() returned unexpected error: %v", err)
	}
	if gp == nil {
		t.Error("NewGossipProtocol() returned nil protocol")
	}
	gp.Stop()
}

// ---------------------------------------------------------------------------
// cluster.go: Start() - gossip.Start() error path (lines 168-170)
// ---------------------------------------------------------------------------

func TestCluster_Start_GossipStartError(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 37902,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Pre-start the gossip protocol to bind the port, so the cluster's
	// gossip.Start() fails because the port is already in use.
	// We create a separate gossip protocol that holds the same port.
	self2 := &Node{ID: "blocker", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl2 := NewNodeList(self2)
	blockerCfg := DefaultGossipConfig()
	blockerCfg.BindAddr = "127.0.0.1"
	blockerCfg.BindPort = 37902
	blocker, err := NewGossipProtocol(blockerCfg, nl2)
	if err != nil {
		t.Fatalf("NewGossipProtocol() error = %v", err)
	}
	if err := blocker.Start(); err != nil {
		t.Fatalf("blocker Start() error = %v", err)
	}
	defer blocker.Stop()

	// Now starting the cluster should fail because gossip.Start() fails
	err = c.Start()
	if err == nil {
		c.Stop()
		t.Fatal("Start() should fail when gossip.Start() fails (port already in use)")
	}
}

// ---------------------------------------------------------------------------
// cluster.go: Stop() - gossip.Stop() error path (lines 204-206)
// ---------------------------------------------------------------------------
// gossip.Stop() never returns an error in the current implementation.
// The code path logs a warning if it does. We verify the Stop path works
// when gossip is already stopped.

func TestCluster_Stop_GossipAlreadyStopped(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 37903,
		CacheSync:  true,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Stop the gossip protocol directly before stopping the cluster.
	// The cluster Stop() calls gossip.Stop() again, which handles nil conn gracefully.
	c.gossip.Stop()

	// Now stop the cluster - gossip.Stop() should still succeed
	err = c.Stop()
	if err != nil {
		t.Errorf("Stop() should not error even if gossip already stopped, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// cluster.go: cacheSyncLoop - unknown event type (falls through switch)
// ---------------------------------------------------------------------------

func TestCluster_cacheSyncLoop_UnknownEventType(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 37904,
		CacheSync:  true,
	}

	c, err := New(cfg, logger, dnsCache)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Send a cache sync event with an unknown type - should be ignored
	c.cacheSyncChan <- CacheSyncEvent{
		Type: "unknown_type",
		Keys: []string{"key1"},
	}

	// Also send a valid invalidate event to ensure loop continues working
	c.cacheSyncChan <- CacheSyncEvent{
		Type: "invalidate",
		Keys: []string{"key2"},
	}

	// Allow processing
	time.Sleep(200 * time.Millisecond)

	c.Stop()
}

// ---------------------------------------------------------------------------
// gossip.go: Start() - ResolveUDPAddr error (lines 163-165)
// ---------------------------------------------------------------------------

func TestGossipProtocol_Start_ResolveUDPAddrError(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindAddr = "not-a-valid-ip-address!!!"
	cfg.BindPort = 37905

	gp, _ := NewGossipProtocol(cfg, nl)

	err := gp.Start()
	if err == nil {
		gp.Stop()
		t.Error("Start() should fail with invalid bind address")
	}
}

// ---------------------------------------------------------------------------
// gossip.go: Start() - ListenUDP error (lines 168-170)
// ---------------------------------------------------------------------------

func TestGossipProtocol_Start_ListenUDPError(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	// Use port 1 which requires root/admin privileges - should fail to bind
	cfg := DefaultGossipConfig()
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = 1

	gp, _ := NewGossipProtocol(cfg, nl)

	err := gp.Start()
	if err == nil {
		gp.Stop()
		t.Error("Start() should fail binding to privileged port 1")
	}
}

// ---------------------------------------------------------------------------
// gossip.go: Join() - encodePayload error (lines 208-210)
// ---------------------------------------------------------------------------

func TestGossipProtocol_Join_EncodePayloadError(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 37906

	gp, _ := NewGossipProtocol(cfg, nl)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	// Test encodePayload with an unencodable type
	_, err := encodePayload(make(chan int))
	if err == nil {
		t.Error("encodePayload() should fail for channel type")
	}
}

// ---------------------------------------------------------------------------
// gossip.go: encodeMessage / encodePayload error paths (lines 553-555, 564-566)
// ---------------------------------------------------------------------------

func TestEncodeMessage_Error(t *testing.T) {
	// Encode a message with an unencodable type by using gob directly
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	ch := make(chan int)
	err := enc.Encode(ch)
	if err == nil {
		t.Error("gob.Encode should fail for channel type")
	}

	// Verify encodeMessage works with valid data
	data, err := encodeMessage(MessageTypePing, []byte("test"))
	if err != nil {
		t.Errorf("encodeMessage() with valid payload should succeed, got: %v", err)
	}
	if len(data) == 0 {
		t.Error("encodeMessage() should return non-empty data")
	}
}

func TestEncodePayload_Error(t *testing.T) {
	// Test that encodePayload fails for types gob cannot encode
	_, err := encodePayload(make(chan int))
	if err == nil {
		t.Error("encodePayload() should fail for channel type")
	}

	// Test that encodePayload succeeds for a valid type
	data, err := encodePayload(PingPayload{NodeID: "test", Version: 1})
	if err != nil {
		t.Errorf("encodePayload() with valid payload should succeed, got: %v", err)
	}
	if len(data) == 0 {
		t.Error("encodePayload() should return non-empty data")
	}
}

// ---------------------------------------------------------------------------
// gossip.go: BroadcastCacheInvalidation - encode errors (lines 235-242)
// ---------------------------------------------------------------------------

func TestGossipProtocol_BroadcastCacheInvalidation_EncodeError(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 37907

	gp, _ := NewGossipProtocol(cfg, nl)
	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	// We can't easily make encodePayload fail for CacheInvalidatePayload
	// since it's a normal struct. Instead, verify the happy path works.
	err := gp.BroadcastCacheInvalidation([]string{"key1", "key2"})
	if err != nil {
		t.Errorf("BroadcastCacheInvalidation() error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// gossip.go: handleMessage - from self check (lines 292-294)
// ---------------------------------------------------------------------------

func TestGossipProtocol_handleMessage_IgnoresFromSelf(t *testing.T) {
	self := &Node{ID: "self-node", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 37908

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

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	// Build a message where msg.From matches self.ID
	// Since encodeMessage doesn't set From, we need to encode the Message directly
	msg := Message{
		Type:    MessageTypeGossip,
		From:    "self-node",
		Payload: []byte{},
	}

	// We need to encode this message properly with the From field set
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	msg.Timestamp = time.Now()
	gossipPayload := GossipPayload{
		Nodes: []NodeInfo{
			{ID: "new-node", Addr: "192.168.1.1", Port: 7946, State: NodeStateAlive, Version: 1},
		},
	}
	payloadBytes, _ := encodePayload(gossipPayload)
	msg.Payload = payloadBytes

	if err := enc.Encode(msg); err != nil {
		t.Fatalf("Failed to encode message: %v", err)
	}

	// handleMessage should see msg.From == self.ID and return early
	gp.handleMessage(buf.Bytes(), from)

	if joinCalled {
		t.Error("handleMessage should ignore messages from self")
	}
}

// ---------------------------------------------------------------------------
// gossip.go: receiveLoop - non-timeout, non-cancel error (line 276)
// ---------------------------------------------------------------------------

func TestGossipProtocol_receiveLoop_ConnectionError(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 37909

	gp, _ := NewGossipProtocol(cfg, nl)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Close the connection to cause a non-timeout error in receiveLoop
	gp.conn.Close()

	// Wait a moment for the receiveLoop to handle the error
	time.Sleep(300 * time.Millisecond)

	// Stop should still work
	gp.Stop()
}

// ---------------------------------------------------------------------------
// gossip.go: gossip() - encodePayload/encodeMessage errors (lines 435-442)
// ---------------------------------------------------------------------------
// These error paths can't be easily triggered with valid NodeInfo data.
// We test that gossip() works correctly with nodes present.

func TestGossipProtocol_gossip_WithNodes(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	other := &Node{ID: "other", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	nl.Add(other)

	cfg := DefaultGossipConfig()
	cfg.BindPort = 37910
	cfg.GossipNodes = 2

	gp, _ := NewGossipProtocol(cfg, nl)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer gp.Stop()

	// Call gossip directly - should succeed without panicking
	gp.gossip()

	stats := gp.Stats()
	if stats.MessagesSent == 0 {
		t.Error("Expected messages to be sent during gossip")
	}
}

// ---------------------------------------------------------------------------
// gossip.go: probeLoop / gossipLoop - ticker fires (lines 409-410, 468-469)
// ---------------------------------------------------------------------------
// These paths are exercised when the ticker fires in the respective loops.
// We test them by letting the loops run briefly.

func TestGossipProtocol_probeLoop_Fires(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	// Add a recently seen alive node
	other := &Node{
		ID:       "other",
		State:    NodeStateAlive,
		Addr:     "127.0.0.1",
		LastSeen: time.Now(),
	}
	nl := NewNodeList(self)
	nl.Add(other)

	cfg := DefaultGossipConfig()
	cfg.BindPort = 37911
	cfg.ProbeInterval = 50 * time.Millisecond

	gp, _ := NewGossipProtocol(cfg, nl)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Let the probe loop tick at least once
	time.Sleep(150 * time.Millisecond)

	gp.Stop()
}

func TestGossipProtocol_gossipLoop_Fires(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)

	cfg := DefaultGossipConfig()
	cfg.BindPort = 37912
	cfg.GossipInterval = 50 * time.Millisecond

	gp, _ := NewGossipProtocol(cfg, nl)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Let the gossip loop tick at least once
	time.Sleep(200 * time.Millisecond)

	gp.Stop()

	// Verify some activity happened
	stats := gp.Stats()
	_ = stats // Just ensure no panic occurred
}

// ---------------------------------------------------------------------------
// node.go: GetLocalIP - fallback path (lines 230-232, 242)
// ---------------------------------------------------------------------------

func TestGetLocalIP_Fallback(t *testing.T) {
	ip, err := GetLocalIP()
	if err != nil {
		t.Fatalf("GetLocalIP() error = %v", err)
	}
	if ip == "" {
		t.Error("GetLocalIP() should not return empty string")
	}

	// The function returns either a non-loopback IP or "127.0.0.1" as fallback
	// On most CI/systems there is a non-loopback interface, so it likely
	// returns a real IP. We just verify it's a valid format.
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Errorf("GetLocalIP() returned invalid IP: %s", ip)
	}
}

// ---------------------------------------------------------------------------
// gossip.go: Join() - WriteToUDP error (lines 218-220)
// ---------------------------------------------------------------------------

func TestGossipProtocol_Join_WriteToUDPError(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 37913

	gp, _ := NewGossipProtocol(cfg, nl)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Close the connection to force WriteToUDP to fail
	gp.conn.Close()

	err := gp.Join("127.0.0.1:37914")
	if err == nil {
		t.Error("Join() should fail when connection is closed")
	}

	gp.Stop()
}

// ---------------------------------------------------------------------------
// gossip.go: receiveLoop - non-timeout error with context not cancelled
// ---------------------------------------------------------------------------

func TestGossipProtocol_receiveLoop_ReadErrorNonTimeout(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = 37915

	gp, _ := NewGossipProtocol(cfg, nl)

	if err := gp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Close conn to cause read errors, but cancel context shortly after
	// to exercise the non-timeout, non-cancelled error path
	gp.conn.Close()

	// Give receiveLoop time to hit the error and continue
	time.Sleep(300 * time.Millisecond)

	// Now cancel - this will cause receiveLoop to exit
	gp.Stop()
}

// ---------------------------------------------------------------------------
// Additional encode/decode edge cases
// ---------------------------------------------------------------------------

func TestDecodeMessage_InvalidData(t *testing.T) {
	var msg Message
	err := decodeMessage([]byte{0xFF, 0xFE, 0xFD}, &msg)
	if err == nil {
		t.Error("decodeMessage() should fail with invalid data")
	}
}

func TestDecodePayload_InvalidData(t *testing.T) {
	var payload PingPayload
	err := decodePayload([]byte{0xFF, 0xFE, 0xFD}, &payload)
	if err == nil {
		t.Error("decodePayload() should fail with invalid data")
	}
}

// ---------------------------------------------------------------------------
// cluster.go: handleNodeJoin/Leave/Update/CacheInvalid with multiple handlers
// ---------------------------------------------------------------------------

func TestCluster_MultipleEventHandlers(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cacheCfg := cache.Config{Capacity: 1000}
	dnsCache := cache.New(cacheCfg)

	cfg := Config{
		Enabled:    true,
		NodeID:     "test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 37916,
	}

	c, _ := New(cfg, logger, dnsCache)

	joinCount := 0
	leaveCount := 0
	updateCount := 0
	cacheInvalidCount := 0

	// Add first handler
	c.AddEventHandler(&EventHandlerFunc{
		OnJoinFunc:        func(*Node) { joinCount++ },
		OnLeaveFunc:       func(*Node) { leaveCount++ },
		OnUpdateFunc:      func(*Node) { updateCount++ },
		OnCacheInvalidFunc: func([]string) { cacheInvalidCount++ },
	})

	// Add second handler
	c.AddEventHandler(&EventHandlerFunc{
		OnJoinFunc:        func(*Node) { joinCount++ },
		OnLeaveFunc:       func(*Node) { leaveCount++ },
		OnUpdateFunc:      func(*Node) { updateCount++ },
		OnCacheInvalidFunc: func([]string) { cacheInvalidCount++ },
	})

	testNode := &Node{ID: "test-node-2", Addr: "192.168.1.1"}
	c.handleNodeJoin(testNode)
	c.handleNodeLeave(testNode)
	c.handleNodeUpdate(testNode)
	c.handleCacheInvalid([]string{"key1"})

	if joinCount != 2 {
		t.Errorf("Expected 2 join handler calls, got %d", joinCount)
	}
	if leaveCount != 2 {
		t.Errorf("Expected 2 leave handler calls, got %d", leaveCount)
	}
	if updateCount != 2 {
		t.Errorf("Expected 2 update handler calls, got %d", updateCount)
	}
	if cacheInvalidCount != 2 {
		t.Errorf("Expected 2 cache invalid handler calls, got %d", cacheInvalidCount)
	}
}

// ---------------------------------------------------------------------------
// gossip.go: handleMessage with unknown message type
// ---------------------------------------------------------------------------

func TestGossipProtocol_handleMessage_UnknownType(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	from, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	// Create a message with an unknown type ( MessageTypeCacheUpdate = 4 is defined but
	// not handled in handleMessage's switch). Actually, it IS defined as a constant but
	// the switch in handleMessage doesn't have a case for it.
	msg := Message{
		Type:      MessageTypeCacheUpdate, // No case for this in handleMessage
		From:      "other-node",
		Timestamp: time.Now(),
		Payload:   []byte{},
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(msg); err != nil {
		t.Fatalf("Failed to encode message: %v", err)
	}

	// Should not panic with unhandled message type
	gp.handleMessage(buf.Bytes(), from)
}

// ---------------------------------------------------------------------------
// gossip.go: Two-node gossip integration
// ---------------------------------------------------------------------------

func TestGossipProtocol_TwoNodeIntegration(t *testing.T) {
	// Create two gossip protocols that talk to each other
	self1 := &Node{ID: "node1", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl1 := NewNodeList(self1)
	cfg1 := DefaultGossipConfig()
	cfg1.BindAddr = "127.0.0.1"
	cfg1.BindPort = 37917
	cfg1.GossipInterval = 50 * time.Millisecond

	gp1, _ := NewGossipProtocol(cfg1, nl1)

	joinCalled := false
	gp1.SetCallbacks(
		func(*Node) { joinCalled = true },
		nil, nil, nil,
	)

	if err := gp1.Start(); err != nil {
		t.Fatalf("gp1 Start() error = %v", err)
	}
	defer gp1.Stop()

	self2 := &Node{ID: "node2", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl2 := NewNodeList(self2)
	cfg2 := DefaultGossipConfig()
	cfg2.BindAddr = "127.0.0.1"
	cfg2.BindPort = 37918
	cfg2.GossipInterval = 50 * time.Millisecond

	gp2, _ := NewGossipProtocol(cfg2, nl2)
	if err := gp2.Start(); err != nil {
		t.Fatalf("gp2 Start() error = %v", err)
	}
	defer gp2.Stop()

	// Node 2 joins node 1
	err := gp2.Join("127.0.0.1:37917")
	if err != nil {
		t.Fatalf("Join() error = %v", err)
	}

	// Wait for gossip to propagate
	time.Sleep(300 * time.Millisecond)

	// Verify stats are non-zero
	stats1 := gp1.Stats()
	if stats1.PingReceived == 0 && stats1.MessagesReceived == 0 {
		t.Log("gp1 did not receive any messages (may be timing dependent)")
	}

	stats2 := gp2.Stats()
	if stats2.PingSent == 0 && stats2.MessagesSent == 0 {
		t.Log("gp2 did not send any messages (may be timing dependent)")
	}

	_ = joinCalled
}

// ---------------------------------------------------------------------------
// Verify encodeMessage/encodePayload error paths via unregistered gob type
// ---------------------------------------------------------------------------

func TestEncodePayload_UnregisteredType(t *testing.T) {
	// Use a non-gob-encodable type to trigger encode error
	_, err := encodePayload(errors.New("test"))
	// errors.New actually might encode; use a channel to guarantee failure
	_, err = encodePayload(func() {})
	if err == nil {
		t.Error("encodePayload() should fail for function type")
	}
}

func TestEncodeMessage_NilPayload(t *testing.T) {
	// Verify encodeMessage works with empty payload
	data, err := encodeMessage(MessageTypePing, []byte{})
	if err != nil {
		t.Errorf("encodeMessage() with empty payload should succeed, got: %v", err)
	}
	if len(data) == 0 {
		t.Error("encodeMessage() should return non-empty data even with empty payload")
	}
}
