package cluster

import (
	"net"
	"testing"
	"time"
)

// pickFreePort returns a random available TCP port.
func pickFreePort() int {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// ---------------------------------------------------------------------------
// handleElection tests
// ---------------------------------------------------------------------------

func TestHandleElection_ThisNodeIsProposedLeader(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	// Election that proposes this node as leader
	election := ElectionPayload{
		ProposedLeader: "node-A",
		Priority:       1,
		Term:           5,
	}
	payload, _ := encodePayload(election)
	msg := Message{
		Type:    MessageTypeElection,
		From:    "other-node",
		Payload: payload,
	}

	gp.handleElection(msg, &net.UDPAddr{})

	gp.leaderMu.RLock()
	isLeader := gp.isLeader
	leader := gp.currentLeader
	term := gp.leaderTerm
	gp.leaderMu.RUnlock()

	if !isLeader {
		t.Error("expected this node to be the leader")
	}
	if leader != "node-A" {
		t.Errorf("expected currentLeader=node-A, got %s", leader)
	}
	if term != 5 {
		t.Errorf("expected leaderTerm=5, got %d", term)
	}
}

func TestHandleElection_AnotherNodeProposed(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	// Election proposing a different node
	election := ElectionPayload{
		ProposedLeader: "node-B",
		Priority:       1,
		Term:           3,
	}
	payload, _ := encodePayload(election)
	msg := Message{
		Type:    MessageTypeElection,
		From:    "node-B",
		Payload: payload,
	}

	gp.handleElection(msg, &net.UDPAddr{})

	gp.leaderMu.RLock()
	electionTerm := gp.electionTerm
	gp.leaderMu.RUnlock()

	// Should have bumped electionTerm above the received term
	if electionTerm <= 3 {
		t.Errorf("expected electionTerm > 3, got %d", electionTerm)
	}
}

func TestHandleElection_InvalidPayload(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	msg := Message{
		Type:    MessageTypeElection,
		From:    "node-B",
		Payload: []byte("invalid-json"),
	}

	// Should not panic
	gp.handleElection(msg, &net.UDPAddr{})
}

// ---------------------------------------------------------------------------
// handleLeader tests
// ---------------------------------------------------------------------------

func TestHandleLeader_AcceptHigherTerm(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	// Set initial state as if we were leader at term 1
	gp.leaderMu.Lock()
	gp.isLeader = true
	gp.leaderTerm = 1
	gp.leaderMu.Unlock()

	leader := LeaderPayload{
		LeaderID:   "node-B",
		LeaderAddr: "10.0.0.2",
		Term:       5,
	}
	payload, _ := encodePayload(leader)
	msg := Message{
		Type:    MessageTypeLeader,
		From:    "node-B",
		Payload: payload,
	}

	gp.handleLeader(msg, &net.UDPAddr{})

	gp.leaderMu.RLock()
	isLeader := gp.isLeader
	currentLeader := gp.currentLeader
	term := gp.leaderTerm
	gp.leaderMu.RUnlock()

	if isLeader {
		t.Error("expected isLeader=false after accepting higher-term leader")
	}
	if currentLeader != "node-B" {
		t.Errorf("expected currentLeader=node-B, got %s", currentLeader)
	}
	if term != 5 {
		t.Errorf("expected leaderTerm=5, got %d", term)
	}
}

func TestHandleLeader_RejectLowerTerm(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	// Set our term higher than incoming
	gp.leaderMu.Lock()
	gp.leaderTerm = 10
	gp.currentLeader = "node-A"
	gp.isLeader = true
	gp.leaderMu.Unlock()

	leader := LeaderPayload{
		LeaderID:   "node-B",
		LeaderAddr: "10.0.0.2",
		Term:       3, // lower than our 10
	}
	payload, _ := encodePayload(leader)
	msg := Message{
		Type:    MessageTypeLeader,
		From:    "node-B",
		Payload: payload,
	}

	gp.handleLeader(msg, &net.UDPAddr{})

	gp.leaderMu.RLock()
	currentLeader := gp.currentLeader
	term := gp.leaderTerm
	gp.leaderMu.RUnlock()

	if currentLeader != "node-A" {
		t.Errorf("should reject lower-term leader, got currentLeader=%s", currentLeader)
	}
	if term != 10 {
		t.Errorf("leaderTerm should remain 10, got %d", term)
	}
}

func TestHandleLeader_InvalidPayload(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	msg := Message{
		Type:    MessageTypeLeader,
		From:    "node-B",
		Payload: []byte("garbage"),
	}

	// Should not panic
	gp.handleLeader(msg, &net.UDPAddr{})
}

// ---------------------------------------------------------------------------
// handleHeartbeat tests
// ---------------------------------------------------------------------------

func TestHandleHeartbeat_RefreshesLastHeartbeat(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	// Set up a known leader
	gp.leaderMu.Lock()
	gp.currentLeader = "node-B"
	gp.leaderTerm = 5
	gp.lastHeartbeat = time.Now().Add(-10 * time.Second) // old heartbeat
	gp.leaderMu.Unlock()

	heartbeat := LeaderHeartbeatPayload{
		LeaderID: "node-B",
		Term:     5,
	}
	payload, _ := encodePayload(heartbeat)
	msg := Message{
		Type:    MessageTypeHeartbeat,
		From:    "node-B",
		Payload: payload,
	}

	gp.handleHeartbeat(msg, &net.UDPAddr{})

	gp.leaderMu.RLock()
	lastHb := gp.lastHeartbeat
	gp.leaderMu.RUnlock()

	if time.Since(lastHb) > time.Second {
		t.Error("expected lastHeartbeat to be refreshed to near-now")
	}
}

func TestHandleHeartbeat_WrongLeaderIgnored(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	oldTime := time.Now().Add(-10 * time.Second)
	gp.leaderMu.Lock()
	gp.currentLeader = "node-B"
	gp.leaderTerm = 5
	gp.lastHeartbeat = oldTime
	gp.leaderMu.Unlock()

	// Heartbeat from a different leader ID
	heartbeat := LeaderHeartbeatPayload{
		LeaderID: "node-C", // doesn't match currentLeader
		Term:     5,
	}
	payload, _ := encodePayload(heartbeat)
	msg := Message{
		Type:    MessageTypeHeartbeat,
		From:    "node-C",
		Payload: payload,
	}

	gp.handleHeartbeat(msg, &net.UDPAddr{})

	gp.leaderMu.RLock()
	lastHb := gp.lastHeartbeat
	gp.leaderMu.RUnlock()

	if lastHb != oldTime {
		t.Error("expected lastHeartbeat to stay unchanged for wrong leader")
	}
}

func TestHandleHeartbeat_LowerTermIgnored(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	oldTime := time.Now().Add(-10 * time.Second)
	gp.leaderMu.Lock()
	gp.currentLeader = "node-B"
	gp.leaderTerm = 10
	gp.lastHeartbeat = oldTime
	gp.leaderMu.Unlock()

	heartbeat := LeaderHeartbeatPayload{
		LeaderID: "node-B",
		Term:     3, // lower than our term
	}
	payload, _ := encodePayload(heartbeat)
	msg := Message{
		Type:    MessageTypeHeartbeat,
		From:    "node-B",
		Payload: payload,
	}

	gp.handleHeartbeat(msg, &net.UDPAddr{})

	gp.leaderMu.RLock()
	lastHb := gp.lastHeartbeat
	gp.leaderMu.RUnlock()

	if lastHb != oldTime {
		t.Error("expected lastHeartbeat to stay unchanged for lower-term heartbeat")
	}
}

// ---------------------------------------------------------------------------
// handleZoneUpdate tests
// ---------------------------------------------------------------------------

func TestHandleZoneUpdate_FollowerInvokesCallback(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	// Set up as follower with a known leader
	gp.leaderMu.Lock()
	gp.isLeader = false
	gp.currentLeader = "node-B"
	gp.leaderMu.Unlock()

	var received ZoneUpdatePayload
	gp.SetCallbacks(nil, nil, nil, nil, func(p ZoneUpdatePayload) {
		received = p
	}, nil)

	zoneUpdate := ZoneUpdatePayload{
		ZoneName: "example.com",
		Action:   "add",
		Serial:   2024010101,
		Records: []ZoneRecord{
			{Name: "www.example.com", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		},
	}
	payload, _ := encodePayload(zoneUpdate)
	msg := Message{
		Type:    MessageTypeZoneUpdate,
		From:    "node-B",
		Payload: payload,
	}

	gp.handleZoneUpdate(msg, &net.UDPAddr{})

	if received.ZoneName != "example.com" {
		t.Errorf("expected ZoneName=example.com, got %s", received.ZoneName)
	}
	if received.Action != "add" {
		t.Errorf("expected Action=add, got %s", received.Action)
	}
	if received.Serial != 2024010101 {
		t.Errorf("expected Serial=2024010101, got %d", received.Serial)
	}
	if len(received.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(received.Records))
	}
	if received.Records[0].RData != "1.2.3.4" {
		t.Errorf("expected RData=1.2.3.4, got %s", received.Records[0].RData)
	}
}

func TestHandleZoneUpdate_LeaderIgnores(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	// Set up as leader
	gp.leaderMu.Lock()
	gp.isLeader = true
	gp.currentLeader = "node-A"
	gp.leaderMu.Unlock()

	called := false
	gp.SetCallbacks(nil, nil, nil, nil, func(ZoneUpdatePayload) {
		called = true
	}, nil)

	zoneUpdate := ZoneUpdatePayload{ZoneName: "example.com", Action: "add"}
	payload, _ := encodePayload(zoneUpdate)
	msg := Message{
		Type:    MessageTypeZoneUpdate,
		From:    "node-B",
		Payload: payload,
	}

	gp.handleZoneUpdate(msg, &net.UDPAddr{})

	if called {
		t.Error("leader should ignore zone updates from other nodes")
	}
}

func TestHandleZoneUpdate_NoLeader_Ignores(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	// No leader set
	gp.leaderMu.Lock()
	gp.isLeader = false
	gp.currentLeader = ""
	gp.leaderMu.Unlock()

	called := false
	gp.SetCallbacks(nil, nil, nil, nil, func(ZoneUpdatePayload) {
		called = true
	}, nil)

	zoneUpdate := ZoneUpdatePayload{ZoneName: "example.com"}
	payload, _ := encodePayload(zoneUpdate)
	msg := Message{
		Type:    MessageTypeZoneUpdate,
		From:    "node-B",
		Payload: payload,
	}

	gp.handleZoneUpdate(msg, &net.UDPAddr{})

	if called {
		t.Error("should ignore zone update when no leader is known")
	}
}


func TestHandleZoneUpdate_InvalidPayload(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	gp.leaderMu.Lock()
	gp.isLeader = false
	gp.currentLeader = "node-B"
	gp.leaderMu.Unlock()

	called := false
	gp.SetCallbacks(nil, nil, nil, nil, func(ZoneUpdatePayload) {
		called = true
	}, nil)

	msg := Message{
		Type:    MessageTypeZoneUpdate,
		From:    "node-B",
		Payload: []byte("invalid"),
	}

	gp.handleZoneUpdate(msg, &net.UDPAddr{})

	if called {
		t.Error("callback should not be called for invalid payload")
	}
}

// ---------------------------------------------------------------------------
// handleConfigSync tests
// ---------------------------------------------------------------------------

func TestHandleConfigSync_FollowerInvokesCallback(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	gp.leaderMu.Lock()
	gp.isLeader = false
	gp.currentLeader = "node-B"
	gp.leaderMu.Unlock()

	var received ConfigSyncPayload
	gp.SetCallbacks(nil, nil, nil, nil, nil, func(p ConfigSyncPayload) {
		received = p
	})

	configSync := ConfigSyncPayload{
		ConfigSHA256: "abc123",
		NodeID:       "node-B",
		ClusterConfig: &ClusterConfigJSON{
			Enabled:  true,
			NodeID:   "node-B",
			BindAddr: "0.0.0.0",
		},
	}
	payload, _ := encodePayload(configSync)
	msg := Message{
		Type:    MessageTypeConfigSync,
		From:    "node-B",
		Payload: payload,
	}

	gp.handleConfigSync(msg, &net.UDPAddr{})

	if received.ConfigSHA256 != "abc123" {
		t.Errorf("expected ConfigSHA256=abc123, got %s", received.ConfigSHA256)
	}
	if received.NodeID != "node-B" {
		t.Errorf("expected NodeID=node-B, got %s", received.NodeID)
	}
	if received.ClusterConfig == nil {
		t.Fatal("expected ClusterConfig to be set")
	}
	if !received.ClusterConfig.Enabled {
		t.Error("expected ClusterConfig.Enabled=true")
	}
}

func TestHandleConfigSync_LeaderIgnores(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	gp.leaderMu.Lock()
	gp.isLeader = true
	gp.currentLeader = "node-A"
	gp.leaderMu.Unlock()

	called := false
	gp.SetCallbacks(nil, nil, nil, nil, nil, func(ConfigSyncPayload) {
		called = true
	})

	configSync := ConfigSyncPayload{ConfigSHA256: "abc"}
	payload, _ := encodePayload(configSync)
	msg := Message{
		Type:    MessageTypeConfigSync,
		From:    "node-B",
		Payload: payload,
	}

	gp.handleConfigSync(msg, &net.UDPAddr{})

	if called {
		t.Error("leader should ignore config sync messages")
	}
}


// ---------------------------------------------------------------------------
// checkLeaderHealth tests
// ---------------------------------------------------------------------------

func TestCheckLeaderHealth_TriggersElection(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	// Set up as follower with stale heartbeat
	gp.leaderMu.Lock()
	gp.isLeader = false
	gp.currentLeader = "node-B"
	gp.leaderTerm = 5
	gp.lastHeartbeat = time.Now().Add(-20 * time.Second) // > 15s threshold
	gp.leaderMu.Unlock()

	gp.checkLeaderHealth()

	// Give the async goroutine time to run
	time.Sleep(50 * time.Millisecond)

	gp.leaderMu.RLock()
	newTerm := gp.leaderTerm
	gp.leaderMu.RUnlock()

	if newTerm <= 5 {
		t.Errorf("expected leaderTerm to be incremented past 5, got %d", newTerm)
	}
}

func TestCheckLeaderHealth_LeaderNoOp(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	// Set up as leader
	gp.leaderMu.Lock()
	gp.isLeader = true
	gp.leaderTerm = 5
	gp.lastHeartbeat = time.Now().Add(-20 * time.Second)
	gp.leaderMu.Unlock()

	gp.checkLeaderHealth()

	time.Sleep(50 * time.Millisecond)

	gp.leaderMu.RLock()
	term := gp.leaderTerm
	gp.leaderMu.RUnlock()

	if term != 5 {
		t.Errorf("leader should not trigger election, term should stay 5, got %d", term)
	}
}

func TestCheckLeaderHealth_NoLeaderNoOp(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	gp.leaderMu.Lock()
	gp.isLeader = false
	gp.currentLeader = ""
	gp.leaderTerm = 5
	gp.leaderMu.Unlock()

	gp.checkLeaderHealth()

	time.Sleep(50 * time.Millisecond)

	gp.leaderMu.RLock()
	term := gp.leaderTerm
	gp.leaderMu.RUnlock()

	if term != 5 {
		t.Errorf("no leader — term should stay 5, got %d", term)
	}
}

func TestCheckLeaderHealth_RecentHeartbeatNoOp(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	gp.leaderMu.Lock()
	gp.isLeader = false
	gp.currentLeader = "node-B"
	gp.leaderTerm = 5
	gp.lastHeartbeat = time.Now() // recent
	gp.leaderMu.Unlock()

	gp.checkLeaderHealth()

	time.Sleep(50 * time.Millisecond)

	gp.leaderMu.RLock()
	term := gp.leaderTerm
	gp.leaderMu.RUnlock()

	if term != 5 {
		t.Errorf("recent heartbeat — term should stay 5, got %d", term)
	}
}

// ---------------------------------------------------------------------------
// muLeaderSendHeartbeat tests
// ---------------------------------------------------------------------------

func TestMuLeaderSendHeartbeat_NonLeaderNoOp(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	gp.leaderMu.Lock()
	gp.isLeader = false
	gp.leaderMu.Unlock()

	// Should not panic or send anything
	gp.muLeaderSendHeartbeat()
}

func TestMuLeaderSendHeartbeat_LeaderSendsToAliveNodes(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)

	// Add another alive node that listens
	ln, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	peerPort := ln.LocalAddr().(*net.UDPAddr).Port

	nl.Add(&Node{ID: "node-B", Addr: "127.0.0.1", Port: peerPort, State: NodeStateAlive})

	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	gp.leaderMu.Lock()
	gp.isLeader = true
	gp.leaderTerm = 7
	gp.leaderMu.Unlock()

	gp.muLeaderSendHeartbeat()

	// Read the heartbeat from the listener
	buf := make([]byte, 65536)
	ln.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := ln.ReadFrom(buf)
	if err != nil {
		t.Fatalf("expected to receive heartbeat, got error: %v", err)
	}

	// Decode the message
	var msg Message
	if err := decodeMessageRaw(buf[:n], &msg); err != nil {
		t.Fatalf("failed to decode message: %v", err)
	}
	if msg.Type != MessageTypeHeartbeat {
		t.Errorf("expected MessageTypeHeartbeat, got %d", msg.Type)
	}
}

// ---------------------------------------------------------------------------
// BroadcastNodeStats tests
// ---------------------------------------------------------------------------

func TestBroadcastNodeStats_SendsToPeers(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)

	ln, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	peerPort := ln.LocalAddr().(*net.UDPAddr).Port

	nl.Add(&Node{ID: "node-B", Addr: "127.0.0.1", Port: peerPort, State: NodeStateAlive})

	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	stats := NodeHealthStats{
		QueriesPerSecond: 100.5,
		LatencyMs:        12.3,
		CPUPercent:       45.0,
		MemoryPercent:    60.0,
		ActiveConns:      50,
	}

	if err := gp.BroadcastNodeStats(stats); err != nil {
		t.Fatalf("BroadcastNodeStats failed: %v", err)
	}

	buf := make([]byte, 65536)
	ln.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := ln.ReadFrom(buf)
	if err != nil {
		t.Fatalf("expected to receive node stats, got error: %v", err)
	}

	var msg Message
	if err := decodeMessageRaw(buf[:n], &msg); err != nil {
		t.Fatalf("failed to decode message: %v", err)
	}
	if msg.Type != MessageTypeNodeStats {
		t.Errorf("expected MessageTypeNodeStats, got %d", msg.Type)
	}

	var payload NodeStatsPayload
	if err := decodePayload(msg.Payload, &payload); err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	if payload.QueriesPerSecond != 100.5 {
		t.Errorf("expected QueriesPerSecond=100.5, got %f", payload.QueriesPerSecond)
	}
}

// ---------------------------------------------------------------------------
// BroadcastClusterMetrics tests
// ---------------------------------------------------------------------------

func TestBroadcastClusterMetrics_SendsToPeers(t *testing.T) {
	self := &Node{ID: "node-A", State: NodeStateAlive, Addr: "127.0.0.1"}
	nl := NewNodeList(self)

	ln, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	peerPort := ln.LocalAddr().(*net.UDPAddr).Port

	nl.Add(&Node{ID: "node-B", Addr: "127.0.0.1", Port: peerPort, State: NodeStateAlive})

	cfg := DefaultGossipConfig()
	cfg.BindPort = pickFreePort()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatal(err)
	}
	if err := gp.Start(); err != nil {
		t.Fatal(err)
	}
	defer gp.Stop()

	metrics := ClusterMetricsPayload{
		QueriesTotal:  10000,
		QueriesPerSec: 500.5,
		CacheHits:     8000,
		CacheMisses:   2000,
		LatencyMsAvg:  5.5,
		LatencyMsP99:  25.0,
		UptimeSeconds: 3600,
	}

	if err := gp.BroadcastClusterMetrics(metrics); err != nil {
		t.Fatalf("BroadcastClusterMetrics failed: %v", err)
	}

	buf := make([]byte, 65536)
	ln.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := ln.ReadFrom(buf)
	if err != nil {
		t.Fatalf("expected to receive cluster metrics, got error: %v", err)
	}

	var msg Message
	if err := decodeMessageRaw(buf[:n], &msg); err != nil {
		t.Fatalf("failed to decode message: %v", err)
	}
	if msg.Type != MessageTypeClusterMetrics {
		t.Errorf("expected MessageTypeClusterMetrics, got %d", msg.Type)
	}

	var payload ClusterMetricsPayload
	if err := decodePayload(msg.Payload, &payload); err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	if payload.QueriesTotal != 10000 {
		t.Errorf("expected QueriesTotal=10000, got %d", payload.QueriesTotal)
	}
	if payload.NodeID != "node-A" {
		t.Errorf("expected NodeID=node-A, got %s", payload.NodeID)
	}
}

// ---------------------------------------------------------------------------
// Cluster.BroadcastZoneUpdate and BroadcastConfigUpdate wrapper tests
// ---------------------------------------------------------------------------

func TestCluster_BroadcastZoneUpdate_NoGossip(t *testing.T) {
	c := &Cluster{}

	err := c.BroadcastZoneUpdate("example.com", "add", 1, nil, nil)
	if err == nil {
		t.Error("expected error when gossip is nil")
	}
}

func TestCluster_BroadcastConfigUpdate_NoGossip(t *testing.T) {
	c := &Cluster{}

	err := c.BroadcastConfigUpdate("abc123", nil)
	if err == nil {
		t.Error("expected error when gossip is nil")
	}
}
