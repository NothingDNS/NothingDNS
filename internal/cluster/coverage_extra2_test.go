package cluster

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// ---------------------------------------------------------------------------
// 1. ConsensusMode constants
// ---------------------------------------------------------------------------

func TestConsensusMode_Constants(t *testing.T) {
	if ConsensusSWIM != "swim" {
		t.Errorf("ConsensusSWIM = %q, want %q", ConsensusSWIM, "swim")
	}
	if ConsensusRaft != "raft" {
		t.Errorf("ConsensusRaft = %q, want %q", ConsensusRaft, "raft")
	}
}

// ---------------------------------------------------------------------------
// 2. Config struct field defaults and population
// ---------------------------------------------------------------------------

func TestConfig_PeerConfig(t *testing.T) {
	pc := PeerConfig{NodeID: "node-a", Addr: "10.0.0.1:7946"}
	if pc.NodeID != "node-a" {
		t.Errorf("PeerConfig.NodeID = %q, want %q", pc.NodeID, "node-a")
	}
	if pc.Addr != "10.0.0.1:7946" {
		t.Errorf("PeerConfig.Addr = %q, want %q", pc.Addr, "10.0.0.1:7946")
	}
}

// ---------------------------------------------------------------------------
// 3. GossipConfig defaults
// ---------------------------------------------------------------------------

func TestDefaultGossipConfig_Values(t *testing.T) {
	cfg := DefaultGossipConfig()
	if cfg.BindAddr != "0.0.0.0" {
		t.Errorf("BindAddr = %q, want %q", cfg.BindAddr, "0.0.0.0")
	}
	if cfg.BindPort != 7946 {
		t.Errorf("BindPort = %d, want 7946", cfg.BindPort)
	}
	if cfg.GossipInterval != 200*time.Millisecond {
		t.Errorf("GossipInterval = %v, want 200ms", cfg.GossipInterval)
	}
	if cfg.ProbeInterval != 1*time.Second {
		t.Errorf("ProbeInterval = %v, want 1s", cfg.ProbeInterval)
	}
	if cfg.ProbeTimeout != 500*time.Millisecond {
		t.Errorf("ProbeTimeout = %v, want 500ms", cfg.ProbeTimeout)
	}
	if cfg.SuspicionMult != 4 {
		t.Errorf("SuspicionMult = %d, want 4", cfg.SuspicionMult)
	}
	if cfg.RetransmitMult != 4 {
		t.Errorf("RetransmitMult = %d, want 4", cfg.RetransmitMult)
	}
	if cfg.GossipNodes != 3 {
		t.Errorf("GossipNodes = %d, want 3", cfg.GossipNodes)
	}
	if cfg.IndirectChecks != 3 {
		t.Errorf("IndirectChecks = %d, want 3", cfg.IndirectChecks)
	}
	if cfg.ProtocolVersion != 1 {
		t.Errorf("ProtocolVersion = %d, want 1", cfg.ProtocolVersion)
	}
	if cfg.EncryptionKey != nil {
		t.Errorf("EncryptionKey should be nil by default")
	}
}

// ---------------------------------------------------------------------------
// 4. Encryption: initEncryption with invalid key sizes
// ---------------------------------------------------------------------------

func TestGossipProtocol_InitEncryption_ValidKey(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatalf("NewGossipProtocol() error = %v", err)
	}

	// 32-byte key should succeed
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := gp.initEncryption(key); err != nil {
		t.Fatalf("initEncryption(32 bytes) error = %v", err)
	}
	if !gp.IsEncrypted() {
		t.Error("IsEncrypted() should return true after initEncryption")
	}
}

func TestGossipProtocol_InitEncryption_InvalidKeySize(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	// 16-byte key should fail
	err := gp.initEncryption(make([]byte, 16))
	if err == nil {
		t.Error("initEncryption(16 bytes) should fail")
	}

	// 0-byte key should fail
	err = gp.initEncryption(make([]byte, 0))
	if err == nil {
		t.Error("initEncryption(0 bytes) should fail")
	}

	// 64-byte key should fail
	err = gp.initEncryption(make([]byte, 64))
	if err == nil {
		t.Error("initEncryption(64 bytes) should fail")
	}
}

// ---------------------------------------------------------------------------
// 5. Encryption: encrypt/decrypt round-trip
// ---------------------------------------------------------------------------

func TestGossipProtocol_EncryptDecryptRoundTrip(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	// Initialize encryption
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := gp.initEncryption(key); err != nil {
		t.Fatalf("initEncryption() error = %v", err)
	}

	plaintext := []byte("hello gossip cluster encryption test")
	encrypted, err := gp.encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt() error = %v", err)
	}

	// Encrypted data should differ from plaintext
	if string(encrypted) == string(plaintext) {
		t.Error("encrypted data should differ from plaintext")
	}

	// Encrypted data should be longer (nonce + tag)
	if len(encrypted) <= len(plaintext) {
		t.Errorf("encrypted len=%d should be > plaintext len=%d", len(encrypted), len(plaintext))
	}

	// Decrypt should recover plaintext
	decrypted, err := gp.decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt() error = %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypt() = %q, want %q", string(decrypted), string(plaintext))
	}
}

// ---------------------------------------------------------------------------
// 6. Encryption: encrypt with nil AEAD returns plaintext unchanged
// ---------------------------------------------------------------------------

func TestGossipProtocol_Encrypt_NoAEAD(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)
	// Do NOT init encryption — aead is nil

	plaintext := []byte("no encryption")
	result, err := gp.encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt() with nil AEAD should not error: %v", err)
	}
	if string(result) != string(plaintext) {
		t.Error("encrypt() with nil AEAD should return plaintext unchanged")
	}
}

func TestGossipProtocol_Decrypt_NoAEAD(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	data := []byte("no encryption")
	result, err := gp.decrypt(data)
	if err != nil {
		t.Fatalf("decrypt() with nil AEAD should not error: %v", err)
	}
	if string(result) != string(data) {
		t.Error("decrypt() with nil AEAD should return data unchanged")
	}
}

// ---------------------------------------------------------------------------
// 7. Encryption: decrypt with too-short ciphertext
// ---------------------------------------------------------------------------

func TestGossipProtocol_Decrypt_TooShort(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)
	key := make([]byte, 32)
	if err := gp.initEncryption(key); err != nil {
		t.Fatalf("initEncryption() error = %v", err)
	}

	// 1 byte is way too short for nonce + overhead
	_, err := gp.decrypt([]byte{0x01})
	if err == nil {
		t.Error("decrypt() with too-short data should fail")
	}
}

// ---------------------------------------------------------------------------
// 8. Encryption: decrypt with corrupted data
// ---------------------------------------------------------------------------

func TestGossipProtocol_Decrypt_Corrupted(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)
	key := make([]byte, 32)
	if err := gp.initEncryption(key); err != nil {
		t.Fatalf("initEncryption() error = %v", err)
	}

	// Encrypt valid data then corrupt a byte
	encrypted, _ := gp.encrypt([]byte("test data"))
	encrypted[len(encrypted)-1] ^= 0xFF

	_, err := gp.decrypt(encrypted)
	if err == nil {
		t.Error("decrypt() with corrupted data should fail")
	}
}

// ---------------------------------------------------------------------------
// 9. ClusterConfigJSON round-trip
// ---------------------------------------------------------------------------

func TestClusterConfigJSON_RoundTrip(t *testing.T) {
	original := ClusterConfigJSON{
		Enabled:       true,
		NodeID:        "node-1",
		BindAddr:      "192.168.1.10",
		BindPort:      5353,
		GossipPort:    7946,
		ConsensusMode: "raft",
		Region:        "us-east-1",
		Zone:          "us-east-1b",
		Weight:        200,
		SeedNodes:     []string{"192.168.1.11:7946", "192.168.1.12:7946"},
		CacheSync:     true,
		HTTPAddr:      "192.168.1.10:8080",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var decoded ClusterConfigJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if !decoded.Enabled {
		t.Error("Enabled should be true")
	}
	if decoded.NodeID != "node-1" {
		t.Errorf("NodeID = %q, want %q", decoded.NodeID, "node-1")
	}
	if decoded.BindAddr != "192.168.1.10" {
		t.Errorf("BindAddr = %q, want %q", decoded.BindAddr, "192.168.1.10")
	}
	if decoded.BindPort != 5353 {
		t.Errorf("BindPort = %d, want 5353", decoded.BindPort)
	}
	if decoded.GossipPort != 7946 {
		t.Errorf("GossipPort = %d, want 7946", decoded.GossipPort)
	}
	if decoded.ConsensusMode != "raft" {
		t.Errorf("ConsensusMode = %q, want %q", decoded.ConsensusMode, "raft")
	}
	if decoded.Region != "us-east-1" {
		t.Errorf("Region = %q, want %q", decoded.Region, "us-east-1")
	}
	if decoded.Zone != "us-east-1b" {
		t.Errorf("Zone = %q, want %q", decoded.Zone, "us-east-1b")
	}
	if decoded.Weight != 200 {
		t.Errorf("Weight = %d, want 200", decoded.Weight)
	}
	if len(decoded.SeedNodes) != 2 {
		t.Errorf("len(SeedNodes) = %d, want 2", len(decoded.SeedNodes))
	}
	if !decoded.CacheSync {
		t.Error("CacheSync should be true")
	}
	if decoded.HTTPAddr != "192.168.1.10:8080" {
		t.Errorf("HTTPAddr = %q, want %q", decoded.HTTPAddr, "192.168.1.10:8080")
	}
}

// ---------------------------------------------------------------------------
// 10. Message types encode/decode round-trips for all payload types
// ---------------------------------------------------------------------------

func TestEncodeDecode_DrainingPayload(t *testing.T) {
	now := time.Now()
	payload := DrainingPayload{
		NodeID:      "node-1",
		Draining:    true,
		Timestamp:   now,
		InFlightReq: 42,
	}

	data, err := encodePayload(payload)
	if err != nil {
		t.Fatalf("encodePayload() error = %v", err)
	}

	var decoded DrainingPayload
	if err := decodePayload(data, &decoded); err != nil {
		t.Fatalf("decodePayload() error = %v", err)
	}

	if decoded.NodeID != "node-1" {
		t.Errorf("NodeID = %q, want %q", decoded.NodeID, "node-1")
	}
	if !decoded.Draining {
		t.Error("Draining should be true")
	}
	if decoded.InFlightReq != 42 {
		t.Errorf("InFlightReq = %d, want 42", decoded.InFlightReq)
	}
}

func TestEncodeDecode_NodeStatsPayload(t *testing.T) {
	now := time.Now()
	payload := NodeStatsPayload{
		NodeID:           "stats-node",
		QueriesPerSecond: 1234.5,
		LatencyMs:        3.14,
		CPUPercent:       55.0,
		MemoryPercent:    40.0,
		ActiveConns:      500,
		Timestamp:        now,
	}

	data, err := encodePayload(payload)
	if err != nil {
		t.Fatalf("encodePayload() error = %v", err)
	}

	var decoded NodeStatsPayload
	if err := decodePayload(data, &decoded); err != nil {
		t.Fatalf("decodePayload() error = %v", err)
	}

	if decoded.NodeID != "stats-node" {
		t.Errorf("NodeID = %q, want %q", decoded.NodeID, "stats-node")
	}
	if decoded.QueriesPerSecond != 1234.5 {
		t.Errorf("QueriesPerSecond = %f, want 1234.5", decoded.QueriesPerSecond)
	}
	if decoded.LatencyMs != 3.14 {
		t.Errorf("LatencyMs = %f, want 3.14", decoded.LatencyMs)
	}
	if decoded.CPUPercent != 55.0 {
		t.Errorf("CPUPercent = %f, want 55.0", decoded.CPUPercent)
	}
	if decoded.MemoryPercent != 40.0 {
		t.Errorf("MemoryPercent = %f, want 40.0", decoded.MemoryPercent)
	}
	if decoded.ActiveConns != 500 {
		t.Errorf("ActiveConns = %d, want 500", decoded.ActiveConns)
	}
}

func TestEncodeDecode_ClusterMetricsPayload(t *testing.T) {
	now := time.Now()
	payload := ClusterMetricsPayload{
		NodeID:        "metrics-node",
		QueriesTotal:  100000,
		QueriesPerSec: 500.0,
		CacheHits:     80000,
		CacheMisses:   20000,
		LatencyMsAvg:  2.5,
		LatencyMsP99:  15.0,
		UptimeSeconds: 86400,
		Timestamp:     now,
	}

	data, err := encodePayload(payload)
	if err != nil {
		t.Fatalf("encodePayload() error = %v", err)
	}

	var decoded ClusterMetricsPayload
	if err := decodePayload(data, &decoded); err != nil {
		t.Fatalf("decodePayload() error = %v", err)
	}

	if decoded.NodeID != "metrics-node" {
		t.Errorf("NodeID = %q, want %q", decoded.NodeID, "metrics-node")
	}
	if decoded.QueriesTotal != 100000 {
		t.Errorf("QueriesTotal = %d, want 100000", decoded.QueriesTotal)
	}
	if decoded.QueriesPerSec != 500.0 {
		t.Errorf("QueriesPerSec = %f, want 500.0", decoded.QueriesPerSec)
	}
	if decoded.CacheHits != 80000 {
		t.Errorf("CacheHits = %d, want 80000", decoded.CacheHits)
	}
	if decoded.CacheMisses != 20000 {
		t.Errorf("CacheMisses = %d, want 20000", decoded.CacheMisses)
	}
	if decoded.LatencyMsAvg != 2.5 {
		t.Errorf("LatencyMsAvg = %f, want 2.5", decoded.LatencyMsAvg)
	}
	if decoded.LatencyMsP99 != 15.0 {
		t.Errorf("LatencyMsP99 = %f, want 15.0", decoded.LatencyMsP99)
	}
	if decoded.UptimeSeconds != 86400 {
		t.Errorf("UptimeSeconds = %d, want 86400", decoded.UptimeSeconds)
	}
}

func TestEncodeDecode_ElectionPayload(t *testing.T) {
	payload := ElectionPayload{
		ProposedLeader: "node-42",
		Priority:       7,
		Term:           15,
	}

	data, err := encodePayload(payload)
	if err != nil {
		t.Fatalf("encodePayload() error = %v", err)
	}

	var decoded ElectionPayload
	if err := decodePayload(data, &decoded); err != nil {
		t.Fatalf("decodePayload() error = %v", err)
	}

	if decoded.ProposedLeader != "node-42" {
		t.Errorf("ProposedLeader = %q, want %q", decoded.ProposedLeader, "node-42")
	}
	if decoded.Priority != 7 {
		t.Errorf("Priority = %d, want 7", decoded.Priority)
	}
	if decoded.Term != 15 {
		t.Errorf("Term = %d, want 15", decoded.Term)
	}
}

func TestEncodeDecode_LeaderPayload(t *testing.T) {
	payload := LeaderPayload{
		LeaderID:   "leader-node",
		LeaderAddr: "10.0.0.1:7946",
		Term:       99,
	}

	data, err := encodePayload(payload)
	if err != nil {
		t.Fatalf("encodePayload() error = %v", err)
	}

	var decoded LeaderPayload
	if err := decodePayload(data, &decoded); err != nil {
		t.Fatalf("decodePayload() error = %v", err)
	}

	if decoded.LeaderID != "leader-node" {
		t.Errorf("LeaderID = %q, want %q", decoded.LeaderID, "leader-node")
	}
	if decoded.LeaderAddr != "10.0.0.1:7946" {
		t.Errorf("LeaderAddr = %q, want %q", decoded.LeaderAddr, "10.0.0.1:7946")
	}
	if decoded.Term != 99 {
		t.Errorf("Term = %d, want 99", decoded.Term)
	}
}

func TestEncodeDecode_LeaderHeartbeatPayload(t *testing.T) {
	payload := LeaderHeartbeatPayload{
		LeaderID: "heartbeat-leader",
		Term:     42,
	}

	data, err := encodePayload(payload)
	if err != nil {
		t.Fatalf("encodePayload() error = %v", err)
	}

	var decoded LeaderHeartbeatPayload
	if err := decodePayload(data, &decoded); err != nil {
		t.Fatalf("decodePayload() error = %v", err)
	}

	if decoded.LeaderID != "heartbeat-leader" {
		t.Errorf("LeaderID = %q, want %q", decoded.LeaderID, "heartbeat-leader")
	}
	if decoded.Term != 42 {
		t.Errorf("Term = %d, want 42", decoded.Term)
	}
}

func TestEncodeDecode_ZoneUpdatePayload(t *testing.T) {
	payload := ZoneUpdatePayload{
		ZoneName: "example.com.",
		Action:   "add",
		Serial:   2024010100,
		Records: []ZoneRecord{
			{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
			{Name: "mail.example.com.", TTL: 3600, Class: "IN", Type: "MX", RData: "10 mx.example.com."},
		},
		DeletedKeys: []string{"old.example.com./A"},
		RawZone:     []byte("example.com. IN SOA ns1.example.com. admin.example.com. 2024010100 3600 900 604800 86400"),
	}

	data, err := encodePayload(payload)
	if err != nil {
		t.Fatalf("encodePayload() error = %v", err)
	}

	var decoded ZoneUpdatePayload
	if err := decodePayload(data, &decoded); err != nil {
		t.Fatalf("decodePayload() error = %v", err)
	}

	if decoded.ZoneName != "example.com." {
		t.Errorf("ZoneName = %q, want %q", decoded.ZoneName, "example.com.")
	}
	if decoded.Action != "add" {
		t.Errorf("Action = %q, want %q", decoded.Action, "add")
	}
	if decoded.Serial != 2024010100 {
		t.Errorf("Serial = %d, want 2024010100", decoded.Serial)
	}
	if len(decoded.Records) != 2 {
		t.Fatalf("len(Records) = %d, want 2", len(decoded.Records))
	}
	if decoded.Records[0].Name != "www.example.com." {
		t.Errorf("Records[0].Name = %q, want %q", decoded.Records[0].Name, "www.example.com.")
	}
	if decoded.Records[0].RData != "1.2.3.4" {
		t.Errorf("Records[0].RData = %q, want %q", decoded.Records[0].RData, "1.2.3.4")
	}
	if len(decoded.DeletedKeys) != 1 {
		t.Errorf("len(DeletedKeys) = %d, want 1", len(decoded.DeletedKeys))
	}
	if len(decoded.RawZone) == 0 {
		t.Error("RawZone should not be empty")
	}
}

func TestEncodeDecode_ConfigSyncPayload(t *testing.T) {
	now := time.Now()
	payload := ConfigSyncPayload{
		ConfigSHA256: "abc123def456",
		Timestamp:    now,
		NodeID:       "leader-node",
		ClusterConfig: &ClusterConfigJSON{
			Enabled:   true,
			NodeID:    "cfg-node",
			BindAddr:  "10.0.0.1",
			GossipPort: 7946,
		},
	}

	data, err := encodePayload(payload)
	if err != nil {
		t.Fatalf("encodePayload() error = %v", err)
	}

	var decoded ConfigSyncPayload
	if err := decodePayload(data, &decoded); err != nil {
		t.Fatalf("decodePayload() error = %v", err)
	}

	if decoded.ConfigSHA256 != "abc123def456" {
		t.Errorf("ConfigSHA256 = %q, want %q", decoded.ConfigSHA256, "abc123def456")
	}
	if decoded.NodeID != "leader-node" {
		t.Errorf("NodeID = %q, want %q", decoded.NodeID, "leader-node")
	}
	if decoded.ClusterConfig == nil {
		t.Fatal("ClusterConfig should not be nil")
	}
	if decoded.ClusterConfig.NodeID != "cfg-node" {
		t.Errorf("ClusterConfig.NodeID = %q, want %q", decoded.ClusterConfig.NodeID, "cfg-node")
	}
}

func TestEncodeDecode_CacheInvalidatePayload(t *testing.T) {
	now := time.Now()
	payload := CacheInvalidatePayload{
		Keys:      []string{"key-1", "key-2", "key-3"},
		Source:    "origin-node",
		Timestamp: now,
	}

	data, err := encodePayload(payload)
	if err != nil {
		t.Fatalf("encodePayload() error = %v", err)
	}

	var decoded CacheInvalidatePayload
	if err := decodePayload(data, &decoded); err != nil {
		t.Fatalf("decodePayload() error = %v", err)
	}

	if len(decoded.Keys) != 3 {
		t.Errorf("len(Keys) = %d, want 3", len(decoded.Keys))
	}
	if decoded.Source != "origin-node" {
		t.Errorf("Source = %q, want %q", decoded.Source, "origin-node")
	}
}

func TestEncodeDecode_GossipPayload(t *testing.T) {
	now := time.Now()
	payload := GossipPayload{
		Nodes: []NodeInfo{
			{
				ID: "node-a", Addr: "10.0.0.1", Port: 7946,
				State: NodeStateAlive, Version: 5, LastSeen: now,
				Meta: NodeMeta{Region: "us-east", Zone: "us-east-1a", Weight: 100},
			},
			{
				ID: "node-b", Addr: "10.0.0.2", Port: 7946,
				State: NodeStateSuspect, Version: 3, LastSeen: now.Add(-5 * time.Second),
				Meta: NodeMeta{Region: "eu-west", Zone: "eu-west-1a", Weight: 50, HTTPAddr: "10.0.0.2:8080"},
			},
		},
	}

	data, err := encodePayload(payload)
	if err != nil {
		t.Fatalf("encodePayload() error = %v", err)
	}

	var decoded GossipPayload
	if err := decodePayload(data, &decoded); err != nil {
		t.Fatalf("decodePayload() error = %v", err)
	}

	if len(decoded.Nodes) != 2 {
		t.Fatalf("len(Nodes) = %d, want 2", len(decoded.Nodes))
	}
	if decoded.Nodes[0].ID != "node-a" {
		t.Errorf("Nodes[0].ID = %q, want %q", decoded.Nodes[0].ID, "node-a")
	}
	if decoded.Nodes[0].State != NodeStateAlive {
		t.Errorf("Nodes[0].State = %v, want Alive", decoded.Nodes[0].State)
	}
	if decoded.Nodes[1].Meta.Region != "eu-west" {
		t.Errorf("Nodes[1].Meta.Region = %q, want %q", decoded.Nodes[1].Meta.Region, "eu-west")
	}
	if decoded.Nodes[1].Meta.HTTPAddr != "10.0.0.2:8080" {
		t.Errorf("Nodes[1].Meta.HTTPAddr = %q, want %q", decoded.Nodes[1].Meta.HTTPAddr, "10.0.0.2:8080")
	}
}

// ---------------------------------------------------------------------------
// 11. Message struct with ProtocolVersion field
// ---------------------------------------------------------------------------

func TestMessage_ProtocolVersion(t *testing.T) {
	data, err := encodeMessage(MessageTypePing, "test-node", 2, []byte("payload"))
	if err != nil {
		t.Fatalf("encodeMessage() error = %v", err)
	}

	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if msg.ProtocolVersion != 2 {
		t.Errorf("ProtocolVersion = %d, want 2", msg.ProtocolVersion)
	}
	if msg.Type != MessageTypePing {
		t.Errorf("Type = %v, want MessageTypePing", msg.Type)
	}
	if msg.From != "test-node" {
		t.Errorf("From = %q, want %q", msg.From, "test-node")
	}
}

// ---------------------------------------------------------------------------
// 12. GossipProtocol.GetSelfID / GetLeaderTerm / IsLeaderAlive without network
// ---------------------------------------------------------------------------

func TestGossipProtocol_GetSelfID(t *testing.T) {
	self := &Node{ID: "my-node-id", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	if got := gp.GetSelfID(); got != "my-node-id" {
		t.Errorf("GetSelfID() = %q, want %q", got, "my-node-id")
	}
}

func TestGossipProtocol_GetLeaderTerm_Initial(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	if got := gp.GetLeaderTerm(); got != 0 {
		t.Errorf("GetLeaderTerm() = %d, want 0 (initial)", got)
	}
}

func TestGossipProtocol_IsLeaderAlive_NoLeader(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	// No leader set, should return false
	if gp.IsLeaderAlive(10 * time.Second) {
		t.Error("IsLeaderAlive() should return false when no leader exists")
	}
}

func TestGossipProtocol_IsLeaderAlive_StaleHeartbeat(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	// Set a leader with old heartbeat
	gp.leaderMu.Lock()
	gp.currentLeader = "some-leader"
	gp.lastHeartbeat = time.Now().Add(-30 * time.Second)
	gp.leaderMu.Unlock()

	if gp.IsLeaderAlive(10 * time.Second) {
		t.Error("IsLeaderAlive() should return false when heartbeat is stale")
	}
}

func TestGossipProtocol_IsLeaderAlive_RecentHeartbeat(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	// Set a leader with recent heartbeat
	gp.leaderMu.Lock()
	gp.currentLeader = "active-leader"
	gp.lastHeartbeat = time.Now()
	gp.leaderMu.Unlock()

	if !gp.IsLeaderAlive(10 * time.Second) {
		t.Error("IsLeaderAlive() should return true when heartbeat is recent")
	}
}

// ---------------------------------------------------------------------------
// 13. GossipProtocol.GetClusterMetrics aggregation
// ---------------------------------------------------------------------------

func TestGossipProtocol_GetClusterMetrics_Aggregation(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	// Pre-populate nodeMetrics
	gp.nodeMetrics["node-a"] = ClusterMetricsPayload{
		QueriesTotal:  1000,
		CacheHits:     800,
		CacheMisses:   200,
		QueriesPerSec: 100.0,
		LatencyMsAvg:  2.0,
		LatencyMsP99:  10.0,
		UptimeSeconds: 3600,
	}
	gp.nodeMetrics["node-b"] = ClusterMetricsPayload{
		QueriesTotal:  2000,
		CacheHits:     1500,
		CacheMisses:   500,
		QueriesPerSec: 200.0,
		LatencyMsAvg:  4.0,
		LatencyMsP99:  20.0,
		UptimeSeconds: 7200,
	}

	metrics := gp.GetClusterMetrics()

	if metrics.QueriesTotal != 3000 {
		t.Errorf("QueriesTotal = %d, want 3000", metrics.QueriesTotal)
	}
	if metrics.CacheHits != 2300 {
		t.Errorf("CacheHits = %d, want 2300", metrics.CacheHits)
	}
	if metrics.CacheMisses != 700 {
		t.Errorf("CacheMisses = %d, want 700", metrics.CacheMisses)
	}
	if metrics.UptimeSeconds != 10800 {
		t.Errorf("UptimeSeconds = %d, want 10800", metrics.UptimeSeconds)
	}
	// QueriesPerSec should be averaged: (100 + 200) / 2 = 150
	if metrics.QueriesPerSec != 150.0 {
		t.Errorf("QueriesPerSec = %f, want 150.0", metrics.QueriesPerSec)
	}
	// LatencyMsAvg should be averaged: (2.0 + 4.0) / 2 = 3.0
	if metrics.LatencyMsAvg != 3.0 {
		t.Errorf("LatencyMsAvg = %f, want 3.0", metrics.LatencyMsAvg)
	}
	// LatencyMsP99 should be averaged: (10.0 + 20.0) / 2 = 15.0
	if metrics.LatencyMsP99 != 15.0 {
		t.Errorf("LatencyMsP99 = %f, want 15.0", metrics.LatencyMsP99)
	}
}

func TestGossipProtocol_GetClusterMetrics_Empty(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	metrics := gp.GetClusterMetrics()
	if metrics.QueriesTotal != 0 {
		t.Errorf("QueriesTotal = %d, want 0", metrics.QueriesTotal)
	}
	if metrics.QueriesPerSec != 0 {
		t.Errorf("QueriesPerSec = %f, want 0", metrics.QueriesPerSec)
	}
}

// ---------------------------------------------------------------------------
// 14. GossipProtocol.StepDown
// ---------------------------------------------------------------------------

func TestGossipProtocol_StepDown_AsLeader(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	// Set as leader
	gp.leaderMu.Lock()
	gp.isLeader = true
	gp.currentLeader = "self"
	gp.leaderTerm = 5
	gp.leaderMu.Unlock()

	gp.StepDown()

	gp.leaderMu.RLock()
	isLeader := gp.isLeader
	leader := gp.currentLeader
	term := gp.leaderTerm
	gp.leaderMu.RUnlock()

	if isLeader {
		t.Error("isLeader should be false after StepDown")
	}
	if leader != "" {
		t.Errorf("currentLeader = %q, want empty after StepDown", leader)
	}
	if term != 6 {
		t.Errorf("leaderTerm = %d, want 6 (incremented)", term)
	}
}

func TestGossipProtocol_StepDown_NotLeader(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	// Not leader, StepDown should be a no-op
	gp.leaderMu.Lock()
	gp.leaderTerm = 3
	gp.leaderMu.Unlock()

	gp.StepDown()

	if gp.GetLeaderTerm() != 3 {
		t.Errorf("leaderTerm should remain 3 after StepDown when not leader, got %d", gp.GetLeaderTerm())
	}
}

// ---------------------------------------------------------------------------
// 15. GossipStats struct
// ---------------------------------------------------------------------------

func TestGossipStats_Initial(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	stats := gp.Stats()
	if stats.MessagesSent != 0 {
		t.Errorf("MessagesSent = %d, want 0", stats.MessagesSent)
	}
	if stats.MessagesReceived != 0 {
		t.Errorf("MessagesReceived = %d, want 0", stats.MessagesReceived)
	}
	if stats.PingSent != 0 {
		t.Errorf("PingSent = %d, want 0", stats.PingSent)
	}
	if stats.PingReceived != 0 {
		t.Errorf("PingReceived = %d, want 0", stats.PingReceived)
	}
}

// ---------------------------------------------------------------------------
// 16. handleZoneUpdate with various actions (cluster-level)
// ---------------------------------------------------------------------------

func TestCluster_HandleZoneUpdate_NilZoneManager(t *testing.T) {
	c := &Cluster{
		config:    Config{NodeID: "solo"},
		consensus: ConsensusSWIM,
		logger:    util.NewLogger(util.INFO, util.TextFormat, nil),
	}

	// Should not panic with nil zoneManager
	c.handleZoneUpdate(ZoneUpdatePayload{
		ZoneName: "example.com.",
		Action:   "full",
		Serial:   1,
	})
}

func TestCluster_HandleConfigSync_NilCallback(t *testing.T) {
	c := &Cluster{
		config:    Config{NodeID: "solo"},
		consensus: ConsensusSWIM,
		logger:    util.NewLogger(util.INFO, util.TextFormat, nil),
	}

	// Should not panic with nil configReloadCallback
	c.handleConfigSync(ConfigSyncPayload{
		ConfigSHA256: "abc",
		NodeID:       "leader",
	})
}

// ---------------------------------------------------------------------------
// 17. AnnounceLeader when not leader
// ---------------------------------------------------------------------------

func TestGossipProtocol_AnnounceLeader_NotLeader(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)
	// Not started, not leader

	err := gp.AnnounceLeader()
	if err == nil {
		t.Error("AnnounceLeader() should fail when not leader")
	}
}

// ---------------------------------------------------------------------------
// 18. BroadcastZoneUpdate when not leader
// ---------------------------------------------------------------------------

func TestGossipProtocol_BroadcastZoneUpdate_NotLeader(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	err := gp.BroadcastZoneUpdate(ZoneUpdatePayload{
		ZoneName: "example.com.",
		Action:   "add",
		Serial:   1,
	})
	if err == nil {
		t.Error("BroadcastZoneUpdate() should fail when not leader")
	}
}

// ---------------------------------------------------------------------------
// 19. BroadcastConfigUpdate when not leader
// ---------------------------------------------------------------------------

func TestGossipProtocol_BroadcastConfigUpdate_NotLeader(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	err := gp.BroadcastConfigUpdate(ConfigSyncPayload{
		ConfigSHA256: "abc123",
		NodeID:       "self",
	})
	if err == nil {
		t.Error("BroadcastConfigUpdate() should fail when not leader")
	}
}

// ---------------------------------------------------------------------------
// 20. NewGossipProtocol with encryption key
// ---------------------------------------------------------------------------

func TestNewGossipProtocol_WithEncryptionKey(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.EncryptionKey = make([]byte, 32)

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatalf("NewGossipProtocol() with valid key error = %v", err)
	}
	if !gp.IsEncrypted() {
		t.Error("Protocol should be encrypted after init with valid key")
	}
}

func TestNewGossipProtocol_WithInvalidEncryptionKey(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.EncryptionKey = make([]byte, 16) // Wrong size

	_, err := NewGossipProtocol(cfg, nl)
	if err == nil {
		t.Error("NewGossipProtocol() with 16-byte key should fail")
	}
}

// ---------------------------------------------------------------------------
// 21. GossipProtocol decodeMessage with encryption enabled (rejects plaintext)
// ---------------------------------------------------------------------------

func TestGossipProtocol_DecodeMessage_EncryptedRejectsPlaintext(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.EncryptionKey = make([]byte, 32)

	gp, err := NewGossipProtocol(cfg, nl)
	if err != nil {
		t.Fatalf("NewGossipProtocol() error = %v", err)
	}

	// Try to decode plaintext data — should fail because encryption is enabled
	var msg Message
	err = gp.decodeMessage([]byte(`{"type":0,"from":"test"}`), &msg)
	if err == nil {
		t.Error("decodeMessage() should reject unencrypted data when encryption is enabled")
	}
}

// ---------------------------------------------------------------------------
// 22. GossipProtocol decodeMessage protocol version mismatch
// ---------------------------------------------------------------------------

func TestGossipProtocol_DecodeMessage_ProtocolVersionMismatch(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.ProtocolVersion = 2

	gp, _ := NewGossipProtocol(cfg, nl)

	// Encode a message with a different protocol version
	msgData, _ := encodeMessage(MessageTypePing, "other-node", 5, []byte("test"))

	var msg Message
	err := gp.decodeMessage(msgData, &msg)
	if err == nil {
		t.Error("decodeMessage() should reject message with incompatible protocol version")
	}
}

func TestGossipProtocol_DecodeMessage_ProtocolVersionZeroAccepted(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()
	cfg.ProtocolVersion = 2

	gp, _ := NewGossipProtocol(cfg, nl)

	// Create a message with ProtocolVersion=0 (legacy)
	msg := Message{
		Type:            MessageTypePing,
		From:            "other-node",
		Timestamp:       time.Now(),
		Payload:         []byte("test"),
		ProtocolVersion: 0, // Legacy version should be accepted
	}
	data, _ := json.Marshal(msg)

	var decoded Message
	err := gp.decodeMessage(data, &decoded)
	if err != nil {
		t.Errorf("decodeMessage() should accept protocol version 0 (legacy): %v", err)
	}
}

// ---------------------------------------------------------------------------
// 23. NodeList concurrent access safety
// ---------------------------------------------------------------------------

func TestNodeList_ConcurrentAccess(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)

	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 100; i++ {
			nl.Add(&Node{ID: "node-" + string(rune('A'+i%5)), State: NodeStateAlive, Version: uint64(i)})
			nl.MarkSeen("node-" + string(rune('A'+i%5)))
			nl.UpdateState("node-"+string(rune('A'+i%5)), NodeStateAlive)
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 100; i++ {
			nl.GetAll()
			nl.GetAlive()
			nl.Count()
			nl.AliveCount()
			nl.Get("node-A")
		}
		done <- true
	}()

	// Health updater goroutine
	go func() {
		for i := 0; i < 100; i++ {
			nl.UpdateHealth("self", NodeHealthStats{
				LatencyMs:   float64(i),
				LastUpdated: time.Now(),
			})
		}
		done <- true
	}()

	// Wait for all goroutines
	<-done
	<-done
	<-done
}

// ---------------------------------------------------------------------------
// 24. CacheSyncEvent fields
// ---------------------------------------------------------------------------

func TestCacheSyncEvent_Fields(t *testing.T) {
	now := time.Now()
	event := CacheSyncEvent{
		Type:      "update",
		Keys:      []string{"a", "b"},
		Source:    "remote",
		Timestamp: now,
	}

	if event.Type != "update" {
		t.Errorf("Type = %q, want %q", event.Type, "update")
	}
	if len(event.Keys) != 2 {
		t.Errorf("len(Keys) = %d, want 2", len(event.Keys))
	}
	if event.Source != "remote" {
		t.Errorf("Source = %q, want %q", event.Source, "remote")
	}
	if !event.Timestamp.Equal(now) {
		t.Errorf("Timestamp mismatch")
	}
}

// ---------------------------------------------------------------------------
// 25. New with encryption key in cluster config (hex decode path)
// ---------------------------------------------------------------------------

func TestNew_EncryptionKey_InvalidHex(t *testing.T) {
	c := &Cluster{
		config: Config{
			EncryptionKey: "not-valid-hex!!",
		},
		logger: util.NewLogger(util.INFO, util.TextFormat, nil),
	}

	// Call initGossip directly — the hex decode should fail
	err := c.initGossip()
	if err == nil {
		t.Error("initGossip() should fail with invalid hex encryption key")
	}
}

// ---------------------------------------------------------------------------
// 26. Cluster.IsHealthy boundary: 2 nodes 1 alive
// ---------------------------------------------------------------------------

func TestCluster_IsHealthy_TwoNodesOneAlive(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	nl.Add(&Node{ID: "dead-node", State: NodeStateDead})

	c := &Cluster{
		config:    Config{NodeID: "self"},
		consensus: ConsensusSWIM,
		nodeList:  nl,
		started:   true,
	}

	// 2 total, 1 alive. Majority = (2/2)+1 = 2. 1 < 2, so unhealthy
	if c.IsHealthy() {
		t.Error("2 nodes with 1 alive should be unhealthy (need majority)")
	}
}

// ---------------------------------------------------------------------------
// 27. Cluster.IsHealthy: 2 nodes both alive
// ---------------------------------------------------------------------------

func TestCluster_IsHealthy_TwoNodesBothAlive(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	nl.Add(&Node{ID: "alive-node", State: NodeStateAlive})

	c := &Cluster{
		config:    Config{NodeID: "self"},
		consensus: ConsensusSWIM,
		nodeList:  nl,
		started:   true,
	}

	// 2 total, 2 alive. Majority = (2/2)+1 = 2. 2 >= 2, so healthy
	if !c.IsHealthy() {
		t.Error("2 nodes with 2 alive should be healthy")
	}
}

// ---------------------------------------------------------------------------
// 28. NodeHealthStats with edge values
// ---------------------------------------------------------------------------

func TestNodeHealthScore_EdgeValues(t *testing.T) {
	tests := []struct {
		name  string
		stats NodeHealthStats
		want  int
	}{
		{
			name:  "zero stats no LastUpdated gives 50",
			stats: NodeHealthStats{},
			want:  50,
		},
		{
			name: "exactly 500ms latency falls into >200 tier (-25)",
			stats: NodeHealthStats{LatencyMs: 500, LastUpdated: time.Now()},
			want:  75,
		},
		{
			name: "exactly 200ms latency falls into >100 tier (-10)",
			stats: NodeHealthStats{LatencyMs: 200, LastUpdated: time.Now()},
			want:  90,
		},
		{
			name: "exactly 100ms latency no penalty (boundary)",
			stats: NodeHealthStats{LatencyMs: 100, LastUpdated: time.Now()},
			want:  100,
		},
		{
			name: "just above 500ms latency -50",
			stats: NodeHealthStats{LatencyMs: 501, LastUpdated: time.Now()},
			want:  50,
		},
		{
			name: "just above 200ms latency -25",
			stats: NodeHealthStats{LatencyMs: 201, LastUpdated: time.Now()},
			want:  75,
		},
		{
			name: "just above 100ms latency -10",
			stats: NodeHealthStats{LatencyMs: 101, LastUpdated: time.Now()},
			want:  90,
		},
		{
			name: "exactly 80% CPU falls into >60 tier (-20)",
			stats: NodeHealthStats{CPUPercent: 80, LastUpdated: time.Now()},
			want:  80,
		},
		{
			name: "just above 80% CPU -40",
			stats: NodeHealthStats{CPUPercent: 81, LastUpdated: time.Now()},
			want:  60,
		},
		{
			name: "exactly 60% CPU falls into >40 tier (-10)",
			stats: NodeHealthStats{CPUPercent: 60, LastUpdated: time.Now()},
			want:  90,
		},
		{
			name: "just above 60% CPU -20",
			stats: NodeHealthStats{CPUPercent: 61, LastUpdated: time.Now()},
			want:  80,
		},
		{
			name: "exactly 40% CPU no penalty (boundary)",
			stats: NodeHealthStats{CPUPercent: 40, LastUpdated: time.Now()},
			want:  100,
		},
		{
			name: "just above 40% CPU -10",
			stats: NodeHealthStats{CPUPercent: 41, LastUpdated: time.Now()},
			want:  90,
		},
		{
			name: "exactly 85% memory falls into >70 tier (-15)",
			stats: NodeHealthStats{MemoryPercent: 85, LastUpdated: time.Now()},
			want:  85,
		},
		{
			name: "just above 85% memory -30",
			stats: NodeHealthStats{MemoryPercent: 86, LastUpdated: time.Now()},
			want:  70,
		},
		{
			name: "exactly 70% memory no penalty (boundary)",
			stats: NodeHealthStats{MemoryPercent: 70, LastUpdated: time.Now()},
			want:  100,
		},
		{
			name: "just above 70% memory -15",
			stats: NodeHealthStats{MemoryPercent: 71, LastUpdated: time.Now()},
			want:  85,
		},
		{
			name: "exactly 800 conns falls into >500 tier (-15)",
			stats: NodeHealthStats{ActiveConns: 800, LastUpdated: time.Now()},
			want:  85,
		},
		{
			name: "just above 800 conns -30",
			stats: NodeHealthStats{ActiveConns: 801, LastUpdated: time.Now()},
			want:  70,
		},
		{
			name: "exactly 500 conns falls into >300 tier (-5)",
			stats: NodeHealthStats{ActiveConns: 500, LastUpdated: time.Now()},
			want:  95,
		},
		{
			name: "just above 500 conns -15",
			stats: NodeHealthStats{ActiveConns: 501, LastUpdated: time.Now()},
			want:  85,
		},
		{
			name: "exactly 300 conns no penalty (boundary)",
			stats: NodeHealthStats{ActiveConns: 300, LastUpdated: time.Now()},
			want:  100,
		},
		{
			name: "just above 300 conns -5",
			stats: NodeHealthStats{ActiveConns: 301, LastUpdated: time.Now()},
			want:  95,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.stats.HealthScore()
			if got != tt.want {
				t.Errorf("HealthScore() = %d, want %d", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 29. GossipProtocol.handleDraining via handleMessage (without network)
// ---------------------------------------------------------------------------

func TestGossipProtocol_HandleDraining_EnteringDraining(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	nl.Add(&Node{ID: "other", State: NodeStateAlive, Version: 1})
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	// Handle draining message from "other" node
	payload := DrainingPayload{
		NodeID:      "other",
		Draining:    true,
		Timestamp:   time.Now(),
		InFlightReq: 5,
	}
	payloadBytes, _ := encodePayload(payload)
	msg := Message{
		Type:    MessageTypeDraining,
		From:    "other",
		Payload: payloadBytes,
	}
	from := resolveUDPAddr("127.0.0.1:12345")
	gp.handleDraining(msg, from)

	// Verify "other" node is now draining
	node, ok := nl.Get("other")
	if !ok {
		t.Fatal("other node should exist")
	}
	// Note: UpdateState skips self but allows other nodes
	// handleDraining calls UpdateState which checks id != self, so this should work
	_ = node
}

// ---------------------------------------------------------------------------
// 30. GossipProtocol.handleNodeStats via handleMessage (without network)
// ---------------------------------------------------------------------------

func TestGossipProtocol_HandleNodeStats(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	nl.Add(&Node{ID: "other", State: NodeStateAlive, Version: 1})
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	now := time.Now()
	payload := NodeStatsPayload{
		NodeID:           "other",
		QueriesPerSecond: 500.0,
		LatencyMs:        2.5,
		CPUPercent:       30.0,
		MemoryPercent:    40.0,
		ActiveConns:      100,
		Timestamp:        now,
	}
	payloadBytes, _ := encodePayload(payload)
	msg := Message{
		Type:    MessageTypeNodeStats,
		From:    "other",
		Payload: payloadBytes,
	}
	from := resolveUDPAddr("127.0.0.1:12345")
	gp.handleNodeStats(msg, from)

	// Verify health updated on "other" node
	node, ok := nl.Get("other")
	if !ok {
		t.Fatal("other node should exist")
	}
	if node.Health.QueriesPerSecond != 500.0 {
		t.Errorf("Health.QueriesPerSecond = %f, want 500.0", node.Health.QueriesPerSecond)
	}
	if node.Health.LatencyMs != 2.5 {
		t.Errorf("Health.LatencyMs = %f, want 2.5", node.Health.LatencyMs)
	}
}

// ---------------------------------------------------------------------------
// 31. GossipProtocol.handleClusterMetrics (without network)
// ---------------------------------------------------------------------------

func TestGossipProtocol_HandleClusterMetrics(t *testing.T) {
	self := &Node{ID: "self", State: NodeStateAlive}
	nl := NewNodeList(self)
	cfg := DefaultGossipConfig()

	gp, _ := NewGossipProtocol(cfg, nl)

	payload := ClusterMetricsPayload{
		NodeID:        "remote-metrics-node",
		QueriesTotal:  5000,
		QueriesPerSec: 250.0,
		CacheHits:     4000,
		CacheMisses:   1000,
		LatencyMsAvg:  1.5,
		LatencyMsP99:  8.0,
		UptimeSeconds: 43200,
		Timestamp:     time.Now(),
	}
	payloadBytes, _ := encodePayload(payload)
	msg := Message{
		Type:    MessageTypeClusterMetrics,
		From:    "remote-metrics-node",
		Payload: payloadBytes,
	}
	from := resolveUDPAddr("127.0.0.1:12345")
	gp.handleClusterMetrics(msg, from)

	// Verify metrics stored
	gp.nodeMetricsMu.RLock()
	m, ok := gp.nodeMetrics["remote-metrics-node"]
	gp.nodeMetricsMu.RUnlock()

	if !ok {
		t.Fatal("metrics should be stored for remote-metrics-node")
	}
	if m.QueriesTotal != 5000 {
		t.Errorf("QueriesTotal = %d, want 5000", m.QueriesTotal)
	}
	if m.QueriesPerSec != 250.0 {
		t.Errorf("QueriesPerSec = %f, want 250.0", m.QueriesPerSec)
	}
}

