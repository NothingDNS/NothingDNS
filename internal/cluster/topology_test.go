package cluster

import (
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

func TestGetTopologyMembers_RaftIncludesPeersAndRoles(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	lnAddr := ln.Addr().String()
	_ = ln.Close()

	host, portStr, err := net.SplitHostPort(lnAddr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	cfg := Config{
		Enabled:              true,
		AllowInsecureCluster: true,
		NodeID:               "node-1",
		BindAddr:             host,
		GossipPort:           port,
		ConsensusMode:        ConsensusRaft,
		DataDir:              filepath.Join(t.TempDir(), "n1"),
		Region:               "test",
		Zone:                 "a",
		Weight:               100,
		HTTPAddr:             "127.0.0.1:8080",
		Peers: []PeerConfig{
			{NodeID: "node-2", Addr: "127.0.0.1:17947"},
		},
	}

	c, err := New(cfg, util.DefaultLogger(), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = c.Stop() }()

	deadline := time.Now().Add(3 * time.Second)
	for !c.IsLeader() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	members := c.GetTopologyMembers()
	if len(members) != 2 {
		t.Fatalf("GetTopologyMembers len = %d, want 2: %+v", len(members), members)
	}

	byID := map[string]TopologyMember{}
	for _, m := range members {
		byID[m.ID] = m
	}
	self, ok := byID["node-1"]
	if !ok {
		t.Fatal("missing node-1")
	}
	peer, ok := byID["node-2"]
	if !ok {
		t.Fatal("missing node-2")
	}
	if self.Role != "leader" && self.Role != "candidate" && self.Role != "follower" {
		t.Errorf("self role = %q, want raft role", self.Role)
	}
	if peer.Role == "" {
		t.Error("peer role should be set in raft mode")
	}
	if peer.Addr != "127.0.0.1" || peer.Port != 17947 {
		t.Errorf("peer addr = %s:%d, want 127.0.0.1:17947", peer.Addr, peer.Port)
	}

	stats := c.Stats()
	if stats.NodeCount != 2 {
		t.Errorf("Stats.NodeCount = %d, want 2", stats.NodeCount)
	}
}

func TestSplitHostPort(t *testing.T) {
	host, port := splitHostPort("10.0.0.2:7946", 1)
	if host != "10.0.0.2" || port != 7946 {
		t.Errorf("got %s:%d", host, port)
	}
	host, port = splitHostPort("bare-host", 7946)
	if host != "bare-host" || port != 7946 {
		t.Errorf("got %s:%d", host, port)
	}
}
