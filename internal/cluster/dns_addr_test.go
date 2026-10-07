package cluster

// F562 (P2-G1): nodes advertise their DNS (TCP) address in cluster metadata;
// in Raft mode the leader's address reaches followers via AppendEntries.

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

func TestCluster_DNSAddr_F562(t *testing.T) {
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)

	swim, err := New(Config{Enabled: true, AllowInsecureCluster: true, NodeID: "s1", BindAddr: "127.0.0.1",
		GossipPort: 0, ConsensusMode: ConsensusSWIM, DNSAddr: "192.0.2.1:53"}, logger, nil)
	if err != nil {
		t.Fatalf("New swim: %v", err)
	}
	if got := swim.AdvertisedDNSAddr(); got != "192.0.2.1:53" {
		t.Errorf("swim AdvertisedDNSAddr = %q", got)
	}
	if _, _, ok := swim.LeaderDNSAddr(); ok {
		t.Errorf("swim LeaderDNSAddr ok = true, want false (Raft only)")
	}
	if n := swim.GetNodes(); len(n) != 1 || n[0].Meta.DNSAddr != "192.0.2.1:53" {
		t.Errorf("swim self meta = %+v, want DNSAddr 192.0.2.1:53", n)
	}

	if testing.Short() {
		t.Skip("starts a single-node Raft cluster")
	}
	c, err := New(Config{Enabled: true, AllowInsecureCluster: true, NodeID: "r1", BindAddr: "127.0.0.1",
		GossipPort: 0, ConsensusMode: ConsensusRaft, DataDir: t.TempDir(), DNSAddr: "192.0.2.2:5354",
		Peers: []PeerConfig{{NodeID: "r1", Addr: "127.0.0.1:0"}}}, logger, nil)
	if err != nil {
		t.Fatalf("New raft: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = c.Stop() }()
	deadline := time.Now().Add(10 * time.Second)
	for !c.IsLeader() {
		if time.Now().After(deadline) {
			t.Fatal("single-node Raft never elected itself")
		}
		time.Sleep(10 * time.Millisecond) // waiting for election, not ordering
	}
	if id, addr, ok := c.LeaderDNSAddr(); !ok || id != "r1" || addr != "192.0.2.2:5354" {
		t.Errorf("leader LeaderDNSAddr = (%q, %q, %v), want (r1, 192.0.2.2:5354, true)", id, addr, ok)
	}
	for _, m := range c.GetTopologyMembers() {
		if m.ID == "r1" && m.Meta.DNSAddr != "192.0.2.2:5354" {
			t.Errorf("topology self DNSAddr = %q", m.Meta.DNSAddr)
		}
	}
}
