package config

import "testing"

// TestRound050ClusterPeersShape pins the AGENTS.md strict-loading contract
// for cluster.peers at both the section and the entry level: a peers section
// written as a mapping (missing "- ") and a peer entry without node_id are
// load errors, never silent drops. unmarshalCluster previously required
// NodeSequence and silently skipped entries with an empty node_id, so a
// typo'd peers section or an incomplete peer entry shrank the configured
// Raft peer set with no config error — initRaft only rejects a completely
// empty list (internal/cluster/cluster.go:278 "raft consensus requires at
// least one peer"), so the surviving peers silently formed a smaller quorum
// than the operator documented. dnssec.signing.keys, rpz.zones, geodns.rules
// and upstream.anycast_groups already go through listItems and make mis-
// shaped sections/items loud errors; cluster.peers now does the same and
// additionally rejects a peer entry without the required node_id.
//
// Control: the documented shape parses to one peer.

func TestRound050ClusterPeersShape(t *testing.T) {
	// Control: the documented shape parses to one peer.
	cfg, err := UnmarshalYAML("cluster:\n  enabled: true\n  consensus_mode: raft\n  peers:\n    - node_id: node-b\n      addr: 10.0.0.2:7000\n")
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	if len(cfg.Cluster.Peers) != 1 || cfg.Cluster.Peers[0].NodeID != "node-b" ||
		cfg.Cluster.Peers[0].Addr != "10.0.0.2:7000" {
		t.Fatalf("control: peers = %+v", cfg.Cluster.Peers)
	}

	// Shape error 1: peers written as a mapping (missing "- ").
	// Previously: silent skip, empty peer set.
	if _, err = UnmarshalYAML("cluster:\n  enabled: true\n  peers:\n    node_id: node-b\n    addr: 10.0.0.2:7000\n"); err == nil {
		t.Fatalf("FAIL: mapping-shaped cluster.peers accepted silently (want a load error naming peers, per AGENTS.md strict loading)")
	}

	// Shape error 2: a non-mapping item inside the peers sequence.
	// Previously: silent skip.
	if _, err = UnmarshalYAML("cluster:\n  enabled: true\n  peers:\n    - node-b\n"); err == nil {
		t.Fatalf("FAIL: scalar cluster.peers item accepted silently (want a load error)")
	}

	// Field error: a peer entry without node_id. Previously: silently
	// dropped from the peer set — silent Raft quorum shrinkage.
	if _, err = UnmarshalYAML("cluster:\n  enabled: true\n  peers:\n    - addr: 10.0.0.2:7000\n"); err == nil {
		t.Fatalf("FAIL: cluster.peers entry without node_id accepted silently (want a load error naming node_id)")
	}
}
