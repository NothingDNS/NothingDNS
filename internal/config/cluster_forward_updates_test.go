package config

// F569 (P2-G2): cluster.forward_updates is opt-in (default false) and, in
// Raft mode, requires an advertisable DNS address.

import (
	"strings"
	"testing"
)

func TestUnmarshalYAML_ClusterForwardUpdates_F569(t *testing.T) {
	cfg, err := UnmarshalYAML("cluster:\n  enabled: true\n  forward_updates: true\n")
	if err != nil {
		t.Fatalf("UnmarshalYAML: %v", err)
	}
	if !cfg.Cluster.ForwardUpdates {
		t.Error("forward_updates: true not parsed")
	}
	cfg, err = UnmarshalYAML("cluster:\n  enabled: true\n")
	if err != nil {
		t.Fatalf("UnmarshalYAML: %v", err)
	}
	if cfg.Cluster.ForwardUpdates {
		t.Error("forward_updates must default to false")
	}
	if DefaultConfig().Cluster.ForwardUpdates {
		t.Error("DefaultConfig: forward_updates must be false")
	}
}

func forwardUpdatesErr(cfg *Config) string {
	for _, e := range cfg.validateCluster() {
		if strings.Contains(e, "forward_updates") {
			return e
		}
	}
	return ""
}

func TestValidate_ClusterForwardUpdates_F569(t *testing.T) {
	cases := []struct {
		name      string
		mode      string
		forward   bool
		bind, tcp []string
		port      int
		advertise string
		wantErr   bool
	}{
		{"off, wildcard", "raft", false, []string{"0.0.0.0"}, nil, 53, "", false},
		{"on, concrete bind", "raft", true, []string{"192.0.2.1"}, nil, 53, "", false},
		{"on, concrete bind with port", "raft", true, []string{"192.0.2.1:5354"}, nil, 53, "", false},
		{"on, concrete tcp_bind", "raft", true, []string{"0.0.0.0"}, []string{"192.0.2.2"}, 53, "", false},
		{"on, explicit advertise", "raft", true, []string{"0.0.0.0"}, nil, 53, "192.0.2.9:53", false},
		{"on, wildcard v4", "raft", true, []string{"0.0.0.0"}, nil, 53, "", true},
		{"on, wildcard v6", "raft", true, []string{"::"}, nil, 53, "", true},
		{"on, no bind", "raft", true, nil, nil, 53, "", true},
		{"on, wildcard hides same-port concrete", "raft", true, []string{"0.0.0.0", "192.0.2.3"}, nil, 53, "", true},
		{"on, port zero", "raft", true, []string{"192.0.2.1:0"}, nil, 53, "", true},
		{"on, default mode is raft", "", true, []string{"0.0.0.0"}, nil, 53, "", true},
		{"on, swim mode (no forwarding)", "swim", true, []string{"0.0.0.0"}, nil, 53, "", false},
	}
	for _, tc := range cases {
		cfg := DefaultConfig()
		cfg.Cluster.Enabled = true
		cfg.Cluster.ConsensusMode = tc.mode
		cfg.Cluster.ForwardUpdates = tc.forward
		cfg.Cluster.DNSAdvertiseAddr = tc.advertise
		cfg.Server.Bind, cfg.Server.TCPBind, cfg.Server.Port = tc.bind, tc.tcp, tc.port
		if got := forwardUpdatesErr(cfg) != ""; got != tc.wantErr {
			t.Errorf("%s: error=%v (%q), want error=%v", tc.name, got, forwardUpdatesErr(cfg), tc.wantErr)
		}
	}
}
