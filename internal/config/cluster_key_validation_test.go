package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/cluster/raft"
)

// F602: config validation must accept exactly the cluster.encryption_key
// values the gossip and Raft runtimes accept (raw value, hex-decoded, 32
// bytes). Before the fix a base64 or wrong-length key passed Validate /
// -validate-config and the node then failed at cluster start.
func TestValidate_ClusterEncryptionKeyMatchesRuntime_F602(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i*37 + 11)
	}
	lower := hex.EncodeToString(raw)
	cases := []struct {
		name  string
		key   string
		valid bool
	}{
		{"hex lower 64", lower, true},
		{"hex upper 64", strings.ToUpper(lower), true},
		{"base64 of 32 bytes", base64.StdEncoding.EncodeToString(raw), false},
		{"hex 63 chars", lower[:63], false},
		{"hex 62 chars (31 bytes)", lower[:62], false},
		{"hex 66 chars (33 bytes)", lower + "ab", false},
		{"inner space", lower[:32] + " " + lower[32:], false},
		{"trailing space (quoted)", lower + " ", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := UnmarshalYAMLWithEnv(fmt.Sprintf("cluster:\n  enabled: true\n  node_id: n1\n  encryption_key: %q\n", tc.key), false)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if cfg.Cluster.EncryptionKey != tc.key {
				t.Fatalf("parsed key %q, want %q", cfg.Cluster.EncryptionKey, tc.key)
			}
			var keyErrs []string
			for _, e := range cfg.Validate() {
				if strings.Contains(e, "cluster.encryption_key") {
					keyErrs = append(keyErrs, e)
				}
			}
			if tc.valid && len(keyErrs) != 0 {
				t.Fatalf("valid key rejected: %v", keyErrs)
			}
			if !tc.valid {
				if len(keyErrs) == 0 {
					t.Fatal("invalid key passed validation")
				}
				msg := strings.Join(keyErrs, "\n")
				if !strings.Contains(msg, "64 hex characters") || !strings.Contains(msg, "openssl rand -hex 32") {
					t.Fatalf("error does not name the expected format: %s", msg)
				}
				if strings.Contains(msg, tc.key) {
					t.Fatalf("error echoes the secret: %s", msg)
				}
			}

			// Parity with the real runtimes: validation verdict == runtime verdict.
			_, gossipErr := cluster.New(cluster.Config{NodeID: "n1", BindAddr: "127.0.0.1", EncryptionKey: cfg.Cluster.EncryptionKey, ConsensusMode: cluster.ConsensusSWIM}, nil, nil)
			_, raftErr := raft.NewClusterIntegration("n1", nil, nil, "127.0.0.1:0", t.TempDir(), cfg.Cluster.EncryptionKey, "", nil, nil)
			if runtimeOK := gossipErr == nil && raftErr == nil; runtimeOK != tc.valid {
				t.Fatalf("runtime ok=%v (gossip=%v raft=%v), validation valid=%v", runtimeOK, gossipErr, raftErr, tc.valid)
			}
		})
	}
}

// F602: a disabled cluster does not use the key, so its format is not enforced.
func TestValidate_ClusterEncryptionKeyIgnoredWhenDisabled_F602(t *testing.T) {
	c := DefaultConfig()
	c.Cluster.Enabled = false
	c.Cluster.EncryptionKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, e := range c.Validate() {
		if strings.Contains(e, "cluster.encryption_key") {
			t.Fatalf("disabled cluster key validated: %s", e)
		}
	}
}
