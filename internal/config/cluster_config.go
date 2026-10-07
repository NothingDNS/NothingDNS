package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
)

const maxRPCCACertFileSize = 1 << 20

// StorageConfig groups the at-rest data-store settings the daemon
// understands. SECURITY-REPORT.md L-6 added EncryptionKey here so
// operators can opt the on-disk KV file into AES-256-GCM
// confidentiality without touching any other subsystem's keys.
type StorageConfig struct {
	// DataDir is where the embedded persistent database stores data.db.
	// Empty keeps the historical behavior: use zone_dir, or "." when
	// zone_dir is also empty.
	DataDir string `yaml:"data_dir"`

	// EncryptionKey, when set, AES-256-GCM-encrypts the KV data file
	// at rest (32 bytes, hex-encoded). Empty disables encryption
	// (existing plain on-disk files keep loading). Use a DIFFERENT
	// key from cluster.encryption_key and cluster.snapshot_encryption_key
	// — those protect different data classes.
	EncryptionKey string `yaml:"encryption_key"`
}

type ClusterConfig struct {
	// Enable clustering
	Enabled bool `yaml:"enabled"`

	// Node ID (auto-generated if empty)
	NodeID string `yaml:"node_id"`

	// Bind address for gossip protocol
	BindAddr string `yaml:"bind_addr"`

	// Gossip port (default: 7946)
	GossipPort int `yaml:"gossip_port"`

	// Region for topology awareness
	Region string `yaml:"region"`

	// Zone for topology awareness
	Zone string `yaml:"zone"`

	// Weight for load balancing
	Weight int `yaml:"weight"`

	// Seed nodes to join (format: "host:port")
	SeedNodes []string `yaml:"seed_nodes"`

	// Enable cache synchronization
	CacheSync bool `yaml:"cache_sync"`

	// Encryption key for gossip traffic (32 bytes, hex-encoded).
	// When set, all inter-node communication is encrypted with AES-256-GCM.
	EncryptionKey string `yaml:"encryption_key"`

	// SnapshotEncryptionKey, when set, AES-256-GCM-encrypts Raft
	// snapshot files at rest (32 bytes, hex-encoded — same format
	// as EncryptionKey above). See SECURITY-REPORT.md L-6 and
	// internal/cluster/raft/snapshot.go NewSnapshotterEncrypted.
	// Must be a DIFFERENT key from EncryptionKey (key separation:
	// gossip is a network-channel key, snapshots are an at-rest
	// data-encryption key; conflating them widens the leak blast
	// radius if either is compromised). Validated at config-load.
	SnapshotEncryptionKey string `yaml:"snapshot_encryption_key"`

	// AllowInsecureCluster permits starting a cluster without encryption_key.
	// Default: false. Only enable for single-node dev setups; the gossip
	// channel carries zone updates and config sync, so plaintext is forgeable.
	AllowInsecureCluster bool `yaml:"allow_insecure"`

	// Consensus mode for cluster coordination: "raft" (default) or "swim".
	// Raft provides strong consistency for zone replication.
	// SWIM provides eventual consistency with gossip-based membership.
	ConsensusMode string `yaml:"consensus_mode"`

	// DataDir is where Raft persists its WAL, HardState and snapshots.
	// Each node needs its own directory. Defaults to
	// /var/lib/nothingdns/cluster when empty.
	DataDir string `yaml:"data_dir"`

	// Peers lists the OTHER Raft cluster members (this node must NOT be in
	// the list — it's filtered out anyway). Each peer needs a node_id and a
	// reachable host:port RPC address. Required for multi-node Raft.
	Peers []ClusterPeerConfig `yaml:"peers"`

	// DNSAdvertiseAddr is the DNS TCP host:port this node advertises to
	// the cluster (Raft: carried in the leader's AppendEntries) so followers
	// can forward RFC 2136 UPDATEs to the leader. Empty = derive it from the
	// first concrete server.tcp_bind/bind address; a wildcard-only bind
	// (0.0.0.0 / ::) advertises nothing unless this is set. Must be a
	// concrete host:port that the other nodes can reach.
	DNSAdvertiseAddr string `yaml:"dns_advertise_addr"`

	// ForwardUpdates makes a Raft follower forward TSIG-signed RFC 2136
	// UPDATEs for zones it serves to the leader (RFC 2136 §6) instead of
	// answering REFUSED. Default false (BIND also keeps update forwarding
	// off): address-based policy on the leader (tsig_keys allowed_cidrs,
	// ACLs) sees the follower's IP for forwarded UPDATEs, not the client's.
	// In Raft mode, true requires an advertisable DNS address
	// (dns_advertise_addr or a concrete server.tcp_bind/bind address).
	ForwardUpdates bool `yaml:"forward_updates"`

	// RPC TLS configuration for Raft consensus traffic.
	// When TLSCertFile/TLSKeyFile are set, Raft RPC uses TLS.
	RPC RPCConfig `yaml:"rpc"`
}

// ClusterPeerConfig identifies one Raft cluster peer.
type ClusterPeerConfig struct {
	NodeID string `yaml:"node_id"`
	Addr   string `yaml:"addr"` // host:port the peer's Raft RPC server listens on
}

// RPCConfig contains TLS settings for cluster RPC traffic (Raft consensus).
type RPCConfig struct {
	// Enable TLS for Raft RPC
	Enabled bool `yaml:"enabled"`

	// Certificate file for TLS
	TLSCertFile string `yaml:"tls_cert_file"`

	// Key file for TLS
	TLSKeyFile string `yaml:"tls_key_file"`

	// CA file for client certificate verification (optional, for mTLS)
	TLSCACertFile string `yaml:"tls_ca_cert_file"`

	// Minimum TLS version (10=TLS1.0, 11=TLS1.1, 12=TLS1.2, 13=TLS1.3)
	// Default: 12 (TLS1.2)
	MinTLSVersion int `yaml:"min_tls_version"`
}

func unmarshalCluster(node *Node, cfg *ClusterConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	cfg.NodeID = node.GetString("node_id")
	cfg.BindAddr = node.GetString("bind_addr")
	var err error
	if cfg.GossipPort, err = getRequiredInt(node, "gossip_port", cfg.GossipPort); err != nil {
		return err
	}
	cfg.Region = node.GetString("region")
	cfg.Zone = node.GetString("zone")
	if cfg.Weight, err = getRequiredInt(node, "weight", cfg.Weight); err != nil {
		return err
	}
	cfg.CacheSync = getBool(node, "cache_sync", cfg.CacheSync)
	cfg.EncryptionKey = node.GetString("encryption_key")
	cfg.SnapshotEncryptionKey = node.GetString("snapshot_encryption_key")
	cfg.AllowInsecureCluster = getBool(node, "allow_insecure", cfg.AllowInsecureCluster)
	cfg.DNSAdvertiseAddr = node.GetString("dns_advertise_addr")
	cfg.ForwardUpdates = getBool(node, "forward_updates", cfg.ForwardUpdates)

	// Parse consensus mode (default: raft)
	cfg.ConsensusMode = getString(node, "consensus_mode", "raft")
	if cfg.ConsensusMode == "" {
		cfg.ConsensusMode = "raft"
	}

	// Parse RPC TLS configuration
	if rpcNode := node.Get("rpc"); rpcNode != nil {
		cfg.RPC.Enabled = getBool(rpcNode, "enabled", cfg.RPC.Enabled)
		cfg.RPC.TLSCertFile = rpcNode.GetString("tls_cert_file")
		cfg.RPC.TLSKeyFile = rpcNode.GetString("tls_key_file")
		cfg.RPC.TLSCACertFile = rpcNode.GetString("tls_ca_cert_file")
		if cfg.RPC.MinTLSVersion, err = getRequiredInt(rpcNode, "min_tls_version", 12); err != nil {
			return fmt.Errorf("rpc: %w", err)
		}
	}

	// Parse seed nodes
	if seedNodesNode := node.Get("seed_nodes"); seedNodesNode != nil {
		if seedNodesNode.Type == NodeSequence {
			cfg.SeedNodes = seedNodesNode.getStringSlice()
		} else if seedNodesNode.Type == NodeScalar {
			cfg.SeedNodes = []string{seedNodesNode.Value}
		}
	}

	// Raft data directory and peer list.
	cfg.DataDir = node.GetString("data_dir")
	if peersNode := node.Get("peers"); peersNode != nil && peersNode.Type == NodeSequence {
		for _, pn := range peersNode.Children {
			p := ClusterPeerConfig{
				NodeID: pn.GetString("node_id"),
				Addr:   pn.GetString("addr"),
			}
			if p.NodeID != "" {
				cfg.Peers = append(cfg.Peers, p)
			}
		}
	}

	return nil
}

// NewTLSConfig creates a tls.Config for Raft RPC traffic from the RPCConfig.
// Returns nil if TLS is not enabled.
func (c *RPCConfig) NewTLSConfig() (*tls.Config, error) {
	if !c.Enabled {
		return nil, nil
	}

	tlsCert, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load RPC TLS certificate: %w", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	if c.MinTLSVersion == 13 {
		config.MinVersion = tls.VersionTLS13
	}

	if c.TLSCACertFile != "" {
		caCert, err := readRPCCACertFile(c.TLSCACertFile)
		if err != nil {
			return nil, fmt.Errorf("read RPC CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("parse RPC CA certificate: %w", err)
		}
		// ClientCAs gates incoming Raft RPC connections (server side).
		// RootCAs gates outgoing peer dials (client side); without it
		// tls.Dial falls back to the host's system trust store, so any
		// cert chained to a public CA (Let's Encrypt, DigiCert, etc.)
		// whose SAN matches a peer address could impersonate that peer
		// and inject log entries. The same private CA pool is correct
		// for both directions — Raft peers authenticate each other
		// against the cluster-operator-issued CA only.
		config.ClientCAs = caCertPool
		config.RootCAs = caCertPool
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return config, nil
}

func readRPCCACertFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxRPCCACertFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRPCCACertFileSize {
		return nil, fmt.Errorf("RPC CA certificate file exceeds %d bytes", maxRPCCACertFileSize)
	}
	return data, nil
}
