package config

import (
	"fmt"
	"reflect"
)

// ResolutionConfig contains DNS resolution settings.
type ResolutionConfig struct {
	// Enable recursive resolution
	Recursive bool `yaml:"recursive"`

	// AuthoritativeOnly hard-disables every code path that would forward a
	// query off this server (recursive resolver, upstream forwarder, and
	// out-of-zone CNAME chase). Names not covered by a local zone return
	// REFUSED instead of being resolved elsewhere. Set true for any
	// deployment that intends to be a pure authoritative DNS server — this
	// closes the cache-poisoning / query-proxy escape hatch that opens
	// when a malicious or compromised zone contains a CNAME pointing at an
	// attacker-controlled name outside the zone.
	AuthoritativeOnly bool `yaml:"authoritative_only"`

	// Root hints file for recursive resolution
	RootHints string `yaml:"root_hints"`

	// Maximum recursion depth
	MaxDepth int `yaml:"max_depth"`

	// Timeout for queries
	Timeout string `yaml:"timeout"`

	// EDNS0 UDP buffer size
	EDNS0BufferSize int `yaml:"edns0_buffer_size"`

	// QNAME Minimization (RFC 7816) — reduces privacy leakage
	QnameMinimization bool `yaml:"qname_minimization"`

	// DNS 0x20 encoding (Vixie/Dagon) — randomizes query name case for spoofing resistance
	Use0x20 bool `yaml:"use_0x20"`
}

// UpstreamConfig contains upstream DNS server settings.
type UpstreamConfig struct {
	// List of upstream servers
	Servers []string `yaml:"servers"`

	// Strategy for selecting upstream (random, round_robin, fastest)
	Strategy string `yaml:"strategy"`

	// Health check interval
	HealthCheck string `yaml:"health_check"`

	// Failover timeout
	FailoverTimeout string `yaml:"failover_timeout"`

	// Anycast groups for advanced load balancing
	AnycastGroups []AnycastGroupConfig `yaml:"anycast_groups"`

	// Topology configuration for this instance
	Topology TopologyConfig `yaml:"topology"`
}

// AnycastGroupConfig holds configuration for an anycast group.
type AnycastGroupConfig struct {
	// Anycast IP address shared by all backends
	AnycastIP string `yaml:"anycast_ip"`

	// Backend servers in this group
	Backends []AnycastBackendConfig `yaml:"backends"`

	// Health check interval (overrides global setting)
	HealthCheck string `yaml:"health_check"`
}

// AnycastBackendConfig holds configuration for an anycast backend.
type AnycastBackendConfig struct {
	// Physical IP address of the backend
	PhysicalIP string `yaml:"physical_ip"`

	// Port (default: 53)
	Port int `yaml:"port"`

	// Region identifier (e.g., "us-east-1")
	Region string `yaml:"region"`

	// Zone identifier within region (e.g., "a", "b")
	Zone string `yaml:"zone"`

	// Weight for load balancing (0-100, default: 100)
	Weight int `yaml:"weight"`
}

// TopologyConfig holds topology information for routing decisions.
type TopologyConfig struct {
	// Region identifier (e.g., "us-east-1")
	Region string `yaml:"region"`

	// Zone identifier within region (e.g., "a", "b")
	Zone string `yaml:"zone"`

	// Weight for load balancing (0-100)
	Weight int `yaml:"weight"`
}

func unmarshalResolution(node *Node, cfg *ResolutionConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Recursive = getBool(node, "recursive", cfg.Recursive)
	cfg.AuthoritativeOnly = getBool(node, "authoritative_only", cfg.AuthoritativeOnly)
	cfg.RootHints = node.GetString("root_hints")
	var err error
	if cfg.MaxDepth, err = getRequiredInt(node, "max_depth", cfg.MaxDepth); err != nil {
		return err
	}
	cfg.Timeout = node.GetString("timeout")
	if cfg.Timeout == "" {
		cfg.Timeout = "5s"
	}
	if cfg.EDNS0BufferSize, err = getRequiredInt(node, "edns0_buffer_size", cfg.EDNS0BufferSize); err != nil {
		return err
	}
	cfg.QnameMinimization = getBool(node, "qname_minimization", cfg.QnameMinimization)
	cfg.Use0x20 = getBool(node, "use_0x20", cfg.Use0x20)

	return nil
}

func unmarshalUpstream(node *Node, cfg *UpstreamConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Servers = getStringSlice(node, "servers", cfg.Servers)
	cfg.Strategy = node.GetString("strategy")
	if cfg.Strategy == "" {
		cfg.Strategy = "random"
	}
	cfg.HealthCheck = node.GetString("health_check")
	if cfg.HealthCheck == "" {
		cfg.HealthCheck = "30s"
	}
	cfg.FailoverTimeout = node.GetString("failover_timeout")
	if cfg.FailoverTimeout == "" {
		cfg.FailoverTimeout = "5s"
	}

	// Parse topology configuration
	if topologyNode := node.Get("topology"); topologyNode != nil {
		cfg.Topology.Region = topologyNode.GetString("region")
		cfg.Topology.Zone = topologyNode.GetString("zone")
		var err error
		if cfg.Topology.Weight, err = getRequiredInt(topologyNode, "weight", 100); err != nil {
			return fmt.Errorf("topology: %w", err)
		}
	}

	// Parse anycast groups. listItems makes a mis-shaped section or item a
	// load error (AGENTS.md: strict loading, never silent defaults). The
	// previous manual loops required NodeSequence at both levels and
	// skipped any non-mapping item, so a mapping-shaped anycast_groups
	// section, a scalar group item, a mapping-shaped backends list or a
	// scalar backend entry all vanished: upstream load balancing silently
	// ran without the configured anycast topology (or startup failed with
	// the misleading "no upstream servers configured" when anycast was
	// the only upstream source). dnssec.signing.keys, rpz.zones and
	// geodns.rules already go through listItems; anycast_groups now does
	// too, one level deep for backends.
	groupItems, err := listItems(node, "anycast_groups", reflect.TypeOf(AnycastGroupConfig{}))
	if err != nil {
		return fmt.Errorf("upstream: %w", err)
	}
	for _, groupNode := range groupItems {
		var group AnycastGroupConfig
		group.AnycastIP = groupNode.GetString("anycast_ip")
		group.HealthCheck = groupNode.GetString("health_check")

		// Parse backends (same strict contract, one level deeper).
		backendItems, err := listItems(groupNode, "backends", reflect.TypeOf(AnycastBackendConfig{}))
		if err != nil {
			return fmt.Errorf("anycast_groups: %w", err)
		}
		for _, backendNode := range backendItems {
			var backend AnycastBackendConfig
			backend.PhysicalIP = backendNode.GetString("physical_ip")
			var err error
			if backend.Port, err = getRequiredInt(backendNode, "port", 53); err != nil {
				return fmt.Errorf("anycast_groups backend: %w", err)
			}
			backend.Region = backendNode.GetString("region")
			backend.Zone = backendNode.GetString("zone")
			if backend.Weight, err = getRequiredInt(backendNode, "weight", 100); err != nil {
				return fmt.Errorf("anycast_groups backend: %w", err)
			}
			group.Backends = append(group.Backends, backend)
		}

		cfg.AnycastGroups = append(cfg.AnycastGroups, group)
	}

	return nil
}
