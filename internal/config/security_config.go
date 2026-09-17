package config

import (
	"fmt"
	"strconv"
)

// DNSSECConfig contains DNSSEC settings.
type DNSSECConfig struct {
	// Enable DNSSEC validation
	Enabled bool `yaml:"enabled"`

	// Trust anchor file
	TrustAnchor string `yaml:"trust_anchor"`

	// Ignore signature expiration (for testing)
	IgnoreTime bool `yaml:"ignore_time"`

	// Require DNSSEC for all queries (fail if validation unavailable)
	RequireDNSSEC bool `yaml:"require_dnssec"`

	// Zone signing configuration
	Signing SigningConfig `yaml:"signing"`
}

// SigningConfig holds zone signing parameters.
type SigningConfig struct {
	// Enable zone signing
	Enabled bool `yaml:"enabled"`

	// Private key files (one per algorithm)
	Keys []KeyConfig `yaml:"keys"`

	// NSEC3 parameters (if empty, use NSEC)
	NSEC3 *NSEC3Config `yaml:"nsec3"`

	// Signature validity period (e.g., "30d")
	SignatureValidity string `yaml:"signature_validity"`
}

// KeyConfig holds a DNSSEC key file configuration.
type KeyConfig struct {
	// Private key file (PEM format)
	PrivateKey string `yaml:"private_key"`

	// Key type: ksk or zsk
	Type string `yaml:"type"`

	// Algorithm (8=RSASHA256, 13=ECDSAP256SHA256, etc.)
	Algorithm uint8 `yaml:"algorithm"`
}

// NSEC3Config holds NSEC3 parameters for zone signing.
type NSEC3Config struct {
	// Number of hash iterations
	Iterations uint16 `yaml:"iterations"`

	// Salt (hex string, optional)
	Salt string `yaml:"salt"`

	// Opt-out (for insecure delegations)
	OptOut bool `yaml:"opt_out"`
}

// ACLRule defines an access control rule.
type ACLRule struct {
	// Rule name
	Name string `yaml:"name"`

	// Action: "allow", "deny", or "redirect"
	Action string `yaml:"action"`

	// Redirect target domain name (required when action is "redirect"); the
	// client gets a CNAME to it.
	Redirect string `yaml:"redirect"`

	// Networks: CIDRs or single IP addresses
	Networks []string `yaml:"networks"`

	// Query types this rule applies to (empty = all types)
	Types []string `yaml:"types"`
}

// RRLConfig holds Response Rate Limiting configuration.
type RRLConfig struct {
	// Enable rate limiting
	Enabled bool `yaml:"enabled"`

	// Rate limit: responses per second per subnet
	Rate int `yaml:"rate"`

	// Burst allowance
	Burst int `yaml:"burst"`

	// Maximum number of rate limit buckets
	MaxBuckets int `yaml:"max_buckets"`
}

func unmarshalDNSSEC(node *Node, cfg *DNSSECConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	cfg.TrustAnchor = node.GetString("trust_anchor")
	cfg.IgnoreTime = getBool(node, "ignore_time", cfg.IgnoreTime)
	cfg.RequireDNSSEC = getBool(node, "require_dnssec", cfg.RequireDNSSEC)

	// Parse signing configuration
	if signingNode := node.Get("signing"); signingNode != nil {
		cfg.Signing.Enabled = getBool(signingNode, "enabled", cfg.Signing.Enabled)
		cfg.Signing.SignatureValidity = signingNode.GetString("signature_validity")

		// Parse keys
		if keysNode := signingNode.Get("keys"); keysNode != nil && keysNode.Type == NodeSequence {
			for _, keyNode := range keysNode.Children {
				if keyNode.Type == NodeMapping {
					var key KeyConfig
					key.PrivateKey = keyNode.GetString("private_key")
					key.Type = keyNode.GetString("type")
					algorithm, err := getUint(keyNode, "algorithm", 0, 8)
					if err != nil {
						return err
					}
					key.Algorithm = uint8(algorithm)
					cfg.Signing.Keys = append(cfg.Signing.Keys, key)
				}
			}
		}

		// Parse NSEC3 configuration
		if nsec3Node := signingNode.Get("nsec3"); nsec3Node != nil {
			iterations, err := getUint(nsec3Node, "iterations", 0, 16)
			if err != nil {
				return err
			}
			cfg.Signing.NSEC3 = &NSEC3Config{
				Iterations: uint16(iterations),
				Salt:       nsec3Node.GetString("salt"),
				OptOut:     getBool(nsec3Node, "opt_out", false),
			}
		}
	}

	return nil
}

func getUint(node *Node, key string, defaultValue uint64, bitSize int) (uint64, error) {
	child := node.Get(key)
	if child == nil {
		return defaultValue, nil
	}
	if child.Type != NodeScalar {
		return 0, fmt.Errorf("%s: expected scalar unsigned integer", key)
	}
	value, err := strconv.ParseUint(child.Value, 10, bitSize)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid unsigned integer %q: %w", key, child.Value, err)
	}
	return value, nil
}

func unmarshalRRL(node *Node, cfg *RRLConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	var err error
	if cfg.Rate, err = getRequiredInt(node, "rate", cfg.Rate); err != nil {
		return err
	}
	if cfg.Burst, err = getRequiredInt(node, "burst", cfg.Burst); err != nil {
		return err
	}
	if cfg.MaxBuckets, err = getRequiredInt(node, "max_buckets", cfg.MaxBuckets); err != nil {
		return err
	}

	// Backward-compatible aliases used by earlier examples.
	if cfg.Rate, err = getRequiredInt(node, "rate_limit", cfg.Rate); err != nil {
		return err
	}
	if cfg.MaxBuckets, err = getRequiredInt(node, "max_table_size", cfg.MaxBuckets); err != nil {
		return err
	}

	return nil
}
