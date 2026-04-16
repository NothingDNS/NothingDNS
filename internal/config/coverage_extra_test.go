package config

import (
	"errors"
	"testing"
)

// ---------------------------------------------------------------------------
// unmarshalRPZ
// ---------------------------------------------------------------------------

func TestUnmarshalRPZ_Basic(t *testing.T) {
	node := &Node{
		Type: NodeMapping,
		Children: []*Node{
			{Type: NodeScalar, Value: "enabled"},
			{Type: NodeScalar, Value: "true"},
			{Type: NodeScalar, Value: "files"},
			{Type: NodeSequence, Children: []*Node{
				{Type: NodeScalar, Value: "/etc/rpz/block.rpz"},
			}},
			{Type: NodeScalar, Value: "zones"},
			{Type: NodeSequence, Children: []*Node{
				{Type: NodeMapping, Children: []*Node{
					{Type: NodeScalar, Value: "name"},
					{Type: NodeScalar, Value: "block.rpz"},
					{Type: NodeScalar, Value: "file"},
					{Type: NodeScalar, Value: "/etc/rpz/block.rpz"},
					{Type: NodeScalar, Value: "priority"},
					{Type: NodeScalar, Value: "10"},
				}},
			}},
		},
	}

	var cfg RPZConfig
	if err := unmarshalRPZ(node, &cfg); err != nil {
		t.Fatalf("unmarshalRPZ: %v", err)
	}
	if !cfg.Enabled {
		t.Error("expected Enabled=true")
	}
	if len(cfg.Files) != 1 || cfg.Files[0] != "/etc/rpz/block.rpz" {
		t.Errorf("Files = %v, want [/etc/rpz/block.rpz]", cfg.Files)
	}
	if len(cfg.Zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(cfg.Zones))
	}
	if cfg.Zones[0].Name != "block.rpz" {
		t.Errorf("Zone.Name = %q, want block.rpz", cfg.Zones[0].Name)
	}
	if cfg.Zones[0].Priority != 10 {
		t.Errorf("Zone.Priority = %d, want 10", cfg.Zones[0].Priority)
	}
}

func TestUnmarshalRPZ_NotMapping(t *testing.T) {
	node := &Node{Type: NodeScalar, Value: "not-a-mapping"}
	var cfg RPZConfig
	if err := unmarshalRPZ(node, &cfg); err == nil {
		t.Error("expected error for non-mapping node")
	}
}

func TestUnmarshalRPZ_Empty(t *testing.T) {
	node := &Node{Type: NodeMapping}
	var cfg RPZConfig
	if err := unmarshalRPZ(node, &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// unmarshalGeoDNS
// ---------------------------------------------------------------------------

func TestUnmarshalGeoDNS_Basic(t *testing.T) {
	node := &Node{
		Type: NodeMapping,
		Children: []*Node{
			{Type: NodeScalar, Value: "enabled"},
			{Type: NodeScalar, Value: "true"},
			{Type: NodeScalar, Value: "mmdb_file"},
			{Type: NodeScalar, Value: "/etc/geoip/GeoLite2-Country.mmdb"},
			{Type: NodeScalar, Value: "rules"},
			{Type: NodeSequence, Children: []*Node{
				{Type: NodeMapping, Children: []*Node{
					{Type: NodeScalar, Value: "domain"},
					{Type: NodeScalar, Value: "cdn.example.com"},
					{Type: NodeScalar, Value: "type"},
					{Type: NodeScalar, Value: "A"},
					{Type: NodeScalar, Value: "default"},
					{Type: NodeScalar, Value: "1.2.3.4"},
					{Type: NodeScalar, Value: "US"},
					{Type: NodeScalar, Value: "10.0.0.1"},
					{Type: NodeScalar, Value: "DE"},
					{Type: NodeScalar, Value: "10.0.1.1"},
				}},
			}},
		},
	}

	var cfg GeoDNSConfig
	if err := unmarshalGeoDNS(node, &cfg); err != nil {
		t.Fatalf("unmarshalGeoDNS: %v", err)
	}
	if !cfg.Enabled {
		t.Error("expected Enabled=true")
	}
	if cfg.MMDBFile != "/etc/geoip/GeoLite2-Country.mmdb" {
		t.Errorf("MMDBFile = %q", cfg.MMDBFile)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
	if cfg.Rules[0].Domain != "cdn.example.com" {
		t.Errorf("Domain = %q", cfg.Rules[0].Domain)
	}
	if cfg.Rules[0].Records["US"] != "10.0.0.1" {
		t.Errorf("US record = %q", cfg.Rules[0].Records["US"])
	}
	if cfg.Rules[0].Records["DE"] != "10.0.1.1" {
		t.Errorf("DE record = %q", cfg.Rules[0].Records["DE"])
	}
}

func TestUnmarshalGeoDNS_NotMapping(t *testing.T) {
	node := &Node{Type: NodeScalar}
	var cfg GeoDNSConfig
	if err := unmarshalGeoDNS(node, &cfg); err == nil {
		t.Error("expected error for non-mapping")
	}
}

// ---------------------------------------------------------------------------
// unmarshalDNS64
// ---------------------------------------------------------------------------

func TestUnmarshalDNS64_Basic(t *testing.T) {
	node := &Node{
		Type: NodeMapping,
		Children: []*Node{
			{Type: NodeScalar, Value: "enabled"},
			{Type: NodeScalar, Value: "true"},
			{Type: NodeScalar, Value: "prefix"},
			{Type: NodeScalar, Value: "64:ff9b::"},
			{Type: NodeScalar, Value: "prefix_len"},
			{Type: NodeScalar, Value: "96"},
			{Type: NodeScalar, Value: "exclude_nets"},
			{Type: NodeSequence, Children: []*Node{
				{Type: NodeScalar, Value: "10.0.0.0/8"},
			}},
		},
	}

	var cfg DNS64Config
	if err := unmarshalDNS64(node, &cfg); err != nil {
		t.Fatalf("unmarshalDNS64: %v", err)
	}
	if !cfg.Enabled {
		t.Error("expected Enabled=true")
	}
	if cfg.Prefix != "64:ff9b::" {
		t.Errorf("Prefix = %q", cfg.Prefix)
	}
	if cfg.PrefixLen != 96 {
		t.Errorf("PrefixLen = %d, want 96", cfg.PrefixLen)
	}
	if len(cfg.ExcludeNets) != 1 {
		t.Errorf("ExcludeNets = %v", cfg.ExcludeNets)
	}
}

func TestUnmarshalDNS64_NotMapping(t *testing.T) {
	node := &Node{Type: NodeSequence}
	var cfg DNS64Config
	if err := unmarshalDNS64(node, &cfg); err == nil {
		t.Error("expected error for non-mapping")
	}
}

// ---------------------------------------------------------------------------
// unmarshalCookie
// ---------------------------------------------------------------------------

func TestUnmarshalCookie_Basic(t *testing.T) {
	node := &Node{
		Type: NodeMapping,
		Children: []*Node{
			{Type: NodeScalar, Value: "enabled"},
			{Type: NodeScalar, Value: "true"},
			{Type: NodeScalar, Value: "secret_rotation"},
			{Type: NodeScalar, Value: "24h"},
		},
	}

	var cfg CookieConfig
	if err := unmarshalCookie(node, &cfg); err != nil {
		t.Fatalf("unmarshalCookie: %v", err)
	}
	if !cfg.Enabled {
		t.Error("expected Enabled=true")
	}
	if cfg.SecretRotation != "24h" {
		t.Errorf("SecretRotation = %q, want 24h", cfg.SecretRotation)
	}
}

func TestUnmarshalCookie_NotMapping(t *testing.T) {
	node := &Node{Type: NodeScalar}
	var cfg CookieConfig
	if err := unmarshalCookie(node, &cfg); err == nil {
		t.Error("expected error for non-mapping")
	}
}

// ---------------------------------------------------------------------------
// ReloadError.Unwrap
// ---------------------------------------------------------------------------

func TestReloadError_Unwrap(t *testing.T) {
	inner := errors.New("inner error")
	re := &ReloadError{Component: "test", Error: inner}

	unwrapped := re.Unwrap()
	if unwrapped != inner {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, inner)
	}
}

// ---------------------------------------------------------------------------
// unmarshalDNSSEC (partially covered at 40%)
// ---------------------------------------------------------------------------

func TestUnmarshalDNSSEC_Full(t *testing.T) {
	node := &Node{
		Type: NodeMapping,
		Children: []*Node{
			{Type: NodeScalar, Value: "enabled"},
			{Type: NodeScalar, Value: "true"},
			{Type: NodeScalar, Value: "trust_anchor"},
			{Type: NodeScalar, Value: "/etc/dnssec/root.key"},
			{Type: NodeScalar, Value: "ignore_time"},
			{Type: NodeScalar, Value: "true"},
			{Type: NodeScalar, Value: "require_dnssec"},
			{Type: NodeScalar, Value: "false"},
			{Type: NodeScalar, Value: "signing"},
			{Type: NodeMapping, Children: []*Node{
				{Type: NodeScalar, Value: "enabled"},
				{Type: NodeScalar, Value: "true"},
				{Type: NodeScalar, Value: "signature_validity"},
				{Type: NodeScalar, Value: "30d"},
				{Type: NodeScalar, Value: "keys"},
				{Type: NodeSequence, Children: []*Node{
					{Type: NodeMapping, Children: []*Node{
						{Type: NodeScalar, Value: "private_key"},
						{Type: NodeScalar, Value: "/etc/dnssec/Kexample.+013+12345.private"},
						{Type: NodeScalar, Value: "type"},
						{Type: NodeScalar, Value: "ksk"},
						{Type: NodeScalar, Value: "algorithm"},
						{Type: NodeScalar, Value: "13"},
					}},
				}},
				{Type: NodeScalar, Value: "nsec3"},
				{Type: NodeMapping, Children: []*Node{
					{Type: NodeScalar, Value: "iterations"},
					{Type: NodeScalar, Value: "10"},
					{Type: NodeScalar, Value: "salt"},
					{Type: NodeScalar, Value: "AABB"},
					{Type: NodeScalar, Value: "opt_out"},
					{Type: NodeScalar, Value: "true"},
				}},
			}},
		},
	}

	var cfg DNSSECConfig
	if err := unmarshalDNSSEC(node, &cfg); err != nil {
		t.Fatalf("unmarshalDNSSEC: %v", err)
	}
	if !cfg.Enabled {
		t.Error("expected Enabled=true")
	}
	if cfg.TrustAnchor != "/etc/dnssec/root.key" {
		t.Errorf("TrustAnchor = %q", cfg.TrustAnchor)
	}
	if !cfg.IgnoreTime {
		t.Error("expected IgnoreTime=true")
	}
	if !cfg.Signing.Enabled {
		t.Error("expected Signing.Enabled=true")
	}
	if cfg.Signing.SignatureValidity != "30d" {
		t.Errorf("SignatureValidity = %q", cfg.Signing.SignatureValidity)
	}
	if len(cfg.Signing.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(cfg.Signing.Keys))
	}
	if cfg.Signing.Keys[0].Type != "ksk" {
		t.Errorf("Key.Type = %q", cfg.Signing.Keys[0].Type)
	}
	if cfg.Signing.NSEC3 == nil {
		t.Fatal("expected NSEC3 config")
	}
	if cfg.Signing.NSEC3.Iterations != 10 {
		t.Errorf("NSEC3.Iterations = %d", cfg.Signing.NSEC3.Iterations)
	}
}
