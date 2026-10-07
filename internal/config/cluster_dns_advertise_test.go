package config

// F562 (P2-G1): cluster.dns_advertise_addr is parsed and validated.

import (
	"strings"
	"testing"
)

func TestUnmarshalYAML_ClusterDNSAdvertiseAddr_F562(t *testing.T) {
	cfg, err := UnmarshalYAML("cluster:\n  enabled: true\n  dns_advertise_addr: 192.0.2.10:53\n")
	if err != nil {
		t.Fatalf("UnmarshalYAML: %v", err)
	}
	if cfg.Cluster.DNSAdvertiseAddr != "192.0.2.10:53" {
		t.Errorf("DNSAdvertiseAddr = %q", cfg.Cluster.DNSAdvertiseAddr)
	}
	if cfg, err := UnmarshalYAML("cluster:\n  enabled: true\n"); err != nil || cfg.Cluster.DNSAdvertiseAddr != "" {
		t.Errorf("default DNSAdvertiseAddr = %q (%v), want empty", cfg.Cluster.DNSAdvertiseAddr, err)
	}
}

func TestValidate_ClusterDNSAdvertiseAddr_F562(t *testing.T) {
	cases := map[string]string{ // value -> error substring ("" = valid)
		"192.0.2.10:53":      "",
		"[2001:db8::1]:5354": "",
		"dns1.example:53":    "",
		"192.0.2.10":         "host:port",
		":53":                "empty host",
		"0.0.0.0:53":         "wildcard",
		"[::]:53":            "wildcard",
		"192.0.2.10:0":       "port",
		"192.0.2.10:70000":   "port",
		"192.0.2.10:dns":     "port",
	}
	for v, want := range cases {
		cfg := DefaultConfig()
		cfg.Cluster.Enabled = true
		cfg.Cluster.DNSAdvertiseAddr = v
		var found string
		for _, e := range cfg.validateCluster() {
			if strings.Contains(e, "dns_advertise_addr") {
				found = e
			}
		}
		switch {
		case want == "" && found != "":
			t.Errorf("%q: unexpected error %q", v, found)
		case want != "" && !strings.Contains(found, want):
			t.Errorf("%q: error %q, want containing %q", v, found, want)
		}
	}
}
