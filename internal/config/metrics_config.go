package config

import "fmt"

// MetricsConfig contains metrics settings.
type MetricsConfig struct {
	// Enable metrics
	Enabled bool `yaml:"enabled"`

	// Listen address for metrics endpoint
	Bind string `yaml:"bind"`

	// Path for metrics endpoint
	Path string `yaml:"path"`

	// Bearer token required to scrape metrics and metrics health.
	AuthToken string `yaml:"auth_token"`

	// PprofBind, when set, starts a Go pprof (/debug/pprof/*) HTTP listener on
	// this loopback host:port. Empty (the default) disables it. Independent of
	// Enabled; a non-loopback address is a validation error.
	PprofBind string `yaml:"pprof_bind"`
}

func unmarshalMetrics(node *Node, cfg *MetricsConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	cfg.Bind = node.GetString("bind")
	if cfg.Bind == "" {
		cfg.Bind = ":9153"
	}
	cfg.Path = node.GetString("path")
	if cfg.Path == "" {
		cfg.Path = "/metrics"
	}
	cfg.AuthToken = node.GetString("auth_token")
	cfg.PprofBind = node.GetString("pprof_bind")

	return nil
}
