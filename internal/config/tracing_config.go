package config

import (
	"fmt"
	"strconv"
)

// TracingConfig contains distributed tracing settings. When Enabled and an
// Endpoint (or OTEL_EXPORTER_OTLP_* env var) is set, spans are batch-exported
// over OTLP/HTTP to the collector; otherwise they stay in a bounded in-memory
// recorder.
type TracingConfig struct {
	// Enable tracing
	Enabled bool `yaml:"enabled"`

	// Trace verbosity level: none | basic | detailed | verbose
	Level string `yaml:"level"`

	// SampleRate is the fraction of traces kept (0.0-1.0, default 1.0)
	SampleRate float64 `yaml:"sample_rate"`

	// Endpoint is the OTLP collector endpoint, e.g. http://localhost:4318
	Endpoint string `yaml:"endpoint"`
}

func unmarshalTracing(node *Node, cfg *TracingConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	cfg.Level = node.GetString("level")
	if cfg.Level == "" {
		cfg.Level = "basic"
	}
	cfg.Endpoint = node.GetString("endpoint")

	if sr := node.GetString("sample_rate"); sr != "" {
		v, err := strconv.ParseFloat(sr, 64)
		if err != nil || v < 0 || v > 1 {
			return fmt.Errorf("tracing.sample_rate must be a number in [0, 1], got %q", sr)
		}
		cfg.SampleRate = v
	} else if cfg.SampleRate == 0 {
		cfg.SampleRate = 1.0
	}

	return nil
}
