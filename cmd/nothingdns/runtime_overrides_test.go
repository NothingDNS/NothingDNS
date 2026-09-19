package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
)

// writeOverridesTestConfig writes a minimal valid config whose storage.data_dir
// is dir, and returns the config path.
func writeOverridesTestConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yaml")
	yaml := "storage:\n  data_dir: " + dir + "\n" +
		"upstream:\n  servers:\n    - \"8.8.8.8:53\"\n" +
		"logging:\n  level: info\n" +
		"cache:\n  enabled: true\n  size: 1000\n"
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func writeOverridesFile(t *testing.T, dir string, o *config.RuntimeOverrides) {
	t.Helper()
	if err := config.SaveRuntimeOverrides(config.RuntimeOverridesFile(dir), o); err != nil {
		t.Fatalf("SaveRuntimeOverrides: %v", err)
	}
}

func TestLoadConfig_AppliesRuntimeOverrides(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeOverridesTestConfig(t, dir)
	level := "debug"
	size := 5000
	servers := []string{"1.1.1.1:53"}
	writeOverridesFile(t, dir, &config.RuntimeOverrides{
		Logging:         &config.LoggingOverride{Level: &level},
		Cache:           &config.CacheOverride{Size: &size},
		UpstreamServers: &servers,
	})

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %q, want debug (override must win over the config file)", cfg.Logging.Level)
	}
	if cfg.Cache.Size != 5000 {
		t.Errorf("Cache.Size = %d, want 5000", cfg.Cache.Size)
	}
	if len(cfg.Upstream.Servers) != 1 || cfg.Upstream.Servers[0] != "1.1.1.1:53" {
		t.Errorf("Upstream.Servers = %v, want [1.1.1.1:53]", cfg.Upstream.Servers)
	}
}

// A corrupt overrides file must not stop the server from starting: it falls
// back to the config file values.
func TestLoadConfig_CorruptRuntimeOverridesFallsBackToYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeOverridesTestConfig(t, dir)
	if err := os.WriteFile(config.RuntimeOverridesFile(dir), []byte("{ nope"), 0o600); err != nil {
		t.Fatalf("write overrides: %v", err)
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig must not fail on a corrupt overrides file: %v", err)
	}
	if cfg.Logging.Level != "info" || cfg.Cache.Size != 1000 {
		t.Errorf("expected the config file values, got level %q size %d", cfg.Logging.Level, cfg.Cache.Size)
	}
}

// One unusable section must not discard the others: the valid sections still
// apply, the invalid one keeps the config file value.
func TestLoadConfig_InvalidOverrideSectionIsSkipped(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeOverridesTestConfig(t, dir)
	bogus := "chatty"
	size := 7777
	writeOverridesFile(t, dir, &config.RuntimeOverrides{
		Logging: &config.LoggingOverride{Level: &bogus},
		Cache:   &config.CacheOverride{Size: &size},
	})

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("Logging.Level = %q, want info (invalid override must be skipped)", cfg.Logging.Level)
	}
	if cfg.Cache.Size != 7777 {
		t.Errorf("Cache.Size = %d, want 7777 (a valid section must still apply)", cfg.Cache.Size)
	}
}

// No storage.data_dir means no overrides file, and loading must be unaffected.
func TestLoadConfig_NoDataDirSkipsOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := "upstream:\n  servers:\n    - \"8.8.8.8:53\"\nlogging:\n  level: warn\n"
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Logging.Level != "warn" {
		t.Errorf("Logging.Level = %q, want warn", cfg.Logging.Level)
	}
}

// SIGHUP reloads go through loadReloadConfig, so overrides must survive them.
func TestLoadReloadConfig_AppliesRuntimeOverrides(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeOverridesTestConfig(t, dir)
	authOnly := true
	timeout := "2s"
	writeOverridesFile(t, dir, &config.RuntimeOverrides{
		Resolution: &config.ResolutionOverride{AuthoritativeOnly: &authOnly, Timeout: &timeout},
	})

	cfg, err := loadReloadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadReloadConfig: %v", err)
	}
	if !cfg.Resolution.AuthoritativeOnly {
		t.Error("Resolution.AuthoritativeOnly override was not re-applied on reload")
	}
	if cfg.Resolution.Timeout != "2s" {
		t.Errorf("Resolution.Timeout = %q, want 2s", cfg.Resolution.Timeout)
	}
}
