package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRuntimeOverridesFile(t *testing.T) {
	if got := RuntimeOverridesFile(""); got != "" {
		t.Errorf("RuntimeOverridesFile(\"\") = %q, want \"\" (no data dir means no persistence)", got)
	}
	want := filepath.Join("/var/lib/nothingdns", "runtime_overrides.json")
	if got := RuntimeOverridesFile("/var/lib/nothingdns"); got != want {
		t.Errorf("RuntimeOverridesFile = %q, want %q", got, want)
	}
}

// A missing file is the normal first-boot case and must not be an error.
func TestLoadRuntimeOverrides_MissingFile(t *testing.T) {
	o, err := LoadRuntimeOverrides(filepath.Join(t.TempDir(), "runtime_overrides.json"))
	if err != nil {
		t.Fatalf("LoadRuntimeOverrides on missing file: %v", err)
	}
	if o != nil {
		t.Errorf("expected nil overrides for a missing file, got %+v", o)
	}
	if o, err = LoadRuntimeOverrides(""); err != nil || o != nil {
		t.Errorf("LoadRuntimeOverrides(\"\") = %+v, %v; want nil, nil", o, err)
	}
}

func TestLoadRuntimeOverrides_CorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime_overrides.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadRuntimeOverrides(path); err == nil {
		t.Fatal("expected an error for a corrupt overrides file")
	}
}

func TestSaveLoadRuntimeOverrides_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime_overrides.json")
	servers := []string{"1.1.1.1:53", "9.9.9.9:53"}
	want := &RuntimeOverrides{
		Logging:         &LoggingOverride{Level: strPtr("debug")},
		RRL:             &RRLOverride{Enabled: boolPtr(true), Rate: floatPtr(25), Burst: intPtr(50), MaxBuckets: intPtr(4096)},
		Cache:           &CacheOverride{Size: intPtr(20000), ServeStale: boolPtr(true), StaleGraceSecs: intPtr(90)},
		Resolution:      &ResolutionOverride{Recursive: boolPtr(true), Timeout: strPtr("3s"), MaxDepth: intPtr(12)},
		DNS64:           &DNS64Override{Enabled: boolPtr(true)},
		Cookie:          &CookieOverride{Enabled: boolPtr(false)},
		UpstreamServers: &servers,
	}
	if err := SaveRuntimeOverrides(path, want); err != nil {
		t.Fatalf("SaveRuntimeOverrides: %v", err)
	}

	// Owner-only, like the access policy file — it is server state, not config.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("file mode = %04o, want 0600", perm)
		}
	}

	got, err := LoadRuntimeOverrides(path)
	if err != nil {
		t.Fatalf("LoadRuntimeOverrides: %v", err)
	}
	if got == nil {
		t.Fatal("LoadRuntimeOverrides returned nil after a save")
	}
	if got.Logging == nil || got.Logging.Level == nil || *got.Logging.Level != "debug" {
		t.Errorf("logging.level did not round-trip: %+v", got.Logging)
	}
	if got.RRL == nil || got.RRL.Rate == nil || *got.RRL.Rate != 25 || got.RRL.MaxBuckets == nil || *got.RRL.MaxBuckets != 4096 {
		t.Errorf("rrl did not round-trip: %+v", got.RRL)
	}
	if got.Cache == nil || got.Cache.Size == nil || *got.Cache.Size != 20000 || got.Cache.ServeStale == nil || !*got.Cache.ServeStale {
		t.Errorf("cache did not round-trip: %+v", got.Cache)
	}
	if got.Resolution == nil || got.Resolution.Timeout == nil || *got.Resolution.Timeout != "3s" {
		t.Errorf("resolution did not round-trip: %+v", got.Resolution)
	}
	if got.DNS64 == nil || got.DNS64.Enabled == nil || !*got.DNS64.Enabled {
		t.Errorf("dns64 did not round-trip: %+v", got.DNS64)
	}
	if got.Cookie == nil || got.Cookie.Enabled == nil || *got.Cookie.Enabled {
		t.Errorf("cookie did not round-trip: %+v", got.Cookie)
	}
	if got.UpstreamServers == nil || len(*got.UpstreamServers) != 2 || (*got.UpstreamServers)[1] != "9.9.9.9:53" {
		t.Errorf("upstream_servers did not round-trip: %+v", got.UpstreamServers)
	}
}

// Only the fields actually set may appear in the file: an omitted field must
// not be written as a zero value, or loading it would silently overwrite the
// YAML value with 0/false.
func TestSaveRuntimeOverrides_OmitsUnsetFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime_overrides.json")
	if err := SaveRuntimeOverrides(path, &RuntimeOverrides{Logging: &LoggingOverride{Level: strPtr("warn")}}); err != nil {
		t.Fatalf("SaveRuntimeOverrides: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for _, unwanted := range []string{"cache", "rrl", "resolution", "dns64", "cookie", "upstream_servers"} {
		if strings.Contains(string(data), unwanted) {
			t.Errorf("file contains unset section %q:\n%s", unwanted, data)
		}
	}
}

func TestSaveRuntimeOverrides_NoPathIsError(t *testing.T) {
	if err := SaveRuntimeOverrides("", &RuntimeOverrides{}); err == nil {
		t.Fatal("expected an error when no overrides file is configured")
	}
}

func TestApplyRuntimeOverrides_OnlyOverridesSetFields(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Logging.Level = "info"
	cfg.Logging.Format = "text"
	cfg.Cache.Size = 1000
	cfg.Cache.MaxTTL = 3600
	cfg.Resolution.Timeout = "5s"
	cfg.Resolution.RootHints = "/etc/nothingdns/root.hints"
	cfg.RRL.Burst = 10
	cfg.Upstream.Servers = []string{"8.8.8.8:53"}

	servers := []string{"1.1.1.1:53"}
	ApplyRuntimeOverrides(cfg, &RuntimeOverrides{
		Logging:         &LoggingOverride{Level: strPtr("debug")},
		RRL:             &RRLOverride{Rate: floatPtr(42.9), MaxBuckets: intPtr(2048)},
		Cache:           &CacheOverride{Size: intPtr(50000)},
		Resolution:      &ResolutionOverride{AuthoritativeOnly: boolPtr(true), Timeout: strPtr("2s")},
		DNS64:           &DNS64Override{Enabled: boolPtr(true)},
		Cookie:          &CookieOverride{Enabled: boolPtr(true)},
		UpstreamServers: &servers,
	})

	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %q, want debug", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "text" {
		t.Errorf("Logging.Format = %q, want text (not overridden)", cfg.Logging.Format)
	}
	// rrl.rate is an int in Config, so a fractional override truncates.
	if cfg.RRL.Rate != 42 {
		t.Errorf("RRL.Rate = %d, want 42", cfg.RRL.Rate)
	}
	if cfg.RRL.MaxBuckets != 2048 {
		t.Errorf("RRL.MaxBuckets = %d, want 2048", cfg.RRL.MaxBuckets)
	}
	if cfg.RRL.Burst != 10 {
		t.Errorf("RRL.Burst = %d, want 10 (not overridden)", cfg.RRL.Burst)
	}
	if cfg.Cache.Size != 50000 {
		t.Errorf("Cache.Size = %d, want 50000", cfg.Cache.Size)
	}
	if cfg.Cache.MaxTTL != 3600 {
		t.Errorf("Cache.MaxTTL = %d, want 3600 (not overridden)", cfg.Cache.MaxTTL)
	}
	if !cfg.Resolution.AuthoritativeOnly {
		t.Error("Resolution.AuthoritativeOnly was not overridden")
	}
	if cfg.Resolution.Timeout != "2s" {
		t.Errorf("Resolution.Timeout = %q, want 2s", cfg.Resolution.Timeout)
	}
	// root_hints is deliberately not overridable — it needs startup validation.
	if cfg.Resolution.RootHints != "/etc/nothingdns/root.hints" {
		t.Errorf("Resolution.RootHints = %q, want the config value", cfg.Resolution.RootHints)
	}
	if !cfg.DNS64.Enabled || !cfg.Cookie.Enabled {
		t.Errorf("DNS64/Cookie toggles not applied: %v / %v", cfg.DNS64.Enabled, cfg.Cookie.Enabled)
	}
	if len(cfg.Upstream.Servers) != 1 || cfg.Upstream.Servers[0] != "1.1.1.1:53" {
		t.Errorf("Upstream.Servers = %v, want [1.1.1.1:53]", cfg.Upstream.Servers)
	}

	// The applied slice must not alias the override, or a later live apply
	// would mutate the persisted list.
	servers[0] = "mutated"
	if cfg.Upstream.Servers[0] != "1.1.1.1:53" {
		t.Error("Upstream.Servers aliases the override slice")
	}
}

func TestApplyRuntimeOverrides_NilsAreNoOps(t *testing.T) {
	cfg := DefaultConfig()
	level := cfg.Logging.Level
	ApplyRuntimeOverrides(cfg, nil)
	ApplyRuntimeOverrides(nil, &RuntimeOverrides{Logging: &LoggingOverride{Level: strPtr("debug")}})
	ApplyRuntimeOverrides(cfg, &RuntimeOverrides{})
	if cfg.Logging.Level != level {
		t.Errorf("Logging.Level = %q, want unchanged %q", cfg.Logging.Level, level)
	}
}

func TestMergeRuntimeOverridePatch_KeepsUnpatchedFields(t *testing.T) {
	existing := &RuntimeOverrides{
		Logging: &LoggingOverride{Level: strPtr("debug")},
		Cache:   &CacheOverride{Size: intPtr(1000), ServeStale: boolPtr(true)},
	}
	patch := &RuntimeOverrides{
		Cache:  &CacheOverride{Size: intPtr(2000)},
		DNS64:  &DNS64Override{Enabled: boolPtr(true)},
		Cookie: &CookieOverride{Enabled: boolPtr(false)},
	}

	merged := MergeRuntimeOverridePatch(existing, patch)

	if merged.Logging == nil || *merged.Logging.Level != "debug" {
		t.Errorf("untouched section lost: %+v", merged.Logging)
	}
	if merged.Cache.Size == nil || *merged.Cache.Size != 2000 {
		t.Errorf("patched field not applied: %+v", merged.Cache)
	}
	if merged.Cache.ServeStale == nil || !*merged.Cache.ServeStale {
		t.Errorf("unpatched field in a patched section lost: %+v", merged.Cache)
	}
	if merged.DNS64 == nil || !*merged.DNS64.Enabled {
		t.Errorf("new section not added: %+v", merged.DNS64)
	}
	if merged.Cookie == nil || *merged.Cookie.Enabled {
		t.Errorf("false is a real value and must be stored: %+v", merged.Cookie)
	}

	// Merging must not mutate either input, and the result must not alias them.
	*merged.Cache.Size = 3000
	if *existing.Cache.Size != 1000 || *patch.Cache.Size != 2000 {
		t.Error("merge result aliases its inputs")
	}
}

func TestMergeRuntimeOverridePatch_UpstreamServersReplaceWholesale(t *testing.T) {
	old := []string{"8.8.8.8:53"}
	newList := []string{"1.1.1.1:53", "9.9.9.9:53"}

	merged := MergeRuntimeOverridePatch(&RuntimeOverrides{UpstreamServers: &old}, &RuntimeOverrides{})
	if merged.UpstreamServers == nil || len(*merged.UpstreamServers) != 1 {
		t.Fatalf("existing list dropped by an unrelated patch: %+v", merged.UpstreamServers)
	}

	merged = MergeRuntimeOverridePatch(&RuntimeOverrides{UpstreamServers: &old}, &RuntimeOverrides{UpstreamServers: &newList})
	if merged.UpstreamServers == nil || len(*merged.UpstreamServers) != 2 {
		t.Fatalf("patched list not applied: %+v", merged.UpstreamServers)
	}
	// An empty list is a real value (all upstreams removed), not "unset".
	empty := []string{}
	merged = MergeRuntimeOverridePatch(&RuntimeOverrides{UpstreamServers: &old}, &RuntimeOverrides{UpstreamServers: &empty})
	if merged.UpstreamServers == nil || len(*merged.UpstreamServers) != 0 {
		t.Fatalf("empty list not applied: %+v", merged.UpstreamServers)
	}
}

func TestMergeRuntimeOverridePatch_NilArguments(t *testing.T) {
	if merged := MergeRuntimeOverridePatch(nil, nil); merged == nil {
		t.Fatal("MergeRuntimeOverridePatch(nil, nil) must return an empty, non-nil result")
	}
	merged := MergeRuntimeOverridePatch(nil, &RuntimeOverrides{Logging: &LoggingOverride{Level: strPtr("warn")}})
	if merged.Logging == nil || *merged.Logging.Level != "warn" {
		t.Errorf("patch against nil existing lost data: %+v", merged)
	}
	merged = MergeRuntimeOverridePatch(&RuntimeOverrides{Logging: &LoggingOverride{Level: strPtr("warn")}}, nil)
	if merged.Logging == nil || *merged.Logging.Level != "warn" {
		t.Errorf("nil patch dropped existing data: %+v", merged)
	}
}

// The merged result must stay valid config: applying it to a default config
// and validating catches an override that would make the server unstartable.
func TestApplyRuntimeOverrides_ResultValidates(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Upstream.Servers = []string{"8.8.8.8:53"}
	ApplyRuntimeOverrides(cfg, &RuntimeOverrides{
		Logging:    &LoggingOverride{Level: strPtr("warn")},
		Cache:      &CacheOverride{Size: intPtr(1000)},
		Resolution: &ResolutionOverride{Timeout: strPtr("4s"), EDNS0BufferSize: intPtr(1232)},
	})
	if errs := cfg.Validate(); len(errs) > 0 {
		t.Fatalf("overridden config failed validation: %v", errs)
	}

	// A bad override must be caught by the same validation, which is what the
	// loader relies on to fall back to the YAML values.
	ApplyRuntimeOverrides(cfg, &RuntimeOverrides{Logging: &LoggingOverride{Level: strPtr("bogus")}})
	if errs := cfg.Validate(); len(errs) == 0 {
		t.Fatal("expected validation to reject an invalid log level override")
	}
}

func strPtr(s string) *string     { return &s }
func intPtr(i int) *int           { return &i }
func boolPtr(b bool) *bool        { return &b }
func floatPtr(f float64) *float64 { return &f }
