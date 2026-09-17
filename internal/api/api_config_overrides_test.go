package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dns64"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/util"
)

// overridesFixture is an API server wired the way main.go wires it for runtime
// config mutations: an admin user, a live config the handlers mutate, and an
// overrides file in a temp data dir.
type overridesFixture struct {
	server *Server
	admin  *auth.User
	viewer *auth.User
	cfg    *config.Config
	file   string
}

func newOverridesFixture(t *testing.T) *overridesFixture {
	t.Helper()
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	if _, err := store.CreateUser("viewer", "testpass123", auth.RoleViewer); err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	admin, err := store.GetUser("admin")
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}
	viewer, err := store.GetUser("viewer")
	if err != nil {
		t.Fatalf("get viewer: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Upstream.Servers = []string{"8.8.8.8:53"}
	file := filepath.Join(t.TempDir(), "runtime_overrides.json")

	s := NewServer(config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}, nil,
		cache.New(cache.Config{Capacity: 100}), nil, nil, nil, nil)
	s.authStore = store
	s.WithConfigGetter(func() *config.Config { return cfg }).WithRuntimeOverrides(file)

	return &overridesFixture{server: s, admin: admin, viewer: viewer, cfg: cfg, file: file}
}

func (f *overridesFixture) put(t *testing.T, handler http.HandlerFunc, user *auth.User, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// stored reads back the persisted overrides, failing when nothing was written.
func (f *overridesFixture) stored(t *testing.T) *config.RuntimeOverrides {
	t.Helper()
	o, err := config.LoadRuntimeOverrides(f.file)
	if err != nil {
		t.Fatalf("LoadRuntimeOverrides: %v", err)
	}
	if o == nil {
		t.Fatal("no runtime overrides file was written")
	}
	return o
}

func TestHandleConfigLogging_PersistsAndUpdatesConfig(t *testing.T) {
	f := newOverridesFixture(t)
	f.cfg.Logging.Level = "info"
	t.Cleanup(func() { util.GetDefaultLogger().SetLevel(util.INFO) })

	// "warning" must be stored as the canonical "warn": the loader re-validates
	// the file and rejects any spelling the config parser does not accept.
	rec := f.put(t, f.server.handleConfigLogging, f.admin, "/api/v1/config/logging", `{"level":"warning"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := f.stored(t); got.Logging == nil || got.Logging.Level == nil || *got.Logging.Level != "warn" {
		t.Errorf("stored logging override = %+v, want level warn", got.Logging)
	}
	if f.cfg.Logging.Level != "warn" {
		t.Errorf("live config Logging.Level = %q, want warn", f.cfg.Logging.Level)
	}
	if util.GetDefaultLogger().Level() != util.WARN {
		t.Errorf("logger level = %v, want WARN", util.GetDefaultLogger().Level())
	}
}

func TestHandleConfigLogging_InvalidLevelIsNotPersisted(t *testing.T) {
	f := newOverridesFixture(t)
	rec := f.put(t, f.server.handleConfigLogging, f.admin, "/api/v1/config/logging", `{"level":"chatty"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if o, err := config.LoadRuntimeOverrides(f.file); err != nil || o != nil {
		t.Errorf("a rejected level must not be persisted, got %+v (err %v)", o, err)
	}
}

func TestHandleConfigRRL_PersistsIncludingMaxBuckets(t *testing.T) {
	f := newOverridesFixture(t)
	rl := filter.NewRateLimiter(config.RRLConfig{Enabled: false, Rate: 5, Burst: 20})
	t.Cleanup(rl.Stop)
	f.server.WithRateLimiter(rl)

	rec := f.put(t, f.server.handleConfigRRL, f.admin, "/api/v1/config/rrl",
		`{"enabled":true,"rate":50,"burst":100,"max_buckets":2048}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	stored := f.stored(t)
	if stored.RRL == nil {
		t.Fatal("no rrl section persisted")
	}
	if stored.RRL.Enabled == nil || !*stored.RRL.Enabled {
		t.Errorf("enabled not persisted: %+v", stored.RRL)
	}
	if stored.RRL.Rate == nil || *stored.RRL.Rate != 50 {
		t.Errorf("rate not persisted: %+v", stored.RRL)
	}
	if stored.RRL.MaxBuckets == nil || *stored.RRL.MaxBuckets != 2048 {
		t.Errorf("max_buckets not persisted: %+v", stored.RRL)
	}
	if !f.cfg.RRL.Enabled || f.cfg.RRL.Rate != 50 || f.cfg.RRL.Burst != 100 || f.cfg.RRL.MaxBuckets != 2048 {
		t.Errorf("live config RRL = %+v, want enabled/50/100/2048", f.cfg.RRL)
	}
}

// A rate/burst of 0 is ignored by the live setters, so it must not be persisted
// either — otherwise a restart would apply a value the running server never had.
func TestHandleConfigRRL_IgnoredValuesAreNotPersisted(t *testing.T) {
	f := newOverridesFixture(t)
	rl := filter.NewRateLimiter(config.RRLConfig{Enabled: true, Rate: 5, Burst: 20})
	t.Cleanup(rl.Stop)
	f.server.WithRateLimiter(rl)

	rec := f.put(t, f.server.handleConfigRRL, f.admin, "/api/v1/config/rrl", `{"rate":0,"burst":0}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	stored := f.stored(t)
	if stored.RRL == nil {
		t.Fatal("no rrl section persisted")
	}
	if stored.RRL.Rate != nil || stored.RRL.Burst != nil {
		t.Errorf("non-positive rate/burst must not be persisted: %+v", stored.RRL)
	}
}

func TestHandleConfigRRL_RejectsZeroMaxBuckets(t *testing.T) {
	f := newOverridesFixture(t)
	rl := filter.NewRateLimiter(config.RRLConfig{Enabled: true, Rate: 5, Burst: 20})
	t.Cleanup(rl.Stop)
	f.server.WithRateLimiter(rl)

	rec := f.put(t, f.server.handleConfigRRL, f.admin, "/api/v1/config/rrl", `{"max_buckets":0}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for max_buckets 0, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleConfigCache_PersistsAndUpdatesConfig(t *testing.T) {
	f := newOverridesFixture(t)
	f.cfg.Cache.Size = 1000

	rec := f.put(t, f.server.handleConfigCache, f.admin, "/api/v1/config/cache",
		`{"size":5000,"serve_stale":true,"stale_grace_secs":120}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	stored := f.stored(t)
	if stored.Cache == nil || stored.Cache.Size == nil || *stored.Cache.Size != 5000 {
		t.Fatalf("size not persisted: %+v", stored.Cache)
	}
	if stored.Cache.ServeStale == nil || !*stored.Cache.ServeStale {
		t.Errorf("serve_stale not persisted: %+v", stored.Cache)
	}
	if stored.Cache.StaleGraceSecs == nil || *stored.Cache.StaleGraceSecs != 120 {
		t.Errorf("stale_grace_secs not persisted: %+v", stored.Cache)
	}
	// Omitted fields must stay unset so they keep tracking the config file.
	if stored.Cache.MinTTL != nil || stored.Cache.Prefetch != nil {
		t.Errorf("omitted fields were persisted: %+v", stored.Cache)
	}
	if f.cfg.Cache.Size != 5000 || !f.cfg.Cache.ServeStale || f.cfg.Cache.StaleGraceSecs != 120 {
		t.Errorf("live config Cache = %+v, want size 5000, serve_stale, grace 120", f.cfg.Cache)
	}
}

func TestHandleConfigResolution_PersistsAndUpdatesConfig(t *testing.T) {
	f := newOverridesFixture(t)
	f.cfg.Resolution.Timeout = "5s"

	rec := f.put(t, f.server.handleConfigResolution, f.admin, "/api/v1/config/resolution",
		`{"authoritative_only":true,"max_depth":12,"timeout":"2s","edns0_buffer_size":1232,"qname_minimization":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	stored := f.stored(t)
	if stored.Resolution == nil {
		t.Fatal("no resolution section persisted")
	}
	if stored.Resolution.AuthoritativeOnly == nil || !*stored.Resolution.AuthoritativeOnly {
		t.Errorf("authoritative_only not persisted: %+v", stored.Resolution)
	}
	if stored.Resolution.Timeout == nil || *stored.Resolution.Timeout != "2s" {
		t.Errorf("timeout not persisted: %+v", stored.Resolution)
	}
	if stored.Resolution.Recursive != nil {
		t.Errorf("omitted recursive was persisted: %+v", stored.Resolution)
	}
	if !f.cfg.Resolution.AuthoritativeOnly || f.cfg.Resolution.MaxDepth != 12 ||
		f.cfg.Resolution.Timeout != "2s" || f.cfg.Resolution.EDNS0BufferSize != 1232 ||
		!f.cfg.Resolution.QnameMinimization {
		t.Errorf("live config Resolution = %+v", f.cfg.Resolution)
	}
}

func TestHandleConfigResolution_RejectsInvalidValues(t *testing.T) {
	cases := map[string]string{
		"negative max_depth": `{"max_depth":-1}`,
		"edns0 out of range": `{"edns0_buffer_size":70000}`,
		"bad timeout":        `{"timeout":"soon"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			f := newOverridesFixture(t)
			rec := f.put(t, f.server.handleConfigResolution, f.admin, "/api/v1/config/resolution", body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
			if o, err := config.LoadRuntimeOverrides(f.file); err != nil || o != nil {
				t.Errorf("a rejected request must not be persisted, got %+v (err %v)", o, err)
			}
		})
	}
}

func TestHandleConfigDNS64_TogglesSynthesizer(t *testing.T) {
	f := newOverridesFixture(t)
	synth, err := dns64.NewSynthesizer("64:ff9b::", 96)
	if err != nil {
		t.Fatalf("NewSynthesizer: %v", err)
	}
	f.server.WithDNS64(synth)

	rec := f.put(t, f.server.handleConfigDNS64, f.admin, "/api/v1/config/dns64", `{"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if synth.IsEnabled() {
		t.Error("synthesizer is still enabled after a disable request")
	}
	if stored := f.stored(t); stored.DNS64 == nil || stored.DNS64.Enabled == nil || *stored.DNS64.Enabled {
		t.Errorf("disable not persisted: %+v", stored.DNS64)
	}
	if f.cfg.DNS64.Enabled {
		t.Error("live config DNS64.Enabled is still true")
	}

	if rec = f.put(t, f.server.handleConfigDNS64, f.admin, "/api/v1/config/dns64", `{"enabled":true}`); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 re-enabling, got %d: %s", rec.Code, rec.Body.String())
	}
	if !synth.IsEnabled() || !f.cfg.DNS64.Enabled {
		t.Errorf("re-enable not applied: synth=%v cfg=%v", synth.IsEnabled(), f.cfg.DNS64.Enabled)
	}
}

// Without a synthesizer there is no prefix to synthesize from, so enabling must
// fail loudly instead of returning 200 for a setting that cannot take effect.
func TestHandleConfigDNS64_EnableWithoutSynthesizerIs400(t *testing.T) {
	f := newOverridesFixture(t)
	rec := f.put(t, f.server.handleConfigDNS64, f.admin, "/api/v1/config/dns64", `{"enabled":true}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if o, err := config.LoadRuntimeOverrides(f.file); err != nil || o != nil {
		t.Errorf("rejected enable must not be persisted, got %+v (err %v)", o, err)
	}
}

func TestHandleConfigDNS64_RequiresEnabledField(t *testing.T) {
	f := newOverridesFixture(t)
	rec := f.put(t, f.server.handleConfigDNS64, f.admin, "/api/v1/config/dns64", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when enabled is omitted, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleConfigCookie_CallsControlAndPersists(t *testing.T) {
	f := newOverridesFixture(t)
	var got []bool
	f.server.WithCookieControl(func(enabled bool) error {
		got = append(got, enabled)
		return nil
	})

	rec := f.put(t, f.server.handleConfigCookie, f.admin, "/api/v1/config/cookie", `{"enabled":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(got) != 1 || !got[0] {
		t.Fatalf("cookie control calls = %v, want [true]", got)
	}
	if stored := f.stored(t); stored.Cookie == nil || stored.Cookie.Enabled == nil || !*stored.Cookie.Enabled {
		t.Errorf("cookie toggle not persisted: %+v", stored.Cookie)
	}
	if !f.cfg.Cookie.Enabled {
		t.Error("live config Cookie.Enabled is still false")
	}
}

func TestHandleConfigCookie_WithoutControlIs503(t *testing.T) {
	f := newOverridesFixture(t)
	rec := f.put(t, f.server.handleConfigCookie, f.admin, "/api/v1/config/cookie", `{"enabled":true}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
}

// Mutating runtime settings is admin-only (VULN-009): an operator or viewer
// must not be able to widen recursion or silence cookies.
func TestRuntimeConfigEndpoints_AreAdminOnly(t *testing.T) {
	handlers := map[string]struct {
		fn   func(*Server) http.HandlerFunc
		path string
		body string
	}{
		"resolution": {func(s *Server) http.HandlerFunc { return s.handleConfigResolution }, "/api/v1/config/resolution", `{"max_depth":5}`},
		"dns64":      {func(s *Server) http.HandlerFunc { return s.handleConfigDNS64 }, "/api/v1/config/dns64", `{"enabled":false}`},
		"cookie":     {func(s *Server) http.HandlerFunc { return s.handleConfigCookie }, "/api/v1/config/cookie", `{"enabled":false}`},
	}
	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			f := newOverridesFixture(t)
			rec := f.put(t, h.fn(f.server), f.viewer, h.path, h.body)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403 for a viewer, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestRuntimeConfigEndpoints_RejectNonPUT(t *testing.T) {
	f := newOverridesFixture(t)
	for path, handler := range map[string]http.HandlerFunc{
		"/api/v1/config/resolution": f.server.handleConfigResolution,
		"/api/v1/config/dns64":      f.server.handleConfigDNS64,
		"/api/v1/config/cookie":     f.server.handleConfigCookie,
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = req.WithContext(WithUser(req.Context(), f.admin))
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s GET = %d, want 405", path, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != http.MethodPut {
			t.Errorf("%s Allow header = %q, want PUT", path, allow)
		}
	}
}

// Sections written by separate requests must accumulate in one file: the merge
// must not drop what an earlier request stored.
func TestPersistAndApplyOverrides_MergesAcrossRequests(t *testing.T) {
	f := newOverridesFixture(t)
	t.Cleanup(func() { util.GetDefaultLogger().SetLevel(util.INFO) })

	if rec := f.put(t, f.server.handleConfigLogging, f.admin, "/api/v1/config/logging", `{"level":"debug"}`); rec.Code != http.StatusOK {
		t.Fatalf("logging PUT: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.put(t, f.server.handleConfigCache, f.admin, "/api/v1/config/cache", `{"size":4242}`); rec.Code != http.StatusOK {
		t.Fatalf("cache PUT: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.put(t, f.server.handleConfigCache, f.admin, "/api/v1/config/cache", `{"negative_ttl":30}`); rec.Code != http.StatusOK {
		t.Fatalf("second cache PUT: %d %s", rec.Code, rec.Body.String())
	}

	stored := f.stored(t)
	if stored.Logging == nil || stored.Logging.Level == nil || *stored.Logging.Level != "debug" {
		t.Errorf("logging section lost by later requests: %+v", stored.Logging)
	}
	if stored.Cache == nil || stored.Cache.Size == nil || *stored.Cache.Size != 4242 {
		t.Errorf("cache size lost by the second cache request: %+v", stored.Cache)
	}
	if stored.Cache.NegativeTTL == nil || *stored.Cache.NegativeTTL != 30 {
		t.Errorf("negative_ttl not persisted: %+v", stored.Cache)
	}
}

// With no storage.data_dir there is no file to write: the change must still
// apply live and report success, mirroring an ACL update without a policy file.
func TestPersistAndApplyOverrides_NoFileStillApplies(t *testing.T) {
	f := newOverridesFixture(t)
	f.server.WithRuntimeOverrides("")
	t.Cleanup(func() { util.GetDefaultLogger().SetLevel(util.INFO) })

	rec := f.put(t, f.server.handleConfigLogging, f.admin, "/api/v1/config/logging", `{"level":"error"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 without an overrides file, got %d: %s", rec.Code, rec.Body.String())
	}
	if f.cfg.Logging.Level != "error" {
		t.Errorf("live config Logging.Level = %q, want error", f.cfg.Logging.Level)
	}
	if o, err := config.LoadRuntimeOverrides(f.file); err != nil || o != nil {
		t.Errorf("nothing should have been written, got %+v (err %v)", o, err)
	}
}

// A corrupt overrides file must surface as a 500 rather than being silently
// overwritten with a file that holds only the newest patch.
func TestPersistAndApplyOverrides_CorruptFileIsReported(t *testing.T) {
	f := newOverridesFixture(t)
	if err := os.WriteFile(f.file, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}
	t.Cleanup(func() { util.GetDefaultLogger().SetLevel(util.INFO) })

	rec := f.put(t, f.server.handleConfigLogging, f.admin, "/api/v1/config/logging", `{"level":"debug"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 with a corrupt overrides file, got %d: %s", rec.Code, rec.Body.String())
	}
	// The live log level must be rolled back so it matches what is persisted.
	if util.GetDefaultLogger().Level() == util.DEBUG {
		t.Error("log level was left changed after the persist failure")
	}
}
