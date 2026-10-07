package main

// Regression tests F617–F621: the reload path (reloadConfig, as run by SIGHUP
// and POST /api/v1/config/reload) applies resolution.recursive and the
// iterative-resolver tunables incl. the DNSSEC DO bit, the cache tunables,
// logging level/format and the idna.* settings, with runtime_overrides.json
// winning over the YAML exactly as at start.

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/idna"
	"github.com/nothingdns/nothingdns/internal/metrics"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/resolver"
	"github.com/nothingdns/nothingdns/internal/util"
)

const reloadRTBase = `server:
  bind: ["127.0.0.1"]
  port: 15353
storage:
  data_dir: "%DATA%"
upstream:
  servers: ["192.0.2.1:53"]
`

type reloadRTEnv struct {
	dir    string
	path   string
	cfg    *config.Config
	h      *integratedHandler
	s      *reloadableState
	logger *util.Logger
}

func reloadRTWrite(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "nothingdns.yaml")
	if err := os.WriteFile(p, []byte(strings.ReplaceAll(reloadRTBase+body, "%DATA%", dir)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// reloadRTStart wires the managers from config A the way runWithContext
// does, including the start-up iterative resolver.
func reloadRTStart(t *testing.T, bodyA string) *reloadRTEnv {
	t.Helper()
	dir := t.TempDir()
	path := reloadRTWrite(t, dir, bodyA)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("load A: %v", err)
	}
	var cfgMu sync.RWMutex
	logger := util.NewLogger(logLevelFromString(cfg.Logging.Level), logFormatFromString(cfg.Logging.Format), &strings.Builder{})
	cacheMgr := NewCacheManager(cfg, logger)
	upMgr, err := NewUpstreamManager(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	zoneMgr, err := NewZoneManager(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	secMgr, err := NewSecurityManager(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	dnssecFetch := upMgr.Resolver()
	dnssecMgr, err := NewDNSSECManager(cfg, dnssecFetch, logger)
	if err != nil {
		t.Fatal(err)
	}
	zones := zoneMgr.Zones()
	r := secMgr.Result()
	h := &integratedHandler{
		config: cfg, logger: logger, cache: cacheMgr.Cache,
		upstream: upMgr.Client, loadBalancer: upMgr.LoadBalancer,
		zones: zones, zoneManager: zoneMgr.Manager(),
		metrics:      metrics.New(metrics.Config{}),
		validator:    dnssecMgr.Validator,
		zoneSigners:  zoneMgr.Signers(),
		idnaEnabled:  cfg.IDNA.Enabled,
		nsecCache:    cache.NewNSECCache(100),
		zoneProvider: NewMultiZoneProvider(zones, zoneMgr.Manager(), nil, nil),
		security: SecurityComponents{
			Blocklist: r.Blocklist, RPZEngine: r.RPZEngine, GeoEngine: r.GeoEngine, DNS64Synth: r.DNS64Synth,
			ACLChecker: r.ACLChecker, RateLimiter: r.RateLimiter, RRL: r.RRL, RecursionPolicy: r.RecursionPolicy,
		},
	}
	iterative, err := buildIterativeResolver(cfg, cacheMgr.Cache, logger)
	if err != nil {
		t.Fatal(err)
	}
	h.resolver = iterative
	dnssecFetch.SetIterative(iterative)
	bl, rz, ge, d64, acl, rl := r.Blocklist, r.RPZEngine, r.GeoEngine, r.DNS64Synth, r.ACLChecker, r.RateLimiter
	client, lb, val := upMgr.Client, upMgr.LoadBalancer, dnssecMgr.Validator
	zoneFiles := zoneMgr.ZoneFiles()
	env := &reloadRTEnv{dir: dir, path: path, cfg: cfg, h: h, logger: logger}
	env.s = &reloadableState{
		cfg: &env.cfg, cfgMu: &cfgMu, securityManager: &secMgr,
		bl: &bl, rpzEngine: &rz, geoEngine: &ge, dns64Synth: &d64, aclChecker: &acl, rateLimiter: &rl,
		upstreamManager: &upMgr, dnssecManager: &dnssecMgr, client: &client, loadBalancer: &lb, validator: &val,
		zoneFiles: &zoneFiles, zoneMgr: zoneMgr.Manager(), handler: h, logger: logger,
	}
	t.Cleanup(func() { (*env.s.upstreamManager).Stop() })
	return env
}

func (e *reloadRTEnv) overrides(t *testing.T, js string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.dir, "runtime_overrides.json"), []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *reloadRTEnv) reload(t *testing.T, bodyB string) error {
	t.Helper()
	reloadRTWrite(t, e.dir, bodyB)
	_, err := reloadConfig(e.path, e.s)
	return err
}

func (e *reloadRTEnv) mustReload(t *testing.T, bodyB string) {
	t.Helper()
	if err := e.reload(t, bodyB); err != nil {
		t.Fatalf("reload: %v", err)
	}
}

// reloadRTResolverCfg reads the live resolver's construction config.
func reloadRTResolverCfg(t *testing.T, r *resolver.Resolver) resolver.Config {
	t.Helper()
	if r == nil {
		t.Fatal("no iterative resolver")
	}
	c := reflect.ValueOf(r).Elem().FieldByName("config")
	return resolver.Config{
		MaxDepth:          int(c.FieldByName("MaxDepth").Int()),
		Timeout:           time.Duration(c.FieldByName("Timeout").Int()),
		EDNS0BufSize:      uint16(c.FieldByName("EDNS0BufSize").Uint()),
		QnameMinimization: c.FieldByName("QnameMinimization").Bool(),
		Use0x20:           c.FieldByName("Use0x20").Bool(),
		DNSSECOK:          c.FieldByName("DNSSECOK").Bool(),
	}
}

// reloadRTRejected runs the validation stage and reports FORMERR.
func reloadRTRejected(t *testing.T, h *integratedHandler, qname string) bool {
	t.Helper()
	msg, err := protocol.NewQuery(1, qname, protocol.TypeA)
	if err != nil {
		t.Fatalf("NewQuery(%q): %v", qname, err)
	}
	w := newCaptureWriter("192.0.2.10", "udp")
	h.runtimeMu.RLock()
	handled, _ := validationStage(h)(context.Background(), &query{msg: msg, currentWriter: w}, w)
	h.runtimeMu.RUnlock()
	return handled && w.msg != nil && w.msg.Header.Flags.RCODE == protocol.RcodeFormatError
}

func TestReloadRuntime_F617_RecursiveToggle(t *testing.T) {
	e := reloadRTStart(t, "resolution:\n  recursive: true\n")
	first := e.h.resolver
	if first == nil {
		t.Fatal("start: recursive=true built no resolver")
	}
	for i := 0; i < 2; i++ { // repeated toggles
		e.mustReload(t, "resolution:\n  recursive: false\n")
		if e.h.resolver != nil {
			t.Fatalf("round %d: recursive=false left the iterative resolver running", i)
		}
		e.mustReload(t, "resolution:\n  recursive: true\n")
		if e.h.resolver == nil || e.h.resolver == first {
			t.Fatalf("round %d: recursive=true did not build a new resolver", i)
		}
	}
}

func TestReloadRuntime_F617_TunablesOverridesAndDOBit(t *testing.T) {
	e := reloadRTStart(t, "resolution:\n  recursive: true\n  max_depth: 10\ndnssec:\n  enabled: false\n")
	if got := reloadRTResolverCfg(t, e.h.resolver); got.DNSSECOK || got.MaxDepth != 10 {
		t.Fatalf("start config = %+v", got)
	}
	e.overrides(t, `{"resolution":{"max_depth":3}}`)
	e.mustReload(t, "resolution:\n  recursive: true\n  max_depth: 7\n  timeout: 2s\n  edns0_buffer_size: 1232\n  qname_minimization: true\n  use_0x20: true\ndnssec:\n  enabled: true\n")
	got := reloadRTResolverCfg(t, e.h.resolver)
	if got.MaxDepth != 3 || got.Timeout != 2*time.Second || got.EDNS0BufSize != 1232 ||
		!got.QnameMinimization || !got.Use0x20 || !got.DNSSECOK {
		t.Fatalf("reloaded resolver config = %+v; want max_depth 3 (override), timeout 2s, edns0 1232, qmin, 0x20, DO", got)
	}
	// dnssec.enabled true -> false clears the DO bit again.
	e.overrides(t, `{}`)
	e.mustReload(t, "resolution:\n  recursive: true\ndnssec:\n  enabled: false\n")
	if reloadRTResolverCfg(t, e.h.resolver).DNSSECOK {
		t.Fatal("dnssec.enabled=false kept the DO bit")
	}
}

func TestReloadRuntime_F617_BadRootHintsKeepsRunningState(t *testing.T) {
	e := reloadRTStart(t, "resolution:\n  recursive: true\n")
	before := e.h.resolver
	missing := filepath.Join(e.dir, "missing.root")
	reloadRTWrite(t, e.dir, "resolution:\n  recursive: true\n  root_hints: \""+missing+"\"\n")
	// validateRuntimeAssets or the resolver build must reject the reload.
	if _, err := reloadConfig(e.path, e.s); err == nil {
		t.Fatal("reload with an unreadable root_hints file succeeded")
	}
	if e.h.resolver != before || !e.h.config.Resolution.Recursive {
		t.Fatal("a failed reload changed the running resolver")
	}
}

func TestReloadRuntime_F618_CacheTunables(t *testing.T) {
	e := reloadRTStart(t, "cache:\n  size: 1000\n  min_ttl: 5\n")
	e.mustReload(t, "cache:\n  size: 50\n  min_ttl: 1\n  max_ttl: 600\n  negative_ttl: 20\n  prefetch: true\n  serve_stale: true\n")
	c := e.h.cache.GetConfig()
	if c.Capacity != 50 || c.MinTTL != time.Second || c.MaxTTL != 10*time.Minute || c.NegativeTTL != 20*time.Second || !c.PrefetchEnabled || !c.ServeStale {
		t.Fatalf("YAML cache settings not applied: %+v", c)
	}
	// The persisted API value wins over the YAML.
	e.overrides(t, `{"cache":{"min_ttl":2,"size":77}}`)
	e.mustReload(t, "cache:\n  size: 50\n  min_ttl: 1\n")
	if c := e.h.cache.GetConfig(); c.Capacity != 77 || c.MinTTL != 2*time.Second {
		t.Fatalf("override not applied over YAML: capacity=%d min_ttl=%v", c.Capacity, c.MinTTL)
	}
	// A rejected reload leaves the cache alone.
	if err := e.reload(t, "cache:\n  min_ttl: 900\n  max_ttl: 10\n"); err == nil {
		t.Fatal("invalid cache config reloaded")
	}
	if c := e.h.cache.GetConfig(); c.Capacity != 77 || c.MinTTL != 2*time.Second {
		t.Fatalf("failed reload changed the cache: %+v", c)
	}
}

func TestReloadRuntime_F619_LoggingLevelFormat(t *testing.T) {
	e := reloadRTStart(t, "logging:\n  level: info\n")
	e.mustReload(t, "logging:\n  level: debug\n  format: json\n")
	if e.logger.Level() != util.DEBUG {
		t.Fatalf("level = %v, want DEBUG", e.logger.Level())
	}
	if f := util.LogFormat(reflect.ValueOf(e.logger).Elem().FieldByName("format").Int()); f != util.JSONFormat {
		t.Fatalf("format = %v, want JSON", f)
	}
	e.overrides(t, `{"logging":{"level":"warn"}}`)
	e.mustReload(t, "logging:\n  level: debug\n")
	if e.logger.Level() != util.WARN {
		t.Fatalf("override level not applied: %v", e.logger.Level())
	}
}

func TestReloadRuntime_F620_IDNAEnabledToggle(t *testing.T) {
	e := reloadRTStart(t, "idna:\n  enabled: false\n")
	if reloadRTRejected(t, e.h, "a_b.example.") {
		t.Fatal("IDNA off at start rejected a_b.example")
	}
	e.mustReload(t, "idna:\n  enabled: true\n")
	if !reloadRTRejected(t, e.h, "a_b.example.") || reloadRTRejected(t, e.h, "www.example.com.") {
		t.Fatal("idna.enabled=true not applied by reload")
	}
	e.mustReload(t, "idna:\n  enabled: false\n")
	if reloadRTRejected(t, e.h, "a_b.example.") {
		t.Fatal("idna.enabled=false not applied by reload")
	}
}

func TestReloadRuntime_F621_IDNAOptions(t *testing.T) {
	ace := func(u string) string {
		a, err := idna.ToASCII(u)
		if err != nil {
			t.Fatalf("ToASCII(%q): %v", u, err)
		}
		return a + ".example."
	}
	e := reloadRTStart(t, "idna:\n  enabled: true\n  use_std3_rules: false\n  allow_unassigned: false\n  check_bidi: true\n")
	cases := []struct {
		name   string
		reject bool
	}{
		{"_dmarc.example.com.", false},
		{ace("a\u0378b"), true},      // unassigned
		{ace("\u05d0a"), true},       // RTL label with an L letter
		{ace("\u05d0\u05d1"), false}, // valid Hebrew
		{ace("\u0627\u0661"), false}, // AL + AN
		{ace("b\u00fccher"), false},  // valid Latin U-label
		{"xn--zzzz-invalid.example.", false},
	}
	for _, c := range cases {
		if got := reloadRTRejected(t, e.h, c.name); got != c.reject {
			t.Errorf("start profile: %s rejected=%v, want %v", c.name, got, c.reject)
		}
	}
	// Reload flips every option.
	e.mustReload(t, "idna:\n  enabled: true\n  use_std3_rules: true\n  allow_unassigned: true\n  check_bidi: false\n")
	for name, want := range map[string]bool{
		"_dmarc.example.com.": true,
		ace("a\u0378b"):       false,
		ace("\u05d0a"):        false,
	} {
		if got := reloadRTRejected(t, e.h, name); got != want {
			t.Errorf("reloaded profile: %s rejected=%v, want %v", name, got, want)
		}
	}
}

func TestReloadRuntime_F621_CheckJoinerWarns(t *testing.T) {
	var out strings.Builder
	logger := util.NewLogger(util.INFO, util.TextFormat, &out)
	logIDNASettings(config.IDNAConfig{Enabled: true, CheckJoiner: true}, logger)
	if !strings.Contains(out.String(), "idna.check_joiner is deprecated and has no effect") {
		t.Fatalf("no check_joiner warning: %q", out.String())
	}
	out.Reset()
	logIDNASettings(config.IDNAConfig{Enabled: false, CheckJoiner: true}, logger)
	if out.Len() != 0 {
		t.Fatalf("warned with IDNA disabled: %q", out.String())
	}
}
