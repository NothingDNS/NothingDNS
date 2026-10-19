package main

// Regression test for the 2026-10-18 proof-driven round: a zone restored from
// the persistent KV database at startup was dropped from the running server by
// the next reload.
//
// synchronizeKVZones (zone_manager.go) recorded every KV-restored origin in
// result.ZoneFiles with an empty path, and run() aliases that same map as the
// reload tracking map (reloadableState.zoneFiles). applyConfiguredZoneFiles
// prunes every tracked origin the new file-based plan does not contain — which
// is every KV zone — and nothing re-added it, so the first SIGHUP or
// POST /api/v1/config/reload silently stopped serving every API-created zone
// until the next restart. synchronizeKVZones no longer tracks KV origins in
// the file-backed map; this test pins that behavior.

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/metrics"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// reloadRTStartIn is reloadRTStart with a caller-chosen dir, so two boots can
// share one KV database. It also returns the ZoneManager wrapper for direct
// KV-store access (package-internal field).
func reloadRTStartIn(t *testing.T, dir, body string) (*reloadRTEnv, *ZoneManager) {
	t.Helper()
	path := reloadRTWrite(t, dir, body)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
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
	return env, zoneMgr
}

func TestKVRestoredZoneSurvivesReload(t *testing.T) {
	dir := t.TempDir()

	// File-backed control zone, loaded from config on both boots.
	zoneFile := filepath.Join(dir, "control.zone")
	controlText := "$ORIGIN control.test.\n$TTL 300\n@ IN SOA ns1 h 1 1 1 1 1\n@ IN NS ns1\nns1 IN A 192.0.2.1\n"
	if err := os.WriteFile(zoneFile, []byte(controlText), 0o600); err != nil {
		t.Fatal(err)
	}
	body := "zones:\n  - \"" + zoneFile + "\"\n"

	// Boot 1: create the zone through the production mutation path; the KV
	// persistence hook (KVPersistence.Enable) saves it to the store.
	env1, zm1 := reloadRTStartIn(t, dir, body)
	err := env1.s.zoneMgr.CreateZone("kvzone.test.", 300,
		&zone.SOARecord{TTL: 300, MName: "ns1.kvzone.test.", RName: "hostmaster@kvzone.test",
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400},
		[]zone.NSRecord{{TTL: 300, NSDName: "ns1.kvzone.test."}})
	if err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
	kvZones, err := zm1.result.KVPersistence.ListKVZones()
	if err != nil || len(kvZones) == 0 {
		t.Fatalf("CONTROL FAILED: zone not persisted to KV (err=%v, zones=%v)", err, kvZones)
	}
	if err := zm1.result.KVStore.Close(); err != nil {
		t.Fatalf("closing KV store: %v", err)
	}

	// Boot 2 against the same data dir: synchronizeKVZones restores the zone.
	env2, _ := reloadRTStartIn(t, dir, body)
	served := func(origin string) (inMgr, inHandler bool) {
		_, inMgr = env2.h.zoneManager.Get(origin)
		env2.h.zonesMu.RLock()
		_, inHandler = env2.h.zones[origin]
		env2.h.zonesMu.RUnlock()
		return inMgr, inHandler
	}
	kMgr, kHandler := served("kvzone.test.")
	cMgr, cHandler := served("control.test.")
	if !kMgr || !kHandler {
		t.Fatalf("CONTROL FAILED: KV zone not restored at boot (manager=%v handler=%v)", kMgr, kHandler)
	}
	if !cMgr || !cHandler {
		t.Fatalf("CONTROL FAILED: file zone not loaded at boot (manager=%v handler=%v)", cMgr, cHandler)
	}

	// An unchanged reload must keep serving both zones.
	env2.mustReload(t, body)

	kMgr, kHandler = served("kvzone.test.")
	cMgr, cHandler = served("control.test.")
	if !kMgr || !kHandler {
		t.Fatalf("reload dropped the KV-restored zone (manager=%v handler=%v)", kMgr, kHandler)
	}
	if !cMgr || !cHandler {
		t.Fatalf("reload dropped the file-backed control zone (manager=%v handler=%v)", cMgr, cHandler)
	}
}
