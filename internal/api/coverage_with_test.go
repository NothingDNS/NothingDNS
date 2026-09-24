package api

// Targeted coverage for previously-zero functions:
//   - redactIP utility (PII reduction)
//   - apiRateLimiter.cleanup background sweep
//   - All Server.WithX functional-option setters
//
// The WithX surface accounts for ~15 zero-coverage functions in
// internal/api/server.go simply because the existing tests construct
// the Server directly. This test threads a fresh Server through every
// option and confirms each field landed correctly.

import (
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dashboard"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/geodns"
	"github.com/nothingdns/nothingdns/internal/metrics"
	"github.com/nothingdns/nothingdns/internal/odoh"
	"github.com/nothingdns/nothingdns/internal/otel"
	"github.com/nothingdns/nothingdns/internal/rpz"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/upstream"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestRedactIP(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"192.0.2.1", "192.0.2.xxx"},
		{"2001:db8::1", "2001:db8::xxxx"},
		{"", "xxx.xxx.xxx.xxx"},
		{"not-an-ip", "xxx.xxx.xxx.xxx"},
	}
	for _, c := range cases {
		if got := redactIP(c.in); got != c.want {
			t.Errorf("redactIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAPIRateLimiter_Cleanup_DropsStaleEntries(t *testing.T) {
	r := newAPIRateLimiter(0, 0)
	// Force a small window so we can stage entries that fall outside it.
	r.windowSecs = 1
	now := time.Now()

	r.mu.Lock()
	r.requests["1.1.1.1"] = []time.Time{
		now.Add(-2 * time.Second), // outside window — should drop
		now.Add(-2 * time.Second),
	}
	r.requests["2.2.2.2"] = []time.Time{
		now.Add(-2 * time.Second),        // outside
		now.Add(-100 * time.Millisecond), // inside
	}
	r.mu.Unlock()

	r.cleanup()

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.requests["1.1.1.1"]; ok {
		t.Error("1.1.1.1 should have been deleted (all entries stale)")
	}
	if v, ok := r.requests["2.2.2.2"]; !ok || len(v) != 1 {
		t.Errorf("2.2.2.2 should retain 1 fresh entry, got %v", v)
	}
}

// TestServer_WithSetters threads a fresh Server through every WithX
// option to confirm each one stores its argument on the correct field.
// Each option is a single-line setter, so the test is a stub-arg dance
// rather than behaviour verification — but it pulls these out of the
// zero-coverage column.
func TestServer_WithSetters(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	// Build sentinel values whose only requirement is "non-nil"
	bl := &blocklist.Blocklist{}
	upClient := &upstream.Client{}
	upLB := &upstream.LoadBalancer{}
	acl := &filter.ACLChecker{}
	store, err := auth.NewStore(&auth.Config{})
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	cfgGetter := func() *config.Config { return &config.Config{} }
	mc := metrics.New(metrics.Config{})
	validator := &dnssec.Validator{}
	zoneSigners := map[string]*dnssec.Signer{}
	rpzEngine := &rpz.Engine{}
	geoEngine := &geodns.Engine{}
	slaveManager := &transfer.SlaveManager{}
	rateLimiter := filter.NewRateLimiter(config.RRLConfig{})
	defer rateLimiter.Stop()
	odohProxy := &odoh.ObliviousProxy{}
	odohTarget := &odoh.ObliviousTarget{}
	tracer := otel.NewTracer(otel.Config{})
	dashboardSrv := &dashboard.Server{}

	out := srv.
		WithBlocklist(bl).
		WithUpstream(upClient, upLB).
		WithACL(acl).
		WithAuth(store).
		WithConfigGetter(cfgGetter).
		WithMetrics(mc).
		WithDNSSEC(validator).
		WithZoneSigners(zoneSigners).
		WithRPZ(rpzEngine).
		WithGeoDNS(geoEngine).
		WithSlaveManager(slaveManager).
		WithRateLimiter(rateLimiter).
		WithODoH(odohProxy).
		WithODoHTarget(odohTarget).
		WithTracer(tracer).
		WithDashboard(dashboardSrv)

	// Chain returns the same Server pointer.
	if out != srv {
		t.Error("With chain returned a different Server pointer")
	}

	// Spot-check fields landed.
	checks := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"blocklist", srv.blocklist, bl},
		{"upstreamClient", srv.upstreamClient, upClient},
		{"upstreamLB", srv.upstreamLB, upLB},
		{"aclChecker", srv.aclChecker, acl},
		{"authStore", srv.authStore, store},
		{"metrics", srv.metrics, mc},
		{"validator", srv.validator, validator},
		{"rpzEngine", srv.rpzEngine, rpzEngine},
		{"geoEngine", srv.geoEngine, geoEngine},
		{"slaveManager", srv.slaveManager, slaveManager},
		{"rateLimiter", srv.rateLimiter, rateLimiter},
		{"odohProxy", srv.odohProxy, odohProxy},
		{"odohTarget", srv.odohTarget, odohTarget},
		{"tracer", srv.tracer, tracer},
		{"dashboardServer", srv.dashboardServer, dashboardSrv},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %v want %v", c.name, c.got, c.want)
		}
	}

	// configGetter is a func — compare via call.
	if srv.configGetter == nil {
		t.Error("configGetter not set")
	}

	// zoneSigners is a map, locked accessor.
	srv.zoneSignersMu.Lock()
	if len(srv.zoneSigners) != 0 {
		t.Error("zoneSigners should be the empty map we passed")
	}
	srv.zoneSignersMu.Unlock()
}

func TestServerRuntimeSnapshotDoesNotRaceWithSetters(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	store, err := auth.NewStore(&auth.Config{})
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	upClient := &upstream.Client{}
	upLB := &upstream.LoadBalancer{}
	mc := metrics.New(metrics.Config{})
	dashboardSrv := &dashboard.Server{}
	odohProxy := &odoh.ObliviousProxy{}
	odohTarget := &odoh.ObliviousTarget{}
	tracer := otel.NewTracer(otel.Config{})

	var wg sync.WaitGroup
	const iterations = 100
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if i%2 == 0 {
				srv.WithAuth(store).
					WithUpstream(upClient, upLB).
					WithMetrics(mc).
					WithDashboard(dashboardSrv).
					WithODoH(odohProxy).
					WithODoHTarget(odohTarget).
					WithTracer(tracer)
			} else {
				srv.WithAuth(nil).
					WithUpstream(nil, nil).
					WithMetrics(nil).
					WithDashboard(nil).
					WithODoH(nil).
					WithODoHTarget(nil).
					WithTracer(nil)
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			snapshot := srv.currentRuntimeSnapshot()
			_ = snapshot.authStore
			_ = snapshot.metrics
			_ = snapshot.dashboardServer
			_ = snapshot.upstreamClient
			_ = snapshot.upstreamLB
			_ = snapshot.odohProxy
			_ = snapshot.odohTarget
			_ = snapshot.tracer
			_ = srv.currentAuthStore()
			_ = srv.currentODoHTarget()
		}
	}()

	wg.Wait()
}

// Sanity that the existing imports stay used even if a future refactor
// drops some option types. server.Handler isn't directly threaded by
// any With method but is part of NewServer's arglist.
var _ = server.Handler(nil)
var _ *zone.Manager
var _ *cache.Cache
var _ *cluster.Cluster
