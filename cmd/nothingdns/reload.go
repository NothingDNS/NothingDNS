// NothingDNS — Configuration hot-reload logic.
//
// Extracted from run() to make the reload path independently testable and
// eliminate the ~70% code duplication between the SIGHUP handler and the
// API /config/reload endpoint.

package main

import (
	"fmt"
	"sync"

	"github.com/nothingdns/nothingdns/internal/api"
	"github.com/nothingdns/nothingdns/internal/audit"
	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dns64"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/geodns"
	"github.com/nothingdns/nothingdns/internal/rpz"
	"github.com/nothingdns/nothingdns/internal/upstream"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// reloadableState bundles the mutable server references that a hot-reload
// updates. Passing a single struct pointer avoids the long parameter list
// that the run() closure relied on.
type reloadableState struct {
	// Config (mutated)
	cfg   **config.Config
	cfgMu *sync.RWMutex

	// Security components (replaced on reload)
	securityManager **SecurityManager
	bl              **blocklist.Blocklist
	rpzEngine       **rpz.Engine
	geoEngine       **geodns.Engine
	dns64Synth      **dns64.Synthesizer
	aclChecker      **filter.ACLChecker
	rateLimiter     **filter.RateLimiter

	// Upstream components (replaced on reload)
	upstreamManager **UpstreamManager
	dnssecManager   **DNSSECManager
	client          **upstream.Client
	loadBalancer    **upstream.LoadBalancer
	validator       **dnssec.Validator

	// Zone state (mutated in place)
	zoneFiles *map[string]string
	zoneMgr   *zone.Manager

	// External references (not replaced, but updated)
	handler   *integratedHandler
	apiServer *api.Server
	logger    *util.Logger
	auditLog  *audit.AuditLogger
}

// reloadConfig loads the config from the given path, prepares all downstream
// components (zones, views, upstream, security), and applies them atomically
// as far as the component architecture allows.
//
// On success the mutable state in s is updated to point at the new components;
// the old components are stopped once the caller confirms the new state is
// live. On error the old state is left intact.
//
// The caller should log the start and completion — this function only logs
// intermediate warnings.
//
// reloadedZones is the number of zone files successfully loaded (may be >0
// even when err != nil if some zones loaded before a later step failed).
func reloadConfig(configPath string, s *reloadableState) (reloadedZones int, err error) {
	// 1. Load and validate the new config.
	newCfg, err := loadReloadConfig(configPath)
	if err != nil {
		return 0, fmt.Errorf("loading config: %w", err)
	}

	// 2. Prepare zone files.
	zonePlan, err := prepareConfiguredZoneFiles(newCfg.Zones, loadZoneFile)
	if err != nil {
		return 0, fmt.Errorf("loading zone files: %w", err)
	}

	// 3. Prepare split-horizon views.
	viewPlan, _, err := prepareConfiguredViews(s.handler, newCfg.Views, loadZoneFile)
	if err != nil {
		return len(zonePlan), fmt.Errorf("loading views: %w", err)
	}

	// 4. Prepare upstream components (client + load balancer + DNSSEC fetch).
	upstreamPlan, err := prepareUpstreamComponents(newCfg, s.logger)
	if err != nil {
		return len(zonePlan), fmt.Errorf("preparing upstream: %w", err)
	}

	// 5. Reload security components (blocklist, RPZ, GeoDNS, DNS64, ACL, RRL).
	currentSec := *s.securityManager
	nextSecMgr, secResult, err := reloadSecurityComponents(newCfg, currentSec, s.handler, s.apiServer, s.logger)
	if err != nil {
		upstreamPlan.upstreamManager.Stop()
		return len(zonePlan), fmt.Errorf("reloading security: %w", err)
	}

	// 6. Apply all prepared plans.
	applyConfiguredZoneFiles(s.handler, s.zoneMgr, *s.zoneFiles, zonePlan, s.logger)
	applyConfiguredViews(s.handler, viewPlan, len(newCfg.Views), s.logger)

	oldUpstream := *s.upstreamManager
	applyUpstreamComponents(upstreamPlan, oldUpstream, s.handler, s.apiServer)

	// 7. Commit the new config.
	commitLoadedConfig(newCfg, s.cfgMu, s.cfg, s.handler)

	// 8. Update mutable state pointers.
	*s.securityManager = nextSecMgr
	*s.bl = secResult.Blocklist
	*s.rpzEngine = secResult.RPZEngine
	*s.geoEngine = secResult.GeoEngine
	*s.dns64Synth = secResult.DNS64Synth
	*s.aclChecker = secResult.ACLChecker
	*s.rateLimiter = secResult.RateLimiter
	*s.upstreamManager = upstreamPlan.upstreamManager
	*s.client = upstreamPlan.upstreamManager.Client
	*s.loadBalancer = upstreamPlan.upstreamManager.LoadBalancer
	*s.validator = upstreamPlan.dnssecManager.Validator
	*s.dnssecManager = upstreamPlan.dnssecManager

	return len(zonePlan), nil
}

// ============================================================================
// Hot-reload test helpers — exposed for testing only
// ============================================================================
