// NothingDNS — Configuration hot-reload logic.
//
// Extracted from run() to make the reload path independently testable and
// eliminate the ~70% code duplication between the SIGHUP handler and the
// API /config/reload endpoint.

package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/api"
	"github.com/nothingdns/nothingdns/internal/audit"
	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dns64"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/geodns"
	"github.com/nothingdns/nothingdns/internal/idna"
	"github.com/nothingdns/nothingdns/internal/resolver"
	"github.com/nothingdns/nothingdns/internal/rpz"
	"github.com/nothingdns/nothingdns/internal/transfer"
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

	// Serializes concurrent reloads (SIGHUP + API reload can fire simultaneously)
	reloadMu sync.Mutex

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

	// DNS transports whose TLS certificates a reload re-reads (F611); set
	// with setTransports once they are listening.
	transports *servers
}

// setTransports wires the running DNS transports into the reload state so
// reloads re-read their TLS certificates.
func (s *reloadableState) setTransports(t *servers) {
	s.reloadMu.Lock()
	s.transports = t
	s.reloadMu.Unlock()
}

// reloadTLSCertificates re-reads the certificate (and XoT CA) files of
// every TLS listener — DoT, DoQ, XoT and the HTTPS API (F611). It runs on
// every reload, before and independently of the config file, so a renewed
// certificate is picked up even when the config itself does not change or
// fails to load. A listener whose files fail to load keeps its current
// certificate and the error is logged; listeners are never taken down.
func reloadTLSCertificates(s *reloadableState) {
	s.transports.reloadCertificates(s.logger)
	if s.apiServer == nil {
		return
	}
	if err := s.apiServer.ReloadTLS(); err != nil {
		if s.logger != nil {
			s.logger.Errorf("HTTPS API: certificate reload failed, keeping the previous certificate: %v", err)
		}
	}
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
	// Serialize whole reloads (SIGHUP + API reload can fire simultaneously).
	// Locking only the final pointer swap let two reloads both snapshot the
	// same "current" managers, stop them twice and leak one new set.
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	// 0. Re-read TLS certificates (F611).
	reloadTLSCertificates(s)

	// 1. Load and validate the new config.
	newCfg, err := loadReloadConfig(configPath)
	if err != nil {
		return 0, fmt.Errorf("loading config: %w", err)
	}

	// 1b. Prepare the outgoing NOTIFY target list and key (F567).
	notifySend, err := notifySendFromConfig(newCfg.Transfer)
	if err != nil {
		return 0, fmt.Errorf("preparing NOTIFY: %w", err)
	}

	// 1c. Prepare the transfer.tsig_keys and slave_zones TSIG keys (F583,
	// F584); an unparsable key aborts the reload before anything is applied.
	keyPlan, err := prepareTransferKeys(newCfg, s.logger)
	if err != nil {
		return 0, fmt.Errorf("preparing TSIG keys: %w", err)
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

	// 4b. Rebuild the iterative resolver from the new resolution.* and
	// dnssec.enabled settings (runtime overrides already applied by
	// loadConfig); nil when resolution.recursive is false (F617). It
	// replaces the running resolver in step 6.
	var dnsCache *cache.Cache
	if s.handler != nil {
		dnsCache = s.handler.cache
	}
	nextResolver, err := buildIterativeResolver(newCfg, dnsCache, s.logger)
	if err != nil {
		upstreamPlan.upstreamManager.Stop()
		return len(zonePlan), fmt.Errorf("preparing iterative resolver: %w", err)
	}
	upstreamPlan.iterative = nextResolver
	upstreamPlan.replaceIterative = true

	// 5. Reload security components (blocklist, RPZ, GeoDNS, DNS64, ACL, RRL).
	currentSec := *s.securityManager
	nextSecMgr, secResult, err := reloadSecurityComponents(newCfg, currentSec, s.handler, s.apiServer, s.logger)
	if err != nil {
		upstreamPlan.upstreamManager.Stop()
		return len(zonePlan), fmt.Errorf("reloading security: %w", err)
	}

	// 6. Apply all prepared plans. The NOTIFY targets go first so a serial
	// change carried by this same reload is announced to the new list
	// (F567).
	applyNotifyTargets(s.handler, newCfg.Transfer.AlsoNotify, notifySend, s.logger)
	applyTransferKeys(s.handler, keyPlan, s.logger)
	applyConfiguredZoneFiles(s.handler, s.zoneMgr, *s.zoneFiles, zonePlan, s.logger)
	applyConfiguredViews(s.handler, viewPlan, len(newCfg.Views), s.logger)

	oldUpstream := *s.upstreamManager
	applyUpstreamComponents(upstreamPlan, oldUpstream, s.handler, s.apiServer)

	// 7. Commit the new config (also idna.enabled), then apply the cache
	// and logging tunables (F618/F619/F620).
	commitLoadedConfig(newCfg, s.cfgMu, s.cfg, s.handler)
	applyRuntimeTunables(newCfg, s.handler, s.logger)

	// 8. Update mutable state pointers. reloadSecurityComponents already
	// stopped the previous security manager.
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

// buildIterativeResolver builds the iterative resolver for cfg exactly as
// start-up does; it returns nil when resolution.recursive is false. Used at
// start and on every reload (F617), so a reload applies recursive on/off,
// max_depth, timeout, edns0_buffer_size, qname_minimization, use_0x20,
// root_hints and the DNSSEC DO bit (dnssec.enabled).
func buildIterativeResolver(cfg *config.Config, dnsCache *cache.Cache, logger *util.Logger) (*resolver.Resolver, error) {
	if cfg == nil || !cfg.Resolution.Recursive {
		return nil, nil
	}
	resolverConfig := resolver.Config{
		MaxDepth:          cfg.Resolution.MaxDepth,
		MaxCNAMEDepth:     16,
		Timeout:           5 * time.Second,
		EDNS0BufSize:      uint16(cfg.Resolution.EDNS0BufferSize),
		QnameMinimization: cfg.Resolution.QnameMinimization,
		Use0x20:           cfg.Resolution.Use0x20,
		DNSSECOK:          cfg.DNSSEC.Enabled,
	}
	if cfg.Resolution.Timeout != "" {
		if d, err := time.ParseDuration(cfg.Resolution.Timeout); err == nil {
			resolverConfig.Timeout = d
		}
	}
	if resolverConfig.EDNS0BufSize == 0 {
		resolverConfig.EDNS0BufSize = 4096
	}
	if resolverConfig.MaxDepth > 30 {
		if logger != nil {
			logger.Warnf("MaxDepth %d exceeds safe limit, clamping to 30", resolverConfig.MaxDepth)
		}
		resolverConfig.MaxDepth = 30
	}
	if cfg.Resolution.RootHints != "" {
		hints, err := loadRootHintsFile(cfg.Resolution.RootHints)
		if err != nil {
			return nil, fmt.Errorf("loading root hints file %s: %w", cfg.Resolution.RootHints, err)
		}
		resolverConfig.Hints = hints
		if logger != nil {
			logger.Infof("Loaded %d custom root hints from %s", len(hints), cfg.Resolution.RootHints)
		}
	}
	r := resolver.NewResolver(resolverConfig, &resolverCacheAdapter{cache: dnsCache}, newResolverTransport(nil, nil))
	if logger != nil {
		logger.Info("Iterative recursive resolver enabled")
		if resolverConfig.QnameMinimization {
			logger.Info("QNAME minimization enabled (RFC 7816)")
		}
		if resolverConfig.Use0x20 {
			logger.Info("0x20 encoding enabled for spoofing resistance")
		}
	}
	return r, nil
}

// applyRuntimeTunables applies the reloaded cache tunables (F618) and the
// logging level and format (F619) to the running cache and logger. cfg has
// the runtime overrides applied, so a value changed through the API keeps
// winning over the YAML exactly as at start. cache.size resizes the
// per-shard capacity (excess entries are evicted as new ones arrive).
func applyRuntimeTunables(cfg *config.Config, handler *integratedHandler, logger *util.Logger) {
	if cfg == nil {
		return
	}
	if handler != nil && handler.cache != nil {
		handler.cache.UpdateConfig(cacheConfigFromConfig(cfg))
	}
	if logger != nil {
		logger.SetLevel(logLevelFromString(cfg.Logging.Level))
		logger.SetFormat(logFormatFromString(cfg.Logging.Format))
		logIDNASettings(cfg.IDNA, logger)
	}
}

// idnaProfileFromConfig maps the idna section to the validation profile
// the pipeline applies to query names (F621).
func idnaProfileFromConfig(c config.IDNAConfig) idna.Profile {
	return idna.Profile{
		UseSTD3Rules:    c.UseSTD3Rules,
		AllowUnassigned: c.AllowUnassigned,
		CheckBidi:       c.CheckBidi,
		CheckJoiner:     c.CheckJoiner,
	}
}

// logIDNASettings reports the IDNA validation settings at start and on
// reload, and warns that idna.check_joiner has no effect (F621: the RFC
// 5892 CONTEXTJ rules are not implemented).
func logIDNASettings(c config.IDNAConfig, logger *util.Logger) {
	if logger == nil || !c.Enabled {
		return
	}
	logger.Infof("IDNA validation enabled (STD3=%v, AllowUnassigned=%v, Bidi=%v)",
		c.UseSTD3Rules, c.AllowUnassigned, c.CheckBidi)
	if c.CheckJoiner {
		logger.Warn("idna.check_joiner is deprecated and has no effect: the RFC 5892 CONTEXTJ joiner rules are always enforced")
	}
}

// applyNotifyTargets swaps the outgoing NOTIFY target list and key on reload
// (F567). Removed targets' in-flight sends are cancelled; added targets are
// notified from the next serial change.
func applyNotifyTargets(handler *integratedHandler, targets []string, send notifySendFunc, logger *util.Logger) {
	if handler == nil || handler.transfer.Notifier == nil {
		return
	}
	handler.transfer.Notifier.SetTargets(targets, send)
	if logger != nil {
		logger.Infof("NOTIFY: %d also_notify target(s) after reload", len(targets))
	}
}

// transferKeyPlan is a reload's prepared TSIG key state (F583/F584).
type transferKeyPlan struct {
	transfer config.TransferConfig
	xfer     []*transfer.TSIGKey // transfer.tsig_keys: AXFR/IXFR and DDNS
	slave    []*transfer.TSIGKey // slave_zones tsig_key_name/tsig_secret
}

func prepareTransferKeys(cfg *config.Config, logger *util.Logger) (*transferKeyPlan, error) {
	xfer, err := transferKeysFromConfig(cfg.Transfer)
	if err != nil {
		return nil, err
	}
	return &transferKeyPlan{transfer: cfg.Transfer, xfer: xfer, slave: slaveKeysFromConfig(cfg.SlaveZones, logger)}, nil
}

// applyTransferKeys applies a reload's TSIG keys (F583/F584): the AXFR/IXFR
// key store is re-synced (removed keys deleted, rotated secrets replaced,
// allowed_cidrs updated) and the DDNS handler is replaced by one built from
// the new keys and allow_update grants (a grant cannot be revoked on the
// old one). Both happen under xferKeysMu, so a transfer or UPDATE is
// authenticated entirely against the old or entirely against the new set;
// in-flight requests finish with the old set first. A removed key is
// rejected by every request that starts after this returns. The replaced
// DDNS handler is closed; its event consumer drains and exits.
//
// Slave zone keys are re-synced from the new slave_zones secrets (each key
// swap is atomic); the next transfer of a slave zone signs with the new
// secret. The slave zone list itself (zones, masters, key names) is not
// reloaded — a running slave zone whose key name disappeared from the new
// config can no longer transfer until restart (warned).
func applyTransferKeys(h *integratedHandler, plan *transferKeyPlan, logger *util.Logger) {
	if h == nil || plan == nil {
		return
	}
	var next *transfer.DynamicDNSHandler
	grants := 0
	h.xferKeysMu.RLock()
	hasDDNS := h.transfer.DDNSHandler != nil
	h.xferKeysMu.RUnlock()
	if hasDDNS {
		next, grants = newDDNSHandlerFromConfig(h.zones, plan.transfer, plan.xfer)
		next.SetZonesMu(&h.zonesMu)
	}

	h.xferKeysMu.Lock()
	h.transfer.AXFRKeys.sync(plan.xfer)
	prev := h.transfer.DDNSHandler
	if next != nil {
		h.transfer.DDNSHandler = next
	}
	h.transfer.SlaveKeys.sync(plan.slave)
	h.xferKeysMu.Unlock()

	if next != nil && prev != nil {
		prev.Close()
	}
	if logger == nil {
		return
	}
	logger.Infof("TSIG: %d transfer key(s), %d key/zone update grant(s), %d slave key(s) after reload", len(plan.xfer), grants, len(plan.slave))
	if h.transfer.SlaveManager == nil || h.transfer.SlaveKeys == nil {
		return
	}
	have := make(map[string]bool, len(plan.slave))
	for _, k := range plan.slave {
		have[transfer.CanonicalTSIGKeyName(k.Name)] = true
	}
	for name, sz := range h.transfer.SlaveManager.GetAllSlaveZones() {
		if kn := sz.Config.TSIGKeyName; kn != "" && !have[transfer.CanonicalTSIGKeyName(kn)] {
			logger.Warnf("slave zone %s: TSIG key %s is no longer configured; its transfers fail until slave_zones is fixed and the server restarted", name, kn)
		}
	}
}

// ============================================================================
// Hot-reload test helpers — exposed for testing only
// ============================================================================
