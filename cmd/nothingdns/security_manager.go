// NothingDNS - Security Manager
// Manages blocklist, RPZ, GeoDNS, ACL, and rate limiting

package main

import (
	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dns64"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/geodns"
	"github.com/nothingdns/nothingdns/internal/rpz"
	"github.com/nothingdns/nothingdns/internal/util"
)

// SecurityManagerResult holds the results of security initialization.
type SecurityManagerResult struct {
	Blocklist   *blocklist.Blocklist
	RPZEngine   *rpz.Engine
	GeoEngine   *geodns.Engine
	DNS64Synth  *dns64.Synthesizer
	ACLChecher  *filter.ACLChecker
	RateLimiter *filter.RateLimiter
	RRL        *filter.RRL
}

// SecurityManager manages DNS security features: blocklist, RPZ, GeoDNS, ACL, and rate limiting.
type SecurityManager struct {
	result SecurityManagerResult
	logger *util.Logger
}

// NewSecurityManager creates a new security manager with the given configuration.
func NewSecurityManager(cfg *config.Config, logger *util.Logger) (*SecurityManager, error) {
	mgr := &SecurityManager{logger: logger}

	// Initialize blocklist
	mgr.result.Blocklist = blocklist.New(blocklist.Config{
		Enabled: cfg.Blocklist.Enabled,
		Files:   cfg.Blocklist.Files,
		URLs:    cfg.Blocklist.URLs,
	})
	if err := mgr.result.Blocklist.Load(); err != nil {
		logger.Warnf("Failed to load blocklist: %v", err)
	} else if cfg.Blocklist.Enabled {
		stats := mgr.result.Blocklist.Stats()
		logger.Infof("Blocklist loaded with %d entries from %d files and %d URLs", stats.TotalBlocks, stats.Files, stats.URLs)
	}

	// Initialize RPZ engine
	if cfg.RPZ.Enabled {
		rpzFiles := make([]string, 0, len(cfg.RPZ.Files)+len(cfg.RPZ.Zones))
		rpzFiles = append(rpzFiles, cfg.RPZ.Files...)
		policies := make(map[string]int)
		for _, pz := range cfg.RPZ.Zones {
			rpzFiles = append(rpzFiles, pz.File)
			policies[pz.File] = pz.Priority
		}
		mgr.result.RPZEngine = rpz.NewEngine(rpz.Config{
			Enabled:  true,
			Files:    rpzFiles,
			Policies: policies,
			Logger:   logger,
		})
		if err := mgr.result.RPZEngine.Load(); err != nil {
			logger.Warnf("Failed to load RPZ zones: %v", err)
		} else {
			stats := mgr.result.RPZEngine.Stats()
			logger.Infof("RPZ engine loaded with %d rules from %d files", stats.TotalRules, stats.Files)
		}
	}

	// Initialize GeoDNS engine
	if cfg.GeoDNS.Enabled {
		mgr.result.GeoEngine = geodns.NewEngine(geodns.Config{Enabled: true})
		if cfg.GeoDNS.MMDBFile != "" {
			if err := mgr.result.GeoEngine.LoadMMDB(cfg.GeoDNS.MMDBFile); err != nil {
				logger.Warnf("Failed to load MMDB: %v", err)
			} else {
				logger.Infof("GeoDNS MMDB loaded from %s", cfg.GeoDNS.MMDBFile)
			}
		}
		for _, rule := range cfg.GeoDNS.Rules {
			mgr.result.GeoEngine.SetRule(rule.Domain, rule.Type, &geodns.GeoRecord{
				Records: rule.Records,
				Default: rule.Default,
				Type:    rule.Type,
			})
		}
		if len(cfg.GeoDNS.Rules) > 0 {
			stats := mgr.result.GeoEngine.Stats()
			logger.Infof("GeoDNS engine loaded with %d rules", stats.Rules)
		}
	}

	// Initialize DNS64 synthesizer (RFC 6147)
	if cfg.DNS64.Enabled {
		var err error
		mgr.result.DNS64Synth, err = dns64.NewSynthesizer(cfg.DNS64.Prefix, cfg.DNS64.PrefixLen)
		if err != nil {
			logger.Warnf("Failed to initialize DNS64: %v", err)
		} else {
			for _, cidr := range cfg.DNS64.ExcludeNets {
				if err := mgr.result.DNS64Synth.AddExcludeNet(cidr); err != nil {
					logger.Warnf("DNS64: invalid exclude network %q: %v", cidr, err)
				}
			}
			logger.Infof("DNS64 enabled with prefix %s/%d", cfg.DNS64.Prefix, cfg.DNS64.PrefixLen)
		}
	}

	// Initialize ACL checker
	if len(cfg.ACL) > 0 {
		var err error
		mgr.result.ACLChecher, err = filter.NewACLChecker(cfg.ACL, false)
		if err != nil {
			return nil, err
		}
		logger.Infof("ACL loaded with %d rules", len(cfg.ACL))
	} else if cfg.Resolution.Recursive && !cfg.Server.ACLAllowUnrestrictedRecursion {
		// VULN-041: Recursion enabled but no ACL rules and not explicitly allowed to be unrestricted.
		// Create a deny-by-default ACL checker to prevent open resolver.
		aclChecker, err := filter.NewACLChecker(nil, true)
		if err != nil {
			return nil, err
		}
		mgr.result.ACLChecher = aclChecker
		logger.Warnf("Recursive resolver enabled with no ACL rules and acl_allow_unrestricted_recursion=false; defaulting to deny-by-default (all clients blocked). Set explicit ACL rules or set acl_allow_unrestricted_recursion=true to allow unrestricted access.")
	}

	// Initialize rate limiter (client-side token bucket).
	if cfg.RRL.Enabled {
		mgr.result.RateLimiter = filter.NewRateLimiter(cfg.RRL)
		logger.Infof("RRL enabled: %d qps/client, burst %d", cfg.RRL.Rate, cfg.RRL.Burst)
	}

	// Initialize RRL (response-side rate limiting per RFC 8231).
	mgr.result.RRL = filter.NewRRL(filter.RRLConfig{
		Enabled:       cfg.RRL.Enabled,
		Rate:          cfg.RRL.Rate,
		Burst:         cfg.RRL.Burst,
		Window:        10,
		MaxBuckets:    cfg.RRL.MaxBuckets,
		ResponsesOnly: true,
	})

	return mgr, nil
}

// Stop stops the security manager and its components.
func (m *SecurityManager) Stop() {
	if m.result.RateLimiter != nil {
		m.result.RateLimiter.Stop()
	}
	if m.result.RRL != nil {
		m.result.RRL.Stop()
	}
}

// Result returns the security manager results.
func (m *SecurityManager) Result() *SecurityManagerResult {
	return &m.result
}

// Reload reloads blocklist and RPZ.
func (m *SecurityManager) Reload() {
	if m.result.Blocklist != nil {
		if err := m.result.Blocklist.Reload(); err != nil {
			m.logger.Warnf("Failed to reload blocklist: %v", err)
		} else {
			stats := m.result.Blocklist.Stats()
			m.logger.Infof("Reloaded blocklist with %d entries from %d files", stats.TotalBlocks, stats.Files)
		}
	}

	if m.result.RPZEngine != nil {
		if err := m.result.RPZEngine.Reload(); err != nil {
			m.logger.Warnf("Failed to reload RPZ zones: %v", err)
		} else {
			stats := m.result.RPZEngine.Stats()
			m.logger.Infof("Reloaded RPZ with %d rules from %d files", stats.TotalRules, stats.Files)
		}
	}
}
