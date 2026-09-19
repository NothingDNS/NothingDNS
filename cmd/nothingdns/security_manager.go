// NothingDNS - Security Manager
// Manages blocklist, RPZ, GeoDNS, ACL, and rate limiting

package main

import (
	"fmt"
	"strings"

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
	ACLChecker  *filter.ACLChecker
	RateLimiter *filter.RateLimiter
	RRL         *filter.RRL
	// RecursionPolicy limits recursion (forwarding, iterative resolution,
	// cached answers) to allowed clients.
	RecursionPolicy *filter.RecursionPolicy
	// AccessPolicyFile stores dashboard changes to the ACL and recursion
	// allow list ("" when storage.data_dir is unset).
	AccessPolicyFile string
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
		BaseDir: cfg.Blocklist.BaseDir,
	})
	if err := mgr.result.Blocklist.Load(); err != nil {
		return nil, fmt.Errorf("loading blocklist: %w", err)
	} else if cfg.Blocklist.Enabled {
		stats := mgr.result.Blocklist.Stats()
		logger.Infof("Blocklist loaded with %d entries from %d files and %d URLs", stats.TotalBlocks, stats.Files, stats.URLs)
	}

	// Initialize RPZ engine. Like the blocklist it always exists — disabled
	// engines match nothing — so the dashboard/API can enable it and add
	// rules at runtime. With a nil engine every toggle and rule request
	// returned 503 "RPZ not available" unless rpz.enabled was set in config.
	rpzFiles := make([]string, 0, len(cfg.RPZ.Files)+len(cfg.RPZ.Zones))
	rpzFiles = append(rpzFiles, cfg.RPZ.Files...)
	policies := make(map[string]int)
	for _, pz := range cfg.RPZ.Zones {
		rpzFiles = append(rpzFiles, pz.File)
		policies[pz.File] = pz.Priority
	}
	mgr.result.RPZEngine = rpz.NewEngine(rpz.Config{
		Enabled:  cfg.RPZ.Enabled,
		Files:    rpzFiles,
		Policies: policies,
		Logger:   logger,
	})
	if err := mgr.result.RPZEngine.Load(); err != nil {
		return nil, fmt.Errorf("loading RPZ zones: %w", err)
	} else if cfg.RPZ.Enabled {
		stats := mgr.result.RPZEngine.Stats()
		logger.Infof("RPZ engine loaded with %d rules from %d files", stats.TotalRules, stats.Files)
	}

	// Initialize GeoDNS engine
	if cfg.GeoDNS.Enabled {
		mgr.result.GeoEngine = geodns.NewEngine(geodns.Config{Enabled: true})
		if cfg.GeoDNS.MMDBFile != "" {
			if err := mgr.result.GeoEngine.LoadMMDB(cfg.GeoDNS.MMDBFile); err != nil {
				return nil, fmt.Errorf("loading GeoDNS MMDB: %w", err)
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
			return nil, fmt.Errorf("initializing DNS64: %w", err)
		} else {
			for _, cidr := range cfg.DNS64.ExcludeNets {
				if err := mgr.result.DNS64Synth.AddExcludeNet(cidr); err != nil {
					return nil, fmt.Errorf("adding DNS64 exclude network %q: %w", cidr, err)
				}
			}
			logger.Infof("DNS64 enabled with prefix %s/%d", cfg.DNS64.Prefix, cfg.DNS64.PrefixLen)
		}
	}

	// Initialize the ACL and the recursion allow list.
	if err := mgr.initAccessPolicy(cfg); err != nil {
		return nil, err
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

// initAccessPolicy builds the general ACL and the recursion policy.
//
// The general ACL applies to every query; an empty ACL admits everyone, so
// the server's own zones are answered for all clients by default.
// Recursion is decided separately (VULN-041: never an open resolver by
// accident):
//   - allow_recursion present in the config: exactly those networks;
//   - acl_allow_unrestricted_recursion: true: every client;
//   - general ACL rules configured but no allow_recursion: every client
//     the ACL admits (the pre-allow_recursion behaviour);
//   - otherwise: loopback and private networks only.
//
// A stored access policy (dashboard changes) replaces both lists.
func (m *SecurityManager) initAccessPolicy(cfg *config.Config) error {
	aclRules := cfg.ACL
	recursion := filter.DefaultRecursionNetworks
	recursionAll := false
	switch {
	case cfg.AllowRecursionSet:
		recursion = cfg.AllowRecursion
	case cfg.Server.ACLAllowUnrestrictedRecursion:
		recursionAll = true
	case len(cfg.ACL) > 0:
		recursionAll = true
	}

	m.result.AccessPolicyFile = filter.AccessPolicyFile(cfg.Storage.DataDir)
	stored, err := filter.LoadAccessPolicy(m.result.AccessPolicyFile)
	if err != nil {
		return fmt.Errorf("loading access policy: %w", err)
	}
	if stored != nil {
		aclRules = stored.ConfigRules()
		recursion = stored.AllowRecursion
		recursionAll = false
		m.logger.Infof("Access policy loaded from %s (overrides acl and allow_recursion in the config file)", m.result.AccessPolicyFile)
	}

	m.result.ACLChecker = filter.NewEmptyACLChecker()
	if err := m.result.ACLChecker.UpdateRules(aclRules); err != nil {
		return err
	}
	if len(aclRules) > 0 {
		m.logger.Infof("ACL loaded with %d rules", len(aclRules))
	}

	m.result.RecursionPolicy, err = filter.NewRecursionPolicy(recursion, recursionAll)
	if err != nil {
		return err
	}
	if recursionAll {
		m.logger.Infof("Recursion allowed for every client admitted by the ACL")
	} else {
		m.logger.Infof("Recursion allowed for: %s", strings.Join(m.result.RecursionPolicy.Networks(), ", "))
	}
	return nil
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
