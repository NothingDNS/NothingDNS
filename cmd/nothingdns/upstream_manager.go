// NothingDNS - Upstream Manager
// Manages upstream DNS client and load balancer

package main

import (
	"fmt"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/upstream"
	"github.com/nothingdns/nothingdns/internal/util"
)

// UpstreamManager manages the upstream DNS client and optional load balancer.
type UpstreamManager struct {
	Client       *upstream.Client
	LoadBalancer *upstream.LoadBalancer
	logger       *util.Logger
}

// NewUpstreamManager creates a new upstream manager with the given configuration.
func NewUpstreamManager(cfg *config.Config, logger *util.Logger) (*UpstreamManager, error) {
	mgr := &UpstreamManager{logger: logger}

	if len(cfg.Upstream.Servers) == 0 && len(cfg.Upstream.AnycastGroups) == 0 {
		return mgr, nil
	}

	// Check if anycast groups are configured
	if len(cfg.Upstream.AnycastGroups) > 0 {
		// Use advanced load balancer with anycast support
		lbConfig := upstream.LoadBalancerConfig{
			Servers:         cfg.Upstream.Servers,
			Strategy:        cfg.Upstream.Strategy,
			Timeout:         parseDurationOrDefault(cfg.Resolution.Timeout, 5*time.Second),
			HealthCheck:     parseDurationOrDefault(cfg.Upstream.HealthCheck, 30*time.Second),
			FailoverTimeout: parseDurationOrDefault(cfg.Upstream.FailoverTimeout, 5*time.Second),
			Region:          cfg.Upstream.Topology.Region,
			Zone:            cfg.Upstream.Topology.Zone,
			Weight:          cfg.Upstream.Topology.Weight,
		}

		// Convert anycast group configs
		for _, groupConfig := range cfg.Upstream.AnycastGroups {
			group := upstream.AnycastGroupConfig{
				AnycastIP:   groupConfig.AnycastIP,
				HealthCheck: groupConfig.HealthCheck,
			}
			for _, backendConfig := range groupConfig.Backends {
				group.Backends = append(group.Backends, upstream.AnycastBackendConfig{
					PhysicalIP: backendConfig.PhysicalIP,
					Port:       backendConfig.Port,
					Region:     backendConfig.Region,
					Zone:       backendConfig.Zone,
					Weight:     backendConfig.Weight,
				})
			}
			lbConfig.AnycastGroups = append(lbConfig.AnycastGroups, group)
		}

		var err error
		mgr.LoadBalancer, err = upstream.NewLoadBalancer(lbConfig)
		if err != nil {
			return nil, fmt.Errorf("initializing upstream load balancer: %w", err)
		}
		totalBackends := 0
		for _, group := range mgr.LoadBalancer.GetAnycastGroups() {
			total, _ := group.Stats()
			totalBackends += total
		}
		logger.Infof("Load balancer initialized with %d anycast groups (%d total backends)",
			len(lbConfig.AnycastGroups), totalBackends)
		if len(cfg.Upstream.Servers) > 0 {
			logger.Infof("Load balancer also has %d standalone servers (used when no anycast backend is healthy)", len(cfg.Upstream.Servers))
		}
	} else {
		// Use standard upstream client
		upstreamConfig := upstream.Config{
			Servers:     cfg.Upstream.Servers,
			Strategy:    cfg.Upstream.Strategy,
			Timeout:     parseDurationOrDefault(cfg.Resolution.Timeout, 5*time.Second),
			HealthCheck: parseDurationOrDefault(cfg.Upstream.HealthCheck, 30*time.Second),
		}
		var err error
		mgr.Client, err = upstream.NewClient(upstreamConfig)
		if err != nil {
			return nil, fmt.Errorf("initializing upstream client: %w", err)
		}
		logger.Infof("Upstream client initialized with %d servers", len(cfg.Upstream.Servers))
	}

	return mgr, nil
}

// Stop stops the upstream manager and its components.
func (m *UpstreamManager) Stop() {
	if m == nil {
		return
	}
	if m.Client != nil {
		logManagerStopError(m.logger, "upstream client", m.Client.Close())
	}
	if m.LoadBalancer != nil {
		logManagerStopError(m.logger, "upstream load balancer", m.LoadBalancer.Close())
	}
}

func logManagerStopError(logger *util.Logger, component string, err error) {
	if err == nil {
		return
	}
	if logger != nil {
		logger.Warnf("Failed to stop %s: %v", component, err)
		return
	}
	util.Warnf("Failed to stop %s: %v", component, err)
}

// Resolver returns an adapter that implements the dnssec.Resolver interface.
// With no upstream configured the adapter's upstream stays nil (a typed-nil
// *upstream.Client in the interface would nil-panic on Query); the caller is
// expected to wire in the iterative resolver via SetIterative for that case.
func (m *UpstreamManager) Resolver() *dnssecResolverAdapter {
	if m.LoadBalancer != nil {
		return &dnssecResolverAdapter{upstream: m.LoadBalancer}
	}
	if m.Client != nil {
		return &dnssecResolverAdapter{upstream: m.Client}
	}
	return &dnssecResolverAdapter{}
}
