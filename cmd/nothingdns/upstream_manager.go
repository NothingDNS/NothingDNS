// NothingDNS - Upstream Manager
// Manages upstream DNS client and load balancer

package main

import (
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
			logger.Warnf("Failed to initialize load balancer: %v", err)
		} else {
			totalBackends := 0
			for _, group := range mgr.LoadBalancer.GetAnycastGroups() {
				total, _ := group.Stats()
				totalBackends += total
			}
			logger.Infof("Load balancer initialized with %d anycast groups (%d total backends)",
				len(lbConfig.AnycastGroups), totalBackends)
			if len(cfg.Upstream.Servers) > 0 {
				logger.Infof("Load balancer also has %d standalone servers", len(cfg.Upstream.Servers))
			}
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
			logger.Warnf("Failed to initialize upstream client: %v", err)
		} else {
			logger.Infof("Upstream client initialized with %d servers", len(cfg.Upstream.Servers))
		}
	}

	return mgr, nil
}

// Stop stops the upstream manager and its components.
func (m *UpstreamManager) Stop() {
	if m.Client != nil {
		m.Client.Close()
	}
	if m.LoadBalancer != nil {
		m.LoadBalancer.Close()
	}
}

// Resolver returns an adapter that implements the dnssec.Resolver interface.
func (m *UpstreamManager) Resolver() *dnssecResolverAdapter {
	if m.LoadBalancer != nil {
		return &dnssecResolverAdapter{upstream: m.LoadBalancer}
	}
	return &dnssecResolverAdapter{upstream: m.Client}
}
