// NothingDNS - DNSSEC Manager
// Manages DNSSEC validation and trust anchors

package main

import (
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/util"
)

// DNSSECManager manages DNSSEC validation and trust anchors.
type DNSSECManager struct {
	Validator *dnssec.Validator
	logger    *util.Logger
}

// NewDNSSECManager creates a new DNSSEC manager with the given configuration.
// The resolverAdapter should be the dnssecResolverAdapter from adapters.go.
func NewDNSSECManager(cfg *config.Config, resolverAdapter dnssec.Resolver, logger *util.Logger) (*DNSSECManager, error) {
	if !cfg.DNSSEC.Enabled || resolverAdapter == nil {
		return &DNSSECManager{logger: logger}, nil
	}

	mgr := &DNSSECManager{logger: logger}

	trustAnchors := dnssec.NewTrustAnchorStoreWithBuiltIn()

	// Load custom trust anchors if specified
	if cfg.DNSSEC.TrustAnchor != "" {
		if err := trustAnchors.LoadFromFile(cfg.DNSSEC.TrustAnchor); err != nil {
			logger.Warnf("Failed to load trust anchor file: %v", err)
		} else {
			logger.Infof("Loaded trust anchors from %s", cfg.DNSSEC.TrustAnchor)
		}
	}

	mgr.Validator = dnssec.NewValidator(dnssec.ValidatorConfig{
		Enabled:    cfg.DNSSEC.Enabled,
		IgnoreTime: cfg.DNSSEC.IgnoreTime,
	}, trustAnchors, resolverAdapter)

	logger.Info("DNSSEC validation enabled")

	return mgr, nil
}
