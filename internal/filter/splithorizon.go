// Package filter provides DNS query filtering and policy enforcement.
//
// SplitHorizon implements view-based DNS resolution where different clients
// receive different answers based on their source IP address. Each view has
// its own set of zone files, allowing internal/external split-DNS deployments.

package filter

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// View represents a single named DNS view with client matching rules
// and its own set of zone file paths.
type View struct {
	// Name is a unique identifier for this view (e.g., "internal", "external").
	Name string

	// MatchClients contains CIDR networks that this view matches.
	// The first matching view wins; use "0.0.0.0/0" and "::/0" for a default/catch-all.
	MatchClients []*net.IPNet

	// ZoneFiles lists zone file paths that belong to this view.
	// These are loaded separately from the global zone list.
	ZoneFiles []string
}

// SplitHorizon manages view-based DNS resolution.
// Views are evaluated in order; the first view whose MatchClients
// contains the client IP is selected. If no view matches, the
// default view (if any) is returned.
type SplitHorizon struct {
	mu    sync.RWMutex
	views []*View
}

// NewSplitHorizon creates a SplitHorizon engine from a list of view
// configurations. Views are evaluated in the order provided.
func NewSplitHorizon(configs []ViewConfig) (*SplitHorizon, error) {
	sh := &SplitHorizon{}

	for _, cfg := range configs {
		v, err := newView(cfg)
		if err != nil {
			return nil, fmt.Errorf("view %q: %w", cfg.Name, err)
		}
		sh.views = append(sh.views, v)
	}

	return sh, nil
}

// ViewConfig is the configuration for a single view.
type ViewConfig struct {
	Name         string   // View name
	MatchClients []string // CIDRs or "any" for catch-all
	ZoneFiles    []string // Zone file paths for this view
}

// newView constructs a View from a ViewConfig.
func newView(cfg ViewConfig) (*View, error) {
	v := &View{
		Name:      cfg.Name,
		ZoneFiles: cfg.ZoneFiles,
	}

	for _, cidr := range cfg.MatchClients {
		cidr = strings.TrimSpace(cidr)

		// "any" is shorthand for match-all
		if strings.EqualFold(cidr, "any") {
			_, ipnet, _ := net.ParseCIDR("0.0.0.0/0")
			v.MatchClients = append(v.MatchClients, ipnet)
			_, ipnet6, _ := net.ParseCIDR("::/0")
			v.MatchClients = append(v.MatchClients, ipnet6)
			continue
		}

		// Ensure it's a CIDR, not a bare IP
		if !strings.Contains(cidr, "/") {
			ip := net.ParseIP(cidr)
			if ip == nil {
				return nil, fmt.Errorf("invalid match_clients entry: %q", cidr)
			}
			if ip.To4() != nil {
				cidr = cidr + "/32"
			} else {
				cidr = cidr + "/128"
			}
		}

		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		v.MatchClients = append(v.MatchClients, ipnet)
	}

	return v, nil
}

// SelectView returns the first view whose MatchClients contains the given
// client IP. Returns nil if no view matches.
func (sh *SplitHorizon) SelectView(clientIP net.IP) *View {
	if clientIP == nil {
		return nil
	}

	sh.mu.RLock()
	defer sh.mu.RUnlock()

	for _, v := range sh.views {
		for _, ipnet := range v.MatchClients {
			if ipnet.Contains(clientIP) {
				return v
			}
		}
	}

	return nil
}

// Views returns a copy of the configured views.
func (sh *SplitHorizon) Views() []*View {
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	out := make([]*View, len(sh.views))
	copy(out, sh.views)
	return out
}

// ViewNames returns the names of all configured views in order.
func (sh *SplitHorizon) ViewNames() []string {
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	names := make([]string, len(sh.views))
	for i, v := range sh.views {
		names[i] = v.Name
	}
	return names
}
