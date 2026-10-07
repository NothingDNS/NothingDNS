// NothingDNS - Zone Provider Interface
// Unified zone lookup interface to replace the quadruple source pattern

package main

import (
	"sort"
	"sync"

	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ZoneProvider defines the interface for zone lookups.
// Implementations can combine multiple zone sources.
type ZoneProvider interface {
	// FindZones returns all zones that could match the given domain name,
	// sorted by specificity (longest match first).
	FindZones(qname string) []ZoneMatch

	// ListZones returns all zones managed by this provider.
	ListZones() map[string]*zone.Zone

	// GetZone returns the zone for the exact given origin, if present.
	GetZone(origin string) (*zone.Zone, bool)
}

// ZoneMatch represents a matched zone with its origin.
type ZoneMatch struct {
	Origin string
	Zone   *zone.Zone
}

// MultiZoneProvider combines multiple ZoneProviders into one.
// Queries each provider in order and merges results.
type MultiZoneProvider struct {
	providers []ZoneProvider
	mu        sync.RWMutex
}

// NewMultiZoneProvider creates a new MultiZoneProvider from existing sources.
func NewMultiZoneProvider(
	zones map[string]*zone.Zone,
	zoneManager *zone.Manager,
	kvPersistence *zone.KVPersistence,
	zoneTree *zone.RadixTree,
) *MultiZoneProvider {
	providers := make([]ZoneProvider, 0, 4)

	// Always add static zones
	if len(zones) > 0 {
		providers = append(providers, &staticZoneProvider{zones: zones})
	}

	// Add zone manager if present
	if zoneManager != nil {
		providers = append(providers, &managerZoneProvider{manager: zoneManager})
	}

	// Add KV persistence if present
	if kvPersistence != nil {
		providers = append(providers, &kvZoneProvider{kv: kvPersistence})
	}

	// Add radix tree for O(log n) lookup
	if zoneTree != nil {
		providers = append(providers, &radixZoneProvider{tree: zoneTree})
	}

	return &MultiZoneProvider{providers: providers}
}

// withSlaveZones appends the transferred slave zones of sm (nil: no-op) as
// the lowest-priority source. Slave zones live only in the SlaveManager, so
// without this a secondary never answered for the zones it replicates (F397).
func (m *MultiZoneProvider) withSlaveZones(sm *transfer.SlaveManager) *MultiZoneProvider {
	if sm != nil {
		m.providers = append(m.providers, &slaveZoneProvider{sm: sm})
	}
	return m
}

// FindZones queries all providers and merges results.
func (m *MultiZoneProvider) FindZones(qname string) []ZoneMatch {
	m.mu.RLock()
	defer m.mu.RUnlock()

	seen := make(map[string]struct{})
	var matches []ZoneMatch

	for _, p := range m.providers {
		for _, match := range p.FindZones(qname) {
			if _, exists := seen[match.Origin]; !exists {
				matches = append(matches, match)
				seen[match.Origin] = struct{}{}
			}
		}
	}

	// Sort by origin length descending (most specific first)
	sortZonesByLength(matches)
	return matches
}

// ListZones returns all zones from all providers.
func (m *MultiZoneProvider) ListZones() map[string]*zone.Zone {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*zone.Zone)
	for _, p := range m.providers {
		for k, v := range p.ListZones() {
			result[k] = v
		}
	}
	return result
}

// GetZone returns the zone for the exact origin.
func (m *MultiZoneProvider) GetZone(origin string) (*zone.Zone, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.providers {
		if zone, found := p.GetZone(origin); found {
			return zone, true
		}
	}
	return nil, false
}

// staticZoneProvider provides zones from a map.
type staticZoneProvider struct {
	zones map[string]*zone.Zone
}

func (p *staticZoneProvider) FindZones(qname string) []ZoneMatch {
	var matches []ZoneMatch
	for origin, z := range p.zones {
		if isSubdomain(qname, origin) {
			matches = append(matches, ZoneMatch{origin, z})
		}
	}
	return matches
}

func (p *staticZoneProvider) ListZones() map[string]*zone.Zone {
	return p.zones
}

func (p *staticZoneProvider) GetZone(origin string) (*zone.Zone, bool) {
	z, ok := p.zones[origin]
	return z, ok
}

// managerZoneProvider provides zones from a zone.Manager.
type managerZoneProvider struct {
	manager *zone.Manager
}

func (p *managerZoneProvider) FindZones(qname string) []ZoneMatch {
	var matches []ZoneMatch
	for name, z := range p.manager.List() {
		if isSubdomain(qname, name) {
			matches = append(matches, ZoneMatch{name, z})
		}
	}
	return matches
}

func (p *managerZoneProvider) ListZones() map[string]*zone.Zone {
	return p.manager.List()
}

func (p *managerZoneProvider) GetZone(origin string) (*zone.Zone, bool) {
	return p.manager.Get(origin)
}

// kvZoneProvider provides zones from KVPersistence.
type kvZoneProvider struct {
	kv *zone.KVPersistence
}

func (p *kvZoneProvider) FindZones(qname string) []ZoneMatch {
	var matches []ZoneMatch
	for name, z := range p.kv.Manager().List() {
		if isSubdomain(qname, name) {
			matches = append(matches, ZoneMatch{name, z})
		}
	}
	return matches
}

func (p *kvZoneProvider) ListZones() map[string]*zone.Zone {
	return p.kv.Manager().List()
}

func (p *kvZoneProvider) GetZone(origin string) (*zone.Zone, bool) {
	return p.kv.Manager().Get(origin)
}

// radixZoneProvider provides zones from a RadixTree.
type radixZoneProvider struct {
	tree *zone.RadixTree
}

func (p *radixZoneProvider) FindZones(qname string) []ZoneMatch {
	if p.tree == nil {
		return nil
	}
	best := p.tree.Find(qname)
	if best == nil {
		return nil
	}
	return []ZoneMatch{{best.Origin, best}}
}

func (p *radixZoneProvider) ListZones() map[string]*zone.Zone {
	if p.tree == nil {
		return nil
	}
	return p.tree.List()
}

func (p *radixZoneProvider) GetZone(origin string) (*zone.Zone, bool) {
	if p.tree == nil {
		return nil, false
	}
	zone := p.tree.Find(origin)
	if zone == nil {
		return nil, false
	}
	return zone, canonicalize(zone.Origin) == canonicalize(origin)
}

// slaveZoneProvider serves the zones a SlaveManager has transferred. It reads
// the live SlaveZone data on every call, so a completed transfer (which
// replaces the zone object) is visible without a rebuild. A slave zone that
// has not completed a transfer yet (no SOA) is not served, and neither is one
// whose SOA EXPIRE interval elapsed without a successful refresh (RFC 1035
// §4.3.5; F447).
type slaveZoneProvider struct {
	sm *transfer.SlaveManager
}

func (p *slaveZoneProvider) ListZones() map[string]*zone.Zone {
	result := make(map[string]*zone.Zone)
	for name, sz := range p.sm.GetAllSlaveZones() {
		if z := sz.GetZone(); z != nil && sz.IsServable() {
			result[name] = z
		}
	}
	return result
}

func (p *slaveZoneProvider) FindZones(qname string) []ZoneMatch {
	var matches []ZoneMatch
	for name, z := range p.ListZones() {
		if isSubdomain(qname, name) {
			matches = append(matches, ZoneMatch{name, z})
		}
	}
	return matches
}

func (p *slaveZoneProvider) GetZone(origin string) (*zone.Zone, bool) {
	sz := p.sm.GetSlaveZone(origin)
	if sz == nil {
		return nil, false
	}
	z := sz.GetZone()
	if z == nil || !sz.IsServable() {
		return nil, false
	}
	return z, true
}

// localZonesLocked returns the static zones plus the transferred slave zones
// (a static zone wins on the same origin), for the CNAME paths that scan
// whole zone sets rather than routing through the zone provider (F398).
// The caller must hold zonesMu (at least RLock).
func (h *integratedHandler) localZonesLocked() map[string]*zone.Zone {
	if h.transfer.SlaveManager == nil {
		return h.zones
	}
	slaves := (&slaveZoneProvider{sm: h.transfer.SlaveManager}).ListZones()
	if len(slaves) == 0 {
		return h.zones
	}
	for origin, z := range h.zones {
		slaves[origin] = z
	}
	return slaves
}

// sortZonesByLength sorts zones by origin length descending (most specific first).
func sortZonesByLength(zones []ZoneMatch) {
	sort.Slice(zones, func(i, j int) bool {
		return len(zones[i].Origin) > len(zones[j].Origin)
	})
}
