// NothingDNS - Zone Provider Interface
// Unified zone lookup interface to replace the quadruple source pattern

package main

import (
	"slices"
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

// zoneAppender is implemented by the built-in providers so MultiZoneProvider
// can collect matches into one slice: FindZones on the hot path then allocates
// that slice only, instead of a slice, a closure and a captured variable per
// provider.
type zoneAppender interface {
	appendZones(dst []ZoneMatch, qname string) []ZoneMatch
}

// appendMatch appends m, giving a nil dst room for a few matches at once (a
// query matches at most a handful of zones) while leaving it nil, with no
// allocation, when nothing matches.
func appendMatch(dst []ZoneMatch, m ZoneMatch) []ZoneMatch {
	if dst == nil {
		dst = make([]ZoneMatch, 0, 4)
	}
	return append(dst, m)
}

// FindZones queries all providers and merges results.
func (m *MultiZoneProvider) FindZones(qname string) []ZoneMatch {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matches []ZoneMatch
	for _, p := range m.providers {
		if a, ok := p.(zoneAppender); ok {
			matches = a.appendZones(matches, qname)
		} else {
			matches = append(matches, p.FindZones(qname)...)
		}
	}
	matches = dedupeZoneMatches(matches)

	// Sort by origin length descending (most specific first)
	sortZonesByLength(matches)
	return matches
}

// dedupeZoneMatches drops later matches for an origin already present (the
// earlier provider wins). A query matches few zones, so the quadratic scan
// beats a map.
func dedupeZoneMatches(matches []ZoneMatch) []ZoneMatch {
	out := matches[:0]
	for _, m := range matches {
		dup := false
		for i := range out {
			if out[i].Origin == m.Origin {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, m)
		}
	}
	return out
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
	return p.appendZones(nil, qname)
}

func (p *staticZoneProvider) appendZones(dst []ZoneMatch, qname string) []ZoneMatch {
	for origin, z := range p.zones {
		if isSubdomain(qname, origin) {
			dst = appendMatch(dst, ZoneMatch{origin, z})
		}
	}
	return dst
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
	return p.appendZones(nil, qname)
}

func (p *managerZoneProvider) appendZones(dst []ZoneMatch, qname string) []ZoneMatch {
	p.manager.Range(func(name string, z *zone.Zone) bool {
		if isSubdomain(qname, name) {
			dst = appendMatch(dst, ZoneMatch{name, z})
		}
		return true
	})
	return dst
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
	return p.appendZones(nil, qname)
}

func (p *kvZoneProvider) appendZones(dst []ZoneMatch, qname string) []ZoneMatch {
	p.kv.Manager().Range(func(name string, z *zone.Zone) bool {
		if isSubdomain(qname, name) {
			dst = appendMatch(dst, ZoneMatch{name, z})
		}
		return true
	})
	return dst
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
	return p.appendZones(nil, qname)
}

func (p *radixZoneProvider) appendZones(dst []ZoneMatch, qname string) []ZoneMatch {
	if p.tree == nil {
		return dst
	}
	if best := p.tree.Find(qname); best != nil {
		dst = appendMatch(dst, ZoneMatch{best.Origin, best})
	}
	return dst
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
	return p.appendZones(nil, qname)
}

func (p *slaveZoneProvider) appendZones(dst []ZoneMatch, qname string) []ZoneMatch {
	for name, z := range p.ListZones() {
		if isSubdomain(qname, name) {
			dst = appendMatch(dst, ZoneMatch{name, z})
		}
	}
	return dst
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
	slices.SortStableFunc(zones, func(a, b ZoneMatch) int {
		return len(b.Origin) - len(a.Origin)
	})
}
