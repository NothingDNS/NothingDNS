// NothingDNS - Manager Interfaces
// Interfaces for testability - enables mock implementations

package main

import (
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ZoneManagerInterface defines the interface for zone management.
type ZoneManagerInterface interface {
	// List returns all zones.
	List() map[string]*zone.Zone

	// Get returns a zone by origin.
	Get(origin string) (*zone.Zone, bool)

	// LoadZone loads a zone in-memory without validation.
	LoadZone(z *zone.Zone, file string)

	// ReloadZone reloads a zone from its file.
	ReloadZone(origin string) error
}

// CacheManagerInterface defines the interface for DNS cache management.
type CacheManagerInterface interface {
	// Get returns a cached response for the given key.
	Get(key string) any

	// Set stores a response in the cache.
	Set(key string, value any)

	// Delete removes a response from the cache.
	Delete(key string)

	// Clear removes all entries from the cache.
	Clear()

	// Size returns the number of entries in the cache.
	Size() int
}

// SecurityManagerInterface defines the interface for security management.
type SecurityManagerInterface interface {
	// Result returns the security components.
	Result() *SecurityManagerResult

	// Reload reloads security configurations.
	Reload()

	// Stop stops the security manager.
	Stop()
}

// ClusterManagerInterface defines the interface for cluster management.
type ClusterManagerInterface interface {
	// IsLeader returns true if this node is the cluster leader.
	IsLeader() bool

	// Join joins the cluster.
	Join(address string) error

	// Leave removes this node from the cluster.
	Leave() error

	// Members returns the list of cluster members.
	Members() []string
}

// TransferManagerInterface defines the interface for zone transfer management.
type TransferManagerInterface interface {
	// Result returns the transfer components.
	Result() *TransferManagerResult

	// Reload reloads transfer configurations.
	Reload()

	// Stop stops the transfer manager.
	Stop()
}
