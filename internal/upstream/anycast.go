package upstream

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// AnycastGroup represents a group of servers that share the same anycast IP.
// Anycast allows multiple servers to advertise the same IP address for
// high availability and geographic distribution.
type AnycastGroup struct {
	// Anycast IP address shared by all servers in the group
	AnycastIP string

	// Physical backend servers in this anycast group
	Backends []*AnycastBackend

	// Health check configuration
	HealthCheck     time.Duration
	FailoverTimeout time.Duration

	// Current active backend index (for failover)
	activeIndex uint32

	mu sync.RWMutex
}

// AnycastBackend represents a physical server in an anycast group.
type AnycastBackend struct {
	// Physical IP address of the server
	PhysicalIP string

	// Port for DNS queries
	Port int

	// Region identifier (e.g., "us-east-1")
	Region string

	// Zone identifier within region (e.g., "a", "b")
	Zone string

	// Weight for weighted load balancing (0-100)
	Weight int

	// Health tracking
	mu          sync.RWMutex
	healthy     bool
	lastCheck   time.Time
	latency     time.Duration
	failCount   int
	successCount int
}

// IsHealthy returns true if the backend is healthy.
func (b *AnycastBackend) IsHealthy() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.healthy
}

// markFailure marks the backend as having failed.
func (b *AnycastBackend) markFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failCount++
	b.successCount = 0
	// Mark unhealthy after 3 consecutive failures
	if b.failCount >= 3 {
		b.healthy = false
	}
}

// markSuccess marks the backend as having succeeded.
func (b *AnycastBackend) markSuccess(latency time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.successCount++
	b.failCount = 0
	b.latency = latency
	b.lastCheck = time.Now()
	// Mark healthy after 2 consecutive successes
	if b.successCount >= 2 {
		b.healthy = true
	}
}

// Stats returns current health statistics.
func (b *AnycastBackend) Stats() (healthy bool, latency time.Duration, failCount, successCount int) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.healthy, b.latency, b.failCount, b.successCount
}

// Address returns the full address (IP:port) for the backend.
func (b *AnycastBackend) Address() string {
	return net.JoinHostPort(b.PhysicalIP, fmt.Sprintf("%d", b.Port))
}

// NewAnycastGroup creates a new anycast group with the given anycast IP.
func NewAnycastGroup(anycastIP string, healthCheck, failoverTimeout time.Duration) *AnycastGroup {
	return &AnycastGroup{
		AnycastIP:       anycastIP,
		Backends:        make([]*AnycastBackend, 0),
		HealthCheck:     healthCheck,
		FailoverTimeout: failoverTimeout,
		activeIndex:     0,
	}
}

// AddBackend adds a backend server to the anycast group.
func (g *AnycastGroup) AddBackend(backend *AnycastBackend) error {
	if backend.PhysicalIP == "" {
		return fmt.Errorf("backend physical IP cannot be empty")
	}
	if backend.Port == 0 {
		backend.Port = 53
	}
	if backend.Weight == 0 {
		backend.Weight = 100 // Default weight
	}
	if backend.Weight < 0 || backend.Weight > 100 {
		return fmt.Errorf("backend weight must be between 0 and 100")
	}

	// Initialize as healthy
	backend.healthy = true
	backend.lastCheck = time.Now()

	g.mu.Lock()
	g.Backends = append(g.Backends, backend)
	g.mu.Unlock()

	return nil
}

// RemoveBackend removes a backend from the anycast group.
func (g *AnycastGroup) RemoveBackend(physicalIP string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	filtered := make([]*AnycastBackend, 0, len(g.Backends))
	for _, b := range g.Backends {
		if b.PhysicalIP != physicalIP {
			filtered = append(filtered, b)
		}
	}
	g.Backends = filtered
}

// GetActiveBackend returns the currently active backend (for failover).
func (g *AnycastGroup) GetActiveBackend() *AnycastBackend {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.Backends) == 0 {
		return nil
	}

	idx := atomic.LoadUint32(&g.activeIndex)
	if int(idx) >= len(g.Backends) {
		idx = 0
		atomic.StoreUint32(&g.activeIndex, idx)
	}

	return g.Backends[idx]
}

// SelectBackend selects a backend based on health, region, and weight.
func (g *AnycastGroup) SelectBackend(preferredRegion, preferredZone string) *AnycastBackend {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.Backends) == 0 {
		return nil
	}

	// First, try to find a healthy backend in the preferred region and zone
	if preferredRegion != "" {
		for _, b := range g.Backends {
			if b.IsHealthy() && b.Region == preferredRegion {
				if preferredZone == "" || b.Zone == preferredZone {
					return b
				}
			}
		}

		// Try any healthy backend in the preferred region
		for _, b := range g.Backends {
			if b.IsHealthy() && b.Region == preferredRegion {
				return b
			}
		}
	}

	// Get all healthy backends
	var healthy []*AnycastBackend
	for _, b := range g.Backends {
		if b.IsHealthy() {
			healthy = append(healthy, b)
		}
	}

	if len(healthy) == 0 {
		// Fallback to first backend even if unhealthy
		return g.Backends[0]
	}

	// Weighted selection from healthy backends
	return weightedSelect(healthy)
}

// weightedSelect selects a backend using weighted random selection.
func weightedSelect(backends []*AnycastBackend) *AnycastBackend {
	if len(backends) == 1 {
		return backends[0]
	}

	// Calculate total weight
	totalWeight := 0
	for _, b := range backends {
		totalWeight += b.Weight
	}

	if totalWeight == 0 {
		// All weights are 0, use round-robin
		idx := int(time.Now().UnixNano()) % len(backends)
		return backends[idx]
	}

	// Weighted selection using current time nanoseconds
	// (Simple deterministic selection for load balancing)
	selector := int(time.Now().UnixNano()) % totalWeight
	currentWeight := 0

	for _, b := range backends {
		currentWeight += b.Weight
		if selector < currentWeight {
			return b
		}
	}

	// Fallback to last backend
	return backends[len(backends)-1]
}

// FailoverToNext switches to the next backend in the group.
func (g *AnycastGroup) FailoverToNext() *AnycastBackend {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.Backends) <= 1 {
		return nil
	}

	currentIdx := atomic.LoadUint32(&g.activeIndex)
	nextIdx := (int(currentIdx) + 1) % len(g.Backends)
	atomic.StoreUint32(&g.activeIndex, uint32(nextIdx))

	return g.Backends[nextIdx]
}

// GetHealthyBackends returns all healthy backends.
func (g *AnycastGroup) GetHealthyBackends() []*AnycastBackend {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var healthy []*AnycastBackend
	for _, b := range g.Backends {
		if b.IsHealthy() {
			healthy = append(healthy, b)
		}
	}
	return healthy
}

// Stats returns statistics for the anycast group.
func (g *AnycastGroup) Stats() (total, healthy int) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	total = len(g.Backends)
	for _, b := range g.Backends {
		if b.IsHealthy() {
			healthy++
		}
	}
	return total, healthy
}
