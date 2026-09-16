package upstream

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var secureRandInt = rand.Int

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
	mu           sync.RWMutex
	healthy      bool
	lastCheck    time.Time
	latency      time.Duration
	failCount    int
	successCount int
}

// IsHealthy returns true if the backend is healthy.
func (b *AnycastBackend) IsHealthy() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.healthy
}

func (b *AnycastBackend) snapshot() *AnycastBackend {
	if b == nil {
		return nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return &AnycastBackend{
		PhysicalIP:   b.PhysicalIP,
		Port:         b.Port,
		Region:       b.Region,
		Zone:         b.Zone,
		Weight:       b.Weight,
		healthy:      b.healthy,
		lastCheck:    b.lastCheck,
		latency:      b.latency,
		failCount:    b.failCount,
		successCount: b.successCount,
	}
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
	if backend == nil {
		return fmt.Errorf("backend cannot be nil")
	}
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
		if b != nil && b.PhysicalIP != physicalIP {
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

	nextIdx, backend := firstBackendIndex(g.Backends, int(idx))
	if backend == nil {
		return nil
	}
	if uint32(nextIdx) != idx {
		atomic.StoreUint32(&g.activeIndex, uint32(nextIdx))
	}
	return backend
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
			if b == nil {
				continue
			}
			if b.IsHealthy() && b.Region == preferredRegion {
				if preferredZone == "" || b.Zone == preferredZone {
					return b
				}
			}
		}
		// If preferredZone was set but no backend matched, fall through
		// to weighted selection over ALL healthy backends below. Do NOT
		// short-circuit to the first region-match here — that would
		// bypass load balancing when the preferred zone has a temporary
		// outage. (Previously this had a second loop that returned the
		// first region-match by slice order; that loop was dead code
		// since the first loop already covers the zone-empty case.)
	}

	// Get all healthy backends
	var healthy []*AnycastBackend
	for _, b := range g.Backends {
		if b != nil && b.IsHealthy() {
			healthy = append(healthy, b)
		}
	}

	if len(healthy) == 0 {
		// Fallback to first backend even if unhealthy
		return firstBackend(g.Backends)
	}

	// Weighted selection from healthy backends
	return weightedSelect(healthy)
}

// weightedSelect selects a backend using weighted random selection.
func weightedSelect(backends []*AnycastBackend) *AnycastBackend {
	backends = nonNilBackends(backends)
	if len(backends) == 0 {
		return nil
	}
	if len(backends) == 1 {
		return backends[0]
	}

	// Calculate total weight
	totalWeight := 0
	for _, b := range backends {
		totalWeight += b.Weight
	}

	if totalWeight == 0 {
		// All weights are 0, pick randomly using crypto/rand.
		idx, ok := randomInt(int64(len(backends)))
		if !ok {
			return backends[0]
		}
		return backends[idx]
	}

	// Weighted random selection for load balancing
	selectorVal, ok := randomInt(int64(totalWeight))
	if !ok {
		return backends[0]
	}
	currentWeight := 0

	for _, b := range backends {
		currentWeight += b.Weight
		if selectorVal < int64(currentWeight) {
			return b
		}
	}

	// Fallback to last backend
	return backends[len(backends)-1]
}

func randomInt(max int64) (int64, bool) {
	if max <= 0 {
		return 0, false
	}
	n, err := secureRandInt(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, false
	}
	return n.Int64(), true
}

func firstBackend(backends []*AnycastBackend) *AnycastBackend {
	_, backend := firstBackendIndex(backends, 0)
	return backend
}

func firstBackendIndex(backends []*AnycastBackend, start int) (int, *AnycastBackend) {
	if len(backends) == 0 {
		return -1, nil
	}
	if start < 0 || start >= len(backends) {
		start = 0
	}
	for i := 0; i < len(backends); i++ {
		idx := (start + i) % len(backends)
		if backends[idx] != nil {
			return idx, backends[idx]
		}
	}
	return -1, nil
}

func nonNilBackendCount(backends []*AnycastBackend) int {
	count := 0
	for _, b := range backends {
		if b != nil {
			count++
		}
	}
	return count
}

func nonNilBackends(backends []*AnycastBackend) []*AnycastBackend {
	if len(backends) == 0 {
		return nil
	}
	filtered := make([]*AnycastBackend, 0, len(backends))
	for _, b := range backends {
		if b != nil {
			filtered = append(filtered, b)
		}
	}
	return filtered
}

// FailoverToNext switches to the next backend in the group.
func (g *AnycastGroup) FailoverToNext() *AnycastBackend {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.Backends) <= 1 {
		return nil
	}
	if nonNilBackendCount(g.Backends) <= 1 {
		return nil
	}

	currentIdx := atomic.LoadUint32(&g.activeIndex)
	nextIdx, backend := firstBackendIndex(g.Backends, int(currentIdx)+1)
	if backend == nil {
		return nil
	}
	atomic.StoreUint32(&g.activeIndex, uint32(nextIdx))

	return backend
}

// GetHealthyBackends returns all healthy backends.
func (g *AnycastGroup) GetHealthyBackends() []*AnycastBackend {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var healthy []*AnycastBackend
	for _, b := range g.Backends {
		if b != nil && b.IsHealthy() {
			healthy = append(healthy, b.snapshot())
		}
	}
	return healthy
}

func (g *AnycastGroup) snapshot() *AnycastGroup {
	if g == nil {
		return nil
	}
	g.mu.RLock()
	defer g.mu.RUnlock()

	backends := make([]*AnycastBackend, len(g.Backends))
	for i, backend := range g.Backends {
		backends[i] = backend.snapshot()
	}
	return &AnycastGroup{
		AnycastIP:       g.AnycastIP,
		Backends:        backends,
		HealthCheck:     g.HealthCheck,
		FailoverTimeout: g.FailoverTimeout,
		activeIndex:     atomic.LoadUint32(&g.activeIndex),
	}
}

// Stats returns statistics for the anycast group.
func (g *AnycastGroup) Stats() (total, healthy int) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, b := range g.Backends {
		if b == nil {
			continue
		}
		total++
		if b.IsHealthy() {
			healthy++
		}
	}
	return total, healthy
}
