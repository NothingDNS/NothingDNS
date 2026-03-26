package upstream

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewAnycastGroup(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	if group == nil {
		t.Fatal("NewAnycastGroup returned nil")
	}

	if group.AnycastIP != "192.0.2.1" {
		t.Errorf("Expected AnycastIP to be '192.0.2.1', got '%s'", group.AnycastIP)
	}

	if group.HealthCheck != 30*time.Second {
		t.Errorf("Expected HealthCheck to be 30s, got %v", group.HealthCheck)
	}

	if group.FailoverTimeout != 5*time.Second {
		t.Errorf("Expected FailoverTimeout to be 5s, got %v", group.FailoverTimeout)
	}

	if len(group.Backends) != 0 {
		t.Errorf("Expected 0 backends, got %d", len(group.Backends))
	}
}

func TestAnycastGroupAddBackend(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	backend := &AnycastBackend{
		PhysicalIP: "10.0.1.1",
		Port:       53,
		Region:     "us-east-1",
		Zone:       "a",
		Weight:     50,
	}

	err := group.AddBackend(backend)
	if err != nil {
		t.Fatalf("AddBackend failed: %v", err)
	}

	if len(group.Backends) != 1 {
		t.Errorf("Expected 1 backend, got %d", len(group.Backends))
	}

	// Test default port assignment
	backend2 := &AnycastBackend{
		PhysicalIP: "10.0.1.2",
		Region:     "us-east-1",
		Zone:       "b",
	}

	err = group.AddBackend(backend2)
	if err != nil {
		t.Fatalf("AddBackend failed: %v", err)
	}

	if backend2.Port != 53 {
		t.Errorf("Expected default port 53, got %d", backend2.Port)
	}

	if backend2.Weight != 100 {
		t.Errorf("Expected default weight 100, got %d", backend2.Weight)
	}

	// Test validation - empty physical IP
	invalidBackend := &AnycastBackend{
		Port: 53,
	}

	err = group.AddBackend(invalidBackend)
	if err == nil {
		t.Error("Expected error for empty physical IP, got nil")
	}

	// Test validation - invalid weight
	invalidWeightBackend := &AnycastBackend{
		PhysicalIP: "10.0.1.3",
		Weight:     150,
	}

	err = group.AddBackend(invalidWeightBackend)
	if err == nil {
		t.Error("Expected error for invalid weight, got nil")
	}
}

func TestAnycastGroupRemoveBackend(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	backend1 := &AnycastBackend{PhysicalIP: "10.0.1.1", Port: 53}
	backend2 := &AnycastBackend{PhysicalIP: "10.0.1.2", Port: 53}

	group.AddBackend(backend1)
	group.AddBackend(backend2)

	if len(group.Backends) != 2 {
		t.Fatalf("Expected 2 backends, got %d", len(group.Backends))
	}

	group.RemoveBackend("10.0.1.1")

	if len(group.Backends) != 1 {
		t.Errorf("Expected 1 backend after removal, got %d", len(group.Backends))
	}

	if group.Backends[0].PhysicalIP != "10.0.1.2" {
		t.Errorf("Expected remaining backend to be '10.0.1.2', got '%s'", group.Backends[0].PhysicalIP)
	}
}

func TestAnycastBackendAddress(t *testing.T) {
	backend := &AnycastBackend{
		PhysicalIP: "10.0.1.1",
		Port:       53,
	}

	addr := backend.Address()
	if addr != "10.0.1.1:53" {
		t.Errorf("Expected address '10.0.1.1:53', got '%s'", addr)
	}

	backend2 := &AnycastBackend{
		PhysicalIP: "10.0.1.2",
		Port:       5353,
	}

	addr2 := backend2.Address()
	if addr2 != "10.0.1.2:5353" {
		t.Errorf("Expected address '10.0.1.2:5353', got '%s'", addr2)
	}
}

func TestAnycastBackendHealth(t *testing.T) {
	backend := &AnycastBackend{
		PhysicalIP: "10.0.1.1",
		Port:       53,
		healthy:    true,
	}

	if !backend.IsHealthy() {
		t.Error("Expected backend to be healthy")
	}

	// Mark failures
	backend.markFailure()
	if !backend.IsHealthy() {
		t.Error("Expected backend to still be healthy after 1 failure")
	}

	backend.markFailure()
	if !backend.IsHealthy() {
		t.Error("Expected backend to still be healthy after 2 failures")
	}

	backend.markFailure()
	if backend.IsHealthy() {
		t.Error("Expected backend to be unhealthy after 3 failures")
	}

	// Mark successes to recover
	backend.markSuccess(0)
	if backend.IsHealthy() {
		t.Error("Expected backend to still be unhealthy after 1 success")
	}

	backend.markSuccess(0)
	if !backend.IsHealthy() {
		t.Error("Expected backend to be healthy after 2 successes")
	}
}

func TestAnycastGroupSelectBackend(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	// Add backends in different regions
	backend1 := &AnycastBackend{
		PhysicalIP: "10.0.1.1",
		Port:       53,
		Region:     "us-east-1",
		Zone:       "a",
		Weight:     50,
		healthy:    true,
	}
	backend2 := &AnycastBackend{
		PhysicalIP: "10.0.1.2",
		Port:       53,
		Region:     "us-east-1",
		Zone:       "b",
		Weight:     50,
		healthy:    true,
	}
	backend3 := &AnycastBackend{
		PhysicalIP: "10.0.2.1",
		Port:       53,
		Region:     "eu-west-1",
		Zone:       "a",
		Weight:     50,
		healthy:    true,
	}

	group.AddBackend(backend1)
	group.AddBackend(backend2)
	group.AddBackend(backend3)

	// Test selection with preferred region and zone
	selected := group.SelectBackend("us-east-1", "a")
	if selected == nil {
		t.Fatal("SelectBackend returned nil")
	}
	if selected.PhysicalIP != "10.0.1.1" {
		t.Errorf("Expected backend in us-east-1a, got %s", selected.PhysicalIP)
	}

	// Test selection with preferred region only
	selected = group.SelectBackend("us-east-1", "")
	if selected == nil {
		t.Fatal("SelectBackend returned nil")
	}
	if selected.Region != "us-east-1" {
		t.Errorf("Expected backend in us-east-1, got %s", selected.Region)
	}

	// Test selection with non-matching region (should return any healthy)
	selected = group.SelectBackend("ap-south-1", "")
	if selected == nil {
		t.Fatal("SelectBackend returned nil")
	}
	if !selected.IsHealthy() {
		t.Error("Expected a healthy backend")
	}

	// Test with no backends
	emptyGroup := NewAnycastGroup("192.0.2.2", 30*time.Second, 5*time.Second)
	selected = emptyGroup.SelectBackend("us-east-1", "")
	if selected != nil {
		t.Error("Expected nil for empty group")
	}
}

func TestAnycastGroupStats(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	total, healthy := group.Stats()
	if total != 0 || healthy != 0 {
		t.Errorf("Expected 0 total and 0 healthy, got %d total and %d healthy", total, healthy)
	}

	backend1 := &AnycastBackend{PhysicalIP: "10.0.1.1", Port: 53}
	backend2 := &AnycastBackend{PhysicalIP: "10.0.1.2", Port: 53}

	group.AddBackend(backend1)
	group.AddBackend(backend2)

	// Make backend2 unhealthy (AddBackend initializes as healthy)
	backend2.markFailure()
	backend2.markFailure()
	backend2.markFailure()

	total, healthy = group.Stats()
	if total != 2 {
		t.Errorf("Expected 2 total, got %d", total)
	}
	if healthy != 1 {
		t.Errorf("Expected 1 healthy, got %d", healthy)
	}
}

func TestWeightedSelect(t *testing.T) {
	// Test with single backend
	backends := []*AnycastBackend{
		{PhysicalIP: "10.0.1.1", Weight: 100, healthy: true},
	}

	selected := weightedSelect(backends)
	if selected.PhysicalIP != "10.0.1.1" {
		t.Errorf("Expected only backend, got %s", selected.PhysicalIP)
	}

	// Test with multiple backends
	backends = []*AnycastBackend{
		{PhysicalIP: "10.0.1.1", Weight: 50, healthy: true},
		{PhysicalIP: "10.0.1.2", Weight: 50, healthy: true},
		{PhysicalIP: "10.0.1.3", Weight: 50, healthy: true},
	}

	// Run multiple times to ensure we get selections
	selections := make(map[string]int)
	for i := 0; i < 100; i++ {
		selected = weightedSelect(backends)
		selections[selected.PhysicalIP]++
	}

	if len(selections) == 0 {
		t.Error("Expected some selections")
	}

	// Test with zero weights (should use round-robin)
	backends = []*AnycastBackend{
		{PhysicalIP: "10.0.1.1", Weight: 0, healthy: true},
		{PhysicalIP: "10.0.1.2", Weight: 0, healthy: true},
	}

	selected = weightedSelect(backends)
	if selected == nil {
		t.Error("Expected selection with zero weights")
	}
}

func TestAnycastGroupFailover(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	backend1 := &AnycastBackend{PhysicalIP: "10.0.1.1", Port: 53}
	backend2 := &AnycastBackend{PhysicalIP: "10.0.1.2", Port: 53}

	group.AddBackend(backend1)
	group.AddBackend(backend2)

	// Get initial active backend
	initial := group.GetActiveBackend()
	if initial.PhysicalIP != "10.0.1.1" {
		t.Errorf("Expected initial backend to be 10.0.1.1, got %s", initial.PhysicalIP)
	}

	// Failover to next
	next := group.FailoverToNext()
	if next.PhysicalIP != "10.0.1.2" {
		t.Errorf("Expected failover backend to be 10.0.1.2, got %s", next.PhysicalIP)
	}

	// Verify active index was updated
	active := group.GetActiveBackend()
	if active.PhysicalIP != "10.0.1.2" {
		t.Errorf("Expected active backend to be 10.0.1.2, got %s", active.PhysicalIP)
	}

	// Failover with single backend should return nil
	singleGroup := NewAnycastGroup("192.0.2.2", 30*time.Second, 5*time.Second)
	singleGroup.AddBackend(&AnycastBackend{PhysicalIP: "10.0.1.1", Port: 53})

	failover := singleGroup.FailoverToNext()
	if failover != nil {
		t.Error("Expected nil failover with single backend")
	}
}

func TestAnycastBackendStats(t *testing.T) {
	backend := &AnycastBackend{
		PhysicalIP:   "10.0.1.1",
		Port:         53,
		healthy:      true,
		latency:      10 * time.Millisecond,
		failCount:    1,
		successCount: 5,
	}

	healthy, latency, failCount, successCount := backend.Stats()

	if !healthy {
		t.Error("Expected backend to be healthy")
	}
	if latency != 10*time.Millisecond {
		t.Errorf("Expected latency 10ms, got %v", latency)
	}
	if failCount != 1 {
		t.Errorf("Expected failCount 1, got %d", failCount)
	}
	if successCount != 5 {
		t.Errorf("Expected successCount 5, got %d", successCount)
	}
}

func TestAnycastGroupGetHealthyBackends(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	backend1 := &AnycastBackend{PhysicalIP: "10.0.1.1"}
	backend2 := &AnycastBackend{PhysicalIP: "10.0.1.2"}
	backend3 := &AnycastBackend{PhysicalIP: "10.0.1.3"}

	group.AddBackend(backend1)
	group.AddBackend(backend2)
	group.AddBackend(backend3)

	// Make backend2 unhealthy
	backend2.markFailure()
	backend2.markFailure()
	backend2.markFailure()

	healthy := group.GetHealthyBackends()
	if len(healthy) != 2 {
		t.Errorf("Expected 2 healthy backends, got %d", len(healthy))
	}
}

func TestAnycastGroupGetActiveBackendWithIndexReset(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	backend1 := &AnycastBackend{PhysicalIP: "10.0.1.1", Port: 53}
	backend2 := &AnycastBackend{PhysicalIP: "10.0.1.2", Port: 53}

	group.AddBackend(backend1)
	group.AddBackend(backend2)

	// Set an out-of-bounds index
	atomic.StoreUint32(&group.activeIndex, 100)

	// GetActiveBackend should reset the index
	backend := group.GetActiveBackend()
	if backend == nil {
		t.Error("Expected active backend after index reset")
	}

	// Verify index was reset
	newIdx := atomic.LoadUint32(&group.activeIndex)
	if newIdx != 0 {
		t.Errorf("Expected index to be reset to 0, got %d", newIdx)
	}
}

func TestAnycastGroupGetActiveBackendEmpty(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	backend := group.GetActiveBackend()
	if backend != nil {
		t.Error("Expected nil for empty group")
	}
}

func TestAnycastGroupSelectBackendOnlyZoneMatch(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	backend1 := &AnycastBackend{
		PhysicalIP: "10.0.1.1",
		Port:       53,
		Region:     "us-east-1",
		Zone:       "a",
		Weight:     50,
		healthy:    true,
	}
	backend2 := &AnycastBackend{
		PhysicalIP: "10.0.1.2",
		Port:       53,
		Region:     "us-west-1",
		Zone:       "a",
		Weight:     50,
		healthy:    true,
	}

	group.AddBackend(backend1)
	group.AddBackend(backend2)

	// Test selection with preferred region only (zone matches multiple)
	selected := group.SelectBackend("us-east-1", "a")
	if selected == nil {
		t.Fatal("SelectBackend returned nil")
	}
	if selected.PhysicalIP != "10.0.1.1" {
		t.Errorf("Expected backend 10.0.1.1 (region and zone match), got %s", selected.PhysicalIP)
	}
}

func TestAnycastGroupSelectBackendRegionFallback(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	backend1 := &AnycastBackend{
		PhysicalIP: "10.0.1.1",
		Port:       53,
		Region:     "us-east-1",
		Zone:       "a",
		Weight:     50,
		healthy:    true,
	}
	backend2 := &AnycastBackend{
		PhysicalIP: "10.0.1.2",
		Port:       53,
		Region:     "us-east-1",
		Zone:       "b",
		Weight:     50,
		healthy:    true,
	}

	group.AddBackend(backend1)
	group.AddBackend(backend2)

	// Request zone that doesn't exist
	selected := group.SelectBackend("us-east-1", "z")
	if selected == nil {
		t.Fatal("SelectBackend returned nil")
	}
	if selected.Region != "us-east-1" {
		t.Errorf("Expected us-east-1 region, got %s", selected.Region)
	}
}

func TestAnycastGroupSelectBackendAllUnhealthy(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	backend1 := &AnycastBackend{
		PhysicalIP: "10.0.1.1",
		Port:       53,
		Region:     "us-east-1",
		Zone:       "a",
		Weight:     50,
		healthy:    false,
	}

	group.AddBackend(backend1)

	// Make backend unhealthy
	backend1.markFailure()
	backend1.markFailure()
	backend1.markFailure()

	// Should fallback to first backend even if unhealthy
	selected := group.SelectBackend("us-east-1", "a")
	if selected == nil {
		t.Fatal("SelectBackend returned nil")
	}
	if selected.PhysicalIP != "10.0.1.1" {
		t.Errorf("Expected fallback to first backend, got %s", selected.PhysicalIP)
	}
}

func TestAnycastGroupSelectBackendNoPreferredRegion(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	backend1 := &AnycastBackend{
		PhysicalIP: "10.0.1.1",
		Port:       53,
		Region:     "us-east-1",
		Zone:       "a",
		Weight:     50,
		healthy:    true,
	}
	backend2 := &AnycastBackend{
		PhysicalIP: "10.0.1.2",
		Port:       53,
		Region:     "us-west-1",
		Zone:       "a",
		Weight:     50,
		healthy:    true,
	}

	group.AddBackend(backend1)
	group.AddBackend(backend2)

	// No preferred region
	selected := group.SelectBackend("", "")
	if selected == nil {
		t.Fatal("SelectBackend returned nil")
	}
	if !selected.IsHealthy() {
		t.Error("Expected healthy backend")
	}
}

func TestWeightedSelectAllZeroWeights(t *testing.T) {
	backends := []*AnycastBackend{
		{PhysicalIP: "10.0.1.1", Weight: 0, healthy: true},
		{PhysicalIP: "10.0.1.2", Weight: 0, healthy: true},
		{PhysicalIP: "10.0.1.3", Weight: 0, healthy: true},
	}

	// Multiple selections should all return valid backends
	for i := 0; i < 10; i++ {
		selected := weightedSelect(backends)
		if selected == nil {
			t.Error("Expected selection with all zero weights")
		}
	}
}

func TestWeightedSelectSingleBackend(t *testing.T) {
	backends := []*AnycastBackend{
		{PhysicalIP: "10.0.1.1", Weight: 100, healthy: true},
	}

	for i := 0; i < 10; i++ {
		selected := weightedSelect(backends)
		if selected.PhysicalIP != "10.0.1.1" {
			t.Errorf("Expected only backend 10.0.1.1, got %s", selected.PhysicalIP)
		}
	}
}

func TestWeightedSelectDistribution(t *testing.T) {
	backends := []*AnycastBackend{
		{PhysicalIP: "10.0.1.1", Weight: 80, healthy: true},
		{PhysicalIP: "10.0.1.2", Weight: 20, healthy: true},
	}

	// Run many selections to verify we get valid selections
	// Note: weightedSelect uses time-based selection which may not be deterministic
	selections := make(map[string]int)
	iterations := 100
	for i := 0; i < iterations; i++ {
		selected := weightedSelect(backends)
		selections[selected.PhysicalIP]++
	}

	// At minimum, we should get at least one selection
	if len(selections) == 0 {
		t.Error("Expected at least one selection")
	}

	// Verify all selections are valid backends
	for ip := range selections {
		valid := false
		for _, b := range backends {
			if b.PhysicalIP == ip {
				valid = true
				break
			}
		}
		if !valid {
			t.Errorf("Unexpected selection: %s", ip)
		}
	}
}

func TestAnycastBackendMarkSuccessLatency(t *testing.T) {
	backend := &AnycastBackend{
		PhysicalIP: "10.0.1.1",
		Port:       53,
		healthy:    false,
	}

	// First success - backend should still be unhealthy (need 2 consecutive successes)
	backend.markSuccess(25 * time.Millisecond)

	healthy, latency, _, successCount := backend.Stats()
	if healthy {
		t.Error("Expected backend to still be unhealthy after first success (need 2)")
	}
	if latency != 25*time.Millisecond {
		t.Errorf("Expected latency 25ms, got %v", latency)
	}
	if successCount != 1 {
		t.Errorf("Expected successCount 1, got %d", successCount)
	}

	// Second success - now backend should become healthy
	backend.markSuccess(15 * time.Millisecond)

	healthy, latency, _, successCount = backend.Stats()
	if !healthy {
		t.Error("Expected backend to be healthy after 2 consecutive successes")
	}
	if latency != 15*time.Millisecond {
		t.Errorf("Expected latency 15ms, got %v", latency)
	}
	if successCount != 2 {
		t.Errorf("Expected successCount 2, got %d", successCount)
	}
}

func TestAnycastBackendMarkFailureReset(t *testing.T) {
	backend := &AnycastBackend{
		PhysicalIP:   "10.0.1.1",
		Port:         53,
		healthy:      true,
		successCount: 5,
	}

	// Mark failure should reset success count
	backend.markFailure()

	_, _, failCount, successCount := backend.Stats()
	if failCount != 1 {
		t.Errorf("Expected failCount 1, got %d", failCount)
	}
	if successCount != 0 {
		t.Errorf("Expected successCount 0, got %d", successCount)
	}
}

func TestAnycastGroupFailoverToNextCycle(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	backend1 := &AnycastBackend{PhysicalIP: "10.0.1.1", Port: 53}
	backend2 := &AnycastBackend{PhysicalIP: "10.0.1.2", Port: 53}
	backend3 := &AnycastBackend{PhysicalIP: "10.0.1.3", Port: 53}

	group.AddBackend(backend1)
	group.AddBackend(backend2)
	group.AddBackend(backend3)

	// Initial should be first
	first := group.GetActiveBackend()
	if first.PhysicalIP != "10.0.1.1" {
		t.Errorf("Expected initial backend 10.0.1.1, got %s", first.PhysicalIP)
	}

	// Failover through all backends
	second := group.FailoverToNext()
	if second.PhysicalIP != "10.0.1.2" {
		t.Errorf("Expected second backend 10.0.1.2, got %s", second.PhysicalIP)
	}

	third := group.FailoverToNext()
	if third.PhysicalIP != "10.0.1.3" {
		t.Errorf("Expected third backend 10.0.1.3, got %s", third.PhysicalIP)
	}

	// Should cycle back to first
	firstAgain := group.FailoverToNext()
	if firstAgain.PhysicalIP != "10.0.1.1" {
		t.Errorf("Expected cycled backend 10.0.1.1, got %s", firstAgain.PhysicalIP)
	}
}

func TestAnycastGroupAddBackendNegativeWeight(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	backend := &AnycastBackend{
		PhysicalIP: "10.0.1.1",
		Port:       53,
		Weight:     -10,
	}

	err := group.AddBackend(backend)
	if err == nil {
		t.Error("Expected error for negative weight")
	}
}

func TestAnycastGroupRemoveBackendNotFound(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	backend1 := &AnycastBackend{PhysicalIP: "10.0.1.1", Port: 53}
	group.AddBackend(backend1)

	// Remove non-existent backend should not panic
	group.RemoveBackend("10.0.9.9")

	if len(group.Backends) != 1 {
		t.Errorf("Expected 1 backend after removing non-existent, got %d", len(group.Backends))
	}
}

func TestAnycastGroupRemoveBackendAll(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	backend1 := &AnycastBackend{PhysicalIP: "10.0.1.1", Port: 53}
	backend2 := &AnycastBackend{PhysicalIP: "10.0.1.2", Port: 53}

	group.AddBackend(backend1)
	group.AddBackend(backend2)

	// Remove all backends
	group.RemoveBackend("10.0.1.1")
	group.RemoveBackend("10.0.1.2")

	if len(group.Backends) != 0 {
		t.Errorf("Expected 0 backends, got %d", len(group.Backends))
	}
}

func TestAnycastGroupStatsAllUnhealthy(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	backend1 := &AnycastBackend{PhysicalIP: "10.0.1.1", Port: 53}
	backend2 := &AnycastBackend{PhysicalIP: "10.0.1.2", Port: 53}

	group.AddBackend(backend1)
	group.AddBackend(backend2)

	// Make all unhealthy
	backend1.markFailure()
	backend1.markFailure()
	backend1.markFailure()
	backend2.markFailure()
	backend2.markFailure()
	backend2.markFailure()

	total, healthy := group.Stats()
	if total != 2 {
		t.Errorf("Expected 2 total, got %d", total)
	}
	if healthy != 0 {
		t.Errorf("Expected 0 healthy, got %d", healthy)
	}
}

func TestAnycastGroupConcurrentAccess(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	for i := 0; i < 10; i++ {
		backend := &AnycastBackend{
			PhysicalIP: fmt.Sprintf("10.0.1.%d", i),
			Port:       53,
		}
		group.AddBackend(backend)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(5)
		go func() {
			defer wg.Done()
			_ = group.GetActiveBackend()
		}()
		go func() {
			defer wg.Done()
			_ = group.SelectBackend("us-east-1", "a")
		}()
		go func() {
			defer wg.Done()
			_ = group.GetHealthyBackends()
		}()
		go func() {
			defer wg.Done()
			_, _ = group.Stats()
		}()
		go func() {
			defer wg.Done()
			_ = group.FailoverToNext()
		}()
	}
	wg.Wait()
}

func TestAnycastBackendConcurrentHealthUpdates(t *testing.T) {
	backend := &AnycastBackend{
		PhysicalIP: "10.0.1.1",
		Port:       53,
		healthy:    true,
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			backend.markFailure()
		}()
		go func() {
			defer wg.Done()
			backend.markSuccess(time.Duration(i) * time.Millisecond)
		}()
	}
	wg.Wait()

	// Just ensure no data races - result state doesn't matter
	_ = backend.IsHealthy()
}

func TestAnycastBackendAddressIPv6(t *testing.T) {
	backend := &AnycastBackend{
		PhysicalIP: "2001:db8::1",
		Port:       53,
	}

	addr := backend.Address()
	if addr != "[2001:db8::1]:53" {
		t.Errorf("Expected IPv6 address '[2001:db8::1]:53', got '%s'", addr)
	}
}

func TestAnycastGroupMultipleRegions(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	// Add backends across multiple regions
	regions := []struct {
		ip     string
		region string
		zone   string
	}{
		{"10.0.1.1", "us-east-1", "a"},
		{"10.0.1.2", "us-east-1", "b"},
		{"10.0.2.1", "eu-west-1", "a"},
		{"10.0.2.2", "eu-west-1", "b"},
		{"10.0.3.1", "ap-south-1", "a"},
	}

	for _, r := range regions {
		backend := &AnycastBackend{
			PhysicalIP: r.ip,
			Port:       53,
			Region:     r.region,
			Zone:       r.zone,
			Weight:     50,
			healthy:    true,
		}
		group.AddBackend(backend)
	}

	// Test selection for each region
	testCases := []struct {
		region         string
		expectedRegion string
	}{
		{"us-east-1", "us-east-1"},
		{"eu-west-1", "eu-west-1"},
		{"ap-south-1", "ap-south-1"},
	}

	for _, tc := range testCases {
		selected := group.SelectBackend(tc.region, "")
		if selected == nil {
			t.Errorf("No backend selected for region %s", tc.region)
			continue
		}
		if selected.Region != tc.expectedRegion {
			t.Errorf("Expected region %s, got %s", tc.expectedRegion, selected.Region)
		}
	}
}

func TestAnycastBackendStatsZeroValues(t *testing.T) {
	backend := &AnycastBackend{
		PhysicalIP: "10.0.1.1",
		Port:       53,
	}

	healthy, latency, failCount, successCount := backend.Stats()
	// Default values should be false/0
	if healthy {
		t.Error("Expected healthy to be false by default")
	}
	if latency != 0 {
		t.Errorf("Expected latency 0, got %v", latency)
	}
	if failCount != 0 {
		t.Errorf("Expected failCount 0, got %d", failCount)
	}
	if successCount != 0 {
		t.Errorf("Expected successCount 0, got %d", successCount)
	}
}

func TestAnycastGroupDefaultHealthCheckInterval(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 0, 5*time.Second)
	if group.HealthCheck != 0 {
		t.Errorf("HealthCheck should be 0 when passed as 0, got %v", group.HealthCheck)
	}
}

func TestAnycastBackendLastCheckUpdate(t *testing.T) {
	backend := &AnycastBackend{
		PhysicalIP: "10.0.1.1",
		Port:       53,
		healthy:    true,
	}

	before := backend.lastCheck

	// Mark success should update lastCheck
	time.Sleep(1 * time.Millisecond) // Ensure time passes
	backend.markSuccess(10 * time.Millisecond)

	backend.mu.RLock()
	lastCheck := backend.lastCheck
	backend.mu.RUnlock()

	if !lastCheck.After(before) {
		t.Error("Expected lastCheck to be updated after markSuccess")
	}
}
