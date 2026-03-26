package upstream

import (
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
