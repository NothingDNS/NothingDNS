package upstream

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

// Topology represents the network topology for routing decisions.
type Topology struct {
	// Region identifier (e.g., "us-east-1", "eu-west-1")
	Region string

	// Zone identifier within region (e.g., "a", "b", "c")
	Zone string

	// Weight for load balancing (0-100)
	Weight int
}

// LoadBalancer provides advanced load balancing with anycast and topology awareness.
type LoadBalancer struct {
	// Anycast groups indexed by anycast IP
	anycastGroups map[string]*AnycastGroup

	// Standalone upstream servers (non-anycast)
	servers []*Server

	// Topology information for this instance
	topology Topology

	// Load balancing strategy
	strategy Strategy

	// Query timeout
	timeout time.Duration

	// Health check configuration
	healthCheck     time.Duration
	failoverTimeout time.Duration

	// Connection pools
	udpPool map[string]*sync.Pool
	tcpPool map[string]*sync.Pool
	mu      sync.RWMutex

	// Health check control
	healthCheckCancel context.CancelFunc
	wg                sync.WaitGroup

	// Metrics
	queriesTotal  uint64
	queriesFailed uint64
	failoverCount uint64

	// Circuit breaker state per server address
	circuitBreakers map[string]*circuitBreaker
	cbMu            sync.RWMutex
}

// circuitBreaker implements the circuit breaker pattern.
type circuitBreaker struct {
	mu           sync.Mutex
	state        cbState // closed, open, half-open
	failures     int
	failureLimit int
	resetTimeout time.Duration
	lastFailure  time.Time
	backoff      time.Duration
}

type cbState int

const (
	cbClosed cbState = iota
	cbOpen
	cbHalfOpen
)

// shouldAllow returns true if the circuit breaker allows the request.
func (cb *circuitBreaker) shouldAllow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case cbClosed:
		return true
	case cbOpen:
		// Check if reset timeout has passed
		if circuitBreakerResetReachedAt(cb.lastFailure, time.Now(), cb.resetTimeout) {
			cb.state = cbHalfOpen
			return true
		}
		return false
	case cbHalfOpen:
		return true
	default:
		return true
	}
}

func circuitBreakerResetReachedAt(lastFailure, now time.Time, resetTimeout time.Duration) bool {
	return !now.Before(lastFailure.Add(resetTimeout))
}

// recordSuccess resets the circuit breaker on successful request.
func (cb *circuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.state = cbClosed
}

// recordFailure records a failed request and potentially trips the circuit.
func (cb *circuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	cb.lastFailure = time.Now()

	if cb.failures >= cb.failureLimit {
		cb.state = cbOpen
	}
}

// getBackoff returns the exponential backoff duration for retries.
func (cb *circuitBreaker) getBackoff(attempt int) time.Duration {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if attempt <= 0 {
		return 100 * time.Millisecond
	}
	backoff := 100 * time.Millisecond * time.Duration(1<<(attempt-1))
	if backoff > cb.backoff {
		return cb.backoff
	}
	return backoff
}

// getOrCreateCircuitBreaker returns or creates a circuit breaker for an address.
func (lb *LoadBalancer) getOrCreateCircuitBreaker(address string) *circuitBreaker {
	lb.cbMu.Lock()
	defer lb.cbMu.Unlock()

	if lb.circuitBreakers == nil {
		lb.circuitBreakers = make(map[string]*circuitBreaker)
	}

	if cb, ok := lb.circuitBreakers[address]; ok {
		return cb
	}

	cb := &circuitBreaker{
		state:        cbClosed,
		failureLimit: 5,
		resetTimeout: 30 * time.Second,
		backoff:      30 * time.Second,
	}
	lb.circuitBreakers[address] = cb
	return cb
}

// LoadBalancerConfig holds load balancer configuration.
type LoadBalancerConfig struct {
	// Anycast groups configuration
	AnycastGroups []AnycastGroupConfig

	// Standalone upstream servers
	Servers []string

	// Load balancing strategy
	Strategy string

	// Query timeout
	Timeout time.Duration

	// Health check interval
	HealthCheck time.Duration

	// Failover timeout
	FailoverTimeout time.Duration

	// Topology information
	Region string
	Zone   string
	Weight int
}

// AnycastGroupConfig holds configuration for an anycast group.
type AnycastGroupConfig struct {
	// Anycast IP address
	AnycastIP string

	// Backend servers in this group
	Backends []AnycastBackendConfig

	// Health check interval
	HealthCheck string
}

// AnycastBackendConfig holds configuration for an anycast backend.
type AnycastBackendConfig struct {
	// Physical IP address
	PhysicalIP string

	// Port (default: 53)
	Port int

	// Region identifier
	Region string

	// Zone identifier
	Zone string

	// Weight for load balancing (0-100)
	Weight int
}

// NewLoadBalancer creates a new load balancer.
func NewLoadBalancer(config LoadBalancerConfig) (*LoadBalancer, error) {
	if len(config.AnycastGroups) == 0 && len(config.Servers) == 0 {
		return nil, fmt.Errorf("no upstream servers or anycast groups configured")
	}

	lb := &LoadBalancer{
		anycastGroups:   make(map[string]*AnycastGroup),
		servers:         make([]*Server, 0),
		strategy:        StrategyFromString(config.Strategy),
		timeout:         config.Timeout,
		healthCheck:     config.HealthCheck,
		failoverTimeout: config.FailoverTimeout,
		udpPool:         make(map[string]*sync.Pool),
		tcpPool:         make(map[string]*sync.Pool),
		topology: Topology{
			Region: config.Region,
			Zone:   config.Zone,
			Weight: config.Weight,
		},
	}

	// Set defaults
	if lb.timeout <= 0 {
		lb.timeout = 5 * time.Second
	}
	if lb.healthCheck <= 0 {
		lb.healthCheck = 30 * time.Second
	}
	if lb.failoverTimeout <= 0 {
		lb.failoverTimeout = 5 * time.Second
	}

	// Initialize anycast groups
	for _, groupConfig := range config.AnycastGroups {
		groupHealthCheck := lb.healthCheck
		if groupConfig.HealthCheck != "" {
			parsed, err := time.ParseDuration(groupConfig.HealthCheck)
			if err != nil {
				return nil, fmt.Errorf("invalid health check duration for anycast group %s: %w", groupConfig.AnycastIP, err)
			}
			if parsed > 0 {
				groupHealthCheck = parsed
			}
		}
		group := NewAnycastGroup(groupConfig.AnycastIP, groupHealthCheck, lb.failoverTimeout)

		for _, backendConfig := range groupConfig.Backends {
			backend := &AnycastBackend{
				PhysicalIP: backendConfig.PhysicalIP,
				Port:       backendConfig.Port,
				Region:     backendConfig.Region,
				Zone:       backendConfig.Zone,
				Weight:     backendConfig.Weight,
			}
			if err := group.AddBackend(backend); err != nil {
				return nil, fmt.Errorf("failed to add backend to anycast group %s: %w", groupConfig.AnycastIP, err)
			}
		}

		lb.anycastGroups[groupConfig.AnycastIP] = group
	}

	// Initialize standalone servers
	for _, addr := range config.Servers {
		server := &Server{
			Address:     addr,
			Network:     "udp",
			Timeout:     lb.timeout,
			healthy:     true,
			HealthCheck: lb.healthCheck,
		}
		lb.servers = append(lb.servers, server)

		// Initialize connection pools
		lb.udpPool[addr] = &sync.Pool{
			New: func() interface{} {
				return make([]byte, 4096)
			},
		}
		lb.tcpPool[addr] = &sync.Pool{
			New: func() interface{} {
				return make([]byte, 65535)
			},
		}
	}

	// Start health check goroutine
	ctx, cancel := context.WithCancel(context.Background())
	lb.healthCheckCancel = cancel
	lb.wg.Add(1)
	go lb.healthCheckLoop(ctx)

	return lb, nil
}

// Close shuts down the load balancer.
func (lb *LoadBalancer) Close() error {
	if lb.healthCheckCancel != nil {
		lb.healthCheckCancel()
		lb.wg.Wait()
	}
	return nil
}

func (lb *LoadBalancer) queryTimeout() time.Duration {
	if lb.timeout <= 0 {
		return 5 * time.Second
	}
	return lb.timeout
}

// Query forwards a DNS query using load balancing.
func (lb *LoadBalancer) Query(msg *protocol.Message) (*protocol.Message, error) {
	atomic.AddUint64(&lb.queriesTotal, 1)

	// Select target based on strategy
	target, err := lb.selectTarget()
	if err != nil {
		atomic.AddUint64(&lb.queriesFailed, 1)
		return nil, err
	}

	// Try query with failover
	resp, err := lb.queryWithFailover(target, msg)
	if err != nil {
		atomic.AddUint64(&lb.queriesFailed, 1)
		return nil, err
	}

	return resp, nil
}

// QueryContext forwards a DNS query with context.
func (lb *LoadBalancer) QueryContext(ctx context.Context, msg *protocol.Message) (*protocol.Message, error) {
	type result struct {
		resp *protocol.Message
		err  error
	}

	done := make(chan result, 1)
	go func() {
		resp, err := lb.Query(msg)
		done <- result{resp, err}
	}()

	select {
	case <-ctx.Done():
		// Check if query completed anyway before returning cancellation error
		select {
		case r := <-done:
			return r.resp, r.err
		default:
			return nil, ctx.Err()
		}
	case r := <-done:
		return r.resp, r.err
	}
}

// Target represents a query target (either anycast backend or standalone server).
type Target struct {
	// Type indicates if this is an anycast backend or standalone server
	Type string // "anycast" or "standalone"

	// Address to connect to
	Address string

	// For anycast backends
	AnycastIP  string
	PhysicalIP string
	Region     string
	Zone       string

	// Backend reference for anycast health tracking.
	// Populated by selectAnycastTarget so queryWithFailover can call
	// b.markSuccess(latency) and b.markFailure() — mirroring the
	// standalone server pattern (server.markSuccess/markFailure).
	Backend *AnycastBackend

	// Reference to original server (for standalone)
	Server *Server
}

// selectTarget selects a target based on the load balancing strategy.
func (lb *LoadBalancer) selectTarget() (*Target, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	// Check if we have anycast groups
	if len(lb.anycastGroups) > 0 {
		return lb.selectAnycastTarget()
	}

	// Fall back to standalone servers
	return lb.selectStandaloneTarget()
}

// selectAnycastTarget selects a target from anycast groups.
func (lb *LoadBalancer) selectAnycastTarget() (*Target, error) {
	// Get a list of any healthy anycast group
	var selectedGroup *AnycastGroup

	for _, group := range lb.anycastGroups {
		if group == nil {
			continue
		}
		total, healthy := group.Stats()
		if healthy > 0 {
			selectedGroup = group
			break
		}
		// Track if all groups are unhealthy
		if selectedGroup == nil && total > 0 {
			selectedGroup = group // Fallback
		}
	}

	if selectedGroup == nil {
		return nil, fmt.Errorf("no anycast groups available")
	}

	// Select backend from the group
	backend := selectedGroup.SelectBackend(lb.topology.Region, lb.topology.Zone)
	if backend == nil {
		return nil, fmt.Errorf("no healthy backends in anycast group %s", selectedGroup.AnycastIP)
	}

	return &Target{
		Type:       "anycast",
		Address:    backend.Address(),
		AnycastIP:  selectedGroup.AnycastIP,
		PhysicalIP: backend.PhysicalIP,
		Region:     backend.Region,
		Zone:       backend.Zone,
		Backend:    backend, // populate so queryWithFailover can call b.markSuccess/markFailure
	}, nil
}

// selectStandaloneTarget selects a target from standalone servers.
func (lb *LoadBalancer) selectStandaloneTarget() (*Target, error) {
	if len(lb.servers) == 0 {
		return nil, fmt.Errorf("no upstream servers available")
	}

	var selected *Server

	switch lb.strategy {
	case RoundRobin:
		selected = lb.selectRoundRobin()
	case Fastest:
		selected = lb.selectFastest()
	default:
		selected = lb.selectRandom()
	}

	if selected == nil {
		return nil, fmt.Errorf("no healthy upstream servers available")
	}

	return &Target{
		Type:    "standalone",
		Address: selected.Address,
		Server:  selected,
	}, nil
}

// selectRandom selects a random healthy server.
func (lb *LoadBalancer) selectRandom() *Server {
	var healthy []*Server
	for _, s := range lb.servers {
		if s != nil && s.IsHealthy() {
			healthy = append(healthy, s)
		}
	}

	if len(healthy) == 0 {
		return firstServer(lb.servers, 0)
	}

	// Modulo in uint32 space: int(time.Now().UnixNano()) truncates negative
	// on 32-bit platforms and would index out of range.
	idx := int(atomic.AddUint32(&roundRobinIndex, 1) % uint32(len(healthy)))
	return healthy[idx]
}

// selectRoundRobin selects the next server in round-robin order.
func (lb *LoadBalancer) selectRoundRobin() *Server {
	servers := lb.servers
	if len(servers) == 0 {
		return nil
	}

	// Try to find a healthy server
	startIdx := int(atomic.AddUint32(&roundRobinIndex, 1) % uint32(len(servers)))
	for i := 0; i < len(servers); i++ {
		idx := (startIdx + i) % len(servers)
		server := servers[idx]
		if server != nil && server.IsHealthy() {
			return server
		}
	}

	// Fallback to starting position
	return firstServer(servers, startIdx)
}

// selectFastest selects the server with the lowest latency.
//
// Servers are constructed with latency=0; the first real
// measurement arrives later from a successful query. A naive
// "min latency" comparison would treat 0 as the best possible
// value and steer every query to an un-measured server until
// its first measurement landed. Same root cause as the fix in
// Client.selectFastest. Skip latency<=0 (un-measured) from the
// main pick; fall back to any healthy server if no measured
// server is healthy yet.
func (lb *LoadBalancer) selectFastest() *Server {
	var fastest *Server
	var lowestLatency time.Duration = -1

	for _, s := range lb.servers {
		if s == nil || !s.IsHealthy() {
			continue
		}

		s.mu.RLock()
		latency := s.latency
		s.mu.RUnlock()

		// Un-measured: cannot honestly compete on speed yet.
		if latency <= 0 {
			continue
		}

		if lowestLatency < 0 || latency < lowestLatency {
			lowestLatency = latency
			fastest = s
		}
	}

	if fastest != nil {
		return fastest
	}

	// No measured-healthy server — fall back to any healthy server
	// so cold-start queries still get answered.
	for _, s := range lb.servers {
		if s != nil && s.IsHealthy() {
			return s
		}
	}

	return firstServer(lb.servers, 0)
}

func firstServer(servers []*Server, start int) *Server {
	if len(servers) == 0 {
		return nil
	}
	if start < 0 || start >= len(servers) {
		start = 0
	}
	for i := 0; i < len(servers); i++ {
		idx := (start + i) % len(servers)
		if servers[idx] != nil {
			return servers[idx]
		}
	}
	return nil
}

// queryWithFailover performs a query with automatic failover.
func (lb *LoadBalancer) queryWithFailover(target *Target, msg *protocol.Message) (*protocol.Message, error) {
	cb := lb.getOrCreateCircuitBreaker(target.Address)

	// Check circuit breaker before attempting request
	if !cb.shouldAllow() {
		atomic.AddUint64(&lb.queriesFailed, 1)
		return nil, fmt.Errorf("circuit breaker open for %s", target.Address)
	}

	// Try UDP first
	resp, err := lb.queryUDP(target.Address, msg)
	if err == nil {
		cb.recordSuccess()
		// Drive anycast backend health state machine from real traffic,
		// mirroring the standalone server pattern. Without this, the anycast
		// health machine is only driven by checkHealth() and real client queries
		// contribute nothing — a backend can stay unhealthy indefinitely.
		if target.Type == "anycast" && target.Backend != nil {
			target.Backend.markSuccess(0) // query path doesn't measure latency
		}
		return resp, nil
	}

	// If UDP fails or truncates, try TCP
	util.Warnf("loadbalancer UDP query failed for %s: %v, trying TCP", target.Address, err)
	resp, err = lb.queryTCP(target.Address, msg)
	if err == nil {
		cb.recordSuccess()
		if target.Type == "anycast" && target.Backend != nil {
			target.Backend.markSuccess(0) // query path doesn't measure latency
		}
		return resp, nil
	}

	// Record failure for circuit breaker
	cb.recordFailure()

	// Mark target as failed
	if target.Type == "standalone" && target.Server != nil {
		target.Server.markFailure()
	}
	// Mark anycast backend as failed, mirroring the standalone server pattern.
	if target.Type == "anycast" && target.Backend != nil {
		target.Backend.markFailure()
	}

	// Try failover to another target
	atomic.AddUint64(&lb.failoverCount, 1)

	// Select a different target
	failoverTarget, selectErr := lb.selectTarget()
	if selectErr != nil || failoverTarget.Address == target.Address {
		atomic.AddUint64(&lb.queriesFailed, 1)
		return nil, fmt.Errorf("query failed and no failover available: %w", err)
	}

	// Check circuit breaker for failover target
	failoverCB := lb.getOrCreateCircuitBreaker(failoverTarget.Address)
	if !failoverCB.shouldAllow() {
		atomic.AddUint64(&lb.queriesFailed, 1)
		return nil, fmt.Errorf("circuit breaker open for failover target %s", failoverTarget.Address)
	}

	// Note: No blocking sleep here - we fail fast to the failover target
	// The circuit breaker will prevent hammering a failing server

	// Retry with failover target
	resp, retryErr := lb.queryUDP(failoverTarget.Address, msg)
	if retryErr != nil {
		util.Warnf("loadbalancer failover UDP failed for %s: %v, trying TCP", failoverTarget.Address, retryErr)
		resp, retryErr = lb.queryTCP(failoverTarget.Address, msg)
	}

	if retryErr != nil {
		failoverCB.recordFailure()
		atomic.AddUint64(&lb.queriesFailed, 1)
		return nil, fmt.Errorf("query failed on primary and failover: %w", retryErr)
	}

	failoverCB.recordSuccess()
	return resp, nil
}

// queryUDP sends a query via UDP.
func (lb *LoadBalancer) queryUDP(address string, msg *protocol.Message) (*protocol.Message, error) {
	lb.mu.RLock()
	pool := lb.udpPool[address]
	lb.mu.RUnlock()

	if pool == nil {
		// Create pool dynamically for anycast backends
		lb.mu.Lock()
		pool = lb.udpPool[address]
		if pool == nil {
			pool = &sync.Pool{
				New: func() interface{} {
					return make([]byte, 4096)
				},
			}
			lb.udpPool[address] = pool
		}
		lb.mu.Unlock()
	}

	var buf []byte
	if pooled := pool.Get(); pooled != nil {
		switch p := pooled.(type) {
		case []byte:
			buf = p
		case *[]byte:
			if p != nil {
				buf = *p
			}
		}
	}
	if buf == nil {
		buf = make([]byte, 4096)
	}
	defer func() {
		// Reset buffer before returning to pool to prevent stale data aliasing
		for i := range buf {
			buf[i] = 0
		}
		pool.Put(&buf)
	}()

	n, err := msg.Pack(buf)
	if err != nil {
		return nil, fmt.Errorf("pack message: %w", err)
	}
	packed := buf[:n]

	timeout := lb.queryTimeout()
	conn, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial udp: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	start := time.Now()
	if err := writePacket(conn, packed); err != nil {
		return nil, fmt.Errorf("send query: %w", err)
	}

	n, err = conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	latency := time.Since(start)

	resp, err := protocol.UnpackMessage(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("unpack response: %w", err)
	}

	// Reject responses whose transaction ID doesn't match — stale or spoofed
	// responses must not be returned as the current answer. This is the same
	// guard already present in (*Client).queryUDP/queryTCP
	// (fix for memory 01M1PHJT9DRKY835ZPZEV7R6N0).
	if resp.Header.ID != msg.Header.ID {
		resp.Release()
		return nil, fmt.Errorf("response ID mismatch: got %d, want %d", resp.Header.ID, msg.Header.ID)
	}

	// Update latency for the target if it's a standalone server
	for _, s := range lb.servers {
		if s.Address == address {
			s.markSuccess(latency)
			break
		}
	}

	if resp.Header.Flags.TC {
		return resp, fmt.Errorf("response truncated")
	}

	return resp, nil
}

// queryTCP sends a query via TCP.
func (lb *LoadBalancer) queryTCP(address string, msg *protocol.Message) (*protocol.Message, error) {
	lb.mu.RLock()
	pool := lb.tcpPool[address]
	lb.mu.RUnlock()

	if pool == nil {
		lb.mu.Lock()
		pool = lb.tcpPool[address]
		if pool == nil {
			pool = &sync.Pool{
				New: func() interface{} {
					return make([]byte, 65535)
				},
			}
			lb.tcpPool[address] = pool
		}
		lb.mu.Unlock()
	}

	var buf []byte
	if pooled := pool.Get(); pooled != nil {
		switch p := pooled.(type) {
		case []byte:
			buf = p
		case *[]byte:
			if p != nil {
				buf = *p
			}
		}
	}
	if buf == nil {
		buf = make([]byte, 65535)
	}
	defer func() {
		// Reset buffer before returning to pool to prevent stale data aliasing
		for i := range buf {
			buf[i] = 0
		}
		pool.Put(&buf)
	}()

	n, err := msg.Pack(buf)
	if err != nil {
		return nil, fmt.Errorf("pack message: %w", err)
	}
	packed := buf[:n]

	timeout := lb.queryTimeout()
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	if len(packed) > 65535 {
		return nil, fmt.Errorf("message too large for TCP: %d bytes", len(packed))
	}
	length := uint16(len(packed))
	lengthBuf := []byte{byte(length >> 8), byte(length)}
	if err := util.WriteFull(conn, lengthBuf); err != nil {
		return nil, fmt.Errorf("send length: %w", err)
	}

	start := time.Now()
	if err := util.WriteFull(conn, packed); err != nil {
		return nil, fmt.Errorf("send query: %w", err)
	}

	lengthBuf = make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	respLen := uint16(lengthBuf[0])<<8 | uint16(lengthBuf[1])

	if int(respLen) > len(buf) {
		buf = make([]byte, respLen)
	}

	_, err = io.ReadFull(conn, buf[:respLen])
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	latency := time.Since(start)

	resp, err := protocol.UnpackMessage(buf[:respLen])
	if err != nil {
		return nil, fmt.Errorf("unpack response: %w", err)
	}

	// Reject responses whose transaction ID doesn't match — stale or spoofed
	// responses must not be returned as the current answer. This is the same
	// guard already present in (*Client).queryUDP and (*Client).queryTCP
	// (fix for memory 01M1PHJT9DRKY835ZPZEV7R6N0).
	if resp.Header.ID != msg.Header.ID {
		resp.Release()
		return nil, fmt.Errorf("response ID mismatch: got %d, want %d", resp.Header.ID, msg.Header.ID)
	}

	// Update latency for the target
	for _, s := range lb.servers {
		if s.Address == address {
			s.markSuccess(latency)
			break
		}
	}

	return resp, nil
}

// healthCheckLoop periodically checks server health.
func (lb *LoadBalancer) healthCheckLoop(ctx context.Context) {
	defer lb.wg.Done()

	ticker := time.NewTicker(lb.healthCheck)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lb.checkHealth()
		}
	}
}

// checkHealth performs health checks on all servers and anycast backends.
// Each per-probe goroutine builds its own Message with a fresh
// RandomTXID() — see the matching fix on Client.checkHealth for the
// rationale (predictable IDs across all probes make every health
// response trivially spoofable for any in-path attacker that saw one).
func (lb *LoadBalancer) checkHealth() {
	rootQuestion := &protocol.Question{
		Name:   protocol.NewName([]string{}, true),
		QType:  protocol.TypeNS,
		QClass: protocol.ClassIN,
	}
	newQuery := func() *protocol.Message {
		return &protocol.Message{
			Header: protocol.Header{
				ID:      RandomTXID(),
				Flags:   protocol.Flags{RD: true},
				QDCount: 1,
			},
			Questions: []*protocol.Question{rootQuestion},
		}
	}

	// Check standalone servers — snapshot under lock
	lb.mu.RLock()
	servers := make([]*Server, len(lb.servers))
	copy(servers, lb.servers)
	lb.mu.RUnlock()

	var healthWg sync.WaitGroup

	for _, server := range servers {
		if server == nil {
			continue
		}
		healthWg.Add(1)
		go func(s *Server) {
			defer healthWg.Done()
			query := newQuery()
			_, err := lb.queryUDP(s.Address, query)
			if err != nil {
				util.Warnf("health check UDP failed for %s: %v, trying TCP", s.Address, err)
				if _, tcpErr := lb.queryTCP(s.Address, query); tcpErr != nil {
					util.Debugf("health check TCP failed for %s: %v", s.Address, tcpErr)
					s.markFailure()
				}
			}
			// queryUDP/queryTCP mark success on successful probes.
		}(server)
	}

	// Check anycast backends
	for _, group := range lb.anycastGroups {
		if group == nil {
			continue
		}
		group.mu.RLock()
		backends := make([]*AnycastBackend, len(group.Backends))
		copy(backends, group.Backends)
		group.mu.RUnlock()

		for _, backend := range backends {
			if backend == nil {
				continue
			}
			healthWg.Add(1)
			go func(b *AnycastBackend) {
				defer healthWg.Done()
				query := newQuery()
				_, err := lb.queryUDP(b.Address(), query)
				if err != nil {
					util.Warnf("health check UDP failed for anycast %s: %v, trying TCP", b.Address(), err)
					_, err = lb.queryTCP(b.Address(), query)
				}
				if err != nil {
					b.markFailure()
				} else {
					b.markSuccess(0)
				}
			}(backend)
		}
	}

	healthWg.Wait()
}

// Stats returns load balancer statistics.
func (lb *LoadBalancer) Stats() (queries, failed, failovers uint64) {
	return atomic.LoadUint64(&lb.queriesTotal),
		atomic.LoadUint64(&lb.queriesFailed),
		atomic.LoadUint64(&lb.failoverCount)
}

// IsHealthy returns true if at least one server or anycast backend is healthy.
func (lb *LoadBalancer) IsHealthy() bool {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	for _, s := range lb.servers {
		if s != nil && s.IsHealthy() {
			return true
		}
	}
	for _, group := range lb.anycastGroups {
		if group == nil {
			continue
		}
		group.mu.RLock()
		for _, b := range group.Backends {
			if b != nil && b.IsHealthy() {
				group.mu.RUnlock()
				return true
			}
		}
		group.mu.RUnlock()
	}
	return false
}

// GetAnycastGroups returns all anycast groups.
func (lb *LoadBalancer) GetAnycastGroups() map[string]*AnycastGroup {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	result := make(map[string]*AnycastGroup)
	for k, v := range lb.anycastGroups {
		result[k] = v.snapshot()
	}
	return result
}

// GetTopology returns the current topology configuration.
func (lb *LoadBalancer) GetTopology() Topology {
	return lb.topology
}
