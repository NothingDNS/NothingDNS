package upstream

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
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
	queriesTotal   uint64
	queriesFailed  uint64
	failoverCount  uint64
}

// LoadBalancerConfig holds load balancer configuration.
type LoadBalancerConfig struct {
	// Anycast groups configuration
	AnycastGroups []AnycastGroupConfig

	// Standalone upstream servers
	Servers []string

	// Load balancing strategy
	Strategy string

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
	if lb.healthCheck == 0 {
		lb.healthCheck = 30 * time.Second
	}
	if lb.failoverTimeout == 0 {
		lb.failoverTimeout = 5 * time.Second
	}

	// Initialize anycast groups
	for _, groupConfig := range config.AnycastGroups {
		group := NewAnycastGroup(groupConfig.AnycastIP, lb.healthCheck, lb.failoverTimeout)

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
			Timeout:     5 * time.Second,
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
		return nil, ctx.Err()
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
	AnycastIP   string
	PhysicalIP  string
	Region      string
	Zone        string

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
		if s.IsHealthy() {
			healthy = append(healthy, s)
		}
	}

	if len(healthy) == 0 {
		if len(lb.servers) > 0 {
			return lb.servers[0]
		}
		return nil
	}

	idx := int(time.Now().UnixNano()) % len(healthy)
	return healthy[idx]
}

// selectRoundRobin selects the next server in round-robin order.
func (lb *LoadBalancer) selectRoundRobin() *Server {
	servers := lb.servers
	if len(servers) == 0 {
		return nil
	}

	// Try to find a healthy server
	startIdx := int(atomic.AddUint32(&roundRobinIndex, 1)) % len(servers)
	for i := 0; i < len(servers); i++ {
		idx := (startIdx + i) % len(servers)
		if servers[idx].IsHealthy() {
			return servers[idx]
		}
	}

	// Fallback to starting position
	return servers[startIdx]
}

// selectFastest selects the server with the lowest latency.
func (lb *LoadBalancer) selectFastest() *Server {
	var fastest *Server
	var lowestLatency time.Duration = -1

	for _, s := range lb.servers {
		if !s.IsHealthy() {
			continue
		}

		s.mu.RLock()
		latency := s.latency
		s.mu.RUnlock()

		if lowestLatency < 0 || latency < lowestLatency {
			lowestLatency = latency
			fastest = s
		}
	}

	if fastest == nil && len(lb.servers) > 0 {
		return lb.servers[0]
	}

	return fastest
}

// queryWithFailover performs a query with automatic failover.
func (lb *LoadBalancer) queryWithFailover(target *Target, msg *protocol.Message) (*protocol.Message, error) {
	// Try UDP first
	resp, err := lb.queryUDP(target.Address, msg)
	if err == nil {
		return resp, nil
	}

	// If UDP fails or truncates, try TCP
	resp, err = lb.queryTCP(target.Address, msg)
	if err == nil {
		return resp, nil
	}

	// Mark target as failed and try failover
	if target.Type == "standalone" && target.Server != nil {
		target.Server.markFailure()
	}

	// Try failover to another target
	atomic.AddUint64(&lb.failoverCount, 1)

	// Select a different target
	failoverTarget, selectErr := lb.selectTarget()
	if selectErr != nil || failoverTarget.Address == target.Address {
		return nil, fmt.Errorf("query failed and no failover available: %w", err)
	}

	// Retry with failover target
	resp, retryErr := lb.queryUDP(failoverTarget.Address, msg)
	if retryErr != nil {
		resp, retryErr = lb.queryTCP(failoverTarget.Address, msg)
	}

	if retryErr != nil {
		return nil, fmt.Errorf("query failed on primary and failover: %w", retryErr)
	}

	return resp, nil
}

// queryUDP sends a query via UDP.
func (lb *LoadBalancer) queryUDP(address string, msg *protocol.Message) (*protocol.Message, error) {
	lb.mu.RLock()
	pool := lb.udpPool[address]
	lb.mu.RUnlock()

	if pool == nil {
		// Create pool dynamically for anycast backends
		pool = &sync.Pool{
			New: func() interface{} {
				return make([]byte, 4096)
			},
		}
		lb.mu.Lock()
		lb.udpPool[address] = pool
		lb.mu.Unlock()
	}

	buf := pool.Get().([]byte)
	defer pool.Put(buf)

	n, err := msg.Pack(buf)
	if err != nil {
		return nil, fmt.Errorf("pack message: %w", err)
	}
	packed := buf[:n]

	conn, err := net.DialTimeout("udp", address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial udp: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	start := time.Now()
	if _, err := conn.Write(packed); err != nil {
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
		pool = &sync.Pool{
			New: func() interface{} {
				return make([]byte, 65535)
			},
		}
		lb.mu.Lock()
		lb.tcpPool[address] = pool
		lb.mu.Unlock()
	}

	buf := pool.Get().([]byte)
	defer pool.Put(buf)

	n, err := msg.Pack(buf)
	if err != nil {
		return nil, fmt.Errorf("pack message: %w", err)
	}
	packed := buf[:n]

	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	length := uint16(len(packed))
	lengthBuf := []byte{byte(length >> 8), byte(length)}
	if _, err := conn.Write(lengthBuf); err != nil {
		return nil, fmt.Errorf("send length: %w", err)
	}

	start := time.Now()
	if _, err := conn.Write(packed); err != nil {
		return nil, fmt.Errorf("send query: %w", err)
	}

	lengthBuf = make([]byte, 2)
	if _, err := conn.Read(lengthBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	respLen := uint16(lengthBuf[0])<<8 | uint16(lengthBuf[1])

	if int(respLen) > len(buf) {
		buf = make([]byte, respLen)
	}

	_, err = conn.Read(buf[:respLen])
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	latency := time.Since(start)

	resp, err := protocol.UnpackMessage(buf[:respLen])
	if err != nil {
		return nil, fmt.Errorf("unpack response: %w", err)
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
func (lb *LoadBalancer) checkHealth() {
	// Create a simple health check query
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      0,
			Flags:   protocol.Flags{RD: true},
			QDCount: 1,
		},
	}
	msg.Questions = append(msg.Questions, &protocol.Question{
		Name:   &protocol.Name{Labels: []string{}, FQDN: true},
		QType:  protocol.TypeNS,
		QClass: protocol.ClassIN,
	})

	// Check standalone servers
	for _, server := range lb.servers {
		go func(s *Server) {
			_, err := lb.queryUDP(s.Address, msg)
			if err != nil {
				_, err = lb.queryTCP(s.Address, msg)
			}
			// queryUDP/TCP already mark success/failure
		}(server)
	}

	// Check anycast backends
	for _, group := range lb.anycastGroups {
		for _, backend := range group.Backends {
			go func(b *AnycastBackend) {
				_, err := lb.queryUDP(b.Address(), msg)
				if err != nil {
					_, err = lb.queryTCP(b.Address(), msg)
				}
				if err != nil {
					b.markFailure()
				} else {
					b.markSuccess(0)
				}
			}(backend)
		}
	}
}

// Stats returns load balancer statistics.
func (lb *LoadBalancer) Stats() (queries, failed, failovers uint64) {
	return atomic.LoadUint64(&lb.queriesTotal),
		atomic.LoadUint64(&lb.queriesFailed),
		atomic.LoadUint64(&lb.failoverCount)
}

// GetAnycastGroups returns all anycast groups.
func (lb *LoadBalancer) GetAnycastGroups() map[string]*AnycastGroup {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	result := make(map[string]*AnycastGroup)
	for k, v := range lb.anycastGroups {
		result[k] = v
	}
	return result
}

// GetTopology returns the current topology configuration.
func (lb *LoadBalancer) GetTopology() Topology {
	return lb.topology
}
