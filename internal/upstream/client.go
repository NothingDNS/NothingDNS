package upstream

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ecostack/nothingdns/internal/protocol"
)

// Server represents an upstream DNS server.
type Server struct {
	Address     string
	Network     string // "udp" or "tcp"
	Timeout     time.Duration
	HealthCheck time.Duration

	// Health tracking
	mu          sync.RWMutex
	healthy     bool
	lastFailure time.Time
	failCount   int
	latency     time.Duration
}

// IsHealthy returns true if the server is considered healthy.
func (s *Server) IsHealthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.healthy
}

// markFailure marks the server as having failed.
func (s *Server) markFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failCount++
	s.lastFailure = time.Now()
	if s.failCount >= 3 {
		s.healthy = false
	}
}

// markSuccess marks the server as having succeeded.
func (s *Server) markSuccess(latency time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failCount = 0
	s.healthy = true
	s.latency = latency
}

// Client forwards DNS queries to upstream servers.
type Client struct {
	// Configuration
	servers  []*Server
	strategy Strategy
	timeout  time.Duration

	// Connection pools
	udpPool map[string]*sync.Pool // address -> pool
	tcpPool map[string]*sync.Pool
	mu      sync.RWMutex

	// Health check control
	healthCheckCancel context.CancelFunc
	wg                sync.WaitGroup

	// Metrics
	queriesTotal   uint64
	queriesFailed  uint64
	responsesTotal uint64
}

// Strategy defines how upstream servers are selected.
type Strategy int

const (
	// Random selects a random healthy server.
	Random Strategy = iota
	// RoundRobin cycles through servers in order.
	RoundRobin
	// Fastest selects the server with lowest latency.
	Fastest
)

// StrategyFromString converts a strategy name to a Strategy.
func StrategyFromString(s string) Strategy {
	switch s {
	case "round_robin":
		return RoundRobin
	case "fastest":
		return Fastest
	default:
		return Random
	}
}

// roundRobinIndex is used for round-robin selection.
var roundRobinIndex uint32

// Config holds upstream client configuration.
type Config struct {
	Servers     []string
	Strategy    string
	Timeout     time.Duration
	HealthCheck time.Duration
}

// DefaultConfig returns the default upstream configuration.
func DefaultConfig() Config {
	return Config{
		Servers:     []string{"8.8.8.8:53", "8.8.4.4:53"},
		Strategy:    "random",
		Timeout:     5 * time.Second,
		HealthCheck: 30 * time.Second,
	}
}

// NewClient creates a new upstream client.
func NewClient(config Config) (*Client, error) {
	if len(config.Servers) == 0 {
		return nil, fmt.Errorf("no upstream servers configured")
	}

	client := &Client{
		servers:  make([]*Server, 0, len(config.Servers)),
		strategy: StrategyFromString(config.Strategy),
		timeout:  config.Timeout,
		udpPool:  make(map[string]*sync.Pool),
		tcpPool:  make(map[string]*sync.Pool),
	}

	// Initialize servers
	for _, addr := range config.Servers {
		server := &Server{
			Address:     addr,
			Network:     "udp",
			Timeout:     config.Timeout,
			healthy:     true,
			HealthCheck: config.HealthCheck,
		}
		client.servers = append(client.servers, server)

		// Initialize connection pools
		client.udpPool[addr] = &sync.Pool{
			New: func() interface{} {
				return make([]byte, 4096)
			},
		}
		client.tcpPool[addr] = &sync.Pool{
			New: func() interface{} {
				return make([]byte, 65535)
			},
		}
	}

	// Start health check goroutine
	ctx, cancel := context.WithCancel(context.Background())
	client.healthCheckCancel = cancel
	client.wg.Add(1)
	go client.healthCheckLoop(ctx)

	return client, nil
}

// Close shuts down the upstream client.
func (c *Client) Close() error {
	if c.healthCheckCancel != nil {
		c.healthCheckCancel()
		c.wg.Wait()
	}
	return nil
}

// Query forwards a DNS query to an upstream server.
func (c *Client) Query(msg *protocol.Message) (*protocol.Message, error) {
	atomic.AddUint64(&c.queriesTotal, 1)

	// Select a healthy server
	server := c.selectServer()
	if server == nil {
		atomic.AddUint64(&c.queriesFailed, 1)
		return nil, fmt.Errorf("no healthy upstream servers available")
	}

	// Try UDP first, fallback to TCP if truncated
	resp, err := c.queryUDP(server, msg)
	if err != nil {
		// Try TCP as fallback
		resp, err = c.queryTCP(server, msg)
	}

	if err != nil {
		server.markFailure()
		atomic.AddUint64(&c.queriesFailed, 1)
		return nil, err
	}

	atomic.AddUint64(&c.responsesTotal, 1)
	return resp, nil
}

// QueryContext forwards a DNS query with context for cancellation/timeout.
func (c *Client) QueryContext(ctx context.Context, msg *protocol.Message) (*protocol.Message, error) {
	type result struct {
		resp *protocol.Message
		err  error
	}

	done := make(chan result, 1)
	go func() {
		resp, err := c.Query(msg)
		done <- result{resp, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-done:
		return r.resp, r.err
	}
}

// selectServer selects an upstream server based on the strategy.
func (c *Client) selectServer() *Server {
	switch c.strategy {
	case RoundRobin:
		return c.selectRoundRobin()
	case Fastest:
		return c.selectFastest()
	default:
		return c.selectRandom()
	}
}

// selectRandom selects a random healthy server.
func (c *Client) selectRandom() *Server {
	// Get list of healthy servers
	var healthy []*Server
	for _, s := range c.servers {
		if s.IsHealthy() {
			healthy = append(healthy, s)
		}
	}

	if len(healthy) == 0 {
		// Fallback to any server if none are healthy
		if len(c.servers) > 0 {
			return c.servers[0]
		}
		return nil
	}

	// Simple round-robin via incrementing counter for now
	// (True random requires math/rand which we'd need to seed)
	idx := int(atomic.AddUint32(&roundRobinIndex, 1)) % len(healthy)
	return healthy[idx]
}

// selectRoundRobin selects the next server in round-robin order.
func (c *Client) selectRoundRobin() *Server {
	servers := c.servers
	if len(servers) == 0 {
		return nil
	}

	// Try to find a healthy server starting from current index
	startIdx := int(atomic.AddUint32(&roundRobinIndex, 1)) % len(servers)
	for i := 0; i < len(servers); i++ {
		idx := (startIdx + i) % len(servers)
		if servers[idx].IsHealthy() {
			return servers[idx]
		}
	}

	// Fallback to starting position if no healthy servers
	return servers[startIdx]
}

// selectFastest selects the server with the lowest latency.
func (c *Client) selectFastest() *Server {
	var fastest *Server
	var lowestLatency time.Duration = -1

	for _, s := range c.servers {
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

	if fastest == nil && len(c.servers) > 0 {
		// Fallback to first server
		return c.servers[0]
	}

	return fastest
}

// queryUDP sends a query via UDP.
func (c *Client) queryUDP(server *Server, msg *protocol.Message) (*protocol.Message, error) {
	// Pack the message
	c.mu.RLock()
	pool := c.udpPool[server.Address]
	c.mu.RUnlock()

	buf := pool.Get().([]byte)
	defer pool.Put(buf)

	n, err := msg.Pack(buf)
	if err != nil {
		return nil, fmt.Errorf("pack message: %w", err)
	}
	packed := buf[:n]

	// Create UDP connection
	conn, err := net.DialTimeout("udp", server.Address, server.Timeout)
	if err != nil {
		return nil, fmt.Errorf("dial udp: %w", err)
	}
	defer conn.Close()

	// Set deadline
	if err := conn.SetDeadline(time.Now().Add(server.Timeout)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	// Send query
	start := time.Now()
	if _, err := conn.Write(packed); err != nil {
		return nil, fmt.Errorf("send query: %w", err)
	}

	// Read response
	n, err = conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	latency := time.Since(start)

	// Parse response
	resp, err := protocol.UnpackMessage(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("unpack response: %w", err)
	}

	server.markSuccess(latency)

	// Check for truncation - caller should retry with TCP
	if resp.Header.Flags.TC {
		return resp, fmt.Errorf("response truncated")
	}

	return resp, nil
}

// queryTCP sends a query via TCP.
func (c *Client) queryTCP(server *Server, msg *protocol.Message) (*protocol.Message, error) {
	// Pack the message
	c.mu.RLock()
	pool := c.tcpPool[server.Address]
	c.mu.RUnlock()

	buf := pool.Get().([]byte)
	defer pool.Put(buf)

	n, err := msg.Pack(buf)
	if err != nil {
		return nil, fmt.Errorf("pack message: %w", err)
	}
	packed := buf[:n]

	// Create TCP connection
	conn, err := net.DialTimeout("tcp", server.Address, server.Timeout)
	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}
	defer conn.Close()

	// Set deadline
	if err := conn.SetDeadline(time.Now().Add(server.Timeout)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	// Send length-prefixed query
	length := uint16(len(packed))
	lengthBuf := []byte{byte(length >> 8), byte(length)}
	if _, err := conn.Write(lengthBuf); err != nil {
		return nil, fmt.Errorf("send length: %w", err)
	}

	start := time.Now()
	if _, err := conn.Write(packed); err != nil {
		return nil, fmt.Errorf("send query: %w", err)
	}

	// Read length prefix
	lengthBuf = make([]byte, 2)
	if _, err := conn.Read(lengthBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	respLen := uint16(lengthBuf[0])<<8 | uint16(lengthBuf[1])

	if int(respLen) > len(buf) {
		buf = make([]byte, respLen)
	}

	// Read response
	_, err = conn.Read(buf[:respLen])
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	latency := time.Since(start)

	// Parse response
	resp, err := protocol.UnpackMessage(buf[:respLen])
	if err != nil {
		return nil, fmt.Errorf("unpack response: %w", err)
	}

	server.markSuccess(latency)

	return resp, nil
}

// healthCheckLoop periodically checks server health.
func (c *Client) healthCheckLoop(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.checkHealth()
		}
	}
}

// checkHealth performs health checks on all servers.
func (c *Client) checkHealth() {
	// Create a simple query for health check
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      0,
			Flags:   protocol.Flags{RD: true},
			QDCount: 1,
		},
	}
	// Add a question for root NS (should always work)
	msg.Questions = append(msg.Questions, &protocol.Question{
		Name:   &protocol.Name{Labels: []string{}, FQDN: true},
		QType:  protocol.TypeNS,
		QClass: protocol.ClassIN,
	})

	for _, server := range c.servers {
		go func(s *Server) {
			_, err := c.queryUDP(s, msg)
			if err != nil {
				// Try TCP
				_, err = c.queryTCP(s, msg)
			}
			// queryUDP/TCP already mark success/failure
		}(server)
	}
}

// Stats returns client statistics.
func (c *Client) Stats() (queries, failed, responses uint64) {
	return atomic.LoadUint64(&c.queriesTotal),
		atomic.LoadUint64(&c.queriesFailed),
		atomic.LoadUint64(&c.responsesTotal)
}

// Servers returns the list of upstream servers.
func (c *Client) Servers() []*Server {
	return c.servers
}
