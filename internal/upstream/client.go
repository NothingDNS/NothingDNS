package upstream

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
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

func (s *Server) snapshot() *Server {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return &Server{
		Address:     s.Address,
		Network:     s.Network,
		Timeout:     s.Timeout,
		HealthCheck: s.HealthCheck,
		healthy:     s.healthy,
		lastFailure: s.lastFailure,
		failCount:   s.failCount,
		latency:     s.latency,
	}
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
	servers     []*Server
	strategy    Strategy
	timeout     time.Duration
	healthCheck time.Duration

	// Buffer pools
	udpPool map[string]*sync.Pool // address -> buffer pool
	tcpPool map[string]*sync.Pool

	// TCP connection pools for persistent connections
	tcpConnPools map[string]*tcpConnPool // address -> conn pool

	mu sync.RWMutex

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

// HealthCheckDuration returns the health check interval from the config.
func (c *Config) HealthCheckDuration() time.Duration {
	if c.HealthCheck <= 0 {
		return 30 * time.Second
	}
	return c.HealthCheck
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
	if config.Timeout <= 0 {
		config.Timeout = 5 * time.Second
	}
	if config.HealthCheck <= 0 {
		config.HealthCheck = 30 * time.Second
	}

	client := &Client{
		servers:      make([]*Server, 0, len(config.Servers)),
		strategy:     StrategyFromString(config.Strategy),
		timeout:      config.Timeout,
		healthCheck:  config.HealthCheck,
		udpPool:      make(map[string]*sync.Pool),
		tcpPool:      make(map[string]*sync.Pool),
		tcpConnPools: make(map[string]*tcpConnPool),
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

		// Initialize buffer pools
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

		// Initialize TCP connection pool
		client.tcpConnPools[addr] = newTCPConnPool(addr, 4, 64, 30*time.Second, config.Timeout)
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

	// Close all TCP connection pools
	c.mu.Lock()
	var closeErr error
	for _, pool := range c.tcpConnPools {
		if err := pool.closeAll(); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
	}
	c.mu.Unlock()

	return closeErr
}

// RandomTXID generates a cryptographically random 16-bit transaction ID.
// Exported for use in handler.go for the forwarder path (VULN-059).
func RandomTXID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to time-based bottom bits if crypto/rand fails (shouldn't happen)
		return uint16(time.Now().UnixNano() & 0xFFFF)
	}
	return binary.BigEndian.Uint16(b[:])
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
		util.Warnf("upstream UDP query failed for %s: %v, trying TCP", server.Address, err)
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

	// Buffered channel: goroutine exits even if context is cancelled and
	// no receiver reads from done. Without buffer size 1, a cancelled context
	// causes the goroutine to block forever on the send to done.
	done := make(chan result, 1)
	go func() {
		resp, err := c.Query(msg)
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
//
// Holds c.mu.RLock while iterating c.servers — AddServer and
// RemoveServer reassign that slice under c.mu.Lock(), so a
// concurrent mutation between the range loop and the index-into
// healthy[] (or the fallback c.servers[0] read) was a textbook
// data race: Go's race detector flagged it and a sufficiently
// busy admin could trigger an index-out-of-range panic if
// RemoveServer shrank c.servers between our two reads.
func (c *Client) selectRandom() *Server {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Get list of healthy servers
	var healthy []*Server
	for _, s := range c.servers {
		if s != nil && s.IsHealthy() {
			healthy = append(healthy, s)
		}
	}

	if len(healthy) == 0 {
		// Fallback to any server if none are healthy
		return firstClientServer(c.servers, 0)
	}

	// Simple round-robin via incrementing counter for now
	// (True random requires math/rand which we'd need to seed)
	// Modulo in uint32 space: int(uint32) can go negative on 32-bit.
	idx := int(atomic.AddUint32(&roundRobinIndex, 1) % uint32(len(healthy)))
	return healthy[idx]
}

// selectRoundRobin selects the next server in round-robin order.
//
// See selectRandom for the rationale on the RLock — same race
// against concurrent AddServer/RemoveServer.
func (c *Client) selectRoundRobin() *Server {
	c.mu.RLock()
	defer c.mu.RUnlock()

	servers := c.servers
	if len(servers) == 0 {
		return nil
	}

	// Try to find a healthy server starting from current index
	startIdx := int(atomic.AddUint32(&roundRobinIndex, 1) % uint32(len(servers)))
	for i := 0; i < len(servers); i++ {
		idx := (startIdx + i) % len(servers)
		server := servers[idx]
		if server != nil && server.IsHealthy() {
			return server
		}
	}

	// Fallback to starting position if no healthy servers
	return firstClientServer(servers, startIdx)
}

// selectFastest selects the server with the lowest latency.
//
// Servers are created with latency=0 and healthy=true; the first
// real measurement arrives later from markSuccess via the
// queryUDP/queryTCP success path or the health-check loop. A naive
// "min latency" comparison would treat the unmeasured zero as the
// best possible value and always steer every query to the
// most-recently-added server until its first measurement landed.
// That bypasses the actual "fastest" selection promise: a freshly
// added node, a node whose latency hasn't been refreshed since
// startup, or any node whose markSuccess hasn't fired would always
// win against measured peers — including measured-fast peers.
//
// Treat latency==0 as un-measured and skip those in the main pick.
// If no measured server is healthy, fall back to the first healthy
// (unmeasured) server, then finally to c.servers[0].
func (c *Client) selectFastest() *Server {
	// See selectRandom for the c.mu.RLock rationale: AddServer/
	// RemoveServer rewrite c.servers under the write lock.
	c.mu.RLock()
	defer c.mu.RUnlock()

	var fastest *Server
	var lowestLatency time.Duration = -1

	for _, s := range c.servers {
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
	for _, s := range c.servers {
		if s != nil && s.IsHealthy() {
			return s
		}
	}

	return firstClientServer(c.servers, 0)
}

func firstClientServer(servers []*Server, start int) *Server {
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

// queryUDP sends a query via UDP.
func (c *Client) queryUDP(server *Server, msg *protocol.Message) (*protocol.Message, error) {
	c.mu.RLock()
	pool := c.udpPool[server.Address]
	c.mu.RUnlock()

	var buf []byte
	var putBack func()
	if pool != nil {
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
		putBack = func() {
			pool.Put(&buf)
		}
	} else {
		buf = make([]byte, 4096)
		putBack = func() {}
	}
	defer putBack()

	return c.queryUDPBuf(server, msg, buf)
}

// queryUDPBuf performs a UDP query using the provided buffer.
func (c *Client) queryUDPBuf(server *Server, msg *protocol.Message, buf []byte) (resp *protocol.Message, err error) {
	n, packErr := msg.Pack(buf)
	if packErr != nil {
		// Pack failures are input-side bugs (our own malformed message);
		// do NOT penalise the server health for them.
		return nil, fmt.Errorf("pack message: %w", packErr)
	}
	packed := buf[:n]

	// From here on, any returned error reflects a problem talking to the
	// server (dial/deadline/write/read/unpack). Record markFailure via defer
	// so health-check probes and load-balancer back-off see the outcome.
	// Previously the success path called markSuccess but no path called
	// markFailure, leaving dead servers permanently marked healthy.
	//
	// Truncation is a soft outcome: the server DID respond, just over UDP
	// with TC=1. The caller retries on TCP. Skip the failure mark in that
	// case via the local flag below.
	skipFailureMark := false
	defer func() {
		if err != nil && !skipFailureMark {
			server.markFailure()
		}
	}()

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
	if err := writePacket(conn, packed); err != nil {
		return nil, fmt.Errorf("send query: %w", err)
	}

	// Read response
	n, err = conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	latency := time.Since(start)

	// Parse response
	resp, err = protocol.UnpackMessage(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("unpack response: %w", err)
	}

	server.markSuccess(latency)

	// Check for truncation - caller should retry with TCP. Treat truncation
	// as a transport "soft failure": the server responded, so do NOT call
	// markFailure via the defer.
	if resp.Header.Flags.TC {
		skipFailureMark = true
		return resp, fmt.Errorf("response truncated")
	}

	return resp, nil
}

// queryTCP sends a query via TCP.
func (c *Client) queryTCP(server *Server, msg *protocol.Message) (*protocol.Message, error) {
	c.mu.RLock()
	pool := c.tcpPool[server.Address]
	c.mu.RUnlock()

	var buf []byte
	var putBack func()
	if pool != nil {
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
		putBack = func() {
			pool.Put(&buf)
		}
	} else {
		buf = make([]byte, 65535)
		putBack = func() {}
	}
	defer putBack()

	return c.queryTCPBuf(server, msg, buf)
}

// queryTCPBuf performs a TCP query using the provided buffer.
func (c *Client) queryTCPBuf(server *Server, msg *protocol.Message, buf []byte) (resp *protocol.Message, err error) {
	n, packErr := msg.Pack(buf)
	if packErr != nil {
		// Pack/size failures are input-side bugs; don't penalise the server.
		return nil, fmt.Errorf("pack message: %w", packErr)
	}
	packed := buf[:n]

	if len(packed) > 65535 {
		return nil, fmt.Errorf("message too large for TCP: %d bytes", len(packed))
	}

	// From here on, any error reflects a problem talking to the server.
	// Mark failure on return so the health-check loop and the load balancer
	// can react. Previously success was tracked but failure was not.
	defer func() {
		if err != nil {
			server.markFailure()
		}
	}()

	// Get a pooled connection
	c.mu.RLock()
	pool, hasPool := c.tcpConnPools[server.Address]
	c.mu.RUnlock()

	var tc *tcpConn
	if hasPool {
		tc, err = pool.get()
	} else {
		// Fallback: direct connection
		var conn net.Conn
		conn, err = net.DialTimeout("tcp", server.Address, server.Timeout)
		if err == nil {
			tc = &tcpConn{conn: conn, createdAt: time.Now(), lastUsedAt: time.Now()}
		}
	}

	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}

	// Return connection to pool when done
	returnToPool := true
	defer func() {
		if tc == nil {
			return
		}
		if returnToPool && hasPool {
			if err := pool.put(tc); err != nil {
				util.Warnf("upstream TCP pool: failed to return connection for %s: %v", server.Address, err)
			}
		} else {
			if err := tc.close(); err != nil {
				util.Warnf("upstream TCP: failed to close connection for %s: %v", server.Address, err)
			}
		}
	}()

	// Set deadline for this query
	if err := tc.conn.SetDeadline(time.Now().Add(server.Timeout)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	// Send length-prefixed query
	length := uint16(len(packed))
	lengthBuf := []byte{byte(length >> 8), byte(length)}
	if err := util.WriteFull(tc.conn, lengthBuf); err != nil {
		if closeErr := tc.close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close broken tcp connection: %w", closeErr))
		}
		tc = nil // don't return broken conn to pool
		return nil, fmt.Errorf("send length: %w", err)
	}

	start := time.Now()
	if err := util.WriteFull(tc.conn, packed); err != nil {
		if closeErr := tc.close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close broken tcp connection: %w", closeErr))
		}
		tc = nil
		return nil, fmt.Errorf("send query: %w", err)
	}

	// Read length prefix
	respLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(tc.conn, respLenBuf); err != nil {
		if closeErr := tc.close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close broken tcp connection: %w", closeErr))
		}
		tc = nil
		return nil, fmt.Errorf("read length: %w", err)
	}
	respLen := uint16(respLenBuf[0])<<8 | uint16(respLenBuf[1])

	if int(respLen) > len(buf) {
		buf = make([]byte, respLen)
	}

	// Read response
	_, err = io.ReadFull(tc.conn, buf[:respLen])
	if err != nil {
		if closeErr := tc.close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close broken tcp connection: %w", closeErr))
		}
		tc = nil
		return nil, fmt.Errorf("read response: %w", err)
	}

	latency := time.Since(start)

	// Clear deadline so connection can be reused
	if err := tc.conn.SetDeadline(time.Time{}); err != nil {
		if closeErr := tc.close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close tcp connection after deadline reset failure: %w", closeErr))
		}
		tc = nil
		return nil, fmt.Errorf("reset deadline: %w", err)
	}

	// Parse response
	resp, err = protocol.UnpackMessage(buf[:respLen])
	if err != nil {
		return nil, fmt.Errorf("unpack response: %w", err)
	}

	server.markSuccess(latency)

	return resp, nil
}

func writePacket(conn net.Conn, data []byte) error {
	n, err := conn.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

// healthCheckLoop periodically checks server health.
func (c *Client) healthCheckLoop(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(c.healthCheck)
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
	// Build a question for root NS (should always work). One Question
	// instance is shared across the per-server goroutines — Pack only
	// reads from it, never mutates — but each goroutine builds its own
	// Message header with a fresh random transaction ID via RandomTXID
	// (VULN-059 style). The previous code reused ID=0 across every
	// goroutine and every health-check cycle, which makes the response
	// matching trivial to spoof for any in-path attacker that can
	// see the source-port-randomised UDP socket.
	rootQuestion := &protocol.Question{
		Name:   protocol.NewName([]string{}, true),
		QType:  protocol.TypeNS,
		QClass: protocol.ClassIN,
	}

	var healthWg sync.WaitGroup
	c.mu.RLock()
	servers := make([]*Server, len(c.servers))
	copy(servers, c.servers)
	c.mu.RUnlock()

	for _, server := range servers {
		if server == nil {
			continue
		}
		healthWg.Add(1)
		go func(s *Server) {
			defer healthWg.Done()
			query := &protocol.Message{
				Header: protocol.Header{
					ID:      RandomTXID(),
					Flags:   protocol.Flags{RD: true},
					QDCount: 1,
				},
				Questions: []*protocol.Question{rootQuestion},
			}
			_, err := c.queryUDP(s, query)
			if err != nil {
				// Try TCP
				util.Warnf("health check UDP failed for %s: %v, trying TCP", s.Address, err)
				if _, tcpErr := c.queryTCP(s, query); tcpErr != nil {
					util.Debugf("health check TCP failed for %s: %v", s.Address, tcpErr)
				}
			}
			// queryUDP/TCP already mark success/failure
		}(server)
	}
	healthWg.Wait()
}

// Stats returns client statistics.
func (c *Client) Stats() (queries, failed, responses uint64) {
	return atomic.LoadUint64(&c.queriesTotal),
		atomic.LoadUint64(&c.queriesFailed),
		atomic.LoadUint64(&c.responsesTotal)
}

// IsHealthy returns true if at least one upstream server is healthy.
func (c *Client) IsHealthy() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, s := range c.servers {
		if s != nil && s.IsHealthy() {
			return true
		}
	}
	return false
}

// Servers returns the list of upstream servers.
func (c *Client) Servers() []*Server {
	c.mu.RLock()
	defer c.mu.RUnlock()

	servers := make([]*Server, len(c.servers))
	for i, server := range c.servers {
		servers[i] = server.snapshot()
	}
	return servers
}

// AddServer adds a new upstream server dynamically.
func (c *Client) AddServer(addr string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if server already exists
	for _, s := range c.servers {
		if s != nil && s.Address == addr {
			return fmt.Errorf("server %s already exists", addr)
		}
	}

	server := &Server{
		Address:     addr,
		Network:     "udp",
		Timeout:     c.timeout,
		healthy:     true,
		HealthCheck: 30 * time.Second,
	}
	c.servers = append(c.servers, server)

	// Initialize buffer pools
	c.udpPool[addr] = &sync.Pool{
		New: func() interface{} {
			return make([]byte, 4096)
		},
	}
	c.tcpPool[addr] = &sync.Pool{
		New: func() interface{} {
			return make([]byte, 65535)
		},
	}

	// Initialize TCP connection pool
	c.tcpConnPools[addr] = newTCPConnPool(addr, 4, 64, 30*time.Second, c.timeout)

	return nil
}

// RemoveServer removes an upstream server dynamically.
func (c *Client) RemoveServer(addr string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Find and remove server
	found := false
	newServers := make([]*Server, 0, len(c.servers))
	for _, s := range c.servers {
		if s == nil {
			continue
		}
		if s.Address == addr {
			found = true
			continue
		}
		newServers = append(newServers, s)
	}

	if !found {
		return fmt.Errorf("server %s not found", addr)
	}

	c.servers = newServers

	// Clean up pools (don't close them, just remove references)
	delete(c.udpPool, addr)
	delete(c.tcpPool, addr)
	if pool, ok := c.tcpConnPools[addr]; ok {
		if err := pool.closeAll(); err != nil {
			return err
		}
		delete(c.tcpConnPools, addr)
	}

	return nil
}
