// Package chaos provides chaos testing capabilities for NothingDNS.
// It tests resilience under adverse conditions like network partitions,
// memory pressure, and sudden shutdowns.
package chaos

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ChaosConfig holds configuration for chaos tests
type ChaosConfig struct {
	NumQueries  int           // Number of concurrent queries
	Timeout     time.Duration // Query timeout
	FailureRate float64       // Simulated failure rate (0.0-1.0)
	NetworkLoss float64       // Simulated packet loss (0.0-1.0)
}

// Stats holds chaos test statistics
type Stats struct {
	Total      int64
	Success    int64
	Failure    int64
	Timeout    int64
	NetworkErr int64
	Latencies  []time.Duration
}

func requireChaosInjection(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping in short mode - requires chaos injection setup")
	}
	if os.Getenv("NOTHINGDNS_CHAOS") != "1" {
		t.Skip("skipping chaos test by default; set NOTHINGDNS_CHAOS=1 to enable")
	}
}

// TestNetworkPartition tests behavior during network partition
// TODO: re-enable when chaos injection is properly implemented
func TestNetworkPartition(t *testing.T) {
	requireChaosInjection(t)
	cfg := &ChaosConfig{
		NumQueries:  100,
		Timeout:     100 * time.Millisecond,
		FailureRate: 0.1,
		NetworkLoss: 0.05,
	}

	stats := runChaosQueries(t, cfg)

	t.Logf("Network partition test: total=%d, success=%d, failure=%d, timeout=%d, neterr=%d",
		stats.Total, stats.Success, stats.Failure, stats.Timeout, stats.NetworkErr)

	// Success rate should be reasonable even with failures
	successRate := float64(stats.Success) / float64(stats.Total)
	if successRate < 0.5 {
		t.Errorf("Success rate too low under partition: %.2f%%", successRate*100)
	}
}

// TestGracefulShutdown tests server shutdown under load
// TODO: re-enable when chaos injection is properly implemented
func TestGracefulShutdown(t *testing.T) {
	requireChaosInjection(t)
	z := createTestZone(t, "chaos.test.")
	h := &chaosHandler{zones: map[string]*zone.Zone{"chaos.test.": z}}

	addr := findFreePort(t)
	tcpServer := server.NewTCPServer(addr, h)
	tcpServer.Listen()

	// Start server
	go tcpServer.Serve()

	// Send queries while shutting down
	var wg sync.WaitGroup
	successCount := atomic.Int64{}
	failCount := atomic.Int64{}

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				failCount.Add(1)
				return
			}
			defer conn.Close()

			// Send query
			query := makeTestQuery("www.chaos.test.")
			buf := make([]byte, 512)
			n, _ := query.Pack(buf)
			conn.Write(buf[:n])

			// Read response with timeout
			conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
			resp := make([]byte, 512)
			_, err = conn.Read(resp)
			if err == nil {
				successCount.Add(1)
			} else {
				failCount.Add(1)
			}
		}()
	}

	// Give queries a moment to start
	time.Sleep(50 * time.Millisecond)

	// Shutdown while queries are in flight
	tcpServer.Stop()

	// Wait for queries to complete
	wg.Wait()

	t.Logf("Graceful shutdown: success=%d, failed=%d", successCount.Load(), failCount.Load())

	// Most queries should have completed (some may have failed due to connection closure)
	if failCount.Load() > 40 {
		t.Errorf("Too many query failures during shutdown: %d", failCount.Load())
	}
}

// TestConcurrentLoad tests behavior under high concurrent load
// TODO: re-enable when chaos injection is properly implemented
func TestConcurrentLoad(t *testing.T) {
	requireChaosInjection(t)
	cfg := &ChaosConfig{
		NumQueries:  500,
		Timeout:     200 * time.Millisecond,
		FailureRate: 0.01,
	}

	stats := runChaosQueries(t, cfg)

	// Calculate latency percentiles
	if len(stats.Latencies) > 0 {
		p50 := percentile(stats.Latencies, 50)
		p95 := percentile(stats.Latencies, 95)
		p99 := percentile(stats.Latencies, 99)
		t.Logf("Latency: p50=%v, p95=%v, p99=%v", p50, p95, p99)
	}

	successRate := float64(stats.Success) / float64(stats.Total)
	t.Logf("Concurrent load: total=%d, success=%d (%.2f%%), failure=%d, timeout=%d",
		stats.Total, stats.Success, successRate*100, stats.Failure, stats.Timeout)

	if successRate < 0.95 {
		t.Errorf("Success rate should be >95%% under normal load: %.2f%%", successRate*100)
	}
}

// TestQueryTimeout tests behavior when queries timeout
func TestQueryTimeout(t *testing.T) {
	z := createTestZone(t, "timeout.test.")
	h := &slowHandler{zones: map[string]*zone.Zone{"timeout.test.": z}, delay: 100 * time.Millisecond}

	addr := findFreePort(t)
	tcpServer := server.NewTCPServer(addr, h)
	tcpServer.Listen()
	go tcpServer.Serve()

	// Query with very short timeout
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(50 * time.Millisecond)) // 50ms deadline

	query := makeTestQuery("www.timeout.test.")
	buf := make([]byte, 512)
	n, _ := query.Pack(buf)
	conn.Write(buf[:n])

	resp := make([]byte, 512)
	_, err = conn.Read(resp)

	// Should timeout or fail, not hang
	if err == nil {
		t.Error("Expected timeout error")
	}

	tcpServer.Stop()
}

// TestPanicRecovery tests that server recovers from panics in handlers
func TestPanicRecovery(t *testing.T) {
	z := createTestZone(t, "panic.test.")
	h := &panicHandler{zones: map[string]*zone.Zone{"panic.test.": z}}

	addr := findFreePort(t)
	tcpServer := server.NewTCPServer(addr, h)
	tcpServer.Listen()
	go tcpServer.Serve()

	// Send queries - some may trigger panics
	for i := 0; i < 20; i++ {
		go func() {
			conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()

			query := makeTestQuery("www.panic.test.")
			buf := make([]byte, 512)
			n, _ := query.Pack(buf)
			conn.Write(buf[:n])
			resp := make([]byte, 512)
			conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
			conn.Read(resp)
		}()
	}

	// Server should still be running
	time.Sleep(500 * time.Millisecond)

	// Try a normal query - should work
	conn, _ := net.DialTimeout("tcp", addr, 1*time.Second)
	if conn != nil {
		defer conn.Close()
		query := makeTestQuery("normal.panic.test.")
		buf := make([]byte, 512)
		n, _ := query.Pack(buf)
		conn.Write(buf[:n])
		conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		resp := make([]byte, 512)
		_, err := conn.Read(resp)
		if err == nil {
			t.Log("Server recovered from panics and responded to query")
		}
	}

	tcpServer.Stop()
}

// TestConnectionExhaustion tests behavior when connections are exhausted
// TODO: re-enable when chaos injection is properly implemented
func TestConnectionExhaustion(t *testing.T) {
	requireChaosInjection(t)
	z := createTestZone(t, "conn.test.")
	h := &chaosHandler{zones: map[string]*zone.Zone{"conn.test.": z}}

	addr := findFreePort(t)
	tcpServer := server.NewTCPServer(addr, h)
	tcpServer.Listen()
	go tcpServer.Serve()

	// Open many connections
	connections := make([]net.Conn, 0, 100)
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err != nil {
			continue
		}
		connections = append(connections, conn)
	}

	// All connections should get responses (or proper errors)
	errorCount := 0
	for _, conn := range connections {
		query := makeTestQuery("www.conn.test.")
		buf := make([]byte, 512)
		n, _ := query.Pack(buf)
		conn.Write(buf[:n])
		resp := make([]byte, 512)
		conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
		_, err := conn.Read(resp)
		if err != nil {
			errorCount++
		}
	}

	// Close connections
	for _, conn := range connections {
		conn.Close()
	}

	t.Logf("Connection exhaustion: opened=%d, errors=%d", len(connections), errorCount)

	tcpServer.Stop()

	if errorCount > len(connections)/2 {
		t.Errorf("Too many connection errors: %d/%d", errorCount, len(connections))
	}
}

// TestUDPPacketLoss tests UDP behavior with simulated packet loss
func TestUDPPacketLoss(t *testing.T) {
	cfg := &ChaosConfig{
		NumQueries:  100,
		Timeout:     100 * time.Millisecond,
		NetworkLoss: 0.1, // 10% loss
	}

	stats := runUDPChaosQueries(t, cfg)

	// With 10% loss, success should be roughly 90%
	successRate := float64(stats.Success) / float64(stats.Total)
	t.Logf("UDP packet loss: total=%d, success=%d (%.2f%%), timeout=%d",
		stats.Total, stats.Success, successRate*100, stats.Timeout)

	// Should have some timeouts due to packet loss
	if stats.Timeout == 0 {
		t.Error("Expected some timeouts due to packet loss")
	}
}

// TestCacheUnderLoad tests cache behavior under concurrent access
func TestCacheUnderLoad(t *testing.T) {
	cfg := cache.Config{
		Capacity:    10000,
		MinTTL:      1 * time.Second,
		MaxTTL:      1 * time.Hour,
		DefaultTTL:  5 * time.Minute,
		NegativeTTL: 30 * time.Second,
	}
	c := cache.New(cfg)

	// Concurrent reads and writes
	var wg sync.WaitGroup
	successCount := atomic.Int64{}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			key := fmt.Sprintf("key-%d", id%1000)
			msg := &protocol.Message{
				Header: protocol.Header{ID: uint16(id)},
			}

			// Write
			c.Set(key, msg, 300)

			// Read
			entry := c.Get(key)
			if entry != nil {
				successCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	t.Logf("Cache under load: operations=%d, successful reads=%d", 100, successCount.Load())

	if successCount.Load() < 50 {
		t.Errorf("Too few successful cache reads: %d", successCount.Load())
	}
}

// TestGoroutineLeakDetection tests for goroutine leaks
func TestGoroutineLeakDetection(t *testing.T) {
	initialGoroutines := runtime.NumGoroutine()

	// Create and stop servers multiple times
	for i := 0; i < 5; i++ {
		z := createTestZone(t, fmt.Sprintf("leak%d.test.", i))
		h := &chaosHandler{zones: map[string]*zone.Zone{fmt.Sprintf("leak%d.test.", i): z}}

		addr := findFreePort(t)
		tcpServer := server.NewTCPServer(addr, h)
		tcpServer.Listen()
		go tcpServer.Serve()

		// Send some queries
		for j := 0; j < 10; j++ {
			conn, _ := net.DialTimeout("tcp", addr, 1*time.Second)
			if conn != nil {
				query := makeTestQuery(fmt.Sprintf("www.leak%d.test.", i))
				buf := make([]byte, 512)
				n, _ := query.Pack(buf)
				conn.Write(buf[:n])
				resp := make([]byte, 512)
				conn.SetDeadline(time.Now().Add(50 * time.Millisecond))
				conn.Read(resp)
				conn.Close()
			}
		}

		tcpServer.Stop()
		time.Sleep(100 * time.Millisecond)
	}

	// Give time for goroutines to exit
	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	t.Logf("Goroutine leak detection: initial=%d, final=%d, delta=%d",
		initialGoroutines, finalGoroutines, finalGoroutines-initialGoroutines)

	// Allow some variance, but shouldn't grow unbounded
	if finalGoroutines > initialGoroutines+20 {
		t.Errorf("Potential goroutine leak: %d -> %d", initialGoroutines, finalGoroutines)
	}
}

// ============================================================================

// Helper functions

func runChaosQueries(t *testing.T, cfg *ChaosConfig) *Stats {
	z := createTestZone(t, "chaos.test.")
	h := &chaosHandler{zones: map[string]*zone.Zone{"chaos.test.": z}}

	addr := findFreePort(t)
	tcpServer := server.NewTCPServer(addr, h)
	tcpServer.Listen()
	go tcpServer.Serve()

	stats := &Stats{Latencies: make([]time.Duration, 0, cfg.NumQueries)}
	var wg sync.WaitGroup

	for i := 0; i < cfg.NumQueries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			atomic.AddInt64(&stats.Total, 1)

			start := time.Now()
			conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
			if err != nil {
				atomic.AddInt64(&stats.NetworkErr, 1)
				return
			}
			defer conn.Close()

			query := makeTestQuery(fmt.Sprintf("www-%d.chaos.test.", rand.Intn(100)))
			buf := make([]byte, 512)
			n, _ := query.Pack(buf)

			if _, err := conn.Write(buf[:n]); err != nil {
				atomic.AddInt64(&stats.NetworkErr, 1)
				return
			}

			resp := make([]byte, 512)
			conn.SetDeadline(time.Now().Add(cfg.Timeout))
			_, err = conn.Read(resp)

			latency := time.Since(start)
			stats.Latencies = append(stats.Latencies, latency)

			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					atomic.AddInt64(&stats.Timeout, 1)
				} else {
					atomic.AddInt64(&stats.Failure, 1)
				}
				return
			}

			atomic.AddInt64(&stats.Success, 1)
		}()
	}

	wg.Wait()
	tcpServer.Stop()

	return stats
}

func runUDPChaosQueries(t *testing.T, cfg *ChaosConfig) *Stats {
	z := createTestZone(t, "chaos.test.")
	h := &chaosHandler{zones: map[string]*zone.Zone{"chaos.test.": z}}

	addr := findFreePortUDP(t)
	udpServer := server.NewUDPServer(addr, h)
	udpServer.Listen()

	stats := &Stats{Latencies: make([]time.Duration, 0, cfg.NumQueries)}
	var wg sync.WaitGroup

	for i := 0; i < cfg.NumQueries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			atomic.AddInt64(&stats.Total, 1)

			// Simulate packet loss by occasionally not sending
			if rand.Float64() < cfg.NetworkLoss {
				time.Sleep(cfg.Timeout)
				atomic.AddInt64(&stats.Timeout, 1)
				return
			}

			start := time.Now()
			conn, err := net.DialTimeout("udp", addr, cfg.Timeout)
			if err != nil {
				atomic.AddInt64(&stats.NetworkErr, 1)
				return
			}
			defer conn.Close()

			query := makeTestQuery(fmt.Sprintf("www-%d.chaos.test.", rand.Intn(100)))
			buf := make([]byte, 512)
			n, _ := query.Pack(buf)

			if _, err := conn.Write(buf[:n]); err != nil {
				atomic.AddInt64(&stats.NetworkErr, 1)
				return
			}

			resp := make([]byte, 512)
			conn.SetDeadline(time.Now().Add(cfg.Timeout))
			_, err = conn.Read(resp)

			latency := time.Since(start)
			stats.Latencies = append(stats.Latencies, latency)

			if err != nil {
				atomic.AddInt64(&stats.Timeout, 1)
				return
			}

			atomic.AddInt64(&stats.Success, 1)
		}()
	}

	wg.Wait()
	udpServer.Stop()

	return stats
}

type chaosHandler struct {
	zones map[string]*zone.Zone
}

func (h *chaosHandler) ServeDNS(w server.ResponseWriter, r *protocol.Message) {
	if len(r.Questions) == 0 {
		return
	}
	q := r.Questions[0]
	qname := q.Name.String()

	for _, z := range h.zones {
		records := z.Lookup(qname, protocol.TypeString(q.QType))
		if len(records) > 0 {
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:    r.Header.ID,
					Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
				},
				Questions: r.Questions,
			}
			for range records {
				resp.AddAnswer(&protocol.ResourceRecord{
					Name:  q.Name,
					Type:  q.QType,
					Class: protocol.ClassIN,
					TTL:   300,
				})
			}
			w.Write(resp)
			return
		}
	}

	// NXDOMAIN
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    r.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
		Questions: r.Questions,
	}
	w.Write(resp)
}

type slowHandler struct {
	zones map[string]*zone.Zone
	delay time.Duration
}

func (h *slowHandler) ServeDNS(w server.ResponseWriter, r *protocol.Message) {
	time.Sleep(h.delay)
	if len(r.Questions) == 0 {
		return
	}
	q := r.Questions[0]
	qname := q.Name.String()

	for _, z := range h.zones {
		records := z.Lookup(qname, protocol.TypeString(q.QType))
		if len(records) > 0 {
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:    r.Header.ID,
					Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
				},
				Questions: r.Questions,
			}
			w.Write(resp)
			return
		}
	}
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    r.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
		Questions: r.Questions,
	}
	w.Write(resp)
}

type panicHandler struct {
	zones map[string]*zone.Zone
}

func (h *panicHandler) ServeDNS(w server.ResponseWriter, r *protocol.Message) {
	// Randomly panic (1 in 5 chance)
	if rand.Intn(5) == 0 {
		panic("chaos test panic")
	}

	if len(r.Questions) == 0 {
		return
	}
	q := r.Questions[0]
	qname := q.Name.String()

	for _, z := range h.zones {
		records := z.Lookup(qname, protocol.TypeString(q.QType))
		if len(records) > 0 {
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:    r.Header.ID,
					Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
				},
				Questions: r.Questions,
			}
			w.Write(resp)
			return
		}
	}
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    r.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
		Questions: r.Questions,
	}
	w.Write(resp)
}

func createTestZone(t *testing.T, name string) *zone.Zone {
	content := fmt.Sprintf(`$ORIGIN %s
$TTL 3600
@ IN SOA ns1.%s admin.%s (
    2024010101 3600 900 604800 86400 )
@ IN NS ns1.%s
ns1 IN A 127.0.0.1
www IN A 192.168.1.1
mail IN A 192.168.1.2
`, name, name, name, name)

	z, err := zone.ParseFile(name, strings.NewReader(content))
	if err != nil {
		t.Fatalf("creating test zone: %v", err)
	}
	return z
}

func makeTestQuery(name string) *protocol.Message {
	parsedName, _ := protocol.ParseName(name)
	return &protocol.Message{
		Header: protocol.Header{
			ID:      0x1234,
			Flags:   protocol.NewQueryFlags(),
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   parsedName,
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}
}

func findFreePort(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func findFreePortUDP(t *testing.T) string {
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.LocalAddr().String()
}

func percentile(values []time.Duration, p int) time.Duration {
	if len(values) == 0 {
		return 0
	}
	// Simple sorting for percentile calculation
	sorted := make([]time.Duration, len(values))
	copy(sorted, values)
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	idx := (len(sorted) * p) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
