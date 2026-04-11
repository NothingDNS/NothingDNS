package load

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// Config holds load test configuration.
type Config struct {
	Server   string        // Server address (host:port)
	Queries  int           // Number of queries per worker
	Workers  int           // Number of concurrent workers
	Timeout  time.Duration // Query timeout
	Type     uint16        // Query type (A, AAAA, TXT, etc.)
	Name     string        // Query name
	Protocol string        // "udp", "tcp", "dot", "doh"
}

// Result holds load test results.
type Result struct {
	Queries       int64           // Total queries sent
	Success       int64           // Successful responses
	Errors        int64           // Errors (network, protocol)
	Timeouts      int64           // Timeouts
	TotalDuration time.Duration   // Total test duration
	LatencyMin    time.Duration   // Min latency
	LatencyMax    time.Duration   // Max latency
	LatencyAvg    time.Duration   // Avg latency
	LatencyP50    time.Duration   // 50th percentile
	LatencyP95    time.Duration   // 95th percentile
	LatencyP99    time.Duration   // 99th percentile
	QPS           float64         // Queries per second
	ErrorsDetail  map[string]int64 // Error type counts
}

// Runner executes load tests.
type Runner struct {
	cfg       Config
	latencies []time.Duration
	success   int64
	errors    int64
	timeouts  int64
	mu        sync.Mutex
}

// NewRunner creates a new load test runner.
func NewRunner(cfg Config) *Runner {
	return &Runner{
		cfg:      cfg,
		latencies: make([]time.Duration, 0, cfg.Queries*cfg.Workers),
	}
}

// Run executes the load test and returns results.
func (r *Runner) Run(ctx context.Context) *Result {
	if r.cfg.Timeout == 0 {
		r.cfg.Timeout = 5 * time.Second
	}

	start := time.Now()
	var wg sync.WaitGroup

	for w := 0; w < r.cfg.Workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			r.runWorker(ctx, workerID)
		}(w)
	}

	wg.Wait()

	return r.computeResult(time.Since(start))
}

func (r *Runner) runWorker(ctx context.Context, workerID int) {
	var conn net.Conn
	var err error

	// Use TCP for reliability under load
	proto := r.cfg.Protocol
	if proto != "udp" {
		proto = "tcp"
	}

	conn, err = net.DialTimeout(proto, r.cfg.Server, r.cfg.Timeout)
	if err != nil {
		r.errors += int64(r.cfg.Queries)
		return
	}
	defer conn.Close()

	for q := 0; q < r.cfg.Queries; q++ {
		select {
		case <-ctx.Done():
			return
		default:
			r.sendQuery(conn)
		}
	}
}

func (r *Runner) sendQuery(conn net.Conn) {
	// Build DNS query
	qname, err := protocol.ParseName(r.cfg.Name)
	if err != nil {
		r.errors++
		return
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:     uint16(time.Now().UnixNano() & 0xFFFF),
			Flags:  protocol.Flags{QR: false, Opcode: protocol.OpcodeQuery, RD: true},
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: qname, QType: r.cfg.Type, QClass: protocol.ClassIN},
		},
	}

	buf := make([]byte, 512)
	n, err := msg.Pack(buf)
	if err != nil {
		r.errors++
		return
	}

	queryStart := time.Now()

	// Send with deadline
	conn.SetDeadline(queryStart.Add(r.cfg.Timeout))
	_, err = conn.Write(buf[:n])
	if err != nil {
		r.timeouts++
		return
	}

	// Read response
	resp := make([]byte, 512)
	_, err = conn.Read(resp)
	latency := time.Since(queryStart)

	if err != nil {
		r.timeouts++
		return
	}

	// Unpack to validate
	_, err = protocol.UnpackMessage(resp)
	if err != nil {
		r.errors++
		return
	}

	r.success++

	r.mu.Lock()
	r.latencies = append(r.latencies, latency)
	r.mu.Unlock()
}

func (r *Runner) computeResult(total time.Duration) *Result {

	latencies := r.latencies
	if len(latencies) == 0 {
		return &Result{
			TotalDuration: total,
			ErrorsDetail:  map[string]int64{},
		}
	}

	// Sort for percentiles
	for i := 0; i < len(latencies); i++ {
		for j := i + 1; j < len(latencies); j++ {
			if latencies[j] < latencies[i] {
				latencies[i], latencies[j] = latencies[j], latencies[i]
			}
		}
	}

	var sum time.Duration
	for _, l := range latencies {
		sum += l
	}

	n := len(latencies)
	result := &Result{
		Success:       r.success,
		Errors:        r.errors,
		Timeouts:      r.timeouts,
		TotalDuration: total,
		LatencyMin:    latencies[0],
		LatencyMax:    latencies[n-1],
		LatencyAvg:    sum / time.Duration(n),
		LatencyP50:    latencies[n/2],
		LatencyP95:    latencies[int(float64(n)*0.95)],
		LatencyP99:    latencies[int(float64(n)*0.99)],
		QPS:           float64(n) / total.Seconds(),
		ErrorsDetail: map[string]int64{
			"protocol": r.errors,
			"timeout":  r.timeouts,
		},
	}

	return result
}

// String implements fmt.Stringer for Result.
func (r *Result) String() string {
	return fmt.Sprintf(`Load Test Results
================
Queries:       %d
Success:       %d (%.2f%%)
Errors:        %d
Timeouts:      %d
Duration:      %v
QPS:           %.2f

Latency:
  Min:         %v
  Avg:         %v
  P50:         %v
  P95:         %v
  P99:         %v
  Max:         %v`,
		r.Queries, r.Success, percent(r.Success, r.Queries),
		r.Errors, r.Timeouts, r.TotalDuration, r.QPS,
		r.LatencyMin, r.LatencyAvg, r.LatencyP50, r.LatencyP95, r.LatencyP99, r.LatencyMax)
}

func percent(numerator, denominator int64) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator) * 100
}

// RunPreset runs a predefined load test scenario.
func RunPreset(ctx context.Context, server string, preset string) *Result {
	var cfg Config
	cfg.Server = server
	cfg.Timeout = 5 * time.Second
	cfg.Protocol = "tcp"

	switch preset {
	case "light":
		cfg.Workers = 4
		cfg.Queries = 1000
	case "medium":
		cfg.Workers = 16
		cfg.Queries = 5000
	case "heavy":
		cfg.Workers = 64
		cfg.Queries = 20000
	case "stress":
		cfg.Workers = 256
		cfg.Queries = 100000
	default:
		cfg.Workers = 8
		cfg.Queries = 2500
	}

	cfg.Name = "www.example.com."
	cfg.Type = protocol.TypeA

	runner := NewRunner(cfg)
	return runner.Run(ctx)
}
