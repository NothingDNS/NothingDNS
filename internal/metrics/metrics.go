package metrics

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// MetricsCollector collects and exposes Prometheus-format metrics.
type MetricsCollector struct {
	mu     sync.RWMutex
	config Config
	server *http.Server

	// Query metrics
	queriesTotal   map[string]*uint64 // by query type
	responsesTotal map[uint8]*uint64  // by rcode

	// Cache metrics
	cacheHits   uint64
	cacheMisses uint64

	// Blocklist metrics
	blocklistBlocks uint64

	// Upstream metrics
	upstreamQueries map[string]*uint64 // by server

	// Server metrics
	startTime time.Time
}

// Config holds metrics configuration.
type Config struct {
	Enabled bool
	Bind    string
	Path    string
}

// New creates a new metrics collector.
func New(cfg Config) *MetricsCollector {
	if cfg.Path == "" {
		cfg.Path = "/metrics"
	}

	return &MetricsCollector{
		config:          cfg,
		queriesTotal:    make(map[string]*uint64),
		responsesTotal:  make(map[uint8]*uint64),
		upstreamQueries: make(map[string]*uint64),
		startTime:       time.Now(),
	}
}

// Start starts the metrics HTTP server.
func (m *MetricsCollector) Start() error {
	if !m.config.Enabled {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc(m.config.Path, m.handleMetrics)
	mux.HandleFunc("/health", m.handleHealth)

	m.server = &http.Server{
		Addr:         m.config.Bind,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	go func() {
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Log error but don't fail - metrics are best-effort
		}
	}()

	return nil
}

// Stop stops the metrics HTTP server.
func (m *MetricsCollector) Stop() error {
	if m.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return m.server.Shutdown(ctx)
}

// RecordQuery records a DNS query.
func (m *MetricsCollector) RecordQuery(qtype string) {
	if !m.config.Enabled {
		return
	}

	m.mu.RLock()
	counter, exists := m.queriesTotal[qtype]
	m.mu.RUnlock()

	if !exists {
		m.mu.Lock()
		if m.queriesTotal[qtype] == nil {
			var newCounter uint64
			m.queriesTotal[qtype] = &newCounter
		}
		counter = m.queriesTotal[qtype]
		m.mu.Unlock()
	}

	atomic.AddUint64(counter, 1)
}

// RecordResponse records a DNS response.
func (m *MetricsCollector) RecordResponse(rcode uint8) {
	if !m.config.Enabled {
		return
	}

	m.mu.RLock()
	counter, exists := m.responsesTotal[rcode]
	m.mu.RUnlock()

	if !exists {
		m.mu.Lock()
		if m.responsesTotal[rcode] == nil {
			var newCounter uint64
			m.responsesTotal[rcode] = &newCounter
		}
		counter = m.responsesTotal[rcode]
		m.mu.Unlock()
	}

	atomic.AddUint64(counter, 1)
}

// RecordCacheHit records a cache hit.
func (m *MetricsCollector) RecordCacheHit() {
	if !m.config.Enabled {
		return
	}
	atomic.AddUint64(&m.cacheHits, 1)
}

// RecordCacheMiss records a cache miss.
func (m *MetricsCollector) RecordCacheMiss() {
	if !m.config.Enabled {
		return
	}
	atomic.AddUint64(&m.cacheMisses, 1)
}

// RecordBlocklistBlock records a blocked query.
func (m *MetricsCollector) RecordBlocklistBlock() {
	if !m.config.Enabled {
		return
	}
	atomic.AddUint64(&m.blocklistBlocks, 1)
}

// RecordUpstreamQuery records an upstream query.
func (m *MetricsCollector) RecordUpstreamQuery(server string) {
	if !m.config.Enabled {
		return
	}

	m.mu.RLock()
	counter, exists := m.upstreamQueries[server]
	m.mu.RUnlock()

	if !exists {
		m.mu.Lock()
		if m.upstreamQueries[server] == nil {
			var newCounter uint64
			m.upstreamQueries[server] = &newCounter
		}
		counter = m.upstreamQueries[server]
		m.mu.Unlock()
	}

	atomic.AddUint64(counter, 1)
}

// handleMetrics serves Prometheus-format metrics.
func (m *MetricsCollector) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	// Uptime
	uptime := time.Since(m.startTime).Seconds()
	fmt.Fprintf(w, "# HELP nothingdns_server_uptime_seconds Server uptime in seconds\n")
	fmt.Fprintf(w, "# TYPE nothingdns_server_uptime_seconds gauge\n")
	fmt.Fprintf(w, "nothingdns_server_uptime_seconds %.2f\n\n", uptime)

	// Queries total
	fmt.Fprintf(w, "# HELP nothingdns_queries_total Total number of DNS queries received\n")
	fmt.Fprintf(w, "# TYPE nothingdns_queries_total counter\n")
	m.mu.RLock()
	for qtype, counter := range m.queriesTotal {
		if counter != nil {
			fmt.Fprintf(w, "nothingdns_queries_total{type=\"%s\"} %d\n", qtype, atomic.LoadUint64(counter))
		}
	}
	m.mu.RUnlock()
	fmt.Fprintln(w)

	// Responses total
	fmt.Fprintf(w, "# HELP nothingdns_responses_total Total number of DNS responses sent\n")
	fmt.Fprintf(w, "# TYPE nothingdns_responses_total counter\n")
	m.mu.RLock()
	for rcode, counter := range m.responsesTotal {
		if counter != nil {
			fmt.Fprintf(w, "nothingdns_responses_total{rcode=\"%d\"} %d\n", rcode, atomic.LoadUint64(counter))
		}
	}
	m.mu.RUnlock()
	fmt.Fprintln(w)

	// Cache metrics
	fmt.Fprintf(w, "# HELP nothingdns_cache_hits_total Total number of cache hits\n")
	fmt.Fprintf(w, "# TYPE nothingdns_cache_hits_total counter\n")
	fmt.Fprintf(w, "nothingdns_cache_hits_total %d\n\n", atomic.LoadUint64(&m.cacheHits))

	fmt.Fprintf(w, "# HELP nothingdns_cache_misses_total Total number of cache misses\n")
	fmt.Fprintf(w, "# TYPE nothingdns_cache_misses_total counter\n")
	fmt.Fprintf(w, "nothingdns_cache_misses_total %d\n\n", atomic.LoadUint64(&m.cacheMisses))

	// Blocklist metrics
	fmt.Fprintf(w, "# HELP nothingdns_blocklist_blocks_total Total number of blocked queries\n")
	fmt.Fprintf(w, "# TYPE nothingdns_blocklist_blocks_total counter\n")
	fmt.Fprintf(w, "nothingdns_blocklist_blocks_total %d\n\n", atomic.LoadUint64(&m.blocklistBlocks))

	// Upstream queries
	fmt.Fprintf(w, "# HELP nothingdns_upstream_queries_total Total number of upstream queries\n")
	fmt.Fprintf(w, "# TYPE nothingdns_upstream_queries_total counter\n")
	m.mu.RLock()
	for server, counter := range m.upstreamQueries {
		if counter != nil {
			fmt.Fprintf(w, "nothingdns_upstream_queries_total{server=\"%s\"} %d\n", server, atomic.LoadUint64(counter))
		}
	}
	m.mu.RUnlock()
}

// handleHealth serves a simple health check endpoint.
func (m *MetricsCollector) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"healthy","uptime":"%s"}`, time.Since(m.startTime).String())
}
