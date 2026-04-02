package metrics

import (
	"context"
	"fmt"
	"log"
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
	wg     sync.WaitGroup

	// Query metrics
	queriesTotal   map[string]*uint64 // by query type
	responsesTotal map[uint8]*uint64  // by rcode

	// Cache metrics
	cacheHits   uint64
	cacheMisses uint64

	// Blocklist metrics
	blocklistBlocks uint64

	// Rate limit metrics
	rateLimited uint64

	// Upstream metrics
	upstreamQueries map[string]*uint64 // by server

	// Cluster metrics
	clusterNodeCount  uint64
	clusterAliveCount uint64
	clusterHealthy    uint32 // 0 or 1
	clusterGossipSent uint64
	clusterGossipRecv uint64

	// Server metrics
	startTime time.Time

	// Latency histograms
	latencyMu      sync.RWMutex
	latencyHists   map[string]*latencyHistogram // by query type
}

// latencyHistogram implements a fixed-bucket histogram without external dependencies.
type latencyHistogram struct {
	bucketCounts [numLatencyBuckets]uint64
	totalCount   uint64
	sumNs        uint64
}

const numLatencyBuckets = 9

var latencyBounds = [numLatencyBuckets]time.Duration{
	1 * time.Millisecond,
	5 * time.Millisecond,
	10 * time.Millisecond,
	25 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	1000 * time.Millisecond,
}

var latencyLabels = [numLatencyBuckets]string{
	"0.001", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1.0",
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
		latencyHists:    make(map[string]*latencyHistogram),
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

	m.mu.Lock()
	m.server = &http.Server{
		Addr:         m.config.Bind,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	m.mu.Unlock()

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("metrics server error: %v", err)
		}
	}()

	return nil
}

// Stop stops the metrics HTTP server.
func (m *MetricsCollector) Stop() error {
	m.mu.RLock()
	srv := m.server
	m.mu.RUnlock()

	if srv == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := srv.Shutdown(ctx)
	m.wg.Wait()
	return err
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

// RecordRateLimited records a rate-limited query.
func (m *MetricsCollector) RecordRateLimited() {
	if !m.config.Enabled {
		return
	}
	atomic.AddUint64(&m.rateLimited, 1)
}

// RecordQueryLatency records query processing latency.
func (m *MetricsCollector) RecordQueryLatency(qtype string, duration time.Duration) {
	if !m.config.Enabled {
		return
	}

	m.latencyMu.Lock()
	h, ok := m.latencyHists[qtype]
	if !ok {
		h = &latencyHistogram{}
		m.latencyHists[qtype] = h
	}
	m.latencyMu.Unlock()

	ns := duration.Nanoseconds()
	atomic.AddUint64(&h.totalCount, 1)
	atomic.AddUint64(&h.sumNs, uint64(ns))

	// Find and increment the appropriate bucket
	for i, bound := range latencyBounds {
		if duration <= bound {
			atomic.AddUint64(&h.bucketCounts[i], 1)
			return
		}
	}
	// Falls into implicit +Inf bucket (no explicit counter needed)
}

// SetClusterMetrics sets cluster-related metrics.
func (m *MetricsCollector) SetClusterMetrics(nodeCount, aliveCount int, healthy bool, gossipSent, gossipRecv uint64) {
	if !m.config.Enabled {
		return
	}
	atomic.StoreUint64(&m.clusterNodeCount, uint64(nodeCount))
	atomic.StoreUint64(&m.clusterAliveCount, uint64(aliveCount))
	if healthy {
		atomic.StoreUint32(&m.clusterHealthy, 1)
	} else {
		atomic.StoreUint32(&m.clusterHealthy, 0)
	}
	atomic.StoreUint64(&m.clusterGossipSent, gossipSent)
	atomic.StoreUint64(&m.clusterGossipRecv, gossipRecv)
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

	// Rate limit metrics
	fmt.Fprintf(w, "# HELP nothingdns_rate_limited_total Total number of rate-limited queries\n")
	fmt.Fprintf(w, "# TYPE nothingdns_rate_limited_total counter\n")
	fmt.Fprintf(w, "nothingdns_rate_limited_total %d\n\n", atomic.LoadUint64(&m.rateLimited))

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
	fmt.Fprintln(w)

	// Latency histograms
	fmt.Fprintf(w, "# HELP nothingdns_query_duration_seconds Query latency distribution\n")
	fmt.Fprintf(w, "# TYPE nothingdns_query_duration_seconds histogram\n")
	m.latencyMu.RLock()
	for qtype, h := range m.latencyHists {
		count := atomic.LoadUint64(&h.totalCount)
		sum := atomic.LoadUint64(&h.sumNs)
		for i, label := range latencyLabels {
			bucketCount := atomic.LoadUint64(&h.bucketCounts[i])
			fmt.Fprintf(w, "nothingdns_query_duration_seconds_bucket{type=\"%s\",le=\"%s\"} %d\n", qtype, label, bucketCount)
		}
		fmt.Fprintf(w, "nothingdns_query_duration_seconds_bucket{type=\"%s\",le=\"+Inf\"} %d\n", qtype, count)
		fmt.Fprintf(w, "nothingdns_query_duration_seconds_sum{type=\"%s\"} %.6f\n", qtype, float64(sum)/1e9)
		fmt.Fprintf(w, "nothingdns_query_duration_seconds_count{type=\"%s\"} %d\n", qtype, count)
	}
	m.latencyMu.RUnlock()
	fmt.Fprintln(w)

	// Cluster metrics
	fmt.Fprintf(w, "# HELP nothingdns_cluster_nodes_total Total number of cluster nodes\n")
	fmt.Fprintf(w, "# TYPE nothingdns_cluster_nodes_total gauge\n")
	fmt.Fprintf(w, "nothingdns_cluster_nodes_total %d\n\n", atomic.LoadUint64(&m.clusterNodeCount))

	fmt.Fprintf(w, "# HELP nothingdns_cluster_nodes_alive Number of alive cluster nodes\n")
	fmt.Fprintf(w, "# TYPE nothingdns_cluster_nodes_alive gauge\n")
	fmt.Fprintf(w, "nothingdns_cluster_nodes_alive %d\n\n", atomic.LoadUint64(&m.clusterAliveCount))

	fmt.Fprintf(w, "# HELP nothingdns_cluster_healthy Whether the cluster is healthy (1=healthy, 0=unhealthy)\n")
	fmt.Fprintf(w, "# TYPE nothingdns_cluster_healthy gauge\n")
	fmt.Fprintf(w, "nothingdns_cluster_healthy %d\n\n", atomic.LoadUint32(&m.clusterHealthy))

	fmt.Fprintf(w, "# HELP nothingdns_cluster_gossip_messages_sent_total Total gossip messages sent\n")
	fmt.Fprintf(w, "# TYPE nothingdns_cluster_gossip_messages_sent_total counter\n")
	fmt.Fprintf(w, "nothingdns_cluster_gossip_messages_sent_total %d\n\n", atomic.LoadUint64(&m.clusterGossipSent))

	fmt.Fprintf(w, "# HELP nothingdns_cluster_gossip_messages_received_total Total gossip messages received\n")
	fmt.Fprintf(w, "# TYPE nothingdns_cluster_gossip_messages_received_total counter\n")
	fmt.Fprintf(w, "nothingdns_cluster_gossip_messages_received_total %d\n", atomic.LoadUint64(&m.clusterGossipRecv))
}

// handleHealth serves a simple health check endpoint.
func (m *MetricsCollector) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"healthy","uptime":"%s"}`, time.Since(m.startTime).String())
}
