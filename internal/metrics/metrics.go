package metrics

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// MetricsCollector collects and exposes Prometheus-format metrics.
type MetricsCollector struct {
	mu     sync.RWMutex
	config Config
	server *http.Server
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc

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

	// Transport stats (set periodically from UDP/TCP servers)
	udpPacketsRecv uint64
	udpPacketsSent uint64
	udpErrors      uint64
	tcpConnAccept  uint64
	tcpConnClosed  uint64
	tcpMsgRecv     uint64
	tcpErrors      uint64

	// Latency histograms
	latencyMu    sync.RWMutex
	latencyHists map[string]*latencyHistogram // by query type

	// Metrics history ring buffer (snapshots every minute, last 60 minutes)
	historyMu          sync.RWMutex
	historyIndex       int
	historyCount       int
	historySize        int
	historyTimestamps  []int64
	historyQueries     []uint64
	historyCacheHits   []uint64
	historyCacheMisses []uint64
	historyUpstreamMs  []int64 // average upstream latency in ms per minute
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
	Enabled  bool
	Bind     string
	Path     string
	AuthToken string // If set, requires ?token= on /metrics requests
}

// New creates a new metrics collector.
func New(cfg Config) *MetricsCollector {
	if cfg.Path == "" {
		cfg.Path = "/metrics"
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &MetricsCollector{
		config:             cfg,
		queriesTotal:       make(map[string]*uint64),
		responsesTotal:     make(map[uint8]*uint64),
		upstreamQueries:    make(map[string]*uint64),
		latencyHists:       make(map[string]*latencyHistogram),
		startTime:          time.Now(),
		ctx:                ctx,
		cancel:             cancel,
		historySize:        60, // 60 minutes of history
		historyTimestamps:  make([]int64, 60),
		historyQueries:     make([]uint64, 60),
		historyCacheHits:   make([]uint64, 60),
		historyCacheMisses: make([]uint64, 60),
		historyUpstreamMs:  make([]int64, 60),
	}
}

// Start starts the metrics HTTP server.
func (m *MetricsCollector) Start() error {
	if !m.config.Enabled {
		return nil
	}

	mux := http.NewServeMux()

	// Wrap with authentication if token is configured
	var metricsHandler http.HandlerFunc = m.handleMetrics
	var healthHandler http.HandlerFunc = m.handleHealth
	if m.config.AuthToken != "" {
		metricsHandler = m.requireMetricsAuth(m.handleMetrics)
		healthHandler = m.requireMetricsAuth(m.handleHealth)
	}
	mux.HandleFunc(m.config.Path, metricsHandler)
	mux.HandleFunc("/health", healthHandler)

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
			util.Warnf("metrics server error: %v", err)
		}
	}()

	// Start metrics history snapshot goroutine
	m.wg.Add(1)
	go m.historyLoop()

	return nil
}

// historyLoop snapshots metrics every minute into a ring buffer.
func (m *MetricsCollector) historyLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.recordHistorySnapshot()
		}
	}
}

// recordHistorySnapshot records a single metrics snapshot.
func (m *MetricsCollector) recordHistorySnapshot() {
	m.historyMu.Lock()
	defer m.historyMu.Unlock()

	idx := m.historyIndex % m.historySize

	var totalQueries uint64
	m.mu.RLock()
	for _, v := range m.queriesTotal {
		totalQueries += atomic.LoadUint64(v)
	}
	m.mu.RUnlock()

	m.historyTimestamps[idx] = time.Now().Unix()
	m.historyQueries[idx] = totalQueries
	m.historyCacheHits[idx] = atomic.LoadUint64(&m.cacheHits)
	m.historyCacheMisses[idx] = atomic.LoadUint64(&m.cacheMisses)

	// Average upstream latency
	m.mu.RLock()
	var totalLatency int64
	var count int
	for _, h := range m.latencyHists {
		totalLatency += int64(atomic.LoadUint64(&h.sumNs))
		count++
	}
	m.mu.RUnlock()

	if count > 0 {
		m.historyUpstreamMs[idx] = totalLatency / int64(count) / 1e6
	}

	m.historyIndex++
	if m.historyCount < m.historySize {
		m.historyCount++
	}
}

// Stop stops the metrics HTTP server.
func (m *MetricsCollector) Stop() error {
	m.mu.RLock()
	srv := m.server
	m.mu.RUnlock()

	if srv == nil {
		return nil
	}

	if m.cancel != nil {
		m.cancel()
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

// SetTransportStats sets UDP/TCP transport stats from the DNS servers.
func (m *MetricsCollector) SetTransportStats(udpPacketsRecv, udpPacketsSent, udpErrors, tcpConnAccept, tcpConnClosed, tcpMsgRecv, tcpErrors uint64) {
	if !m.config.Enabled {
		return
	}
	atomic.StoreUint64(&m.udpPacketsRecv, udpPacketsRecv)
	atomic.StoreUint64(&m.udpPacketsSent, udpPacketsSent)
	atomic.StoreUint64(&m.udpErrors, udpErrors)
	atomic.StoreUint64(&m.tcpConnAccept, tcpConnAccept)
	atomic.StoreUint64(&m.tcpConnClosed, tcpConnClosed)
	atomic.StoreUint64(&m.tcpMsgRecv, tcpMsgRecv)
	atomic.StoreUint64(&m.tcpErrors, tcpErrors)
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

// requireMetricsAuth wraps a handler with token-based authentication.
// The token is accepted via the Authorization header (Bearer token).
func (m *MetricsCollector) requireMetricsAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")
		if len(token) != len(m.config.AuthToken) ||
			subtle.ConstantTimeCompare([]byte(token), []byte(m.config.AuthToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
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
	fmt.Fprintf(w, "nothingdns_cluster_gossip_messages_received_total %d\n\n", atomic.LoadUint64(&m.clusterGossipRecv))

	// Transport metrics
	fmt.Fprintf(w, "# HELP nothingdns_udp_packets_received_total Total UDP packets received\n")
	fmt.Fprintf(w, "# TYPE nothingdns_udp_packets_received_total counter\n")
	fmt.Fprintf(w, "nothingdns_udp_packets_received_total %d\n\n", atomic.LoadUint64(&m.udpPacketsRecv))

	fmt.Fprintf(w, "# HELP nothingdns_udp_packets_sent_total Total UDP packets sent\n")
	fmt.Fprintf(w, "# TYPE nothingdns_udp_packets_sent_total counter\n")
	fmt.Fprintf(w, "nothingdns_udp_packets_sent_total %d\n\n", atomic.LoadUint64(&m.udpPacketsSent))

	fmt.Fprintf(w, "# HELP nothingdns_udp_errors_total Total UDP errors\n")
	fmt.Fprintf(w, "# TYPE nothingdns_udp_errors_total counter\n")
	fmt.Fprintf(w, "nothingdns_udp_errors_total %d\n\n", atomic.LoadUint64(&m.udpErrors))

	fmt.Fprintf(w, "# HELP nothingdns_tcp_connections_accepted_total Total TCP connections accepted\n")
	fmt.Fprintf(w, "# TYPE nothingdns_tcp_connections_accepted_total counter\n")
	fmt.Fprintf(w, "nothingdns_tcp_connections_accepted_total %d\n\n", atomic.LoadUint64(&m.tcpConnAccept))

	fmt.Fprintf(w, "# HELP nothingdns_tcp_connections_closed_total Total TCP connections closed\n")
	fmt.Fprintf(w, "# TYPE nothingdns_tcp_connections_closed_total counter\n")
	fmt.Fprintf(w, "nothingdns_tcp_connections_closed_total %d\n\n", atomic.LoadUint64(&m.tcpConnClosed))

	fmt.Fprintf(w, "# HELP nothingdns_tcp_messages_received_total Total TCP messages received\n")
	fmt.Fprintf(w, "# TYPE nothingdns_tcp_messages_received_total counter\n")
	fmt.Fprintf(w, "nothingdns_tcp_messages_received_total %d\n\n", atomic.LoadUint64(&m.tcpMsgRecv))

	fmt.Fprintf(w, "# HELP nothingdns_tcp_errors_total Total TCP errors\n")
	fmt.Fprintf(w, "# TYPE nothingdns_tcp_errors_total counter\n")
	fmt.Fprintf(w, "nothingdns_tcp_errors_total %d\n", atomic.LoadUint64(&m.tcpErrors))
}

// MetricsHistoryResponse is returned by GET /api/v1/metrics/history.
type MetricsHistoryResponse struct {
	Timestamps  []int64  `json:"timestamps"`
	Queries     []uint64 `json:"queries"`
	CacheHits   []uint64 `json:"cache_hits"`
	CacheMisses []uint64 `json:"cache_misses"`
	LatencyMs   []int64  `json:"latency_ms"`
	Count       int      `json:"count"`
}

// GetHistory returns the metrics history ring buffer data.
func (m *MetricsCollector) GetHistory() MetricsHistoryResponse {
	m.historyMu.RLock()
	defer m.historyMu.RUnlock()

	count := m.historyCount
	timestamps := make([]int64, count)
	queries := make([]uint64, count)
	cacheHits := make([]uint64, count)
	cacheMisses := make([]uint64, count)
	latencyMs := make([]int64, count)

	for i := 0; i < count; i++ {
		// Use proper modulo arithmetic to handle wrapping
		// Add historySize to ensure non-negative before modulo
		idx := (m.historyIndex - 1 - i + m.historySize) % m.historySize
		timestamps[i] = m.historyTimestamps[idx]
		queries[i] = m.historyQueries[idx]
		cacheHits[i] = m.historyCacheHits[idx]
		cacheMisses[i] = m.historyCacheMisses[idx]
		latencyMs[i] = m.historyUpstreamMs[idx]
	}

	return MetricsHistoryResponse{
		Timestamps:  timestamps,
		Queries:     queries,
		CacheHits:   cacheHits,
		CacheMisses: cacheMisses,
		LatencyMs:   latencyMs,
		Count:       count,
	}
}
func (m *MetricsCollector) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"healthy","uptime":"%s"}`, time.Since(m.startTime).String())
}
