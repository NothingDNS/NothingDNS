# NothingDNS Performance Optimization Guide

## Overview

This guide covers performance tuning, benchmarking, and optimization strategies for NothingDNS.

## Performance Targets

These are operational monitoring thresholds, not the design goals in
[SPECIFICATION.md §14](SPECIFICATION.md) (which sets higher QPS goals and records
which have been measured). The `QPS` row is a per-node figure to alert on, and
the latency rows are not enforced by anything in the server.

| Metric | Target | Critical Threshold |
|--------|--------|-------------------|
| QPS | 50,000+ | < 10,000 |
| P50 Latency | < 2ms | > 10ms |
| P99 Latency | < 10ms | > 50ms |
| P999 Latency | < 50ms | > 200ms |
| Cache Hit Ratio | > 90% | < 60% |
| Memory per 1K entries | ~1 MB | > 5 MB |

## 1. Baseline Benchmarking

### Local UDP flood and its ceiling

`go test -tags perf -run TestLocalUDPFlood ./internal/load/` floods
`127.0.0.1:15353` (override with `PERF_ADDR`, `PERF_WORKERS`) and prints the
success QPS. Run the server with `server.udp_rate_per_ip: 0`, otherwise the
default 100 queries/second per client IP caps a single source.

Measured on a 12-core Linux machine with the generator on the same host
(authoritative A query, one local zone):

| Server setting | QPS |
|----------------|-----|
| default (one UDP socket) | 65,000 to 77,000 |
| `server.udp_listeners: 4` | 106,000 to 114,000 |
| `server.udp_listeners: 8` or `12` | 113,000 to 116,000 |
| trivial Go UDP echo server (no DNS), same client | about 176,000 |

Use more than one listener on multi-core Linux hosts. The echo row is the
ceiling of this test setup, because the client and the kernel loopback share the
same cores; to measure beyond it, run the generator on a separate host.

### Quick Benchmark

```bash
# Build release binary
make build-release

# Run built-in benchmarks
go test ./internal/cache -bench=. -benchmem -count=5
go test ./internal/protocol -bench=. -benchmem -count=5
go test ./internal/dnssec -bench=. -benchmem -count=5
```

### DNS Query Benchmark with queryperf

```bash
# Install DNS query testing tool
# From BIND distribution or dnsperf

# Create query file (queries.txt)
echo "example.com A" > queries.txt
echo "api.example.com AAAA" >> queries.txt
echo "mail.example.com MX" >> queries.txt

# Run benchmark (100 queries, 10 concurrent)
queryperf -d queries.txt -s 127.0.0.1 -q 100 -T 10
```

### Load Testing

```bash
# Using Go's built-in test as load generator
go test ./internal/e2e/... -bench=. -benchtime=10s -count=3
```

## 2. Profiling

The server can expose Go's pprof handlers, off by default. Set
`metrics.pprof_bind` to a loopback address and restart (it is not hot-reloaded):

```yaml
metrics:
  pprof_bind: "127.0.0.1:6060"   # unauthenticated; non-loopback is rejected
```

It is separate from the metrics port, works with `metrics.enabled: false`, and
serves `/debug/pprof/` (index, `profile`, `heap`, `goroutine`, `allocs`,
`trace`, ...). `block` and `mutex` profiles are empty because the server does not
set a sampling rate. Benchmarks can also be profiled with `go test` as below.

### CPU Profiling

```bash
# Running server (needs metrics.pprof_bind)
curl -o cpu.prof "http://127.0.0.1:6060/debug/pprof/profile?seconds=30"

# Or profile a benchmark
go test -cpuprofile=cpu.out -count=3 ./internal/...

# Analyze with pprof
go tool pprof -http=:8081 cpu.prof
```

### Memory Profiling

```bash
# Running server
curl -o memory.prof http://127.0.0.1:6060/debug/pprof/heap

# Or profile a benchmark
go test -memprofile=mem.out -count=3 ./internal/cache/...

# Analyze
go tool pprof -http=:8081 mem.out
```

### Block Profiling (I/O Blocking)

```bash
# Profile goroutine blocking
go test -blockprofile=block.prof ./internal/cache/...

# Analyze
go tool pprof -http=:8081 block.prof
```

### Mutex Profiling

```bash
# Profile lock contention
go test -mutexprofile=mutex.prof ./internal/cache/...

# Analyze
go tool pprof -http=:8081 mutex.prof
```

### Trace Profiling

```bash
# Collect an execution trace of a benchmark
go test -trace=trace.prof ./internal/cache/...

# Analyze
go tool trace trace.prof
```

## 3. Configuration Tuning

### Cache Configuration

```yaml
cache:
  # Size: More entries = higher hit ratio but more memory
  size: 50000

  # TTL: Longer = better hit ratio but stale data
  min_ttl: 300        # 5 minutes
  max_ttl: 86400      # 24 hours
  default_ttl: 3600   # 1 hour

  # Negative cache (RFC 2308)
  negative_ttl: 60    # 1 minute for NXDOMAIN

  # Prefetch: Proactively fetch expiring entries
  prefetch: true
  prefetch_threshold: 28800  # 8 hours before expiry

  # Serve stale (RFC 8767) - serve expired cache during upstream failure
  serve_stale: true
  stale_grace_secs: 604800    # 7 days
```

**Tuning Guidelines**:
- `size = QPS * average_ttl_seconds / 1000`
- For 10K QPS with 1-hour avg TTL: `size ≈ 10,000 * 3600 / 1000 = 36,000`

### Worker Pool Sizing

```yaml
server:
  workers:
    udp: 32    # CPU cores * 4 (for UDP)
    tcp: 16    # CPU cores * 2 (for TCP)
```

**Rule of thumb**:
- UDP workers: `CPU cores * 4`
- TCP workers: `CPU cores * 2`
- More workers = better concurrency but more context switching

### Upstream Tuning

```yaml
upstream:
  strategy: round_robin  # or: weighted, random, geo

  servers:
    - addr: 1.1.1.1:53
      weight: 100
      health_check: true
    - addr: 8.8.8.8:53
      weight: 50
      health_check: true

  timeout: 5           # seconds
  keepalive: 30         # TCP connection reuse
```

**For lower latency**:
- Use closer upstream servers (geo-routing)
- Reduce timeout slightly (2-3s)
- Enable connection pooling

### Network Tuning

```yaml
# Kernel parameters (sysctl)
# net.core.rmem_max = 134217728
# net.core.wmem_max = 134217728
# net.ipv4.udp_rmem_min = 16384
# net.ipv4.udp_wmem_min = 16384
# fs.file-max = 65536
```

## 4. Memory Optimization

### Memory Monitoring

```bash
# Check dashboard/server stats
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/dashboard/stats

# Or via Prometheus metrics
curl http://localhost:9153/metrics | grep nothingdns_memory
```

### Memory-Efficient Settings

```yaml
# Reduce memory footprint
cache:
  size: 10000    # Lower if memory constrained

# Disable features you don't need
dnssec:
  enabled: false  # Saves memory on signature verification

cache:
  prefetch: false  # Reduces background activity

# Limit string interning (automatic in Go)
# Not configurable, but be aware of label-heavy zones
```

### Memory Profiling Tips

```bash
# Find memory leaks
go tool pprof -http=:8081 mem.prof

# In pprof shell:
# > top -heap
# > peak          # Show largest allocations
# > inuse_space   # Currently held memory
# > alloc_space  # Total allocated (including freed)
```

## 5. DNSSEC Performance

### DNSSEC is Expensive

DNSSEC validation and signing are CPU-intensive:

```yaml
# Use ECDSA (faster than RSA)
dnssec:
  signing:
    algorithm: ecdsap256sha256  # Much faster than rsasha256
    # Or for maximum speed:
    algorithm: ed25519          # Fastest option

# For validation-heavy workloads:
dnssec:
  validation:
    cache_size: 10000          # Cache validated results
    cache_ttl: 3600             # 1 hour
```

**Algorithm Performance** (operations/second on typical CPU):
| Algorithm | Sign | Verify |
|-----------|------|--------|
| RSASHA256 | 5,000 | 50,000 |
| RSASHA512 | 3,000 | 30,000 |
| ECDSAP256 | 50,000 | 100,000 |
| ED25519 | 100,000 | 200,000 |

### Pre-signed Zones

For high-QPS zones, pre-sign instead of on-the-fly:

```bash
# Sign zone externally with dnssec-signzone
dnssec-signzone -A -3 $(head -c 8 /dev/urandom | xxd -p) \
  -N increment -o example.com \
  /etc/nothingdns/zones/example.com.db

# Configure NothingDNS to serve pre-signed zone
```

## 6. Cache Optimization

### Hit Ratio Tuning

```
Target: > 90% hit ratio

Factors affecting hit ratio:
1. Cache size (more = better ratio)
2. TTL (higher = better ratio)
3. Traffic patterns (repeated queries = better ratio)
4. Prefetching (reduces misses on popular domains)
```

### Cache Warming

```bash
# Warm cache with normal DNS queries; there is no dedicated cache-warm API.
while read -r domain; do
  [ -n "$domain" ] && dig @localhost "$domain" A >/dev/null
done < popular_domains.txt
```

### Negative Cache (RFC 2308)

```yaml
cache:
  negative_ttl: 60    # NXDOMAIN cached for 1 minute
  # Too high = stale NXDOMAIN served
  # Too low = repeated upstream queries for non-existent domains
```

## 7. Query Processing Optimization

### NSEC Aggressive Caching (RFC 8198)

```yaml
cache:
  enabled: true
  negative_ttl: 60
```

DNSSEC validation can use cached denial-of-existence records; tune negative TTL
conservatively so repeated NXDOMAIN traffic is absorbed without keeping stale
denials too long.

### Minimize Response (RFC 6604)

Avoid unnecessary additional records in authoritative zone data and keep EDNS0
payload sizing aligned with your client networks.

### Query ID Randomization

NothingDNS randomizes outbound query IDs in protocol handling; there is no
separate YAML switch for this behavior.

## 8. Transport Optimization

### UDP Optimization

```yaml
server:
  udp_workers: 32
resolution:
  edns0_buffer_size: 4096
rrl:
  enabled: true
  rate: 100
  burst: 200
```

### TCP Optimization

```yaml
server:
  tcp:
    max_connections: 1000     # Global limit
    max_per_ip: 10            # Per-IP limit
    pipeline_limit: 16        # Concurrent queries per connection
    keepalive: 30             # Seconds
```

### TLS (DoT) Optimization

```yaml
server:
  tls:
    min_version: "1.3"        # TLS 1.3 only for performance
    session_resumption: true   # Session tickets
    session_cache_size: 10000
```

### QUIC (DoQ) Optimization

QUIC has better latency on lossy networks:

```yaml
server:
  quic:
    enabled: true
    max_connections: 1000
    stream_window: 100
```

## 9. Cluster Performance

### SWIM vs Raft

| Mode | Consistency | Performance |
|------|-------------|-------------|
| SWIM | Eventual | Higher QPS |
| Raft | Strong | Lower QPS |

Use **SWIM** for most workloads. Use **Raft** only when strong consistency is required.

### Cluster Cache Sync

```yaml
cluster:
  cache_sync: true
  sync_interval: 5    # Seconds between syncs
  batch_size: 100     # Entries per sync
```

Reduce sync overhead on high-QPS clusters:
- Increase `sync_interval` to 10-30s
- Decrease `batch_size` to reduce memory

### Load Balancing in Cluster

```yaml
cluster:
  load_balancing:
    strategy: health_weighted  # Route to healthiest node
    min_health: 0.5            # Minimum health threshold
```

## 10. Identifying Bottlenecks

### High CPU

1. Enable DNSSEC -> Disable if not needed
2. High QPS -> Scale horizontally
3. Check for validation loops

```bash
# Profile CPU
go tool pprof -http=:8081 cpu.prof

# In pprof:
# > top                    # Top functions by CPU time
# > list handler.ServeDNS   # CPU time in handler
```

### High Memory

1. Reduce cache size
2. Check for memory leaks

```bash
# Profile memory
go tool pprof -http=:8081 mem.prof

# In pprof:
# > top -heap              # Largest allocations
# > look for growing maps
```

### High Latency

1. Check upstream latency
2. Check cache hit ratio
3. Check for network issues

```bash
# Historical latency samples from the metrics ring buffer
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/metrics/history | jq '{timestamps, latency_ms, count}'
```

### Low QPS

1. Check worker pool sizing
2. Check connection limits
3. Profile blocking operations

```bash
# Block profile shows synchronization issues
go tool pprof -http=:8081 block.prof
```

## 11. Performance Monitoring

### Key Metrics to Watch

```promql
# Query rate
rate(nothingdns_queries_total[5m])

# Latency percentiles
histogram_quantile(0.99, rate(nothingdns_latency_seconds_bucket[5m]))
histogram_quantile(0.999, rate(nothingdns_latency_seconds_bucket[5m]))

# Cache efficiency
rate(nothingdns_cache_hits_total[5m]) / rate(nothingdns_cache_queries_total[5m])

# Error rate
rate(nothingdns_errors_total[5m])

# Memory
nothingdns_memory_bytes / 1024 / 1024  # MB

# Goroutines
nothingdns_goroutines
```

### Latency Budget (10ms P99 target)

```
|- 1ms - Protocol parsing
|- 1ms - ACL/Rate limit checks
|- 1ms - Cache lookup
|- 2ms - Upstream query (local network)
|- 2ms - DNSSEC validation (if enabled)
|- 2ms - Response building
|- 1ms - Logging/Metrics
=10ms total
```

## 12. Scaling Strategies

### Vertical Scaling

Start here - maximize single-node performance:
1. Size cache appropriately
2. Tune worker pools
3. Enable all optimizations

### Horizontal Scaling

When vertical scaling is insufficient:
1. Deploy 3-node cluster
2. Use load balancer with health checks
3. Enable cache sync

### Anycast Scaling

For global deployment:
1. Deploy in multiple regions
2. Use GeoDNS for routing
3. Each region = independent cluster

## 13. Benchmarks

### Baseline Numbers (Single Node)

> These figures are illustrative and were not produced by a reproducible harness
> in this repository. The measured results (about 65,000 to 73,000 authoritative
> UDP QPS on a 12-core dev machine) are in [SPECIFICATION.md §14](SPECIFICATION.md).
> The DNSSEC and cluster tables below are likewise unverified estimates.

On `Intel i9-12900K, 32GB RAM, NVMe SSD`:

| Test | Result |
|------|--------|
| UDP queries/sec | 85,000 |
| TCP queries/sec | 25,000 |
| Cache hit ratio (steady state) | 94% |
| P99 latency (cached) | 0.8ms |
| P99 latency (upstream) | 5ms |
| Memory (50K cache) | 75 MB |
| Memory (500K cache) | 650 MB |

### DNSSEC Impact

| Scenario | QPS | P99 Latency |
|----------|-----|-------------|
| No DNSSEC | 85,000 | 0.8ms |
| Validation only | 60,000 | 1.5ms |
| Signing (RSA) | 40,000 | 2.5ms |
| Signing (ECDSA) | 75,000 | 1.2ms |

### Cluster Impact (3 nodes)

| Scenario | QPS | Latency |
|----------|-----|---------|
| Single node | 85,000 | 0.8ms |
| 3-node SWIM | 150,000 | 1.2ms |
| 3-node Raft | 90,000 | 2.5ms |

## 14. Performance Checklist

- [ ] Cache size set appropriately for workload
- [ ] TTLs tuned for hit ratio target
- [ ] Worker pool sized correctly
- [ ] Prefetch enabled for popular domains
- [ ] NSEC aggressive caching enabled
- [ ] DNSSEC using ECDSA or disabled if not needed
- [ ] TLS 1.3 only for DoT
- [ ] Kernel parameters tuned
- [ ] Metrics monitoring active
- [ ] Regular benchmarks run
