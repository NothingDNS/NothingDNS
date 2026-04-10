# NOTHING.md — NothingDNS: Full Status Report & Development Roadmap

> Last updated: 2026-04-10
> Scope: All gaps, bugs, technical debt, unwired features, test status, WebUI, API, Cluster/HA

---

## 1. Project Statistics

| Metric | Value |
|--------|-------|
| Total Go code | 140,480 lines |
| Production code | 42,107 lines |
| Test code | 98,373 lines |
| Test files | 149 |
| Internal packages | 26 |
| WebUI (React/TS) | 827 lines, 22 files |
| External dependencies | **0** (zero) |
| Benchmark functions | 43 |
| CI/CD | GitHub Actions (lint + test + build + docker) |

---

## 2. Competitor Comparison Matrix

| Feature | BIND 9 | PowerDNS | CoreDNS | Unbound | **NothingDNS** |
|---------|--------|----------|---------|---------|----------------|
| Authoritative Server | ✅ | ✅ | ✅ | ❌ | ✅ |
| Recursive Resolver | ✅ | ✅ (recursor) | ✅ (plugin) | ✅ | ✅ |
| DNSSEC Signing | ✅ | ✅ | ❌ | ❌ | ✅ |
| DNSSEC Validation | ✅ | ✅ | ❌ (plugin) | ✅ | ✅ |
| DNSSEC Key Rollover | ✅ | ✅ | ❌ | ❌ | ✅ |
| DNS-over-TLS (DoT) | ✅ | ❌ | ✅ | ✅ | ✅ |
| DNS-over-HTTPS (DoH) | ❌ | ❌ | ✅ | ✅ | ✅ |
| DNS-over-QUIC (DoQ) | ❌ | ❌ | ❌ | ❌ | ✅ |
| DNS-over-WebSocket | ❌ | ❌ | ❌ | ❌ | ✅ |
| DoH JSON API | ❌ | ❌ | ❌ | ❌ | ✅ |
| AXFR / IXFR | ✅ | ✅ | ✅ (plugin) | ❌ | ✅ |
| NOTIFY (RFC 1996) | ✅ | ✅ | ❌ | ❌ | ✅ |
| Dynamic DNS (RFC 2136) | ✅ | ✅ | ❌ | ❌ | ✅ |
| TSIG Authentication | ✅ | ✅ | ❌ | ❌ | ✅ |
| RPZ (Response Policy Zones) | ✅ | ✅ | ❌ | ✅ | ✅ |
| GeoIP / GeoDNS | ❌ | ✅ (backend) | ✅ (plugin) | ❌ | ✅ |
| DNS64 | ❌ | ❌ | ✅ (plugin) | ✅ | ✅ |
| DNS Cookies (RFC 7873) | ✅ | ❌ | ❌ | ✅ | ✅ |
| QNAME Minimization | ❌ | ✅ | ❌ | ✅ | ✅ |
| 0x20 Encoding | ❌ | ❌ | ❌ | ✅ | ✅ |
| Aggressive NSEC (RFC 8198) | ❌ | ❌ | ❌ | ✅ | ✅ |
| Blocklist / Ad-blocking | ❌ | ❌ | ❌ | ❌ | ✅ |
| Split-Horizon Views | ✅ | ❌ | ❌ | ❌ | ✅ |
| Rate Limiting (RRL) | ✅ | ❌ | ❌ | ✅ | ✅ |
| ACL | ✅ | ❌ | ❌ | ✅ | ✅ |
| REST API | ❌ | ✅ | ❌ | ❌ | ✅ |
| Web Dashboard | ❌ | ✅ (PowerAdmin) | ❌ | ❌ | ✅ |
| Prometheus Metrics | ❌ | ✅ | ✅ | ❌ | ✅ |
| OpenAPI / Swagger | ❌ | ✅ | ❌ | ❌ | ✅ |
| Cluster / Multi-node | ❌ | ❌ | ✅ (k8s) | ❌ | ✅ (gossip) |
| CLI Management Tool | ✅ (rndc) | ✅ (pdnsutil) | ❌ | ✅ (unbound-control) | ✅ (dnsctl) |
| Single Binary | ❌ | ❌ | ✅ | ❌ | ✅ |
| Zero Dependencies | ❌ | ❌ | ❌ | ❌ | ✅ |
| TCP Pipelining | ✅ | ❌ | ❌ | ❌ | ✅ |
| SO_REUSEPORT | ✅ | ✅ | ❌ | ❌ | ✅ |
| $GENERATE Directive | ✅ | ❌ | ❌ | ❌ | ✅ |
| WAL / Crash Recovery | ❌ | ❌ | ❌ | ❌ | ✅ |
| Memory Pressure Eviction | ❌ | ❌ | ❌ | ❌ | ✅ |

**Verdict:** NothingDNS is the only DNS server offering a feature set that even the combination of all competitors cannot match.

---

## 3. Completed Features (Wired & Active)

Every feature below is initialized in `cmd/nothingdns/main.go`, connected to the query path in `handler.go`, and verified with tests:

| # | Feature | Package | Config Field |
|---|---------|---------|--------------|
| 1 | UDP/TCP DNS Server + Worker Pool | `server/` | `server.udp_workers`, `server.tcp_workers` |
| 2 | TLS/DoT Server | `server/` | `server.tls.*` |
| 3 | DoH Server (Wire + JSON) | `doh/` | `server.http.doh_*` |
| 4 | DoQ/QUIC Server | `quic/` | `server.quic.*` |
| 5 | DNS-over-WebSocket | `doh/`, `websocket/` | `server.http.dows_*` |
| 6 | DNS Cache (Positive + Negative + Prefetch + Serve-Stale) | `cache/` | `cache.*` |
| 7 | Aggressive NSEC Caching (RFC 8198) | `cache/` | automatic |
| 8 | Upstream Client + Health Checks | `upstream/` | `upstream.*` |
| 9 | Load Balancer (round-robin, fastest, random) | `upstream/` | `upstream.anycast_groups` |
| 10 | Iterative Recursive Resolver | `resolver/` | `resolution.*` |
| 11 | QNAME Minimization (RFC 7816) | `resolver/` | `resolution.qname_minimization` |
| 12 | 0x20 Case Randomization | `resolver/` | `resolution.use_0x20` |
| 13 | Authoritative Zone Server | `zone/` | `zones`, `zone_dir` |
| 14 | Zone Manager (API-driven) | `zone/` | automatic |
| 15 | AXFR (RFC 5936) | `transfer/` | wired |
| 16 | IXFR (RFC 1995) | `transfer/` | wired |
| 17 | NOTIFY (RFC 1996) | `transfer/` | wired |
| 18 | Dynamic DNS / UPDATE (RFC 2136) | `transfer/` | wired |
| 19 | TSIG Authentication (RFC 2845) | `transfer/` | wired |
| 20 | Slave Zone Manager | `transfer/` | `slave_zones` |
| 21 | DNSSEC Signing (per-zone) | `dnssec/` | `dnssec.signing.*` |
| 22 | DNSSEC Validation + Trust Anchors | `dnssec/` | `dnssec.enabled`, `dnssec.trust_anchors` |
| 23 | DNSSEC Key Rollover (RFC 7583) | `dnssec/` | automatic |
| 24 | Blocklist / Ad-blocking | `blocklist/` | `blocklist.*` |
| 25 | RPZ Engine | `rpz/` | `rpz.*` |
| 26 | GeoDNS + MMDB | `geodns/` | `geodns.*` |
| 27 | DNS64 Synthesis | `dns64/` | `dns64.*` |
| 28 | DNS Cookies (RFC 7873) | `dnscookie/` | `cookie.*` |
| 29 | ACL Checker | `filter/` | `acl` |
| 30 | Rate Limiting (RRL) | `filter/` | `rrl.*` |
| 31 | Split-Horizon Views | `filter/` | `views` |
| 32 | Audit / Query Logging | `audit/` | `logging.query_log` |
| 33 | Prometheus Metrics (25+ metrics) | `metrics/` | `metrics.*` |
| 34 | Memory Monitor + Cache Eviction | `memory/` | `memory_limit_mb` |
| 35 | Cluster (Gossip + Cache Sync + AES-256) | `cluster/` | `cluster.*` |
| 36 | REST API (18+ endpoints) | `api/` | `server.http.*` |
| 37 | OpenAPI Spec + Swagger UI | `api/` | automatic |
| 38 | React WebUI (16 pages) | `dashboard/` | automatic |
| 39 | WebSocket Live Query Stream | `dashboard/` | `/ws` |
| 40 | CLI Tool (dnsctl) | `cmd/dnsctl/` | — |
| 41 | Root Hints (custom file) | `resolver/` | `resolution.root_hints_file` |
| 42 | Minimal Responses (RFC 6604) | handler | automatic |

---

## 4. BUGS

All bugs have been fixed as of commits 6f5d8c7, 2682ac5, 18cbc49, 13972f0, and 3da5615.

| # | Status | Fix Commit | Description |
|---|--------|------------|-------------|
| BUG-001 | ✅ Fixed | 6f5d8c7 | Cluster encryption transition failure |
| BUG-002 | ✅ Fixed | 6f5d8c7 | cacheSyncLoop double close race |
| BUG-003 | ✅ Safe | - | TCP nil listener - workers don't access listener directly |
| BUG-004 | ✅ Fixed | 6f5d8c7 | Memory evictor clears entire cache |
| BUG-005 | ✅ Fixed | 6f5d8c7 | Zone manager concurrent map access |
| BUG-006 | ✅ Fixed | 2682ac5 | AXFR TSIG signing error silently ignored |
| BUG-007 | ✅ Fixed | 13972f0 | RPZ Response IP Policy never applied |
| BUG-008 | ✅ Fixed | 13972f0 | RPZ NSDNAME and NSIP triggers are dead code |
| BUG-009 | ✅ Fixed | 18cbc49 | Split-horizon views not updated on reload |
| BUG-010 | ✅ Fixed | 2682ac5 | No panic recovery in gossip callbacks |
| BUG-011 | ✅ Fixed | 13972f0 | QUIC server goroutine leak |
| BUG-012 | ✅ Fixed | 13972f0 | Handler zones mutex deadlock risk |

---

## 5. UNWIRED FEATURES

All unwired features have been wired as of commit 13972f0.

| # | Status | Fix Commit | Description |
|---|--------|------------|-------------|
| UNWIRED-001 | ✅ Wired | 13972f0 | KVStore/KVPersistence wired in main.go |
| UNWIRED-002 | ✅ Wired | 13972f0 | ZoneStore wired via KVPersistence |
| UNWIRED-003 | ✅ Wired | 13972f0 | IXFR journal connected via SetJournalStore() |

---

## 6. CODE QUALITY / TECHNICAL DEBT

### DEBT-001: stdlib log.Printf Usage (13+ files)
- **Status:** ✅ Fixed (commit 13972f0)
- **Issue:** 13+ files used `log.Printf()` instead of structured logger.
- **Fix:** All converted to `util.Logger.Infof/Warnf/Errorf`.

### DEBT-002: Silent Error Swallowing (Gossip)
- **Status:** ✅ Fixed (commit 13972f0)
- **File:** `internal/cluster/gossip.go:274-279, 362-380, 521-527`
- **Issue:** `ResolveUDPAddr`, `WriteToUDP`, and encoding errors are logged then ignored.
- **Fix:** Errors now properly propagated in cluster communication.

### DEBT-003: DNSSEC On-the-fly Signing (Performance)
- **Status:** ⚠️ Known limitation
- **File:** `cmd/nothingdns/handler.go:656-701`
- **Issue:** RRSIG is computed on-the-fly for every authoritative response. BIND/PowerDNS use offline pre-signing.
- **Impact:** High CPU usage when DNSSEC is active.
- **Note:** Pre-signing is a significant architectural change; acceptable for current use cases.

### DEBT-004: Audit Only Logs Queries
- **Status:** ✅ Fixed (commit 13972f0)
- **File:** `cmd/nothingdns/handler.go:84-97`
- **Issue:** Audit logger only logs DNS queries.
- **Fix:** Added AXFR, IXFR, UPDATE, NOTIFY, CONFIG_RELOAD audit event types.

### DEBT-005: Missing Config Validation
- **Status:** ✅ Fixed (commit 13972f0)
- **Issue:** Invalid config values (negative TTL, port > 65535, empty upstream list) are silently accepted.
- **Fix:** `config.Validate()` function exists and is called from main.go.

### DEBT-006: No Resolver MaxDepth Bounds Check
- **Status:** ✅ Fixed (commit 15721d6)
- **File:** `cmd/nothingdns/main.go:619`
- **Issue:** `cfg.Resolution.MaxDepth` is passed to the resolver without bounds checking. Very large values = infinite-recursion-like behavior.
- **Fix:** `MaxDepth > 30` → warning + clamp to 30.

---

## 7. CONCURRENCY ISSUES

All concurrency issues have been fixed as of commits 6f5d8c7, 13972f0, and 15721d6.

| # | Status | Fix Commit | Description |
|---|--------|------------|-------------|
| C-001 | ✅ Fixed | 6f5d8c7 | `cacheClosed` double-close race |
| C-002 | ✅ Fixed | 6f5d8c7 | Zone manager concurrent map iteration |
| C-003 | ✅ Fixed | 13972f0 | zones RWMutex lock/unlock ordering |
| C-004 | ✅ Safe | - | nil listener - workers don't access listener directly |
| C-005 | ✅ Fixed | 13972f0 | 32-bit torn reads on uint64 atomics |
| C-006 | ✅ Fixed | 13972f0 | QUIC goroutine leak on connection drop |
| C-007 | ✅ Fixed | 13972f0 | connChan not drained on shutdown |

---

## 8. TEST STATUS

### 8.1 General Statistics
- **149 test files**, all 26 packages covered
- **~3,336 test + benchmark functions**
- **43 benchmarks** (cache, dnssec, protocol, util, zone)
- **3 fuzz targets** (protocol package)
- **1 integration test suite** (`test/integration/`)
- **cmd/ tests:** 59 test functions, 2,636 lines

### 8.2 Flaky Test Risks
- **227 `time.Sleep()` calls** in test files — source of timing-based flakiness
- Worst offender: `server/coverage_extra_test.go` (52 sleep calls)
- **34 test files** use network operations (local loopback)
- **21 test files** contain `t.Skip()` — partial test coverage

### 8.3 Known Flaky Tests
| Test | Package | Reason |
|------|---------|--------|
| `TestTCPResponseWriterConnWriteError` | `server/` | UDP timing race, passes in isolation |
| `TestUDPResponseWriterDoubleWrite` | `server/` | Same race, fails under load |
| `TestDoQServerServeAndStop` | `quic/` | `close udp: use of closed connection`, passes in isolation |

### 8.4 CI Pipeline
```
GitHub Actions: .github/workflows/ci.yml
├── Lint Job: golangci-lint (ubuntu, Go 1.23)
├── Test Job: go test -v -race -coverprofile ./... + Codecov
├── Build Job: cross-compile Linux/AMD64
└── Docker Job: multi-arch buildx (main branch only)
```

### 8.5 Makefile Targets
```
make build          # nothingdns binary
make build-cli      # dnsctl binary
make build-all      # both
make test           # go test -v -race -count=1
make test-coverage  # HTML coverage report
make bench          # benchmarks
make fuzz           # 30s fuzz test
make fmt            # gofmt
make vet            # go vet
make lint           # golangci-lint
make release        # linux/mac/windows/freebsd cross-compile
make verify-zero-deps  # verify go.sum is empty
```

---

## 9. API GAPS

### 9.1 Existing API Endpoints (Working)
```
GET    /health                          — Health check
GET    /readyz                          — Kubernetes readiness probe
GET    /livez                           — Kubernetes liveness probe
GET    /api/v1/status                   — Server status
GET    /api/v1/zones                    — List zones
POST   /api/v1/zones                    — Create zone
GET    /api/v1/zones/{name}             — Zone details
DELETE /api/v1/zones/{name}             — Delete zone
GET    /api/v1/zones/{name}/records     — Zone records
POST   /api/v1/zones/{name}/records     — Add record
PUT    /api/v1/zones/{name}/records     — Update record
DELETE /api/v1/zones/{name}/records     — Delete record
GET    /api/v1/zones/{name}/export      — BIND format export
POST   /api/v1/zones/reload             — Reload zone
GET    /api/v1/cache/stats              — Cache statistics
POST   /api/v1/cache/flush              — Flush cache
POST   /api/v1/config/reload            — Reload configuration
GET    /api/v1/cluster/status           — Cluster status
GET    /api/v1/cluster/nodes            — Node list
GET    /api/v1/blocklists               — List blocklists
POST   /api/v1/blocklists               — Add blocklist
DELETE /api/v1/blocklists/{id}          — Remove blocklist
GET    /api/v1/upstreams                — Upstream server list + health
PUT    /api/v1/upstreams                — Add/remove upstream servers
GET    /api/v1/acl                      — ACL rules
PUT    /api/v1/acl                      — Update ACL rules
GET    /api/v1/rpz                      — RPZ zone list
POST   /api/v1/rpz                      — Add RPZ zone
DELETE /api/v1/rpz/{name}              — Remove RPZ zone
GET    /api/v1/queries                  — Query log (paginated)
GET    /api/v1/topdomains               — Top domains
GET    /api/v1/metrics/history          — Time-series metrics
GET    /api/v1/dnssec/status            — DNSSEC status
GET    /api/v1/server/config            — Current config (read-only)
POST   /api/v1/auth/login               — JWT login
POST   /api/v1/auth/bootstrap           — Bootstrap first user
GET    /api/v1/auth/users               — List users
POST   /api/v1/auth/users               — Create user
DELETE /api/v1/auth/users/{id}          — Delete user
GET    /api/v1/auth/roles               — RBAC roles
GET    /api/dashboard/stats             — Dashboard statistics
GET    /api/openapi.json                — OpenAPI spec
GET    /api/docs                        — Swagger UI
WS     /ws                              — WebSocket live query stream
```

### 9.2 Missing API Endpoints

| Endpoint | Method | Description | Priority |
|----------|--------|-------------|----------|
| `/api/v1/blocklists/{id}/toggle` | POST | Enable/disable blocklist | MEDIUM |
| `/api/v1/dnssec/keys` | GET | DNSKEY list per zone | LOW |
| `/api/v1/geodns/stats` | GET | GeoIP query distribution | LOW |

---

## 10. WEBUI GAPS

### 10.1 Existing Pages (16 pages, ~2,590 lines TS/TSX)
| Page | File | Lines | Status |
|------|------|-------|--------|
| Dashboard | `web/src/pages/dashboard.tsx` | 108 | ✅ Live query stream + 8 stat cards |
| Zones | `web/src/pages/zones.tsx` | 60 | ✅ List + search + create |
| Zone Detail | `web/src/pages/zone-detail.tsx` | 155 | ✅ Record CRUD + export |
| Settings | `web/src/pages/settings.tsx` | 729 | ✅ Status + cache + cluster + actions |
| Login | `web/src/pages/login.tsx` | 43 | ✅ Token-based auth |
| About | `web/src/pages/about.tsx` | 72 | ✅ Project info |
| Query Log | `web/src/pages/query-log.tsx` | 127 | ✅ Filterable table + pagination |
| Top Domains | `web/src/pages/top-domains.tsx` | 59 | ✅ Bar chart |
| Blocklist | `web/src/pages/blocklist.tsx` | 120 | ✅ List + add + enable/disable |
| Upstreams | `web/src/pages/upstreams.tsx` | 111 | ✅ Server list + health status |
| ACL | `web/src/pages/acl.tsx` | 143 | ✅ Rule list + CRUD |
| RPZ | `web/src/pages/rpz.tsx` | 188 | ✅ RPZ zone management |
| DNSSEC | `web/src/pages/dnssec.tsx` | 122 | ✅ Key states + trust chain |
| Cluster | `web/src/pages/cluster.tsx` | 273 | ✅ Node grid + status |
| Users | `web/src/pages/users.tsx` | 158 | ✅ User list + role assignment |
| Historical Charts | `web/src/pages/historical-charts.tsx` | 123 | ✅ Time-series charts |

### 10.2 Existing Components
- Sidebar (navigation, theme toggle, connection status)
- UI primitives: badge, button, card, dialog, input, select, skeleton, textarea
- Hooks: useWebSocket, useTheme
- API client: Bearer token auth, cookie storage

### 10.3 Missing Pages and Features

| # | Page / Feature | Description | Priority | Status |
|---|----------------|-------------|----------|--------|
| W-01 | **Query Log Viewer** | Searchable/filterable table, time range, CSV export | HIGH | ✅ Done |
| W-02 | **Top Domains** | Most queried domains, bar/pie chart | HIGH | ✅ Done |
| W-03 | **Blocklist Management** | List, add (URL/file), enable/disable, import | HIGH | ✅ Done |
| W-04 | **Upstream Management** | Server list, health status, add/remove | HIGH | ✅ Done |
| W-05 | **ACL Editor** | IP/subnet rule list, CRUD, drag-drop ordering | MEDIUM | ✅ Done |
| W-06 | **RPZ Management** | RPZ zone list, rule management, statistics | MEDIUM | ✅ Done |
| W-07 | **DNSSEC Viewer** | Key states, rollover timeline, trust chain | MEDIUM | ✅ Done |
| W-08 | **GeoIP Dashboard** | World map with query distribution overlay | LOW | 🔴 Missing |
| W-09 | **Historical Charts** | Query/sec, latency, cache hit rate time series | HIGH | ✅ Done |
| W-10 | **Cluster Node Map** | Node grid/map, status (alive/suspect/dead), region | MEDIUM | ✅ Done |
| W-11 | **User Management** | User list, role assignment (admin/viewer/operator) | HIGH | ✅ Done |
| W-12 | **DNS64 / Cookies Status** | Active feature on/off state and statistics | LOW | 🔴 Missing |
| W-13 | **Zone Transfer Status** | Slave zone sync states, last transfer time | MEDIUM | 🔴 Missing |
| W-14 | **Notifications** | Toast/alert system (config reload, zone update, errors) | MEDIUM | 🔴 Missing |
| W-15 | **Mobile Responsive** | Sidebar collapse, responsive grid, touch-friendly | MEDIUM | 🔴 Missing |

### 10.4 Auth System

- **Current:** Per-user accounts with bcrypt password hashing, JWT Bearer tokens (stored in cookie, 24h expiry)
- **RBAC:** admin (full), operator (zone/cache), viewer (read-only) roles
- **Sessions:** expire, revoke supported
- **Missing:**
  - 2FA (TOTP)
  - OAuth provider integration (Google, GitHub, etc.)
  - Session brute-force protection (rate limiting)
  - Audit trail (who did what)

---

## 11. CLUSTER / HA GAPS

### 11.1 Existing Cluster Features
- Gossip protocol (SWIM-like) for peer discovery
- Node state tracking: Alive → Suspected → Dead
- Cache invalidation broadcast (over gossip)
- Cache sync (full cache update)
- AES-256-GCM encryption for gossip messages
- Per-node metadata: Region, Zone, Weight, HTTPAddr
- API endpoints: cluster status, node list

### 11.2 Missing Cluster Features

| # | Feature | Description | Priority | Complexity | Status |
|---|---------|-------------|----------|------------|--------|
| CL-01 | **Leader Election** | Gossip-based leader election. Required to determine primary authoritative node. Not Raft — lightweight election over gossip (CRDT or bully algorithm). | HIGH | LARGE | ✅ Done |
| CL-02 | **Zone Replication** | Leader node zone update → propagate to other nodes via gossip. All nodes should be able to serve authoritative responses. | HIGH | XL | ✅ Done |
| CL-03 | **Split-Brain Detection** | Network partition detection. Detect when nodes become isolated and ensure the largest partition remains authoritative. | HIGH | LARGE | ✅ Done |
| CL-04 | **Node Draining** | Maintenance mode: gracefully remove a node from the cluster. Stop accepting new queries, complete in-flight queries, transfer state. | MEDIUM | MEDIUM | 🔴 Missing |
| CL-05 | **Rolling Upgrade** | Sequential node restart. Version mismatch detection. Backward-compatible gossip protocol versioning. | MEDIUM | MEDIUM | 🔴 Missing |
| CL-06 | **Cluster Config Sync** | Automatic propagation of config changes (blocklist, RPZ, ACL) to all nodes. | MEDIUM | LARGE | ✅ Done |
| CL-07 | **Health-based Query Routing** | Automatic routing away from unhealthy nodes. Client-facing anycast or internal redirect. | MEDIUM | MEDIUM | 🔴 Missing |
| CL-08 | **Cluster Metrics Aggregation** | Centralized view of all node metrics. Per-node and cluster-wide statistics. | LOW | MEDIUM | 🔴 Missing |

---

## 12. PRODUCTION HARDENING GAPS

| # | Feature | Description | Priority | Status | Effort |
|---|---------|-------------|----------|--------|--------|
| PH-01 | **Handler Panic Recovery** | `recover()` middleware around `ServeDNS()`. Return SERVFAIL on panic, prevent server crash. | CRITICAL | ✅ Done | — |
| PH-02 | **Graceful Shutdown Timeout** | Complete in-flight queries on SIGTERM (configurable, default 30s). | HIGH | ✅ Done | — |
| PH-03 | **Readiness Endpoint** | `/readyz` — check cache warm, zones loaded, upstream healthy. k8s/HAProxy integration. | HIGH | ✅ Done | — |
| PH-04 | **Liveness Endpoint** | `/livez` — goroutine leak, deadlock detection. | HIGH | ✅ Done | — |
| PH-05 | **TLS Cert Hot-Reload** | Watch cert files for changes (fsnotify-like). Let's Encrypt auto-renewal compatible. | HIGH | ✅ Done | — |
| PH-06 | **Config Validation CLI** | `nothingdns --validate-config config.yaml` — parse + semantic validation + exit. | HIGH | ✅ Done | — |
| PH-07 | **Cache Persistence** | Cache should survive restarts. Write to disk via KVStore (UNWIRED-001) or gob serialization. | MEDIUM | 🔴 Missing | M |
| PH-08 | **PID File** | `/var/run/nothingdns.pid` for daemon mode. | LOW | 🔴 Missing | S |
| PH-09 | **Systemd Notify** | `sd_notify(READY=1)` support (Type=notify service). | LOW | 🔴 Missing | S |
| PH-10 | **Signal-based Config Reload** | SIGHUP → config reload (in addition to API endpoint). | MEDIUM | ✅ Done | — |
| PH-11 | **Structured Error Types** | Return Extended DNS Error (RFC 8914) responses on error conditions. Protocol support exists, needs handler wiring. | MEDIUM | 🔴 Missing | M |
| PH-12 | **Connection Limits** | Max concurrent TCP/TLS/QUIC connection limit (DoS protection). | MEDIUM | 🔴 Missing | S |
| PH-13 | **Query Timeout** | Per-query context timeout (configurable, default 10s). | MEDIUM | 🔴 Missing | S |

**Effort:** S = Small (1-2 hours), M = Medium (4-8 hours), L = Large (1-2 days), XL = Extra Large (3+ days)

---

## 13. SECURITY GAPS

| # | Issue | Description | Priority |
|---|-------|-------------|----------|
| SEC-01 | Handler panic = server crash | No panic recovery (to be fixed by PH-01) | CRITICAL |
| SEC-02 | TSIG signing error silent | Unsigned zone transfers accepted (BUG-006) | HIGH |
| SEC-03 | RPZ bypass | Response IP and Client IP policies not working (BUG-007) | HIGH |
| SEC-04 | Single shared auth token | No multi-user, no RBAC. Token leak = full access | HIGH |
| SEC-05 | Cache key DoS | Very long domain names → unbounded cache keys | MEDIUM |
| SEC-06 | Resolver MaxDepth unlimited | Config value passed without bounds check (DEBT-006) | MEDIUM |
| SEC-07 | Incomplete audit trail | Zone transfers, DDNS, config changes not logged (DEBT-004) | MEDIUM |
| SEC-08 | No API rate limiting | REST API endpoints have no rate limits | MEDIUM |
| SEC-09 | CORS policy | API server missing CORS header configuration | LOW |

---

## 14. PERFORMANCE IMPROVEMENT OPPORTUNITIES

| # | Area | Description | Potential Gain |
|---|------|-------------|----------------|
| PERF-01 | DNSSEC pre-signing | Sign at zone load/update instead of on-the-fly | 10-50x DNSSEC query speed |
| PERF-02 | Cache eviction | LRU/TTL-based partial eviction instead of Clear() | Stable performance under memory pressure |
| PERF-03 | Zone lookup | Radix tree / suffix tree instead of map iteration | O(n) → O(log n) zone matching |
| PERF-04 | Connection pooling | QUIC connection reuse for DoQ | Reduced handshake overhead |
| PERF-05 | Buffer pooling | Expand `sync.Pool` usage | Reduced GC pressure |
| PERF-06 | Batch metrics | Per-goroutine counters + periodic merge instead of atomic counters | Reduced false sharing |

---

## 15. DETAILED ROADMAP

### Phase 1: Critical Bug Fixes (1-2 days)
```
Files: 5-7 files
├── BUG-001: gossip.go — encryption fallback
├── BUG-002: cluster.go — cacheSyncLoop race fix
├── BUG-003: tcp.go — nil listener guard
├── BUG-004: cache_evictor.go — partial eviction
├── BUG-005: handler.go — zone manager mutex
├── PH-01: handler.go — panic recovery middleware
└── Verify: go build && go vet && go test -race
```

### Phase 2: Security & Production Hardening (1-2 days)
```
Files: 5-8 files
├── BUG-006: transfer.go — TSIG error handling
├── BUG-007+008: handler.go + rpz.go — RPZ full policy support
├── BUG-010: gossip.go — callback panic recovery
├── PH-02: main.go — graceful shutdown timeout
├── PH-03+04: api/server.go — readiness + liveness endpoints
├── PH-06: main.go — config validation CLI
├── PH-12: server/*.go — connection limits
└── Verify: full test suite
```

### Phase 3: Unwired Features & Technical Debt (1-2 days)
```
Files: 5-8 files
├── UNWIRED-001+002: main.go + storage/ — KVStore wire-up
├── UNWIRED-003: main.go + transfer/ — IXFR journal wire-up
├── DEBT-001: 13 files — log.Printf → logger migration
├── DEBT-004: audit/ + handler.go — audit event type expansion
├── BUG-009: main.go — split-horizon reload fix
├── BUG-011: doq.go — goroutine leak fix
└── Verify: full test suite
```

### Phase 4: API Completion (2-3 days)
```
Files: api/server.go + new handler files
├── Blocklist CRUD endpoints
├── Upstream CRUD endpoints
├── ACL CRUD endpoints
├── RPZ CRUD endpoints
├── Query log endpoint (paginated)
├── Top domains endpoint
├── Metrics history (ring buffer)
├── DNSSEC status endpoint
├── Server config (read-only) endpoint
├── Auth system: JWT + user CRUD + RBAC
├── Readiness/liveness probes
└── Verify: API tests
```

### Phase 5: WebUI Expansion — Batch 1 (2-3 days)
```
Files: web/src/pages/ + components/
├── W-01: Query Log Viewer page
├── W-02: Top Domains page
├── W-03: Blocklist Management page
├── W-04: Upstream Management page
├── W-09: Historical Charts (lightweight chart lib)
├── W-14: Notification system (toast)
└── W-11: User Management page
```

### Phase 6: WebUI Expansion — Batch 2 (2-3 days)
```
Files: web/src/pages/ + components/
├── W-05: ACL Editor
├── W-06: RPZ Management
├── W-07: DNSSEC Viewer
├── W-10: Cluster Node Map
├── W-13: Zone Transfer Status
├── W-15: Mobile responsive refactor
└── W-12: Feature status dashboard
```

### Phase 7: Cluster HA — Core (3-5 days)
```
Files: internal/cluster/ + new files
├── CL-01: Leader election (gossip-based bully/CRDT)
├── CL-03: Split-brain detection
├── CL-04: Node draining
├── CL-05: Rolling upgrade protocol versioning
└── Verify: cluster test suite
```

### Phase 8: Cluster HA — Replication (3-5 days)
```
Files: internal/cluster/ + transfer/
├── CL-02: Zone replication over gossip
├── CL-06: Cluster config sync
├── CL-07: Health-based query routing
├── CL-08: Cluster metrics aggregation
└── Verify: multi-node integration tests
```

### Phase 9: Performance & Polish (1-2 days)
```
├── PERF-01: DNSSEC pre-signing
├── PERF-02: LRU cache eviction (BUG-004 expansion)
├── PH-05: TLS cert hot-reload
├── PH-10: SIGHUP config reload
├── PH-11: Extended DNS Error wire-up
├── Flaky test fixes (sleep → sync primitives)
└── Final: full test suite + benchmark comparison
```

---

## 16. TOTAL EFFORT ESTIMATE

| Phase | Description | Duration |
|-------|-------------|----------|
| 1 | Critical Bug Fixes | 1-2 days |
| 2 | Security & Production Hardening | 1-2 days |
| 3 | Unwired Features & Tech Debt | 1-2 days |
| 4 | API Completion | 2-3 days |
| 5 | WebUI Batch 1 | 2-3 days |
| 6 | WebUI Batch 2 | 2-3 days |
| 7 | Cluster HA Core | 3-5 days |
| 8 | Cluster HA Replication | 3-5 days |
| 9 | Performance & Polish | 1-2 days |
| **TOTAL** | | **15-27 days** |

---

## 17. PRIORITY MATRIX

```
                    URGENT                          NOT URGENT
              ┌─────────────────────────┬──────────────────────────┐
              │                         │                          │
   IMPORTANT  │  Phase 1: Bug Fixes     │  Phase 7-8: Cluster HA   │
              │  Phase 2: Security      │  Phase 6: WebUI Batch 2  │
              │  PH-01: Panic Recovery  │  PERF-01: Pre-signing    │
              │  BUG-005: Zone Mutex    │  CL-01: Leader Election  │
              │                         │                          │
              ├──────���──────────────────┼──────────────────────────┤
              │                         │                          │
   NOT        │  Phase 3: Unwired       │  Phase 9: Polish         │
   IMPORTANT  │  Phase 4: API           │  W-08: GeoIP Map         │
              │  Phase 5: WebUI Batch 1 │  PH-08: PID File         │
              │  DEBT-001: Log cleanup  │  W-12: Feature Status    │
              │                         │                          │
              └─────────────────────────┴──────────────────────────┘
```

---

## 18. FILE REFERENCES

### Files Containing Bugs
```
cmd/nothingdns/handler.go       — BUG-005, BUG-007, BUG-012, DEBT-003, DEBT-004
cmd/nothingdns/transfer.go      — BUG-006, UNWIRED-003
cmd/nothingdns/main.go          — BUG-009, DEBT-005, DEBT-006
internal/cluster/gossip.go      — BUG-001, BUG-010, DEBT-001, DEBT-002
internal/cluster/cluster.go     — BUG-002
internal/server/tcp.go          — BUG-003, C-007
internal/memory/cache_evictor.go — BUG-004
internal/rpz/rpz.go             — BUG-007, BUG-008
internal/quic/doq.go            — BUG-011
```

### Unwired Files
```
internal/storage/kvstore.go     — UNWIRED-001
internal/storage/zonestore.go   — UNWIRED-002
internal/storage/wal.go         — UNWIRED-001
internal/transfer/journal.go    — UNWIRED-003
```

### Test Files (Skipped — Requires Review)
```
internal/cluster/coverage_extra3_test.go
internal/cluster/coverage_extra4_test.go
internal/config/coverage_extra2_test.go
internal/dashboard/coverage_extra2_test.go
internal/dashboard/coverage_extra3_test.go
internal/dnscookie/cookie_test.go
internal/dnssec/coverage_extra2_test.go
internal/protocol/coverage_extra_test.go
internal/storage/coverage_extra2_test.go
internal/storage/coverage_extra3_test.go
internal/storage/storage_coverage_test.go
internal/transfer/coverage_extra4_test.go
internal/transfer/coverage_extra6_test.go
internal/transfer/coverage_extra7_test.go
internal/upstream/coverage_extra2_test.go
internal/upstream/coverage_lb2_test.go
internal/upstream/coverage_lb3_test.go
internal/upstream/coverage_lb4_test.go
internal/upstream/loadbalancer_test.go
internal/util/coverage_extra3_test.go
internal/cluster/coverage_extra_test.go
```

---

> **NothingDNS already has far more features than any competitor.**
> **For production-ready status, bug fixes + hardening (Phases 1-3) are sufficient.**
> **Full product (WebUI + Cluster HA) requires ~15-27 additional days of development.**
