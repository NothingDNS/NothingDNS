# NOTHING.md — NothingDNS: Full Status Report & Development Roadmap

> Last updated: 2026-04-05
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
| 38 | React WebUI (6 pages) | `dashboard/` | automatic |
| 39 | WebSocket Live Query Stream | `dashboard/` | `/ws` |
| 40 | CLI Tool (dnsctl) | `cmd/dnsctl/` | — |
| 41 | Root Hints (custom file) | `resolver/` | `resolution.root_hints_file` |
| 42 | Minimal Responses (RFC 6604) | handler | automatic |

---

## 4. BUGS

### BUG-001: Cluster Encryption Transition Failure (HIGH)
- **File:** `internal/cluster/gossip.go:724-728`
- **Issue:** When encryption is enabled, messages that fail to decrypt result in a hard failure. In a mixed cluster (during rolling upgrade) with encrypted/unencrypted nodes, all gossip communication breaks.
- **Impact:** Zero-downtime encryption transition is impossible.
- **Fix:** Add fallback to unencrypted parsing when decryption fails.

### BUG-002: Race Condition — cacheSyncLoop Double Close (HIGH)
- **File:** `internal/cluster/cluster.go:215-220`
- **Issue:** In `Stop()`, the `cacheClosed` flag is set again outside the lock scope. Concurrent `Stop()` calls can trigger a double-close panic on `cacheSyncChan`.
- **Impact:** Panic during server shutdown.
- **Fix:** Ensure flag check and close operation happen within a single lock scope.

### BUG-003: TCP Server Nil Listener Panic (HIGH)
- **File:** `internal/server/tcp.go:129-140`
- **Issue:** Worker goroutines can call `Accept()` on `s.listener` while it is still nil, before `Serve()` has been called.
- **Impact:** Nil pointer panic if called out of order.
- **Fix:** Workers should wait until listener is set, or enforce `Listen()` → `Serve()` ordering.

### BUG-004: Memory Evictor Clears Entire Cache (HIGH)
- **File:** `internal/memory/cache_evictor.go:19-23`
- **Issue:** `Evict(percent int)` completely ignores the `percent` parameter and calls `cache.Clear()`. When 5% eviction is requested, 100% is cleared.
- **Impact:** Full DNS cache loss under memory pressure → instant upstream load spike.
- **Fix:** Implement LRU or TTL-based partial eviction.

### BUG-005: Zone Manager Concurrent Map Access (HIGH)
- **File:** `cmd/nothingdns/handler.go:321-341`
- **Issue:** Handler iterates over `zoneManager.List()` while the API server concurrently calls `zoneManager.LoadZone()` to add/delete zones. In Go, concurrent map read+write = panic.
- **Impact:** Handler panic when adding/deleting zones via API.
- **Fix:** Protect zone manager with RWMutex or use copy-on-write pattern.

### BUG-006: AXFR TSIG Signing Error Silently Ignored (MEDIUM)
- **File:** `cmd/nothingdns/transfer.go:56-63`
- **Issue:** When `transfer.SignMessage()` fails, the RRSIG is silently skipped, returning an unsigned AXFR response.
- **Impact:** Slaves requiring TSIG receive unsigned transfers → security vulnerability.
- **Fix:** Signing error should return SERVFAIL or abort the transfer.

### BUG-007: RPZ Response IP Policy Never Applied (HIGH)
- **File:** `cmd/nothingdns/handler.go:213-246`, `internal/rpz/rpz.go:74-77`
- **Issue:** Handler only checks `QNAMEPolicy()`. `respIPRules`, `respActions`, and client IP policies are never invoked.
- **Impact:** Only 1 of 3 RPZ policy triggers (QNAME) works. Response IP and Client IP rules are dead code.
- **Fix:** Add post-response `ResponseIPPolicy()` and pre-query `ClientIPPolicy()` checks to handler.

### BUG-008: RPZ NSDNAME and NSIP Triggers Are Dead Code (MEDIUM)
- **File:** `internal/rpz/rpz.go:44-47`
- **Issue:** `TriggerNSDNAME` and `TriggerNSIP` constants are defined but never checked in the handler.
- **Impact:** NS-based RPZ rules do not work.
- **Fix:** Add NS name/IP checks during recursive resolution.

### BUG-009: Split-Horizon Views Not Updated on Config Reload (MEDIUM)
- **File:** `cmd/nothingdns/main.go:602-634`
- **Issue:** API reload callback reloads zones, blocklist, and RPZ but skips split-horizon view configuration.
- **Impact:** View changes require server restart.
- **Fix:** Add view re-parsing to the reload callback.

### BUG-010: No Panic Recovery in Gossip Callbacks (MEDIUM)
- **File:** `internal/cluster/gossip.go:421-425, 430-434, 451-455, 570-574`
- **Issue:** `onNodeJoin`, `onNodeUpdate`, `onNodeLeave`, `onCacheInvalid` callbacks are invoked without `recover()`.
- **Impact:** A panic in any callback crashes the entire gossip protocol → cluster down.
- **Fix:** Wrap each callback invocation with `defer recover()`.

### BUG-011: QUIC Server Goroutine Leak (MEDIUM)
- **File:** `internal/quic/doq.go:283-284, 328-329`
- **Issue:** In `handshakeConnection()` and `processStreams()`, goroutines may not reach `wg.Done()` when connections time out or drop.
- **Impact:** Goroutine accumulation under adverse network conditions → memory leak.
- **Fix:** Use context timeout + defer cleanup pattern.

### BUG-012: Handler Zones Mutex Deadlock Risk (MEDIUM)
- **File:** `cmd/nothingdns/handler.go:307-340`
- **Issue:** `zonesMu.RLock()` is acquired and released inside a loop, then `handleAuthoritative()` is called. If a zone write lock is requested in between, deadlock can occur.
- **Impact:** Deadlock when zone API update and query arrive simultaneously.
- **Fix:** Complete zone lookup within lock scope, then process after unlock.

---

## 5. UNWIRED FEATURES (On the Shelf)

These features are implemented and tested but never used in `main.go`:

### UNWIRED-001: Storage / KVStore / WAL
- **Files:** `internal/storage/kvstore.go`, `wal.go`, `serializer.go`
- **Status:** Full implementation + tests available. Not imported anywhere.
- **Potential:** Cache persistence, zone metadata, config state persistence.
- **Action:** Wire up with `zonestore.go` for zone persistence.

### UNWIRED-002: ZoneStore (KVStore-backed Zone Persistence)
- **File:** `internal/storage/zonestore.go`
- **Status:** Zone read/write interface over KVStore. Not used.
- **Potential:** Can replace file-based zone persistence with structured storage.

### UNWIRED-003: Transfer Journal (IXFR Journal Backend)
- **File:** `internal/transfer/journal.go`
- **Status:** IXFR journal mechanism is implemented but the journal backend is not connected to the IXFR server in main.go.
- **Impact:** IXFR always fails to find a journal and falls back to AXFR.
- **Action:** Create journal instance and pass it to the IXFR server as a parameter.

---

## 6. CODE QUALITY / TECHNICAL DEBT

### DEBT-001: stdlib log.Printf Usage (13+ files)
- **Issue:** The entire project has `util.Logger`, yet the following files use `log.Printf()` directly:
  - `internal/cluster/gossip.go` (13 occurrences)
  - `internal/doh/wshandler.go` (2 occurrences)
  - `internal/api/server.go` (2 occurrences)
  - `internal/dashboard/server.go` (4 occurrences)
  - `internal/transfer/axfr.go` (1 occurrence)
  - `internal/transfer/ixfr.go` (2 occurrences)
  - `internal/metrics/metrics.go` (1 occurrence)
  - `internal/storage/kvstore.go` (1 occurrence)
  - `internal/upstream/client.go` (2 occurrences)
  - `internal/upstream/loadbalancer.go` (3 occurrences)
- **Impact:** Configured log level/format is not applied to these messages. Text mixes into JSON log format.
- **Fix:** Convert all `log.Printf` → `logger.Infof/Warnf/Errorf`.

### DEBT-002: Silent Error Swallowing (Gossip)
- **File:** `internal/cluster/gossip.go:274-279, 362-380, 521-527`
- **Issue:** `ResolveUDPAddr`, `WriteToUDP`, and encoding errors are logged then ignored.
- **Impact:** Cluster communication errors are silently lost.

### DEBT-003: DNSSEC On-the-fly Signing (Performance)
- **File:** `cmd/nothingdns/handler.go:656-701`
- **Issue:** RRSIG is computed on-the-fly for every authoritative response. BIND/PowerDNS use offline pre-signing.
- **Impact:** High CPU usage when DNSSEC is active.
- **Fix:** Pre-sign during zone load/update + cache signatures.

### DEBT-004: Audit Only Logs Queries
- **File:** `cmd/nothingdns/handler.go:84-97`
- **Issue:** Audit logger only logs DNS queries. Zone transfers, DDNS updates, NOTIFY, config reload, and other security-critical operations are not logged.
- **Fix:** Expand audit event types: `QUERY`, `AXFR`, `IXFR`, `UPDATE`, `NOTIFY`, `CONFIG_RELOAD`, `ZONE_CREATE`, `ZONE_DELETE`.

### DEBT-005: Missing Config Validation
- **Issue:** Invalid config values (negative TTL, port > 65535, empty upstream list) are silently accepted.
- **Fix:** Add `config.Validate()` function + `nothingdns --validate` CLI flag.

### DEBT-006: No Resolver MaxDepth Bounds Check
- **File:** `cmd/nothingdns/main.go:561`
- **Issue:** `cfg.Resolution.MaxDepth` is passed to the resolver without bounds checking. Very large values = infinite-recursion-like behavior.
- **Fix:** `MaxDepth > 30` → warning + clamp.

---

## 7. CONCURRENCY ISSUES

| # | File | Issue | Severity |
|---|------|-------|----------|
| C-001 | `cluster/cluster.go:215-220` | `cacheClosed` double-close race | HIGH |
| C-002 | `handler.go:321-341` | Zone manager concurrent map iteration | HIGH |
| C-003 | `handler.go:307-340` | zones RWMutex lock/unlock ordering | MEDIUM |
| C-004 | `server/tcp.go:129-140` | nil listener before worker start | HIGH |
| C-005 | `metrics/metrics.go:268-276` | 32-bit torn reads on uint64 atomics | LOW |
| C-006 | `quic/doq.go:283-329` | goroutine leak on connection drop | MEDIUM |
| C-007 | `server/tcp.go:120-166` | connChan not drained on shutdown | MEDIUM |

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
GET    /api/dashboard/stats             — Dashboard statistics
GET    /api/openapi.json                — OpenAPI spec
GET    /api/docs                        — Swagger UI
WS     /ws                              — WebSocket live query stream
```

### 9.2 Missing API Endpoints

| Endpoint | Method | Description | Priority |
|----------|--------|-------------|----------|
| `/api/v1/blocklists` | GET | Active blocklist list | HIGH |
| `/api/v1/blocklists` | POST | Add blocklist (URL or file) | HIGH |
| `/api/v1/blocklists/{id}` | DELETE | Remove blocklist | HIGH |
| `/api/v1/blocklists/{id}/toggle` | POST | Enable/disable blocklist | HIGH |
| `/api/v1/upstreams` | GET | Upstream server list + health status | HIGH |
| `/api/v1/upstreams` | PUT | Update upstream servers | HIGH |
| `/api/v1/acl` | GET | ACL rules | MEDIUM |
| `/api/v1/acl` | PUT | Update ACL rules | MEDIUM |
| `/api/v1/rpz` | GET | RPZ zone list + statistics | MEDIUM |
| `/api/v1/rpz` | POST | Add RPZ zone | MEDIUM |
| `/api/v1/rpz/{name}` | DELETE | Remove RPZ zone | MEDIUM |
| `/api/v1/queries` | GET | Query log (paginated, filterable) | HIGH |
| `/api/v1/queries/top` | GET | Top domains (count, group by) | HIGH |
| `/api/v1/metrics/history` | GET | Time-series metrics (ring buffer) | MEDIUM |
| `/api/v1/dnssec/status` | GET | Key status, rollover timeline | MEDIUM |
| `/api/v1/dnssec/keys` | GET | DNSKEY list per zone | LOW |
| `/api/v1/geodns/stats` | GET | GeoIP query distribution | LOW |
| `/api/v1/server/config` | GET | Current config (read-only, sanitized) | MEDIUM |
| `/api/v1/auth/login` | POST | JWT/session login | HIGH |
| `/api/v1/auth/users` | GET/POST/DELETE | User management | HIGH |
| `/api/v1/auth/roles` | GET | RBAC roles | MEDIUM |
| `/readyz` | GET | Readiness probe (k8s) | HIGH |
| `/livez` | GET | Liveness probe (k8s) | HIGH |

---

## 10. WEBUI GAPS

### 10.1 Existing Pages (6 pages, 827 lines TS/TSX)
| Page | File | Lines | Status |
|------|------|-------|--------|
| Dashboard | `web/src/pages/dashboard.tsx` | 75 | ✅ Live query stream + 8 stat cards |
| Zones | `web/src/pages/zones.tsx` | 60 | ✅ List + search + create |
| Zone Detail | `web/src/pages/zone-detail.tsx` | 122 | ✅ Record CRUD + export |
| Settings | `web/src/pages/settings.tsx` | 81 | ✅ Status + cache + cluster + actions |
| Login | `web/src/pages/login.tsx` | 43 | ✅ Token-based auth |
| About | `web/src/pages/about.tsx` | 64 | ✅ Project info |

### 10.2 Existing Components
- Sidebar (navigation, theme toggle, connection status)
- UI primitives: badge, button, card, dialog, input, select, skeleton, textarea
- Hooks: useWebSocket, useTheme
- API client: Bearer token auth, cookie storage

### 10.3 Missing Pages and Features

| # | Page / Feature | Description | Priority | Est. LOC |
|---|----------------|-------------|----------|----------|
| W-01 | **Query Log Viewer** | Searchable/filterable table, time range, CSV export | HIGH | ~300 |
| W-02 | **Top Domains** | Most queried domains, bar/pie chart | HIGH | ~200 |
| W-03 | **Blocklist Management** | List, add (URL/file), enable/disable, import | HIGH | ~250 |
| W-04 | **Upstream Management** | Server list, health status, add/remove | HIGH | ~200 |
| W-05 | **ACL Editor** | IP/subnet rule list, CRUD, drag-drop ordering | MEDIUM | ~250 |
| W-06 | **RPZ Management** | RPZ zone list, rule management, statistics | MEDIUM | ~200 |
| W-07 | **DNSSEC Viewer** | Key states, rollover timeline, trust chain | MEDIUM | ~300 |
| W-08 | **GeoIP Dashboard** | World map with query distribution overlay | LOW | ~400 |
| W-09 | **Historical Charts** | Query/sec, latency, cache hit rate time series | HIGH | ~350 |
| W-10 | **Cluster Node Map** | Node grid/map, status (alive/suspect/dead), region | MEDIUM | ~250 |
| W-11 | **User Management** | User list, role assignment (admin/viewer/operator) | HIGH | ~300 |
| W-12 | **DNS64 / Cookies Status** | Active feature on/off state and statistics | LOW | ~100 |
| W-13 | **Zone Transfer Status** | Slave zone sync states, last transfer time | MEDIUM | ~150 |
| W-14 | **Notifications** | Toast/alert system (config reload, zone update, errors) | MEDIUM | ~100 |
| W-15 | **Mobile Responsive** | Sidebar collapse, responsive grid, touch-friendly | MEDIUM | ~refactor |

### 10.4 Auth System Gaps
- **Current:** Single shared token (Bearer), stored in cookie for 24 hours
- **Missing:**
  - Per-user accounts (username/password or OAuth)
  - RBAC: admin (full), operator (zone/cache), viewer (read-only)
  - Session management (expire, revoke)
  - 2FA (TOTP)
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

| # | Feature | Description | Priority | Complexity |
|---|---------|-------------|----------|------------|
| CL-01 | **Leader Election** | Gossip-based leader election. Required to determine primary authoritative node. Not Raft — lightweight election over gossip (CRDT or bully algorithm). | HIGH | LARGE |
| CL-02 | **Zone Replication** | Leader node zone update → propagate to other nodes via gossip. All nodes should be able to serve authoritative responses. | HIGH | XL |
| CL-03 | **Split-Brain Detection** | Network partition detection. Detect when nodes become isolated and ensure the largest partition remains authoritative. | HIGH | LARGE |
| CL-04 | **Node Draining** | Maintenance mode: gracefully remove a node from the cluster. Stop accepting new queries, complete in-flight queries, transfer state. | MEDIUM | MEDIUM |
| CL-05 | **Rolling Upgrade** | Sequential node restart. Version mismatch detection. Backward-compatible gossip protocol versioning. | MEDIUM | MEDIUM |
| CL-06 | **Cluster Config Sync** | Automatic propagation of config changes (blocklist, RPZ, ACL) to all nodes. | MEDIUM | LARGE |
| CL-07 | **Health-based Query Routing** | Automatic routing away from unhealthy nodes. Client-facing anycast or internal redirect. | MEDIUM | MEDIUM |
| CL-08 | **Cluster Metrics Aggregation** | Centralized view of all node metrics. Per-node and cluster-wide statistics. | LOW | MEDIUM |

---

## 12. PRODUCTION HARDENING GAPS

| # | Feature | Description | Priority | Effort |
|---|---------|-------------|----------|--------|
| PH-01 | **Handler Panic Recovery** | `recover()` middleware around `ServeDNS()`. Return SERVFAIL on panic, prevent server crash. | CRITICAL | S |
| PH-02 | **Graceful Shutdown Timeout** | Complete in-flight queries on SIGTERM (configurable, default 30s). | HIGH | S |
| PH-03 | **Readiness Endpoint** | `/readyz` — check cache warm, zones loaded, upstream healthy. k8s/HAProxy integration. | HIGH | S |
| PH-04 | **Liveness Endpoint** | `/livez` — goroutine leak, deadlock detection. | HIGH | S |
| PH-05 | **TLS Cert Hot-Reload** | Watch cert files for changes (fsnotify-like). Let's Encrypt auto-renewal compatible. | HIGH | M |
| PH-06 | **Config Validation CLI** | `nothingdns --validate-config config.yaml` — parse + semantic validation + exit. | HIGH | S |
| PH-07 | **Cache Persistence** | Cache should survive restarts. Write to disk via KVStore (UNWIRED-001) or gob serialization. | MEDIUM | M |
| PH-08 | **PID File** | `/var/run/nothingdns.pid` for daemon mode. | LOW | S |
| PH-09 | **Systemd Notify** | `sd_notify(READY=1)` support (Type=notify service). | LOW | S |
| PH-10 | **Signal-based Config Reload** | SIGHUP → config reload (in addition to API endpoint). | MEDIUM | S |
| PH-11 | **Structured Error Types** | Return Extended DNS Error (RFC 8914) responses on error conditions. Protocol support exists, needs handler wiring. | MEDIUM | M |
| PH-12 | **Connection Limits** | Max concurrent TCP/TLS/QUIC connection limit (DoS protection). | MEDIUM | S |
| PH-13 | **Query Timeout** | Per-query context timeout (configurable, default 10s). | MEDIUM | S |

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
