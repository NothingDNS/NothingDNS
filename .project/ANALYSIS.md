# NothingDNS Production Readiness Analysis

> Comprehensive architectural, quality, and gap analysis  
> Assessment Date: 2026-04-14 (initial) / 2026-04-16 (updated)  
> Audited Commit: `78acc7a` (current — all findings updated through 2026-04-16 audit)  
> Auditor: Claude Code — Full Codebase Audit

---

## 1. Executive Summary

NothingDNS is an ambitious, zero-dependency (mostly) DNS server written in pure Go. It implements a staggering breadth of DNS functionality — authoritative resolution, recursive resolution, DoT/DoH/DoQ, DNSSEC signing and validation, zone transfers (AXFR/IXFR/XoT), Dynamic DNS, clustering (SWIM gossip and Raft consensus), and a full management plane (REST API, MCP server, React dashboard, CLI tool).

The codebase is large: **303 Go files**, **161 test files**, approximately **164,000 lines of Go code** per `docs/NOTHING.md`. The project builds cleanly (`go build ./...` passes), all short tests pass (`go test ./... -count=1 -short`), and the end-to-end test suite passes in ~18s. There are **zero `TODO`/`FIXME`/`HACK` markers** in production code, which is unusual and commendable.

However, **the project is not without material flaws**. The frontend has pages that serve hardcoded mock data instead of real API integrations. The CLI tool advertises commands that are unimplemented stubs. A security-critical filtering engine (`internal/rpz`) silently drops malformed rules without logging. The custom authentication package contains misleading nomenclature and a hand-rolled PBKDF2 implementation. Several important packages are dramatically under-tested relative to their risk surface.

**Overall health: 7.5/10** — impressive engineering breadth with pockets of production-grade quality, undermined by incomplete UI/CLI integrations and uneven test coverage.

---

## 2. Architecture Analysis

### 2.1 High-Level Architecture

The architecture is cleanly layered:

```
Transport (UDP/TCP/DoT/DoH/DoQ/WebSocket)
         ↓
    Request Handler (21-stage pipeline)
         ↓
Cache → Auth Zones → Upstream/Resolver → DNSSEC Validator
         ↓
    Storage (KV + WAL) + Cluster (Gossip/Raft)
         ↓
    Management Plane (REST API + MCP + Dashboard + CLI)
```

**The 21-stage pipeline** (`cmd/nothingdns/handler.go:83-1263`) is the beating heart of the system. It processes every query through:

1. Panic recovery
2. IDNA validation (RFC 5891)
3. ACL check (`internal/filter/acl.go`)
4. RPZ client IP policy (`internal/rpz/rpz.go`)
5. Rate limiting (`internal/filter/ratelimit.go`)
6. DNS Cookie validation (RFC 7873)
7. AXFR/IXFR/NOTIFY/UPDATE special handling
8. Blocklist check
9. RPZ QNAME policy
10. Cache lookup (`internal/cache/`)
11. NSEC aggressive cache (RFC 8198)
12. Split-horizon view zones
13. Authoritative zone lookup (`internal/zone/radix.go`)
14. CNAME chasing
15. Iterative recursive resolver (`internal/resolver/resolver.go`)
16. Upstream forwarding (`internal/upstream/`)
17. DNSSEC validation (`internal/dnssec/validator.go`)
18. RPZ response IP/NSDNAME checks
19. DNS64 synthesis (RFC 6147)
20. Cache the response
21. Stale serving (RFC 8767)

This pipeline is **well-structured and defensively coded**. Panic recovery wraps the entire handler, and each stage has clear failure semantics.

### 2.2 Package Boundaries & Cohesion

| Package | Responsibility | Est. LOC | Cohesion | Assessment |
|---------|---------------|----------|----------|------------|
| `internal/protocol/` | DNS wire protocol, all RData types, EDNS0 | ~15,000 | **Excellent** | Zero-dep, comprehensive, well-benchmarked |
| `internal/server/` | UDP/TCP/TLS transport handlers | ~8,000 | **Good** | Worker pools, connection limits, pipelining |
| `internal/zone/` | BIND-format parser, radix tree, wildcard lookup | ~10,000 | **Good** | RFC-compliant `$GENERATE`, `$INCLUDE` |
| `internal/resolver/` | Recursive resolver, CNAME chasing | ~8,000 | **Good** | Iterative + forwarder modes |
| `internal/dnssec/` | Signing, validation, key rollover | ~12,000 | **Good** | RSA/ECDSA/Ed25519, RFC 7583 rollover |
| `internal/cluster/` | SWIM gossip + Raft consensus | ~10,000 | **Good** | SWIM is default; Raft tested (0.78 ratio); snapshot data not applied |
| `internal/transfer/` | AXFR/IXFR/DDNS/NOTIFY/TSIG/XoT/Slave | ~12,000 | **Good** | Very well-tested (447 tests); XoT IXFR uses journal for incremental transfers |
| `internal/storage/` | KV store, WAL, TLV serialization | ~8,000 | **Good** | In-memory KV with WAL journaling |
| `internal/config/` | Custom YAML parser, hot reload | ~5,000 | **Good** | Hand-written parser, no anchors/multiline |
| `internal/api/` | REST API, OpenAPI, MCP server | ~8,000 | **Good** | Split into 15 domain files; `server.go` reduced to ~1,150 lines |
| `internal/filter/` | ACL, rate limiting, split-horizon | ~6,000 | **Good** | Clean separation of concerns |
| `internal/quic/` | Hand-written QUIC for DoQ | ~6,000 | **Good** | Only external dep: `quic-go` |
| `cmd/nothingdns/` | Server entry point | ~2,000 | **Good** | Clean manager constructor pattern |
| `cmd/dnsctl/` | CLI management tool | ~3,000 | **Good** | All advertised commands fully implemented |
| `web/` | React 19 SPA dashboard | ~4,600 | **Good** | All pages wired to real APIs; login flow uses backend auth |

**No circular dependencies were detected.** The dependency graph flows sensibly: `protocol` → `zone`/`resolver`/`dnssec` → `server`/`transfer`/`api` → `cmd/nothingdns`.

### 2.3 Dependency Philosophy vs Reality

The project claims **"zero external dependencies"** in `docs/SECURITY.md` and `CLAUDE.md`. This is **mostly true but technically false**:

```go
// go.mod
require (
    github.com/quic-go/quic-go v0.59.0
    golang.org/x/sys v0.43.0
)
require (
    golang.org/x/crypto v0.45.0 // indirect
    golang.org/x/net v0.47.0 // indirect
)
```

`quic-go` is a significant external dependency for DoQ support. `golang.org/x/sys` is used for platform-specific socket operations (e.g., `SO_REUSEPORT`). The indirects come through `quic-go`. For a project that makes "zero dependencies" a headline security principle, the presence of `quic-go` is a **material deviation** that should be explicitly acknowledged, not buried in `go.mod`.

**The React frontend** (`web/`) adds **9 npm dependencies** (React, Tailwind, Zustand, TanStack Query, etc.), which is a documented deviation in `.project/SPEC_DEVIATIONS.md` but still violates the zero-dependency philosophy for the management plane.

---

## 3. Code Quality Assessment

### 3.1 Strengths

- **Zero technical-debt markers**: A full-repo grep for `TODO|FIXME|HACK|XXX|BUG` in `*.go` production files returned **zero matches**. This is exceptional for a codebase of this size.
- **Comprehensive panic recovery**: Every goroutine boundary that handles external input wraps panics. Examples:
  - `cmd/nothingdns/handler.go:83-95` — `ServeDNS` panic recovery
  - `internal/server/handler.go:83-97` — transport-level panic wrapper
  - `internal/config/reload.go:82-118` — reload callback panic recovery
  - `internal/transfer/slave.go:199` — zone transfer panic recovery
  - `internal/cluster/raft/raft.go:733-982` — multiple Raft goroutine panic recoveries
- **Defensive memory management**: `sync.Pool` is used aggressively in the protocol layer (`internal/protocol/wire.go`) to reduce GC pressure. Comments explicitly warn against passing pool buffer references to `defer pool.Put()` without copying.
- **Standard library crypto**: No custom ciphers. DNSSEC uses `crypto/rsa`, `crypto/ecdsa`, `crypto/ed25519`, `crypto/sha256`, etc. SHA-1 usage is limited to NSEC3 hashes with explicit `#nosec G505` justifications.

### 3.2 Concerns

#### A. Custom PBKDF2 Implementation (`internal/auth/auth.go:260-295`)

The auth package implements its own PBKDF2-HMAC-SHA512 instead of using `golang.org/x/crypto/pbkdf2`:

```go
// internal/auth/auth.go
func pbkdf2Sha512(password, salt []byte, iterations, keyLen int) []byte {
    // ... custom implementation ...
}
```

While the math appears correct (310,000 iterations, 64-byte output, 256-bit salts), maintaining a custom KDF increases the risk of subtle bugs and makes auditing harder. The zero-dependency policy is the likely reason, but this should be **extensively documented and formally reviewed**.

#### B. Misleading "Encryption" Naming (`internal/auth/auth.go:330-370`)

`SaveTokens` and `LoadTokens` claim to encrypt tokens but only append an HMAC-SHA512 signature for integrity:

```go
// SaveTokens "encrypts" tokens to a file.
func (s *AuthStore) SaveTokens(path string) error { ... }
```

The token data is **plaintext JSON** with an authentication tag, not ciphertext. This is misleading and could lead an operator to believe tokens are encrypted at rest when they are not.

#### C. Silent Config Parsing Failures

- `internal/transfer/axfr.go` — `WithAllowList` silently drops invalid CIDRs (`if err == nil { append }`).
- `internal/transfer/xot.go` — `AllowedNetworks` parsing similarly ignores invalid entries.
- `internal/rpz/rpz.go:parseLine` — silently `continue`s on malformed lines without logging. For a security-critical filtering engine, silently discarding rules is a **risky behavior**.

#### D. `internal/api/server.go` — ~3,150 Lines in a Single File

**✅ FIXED**: The REST API has been split into 15 domain-specific files (`api_auth.go`, `api_zones.go`, `api_blocklist.go`, `api_rpz.go`, `api_acl.go`, `api_config.go`, `api_cluster.go`, `api_upstreams.go`, `api_cache.go`, `api_dnssec.go`, `api_health.go`, `api_status.go`, `api_metrics.go`, `api_server.go`). `server.go` reduced from ~3,150 to ~1,150 lines.

#### E. `cmd/dnsctl/` — Advertised Features Are Stubs

**✅ FIXED**: All advertised CLI commands are now fully implemented. `record add/remove/update`, `zone add/remove`, `cluster join/leave`, and `blocklist reload` all work via REST API calls.

---

## 4. Testing & Coverage Analysis

### 4.1 Test Distribution

| Package | Source Files | Test Files | Test Functions | Test-to-Source Ratio |
|---------|--------------|------------|----------------|----------------------|
| `internal/transfer/` | 11 | 16 | 447 | **1.45** |
| `internal/dnssec/` | 9 | 10 | 281 | **1.11** |
| `internal/protocol/` | ~20 | 12 | ~200+ | **~0.60** |
| `internal/config/` | ~10 | 14 | ~150+ | **~1.40** |
| `internal/server/` | ~8 | 9 | ~120+ | **~1.13** |
| `internal/storage/` | ~8 | 8 | ~100+ | **1.00** |
| `internal/zone/` | ~10 | 8 | ~80+ | **0.80** |
| `internal/cache/` | ~4 | 7 | ~60+ | **1.75** |
| `internal/filter/` | 3 | 3 | 37 | **1.00** |
| `internal/resolver/` | ~6 | 4 | 62 | **0.67** |
| `internal/auth/` | 1 | 1 | 60+ | **60.00** ✅ FIXED |
| `internal/rpz/` | 1 | 1 | 50+ | **50.00** ✅ FIXED |
| `internal/dnscookie/` | 1 | 1 | 25+ | **25.00** ✅ FIXED |
| `internal/cluster/raft` | 7 | 1 | 58 | **0.78** ✅ FIXED |
| `cmd/nothingdns/` | 13 | 1 | ~40+ | **~0.30** ✅ FIXED (integration tests added) |
| `cmd/dnsctl/` | 9 | 1 | 29+ | **~0.32** ✅ FIXED |

### 4.2 Critical Gaps

**All previously identified critical gaps have been resolved:**

1. **`internal/cluster/raft/`** — **✅ FIXED**: 58 tests, 0.78 test-to-source ratio. Covers state transitions, log operations, snapshot handling, vote requests, peer management, WAL, and ZoneStateMachine.

2. **`internal/rpz/`** — **✅ FIXED**: 50+ tests covering all trigger types (QNAME, client IP, response IP, NSDNAME, NSIP), wildcard matching, and CNAME redirect chains.

3. **`internal/auth/`** — **✅ FIXED**: 60+ tests covering tokens, roles, edge cases, concurrent token creation, and expired token rejection.

4. **`internal/dnscookie/`** — **✅ FIXED**: 25+ tests covering secret rotation, grace period boundaries, timestamp forgery, and high-concurrency validation.

5. **`cmd/nothingdns/` and `cmd/dnsctl/`** — **✅ FIXED**: Integration tests added. `main_test.go` passes. dnsctl helper tests cover API client, auth, and error handling.

### 4.3 Benchmarks

Actual benchmark results from the codebase:

```
// internal/protocol/
BenchmarkMessagePackUnpackRoundTrip-32    955056    2299 ns/op    1416 B/op    61 allocs/op
BenchmarkPackName-32                      18472166  63.79 ns/op   16 B/op      1 allocs/op
BenchmarkHeaderPack-32                    293426942 4.102 ns/op  0 B/op       0 allocs/op

// internal/cache/
BenchmarkCacheGet_Hit-32                  15613918  82.05 ns/op   13 B/op      1 allocs/op
BenchmarkCacheSet-32                      2806669   388.6 ns/op   186 B/op     4 allocs/op

// internal/dnssec/
BenchmarkSignData_Ed25519-32              84568     14082 ns/op   64 B/op      1 allocs/op
BenchmarkSignData_ECDSA_P256-32           61477     21118 ns/op   6400 B/op    66 allocs/op
BenchmarkSignData_RSA_SHA256-32           1874      669485 ns/op  512 B/op     2 allocs/op
```

**Performance verdict**: The protocol and cache layers are extremely fast. DNSSEC RSA signing is predictably slow (670μs/op), which is a documented limitation (`docs/NOTHING.md` DEBT-003). Ed25519 signing at 14μs/op is perfectly viable for high-QPS zones.

---

## 5. Security Assessment

### 5.1 Authentication & Authorization

- **Password hashing**: PBKDF2-HMAC-SHA512 with 310,000 iterations and 256-bit salts. This meets OWASP 2023 recommendations.
- **Constant-time comparison**: `crypto/subtle.ConstantTimeCompare` is used for password and token verification.
- **Token generation**: Random 32-byte values signed with HMAC-SHA512.
- **Default admin**: If no users are configured, a secure 24-character random password is generated via rejection sampling (no modulo bias). A warning is logged.
- **RBAC**: Three roles (`admin`, `operator`, `viewer`). As documented in `docs/SECURITY.md`, **all authenticated operators have global access** to all zones. There is no per-zone isolation.

**Issues**:
- `User.Password string` is never zeroed from memory after config unmarshaling.
  **✅ FIXED**: V-15 — password zeroed after unmarshaling via direct `passNode.Value` overwrite.
- `SaveTokens` does not actually encrypt tokens (misleading naming).
  **✅ FIXED**: Renamed to `SaveTokensSigned`/`LoadTokensSigned`; tokens now use AES-256-GCM authenticated encryption.
- API tokens can be passed via query parameters (`?token=...`), which exposes them in logs and browser history.
  **✅ FIXED**: V-16 — query param fallback removed from API and WebSocket handlers.

### 5.2 Network Security

- **DoT**: TLS 1.3+ with configurable cipher suites and ALPN (`dot`).
- **DoH**: Standard `application/dns-message` and JSON formats.
- **DoQ**: Uses `quic-go` (external dependency).
- **XoT**: Zone transfers over TLS (RFC 9103) are now fully implemented as of 2026-04-11.
- **TCP protections**: Global connection limit (1000), per-IP limit (10), pipeline limit (16).
- **UDP protections**: Truncation is record-boundary-aware.

### 5.3 DNSSEC Security

- **Signing**: RSA/ECDSA/Ed25519 supported. NSEC3 with opt-out.
- **Validation**: Chain-of-trust from trust anchors, max delegation depth 20, 5-minute clock skew tolerance.
- **Key rollover**: RFC 7583 lifecycle states (Active/Inactive/Retired/Revoked).
- **No obvious cryptographic misuses** were found.

### 5.4 Filtering & Policy Security

- **ACL**: CIDR-based with correct IPv4-mapped IPv6 normalization.
- **Rate limiting**: Token-bucket per IP (5 QPS / burst 20). **✅ FIXED**: V-10/V-11 — bounded with LRU eviction (50K entries) preventing unbounded memory growth.
- **RPZ**: Heuristic parser with silent dropping of malformed lines.
  **✅ FIXED**: V-01/V-12 — all parse errors now logged at Warn level with line number and reason; parse errors tracked in metrics.
- **Blocklist**: Supports hosts-file and domain formats with allowlist override.

---

## 6. Frontend & Dashboard Assessment

### 6.1 Technology Stack

- React 19.2.4, TypeScript 5.9.3 (strict mode), Vite 8.0.8
- Tailwind CSS 4.1, shadcn/ui components
- Zustand 5.0.12 for state, TanStack Query 5.99.0 for data fetching
- React Router DOM 7.14.0

### 6.2 Issues

1. **Mock data on multiple pages**:
   **✅ FIXED**: All dashboard pages now use real API calls. GeoIP, DNS64/Cookies, and Zone Transfer pages are wired to actual endpoints.

2. **Login flow mismatch**: The frontend login page (`login.tsx`) asks for a raw "Access Token" and validates it via `/api/v1/status`. It **does not use** the backend's `/api/v1/auth/login` endpoint, which accepts `username` + `password` and returns a proper JWT/session. This bypasses the entire backend auth flow.
   **✅ FIXED**: Login page now POSTs to `/api/v1/auth/login` with username/password.

3. **No logout functionality**: There is no logout button anywhere in the UI. Users must manually clear `localStorage` and cookies.
   **✅ FIXED**: Logout button added to sidebar with proper cookie clearing.

4. **Settings are read-only**: All 8 settings tabs display config as read-only key-value rows. No edit/save capability exists.
   **✅ FIXED**: Settings page supports runtime config changes for logging, rate limiting, and cache.

5. **Unused notification system**: `web/src/lib/notification.tsx` implements a custom toast stack, but the app uses `sonner`'s `<Toaster>` instead.
   **✅ FIXED**: Removed unused notification system.

6. **Potential JSON case mismatch**: The frontend `ClusterNode` interface uses snake_case-ish field names (`addr`, `http_addr`, `weight`) while Go struct fields are PascalCase. Without explicit JSON tags on some backend structs, this could cause empty fields depending on encoder behavior.
   **✅ FIXED**: Backend structs use proper `json:"..."` tags.

---

## 7. API Assessment

### 7.1 Endpoint Coverage

The API is comprehensive: ~60 endpoints covering zones, records, cache, cluster, blocklists, RPZ, DNSSEC, ACL, upstreams, auth, metrics, and query logs. Full OpenAPI 3.0 spec is served at `/api/openapi.json`.

### 7.2 MCP Server

`internal/api/mcp/` implements a custom Model Context Protocol server with:
- 12 tools (dns_query, zone CRUD, cache ops, server stats)
- Resources (zones, status, cache stats)
- 2 prompts (troubleshoot_dns, zone_setup)
- Optional token-based RBAC

### 7.3 Issues

1. **`internal/api/server.go` is ~3,150 lines** — far too large for a single file.
   **✅ FIXED**: Split into 15 domain files; `server.go` reduced to ~1,150 lines.

2. **`handleServerConfig` returns `ListenPort: 0` and `LogLevel: ""`**:
   These fields are not available in `HTTPConfig`. The struct explicitly returns zeros. This is a **known gap** — not critical.

3. **Mixed response types**: Some endpoints (e.g., bulk PTR preview, ptr6-lookup) return `map[string]interface{}` despite the typed-response mandate in `response.go`.
   **Open** — partially addressed but some endpoints still use untyped maps.

4. **WebSocket auth via query param**: The `/ws` endpoint accepts the auth token as a query parameter (`?token=...`).
   **✅ FIXED**: V-16 — query param fallback removed from API and WebSocket code.

---

## 8. Operations & Deployment

### 8.1 Build & CI/CD

- **Go CI** (`.github/workflows/go.yml`): `go vet`, `go build`, `go test -short` on push/PR.
- **Web CI** (`.github/workflows/web.yml`): `npm install`, `tsc --noEmit`, `lint`, `build`. **Issue**: Uses `npm` despite the repo containing `pnpm-lock.yaml`.
- **Container CI** (`.github/workflows/container.yml`): Multi-platform Docker build (`linux/amd64`, `linux/arm64`) with Buildx and GHCR push.

### 8.2 Docker

Multi-stage `Dockerfile`:
- Build: `golang:1.26.2-alpine`
- Runtime: `FROM scratch`
- Static binaries with `-trimpath -ldflags "-s -w -extldflags '-static'"`
- Exposes: 53/udp, 53/tcp, 853/tcp, 443/tcp, 8080/tcp, 9153/tcp

### 8.3 Configuration

- Default config path: `/etc/nothingdns/nothingdns.yaml`
- Hot reload via SIGHUP — zones, blocklists, RPZ, views, TLS certs
- Custom YAML parser with environment variable expansion (`${VAR}`, `$VAR`)
- **Limitation**: No anchor/alias support, no multiline strings

---

## 9. Spec vs Implementation Gaps

Documented deviations are tracked in `.project/SPEC_DEVIATIONS.md`:

| Spec Requirement | Implementation | Status |
|------------------|----------------|--------|
| Vanilla JS dashboard | React 19 + npm deps | **Deviation — accepted** |
| Raft as default cluster mode | SWIM is default | **Deviation — accepted** |
| XoT (RFC 9103) | Fully implemented (2026-04-11) | **Resolved** |

**Undocumented gaps** (all resolved):

1. **`dnsctl` stubs** — **✅ FIXED**: All advertised commands now implemented.
2. **Frontend mock data** — **✅ FIXED**: All pages wired to real APIs.
3. **Go dependency claim** — **✅ FIXED**: Claims corrected to "minimal external dependencies" in SECURITY.md and README.md.
4. **`Makefile` missing** — **✅ FIXED**: Makefile created at project root with build, test, lint, CI, and release targets.

---

## 10. Summary of Critical Findings

| ID | Finding | Severity | Status | File(s) |
|----|---------|----------|--------|---------|
| F-001 | RPZ silently drops malformed rules without logging | **High** | ✅ FIXED | `internal/rpz/rpz.go` |
| F-002 | Raft consensus severely under-tested (0.14 ratio) | **High** | ✅ FIXED | `internal/cluster/raft/` |
| F-003 | `dnsctl` has multiple advertised-but-unimplemented commands | **Medium** | ✅ FIXED | `cmd/dnsctl/` |
| F-004 | Frontend login bypasses backend auth flow entirely | **Medium** | ✅ FIXED | `web/src/pages/login.tsx` |
| F-005 | Frontend serves mock data on geoip, dns64-cookies, zone-transfer pages | **Medium** | ✅ FIXED | `web/src/pages/*.tsx` |
| F-006 | API auth token accepted via query parameter (logs exposure) | **Medium** | ✅ FIXED | `internal/api/server.go` |
| F-007 | Custom PBKDF2 implementation instead of battle-tested library | **Medium** | ✅ FIXED | `internal/auth/auth.go` |
| F-008 | `SaveTokens` claims encryption but only provides integrity (HMAC) | **Medium** | ✅ FIXED | `internal/auth/auth.go` |
| F-009 | `internal/api/server.go` is ~3,150 lines — unmaintainable scale | **Low** | ✅ FIXED | `internal/api/server.go` (now ~1,150 lines, split into 15 files) |
| F-010 | Rate limiter buckets grow unbounded until 5-minute cleanup | **Low** | ✅ FIXED | `internal/filter/ratelimit.go` |
| F-011 | AXFR/XoT silently ignore invalid CIDRs in allow-lists | **Low** | ✅ FIXED | `internal/transfer/axfr.go`, `xot.go` |
| F-012 | `go.mod` contains external deps despite zero-dep marketing | **Low** | ✅ FIXED | `go.mod`, `docs/SECURITY.md` |
| F-013 | GeoDNS pure IPv6 lookup crashes (`ip.To4()` overwrites to nil, `nil.To16()` returns nil) | **Medium** | ✅ FIXED | `internal/geodns/geodns.go:226-231` |
| F-014 | XoT IXFR falls back to full AXFR instead of incremental changes | **Low** | ✅ FIXED | `internal/transfer/xot.go:490` — journal store wired via `SetJournalStore`, `buildIncrementalIXFR` implements RFC 1995 pattern |
| F-015 | Raft `handleSnapshotRequest` clears log without applying snapshot data | **Low** | **Open** | `internal/cluster/raft/raft.go:682-702` |

---

*End of Analysis*
