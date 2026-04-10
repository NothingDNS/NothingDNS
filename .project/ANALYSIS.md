# Project Analysis Report

> Auto-generated comprehensive analysis of NothingDNS
> Generated: 2026-04-10
> Analyzer: Claude Code - Full Codebase Audit

## 1. Executive Summary
NothingDNS is a Go-based DNS platform that combines authoritative DNS, recursive resolution, DNSSEC, encrypted transports (DoT/DoH/DoQ/ODoH), clustering, REST API, MCP server, and a React dashboard in one repository. It targets operators who want a self-hosted DNS server with no external Go runtime dependencies.

- Key metrics
- Total files (raw): 25,898
- Total files (source-filtered): 485
- Go files (filtered): 294
- Go LOC (filtered): 138,087
- Frontend code files (`web/src`, ts/tsx/js/jsx): 34
- Frontend LOC (`web/src`): 3,560
- Go test files (`*_test.go`): 156
- Go source files (non-test): 138
- External Go dependencies (`go.mod`): 0
- Frontend direct dependencies (`web/package.json`): 9 prod + 12 dev = 21
- Markdown docs read: 113 files, 28,377 lines
- Overall health score: 6.8/10

- Top 3 strengths
- Very broad feature surface in a single codebase with strong package separation (`internal/*`, `cmd/*`).
- Zero external Go dependency policy is actually enforced (`go.mod` has no `require`, `go.sum` empty).
- Test volume is high (156 Go test files) and short test run is green.

- Top 3 concerns
- Full test run is not green: `go test ./... -count=1` fails consistently in `test/chaos`.
- Security and API consistency gaps: CORS behavior contradicts config comments, token handling in frontend uses non-HttpOnly cookie and query-string WebSocket token fallback.
- Documentation/spec drift is significant: `files/SPECIFICATION.md`, `files/IMPLEMENTATION.md`, and `README.md` do not fully match current implementation.

## 2. Architecture Analysis

### 2.1 High-Level Architecture
NothingDNS is a modular monolith (single deployable binary for server, separate CLI binary for management) with internal subsystems for protocol, resolver, zone management, security, API, dashboard, and storage.

Text data flow:

```text
Client Query (UDP/TCP/TLS/DoH/DoQ/ODoH)
  -> internal/server or internal/doh or internal/quic/odoh handlers
  -> cmd/nothingdns handler pipeline (ACL/rate-limit/blocklist/RPZ/cache)
  -> authoritative zone lookup (internal/zone) OR upstream recursive path (internal/upstream/resolver)
  -> optional DNSSEC validate/sign path (internal/dnssec)
  -> response encode (internal/protocol)
  -> metrics/audit/dashboard stream update
```

Control plane flow:

```text
HTTP API (internal/api/server.go)
  -> auth middleware + rate limiting + CORS
  -> config/cache/zone/cluster/auth handlers
  -> dashboard SPA/static serving (internal/dashboard/static.go)
  -> WebSocket stream (/ws)
```

Concurrency model:
- Main runtime uses goroutines for transport servers and background loops (`cmd/nothingdns/main.go:474`, `:485`, `:519`, `:564`).
- Graceful shutdown with stop channel + timeout context (`cmd/nothingdns/main.go:606-664`).
- Per-subsystem loops use ticker + stop channels (example API rate-limit cleanup: `internal/api/server.go:552-565`).
- Cluster and upstream components use `sync.Mutex`, `sync.RWMutex`, `sync.WaitGroup`, atomics.

### 2.2 Package Structure Assessment
Go packages discovered via `go list ./...`: 37 total, including one local non-project package from frontend node modules: `github.com/nothingdns/nothingdns/web/node_modules/flatted/golang/pkg/flatted`.

Primary packages and responsibilities:
- `cmd/dnsctl`: CLI control surface.
- `cmd/nothingdns`: process wiring, boot, shutdown, managers.
- `internal/api`, `internal/api/mcp`: REST API + MCP server.
- `internal/audit`: query audit logging.
- `internal/auth`: users, password hashing, token issuance/validation.
- `internal/blocklist`, `internal/filter`, `internal/rpz`: policy/filtering.
- `internal/cache`: DNS cache and related logic.
- `internal/catalog`: catalog zone support.
- `internal/cluster`, `internal/cluster/raft`: SWIM/raft cluster logic.
- `internal/config`: custom YAML tokenizer/parser/validation/reload.
- `internal/dashboard`: embedded SPA serving and WS integration.
- `internal/dns64`, `internal/dnscookie`, `internal/dnssec`, `internal/doh`, `internal/odoh`, `internal/quic`: protocol and security transports.
- `internal/geodns`, `internal/idna`: DNS data transformations/routing.
- `internal/memory`, `internal/metrics`: memory control and metrics.
- `internal/protocol`: DNS wire/message/record codec.
- `internal/resolver`, `internal/upstream`: recursive and upstream logic.
- `internal/server`: UDP/TCP/TLS servers.
- `internal/storage`: KV/WAL storage layer.
- `internal/transfer`: AXFR/IXFR/DDNS/TSIG/notify.
- `internal/util`: shared utility/logging helpers.
- `internal/websocket`: low-level WS implementation.
- `internal/zone`: zone parsing/manager/writer.
- `test/chaos`, `test/integration`: higher-level test suites.

Cohesion assessment: generally strong. Most packages maintain a single responsibility.

Boundary concerns:
- `internal/cluster/raft` exists, but runtime config path from `config.Cluster` to raft mode is incomplete (see Section 5.2), so part of cluster architecture is present but not fully wired.

Circular dependency risk: no direct circular imports observed in `go list ./...` behavior.

Internal vs pkg separation: clean use of `internal` and `cmd`; no public `pkg` API layer (acceptable for application-style repo).

### 2.3 Dependency Analysis
Go dependencies (`go.mod`):
- No external module dependencies.
- Toolchain: `go 1.23` declared in module; local runtime used for audit: `go1.26.1 windows/amd64`.

Dependency hygiene:
- `go.sum` is empty (0 bytes), matching strict-zero policy.
- `go list ./...` includes a frontend node_modules Go package when `web/node_modules` exists locally; this is not tracked by git but pollutes local Go package graph.

Vulnerability posture (`govulncheck ./...` on local Go 1.26.1):
- GO-2026-4947 (`crypto/x509`, fixed in Go 1.26.2)
- GO-2026-4946 (`crypto/x509`, fixed in Go 1.26.2)
- GO-2026-4870 (`crypto/tls`, fixed in Go 1.26.2)
- GO-2026-4866 (`crypto/x509`, fixed in Go 1.26.2)
- Impact source is stdlib version, not third-party module imports.

Frontend dependencies (`web/package.json`):
- Runtime: React 19.2.4, React Router 7.14.0, Tailwind 4.1, lucide-react, class helpers.
- Build/tooling: Vite 8.0.8, TypeScript 5.9.3, ESLint stack.
- `npm audit --json`: 0 known vulnerabilities in local lock state.

### 2.4 API & Interface Design
Route registration inventory (`internal/api/server.go`): 38 registrations (34 static + 3 configurable dynamic + SPA/static handlers).

Endpoint inventory (method/path/handler):
- `ANY /health -> handleHealth` (`internal/api/server.go:441`)
- `ANY /readyz -> handleReadiness` (`:442`)
- `ANY /livez -> handleLiveness` (`:443`)
- `ANY /api/v1/status -> handleStatus` (`:444`)
- `GET /api/v1/cluster/status -> handleClusterStatus` (`:447`)
- `GET /api/v1/cluster/nodes -> handleClusterNodes` (`:448`)
- `GET,POST /api/v1/zones -> handleZones` (`:451`)
- `POST /api/v1/zones/reload -> handleZoneReload` (`:452`)
- `GET,POST,PUT,DELETE /api/v1/zones/* -> handleZoneActions` (`:453`, comments at `:992-1000`)
- `GET /api/v1/cache/stats -> handleCacheStats` (`:456`)
- `POST /api/v1/cache/flush -> handleCacheFlush` (`:457`)
- `GET,POST /api/v1/blocklists -> handleBlocklists` (`:460`)
- `POST /api/v1/blocklists/* -> handleBlocklistActions` (`:461`)
- `GET,PUT /api/v1/upstreams -> handleUpstreams` (`:464`)
- `GET,PUT /api/v1/acl -> handleACL` (`:467`)
- `GET /api/v1/rpz -> handleRPZ` (`:470`)
- `GET,POST,DELETE /api/v1/rpz/rules -> handleRPZRules` (`:471`)
- `POST /api/v1/rpz/* -> handleRPZActions` (`:472`)
- `GET /api/v1/server/config -> handleServerConfig` (`:475`)
- `POST /api/v1/auth/login -> handleLogin` (`:479`)
- `GET,POST,DELETE /api/v1/auth/users -> handleUsers` (`:480`)
- `ANY /api/v1/auth/roles -> handleRoles` (`:481`, no method guard in handler at `:2637-2645`)
- `POST /api/v1/auth/logout -> handleLogout` (`:482`)
- `POST /api/v1/config/reload -> handleConfigReload` (`:486`)
- `GET /api/v1/config -> handleConfigGet` (`:487`)
- `GET /api/v1/dnssec/status -> handleDNSSECStatus` (`:490`)
- `ANY /api/dashboard/stats -> handleDashboardStats` (`:493`)
- `GET /api/v1/queries -> handleQueryLog` (`:494`)
- `GET /api/v1/topdomains -> handleTopDomains` (`:495`)
- `GET /api/v1/metrics/history -> handleMetricsHistory` (`:499`)
- `ANY /api/openapi.json -> handleOpenAPISpec` (`:503`)
- `ANY /api/docs -> handleSwaggerUI` (`:504`)
- `ANY /ws -> dashboardServer.ServeHTTP` (`:507`)
- `ANY /assets/* -> spaHandler` (`:511`)
- `ANY / -> handleSPA` (`:514`)
- Dynamic: `s.config.DoHPath`, `s.config.DoWSPath`, `s.config.ODoHPath` (`:426`, `:432`, `:437`)

API consistency assessment:
- OpenAPI spec is incomplete: 13 documented paths (`internal/api/openapi.go:179-622`) vs 30+ live API paths.
- Method discipline is inconsistent: several handlers accept `ANY` (for example `handleRoles`, `handleDashboardStats`, docs/spec endpoints).
- Error formatting is mostly centralized (`writeError`), but middleware also uses raw `http.Error` JSON strings (`internal/api/server.go:640`, `:665`, `:680`), creating mixed response formatting.

Auth model:
- Auth middleware supports legacy shared token and auth store token validation (`internal/api/server.go:655-687`).
- Login endpoint supports username/password + token issuing + HttpOnly cookie (`:2455-2521`).
- Frontend login does not use `/api/v1/auth/login`; it checks token validity via `/api/v1/status` and writes cookie from JS (`web/src/pages/login.tsx:17-19`, `internal/dashboard/static.go:139-142`).

Rate limiting, CORS, validation:
- API rate limiting exists globally for authenticated calls (`internal/api/server.go:220-322`, checks at `:662`, `:677`).
- Login has IP+username lockout logic (`:2466-2484`).
- CORS has contradictory semantics:
- Config comment says empty allowed origins means same-origin only (`internal/config/config.go:420-422`).
- Middleware treats empty list as allow-all `*` (`internal/api/server.go:572-580`).
- Config comment says `*` should allow all, middleware explicitly rejects explicit wildcard (`:581-584`).

## 3. Code Quality Assessment

### 3.1 Go Code Quality
Style and tooling:
- `go build ./...` passes.
- `go vet ./...` passes.
- `staticcheck ./...` reports multiple issues across style, possible panics, deprecated usage, and correctness.

Notable staticcheck findings:
- Potential binary encoding correctness bug: `binary.Write` on non-fixed structs in raft transport (`internal/cluster/raft/rpc.go:201`, `:225`, `:249`, SA1003).
- Possible nil dereference in tests and helper paths (`SA5011`) across dashboard/transfer/upstream tests.
- Deprecated constant usage (`os.SEEK_SET`) in raft WAL (`internal/cluster/raft/wal.go:70`, SA1019).
- Allocation/perf issues (`SA6002`) in server/upstream paths.

Error handling patterns:
- Mostly explicit error propagation.
- Some callback paths swallow panics silently with bare `defer recover()` (`internal/cluster/gossip.go:409`, `:421`, `:445`, `:567`), reducing debuggability and masking runtime faults.

Context usage:
- Context propagation is present in many subsystems.
- `performAXFR(ctx, ...)` currently does not use `ctx` internally (`internal/transfer/slave.go:415-440`), so cancellation/deadline intent is partially lost.

Logging:
- Structured logger supports JSON and levels (`internal/util/logger.go:42-50`, `:55-257`).
- No centralized request-id middleware; no explicit correlation-id propagation found.

Configuration:
- Custom parser/tokenizer implementation is mature (`internal/config/*`).
- Defaults and validation are extensive.
- Mismatch between documented and implemented CORS semantics (noted above) is a correctness/documentation bug.

Magic numbers and TODO/FIXME/HACK in project code:
- `test/chaos/chaos_test.go:42`, `:67`, `:134`, `:251` TODO re-enable markers.
- Several hardcoded operational constants in API rate limiting (`internal/api/server.go:84-89`, `:230-231`).

### 3.2 Frontend Code Quality
Stack and patterns:
- React 19 + React Router 7 + Vite 8 + strict TS (`web/tsconfig.app.json:20-25`).
- Functional component architecture with hooks.

Observations:
- Component routing is clean (`web/src/App.tsx:49-65`).
- API utility assumes every response is JSON (`web/src/lib/api.ts:16`), so non-JSON failures can throw unexpectedly.
- Login/auth model stores token in JS-managed cookie (non-HttpOnly) (`web/src/pages/login.tsx:18`, `internal/dashboard/static.go:141`).
- WebSocket token may be sent in query string (`web/src/hooks/useWebSocket.ts:26`) and accepted by server (`internal/dashboard/server.go:256-258`).

TypeScript strictness:
- `strict: true`, unused checks, and no-emit build constraints are enabled.

CSS and UX:
- Tailwind-based UI with shared components in `web/src/components/ui`.
- No frontend test suite present (0 `.test/.spec` files under `web/src`).

Accessibility:
- Some icon-only buttons lack explicit labels (for example user delete button `web/src/pages/users.tsx:145-147`, visibility toggle button `web/src/pages/login.tsx:34`).

Bundle concerns:
- Production bundle from Vite: JS ~383.98 kB (gzip ~108.76 kB), CSS ~35.42 kB (gzip ~6.56 kB). Acceptable for admin dashboard, but no lazy route splitting observed.

### 3.3 Concurrency & Safety
Strengths:
- Widespread use of mutexes, atomics, wait groups.
- Shutdown flow exists with timeout and subsystem stop sequence (`cmd/nothingdns/main.go:611-652`).

Risks:
- Race test could not be executed locally due missing C compiler (`go test -race` requires CGO + `gcc`).
- Callback panic swallowing in gossip can hide concurrency bugs (`internal/cluster/gossip.go:409`, `:421`, `:445`, `:567`).
- Raft RPC transport uses long-lived connections map without explicit transport-level close API in `TCPTransport` path.

Resource leak checks:
- Many network paths use `defer Close()` correctly.
- Upstream client includes explicit pool close (`internal/upstream/client.go:189-203`, `:197-199`).

Graceful shutdown:
- Implemented with signal handling and timeout context in main process.

### 3.4 Security Assessment
Input validation:
- Good validation in config parser and several API handlers.
- API handlers generally decode JSON directly without unknown-field rejection or explicit request body size limits.

Injection risks:
- SQL injection: not applicable (no `database/sql` usage found).
- Command injection: no `os/exec` usage found in project code.

XSS/frontend:
- React auto-escaping protects most view paths.
- Token lives in script-accessible cookie and may be exfiltrated if XSS appears.

Secrets management:
- No hardcoded production secrets found in source paths scanned.
- `test-config.yaml` contains test token literal (`test-config.yaml:16`).
- `.gitignore` includes `.env` patterns (`.gitignore:40-42`).

TLS/HTTPS:
- TLS transports implemented for DNS/TCP and HTTP paths.
- `govulncheck` indicates local stdlib TLS/X509 vulnerabilities due Go patch level.

CORS:
- Behavior/config mismatch is a concrete risk (`internal/config/config.go:420-422` vs `internal/api/server.go:572-584`).

Authz quality:
- RBAC helper present (`internal/api/server.go:2647-2669`) and used in critical handlers.
- Some routes expose `ANY` method shape (for example roles endpoint), not ideal API hardening.

Known vulnerability patterns found:
- Stdlib CVEs from `govulncheck` (Go patch level issue).
- Token-in-query fallback for websocket auth (`internal/dashboard/server.go:256-258`).

## 4. Testing Assessment

### 4.1 Test Coverage
File-level metrics:
- Source files: 138
- Test files: 156
- Ratio: 1.13 test files per source file.

Command results:
- `go test ./... -count=1`: FAIL
- Failing package: `test/chaos`
- Failing tests: `TestNetworkPartition`, `TestGracefulShutdown`, `TestConcurrentLoad`, `TestConnectionExhaustion`
- `go test ./... -count=1 -short`: PASS
- `go test ./... -short -cover`: PASS for packages; high package coverage in many internals.

Packages with zero test coverage:
- No core project package with source files was found without test files.
- Local environment includes extraneous package `web/node_modules/flatted/golang/pkg/flatted` with `coverage: 0.0%` and no tests.

Test types present:
- Unit tests: extensive.
- Integration tests: `test/integration/integration_test.go`.
- Chaos tests: `test/chaos/chaos_test.go` (currently failing in full run).
- Benchmarks: present across multiple packages.
- Fuzz tests: present (`internal/protocol/fuzz_test.go`).
- Frontend tests: absent.

Test quality notes:
- Coverage depth is broad, but many `coverage_extra*` files exist; they improve branch/path execution but can reduce readability of core behavioral test intent.

### 4.2 Test Infrastructure
- CI workflow exists (`.github/workflows/ci.yml`) with lint, race+coverage tests, build, and docker build.
- Local race test was blocked by missing `gcc` in this Windows environment.
- Flakiness risk is concentrated in chaos suite due strict success expectations against intentionally degraded scenarios.

## 5. Specification vs Implementation Gap Analysis

### 5.1 Feature Completion Matrix

| Planned Feature | Spec Section | Implementation Status | Files/Packages | Notes |
|---|---|---|---|---|
| Single binary DNS server + CLI + dashboard | SPEC intro/architecture | ✅ Complete | `cmd/nothingdns`, `cmd/dnsctl`, `internal/dashboard` | Implemented and buildable. |
| Zero external Go dependencies | SPEC core constraints | ✅ Complete | `go.mod`, `go.sum` | No `require` entries, empty `go.sum`. |
| UDP/TCP DNS | SPEC 3.2.1/3.2.2 | ✅ Complete | `internal/server/udp.go`, `internal/server/tcp.go` | Core transport implemented and tested. |
| DoT | SPEC 3.2.3 | ✅ Complete | `internal/server/tls.go` | TLS server path exists and tested. |
| DoH | SPEC 3.2.4 | ✅ Complete | `internal/doh/*`, API mux | Configurable DoH path supported. |
| DoQ | SPEC 3.2.5 | ⚠️ Partial | `internal/quic/*` | Present, but protocol maturity depends on custom implementation complexity. |
| ODoH | SPEC ODoH sections | ✅ Complete | `internal/odoh/*`, API mux | Endpoint integrated. |
| Authoritative BIND zones | SPEC phase auth | ✅ Complete | `internal/zone/*` | Zone parsing/manager implemented. |
| Recursive resolution | SPEC recursive phase | ✅ Complete | `internal/resolver/*`, `internal/upstream/*` | Upstream strategies and resolver components exist. |
| DNSSEC validation/signing | SPEC DNSSEC | ✅ Complete | `internal/dnssec/*` | Large implementation surface with tests. |
| RPZ/blocklist/ACL | SPEC policy/filtering | ✅ Complete | `internal/rpz`, `internal/blocklist`, `internal/filter` | Exposed in API and runtime pipeline. |
| Metrics endpoint | SPEC observability | ✅ Complete | `internal/metrics/*` | Prometheus path default `/metrics`. |
| API dashboard | SPEC web UI | ✅ Complete (different implementation) | `web/src`, `internal/dashboard/static.go` | React SPA, not vanilla JS from spec. |
| WebSocket live stream | SPEC dashboard realtime | ✅ Complete | `/ws`, `internal/dashboard/server.go` | Integrated with query event stream. |
| MCP server | SPEC management | ✅ Complete | `internal/api/mcp/*` | Tool surface implemented and tested. |
| Cluster membership | SPEC clustering | ✅ Complete | `internal/cluster/gossip.go` | SWIM-style gossip implemented. |
| Raft consensus cluster | SPEC raft-focused sections | ⚠️ Partial | `internal/cluster/raft/*`, `internal/cluster/cluster.go` | Raft code exists, but config wiring uses gossip-only fields by default path. |
| gRPC inter-node | SPEC 10.3/impl docs | ❌ Missing | expected `internal/api/grpc/*` not present | Spec/docs mention gRPC files that do not exist. |
| OpenAPI documentation coverage | SPEC API docs intent | ⚠️ Partial | `internal/api/openapi.go` | 13 documented paths vs larger live surface. |
| Chaos test resilience criteria | SPEC quality goals | ❌ Missing (effective) | `test/chaos/chaos_test.go` | Tests exist but fail in full run; not production confidence yet. |

### 5.2 Architectural Deviations
- Spec and implementation docs reference Apache-2.0 (`files/SPECIFICATION.md:26`) but repository license is MIT (`LICENSE:1`). This is a documentation/legal mismatch.
- Spec/impl docs reference gRPC inter-node package (`files/SPECIFICATION.md:168-170`, `files/IMPLEMENTATION.md:2260-2273`) but codebase has no `internal/api/grpc` directory.
- Spec describes embedded vanilla JS dashboard (`files/SPECIFICATION.md:914`, `files/SPECIFICATION.md:184`) while implementation is React 19 SPA (`web/src/*`, `internal/dashboard/static.go:10-16`).
- Cluster docs and runtime are mixed-mode: raft package exists, but `config.ClusterConfig` lacks raft peer/mode fields (`internal/config/config.go:357-389`), and manager wiring uses gossip fields (`cmd/nothingdns/cluster_manager.go:34-46`).

Assessment:
- React dashboard replacement is an improvement for maintainability/UX, but docs must be updated.
- Missing gRPC despite spec promises is a regression relative to documented architecture.
- Raft implementation appears in-progress/partial integration rather than fully productized.

### 5.3 Task Completion Assessment
`files/TASKS.md` does not function as a reliable completion tracker:
- 269 task rows exist.
- Columns contain priority icons (mojibake-encoded in current file), not explicit done/in-progress checkboxes.
- Only one explicit draft status line found (`files/TASKS.md:533`).

Heuristic status (path-reference existence only):
- Rows with parsable path references: 93
- Referenced paths existing now: 35
- Referenced paths missing/renamed: 58

Interpretation:
- Current task sheet is stale relative to refactors and package renames.
- Numeric completion percentage from `TASKS.md` alone is not trustworthy.
- Practical implementation maturity appears higher than file-path heuristic suggests.

### 5.4 Scope Creep Detection
Features/components present in codebase but not aligned with original spec text:
- React 19 SPA dashboard instead of vanilla JS.
- DoWS endpoint (`s.config.DoWSPath`, `internal/api/server.go:432`).
- Extensive security-audit artifacts under `security-report/`.
- Large `coverage_extra*` test expansion across many packages.

Assessment:
- Most scope additions are valuable (dashboard modernization, security tooling).
- The extra test scaffolding increases maintenance load and obscures core behavioral test intent.

### 5.5 Missing Critical Components
Critical planned-but-absent/incomplete items:
- gRPC inter-node implementation promised in docs/spec.
- Fully wired raft configuration path from user config to runtime mode selection.
- Full OpenAPI coverage for actual API surface.
- Stable chaos test suite criteria aligned to expected degraded behavior.

Priority order for closure:
1. Fix failing full test pipeline and chaos suite semantics.
2. Resolve CORS/auth inconsistencies and token handling risks.
3. Update docs/spec/implementation references to actual architecture.
4. Decide and finalize cluster direction (SWIM-only vs fully supported raft mode + config).

## 6. Performance & Scalability

### 6.1 Performance Patterns
Hot paths:
- DNS query handling in `cmd/nothingdns/handler.go` and `internal/server/*`.
- Protocol pack/unpack in `internal/protocol/*`.

Allocation patterns:
- Buffer pooling is used in upstream and server paths.
- Staticcheck still flags avoidable allocations in some hot areas (`SA6002` in server/upstream paths).

Storage/query patterns:
- No SQL layer; custom KV + WAL in `internal/storage`.
- No obvious N+1 query patterns (not database-driven).

Caching:
- Cache subsystem is mature and widely integrated.

HTTP/static optimization:
- Dashboard assets are prebuilt and embedded (`internal/dashboard/static.go:12-16`).
- No obvious compression middleware in API layer found.

### 6.2 Scalability Assessment
Horizontal scale:
- Possible via cluster mode, but consistency model depends on selected mode.
- Effective default path currently gossip-focused from config wiring.

State management:
- In-memory cache/state with optional persistence and transfer mechanisms.
- No external datastore dependency by design.

Back-pressure/resource limits:
- API and login rate limiting exists.
- No global request body size limits observed on API handlers.

Connection pooling:
- Upstream client includes TCP connection pools and explicit shutdown (`internal/upstream/client.go:70`, `:189-203`).

## 7. Developer Experience

### 7.1 Onboarding Assessment
What works:
- Clear build targets in `Makefile`.
- `README.md` is extensive.

Friction:
- Local `-race` requires `gcc` on Windows; not documented prominently in root workflow.
- Presence of local `web/node_modules` can pollute `go list ./...` package graph.

### 7.2 Documentation Quality
Strengths:
- Rich README with operational examples.

Gaps:
- README endpoint list has stale entries (`/api/dashboard/queries`, `/api/dashboard/zones` not registered in API server).
- SPEC/IMPLEMENTATION contain stale package paths and architecture claims (gRPC, vanilla JS dashboard, Apache license).

### 7.3 Build & Deploy
- Build process is straightforward and reproducible.
- Dockerfile is multi-stage and final `scratch` image with non-root user (`Dockerfile:34-50`).
- CI/CD exists and is structurally good.
- Release automation present via `.goreleaser.yaml`.

## 8. Technical Debt Inventory

### Critical (blocks production readiness)
- `test/chaos/chaos_test.go` - Full test run fails consistently; CI confidence blocker. Suggested fix: redesign assertions to validate expected degraded behavior and isolate deterministic scenarios. Effort: 12-20h.
- `internal/config/config.go:420-422` vs `internal/api/server.go:572-584` - CORS policy contradiction and insecure-default ambiguity. Suggested fix: unify semantics and tests, document one definitive behavior. Effort: 4-8h.
- `internal/dashboard/server.go:256-258` and `web/src/hooks/useWebSocket.ts:26` - token in query string accepted/transmitted; leakage risk in logs/proxies. Suggested fix: header/cookie-only auth for WS handshake. Effort: 6-10h.
- Go stdlib patch level (`govulncheck`) - 4 known vulnerabilities in local runtime version. Suggested fix: upgrade build/runtime toolchain to patched Go release. Effort: 2-4h.

### Important (should fix before v1.0)
- `internal/api/openapi.go` - OpenAPI covers only subset of live endpoints. Effort: 12-18h.
- `internal/api/server.go` - method guards missing on several handlers (`handleRoles`, docs/status helpers). Effort: 4-8h.
- `internal/cluster/raft/rpc.go:201/225/249` - binary encoding of non-fixed structs flagged by staticcheck. Effort: 8-16h.
- `internal/cluster/gossip.go:409/421/445/567` - silent panic swallowing in callbacks. Effort: 3-6h.
- `files/SPECIFICATION.md`, `files/IMPLEMENTATION.md`, `README.md` - architecture/docs drift. Effort: 10-16h.

### Minor (nice to fix)
- `web/src/pages/login.tsx:34`, `web/src/pages/users.tsx:145-147` - icon-only controls missing explicit a11y labels. Effort: 1-2h.
- `web/src/lib/api.ts:16` - unsafe unconditional JSON decode on all responses. Effort: 1-3h.
- `internal/transfer/slave.go:415-440` - unused context parameter in AXFR path. Effort: 2-4h.

## 9. Metrics Summary Table

| Metric | Value |
|---|---|
| Total Go Files | 294 |
| Total Go LOC | 138,087 |
| Total Frontend Files | 34 (`web/src` code files) |
| Total Frontend LOC | 3,560 |
| Test Files | 156 |
| Test Coverage (estimated) | High package-level coverage in short run; full pipeline blocked by chaos failures |
| External Go Dependencies | 0 |
| External Frontend Dependencies | 21 direct (9 prod + 12 dev) |
| Open TODOs/FIXMEs | 4 TODOs in project code (`test/chaos`) |
| API Endpoints | 38 route registrations (including dynamic/spa/static handlers) |
| Spec Feature Completion | ~72% (core runtime complete, major doc/cluster/gRPC gaps remain) |
| Task Completion | Not reliably measurable from `TASKS.md`; tracking format is stale/priority-based |
| Overall Health Score | 6.8/10 |
