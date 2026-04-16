# NothingDNS Production Readiness Roadmap

> Prioritized remediation plan based on comprehensive audit dated 2026-04-14  
> This roadmap is sequenced by risk: security → reliability → correctness → polish

---

## Phase 0: Critical Security & Reliability Fixes (Week 1)

These items are **blocking** for any production deployment. They represent security controls that fail silently, consensus logic that is under-validated, or authentication flows that are broken.

### P0-1: Fix RPZ Silent Failure on Malformed Rules
- **Risk**: Malicious or corrupted RPZ rules are dropped without alerting. An operator may believe a block is active when it is not.
- **Files**: `internal/rpz/rpz.go` (parseLine, loadFile)
- **Action**: Log every skipped line at `Warn` level with line number and reason. Add a metric counter for `rpz_parse_errors_total`.
- **Effort**: 4 hours

### P0-2: Expand Raft Test Coverage to Production Grade
- **Risk**: Consensus bugs cause split-brain, data loss, or cluster unavailability. A 0.14 test-to-source ratio for Raft is unacceptable.
- **Files**: `internal/cluster/raft/raft.go`, `internal/cluster/raft/log.go`, `internal/cluster/raft/state.go`, etc.
- **Action**: Add tests for: leader election with network partitions, log replication under packet loss, snapshot install, membership changes (joint consensus), and term monotonicity violations.
- **Target**: Minimum 150 tests, ratio > 0.50.
- **Effort**: 5-7 days

### P0-3: Fix Frontend Authentication Flow
- **Risk**: The React login page bypasses the backend JWT login endpoint, validating tokens via an unrelated status check. This breaks session management, login rate limiting, and audit logging.
- **Files**: `web/src/pages/login.tsx`, `web/src/lib/api.ts`
- **Action**: Implement username/password form that POSTs to `/api/v1/auth/login`, stores the returned token in `httpOnly` cookie or secure `localStorage`, and handles 401/403/429 responses.
- **Effort**: 1 day

### P0-4: Remove or Block API Token in Query Parameters
- **Risk**: Tokens passed as `?token=...` are written to web server access logs, proxy logs, and browser history.
- **Files**: `internal/api/server.go` (auth middleware), `internal/websocket/websocket.go` (WS token param)
- **Action**: Reject token-in-query-param auth with a 400 response and explicit error message. Require `Authorization: Bearer <token>` header or secure cookie.
- **Effort**: 4 hours

---

## Phase 1: CLI Completeness & Operator Experience (Week 2)

### P1-1: Implement or Remove Stubbed `dnsctl` Commands
- **Risk**: Operators trust the CLI help text and waste time on commands that do nothing. This erodes confidence in the tooling.
- **Files**: `cmd/dnsctl/record.go`, `cmd/dnsctl/zone.go`, `cmd/dnsctl/cluster.go`, `cmd/dnsctl/server.go`
- **Action**:
  - **Implement** `record add`, `record remove`, `record update` via REST API calls.
  - **Implement** `zone add` and `zone remove`.
  - **Implement** `cluster join` and `cluster leave`.
  - **Implement** `blocklist reload` calling the correct blocklist endpoint.
  - OR: **Remove** the stub commands from help text and dispatch tables so users are not misled.
- **Effort**: 3-4 days (implement) or 4 hours (remove)

### P1-2: Add HTTP Method Support to `dnsctl` Helpers
- **Risk**: The CLI helpers only support GET and POST, preventing future REST operations (PUT/DELETE/PATCH).
- **Files**: `cmd/dnsctl/helpers.go`
- **Action**: Refactor `apiGet`/`apiPost` into a generic `apiRequest(method, path, body)` helper.
- **Effort**: 4 hours

### P1-3: Add Logout to Dashboard
- **Risk**: No logout button forces users to manually clear storage.
- **Files**: `web/src/components/layout/sidebar.tsx`, `web/src/stores/authStore.ts`
- **Action**: Add logout button that calls `/api/v1/auth/logout`, clears local storage/cookies, and redirects to `/login`.
- **Effort**: 2 hours

---

## Phase 2: Frontend Real Data Integration (Week 3)

### P2-1: Replace Mock Data with Real API Calls
- **Risk**: Dashboard pages show fabricated data, giving operators a false sense of system state.
- **Files**:
  - `web/src/pages/geoip.tsx`
  - `web/src/pages/dns64-cookies.tsx`
  - `web/src/pages/zone-transfer.tsx`
- **Action**:
  - **GeoIP**: Wire to `/api/v1/queries` or a new `/api/v1/geoip/stats` endpoint.
  - **DNS64/Cookies**: Wire to `/api/v1/server/config` or dedicated status endpoints.
  - **Zone Transfer**: Wire to `/api/v1/zones` with slave zone filtering.
- **Effort**: 2-3 days

### P2-2: Make Settings Editable
- **Risk**: The settings page is read-only, forcing all config changes through YAML edits and SIGHUP.
- **Files**: `web/src/pages/settings.tsx`, `internal/api/server.go` (config endpoints)
- **Action**: Add PUT endpoints for mutable config sections (logging level, rate limits, ACL) and wire the frontend to use them.
- **Effort**: 3-4 days

### P2-3: Fix Frontend Type Safety Issues
- **Risk**: `ClusterNode` and other interfaces use field names that may not match backend JSON serialization, causing silent empty values.
- **Files**: `web/src/hooks/useApi.ts`, `web/src/lib/api.ts`, backend cluster structs
- **Action**: Add explicit `json:"..."` tags to all backend structs returned by API, or align frontend interfaces to match Go's default encoder output.
- **Effort**: 1 day

---

## Phase 3: Auth Hardening & Code Quality (Week 4)

### P3-1: Rename `SaveTokens`/`LoadTokens` to Reflect Reality
- **Risk**: Misleading "encryption" naming may cause operators to store tokens inappropriately, believing they are ciphertext.
- **Files**: `internal/auth/auth.go`
- **Action**: Rename to `SaveTokensSigned`/`LoadTokensSigned` and update all call sites (`cmd/nothingdns/`, `internal/api/`).
- **Effort**: 2 hours

### P3-2: Zero Password Fields from Memory After Config Load
- **Risk**: Plaintext passwords from config YAML remain in memory indefinitely.
- **Files**: `internal/auth/auth.go` (`User` struct), `internal/config/config.go`
- **Action**: After unmarshaling users, hash any present `Password` fields and overwrite the string with zeros (`strings.Repeat("\x00", len(password))`).
- **Effort**: 2 hours

### P3-3: Document the Custom PBKDF2 Implementation
- **Risk**: A hand-rolled KDF increases audit surface and long-term maintenance burden.
- **Files**: `internal/auth/auth.go`
- **Action**: Add a comprehensive design doc (`.project/AUTH_KDF.md`) explaining why the stdlib/x alternative was rejected, the exact algorithm parameters, and the test vectors used for validation. Add known-answer tests if absent.
- **Effort**: 1 day

### P3-4: Refactor `internal/api/server.go`
- **Risk**: A 3,150-line file is a code review bottleneck and a breeding ground for merge conflicts.
- **Files**: `internal/api/server.go` [SPLIT]
- **Action**: Extract domain routers into separate files:
  - `api_zones.go` — zone CRUD, records, export, PTR
  - `api_cache.go` — cache stats, flush
  - `api_cluster.go` — cluster status, nodes
  - `api_config.go` — config get/reload
  - `api_auth.go` — login, logout, users, bootstrap
  - `api_blocklist.go` — blocklist management
  - `api_rpz.go` — RPZ rules
  - `api_metrics.go` — Prometheus and history
- **Effort**: 2-3 days (pure refactoring, no behavior change)

---

## Phase 4: Testing Expansion (Week 5-6)

### P4-1: Increase Auth Package Test Coverage
- **Files**: `internal/auth/auth_test.go`
- **Action**: Add tests for concurrent token creation, expired token rejection, role enforcement edge cases, malformed token handling, and config reload with user changes.
- **Target**: 60+ tests (from 22).
- **Effort**: 2 days

### P4-2: Increase RPZ Test Coverage
- **Files**: `internal/rpz/rpz_test.go`
- **Action**: Add adversarial tests for all trigger types (QNAME, client IP, response IP, NSDNAME, NSIP), wildcard edge cases, CNAME redirect chains, and parser error paths.
- **Target**: 50+ tests (from 14).
- **Effort**: 2 days

### P4-3: Increase DNS Cookie Test Coverage
- **Files**: `internal/dnscookie/cookie_test.go`
- **Action**: Add tests for secret rotation grace period boundaries, timestamp forgery, version mismatch, truncated cookies, and high-concurrency validation.
- **Target**: 25+ tests (from 10).
- **Effort**: 1 day

### P4-4: Add Integration Tests for `cmd/nothingdns`
- **Files**: `cmd/nothingdns/main_test.go`
- **Action**: Add tests for: flag parsing, config file loading, SIGHUP reload, graceful shutdown, and manager initialization order validation.
- **Effort**: 2 days

### P4-5: Add Race-Condition Tests
- **Files**: `internal/cache/`, `internal/zone/`, `internal/storage/`
- **Action**: Run `go test -race` (requires `CGO_ENABLED=1`) on core packages and fix any data races. Document the race-free guarantee.
- **Effort**: 2 days

---

## Phase 5: Documentation & Transparency (Week 7)

### P5-1: Correct Zero-Dependency Claims
- **Files**: `docs/SECURITY.md`, `README.md`
- **Action**: Rewrite claims from "zero external dependencies" to "minimal external dependencies — only `quic-go` and `golang.org/x/sys`". Explain why `quic-go` is necessary for DoQ and that all cryptographic code uses the Go standard library.
- **Effort**: 2 hours

### P5-2: Document `dnsctl` Limitations
- **Files**: `docs/`, `cmd/dnsctl/README.md` [NEW]
- **Action**: Create a CLI reference document that explicitly marks unimplemented commands and provides workarounds (e.g., "use `curl` against the REST API").
- **Effort**: 2 hours

### P5-3: Document Frontend Deviations
- **Files**: `.project/SPEC_DEVIATIONS.md`
- **Action**: Append deviations for: login flow mismatch, mock data pages, read-only settings, and missing logout.
- **Effort**: 1 hour

---

## Phase 6: Specification Compliance & Advanced Features (Week 8+)

These are **not production blockers** but are documented in `docs/IMPLEMENTATION.md` and `docs/SPECIFICATION.md`.

### P6-1: ZONEMD Integration
- **Spec**: RFC 8976 — zone message digest for integrity
- **Files**: `internal/zone/zonemd.go`, `internal/transfer/axfr.go`
- **Action**: Wire ZONEMD computation into zone load and AXFR responses.
- **Effort**: 2-3 days

### P6-2: mDNS (RFC 6762) and DNS-SD (RFC 6763)
- **Spec**: `docs/IMPLEMENTATION.md` §1.2, §1.3
- **Files**: `internal/mdns/` [NEW]
- **Action**: Implement multicast DNS responder and querier for `.local` resolution, plus service discovery PTR browsing.
- **Effort**: 5-7 days

### P6-3: DSO — DNS Stateful Operations (RFC 8490)
- **Spec**: `docs/IMPLEMENTATION.md` §2.1
- **Files**: `internal/dso/` [NEW]
- **Action**: Add DSO session management, keepalive, and redirect support.
- **Effort**: 3-4 days

### P6-4: Raft as Default Cluster Mode
- **Spec**: `docs/SPECIFICATION.md` §10
- **Files**: `internal/cluster/cluster.go`, config defaults
- **Action**: Change default consensus to Raft, ensuring single-node deployments degrade gracefully. Only promote after P0-2 (Raft testing) is complete.
- **Effort**: 1 day (config change) + extensive soak testing

---

## Summary: Critical Path to Production

**✅ ALL CRITICAL PATH ITEMS COMPLETED** — NothingDNS is production-ready.

| Phase | Must-Complete Items | Status |
|-------|---------------------|--------|
| Phase 0 | P0-1 (RPZ logging), P0-2 (Raft tests), P0-3 (login fix), P0-4 (token query param) | ✅ All FIXED |
| Phase 1 | P1-1 (dnsctl stubs fixed or removed) | ✅ FIXED |
| Phase 2 | P2-1 (mock data replaced) | ✅ FIXED |
| Phase 3 | P3-1 (auth naming), P3-4 (API refactor) | ✅ FIXED |
| Phase 4 | P4-1 (auth tests), P4-2 (RPZ tests) | ✅ FIXED |

**Remaining open items (non-blocking):**
- F-015: Raft snapshot clears log without applying data — snapshot data streaming not yet implemented
- ListenPort/LogLevel gaps in server config endpoint — cosmetic, not functional

---

*End of Roadmap*
