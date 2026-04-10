# Project Roadmap

> Based on comprehensive codebase analysis performed on 2026-04-10
> This roadmap prioritizes work needed to bring the project to production quality.

## Current State Assessment
- Core DNS functionality is broad and largely implemented (authoritative + recursive + DNSSEC + encrypted transports).
- Short test suite is healthy, but full test run fails due chaos suite failures, so release confidence is lower than apparent package coverage.
- Security posture is mixed: strong auth/rate-limit foundations but concrete issues remain (CORS semantic mismatch, token handling in query string/non-HttpOnly frontend cookie path, stale docs).

Key blockers for production readiness:
- Full test pipeline instability (`test/chaos`).
- Security/behavior mismatches in API auth+CORS boundaries.
- Spec/docs drift causing operational confusion.
- Toolchain patching required (govulncheck stdlib findings on local Go 1.26.1).

What is working well:
- Zero external Go dependencies.
- Clean package architecture and robust subsystem separation.
- Good CI/CD skeleton (lint/test/build/docker).

## Phase 1: Critical Fixes (Week 1-2)
### Must-fix items blocking basic functionality
- [ ] Stabilize `test/chaos` so `go test ./... -count=1` is green on supported platforms.
  - Affected: `test/chaos/chaos_test.go`
  - Effort: 16-24h
- [ ] Resolve CORS policy contradiction between config docs and middleware behavior.
  - Affected: `internal/config/config.go:420-422`, `internal/api/server.go:572-584`, `internal/api/*test.go`
  - Effort: 6-10h
- [ ] Remove WebSocket token query fallback and move to header/cookie-only auth.
  - Affected: `internal/dashboard/server.go:253-263`, `web/src/hooks/useWebSocket.ts:24-27`
  - Effort: 6-10h
- [ ] Patch Go runtime/toolchain to version containing fixes for GO-2026-4947/4946/4870/4866.
  - Affected: build/CI images, local toolchain docs
  - Effort: 2-4h

## Phase 2: Core Completion (Week 3-6)
### Complete missing core features from specification
- [ ] Decide cluster product direction and align implementation:
  - Option A: SWIM-only and remove raft promises from docs.
  - Option B: Fully wire raft mode in config and manager path.
  - Affected: `internal/config/config.go`, `cmd/nothingdns/cluster_manager.go`, `internal/cluster/*`
  - Effort: 24-60h (depends on option)
- [ ] Close gRPC inter-node gap or formally remove from spec.
  - Spec reference: `files/SPECIFICATION.md` section on gRPC inter-node (`line ~724+`)
  - Current gap: docs promise paths not present (`internal/api/grpc` missing)
  - Effort: 20-80h (implement) or 6-10h (de-scope + doc correction)
- [ ] Normalize API method contracts for ANY handlers.
  - Affected: `internal/api/server.go` (`handleRoles`, `handleDashboardStats`, docs endpoints)
  - Effort: 6-12h

## Phase 3: Hardening (Week 7-8)
### Security, error handling, edge cases
- [ ] Add strict request body size limits and JSON unknown-field rejection on sensitive endpoints.
  - Affected: `internal/api/server.go`
  - Effort: 8-14h
- [ ] Add security headers middleware (HSTS, X-Frame-Options, CSP baseline, X-Content-Type-Options).
  - Affected: `internal/api/server.go`, dashboard routes
  - Effort: 6-12h
- [ ] Replace silent `defer recover()` blocks with logged recovery and failure counters.
  - Affected: `internal/cluster/gossip.go`
  - Effort: 3-6h
- [ ] Fix staticcheck correctness warnings in raft transport serialization.
  - Affected: `internal/cluster/raft/rpc.go`
  - Effort: 8-16h

## Phase 4: Testing (Week 9-10)
### Comprehensive test coverage
- [ ] Keep full suite green under `go test ./... -count=1` in CI and locally on at least Linux and Windows.
- [ ] Add deterministic chaos tests with explicit fault injection controls.
- [ ] Add API integration tests for auth/CORS/security header contracts.
- [ ] Add frontend component tests (Vitest + RTL) for login, auth guard, and major pages.
- [ ] Add minimal frontend e2e smoke tests (Playwright) for dashboard load and auth flow.

Effort: 40-64h

## Phase 5: Performance & Optimization (Week 11-12)
### Performance tuning and optimization
- [ ] Address allocation hot spots flagged by staticcheck (`SA6002`) in server/upstream paths.
- [ ] Profile protocol pack/unpack and upstream query path with pprof benchmarks.
- [ ] Add route-level lazy loading in React app to reduce initial bundle JS.
- [ ] Add API response compression where appropriate.

Effort: 24-40h

## Phase 6: Documentation & DX (Week 13-14)
### Documentation and developer experience
- [ ] Reconcile README/SPEC/IMPLEMENTATION/TASKS with actual architecture and current license.
- [ ] Extend OpenAPI spec to cover all live API endpoints.
- [ ] Document platform prerequisites for race tests (CGO/gcc requirements).
- [ ] Convert `TASKS.md` from priority-only list to true status tracking.

Effort: 24-36h

## Phase 7: Release Preparation (Week 15-16)
### Final production preparation
- [ ] Enforce full quality gate in CI:
  - `go build ./...`
  - `go vet ./...`
  - `go test ./... -count=1`
  - `go test ./... -short -count=1`
  - `staticcheck ./...`
  - frontend lint/build/tests
- [ ] Validate Docker production image with hardened runtime config.
- [ ] Finalize release automation and signed artifact policy.
- [ ] Establish monitoring alert thresholds and runbooks.

Effort: 24-36h

## Beyond v1.0: Future Enhancements
### Features and improvements for future versions
- [ ] Route-splitting and performance budgets in dashboard frontend.
- [ ] Optional OpenTelemetry tracing integration.
- [ ] More deterministic chaos/fault simulation framework.
- [ ] Multi-node upgrade/rollback orchestration tooling.

## Effort Summary
| Phase | Estimated Hours | Priority | Dependencies |
|---|---:|---|---|
| Phase 1 | 30-48h | CRITICAL | None |
| Phase 2 | 44-140h | HIGH | Phase 1 |
| Phase 3 | 25-48h | HIGH | Phase 1 |
| Phase 4 | 40-64h | HIGH | Phase 1-3 |
| Phase 5 | 24-40h | MEDIUM | Phase 4 |
| Phase 6 | 24-36h | MEDIUM | Phase 2-4 |
| Phase 7 | 24-36h | HIGH | Phase 1-6 |
| **Total** | **211-412h** |  |  |

## Risk Assessment
| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Chaos suite remains unstable and blocks releases | High | High | Rewrite with deterministic fault injection and stable SLO-based assertions |
| Security regression while changing auth/CORS behavior | Medium | High | Add contract tests before refactor, release behind config flag |
| Raft/SWIM direction remains unresolved and stalls roadmap | Medium | High | Decision milestone in Week 3 with explicit de-scope or full implementation plan |
| Docs continue drifting from implementation | High | Medium | Treat docs parity as release gate in CI review checklist |
| Toolchain vulnerabilities reappear | Medium | Medium | Pin patched Go versions in CI and container builds |
