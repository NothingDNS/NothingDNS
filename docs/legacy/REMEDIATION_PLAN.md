# NothingDNS — Remediation & Execution Plan

**Status:** Active — see completion notes below  
**Derived from:** `./PROJECT_AUDIT_REPORT.md` (2026-07-15)  

---

> ## ⚠️ HISTORICAL — DO NOT TREAT AS ACTIVE WORK
>
> **Derived-from date:** 2026-07-15 (single-point-in-time audit).
> Every Phase 0 (Quick-Wins) item in the table below shipped before this
> banner was added. The longer-phase items (Phase 1+ structural refactors,
> fuzz campaigns, etc.) were either completed in subsequent commits or
> superseded by post-2026-07-15 work.
>
> **For the current state of the project**, see:
> - `./PROJECT_AUDIT_REPORT.md` (the historical snapshot this plan was derived from — also bannered as historical)
> - `security-report/SECURITY-REPORT.md` (security findings & remediation status)
> - `docs/PRODUCTION_READINESS.md` (current production-readiness checklist)
> - `docs/CHANGELOG.md` (post-2026-07-15 changes)
>
> The plan body below is preserved unchanged for the historical record.
> Nothing here is expected to be picked up as new work without independent
> verification against the current codebase.

---

## Completed

| ID | Task | Status | Commit |
|----|------|--------|--------|
| QW-1 | Remove stray `web/go.mod` | ✅ Done | `1459c26` |
| QW-2 | Remove orphaned `web/pnpm-workspace.yaml` | ✅ Done | `1459c26` |
| QW-3 | Git-ignore `cover/*.out` | ✅ Already done | pre-existing |
| QW-4 | Move NOTHING.md, PRODUCTION_READINESS.md → `docs/legacy/` | ✅ Done | `1459c26` |
| **CR-1** | **Extract `run()` reload logic** | **✅ Done** | **`768a4bf`** |
| **H-1** | **Group handler fields into sub-structs** | **✅ Done** | **`e15f174`** |

---

## Phase 0 — Quick Wins (Housekeeping)

> Estimated effort: **0.5 day** · No behavioural changes · Low risk

| ID | Task | File(s) | Effort | Verification |
|----|------|---------|--------|-------------|
| **QW-1** | Remove stray `web/go.mod` | `web/go.mod` | 5 min | `go build ./...` still passes |
| **QW-2** | Resolve npm/pnpm mismatch — remove `web/pnpm-workspace.yaml`, keep npm | `web/pnpm-workspace.yaml` | 5 min | `cd web && npm ci && npm run build` passes |
| **QW-3** | Add `cover/*.out` to `.gitignore` and `git rm --cached` existing files | `.gitignore` + `git rm cover/*.out` | 10 min | `git status` shows no tracked `.out` files |
| **QW-4** | Remove stale `docs/archive/` documents or move to a dedicated archive branch | `docs/archive/*` | 30 min | Only current docs remain in `docs/` |

**Dependencies:** None. All four are independent and safe.

---

## Phase 1 — Archive & Documentation Hygiene

> Estimated effort: **1 day** · No behavioural changes · Low risk

| ID | Task | File(s) | Effort | Verification |
|----|------|---------|--------|-------------|
| **DH-1** | Audit `docs/archive/` — move NOTHING.md, PRODUCTION_READINESS.md, REFACTOR_PLAN_2026-06-15 to a `docs/legacy/` directory with a README noting their historical nature | `docs/archive/` → `docs/legacy/` | 30 min | Remaining docs are current |
| **DH-2** | Audit `.project/` — separate internal planning documents from authoritative docs; move spec/sdd content into `docs/` where missing | `.project/` files | 1 hr | Every `.project/` doc has a clear purpose statement or has been merged into `docs/` |
| **DH-3** | Add prominent operator-facing note about `http.bind: "0.0.0.0:8080"` default — recommend binding to `127.0.0.1` behind a reverse proxy or enabling TLS | `config.example.yaml`, `docs/CONFIG_REFERENCE.md`, `docs/SECURITY.md` | 30 min | Default-bind warning present in all three files |
| **DH-4** | Document CORS wildcard-origin mitigation more prominently — make it clear that production mode rejects wildcard origins on public binds | `docs/SECURITY.md`, `docs/CONFIG_REFERENCE.md` | 30 min | Mitigation described under "API Security" |

**Dependencies:** QW-4 (archive clean-up feeds DH-1).

---

## Phase 2 — Structural Refactoring (Core)

> Estimated effort: **2–3 days** · Moderate risk · Requires careful testing

### P2-A: Refactor `run()` — extract SIGHUP handler and API reload callback

**Problem:** `run()` is 812 lines (`cmd/nothingdns/main.go:373-1148`). The SIGHUP block (lines 1057–1146) and API reload callback (lines 760–858) share ~70% of their logic — different control flow envelopes around the same zone/upstream/security reload sequence.

**Plan:**

```
run()
├── Phase 1: init managers (keep in run())
├── Phase 2: start servers (keep in run())
├── signal loop (keep in run())
└── SIGHUP branch (extract)
         │
         └── reloadConfig(logger, configPath, …) → error
              Performs: loadReloadConfig → prepareConfiguredZoneFiles
                        → prepareConfiguredViews → prepareUpstreamComponents
                        → reloadSecurityComponents → apply*
                        → commitLoadedConfig → audit log

API /reload handler:
         └── (call the same reloadConfig)

Shutdown sequence:
         └── extract into shutdownServer(cfg, …) → error
```

| Step | What | File | Effort |
|------|------|------|--------|
| 1 | Extract the `loadReloadConfig → prepare* → reloadSecurity → apply* → commit` sequence into `reloadConfig(ctx, cfgPath, current, …) error` | `cmd/nothingdns/main.go` | 1 hr |
| 2 | Replace the SIGHUP body and the API reload callback body with calls to `reloadConfig()` | `cmd/nothingdns/main.go` | 30 min |
| 3 | Extract shutdown sequence (lines 965–1055) into `shutdownServer(shutdownCtx, components, …) error` | `cmd/nothingdns/main.go` | 30 min |
| 4 | `go vet ./...`, `go test ./... -short`, manual review of the extracted function signatures | — | 30 min |

**Total: 2.5 hr**

### P2-B: Refactor `integratedHandler` — extract sub-structs

**Problem:** 25+ fields in a single struct with no constructor validation (`cmd/nothingdns/handler.go:52-99`).

**Plan:**

```go
type SecurityComponents struct {
    Blocklist   *blocklist.Blocklist
    RPZEngine   *rpz.Engine
    GeoEngine   *geodns.Engine
    ACLChecker  *filter.ACLChecker
    RateLimiter *filter.RateLimiter
    RRL         *filter.RRL
    DNSSyn      *dns64.Synthesizer
}

type TransferComponents struct {
    AXFRServer    *transfer.AXFRServer
    IXFRServer    *transfer.IXFRServer
    NotifyHandler *transfer.NOTIFYSlaveHandler
    DDNSHandler   *transfer.DynamicDNSHandler
    SlaveManager  *transfer.SlaveManager
}

// NewIntegratedHandler validates every required field is non-nil.
func NewIntegratedHandler(cfg *config.Config, logger *util.Logger, cache *cache.Cache,
    security *SecurityComponents, transfer *TransferComponents, …) (*integratedHandler, error)
```

| Step | What | File | Effort |
|------|------|------|--------|
| 1 | Define `SecurityComponents`, `TransferComponents`, `CacheComponents` in a new `cmd/nothingdns/components.go` | new file | 30 min |
| 2 | Replace inline fields in `integratedHandler` with the sub-structs + update all references | `cmd/nothingdns/handler.go` + all files referencing handler fields | 1.5 hr |
| 3 | Write `NewIntegratedHandler()` with nil-check validation | `cmd/nothingdns/handler.go` | 30 min |
| 4 | Update `run()` to use `NewIntegratedHandler()` instead of the literal struct init | `cmd/nothingdns/main.go` | 30 min |
| 5 | `go test ./... -short`, `go vet ./...`, `go build ./...` | — | 30 min |

**Total: 3.5 hr**

### P2-C: Audit `context.Background()` usage in production goroutines

**Problem:** Several goroutines in `run()` and transport start functions use `context.Background()` instead of `serverCtx`, so they don't receive cancellation on shutdown.

| Step | What | Effort |
|------|------|--------|
| 1 | `grep -rn 'context.Background()' cmd/ internal/` — catalogue every usage | 15 min |
| 2 | For each: replace with `serverCtx` (the cancellable root context), or wrap with `context.WithCancel` if it must outlive the server | 30 min |
| 3 | Verify graceful shutdown still works: start server, send SIGINT, confirm no leaked goroutines | 30 min |

**Total: 1.25 hr**

---

## Phase 3 — Testing & Quality

> Estimated effort: **3–5 days** · Low-to-moderate risk

### P3-A: Frontend unit tests (Vitest + React Testing Library)

**Problem:** `web/src/` has zero unit tests.

| Step | What | Files | Effort |
|------|------|-------|--------|
| 1 | Install Vitest, @testing-library/react, @testing-library/jest-dom, jsdom | `web/package.json` | 15 min |
| 2 | Create `web/vitest.config.ts` extending Vite config | new file | 15 min |
| 3 | Add `npm run test` script and wire into CI (`web.yml`) | `web/package.json`, `.github/workflows/web.yml` | 15 min |
| 4 | Write tests for critical paths: | | |
| 4a | Auth flow: `LoginPage` renders, submits, handles 401/429 | `web/src/pages/login.tsx` | 1 hr |
| 4b | API error handling: `api()` helper with 401 bounce, JSON error parsing | `web/src/lib/api.ts` | 45 min |
| 4c | Zone CRUD: `ZonesPage` loads, filters, delete confirmation | `web/src/pages/zones.tsx` | 1 hr |
| 4d | Dashboard stats rendering + skeleton states | `web/src/pages/dashboard.tsx` | 45 min |
| 4e | `ErrorBoundary` catches and self-heals on navigation | `web/src/components/error-boundary.tsx` | 30 min |
| 5 | Ensure test suite runs in CI (`web.yml`) and `npm test` is required | CI config | 15 min |

**Total: 4 hr**

### P3-B: API integration tests

**Problem:** API tests use mock zone managers — no test exercises the real HTTP routes against a real zone manager.

| Step | What | Effort |
|------|------|--------|
| 1 | Write `internal/api/integration_test.go` with `httptest.NewServer` | 1.5 hr |
| 2 | Cover: zone CRUD, record CRUD, auth login/logout/bootstrap, status endpoint, blocklist, RPZ | 2 hr |
| 3 | Wire into CI `go.yml` as a separate job step | 15 min |

**Total: 3.75 hr**

### P3-C: YAML parser conformance test suite

**Problem:** The custom YAML parser has no spec-conformance test vectors.

| Step | What | Effort |
|------|------|--------|
| 1 | Add test vectors for: plain scalars, quoted scalars, multi-line strings, null/empty values, anchors/aliases, comments, mixed indentation | 1 hr |
| 2 | Add edge cases relevant to the project's config: env var expansion in all positions, nested sequences, nested mappings | 30 min |
| 3 | Run against `config.example.yaml` and `deploy/helm/*/values.yaml` to ensure real configs parse identically | 30 min |

**Total: 2 hr**

---

## Phase 4 — Security Hardening

> Estimated effort: **2 days** · Low risk (most are documentation + config defaults)

| ID | Task | File(s) | Effort | Verification |
|----|------|---------|--------|-------------|
| **SH-1** | Document `http.bind: "0.0.0.0:8080"` risk and remediation in three places (config example, CONFIG_REFERENCE, SECURITY) | `config.example.yaml`, `docs/CONFIG_REFERENCE.md`, `docs/SECURITY.md` | 30 min | Warning visible in all three |
| **SH-2** | Document CORS wildcard-origin mitigation in SECURITY.md | `docs/SECURITY.md` | 15 min | Section present |
| **SH-3** | Make IXFR journal path configurable (add `journal_dir` to transfer config) | `internal/config/transfer_config.go`, `internal/transfer/ixfr.go`, `internal/transfer/journal.go` | 1 hr | Config option appears in validation and hot-reload |
| **SH-4** | Add prominent note in TROUBLESHOOTING.md about the management API default bind | `docs/TROUBLESHOOTING.md` | 15 min | Note present |
| **SH-5** | Add global connection cap documentation as accepted risk in SECURITY.md | `docs/SECURITY.md` | 15 min | Section present under "Accepted Risks" |

---

## Phase 5 — CI & Tooling

> Estimated effort: **1 day** · Low risk

| ID | Task | File(s) | Effort |
|----|------|---------|--------|
| **CI-1** | Add `npm test` step to `web.yml` (after lint, before build) | `.github/workflows/web.yml` | 15 min |
| **CI-2** | Add `npm run typecheck` (tsc --noEmit) as a required check | `.github/workflows/web.yml` | 15 min |
| **CI-3** | Pin Go version in `go.mod` — if 1.26.5 is unreleased, discuss with maintainer about pinning to 1.24.x | `go.mod` | 15 min (discussion) |
| **CI-4** | Add `go mod verify` step to CI (already in Dockerfile, extend to Go CI) | `.github/workflows/go.yml` | 15 min |
| **CI-5** | Remove `cover/*.out` from git tracking | `.gitignore` + `git rm` | 10 min |

**Dependencies:** CI-1 depends on P3-A (frontend tests existing). CI-5 duplicates QW-3.

---

## Phase 6 — Optional / Strategic

> Estimated effort: **variable** · Higher risk · Requires maintainer decision

| ID | Task | Rationale | Effort Estimate |
|----|------|-----------|----------------|
| **ST-1** | Evaluate migrating to a battle-tested Raft library (e.g., hashicorp/raft) | Custom Raft was security-audited and fixed, but long-term maintenance of a consensus protocol is expensive | 1–2 weeks |
| **ST-2** | Add a CLA to the repository | Enables clear contribution management as the project grows | 1 hr (template) |
| **ST-3** | Evaluate coverage consolidation pattern — are `coverage_test.go` imports inflating numbers? | Honest coverage matters for release decisions | 1 hr |

---

## Execution Order (Recommended)

```
Week 1                      Week 2                   Week 3
┌──────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Phase 0      │    │ Phase 2-A        │    │ Phase 3-A       │
│  QW-1..4      │    │  (extract        │    │  (frontend       │
│  (0.5d)       │    │   run() reload)  │    │   tests)         │
│              │    │                  │    │                 │
│ Phase 1      │    │ Phase 2-B        │    │ Phase 3-B       │
│  DH-1..4      │    │  (handler        │    │  (API integ.     │
│  (1d)         │    │   sub-structs)   │    │   tests)         │
│              │    │                  │    │                 │
│ Phase 4      │    │ Phase 2-C        │    │ Phase 3-C       │
│  SH-1..5      │    │  (context.Back-  │    │  (YAML con-      │
│  (1d)         │    │   ground audit)  │    │   formance)      │
│              │    │                  │    │                 │
│ Phase 5      │    │                  │    │ Phase 6 (if     │
│  CI-1..5      │    │                  │    │  decided)        │
│  (1d)         │    │                  │    │                 │
└──────────────┘    └──────────────────┘    └─────────────────┘
         ↕                    ↕                       ↕
   All can run        Phase 2 must not          Phase 3 must
   in parallel        break CI green            preserve CI green
```

### Phase dependencies (simplified)

```
Phase 0       → Phase 1 (archive cleanup feeds doc review)
Phase 2-A     → nothing (independent)
Phase 2-B     → nothing (independent)
Phase 2-C     → nothing (independent)
Phase 3-A     → Phase 5, CI-1 (test step depends on tests existing)
Phase 3-B     → nothing (independent)
Phase 3-C     → nothing (independent)
Phase 4       → nothing (independent)
Phase 5       → Phase 3-A (CI-1)
Phase 6       → maintainer decision first
```

**Within each phase, execute tasks in the order listed.** No phase strictly blocks another — they operate on disjoint files — so parallel execution is safe as long as each task verifies its own changes (`go vet`, `go test`, `npm test`).

---

## Effort Summary

| Phase | Description | Effort | Risk |
|-------|-------------|--------|------|
| 0 | Quick Wins | 0.5 day | None |
| 1 | Archive & Docs | 1 day | None |
| 2 | Structural Refactor | 2–3 days | Moderate |
| 3 | Testing & Quality | 3–5 days | Low |
| 4 | Security Hardening | 2 days | Low |
| 5 | CI & Tooling | 1 day | Low |
| 6 | Strategic | variable | Higher |
| **Total (1–5)** | | **~10–13 days** | |

---

## Verification Checklist (per phase)

After each phase, run:

```bash
# Go
go build ./...
go vet ./...
go test ./... -count=1 -short
make test-race-critical    # concurrency-heavy packages

# Web
cd web && npm ci && npm run build && npm test && npm run lint

# Git hygiene
git status                 # no accidental tracked artifacts
git diff --stat            # changes scoped to the phase
```

---

## How to use this plan

1. **Single-developer track:** Execute phases in order. Phase 2 is the riskiest — invest extra testing time there.
2. **Parallel tracks:** Assign Phase 0+1+4 to one person, Phase 2 to another, Phase 3 to a third. Disjoint file sets mean no merge conflicts.
3. **CI-first:** Before merging any Phase 2 branch, ensure CI is green. The structural refactors touch the most critical code paths in the server.
4. **Sign off:** After Phase 2, run `make test-full` (including long-running tests), not just `-short`.
