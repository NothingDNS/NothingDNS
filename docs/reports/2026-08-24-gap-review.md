# NothingDNS Production-Readiness Gap Report

**Subject:** Full-system review of the working tree at `main` (baseline commit `bcd1038` + fixes from this session, 2026-08-24)
**Prepared by:** WrongStack agent (session of 2026-08-24)

---

## 1. Scope and method

A full production-readiness review of the NothingDNS tree: prior-gap reconciliation (the 8 open items from the 2026-07-29 gap analysis), a fresh sweep of the core runtime paths (`cmd/nothingdns` main/handler/pipeline, `internal/api`, `internal/transfer`, `internal/server`, `internal/websocket`, `internal/doh`, `internal/dashboard`), dependency/vulnerability scanning, and remediation of confirmed defects with regression tests.

Every claim below is anchored to a command run or file read this session.

---

## 2. Baseline (verified, before changes)

| Gate | Result |
|---|---|
| `git status` | clean working tree on `main`, up to date with `origin/main` (`bcd1038`) |
| `make ci` (fmt + vet + staticcheck 2025.1.1 + tests + build) | ✅ all 38 Go packages pass |
| Web dashboard `npm test` | ✅ 196/196 |
| `govulncheck ./...` | ✅ 0 reachable vulnerabilities (1 module-level advisory, not imported) |
| `npm audit --omit=dev` | ✅ 0 vulnerabilities |

---

## 3. Prior-gap reconciliation (2026-07-29 gap list, 8 items)

| # | Item | Status (verified this session) |
|---|---|---|
| 1 | react-router HIGH CVEs (GHSA-qwww-vcr4-c8h2) | **Fixed upstream** — now `react-router@^8.3.0`, `npm audit` clean |
| 2 | `context.TODO()` in `pipeline.go:106` | **Not a production defect** — fallback branch only; `serverCtx` is always wired (`main.go:499` → handler at `main.go:748`), so the branch is reachable only in tests. Comment documents this accurately. |
| 3 | No preStop hook in Helm | **Fixed upstream** — `deploy/helm/nothingdns/templates/deployment.yaml:148` |
| 4 | Custom OTel exporter vs official SDK | **Fixed upstream** — `internal/otel/tracing.go` uses the official `go.opentelemetry.io/otel/sdk/trace` + OTLP HTTP exporter |
| 5 | No Grafana dashboard | **Fixed upstream** — `deploy/grafana/nothingdns-overview.json` |
| 6 | dnsctl dnssec functions at 0% coverage | **Fixed upstream** — all dnssec.go functions now 60–100% (`go tool cover` this session) |
| 7 | No aggregate AXFR/IXFR byte cap | **Fixed upstream** — `maxTransferBytes = 512 << 20` enforced in `axfr.go:620` and `ixfr.go:596` |
| 8 | Per-zone RBAC | **Open by design** — global 3-tier RBAC (viewer/operator/admin) is enforced server-side with privilege-escalation guards (`api_auth.go:317-324`). Per-zone scoping is a multi-tenant roadmap feature, not a single-tenant readiness gap. |

---

## 4. New defects found this session — all fixed

All three were in one feature path: the CSP violation-report endpoint that the server's own `Content-Security-Policy` header advertises via `report-uri /api/v1/csp-report` (`internal/api/server.go:934`).

### GAP-A (functional, medium): every real CSP report was rejected with 401

Browsers submit CSP violation reports automatically, with no credentials. The endpoint was not in `authMiddleware`'s public-path list, and POST is not a "safe method" so the cookie fallback did not apply either — the CSP header advertised an endpoint that 401'd on every legitimate submission. CSP violation monitoring was non-functional in any authenticated deployment.

**Fix:** explicit auth-skip for `/api/v1/csp-report` in `authMiddleware`, with the rationale documented inline.

### GAP-B (security, medium): unbounded request-body decode on that endpoint

`json.NewDecoder(r.Body)` with no size cap. The code comment claimed safety from a "server-level ReadLimit (10MB)" — **no such mechanism exists**; `http.Server.ReadTimeout` (10s) bounds transfer *duration*, not allocation. A fast client could push hundreds of MB into the decoder. Every other JSON endpoint in the package already used the project's own capped `decode()` helper (`server.go:1567`, `maxBodyBytes = 64KB`).

**Fix:** `http.MaxBytesReader(w, r.Body, maxBodyBytes)` — same cap as every other endpoint. Defense-in-depth: the endpoint also sits behind the per-IP API rate limiter (applies to all `/api/` paths before auth).

### GAP-C (functional, low): wrong wire schema — reports decoded to empty strings

Per W3C CSP Level 2/3 §5, browsers POST `{"csp-report": {…}}` — the report fields are nested one level under the `"csp-report"` key. The handler decoded the fields at the top level, so even a report that survived auth and decode produced all-empty log lines.

**Fix:** new `cspReportBody` envelope type (`internal/api/response.go`); a body with no recognizable report fields is now dropped silently instead of logged as an empty violation.

**Regression tests:** 5 new tests in `internal/api/csp_report_test.go` covering: no-credentials acceptance behind the real auth middleware, envelope decoding, oversized-body rejection, non-report JSON, wrong method.

---

## 5. Areas swept and found clean (verified, not assumed)

- **Constant-time comparisons:** TSIG MAC via `hmac.Equal` (`transfer/tsig.go:594`); legacy auth token via SHA-256 digest + `ConstantTimeCompare` with explicit length-oracle hardening (`server.go:1091-1095`).
- **WebSocket hardening:** custom frame reader enforces 16KB frame cap, non-minimal length encoding rejection, uint64→int sign-flip bound (L-1), client masking, per-connection rate limits, read deadlines.
- **DoH/DoWS/ODoH body limits:** three independent layers (`MaxBytesReader` + `LimitReader` at `MaxDNSMessageSize+1`).
- **SPA static serving:** `embed.FS` via `http.FS` — `fs.ValidPath` rejects `..` traversal by construction; no filesystem access at all.
- **HTTP server hygiene:** `ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout`/`IdleTimeout` all set; rate-limiter cleanup goroutine has a WaitGroup + stop channel and starts only after the listener binds.
- **No `panic(` in any non-test production code**; pipeline has per-request recover with EDE-tagged SERVFAIL.
- **Outbound HTTP:** all production `http.Client`s carry timeouts; blocklist fetcher re-validates every redirect hop against SSRF policy (comment-verified at `blocklist.go:102-117`).
- **Repo hygiene:** build artifacts, coverage, cache, journals all gitignored.
- **Wildcard-CORS reflection** (`allowed_origins: ["*"]` reflects any Origin): analyzed — safe because `Access-Control-Allow-Credentials` is never emitted and cookie auth is same-origin/safe-method-only. Operator opt-in; documented behavior.

---

## 6. Verification of the fixes

| Command | Result |
|---|---|
| `go test ./internal/api/ -run TestCSPReport -v` | 5/5 pass |
| `make ci` (full gate: fmt, vet, staticcheck, all tests, build) | ✅ all 38 packages |
| `go test -race ./internal/api/` | ✅ clean |

**Diff:** `internal/api/response.go` (+8), `internal/api/server.go` (+29/−4), `internal/api/csp_report_test.go` (new, 138 lines). No other files touched.

---

## 7. Remaining known limitations (documented, not blocking)

Carried from `docs/reports/2026-08-22-verification-0ebf409.md` §8, unchanged by this session:

1. No load/soak testing — throughput, memory stability under load, failover timing unmeasured.
2. Helm chart template-validated but not deployed against a real cluster.
3. mDNS multicast handlers and raft RPC internals deliberately untested in CI (rationale recorded in the 2026-08-22 report).
4. Per-zone RBAC remains a multi-tenant roadmap feature (§3 item 8).
5. `handler.go` (1076 lines) and `main.go` (1552 lines) exceed the ~200-line single-responsibility guidance — a maintainability concern, deliberately not churned in this pass.

---

## 8. Conclusion

Of the 8 prior gaps, 6 were already fixed upstream, 1 was a non-defect (test-only code path), and 1 is roadmap scope. The fresh sweep found a cluster of 3 real defects in one feature path (CSP reporting) — a broken-by-401 advertised endpoint, an unbounded-body DoS surface, and a wrong wire schema — all fixed with regression tests this session. All quality gates remain green: 38 Go packages, 196 web tests, race detector, govulncheck, npm audit.

No evidence exists of further unresolved defects in the paths swept. As with any finite review, absence of found bugs is not proof of absence — the boundaries in §7 are the honest edge of this report's claims.
