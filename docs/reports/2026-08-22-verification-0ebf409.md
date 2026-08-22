# NothingDNS Verification Report

**Subject:** Verified quality state of commit `0ebf409` on `origin/main`
**Date:** 2026-08-22
**Prepared by:** WrongStack agent (session of 2026-08-21/22)

---

## 1. What this report claims — and what it does not

**Claim established by this report:** at commit `0ebf409` (HEAD of `origin/main`
as of 2026-08-22), every automated quality gate in the project — three GitHub
Actions workflows comprising nine Go jobs plus container and web-dashboard
pipelines — passed in full, the local `make ci` gate passes with a gate set
identical to remote CI, and the measured statement coverage of the Go tree is
**87.8%**, up from 86.1% at session start. Every claim below is traceable to a
run ID, a command, or a commit.

**What no report can claim:** "100% proof of flawless operation" is not a
statement finite test evidence can establish, and this report deliberately does
not make it. What it *can* prove is what was tested, that those tests passed,
and where the boundaries of that evidence lie (§8). Notably, the working session
that produced this state **found and fixed real defects** (§7) — including one
RFC-compliance bug in the DNS answer path — which is itself evidence the gates
have teeth, not that the software is beyond failure.

---

## 2. Headline evidence — GitHub Actions on `0ebf409`

| Workflow | Run ID | Result |
|---|---|---|
| **Go** | [`32557957241`](https://github.com/NothingDNS/NothingDNS/actions/runs/32557957241) | ✅ success — all 9 jobs |
| **Container Image** | [`32557957244`](https://github.com/NothingDNS/NothingDNS/actions/runs/32557957244) | ✅ success |
| **Web Dashboard** | [`32557957390`](https://github.com/NothingDNS/NothingDNS/actions/runs/32557957390) | ✅ success |

All three completed on **first attempt** — no reruns, no flake interventions.

### Go workflow job detail (run 32557957241)

| Job | Result | What it establishes |
|---|---|---|
| `go` | ✅ | Build + vet + full test suite; includes the `gofmt -l` formatting gate |
| `race` | ✅ | Full suite under the Go race detector — no data races detected |
| `coverage` | ✅ | Coverage gate accepted the current profile (87.8%, §4) |
| `security` | ✅ | govulncheck + staticcheck 2025.1.1 + go-errorlint all clean |
| `fuzz` | ✅ | 9 fuzz targets × 30s across 4 steps (§5) |
| `e2e` | ✅ | End-to-end suites (live server, real sockets) |
| `helm` | ✅ | Helm chart template validation |
| `binaries` | ✅ | Release build of `nothingdns` + `dnsctl` (cross-platform artifacts) |
| `actions` | ✅ | Workflow definition lint |

Reproduce: `gh run view 32557957241`

---

## 3. Local gate parity — `make ci` ≡ remote `go` job

`make ci` runs **fmt-check → vet → staticcheck-ci → test → build** — the same
gate set the remote `go` and `security` jobs enforce:

- `fmt-check` added by `2c987a4` (after commit `3a77e97` failed remote CI on a
  formatting-only issue that local `make ci` then missed)
- `staticcheck-ci` added by `0ebf409` (after `6fa75c9` failed the security job
  on a U1000 finding local gates missed); it runs the **exact pinned version**
  the security job uses (`honnef.co/go/tools/cmd/staticcheck@2025.1.1`), so
  local findings equal remote findings

Verified locally on `0ebf409`: `make ci` exit 0, all five stages green.

Reproduce: `make ci`

---

## 4. Test and coverage metrics

- **Statement coverage: 87.8%** (`go tool cover -func`, profile regenerated at
  `ec4c995` via `make test-coverage`; session arc 86.1% → 87.8%). Frontend:
  build, eslint, and its full suite green in the Web Dashboard workflow (last
  observed local full run: 196/196 tests, 2026-08-21).
- **All Go packages pass** with coverage collection enabled (`make
  test-coverage`, exit 0).
- **Risk-function scoreboard** (attacker-facing / integrity-critical functions
  raised during the session's coverage campaign — all at 77–100%):

| Function | Coverage |
|---|---|
| `ParseRDataText` (protocol master text parser) | 100.0% |
| `validateDNSSECResponse` (live query path) | 100.0% |
| `proposeZoneWrite` (cluster write funnel) | 100.0% |
| `validateRPZ` (policy config validation) | 100.0% |
| `fetchNSEC3PARAM` | 100.0% |
| `handleClusterJoin` / `handleClusterLeave` | 95.2% / 86.7% |
| `rollbackActiveAppend` (WAL crash recovery) | 80.0% |
| `validateNegativeResponse` / `verifyDSDenial` (DNSSEC denial proofs) | 90.0% / 87.9% |
| `queryTCP` (resolver TCP fallback) | 91.2% |
| `ServeHTTP` (DoH-over-WebSocket) | 89.3% |
| `tcpConnPool.get` (upstream pooling) | 88.1% |
| `handleAXFRRequest` / `handleIXFRRequest` / `AcceptLoop` (XoT/TLS) | 78.3% / 79.2% / 76.7% |
| `handleZoneUpdate` (gossip replication) | 85.7% |
| `digQueryTCP` / `cmdCluster` (dnsctl CLI) | 87.0% / 100.0% |

Residual uncovered lines are documented-unreachable classes (KeyTrap caps
needing 16+ records, `SetDeadline` error paths on healthy sockets, a WAL
seek-only-failure branch unreachable with a real `*os.File`).

---

## 5. Fuzzing

Four fuzz steps, nine targets, 30s each — all green on `0ebf409`:

- Protocol parsers: `FuzzUnpackMessage`, `FuzzUnpackName`, `FuzzUnpackResourceRecord`
- Zone parser: `FuzzParseZoneFile`
- DSO TLV pipeline: `FuzzUnpackTLV`, `FuzzHandleDSORequest`
- ODoH wire format: `FuzzParseODoHMessage`, `FuzzParseConfigContents`, `FuzzDecryptQuery`

Each step carries an **artifact-conditional retry guard** (added `3f92e5b`,
`691a4bf`, `82603e9`): a failure with a written crash input fails fast (genuine
crash — always deterministic); a failure with *no* artifact is the known
go-fuzz coordinator deadline race and is retried once. This class of
infrastructure flake cost two red runs earlier in the session before being
structurally closed; the guards add zero overhead on green runs.

---

## 6. Live runtime evidence (verified at commit `a44aca4`, 2026-08-21)

Beyond CI, the server binary was exercised live (built from source, real
config, real sockets):

- **Authoritative answers correct per RFC 1035 §4.1.1** — UDP and TCP both
  return `qr aa ra` on positive answers, `aa` on NXDOMAIN/NODATA, AA correctly
  *unset* on referrals. (The AA bit was missing on positive answers at session
  start — a real compliance bug found by this live probe and fixed in
  `a44aca4`, with seven mutation-verified regression tests.)
- **Malformed-input robustness** — five garbage/oversized/truncated datagram
  probes: zero panics, server stayed up, garbage dropped, oversize answered
  with FORMERR.
- **Graceful shutdown** — SIGTERM → clean exit in under 1 second.
- **HTTP API security** — unauthenticated request → 401; `X-Content-Type-Options:
  nosniff` and `X-Frame-Options: DENY` present.
- **Config validation is fail-closed** — all six shipped `deploy/` configs
  validated; production/staging correctly refuse to start on unset secrets
  (env-substitution empty) or missing target-host paths. Placeholder-secret
  guards (VULN-050) reject known template values.
- **Security scans** — `govulncheck`: **0 reachable vulnerabilities** (one
  module-level advisory: unmaintained `x/crypto/openpgp`, not imported by any
  code path). `npm audit`: 0 vulnerabilities (prod and dev). staticcheck: clean.

---

## 7. Defects found and fixed during the session (evidence the gates work)

Nineteen commits (`a44aca4` through `0ebf409`, i.e. `a44aca4~1..0ebf409`
— verified via `git rev-list --count`). The significant findings:

| Commit | Finding | Class |
|---|---|---|
| `a44aca4` | Authoritative positive answers missing the AA bit (RFC 1035 §4.1.1) — found by live probe, fixed, 7 mutation-verified regression tests added | Product bug |
| `35ded5d` | `3a77e97` failed CI: test file not gofmt-clean; **structural fix** `2c987a4` added `fmt-check` to `make ci` | Process gap |
| `6cca7f2` | `6fa75c9` failed the security job: unused test scaffolding (U1000); **structural fix** `0ebf409` added CI-pinned staticcheck to `make ci` | Process gap |
| `ec4c995` | `dee393d` failed the race job: a test closed an fd behind the WAL's background syncer (`syncLoop`), creating a nondeterministic short-circuit — test design flaw, fixed by draining the pending sync; lesson: concurrent-internals tests must be verified with `-race` locally | Test-design flaw |
| `3f92e5b`/`691a4bf`/`82603e9` | go-fuzz coordinator deadline race flaked two CI runs; all four fuzz steps now carry artifact-conditional retry guards | CI infrastructure |

Every red run was root-caused from its log before any fix; every fix commit
was verified green on remote CI before the session proceeded. Three failure
classes (formatting, static analysis, fuzz flake) each received a *structural*
local gate so they cannot recur silently.

---

## 8. Boundaries of this evidence

What this report does **not** establish:

1. **Live TLS transports** — DoT/DoQ/DoH-over-TLS are covered by package tests
   and e2e suites (XoT now includes genuine-TLS transport tests), but no
   live TLS probe with provisioned certificates was run.
2. **Real-cluster deployment** — the Helm chart passes template validation;
   it was not deployed against a real Kubernetes cluster.
3. **Load / soak behavior** — no load testing or long-duration soak was
   performed; throughput, memory stability under load, and failover timing are
   unmeasured.
4. **Formal correctness** — DNSSEC validation logic is heavily tested
   (denial proofs 86–100%) but not formally verified.
5. **Known untested areas** (deliberately triaged, rationale recorded): mDNS
   multicast handlers (flaky in CI sandboxes), raft RPC internals (need an
   in-process multi-node harness; the raft state machine has 21 test files of
   behavioral coverage), legacy dashboard handlers (superseded by the web SPA).

Historical note for auditors: commits `3a77e97`, `6fa75c9`, and `dee393d`
carry permanently red Actions runs (per-commit history); their fixes
(`35ded5d`, `6cca7f2`, `ec4c995`) and every subsequent head are green. The
final head `0ebf409` is green on first attempt across all three workflows.

---

## 9. Reproduction

```bash
git checkout 0ebf409
make ci                     # fmt-check, vet, staticcheck-ci (pinned), tests, build
make test-coverage          # regenerates coverage.out / coverage.html
go tool cover -func=coverage.out | tail -1   # total: 87.8%
gh run view 32557957241     # Go workflow on 0ebf409 (all 9 jobs)
gh run view 32557957244     # Container Image
gh run view 32557957390     # Web Dashboard
```

---

*Report anchored to commit `0ebf409`. Coverage figures from the profile
regenerated at `ec4c995` (identical code for all functions cited; `0ebf409`
changes only the Makefile).*
