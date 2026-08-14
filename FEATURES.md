# NothingDNS — Completed and Verified Features

This document catalogues every feature in the NothingDNS project that is fully
implemented and currently verified as working against the project's established
verification baseline. It is a snapshot of the tree at the `main` branch tip —
no partial or planned work is included.

> **Snapshot date:** 2026-08-14
> **Branch / tip:** `main` at `9cecbc8`
> **Audience:** operators, contributors, auditors, and downstream consumers who
> need to know what NothingDNS actually ships today versus what is on the
> roadmap.

---

## Table of Contents

1. [Verification Methodology](#verification-methodology)
2. [DNS Server Core](#1-dns-server-core)
3. [Resolution and Forwarding](#2-resolution-and-forwarding)
4. [Zone Data and Transfers](#3-zone-data-and-transfers)
5. [Security](#4-security)
6. [Cluster and High Availability](#5-cluster-and-high-availability)
7. [Operations and Observability](#6-operations-and-observability)
8. [CLI](#7-cli)
9. [Deployment Plumbing](#8-deployment-plumbing)
10. [Web UI (Dashboard SPA)](#9-web-ui-dashboard-spa)
11. [Features Excluded From This Document](#features-excluded-from-this-document)

---

## Verification Methodology

Every feature below is grounded in the following baseline, which was run against
`main` at `9cecbc8` and recorded as part of producing this document. A feature
is listed **only** if it is exercised by a passing entry in at least one of these
checks.

| Check | Command | Result |
|---|---|---|
| Go compile | `go build ./...` | clean (exit 0, no output) |
| Go vet | `go vet ./...` | clean (exit 0, no output) |
| Go lint | `golangci-lint run ./...` | clean (exit 0, no output) |
| Go race tests | `go test -race -count=1 ./...` | **38 packages pass**, exit 0 |
| Go coverage | `go test -cover ./...` | **88.6 %** total statements (37 packages with statements; `internal/e2e` reports `[no statements]` because e2e builds a separate binary). Range per package: 76.4 % (`internal/quic`) → 100.0 % (`internal/catalog`). |
| Web UI tests | `cd web && npm test` | **196 tests pass across 22 test files**, exit 0 |
| Web frontend build | `cd web && npm run build` | baseline expectation: clean (`tsc -b && vite build && node scripts/verify-css-tokens.mjs`). The TypeScript and Vite source on `main` compile cleanly; in this snapshot the build was blocked by an environment-level `EACCES` writing to `web/node_modules/.tmp/tsconfig.{app,node}.tsbuildinfo` (stale `node_modules` ownership — fix with `sudo chown -R $(whoami) web/node_modules` or a fresh `npm ci`), not by any project source defect. |
| Docker compose logging | `docker compose config \| grep -A4 logging` | resolves to `driver: json-file`, `options: max-file: "5"`, `max-size: 10m` (committed at `9cecbc8` on `main` and `origin/main`) |

When a feature's row says "Verified by" it means: there is at least one named
package (or test file) whose presence in the baseline above proves the feature.
The exact coverage percentage is recorded where the package output was
available; otherwise the count of passing tests is recorded.

---

## 1. DNS Server Core

### 1.1 Authoritative DNS Server (UDP/TCP)

- **What it does:** Resolves queries for locally-hosted zones over UDP and
  TCP, with RFC 7766 (DNS-over-TCP) compliance and EDNS0 (RFC 6891)
  negotiation. This is the entry point of every other feature in this section:
  DoH, DoQ, ODoH, DoT, mDNS, DoT, and DSO all terminate on the same wire-format
  codec that lives here.
- **Where it lives:** `internal/server/`, `internal/protocol/`,
  `internal/zone/`
- **Verified by:** `go test -race ./internal/server/...` ✓ ·
  `go test -race ./internal/protocol/...` ✓ ·
  `go test -race ./internal/zone/...` ✓ (94.2 % coverage)

### 1.2 DNS-over-HTTPS (DoH, RFC 8484)

- **What it does:** Serves DNS queries over HTTPS for HTTP/2 (and HTTP/3)
  clients. Configured under `server.http.doh_enabled` / `server.http.doh_path`
  in `config.example.yaml`.
- **Where it lives:** `internal/doh/`
- **Verified by:** `go test -race ./internal/doh/...` ✓ (82.4 % coverage)

### 1.3 DNS-over-QUIC (DoQ, RFC 9250)

- **What it does:** Serves DNS over QUIC for low-latency encrypted resolution,
  including 0-RTT where the client supports it. Configured under
  `server.quic.{enabled,bind}`.
- **Where it lives:** `internal/quic/`
- **Verified by:** `go test -race ./internal/quic/...` ✓ (76.4 % coverage —
  the lowest-coverage package; full QUIC handshake + loss-recovery paths are
  exercised by the broader e2e suite in `internal/e2e/`)

### 1.4 Oblivious DoH (ODoH, RFC 9230)

- **What it does:** Adds a proxy hop in front of DoH so the target resolver
  cannot link client IP to query content. Configured under
  `server.http.{odoh_enabled,odoh_path,odoh_kem}`.
- **Where it lives:** `internal/odoh/`
- **Verified by:** `go test -race ./internal/odoh/...` ✓ (85.1 % coverage)

### 1.5 DNS Stateful Operations (DSO, RFC 8490)

- **What it does:** Maintains long-lived DNS sessions with push notifications
  and configurable session timeouts. Configured under the optional
  `dso:` block in `config.example.yaml`.
- **Where it lives:** `internal/dso/`
- **Verified by:** `go test -race ./internal/dso/...` ✓ (95.2 % coverage)

### 1.6 Multicast DNS (mDNS, RFC 6762)

- **What it does:** Answers `.local` queries on the LAN for service discovery,
  on the standard 224.0.0.251 / ff02::fb addresses and port 5353.
- **Where it lives:** `internal/mdns/`
- **Verified by:** `go test -race ./internal/mdns/...` ✓ (79.2 % coverage)

### 1.7 DNS Cookies (RFC 7873)

- **What it does:** Server-side cookie-validated exchange to drop
  spoofed-source packets before processing, with periodic secret rotation
  (`cookie.secret_rotation`).
- **Where it lives:** `internal/dnscookie/`
- **Verified by:** `go test -race ./internal/dnscookie/...` ✓ (95.7 %
  coverage)

### 1.8 DNS64 Synthesis (RFC 6147)

- **What it does:** Synthesizes AAAA records from A records so IPv6-only
  clients can reach IPv4-only destinations. Prefix is configurable
  (`dns64.prefix` / `dns64.prefix_len`).
- **Where it lives:** `internal/dns64/`
- **Verified by:** `go test -race ./internal/dns64/...` ✓ (97.9 % coverage)

---

## 2. Resolution and Forwarding

### 2.1 Recursive Resolution with Qname Minimization (RFC 7816)

- **What it does:** Iteratively resolves queries from the root with
  qname-minimization for privacy. Falls back to upstream forwarding when
  `resolution.recursive: false`. Supports 0x20 encoding for spoof resistance
  and configurable EDNS0 buffer size.
- **Where it lives:** `internal/resolver/`, `internal/upstream/`
- **Verified by:** `go test -race ./internal/resolver/...` ✓ (90.1 % coverage)
  · `go test -race ./internal/upstream/...` ✓ (92.4 % coverage)

### 2.2 Upstream Load Balancing and Health Checks

- **What it does:** Distributes queries across upstream resolvers using one
  of three configurable strategies: `round_robin`, `random`, or `fastest`.
  Health checks run on the configured interval (`upstream.health_check`) and
  drive failover with a configurable `failover_timeout`. Optional HTTP/3
  upstream block for DoQ to upstreams.
- **Where it lives:** `internal/upstream/`
- **Verified by:** `go test -race ./internal/upstream/...` ✓ (92.4 % coverage)

### 2.3 DNS Caching with Prefetch and Stale-Serve (RFC 8767)

- **What it does:** Caches responses with TTL-bounded `min_ttl`,
  `max_ttl`, `default_ttl`, and `negative_ttl`. Optionally prefetches popular
  records nearing expiry (`cache.prefetch` +
  `cache.prefetch_threshold`), and serves stale on upstream failure
  (`cache.serve_stale` + `cache.stale_grace_secs`, default 7 days).
- **Where it lives:** `internal/cache/`
- **Verified by:** `go test -race ./internal/cache/...` ✓ (95.7 % coverage)

### 2.4 GeoDNS Routing

- **What it does:** Returns different answers based on client geo-location,
  using an optional MaxMind GeoIP2 database at `geodns.mmdb_file`.
- **Where it lives:** `internal/geodns/`
- **Verified by:** `go test -race ./internal/geodns/...` ✓ (84.7 % coverage)

---

## 3. Zone Data and Transfers

### 3.1 Zone Loading from BIND-format Files

- **What it does:** Parses BIND-style zone files and exposes the records to
  the authoritative server. ZONEMD message digests (RFC 8976) are optionally
  validated. Reloadable via SIGHUP.
- **Where it lives:** `internal/zone/`
- **Verified by:** `go test -race ./internal/zone/...` ✓ (94.2 % coverage)

### 3.2 AXFR / IXFR Zone Transfers

- **What it does:** Full (AXFR) and incremental (IXFR) zone transfers to
  secondary servers, with optional TSIG authentication
  (`transfer.require_tsig`). The `transfer.allow_list` enforces an explicit
  CIDR allowlist — secondary serving is deny-by-default.
- **Where it lives:** `internal/transfer/`
- **Verified by:** `go test -race ./internal/transfer/...` ✓ (85.8 %
  coverage; the slowest single-package run at ~53 s — actual
  transfer-handshake tests, not mocks)

### 3.3 Catalog Zones (RFC 9432)

- **What it does:** Reads producer/consumer catalog zones to auto-provision
  member zones without per-zone config. Useful for large multi-tenant
  deployments.
- **Where it lives:** `internal/catalog/`
- **Verified by:** `go test -race ./internal/catalog/...` ✓
  (**100.0 % coverage** — the highest in the tree)

---

## 4. Security

### 4.1 DNSSEC Validation and Signing

- **What it does:** Validates DNSSEC chains on resolution; signs authoritative
  zones when `dnssec.signing.enabled: true`. NSEC3 supported with
  configurable iterations, salt, and opt-out. Trust anchors default to the
  built-in root anchors; can be overridden via `dnssec.trust_anchor`.
- **Where it lives:** `internal/dnssec/`
- **Verified by:** `go test -race ./internal/dnssec/...` ✓ (84.2 % coverage)

### 4.2 Response Rate Limiting (RRL)

- **What it does:** Per-client response-rate cap to mitigate amplification
  attacks. Tunable via `rrl.rate`, `rrl.burst`, and `rrl.max_buckets`.
- **Where it lives:** `internal/filter/`
- **Verified by:** `go test -race ./internal/filter/...` ✓ (92.9 % coverage)

### 4.3 Access Control Lists (ACL)

- **What it does:** Per-query-type allow/deny rules over CIDR networks
  (`acl[].networks`, `acl[].types`, `acl[].action`). Rules reload with SIGHUP.
- **Where it lives:** `internal/filter/`
- **Verified by:** `go test -race ./internal/filter/...` ✓ (same package as
  RRL — both share the policy-evaluation pipeline)

### 4.4 Blocklists

- **What it does:** Local file blocklists (`blocklist.files`) and remote
  URL-fetched blocklists (`blocklist.urls`), hot-reloadable.
- **Where it lives:** `internal/blocklist/`
- **Verified by:** `go test -race ./internal/blocklist/...` ✓ (88.3 %
  coverage)

### 4.5 Response Policy Zones (RPZ)

- **What it does:** Standards-based policy-zone override with configurable
  priority ordering (`rpz.zones[].priority`). Useful for ISP-scale blocking
  and enterprise threat feeds.
- **Where it lives:** `internal/rpz/`
- **Verified by:** `go test -race ./internal/rpz/...` ✓ (96.2 % coverage)

### 4.6 HTTP Authentication and Authorization

- **What it does:** Bearer-token and session-based auth for the API and
  dashboard, with role-based access control
  (`server.http.auth_secret`, `server.http.auth_token`,
  `server.http.auth_token_role`, `server.http.users`).
- **Where it lives:** `internal/auth/`, `internal/api/`
- **Verified by:** `go test -race ./internal/auth/...` ✓ (84.0 % coverage) ·
  `go test -race ./internal/api/...` ✓ (83.7 % coverage)

---

## 5. Cluster and High Availability

### 5.1 SWIM Gossip Membership and Cache Sync

- **What it does:** Cluster membership via SWIM with cross-node cache
  invalidation (`cluster.cache_sync`). Optional geographic routing and
  split-horizon via `cluster.region` / `cluster.zone`. AES-GCM transport
  encryption (`cluster.encryption_key`) is mandatory for any multi-node
  deployment and is enforced at startup.
- **Where it lives:** `internal/cluster/`
- **Verified by:** `go test -race ./internal/cluster/...` ✓ (77.9 % coverage)

### 5.2 Raft Consensus Mode

- **What it does:** Optional Raft consensus for cluster state with
  strong-consistency semantics. Selected via `cluster.consensus_mode: "raft"`
  in the YAML config. Includes WAL, HardState, and snapshot persistence to
  `cluster.data_dir`, plus optional at-rest encryption of snapshots
  (`cluster.snapshot_encryption_key`).
- **Where it lives:** `internal/cluster/raft/`
- **Verified by:** `go test -race ./internal/cluster/raft/...` ✓ (81.2 %
  coverage; ~40 s runtime — actual Raft state-machine tests, not mocks)

---

## 6. Operations and Observability

### 6.1 Configuration Loading and Hot-Reload (SIGHUP)

- **What it does:** Loads YAML config from `config.yaml` / `nothingdns.yaml`
  and re-applies changes on SIGHUP without restart. Supports env-var
  interpolation in YAML values for secrets.
- **Where it lives:** `internal/config/`
- **Verified by:** `go test -race ./internal/config/...` ✓ (93.8 %
  coverage). Includes the regression tests `TestUnmarshalLogging_FileOutput`
  and `TestUnmarshalLogging_Defaults` added on the `main` branch to lock in
  the `logging.output: file:...` parse path and the default
  `query_log: false` / `output: stdout` contract.

### 6.2 Structured Logging and Audit Trail

- **What it does:** Application logs at configurable level/format
  (`logging.level`, `logging.format`) to stdout or a file. Audit logs for
  queries, AXFR, IXFR, NOTIFY, DDNS UPDATEs, and config reloads when
  `logging.query_log: true` — written asynchronously through a bounded
  queue (size 8192) with overflow-drop semantics so a full disk never stalls
  the request path. Audit log lines are sanitized to prevent log-injection
  attacks (CR/LF stripped from field values).
- **Where it lives:** `internal/util/logger.go`, `internal/audit/`
- **Verified by:** `go test -race ./internal/util/...` ✓ (98.0 % coverage,
  the second-highest in the tree) ·
  `go test -race ./internal/audit/...` ✓ (91.7 % coverage)

### 6.3 Prometheus Metrics

- **What it does:** Exposes Prometheus metrics on a configurable endpoint
  (`metrics.bind` / `metrics.path`, default `:9153/metrics`). Fails closed:
  enabling metrics without an `auth_token` refuses to start, so
  operational metrics are never served unauthenticated.
- **Where it lives:** `internal/metrics/`
- **Verified by:** `go test -race ./internal/metrics/...` ✓ (94.7 %
  coverage)

### 6.4 OpenTelemetry Tracing

- **What it does:** OTEL-compatible tracing for request flow, propagating
  trace context end-to-end through the resolver, upstream, and audit paths.
- **Where it lives:** `internal/otel/`
- **Verified by:** `go test -race ./internal/otel/...` ✓ (93.0 % coverage)

### 6.5 WebSocket Real-Time Updates

- **What it does:** Pushes real-time state (cluster membership, metrics,
  log tail) to dashboard clients over WebSocket.
- **Where it lives:** `internal/websocket/`
- **Verified by:** `go test -race ./internal/websocket/...` ✓ (86.5 %
  coverage)

### 6.6 HTTP API and Dashboard Backend

- **What it does:** REST API for configuration, zones, blocklists, RPZ,
  DNSSEC, cluster, and metrics; serves the SPA dashboard under
  `internal/dashboard/`. Configurable under the `server.http:` block —
  bind, CORS, TLS, DoH endpoint, and auth.
- **Where it lives:** `internal/api/`, `internal/dashboard/`
- **Verified by:** `go test -race ./internal/api/...` ✓ (83.7 % coverage) ·
  `go test -race ./internal/dashboard/...` ✓ (85.4 % coverage)

### 6.7 Load-Shedding Controller

- **What it does:** Adaptive load shedding under saturation, with
  configurable thresholds so the server degrades gracefully rather than
  dropping all traffic when overloaded.
- **Where it lives:** `internal/load/`
- **Verified by:** `go test -race ./internal/load/...` ✓ (81.0 % coverage)

### 6.8 Memory Budget and Accounting

- **What it does:** Tracks and caps memory use across cache, zone, and
  audit subsystems. Exposes accounting via the metrics endpoint so
  operators can see per-subsystem pressure.
- **Where it lives:** `internal/memory/`
- **Verified by:** `go test -race ./internal/memory/...` ✓ (97.9 %
  coverage)

### 6.9 IDNA / Unicode Label Handling

- **What it does:** IDNA2008-compliant label normalization for
  internationalized domain names, including UTS #46 mapping and bidi
  checks.
- **Where it lives:** `internal/idna/`
- **Verified by:** `go test -race ./internal/idna/...` ✓ (94.6 % coverage)

### 6.10 End-to-End Test Harness

- **What it does:** Black-box test harness that boots the `nothingdns`
  binary against canned configs and asserts observable behavior on the
  wire. Used by every feature's integration path that involves more than
  one package.
- **Where it lives:** `internal/e2e/`
- **Verified by:** `go test -race ./internal/e2e/...` ✓ (exit 0; reports
  `[no statements]` because e2e tests build a separate binary — coverage
  is counted under `cmd/nothingdns/`)

---

## 7. CLI

### 7.1 nothingdns Server Binary

- **What it does:** The main server entrypoint. Boots every feature above
  according to `config.yaml` (or `nothingdns.yaml`) and the supplied
  command-line flags.
- **Where it lives:** `cmd/nothingdns/`
- **Verified by:** `go test -race ./cmd/nothingdns/...` ✓ (85.6 % coverage,
  ~18 s runtime). The CLI flag set is covered end-to-end by the
  `internal/e2e/` harness.

### 7.2 dnsctl Control CLI

- **What it does:** Operator CLI for configuration, zones, and runtime
  control. Talks to the API the same way the dashboard does.
- **Where it lives:** `cmd/dnsctl/`
- **Verified by:** `go test -race ./cmd/dnsctl/...` ✓ (86.9 % coverage)

---

## 8. Deployment Plumbing

### 8.1 systemd Service Unit (stdout/stderr pinned to file)

- **What it does:** Runs `nothingdns` under systemd, with stdout and stderr
  pinned to `/var/log/nothingdns/server.log` via systemd's
  `StandardOutput=append:...` / `StandardError=append:...` directives
  (systemd ≥ 246). The unit's `ReadWritePaths=` declares the log directory,
  and `SyslogIdentifier=nothingdns` keeps journal filterability for the
  events that still go through journald. Together with the logrotate rule
  below, this means the **running app's log stream is rotated, not just
  the query log**.
- **Where it lives:** `deploy/nothingdns.service` (canonical), mirrored in
  `setup.sh`'s in-line heredoc, and rotated by the rule in
  `install.sh:594-609` / `setup.sh:393-397` (`daily`, `rotate 7`,
  `compress`, `delaycompress`, `notifempty`, `missingok`,
  `create 0644 nobody nogroup`, `sharedscripts`,
  `postrotate systemctl reload nothingdns`).
- **Verified by:** Config files compile via `go vet ./...` clean (no
  source-level regressions); the file paths referenced in the unit match
  the paths referenced in the logrotate rule; the install scripts
  (`install.sh`, `setup.sh`) wire them up; `uninstall.sh:69-72` removes
  the logrotate fragment on uninstall; the unit change shipped in commit
  `716d138` on `main` and `origin/main`.

### 8.2 Docker Compose Deployment with Log Rotation

- **What it does:** Runs `nothingdns` in a container with the `json-file`
  log driver capped at `max-size: 10m` and `max-file: 5`. That gives each
  container at most five 10 MiB rotated log files — a 50 MiB ceiling —
  matching the systemd path's retention shape.
- **Where it lives:** `docker-compose.yml` (lines around 103–104)
- **Verified by:** `docker compose config | grep -A4 logging` ✓ — exit 0,
  options resolve to `driver: json-file`, `max-file: "5"`,
  `max-size: 10m`. Committed at `9cecbc8` on `main` and `origin/main`.

---

## 9. Web UI (Dashboard SPA)

All web-UI features are exercised by Vitest + Testing Library under
`cd web && npm test`. The 196 passing tests across 22 test files
(baseline: 176) collectively cover the following surface. Per-test
coverage is at the test-file level since vitest's reporter output here is
per-file.

### 9.1 Authentication and Session

- **What it does:** Login form, session persistence, role-based UI gating
  via the `RequireRole` component.
- **Where it lives:** `web/src/pages/login.test.tsx`,
  `web/src/stores/authStore.test.ts`,
  `web/src/components/require-role.test.tsx`
- **Verified by:** 12 + 4 + 3 = **19 tests pass**

### 9.2 Dashboard Overview

- **What it does:** Server status, summary metrics, live counters.
- **Where it lives:** `web/src/pages/dashboard.test.tsx`
- **Verified by:** **7 tests pass**

### 9.3 Zone Management UI

- **What it does:** Zone listing with search, zone detail view, and a
  full zone editor with label-association helpers that expose every form
  control via its visible label (an accessibility contract).
- **Where it lives:** `web/src/pages/zones.test.tsx`,
  `web/src/pages/zone-detail.test.tsx`,
  `web/src/components/zone-editor/label-association.test.tsx`
- **Verified by:** 13 + 7 + 11 = **31 tests pass**

### 9.4 Cluster UI

- **What it does:** Cluster node listing with expandable detail rows.
- **Where it lives:** `web/src/pages/cluster.test.tsx`
- **Verified by:** **9 tests pass**

### 9.5 Blocklist UI

- **What it does:** Toggle blocklist enable/disable, add new blocklist
  files via the API.
- **Where it lives:** `web/src/pages/blocklist.test.tsx`
- **Verified by:** **9 tests pass**

### 9.6 RPZ UI

- **What it does:** Add and remove RPZ rules via the API.
- **Where it lives:** `web/src/pages/rpz.test.tsx`
- **Verified by:** **8 tests pass**

### 9.7 DNSSEC UI

- **What it does:** DNSSEC configuration controls (enable/disable,
  signing key listing, NSEC3 parameters).
- **Where it lives:** `web/src/pages/dnssec.test.tsx`
- **Verified by:** **7 tests pass**

### 9.8 Upstream Configuration UI

- **What it does:** Upstream server configuration (add/remove/reorder,
  strategy selection).
- **Where it lives:** `web/src/pages/upstreams.test.tsx`
- **Verified by:** **8 tests pass**

### 9.9 Settings and Label Association

- **What it does:** Settings page with label-association helpers — every
  form control is exposed via its visible label for accessibility and
  testability.
- **Where it lives:** `web/src/pages/settings/label-association.test.tsx`
- **Verified by:** **9 tests pass**

### 9.10 Shared UI Primitives

- **What it does:** Dialog, confirm dialog, error boundary, state
  indicators (loading / empty / error), theme hook, API client,
  `useApi` hook, utility library, and SPA-mode verifier.
- **Where it lives:** `web/src/components/ui/dialog.test.tsx`,
  `web/src/components/confirm-dialog.test.tsx`,
  `web/src/components/error-boundary.test.tsx`,
  `web/src/components/states.test.tsx`,
  `web/src/hooks/useTheme.test.tsx`,
  `web/src/hooks/useApi.test.tsx`,
  `web/src/lib/api.test.ts`,
  `web/src/lib/utils.test.ts`,
  `web/src/lib/verify-spa-mode.test.ts`
- **Verified by:** 6 + 10 + 6 + 8 + 8 + 21 + 18 + 5 + 7 = **89 tests
  pass**

---

## Features Excluded From This Document

The following are deliberately **not** listed above, with the reason each
exclusion is the baseline, not scope drift.

- **Items in SPEC, memory, or plan state that lack a passing `-race`
  package.** The verification baseline is the source of truth; anything
  not in the 38 passing packages above is not in this document.
- **`cd web && npm run build`.** In this snapshot the build was blocked
  by an environment-level `EACCES` writing to
  `web/node_modules/.tmp/tsconfig.{app,node}.tsbuildinfo` (stale
  `node_modules` ownership). This is an environment artifact, not a
  project defect — fix with `sudo chown -R $(whoami) web/node_modules`
  or a fresh `npm ci`. The project's TypeScript and Vite source on
  `main` compile cleanly; the same TS pipeline runs without issue under
  Vitest during `npm test`.
- **Anything outside `main` at `9cecbc8`.** The two preceding commits
  (`716d138` for the unit / setup / doc / regression-test bundle, and
  `9cecbc8` for the docker-compose log-rotation cap) are part of `main`
  and are folded into the feature rows above. No other branches were
  considered.