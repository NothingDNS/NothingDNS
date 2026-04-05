# NothingDNS Roadmap

> Prioritized implementation roadmap based on comprehensive codebase analysis
> Generated: 2026-04-05
> Reference: `.project/ANALYSIS.md`

## Overview

The analysis revealed ~75-80% task completion with one critical architectural deviation (SWIM vs Raft clustering). This roadmap prioritizes work into 7 phases, sequenced by dependency order and criticality. Items are estimated in **person-days** (8h each).

**Assumptions:**
- Team size: 1-2 senior Go engineers
- Working full-time on NothingDNS
- Zero-dependency constraint maintained throughout

**Total Estimated Effort:** ~155 person-days (~1,240 hours)

---

## Phase 1: Critical Fixes & Hygiene (Day 1-10)

**Goal:** Achieve a clean `go vet ./...` and resolve blocking code quality issues. These are prerequisites for production readiness.

### 1.1 Fix go vet Unkeyed Fields Error (0.5d)
**File:** `cmd/nothingdns/main.go:482`
**Problem:** `auth.Duration` struct literal uses unkeyed fields
**Fix:** Change to keyed field syntax: `auth.Duration{Duration: someValue}`
**Verification:** `go vet ./...` passes

### 1.2 Fix Internal Test Gaps (2d)
- **internal/auth** has no test files. Add unit tests for JWT generation, token validation, RBAC enforcement, password hashing.
- **Verification:** `go test ./...` shows 100% coverage on auth package

### 1.3 Fix Integration Test Port Binding (2d)
**Problem:** `TestMultipleQueries` and `TestUDP_ConcurrentQueries` fail with `bind: An attempt was made to access a socket in a way forbidden by its access permissions` on Windows.
**Diagnosis:** Likely UDP port not released between tests or test isolation issue.
**Fix:** Ensure `defer close()` on listeners, use port `:0` for dynamic allocation in tests, add Windows-specific skip or isolation.
**Verification:** All integration tests pass on Windows

### 1.4 Silent Error Handling Audit (5d)
**Problem:** ANALYSIS.md §3.2 and PRODUCTION_READINESS.md document multiple places where errors are silently discarded.
**Files to audit:**
- `internal/transfer/` — TSIG parsing errors (item 19)
- `internal/protocol/` — Serial arithmetic edge cases (item 20)
- `internal/resolver/` — Upstream errors silently logged
- `internal/cluster/` — Gossip message parse failures
**Fix:** Each discarded error should either be handled, logged at debug level, or proven harmless. Add `// error intentionally ignored` comments with rationale where truly harmless.
**Verification:** Code review sign-off, no new silently discarded errors

### 1.5 Coverage Extra Test Review (1d)
Review `coverage_extra*.go` files across packages. Ensure they test genuinely tricky error paths and are not workarounds for untestable code.
**Estimated: 1d**

**Phase 1 Subtotal: ~10.5 person-days**

---

## Phase 2: Cluster — Raft Implementation (Day 11-55)

**Goal:** Replace the SWIM gossip-based cluster with a proper Raft consensus implementation as specified in SPECIFICATION.md §10. This is the largest remaining feature gap.

### 2.1 Raft Core Engine (25d)
**Reference:** SPECIFICATION.md §10, IMPLEMENTATION.md §11

Implement from scratch (per spec requirement) with:
- **State Machine:** Leader, Follower, Candidate states with transitions
- **RequestVote RPC:** Term, candidateID, lastLogIndex, lastLogTerm. Vote granting with term check.
- **AppendEntries RPC:** PrevLogIndex, PrevLogTerm, Entries[], LeaderCommit. Consistency checks.
- **Log Replication:** Entries stored with term + index. Committed entries applied to state machine.
- **Leader Election:** Election timeout randomization, lease-based re-election prevention
- **Snapshots:** Periodic snapshotting of state machine state to compact logs

**Files to create/modify:**
- `internal/cluster/raft.go` (new) — Core Raft state machine
- `internal/cluster/log.go` (new) — Raft log management
- `internal/cluster/rpc.go` (new) — RequestVote + AppendEntries RPC handlers
- `internal/cluster/snapshot.go` (new) — Snapshotting

**Verification:** Unit tests for leader election, log append, snapshotting. Property-based tests for log consistency.

### 2.2 Zone State Machine on Raft (10d)
**Problem:** Zone changes (ADD/DELETE/UPDATE records) must be replicated via Raft log, not gossip broadcasts.
**Design:**
- Zone mutations go through Raft propose → replicate → commit → apply pipeline
- Each node applies committed entries to its local zone store
- Read queries can be served from local state (no Raft overhead)
- Consistent reads (for API) require leader confirmation

**Files:** `internal/cluster/zonesm.go` (new)

### 2.3 gRPC-Compatible Inter-Node Protocol (8d)
**Reference:** SPECIFICATION.md §15
**Problem:** Spec calls for "hand-written gRPC-compatible binary protocol" but only plain TCP gossip exists.
**Design:** Use protobuf-like message framing (varint length prefix + message type + payload). Messages: RequestVote, AppendEntries, VoteResponse, AppendResponse, SnapshotChunk, ZoneProposal.
**Alternative:** Skip full protobuf codegen — hand-roll binary marshaling to stay zero-dep. Use manual `proto.Marshal` equivalent with `sync.Pool` buffers.

### 2.4 Cluster Bootstrap & Discovery (4d)
- Initial cluster configuration via config file or CLI flag
- Join protocol: node contacts seed node, exchanges topology
- Partition recovery: re-election after majority loss
- Witness/observer nodes (non-voting Raft members)

### 2.5 Migrate from SWIM to Raft (5d)
- Remove `internal/cluster/gossip.go` and SWIM-related code
- Wire Raft cluster into main.go (replace cluster init)
- Update API endpoints (`/api/v1/cluster/*`) to report Raft state
- Update MCP cluster tools

### 2.6 Integration & Chaos Testing (3d)
- Multi-node cluster tests (3-5 nodes)
- Network partition simulation
- Leader crash/recovery
- Log recovery after restart
- Performance: election timeout, replication lag

**Phase 2 Subtotal: ~55 person-days**

---

## Phase 3: Storage & Persistence Integration (Day 56-75)

**Goal:** Wire the existing KV store + WAL into zone management so zones survive restarts without external file management.

### 3.1 KV Store Zone Persistence (8d)
**Problem:** `internal/storage/` exists but zones are loaded from files at startup, not persisted through KV store.
**Changes:**
- On zone load, write all records to KV store as zone-scoped keys
- On zone update (via API/DDNS), write through to KV store
- On startup, check KV store for persisted zones before loading files
- Background sync: periodic flush of in-memory zone state to KV

**Files:** `internal/storage/zonekv.go` (new), `internal/zone/zone.go` (modify)

### 3.2 WAL Integration for Zone Changes (5d)
- Zone mutations (DDNS UPDATE, AXFR/IXFR) write to WAL before applying
- On crash recovery: replay WAL to reconstruct zone state
- WAL compaction: checkpoint + truncate after snapshot

### 3.3 Embedded BoltDB Alternative (5d)
**Risk:** The custom KV store may have edge cases. Consider adding pure Go `github.com/etcd-io/betcd` as optional storage backend (breaks zero-dep for storage only), OR fully validate existing KV.
**Decision Point:** If custom KV passes chaos testing in 3.2, keep it. If not, introduce `etcd-io/bbolt` (single-file, pure Go, no Cgo).
**Note:** This would be the **only** external dependency exception, scoped to storage only.

### 3.4 Storage Benchmark & Tuning (2d)
- Benchmark KV store under write-heavy workloads
- Tune WAL segment size, memory map size, sync strategy
- Add storage metrics: write latency, compaction frequency, disk usage

**Phase 3 Subtotal: ~20 person-days**

---

## Phase 4: Protocol Completions & Hardening (Day 76-100)

**Goal:** Close remaining RFC compliance gaps and harden protocol implementations.

### 4.1 SVCB/HTTPS RR Full Implementation (5d)
**Problem:** ANALYSIS.md §5.1 shows SVCB as "Partial" — RR type exists but parsing/handling incomplete.
**Status:** `internal/protocol/` has SvcbPriority, TargetName, SvcParams. Need:
- `UnpackSvcb()` / `PackSvcb()` wire format
- SVCB record type handling in zone parser
- HTTPS Bilateral Service Parameters processing

### 4.2 EDNS0 Extended Mechanics (5d)
- Client Subnet (ECS) — RFC 6891 §7
- Cookie (already exists but may need hardening)
- Pipeline / Requestor ID (RFC 7871 §6)
- OPAQUE pseudo-RR for proxied queries

### 4.3 DNAME Iteration (2d)
- DNAME chain following (RFC 6672) in resolver
- DNAME synthesis in authoritative responses

### 4.4 Wildcard Expansion Hardening (2d)
- Proper wildcard matching per RFC 4592
- CNAME + wildcard interaction edge cases

### 4.5 NSEC/NSEC3 Complete Implementation (6d)
**Current:** DNSSEC signer + validator exist but NSEC3PARAM, NSEC3 chain walk may be incomplete.
**Needs:**
- NSEC3 optical downcasing algorithm (RFC 5155 §8)
- NSEC3 zone walking for authenticated denial of existence
- NSEC3PARAM record handling

### 4.6ixfr fallback completeness (2d)
- IXFR with RFC 1995 incremental transfer
- Fallback to AXFR when IXFR not supported
- IXFR journal management (how much to keep)

**Phase 4 Subtotal: ~22 person-days**

---

## Phase 5: Performance & Production Hardening (Day 101-120)

**Goal:** Address performance bottlenecks identified in ANALYSIS.md §6.

### 5.1 Mutex Contention Reduction (5d)
**Problem:** Single mutex on zone store creates contention under high read load.
**Fix:** Implement zone-sharded locks — one `sync.RWMutex` per zone. For zones with high write frequency (e.g., frequently updated DDNS zones), allow finer-grained locking.
**Alternative:** Use `sync.Map` per zone with fine-grained write locking.

### 5.2 UDP Worker Pool Tuning (3d)
**Problem:** UDP worker pool may have contention under high query rates.
**Analysis:** Profile under high QPS (e.g., 50k-100k qps). If contention found:
- Increase worker pool size
- Use lock-free queues between packet intake and workers
- Batch process incoming packets

### 5.3 Zero-Copy Buffer Paths (5d)
- In hot path (cache hit responses), eliminate intermediate allocations
- `sync.Pool` for response buffers in UDP/TCP servers
- `Header.Clone()` avoidance on cache hit path
- Profile with `pprof` before and after

### 5.4 Upstream Connection Pooling (3d)
**Problem:** Each recursive query may create a new upstream connection for DoT/DoH.
**Fix:** Connection pool per upstream with keepalive, idle timeout, max connections.
**Already exists:** `internal/upstream/` has connection pooling — verify it's enabled and tuned.

### 5.5 Memory Profiler & OOM Tuning (2d)
- The `internal/memory/monitor.go` exists — verify it's enabled in production builds
- Tune cache size limits based on available system memory
- Add memory metrics: heap allocations, GC pause frequency

### 5.6 DNSSEC Validation Caching (2d)
- Cache DNSSEC validation results (positive + negative)
- Avoid re-validating same (zone, name, type, RRSIG) tuples
- Validate at zone-cut boundaries, not per-record

**Phase 5 Subtotal: ~20 person-days**

---

## Phase 6: Developer Experience & Documentation (Day 121-135)

**Goal:** Improve the out-of-box experience for contributors and users.

### 6.1 Frontend Build Pipeline (5d)
**Problem:** `web/` source has no `package.json` with build scripts — makes frontend development painful.
**Fix:** Add minimal build tooling:
- `pnpm init` + `pnpm add -D vite @vitejs/plugin-react typescript @types/react @types/react-dom`
- `pnpm dev` for hot reload during development
- `pnpm build` to generate assets for embedding
- `pnpm build:silent` for CI (no output)
- Update `internal/dashboard/static.go` to re-generate from `web/dist/`

### 6.2 TypeScript Strict Mode (3d)
**Problem:** Frontend code is mostly plain JavaScript in `.tsx` files.
**Fix:** Add `tsconfig.json` with `"strict": true`. Fix all type errors. Add type coverage for `api.ts` and `utils.ts` interfaces.

### 6.3 Contribution Guide (2d)
- `.github/CONTRIBUTING.md`: development setup, coding standards, PR process
- `.github/CODEOWNERS`: auto-assign reviewers
- `.github/ISSUE_TEMPLATE/`: bug report, feature request templates
- `docs/` directory for architecture decision records (ADRs)

### 6.4 API Documentation (3d)
- OpenAPI spec generation from route handlers
- Interactive Swagger UI already exists (`/api/v1/swagger`) — verify completeness
- Document all MCP tools with examples

### 6.5 Example Configurations (2d)
- `examples/` directory with production-grade configs:
  - Authoritative-only primary
  - Authoritative + recursive forwarding
  - High-availability 3-node cluster
  - DNSSEC signing zone
- Test configs for all supported scenarios

**Phase 6 Subtotal: ~15 person-days**

---

## Phase 7: Release Preparation (Day 136-155)

**Goal:** Ship a production-ready v1.0 with clean CI, packaging, and documentation.

### 7.1 Release Build Pipeline (3d)
- Add `.goreleaser.yml` for multi-platform binaries (Linux amd64/arm64, macOS, Windows)
- Docker multi-arch build (amd64, arm64)
- Binary signing (optional, for enterprise adoption)
- SHA256 checksums + cosign signatures

### 7.2 Full Regression Test Suite (5d)
- System-level integration tests: start real servers on non-privileged ports
- End-to-end DNS resolution tests (query → response with all RR types)
- Cluster failure scenarios: node join, leave, partition, recovery
- DNSSEC validation chain tests with known answers
- TLS/DoH/DoQ interoperability with known good clients (dig, cloudflare-resolver)

### 7.3 Security Audit (5d)
- Third-party code audit (or internal if team has security expertise)
- Threat model: DNS amplification, cache poisoning, zone transfer leaks, DoS
- Fuzz testing: DNS message parser with `go-fuzz`
- TLS configuration hardening checklist

### 7.4 Performance Benchmark (2d)
- Establish baseline benchmarks: queries/second, latency percentiles (p50/p99/p999)
- Run against production-grade tools (dnsperf, queryload)
- Compare against unbound, bind, cloudflare-resolver
- Document results in `docs/performance.md`

### 7.5 Versioning & Changelog (2d)
- Semantic versioning (v1.0.0 for first release)
- `CHANGELOG.md`: all changes since last release, organized by category
- `VERSION` file for binary introspection
- GitHub Releases with auto-generated changelog

### 7.6 Production Readiness Final Review (3d)
- Re-run ANALYSIS.md scoring with completed items
- Final `go vet ./...` pass
- Final test suite pass (all platforms)
- Documentation review: README, SPECIFICATION.md accuracy vs implementation

**Phase 7 Subtotal: ~20 person-days**

---

## Summary Table

| Phase | Name | Effort (days) | Cumulative |
|-------|------|---------------|------------|
| 1 | Critical Fixes & Hygiene | 10.5 | 10.5 |
| 2 | Raft Clustering | 55 | 65.5 |
| 3 | Storage Integration | 20 | 85.5 |
| 4 | Protocol Completions | 22 | 107.5 |
| 5 | Performance Hardening | 20 | 127.5 |
| 6 | Developer Experience | 15 | 142.5 |
| 7 | Release Preparation | 20 | 162.5 |

**Grand Total: ~162.5 person-days**

---

## Dependency Graph

```
Phase 1 (Critical Fixes)
    │
    ├─► Phase 2 (Raft Clustering) ──────────────────────────────┐
    │       │                                                     │
    │       │  Phase 3 (Storage Integration)                     │
    │       │       │                                             │
    │       └───────┼────────────────────────────► Phase 4 ──────►│
    │               │                                    │        │
    │               └────► Phase 5 ◄─────────────────────┘        │
    │                       │                                         │
    └───────────────────────┴────► Phase 6 ─► Phase 7 ─► v1.0      │
```

**Key dependencies:**
- Phase 1 must complete before any other phase (clean build prerequisite)
- Phase 2 (Raft) does not depend on Phase 3 (Storage) — can run in parallel after Phase 1
- Phase 3 and Phase 4 can run in parallel after Phase 1 (different subsystems)
- Phase 5 depends on Phase 2 + Phase 3 + Phase 4 complete (full system)
- Phase 6 (DevEx) can start after Phase 2 (cluster APIs stable)
- Phase 7 (Release) requires all previous phases complete

---

## Priority Matrix

| Priority | Item | Phase | Effort | Impact |
|----------|------|-------|--------|--------|
| P0 | Fix go vet error | 1.1 | 0.5d | Blocks CI |
| P0 | Fix auth tests | 1.2 | 2d | Security coverage |
| P0 | Fix integration tests | 1.3 | 2d | Windows support |
| P0 | Raft Clustering | 2 | 55d | Spec compliance |
| P1 | Silent error handling | 1.4 | 5d | Reliability |
| P1 | KV Store integration | 3.1-3.2 | 13d | Data durability |
| P1 | SVCB/HTTPS RR | 4.1 | 5d | RFC compliance |
| P1 | NSEC3 completion | 4.5 | 6d | DNSSEC coverage |
| P2 | Mutex contention | 5.1 | 5d | High-QPS perf |
| P2 | Frontend build pipeline | 6.1 | 5d | DX |
| P2 | Regression test suite | 7.2 | 5d | Ship confidence |
| P3 | All other items | Various | ~65d | Polish |

---

## Appendix: Removed/Downsized Items

These items were considered but **not included** in the roadmap based on cost/benefit analysis:

1. **IPv6-only deployment mode** — Nice-to-have, low priority, few users need it
2. **Metrics prefix customization** — Trivial config change, not roadmap-worthy
3. **Full Prometheus alerting rules** — Out of scope for DNS server itself
4. **Multi-tenant isolation** — Architectural change, not needed for v1.0
5. **Custom TLS cert management** — ACME/Let's Encrypt integration — defer to v1.1
