# NothingDNS Roadmap

> Prioritized implementation roadmap based on comprehensive codebase audit
> Generated: 2026-04-08
> Reference: `.project/ANALYSIS.md`, `files/SPECIFICATION.md`, `files/TASKS.md`

## Overview

The audit reveals ~75–80% task completion with one critical architectural deviation (SWIM vs Raft) and two significant integration gaps (KV store not wired, auth package has no tests). This roadmap prioritizes work into 7 phases sequenced by dependency order and criticality. Estimates in **person-days** (8h each).

**Assumptions:**
- Team: 1–2 senior Go engineers, full-time on NothingDNS
- Zero-dependency constraint maintained throughout (except possibly BoltDB — Phase 3 decision point)
- Go 1.23+, pure stdlib

**Total Estimated Effort:** ~160 person-days (~1,280 hours)

---

## Phase 1: Critical Fixes & Hygiene (Day 1–10)

**Goal:** Achieve a clean `go vet ./...` and resolve blocking code quality issues before anything else.

### 1.1 Fix go vet Unkeyed Fields Warning (~0.5d)
**File:** `cmd/nothingdns/main.go:482`
**Problem:** `auth.Duration{Duration: value}` should use keyed fields
**Fix:** Change to `auth.Duration{Duration: value}` — one-line fix
**Verification:** `go vet ./...` passes zero warnings

### 1.2 Add Tests for internal/auth (~2d)
**File:** `internal/auth/auth_test.go` (does not exist)
**Problem:** Security-critical code (JWT, RBAC, password hashing) has zero test coverage
**Fix:** Add comprehensive tests:
- JWT token generation and validation
- RBAC role enforcement (admin/operator/viewer)
- Password hashing with bcrypt cost
- Token expiry handling
- Invalid token rejection
**Verification:** `go test ./internal/auth/...` passes with meaningful coverage

### 1.3 Fix Windows Integration Test Port Binding (~2d)
**Problem:** `TestRecordQueryLatency_PrometheusOutput` (metrics) and integration tests fail on Windows with `bind: An attempt was made to access a socket in a way forbidden by its access permissions`
**Diagnosis:** Likely UDP port not released between tests or test isolation issue on Windows
**Fix:** Use port `:0` for dynamic allocation, ensure `defer close()` on listeners, add Windows-specific test isolation
**Verification:** `go test ./...` passes on Windows

### 1.4 Silent Error Handling Audit (~5d)
**Problem:** Errors silently discarded in several protocol handlers — a reliability and security concern
**Files to audit and fix:**
- `internal/transfer/tsig.go` — TSIG parse errors silently ignored
- `internal/cluster/gossip.go` — message parse failures silently discarded
- `internal/resolver/` — upstream errors logged at debug only
- `internal/protocol/` — serial arithmetic edge cases
**Fix:** Each discarded error: handle properly, log at appropriate level, or add `// error intentionally ignored` with rationale
**Verification:** Code review sign-off, `go vet` clean

### 1.5 Review coverage_extra Test Files (~1d)
**Problem:** Many packages have `coverage_extra*_test.go` files that may inflate coverage without testing real scenarios
**Action:** Audit each file — are they testing genuinely tricky error paths or just padding coverage numbers?
**Verification:** Each coverage_extra file has a comment explaining the specific edge case it targets

**Phase 1 Subtotal: ~10.5 person-days**

---

## Phase 2: Cluster — Raft Implementation (Day 11–65)

**Goal:** Replace SWIM gossip-based cluster with proper Raft consensus as specified in SPECIFICATION.md §10. This is the largest remaining feature gap.

### 2.1 Raft Core Engine (~25d)
**Reference:** SPECIFICATION.md §10, IMPLEMENTATION.md §11

Implement from scratch (per spec requirement) with:
- **State Machine:** Leader, Follower, Candidate states with transitions on term changes
- **RequestVote RPC:** Term, candidateID, lastLogIndex, lastLogTerm. Vote granting with term check.
- **AppendEntries RPC:** PrevLogIndex, PrevLogTerm, Entries[], LeaderCommit. Consistency checks.
- **Log Replication:** Entries stored with term + index. Committed entries applied to state machine.
- **Leader Election:** Election timeout randomization (150–300ms), lease-based re-election prevention
- **Snapshots:** Periodic snapshotting of state machine state to compact logs

**Files to create:**
- `internal/cluster/raft/raft.go` — core state machine
- `internal/cluster/raft/log.go` — log management
- `internal/cluster/raft/rpc.go` — RequestVote + AppendEntries RPC handlers
- `internal/cluster/raft/snapshot.go` — snapshotting
- `internal/cluster/raft/wal.go` — Raft-specific WAL entries

**Verification:** Unit tests for leader election, log append, snapshotting. Property-based tests for log consistency.

### 2.2 Zone State Machine on Raft (~10d)
**Problem:** Zone changes (ADD/DELETE/UPDATE records) must be replicated via Raft log, not gossip broadcasts
**Design:**
- Zone mutations go through Raft: propose → replicate → commit → apply
- Each node applies committed entries to its local zone store
- Read queries served from local state (no Raft overhead)
- Consistent reads (for API) require leader confirmation

**Files:** `internal/cluster/raft/zonesm.go` (new)

### 2.3 Inter-Node Binary Protocol (~8d)
**Reference:** SPECIFICATION.md §15
**Design:** Hand-rolled binary protocol (varint length prefix + message type + payload). Messages: RequestVote, RequestVoteResponse, AppendEntries, AppendEntriesResponse, SnapshotChunk, ZoneProposal.
**Implementation:** Reuse `sync.Pool` buffers. Zero-allocation message packing where possible.

### 2.4 Cluster Bootstrap & Discovery (~4d)
- Initial cluster configuration via config file
- Join protocol: node contacts seed node, exchanges topology
- Partition recovery: re-election after majority loss
- Witness/observer nodes (non-voting Raft members)

### 2.5 Migrate from SWIM to Raft (~5d)
- Remove `internal/cluster/gossip.go` and SWIM-related code
- Wire Raft cluster into `main.go` (replace cluster init)
- Update API endpoints (`/api/v1/cluster/*`) to report Raft state
- Update MCP cluster tools

### 2.6 Integration & Chaos Testing (~5d)
- Multi-node cluster tests (3–5 nodes on localhost)
- Network partition simulation
- Leader crash/recovery
- Log recovery after restart
- Performance: election timeout, replication lag benchmarks

**Phase 2 Subtotal: ~57 person-days**

---

## Phase 3: Storage & Persistence Integration (Day 66–85)

**Goal:** Wire the existing KV store + WAL into zone management so zones survive restarts without external file management.

### 3.1 KV Store Zone Persistence (~8d)
**Problem:** `internal/storage/` exists but zones are loaded from files at startup, not persisted through KV store
**Changes:**
- On zone load, write all records to KV store as zone-scoped keys
- On zone update (via API/DDNS), write through to KV store
- On startup, check KV store for persisted zones before loading files
- Background sync: periodic flush of in-memory zone state to KV

**Files:** `internal/storage/zonekv.go` (new), `internal/zone/zone.go` (modify)

### 3.2 WAL Integration for Zone Changes (~5d)
- Zone mutations (DDNS UPDATE, AXFR/IXFR) write to WAL before applying
- On crash recovery: replay WAL to reconstruct zone state
- WAL compaction: checkpoint + truncate after snapshot

### 3.3 BoltDB Decision Point (~5d)
**Risk:** Custom KV store may have edge cases under crash/recovery
**Decision:** If custom KV passes chaos testing in 3.2, keep it. If not, introduce pure-Go `github.com/etcd-io/bbolt` (single-file, pure Go, no Cgo) as storage backend.
**Note:** This would be the **only** external dependency exception, scoped to storage only.
**Alternative:** Validate existing KV store thoroughly first (may shift this to Phase 4)

### 3.4 Storage Benchmark & Tuning (~2d)
- Benchmark KV store under write-heavy workloads
- Tune WAL segment size, memory map size, sync strategy
- Add storage metrics: write latency, compaction frequency, disk usage

**Phase 3 Subtotal: ~20 person-days**

---

## Phase 4: Protocol Completions & Hardening (Day 86–108)

**Goal:** Close remaining RFC compliance gaps and harden protocol implementations.

### 4.1 SVCB/HTTPS RR Full Implementation (~5d)
**Problem:** RR type exists but wire-format pack/unpack is incomplete
**Needs:**
- `UnpackSvcb()` / `PackSvcb()` wire format implementation
- SVCB record type handling in zone parser
- HTTPS bilateral service parameters processing (RFC 9460 §7)
**Reference:** `internal/protocol/types.go` — existing SvcPriority, TargetName, SvcParams constants

### 4.2 EDNS0 Extended Mechanics (~5d)
- Client Subnet (ECS) — RFC 6891 §7
- Cookie hardening (already exists, may need edge cases)
- Pipeline / Requestor ID (RFC 7871 §6)
- OPAQUE pseudo-RR for proxied queries

### 4.3 DNAME Chain Following (~2d)
- DNAME chain following in resolver (RFC 6672)
- DNAME synthesis in authoritative responses
- CNAME + DNAME interaction edge cases

### 4.4 NSEC/NSEC3 Complete Implementation (~6d)
**Current:** DNSSEC signer + validator exist but NSEC3 chain walk may need verification
**Needs:**
- NSEC3 optical downcasing algorithm (RFC 5155 §8)
- NSEC3 zone walking for authenticated denial of existence
- NSEC3PARAM record handling verification

### 4.5 Fuzz Testing for DNS Wire Parser (~3d)
**Problem:** No fuzz testing exists for `internal/protocol/wire.go`
**Implementation:** `go-fuzz` corpus for DNS message parsing
- Message header corruption
- Malformed RR data
- Buffer overrun attempts
- Truncated messages
**Integration:** Run fuzzing continuously, file bugs on crashes

**Phase 4 Subtotal: ~21 person-days**

---

## Phase 5: Performance & Production Hardening (Day 109–128)

**Goal:** Address performance bottlenecks identified in ANALYSIS.md §6.

### 5.1 Zone Store Lock Sharding (~5d)
**Problem:** Single `sync.RWMutex` on ZoneStore creates contention under high read load
**Fix:** Implement zone-sharded locks — one `sync.RWMutex` per zone
**Alternative:** Use `sync.Map` per zone with fine-grained write locking
**Benchmark:** Measure before/after with `go test -bench`

### 5.2 UDP Worker Pool Tuning (~3d)
**Problem:** UDP worker pool may have contention under very high QPS
**Analysis:** Profile under high QPS (50k–100k qps). If contention found:
- Increase worker pool size
- Use lock-free queues between packet intake and workers
- Batch process incoming packets

### 5.3 Zero-Copy Buffer Paths (~5d)
- In hot path (cache hit responses), eliminate intermediate allocations
- `sync.Pool` for response buffers in UDP/TCP servers (already exists — verify)
- `Header.Clone()` avoidance on cache hit path
- Profile with `pprof` before and after

### 5.4 Upstream Connection Pooling Verification (~2d)
**Problem:** Each recursive query may create a new upstream connection
**Fix:** Verify connection pool in `internal/upstream/` is enabled and tuned for DoT/DoH

### 5.5 DNSSEC Validation Cache Tuning (~2d)
**Current:** 5-minute TTL cache exists per CHANGELOG v0.1.0
**Needs:** Verify cache size limits, eviction policy, memory bounds

### 5.6 Publish Performance Benchmarks (~3d)
- Establish baseline: queries/second, latency percentiles (p50/p99/p999)
- Run against production-grade tools (dnsperf, queryload)
- Compare against unbound, bind, cloudflare-resolver
- Document in `docs/performance.md`

**Phase 5 Subtotal: ~20 person-days**

---

## Phase 6: Developer Experience & Documentation (Day 129–143)

**Goal:** Improve the out-of-box experience for contributors and users.

### 6.1 Frontend Build Pipeline (~5d)
**Problem:** `web/` has source but no clearly documented dev workflow
**Fix:**
- `pnpm dev` for hot reload during development
- `pnpm build` to generate assets for embedding
- Update `internal/dashboard/static.go` to re-generate from `web/dist/`
- Document in `web/README.md`

### 6.2 TypeScript Strict Mode (~3d)
**Problem:** Frontend code is mostly plain JavaScript in `.tsx` files
**Fix:**
- Add `tsconfig.json` with `"strict": true`
- Fix all type errors
- Add type coverage for `api.ts` and `utils.ts` interfaces

### 6.3 Contribution Guide (~2d)
- `.github/CONTRIBUTING.md`: development setup, coding standards, PR process
- `.github/CODEOWNERS`: auto-assign reviewers
- `.github/ISSUE_TEMPLATE/`: bug report, feature request templates
- `docs/` directory for architecture decision records (ADRs)

### 6.4 API Documentation (~3d)
- OpenAPI spec generation from route handlers (already has Swagger UI)
- Document all MCP tools with examples
- Verify completeness of `/api/v1/swagger`

### 6.5 Example Configurations (~2d)
- `examples/` directory with production-grade configs:
  - Authoritative-only primary
  - Authoritative + recursive forwarding
  - High-availability 3-node cluster
  - DNSSEC signing zone

**Phase 6 Subtotal: ~15 person-days**

---

## Phase 7: Release Preparation (Day 144–160)

**Goal:** Ship a production-ready v1.0 with clean CI, packaging, and documentation.

### 7.1 Release Build Pipeline (~3d)
- Add `.goreleaser.yml` for multi-platform binaries (Linux amd64/arm64/armv7, macOS amd64/arm64, Windows amd64, FreeBSD amd64)
- Docker multi-arch build (amd64, arm64)
- SHA256 checksums + cosign signatures

### 7.2 Full Regression Test Suite (~5d)
- System-level integration tests: start real servers on non-privileged ports
- End-to-end DNS resolution tests (query → response with all RR types)
- Cluster failure scenarios: node join, leave, partition, recovery
- DNSSEC validation chain tests with known answers
- TLS/DoH/DoQ interoperability with known good clients (dig, cloudflare-resolver)

### 7.3 Security Audit (~5d)
- Threat model: DNS amplification, cache poisoning, zone transfer leaks, DoS
- Fuzz testing results triage
- TLS configuration hardening checklist
- Attack surface review

### 7.4 Versioning & Changelog (~2d)
- Semantic versioning (v1.0.0)
- `CHANGELOG.md` update with all changes since v0.1.0
- `VERSION` file for binary introspection
- GitHub Releases with auto-generated changelog

### 7.5 Production Readiness Final Review (~5d)
- Re-run scoring from ANALYSIS.md with completed items
- Final `go vet ./...` pass
- Final test suite pass (all platforms)
- Documentation review: README, SPECIFICATION.md accuracy vs implementation
- Deploy to staging environment for smoke testing

**Phase 7 Subtotal: ~20 person-days**

---

## Summary Table

| Phase | Name | Effort (days) | Cumulative |
|-------|------|-------------|------------|
| 1 | Critical Fixes & Hygiene | 10.5 | 10.5 |
| 2 | Raft Clustering | 57 | 67.5 |
| 3 | Storage Integration | 20 | 87.5 |
| 4 | Protocol Completions | 21 | 108.5 |
| 5 | Performance Hardening | 20 | 128.5 |
| 6 | Developer Experience | 15 | 143.5 |
| 7 | Release Preparation | 20 | 163.5 |

**Grand Total: ~163.5 person-days**

---

## Dependency Graph

```
Phase 1 (Critical Fixes)
    │
    ├─► Phase 2 (Raft) ─────────────────────────────────────────────┐
    │       │                                                          │
    │       │  Phase 3 (Storage)  ◄───────────────────────────────────┤
    │       │       │                                                │
    │       └───────┼──────────────────┐                              │
    │               │                  │                               │
    │               ▼                  ▼                               │
    │       Phase 4 ◄────────────► Phase 5                             │
    │           │                       │                               │
    └───────────┴───────────────────────┴────► Phase 6 ─► Phase 7     │
```

**Key dependencies:**
- Phase 1 must complete before everything else (clean vet/CI prerequisite)
- Phase 2 (Raft) and Phase 3 (Storage) can run in parallel after Phase 1
- Phase 4 and Phase 5 can run in parallel after Phase 1
- Phase 6 (DevEx) can start after Phase 2 cluster APIs are stable
- Phase 7 requires all previous phases

---

## Priority Matrix

| Priority | Item | Phase | Effort | Impact |
|----------|------|-------|--------|--------|
| P0 | Fix go vet warning | 1.1 | 0.5d | Blocks CI |
| P0 | Add auth tests | 1.2 | 2d | Security coverage |
| P0 | Raft Clustering | 2 | 57d | Spec compliance |
| P1 | KV store zone wiring | 3.1 | 8d | Data durability |
| P1 | Silent error handling | 1.4 | 5d | Reliability |
| P1 | Windows integration tests | 1.3 | 2d | QA |
| P1 | SVCB/HTTPS RR | 4.1 | 5d | RFC compliance |
| P1 | NSEC3 completion | 4.4 | 6d | DNSSEC coverage |
| P2 | Mutex sharding | 5.1 | 5d | High-QPS perf |
| P2 | Frontend build pipeline | 6.1 | 5d | DX |
| P2 | Regression test suite | 7.2 | 5d | Ship confidence |
| P3 | All other items | Various | ~60d | Polish |

---

## Appendix: Removed Items

These items were considered but **not included** based on cost/benefit:

1. **IDNAc ** — Already implemented per CHANGELOG v0.1.0
2. **ZoneMD ** — Already implemented per CHANGELOG v0.1.0
3. **IPv6-only deployment mode** — Nice-to-have, low deployment share
4. **Metrics prefix customization** — Trivial config change, not roadmap-worthy
5. **Multi-tenant isolation** — Architectural change, defer to v1.1
6. **ACME/Let's Encrypt** — Defer to v1.1
