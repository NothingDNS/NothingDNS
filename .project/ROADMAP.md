# Project Roadmap

> Based on comprehensive codebase analysis performed on 2026-04-11
> This roadmap prioritizes work needed to bring the project to production quality.

## Current State Assessment

**Position**: NothingDNS v0.1.0 is released (2026-04-05) with comprehensive DNS server functionality. The codebase demonstrates production-grade engineering with:
- Zero external Go dependencies
- 161K+ LOC across 294 Go files
- All 29 test packages passing
- Zero `go vet` warnings
- Comprehensive feature set (authoritative, recursive, DoT/DoH/DoQ, DNSSEC, clustering)

**Key Blockers for Production Readiness:**
1. Frontend uses React (breaks zero-dependency philosophy) — but is functional
2. XoT (TLS zone transfer) not implemented — security concern for production
3. SWIM used by default instead of Raft — spec deviation

**What's Working Well:**
- DNS wire protocol implementation is comprehensive and well-tested
- DNSSEC signing/validation complete with multiple algorithms
- Storage layer (KV + WAL) provides crash-safe persistence
- Test coverage is strong across all packages
- Documentation is excellent (SPEC, IMP, TASKS, PRODUCTION_READINESS)

---

## Phase 1: Critical Security Fixes (Week 1-2)

### Must-fix items blocking production deployment

- [ ] **XoT (RFC 9103)** — Zone Transfer over TLS
  - Spec reference: RCP_IMPLEMENTATION.md §1.1
  - Current gap: AXFR/IXFR only over plaintext TCP
  - Implementation plan: Add TLS listener on port 853 for AXFR/IXFR, integrate TLSA record validation
  - Affected files: `internal/transfer/xot.go` [NEW], `internal/server/tls.go` [MODIFY]
  - Effort: ~3-4 days

- [ ] **API Secrets Handling** — No query param exposure
  - Spec reference: SECURITY.md
  - Current gap: Bearer tokens can be passed via query params, exposing in logs
  - Implementation plan: Require Authorization header only, reject query param tokens
  - Affected files: `internal/api/server.go`
  - Effort: ~1 day

---

## Phase 2: Specification Compliance (Week 3-4)

### Align implementation with documented architecture

- [ ] **Raft as Default Cluster Mode** — Make Raft the default, not SWIM
  - Spec reference: SPEC.md §10 "Cluster-First — Raft consensus for zone replication"
  - Current gap: SWIM gossip is default; Raft exists but not promoted
  - Implementation plan: Change default consensus mode, ensure Raft is stable for single-node deployments
  - Affected files: `internal/cluster/cluster.go`, config defaults
  - Effort: ~2-3 days

- [ ] **Vanilla JS Dashboard** — Replace React with framework-free UI
  - Spec reference: SPEC.md §17 "Embedded vanilla JS dashboard (no framework)"
  - Current gap: React 19 + Tailwind CSS with 9 npm packages
  - Implementation plan: Either (a) replace with vanilla JS + CSS or (b) document the exception to zero-dependency policy
  - Affected files: `web/` directory
  - Effort: ~5-7 days (if rewriting) or ~0.5 day (if documenting exception)

- [ ] **ZONEMD Integration** — Wire up zone message digest
  - Spec reference: RCP_IMPLEMENTATION.md §1.5, SPEC.md §12
  - Current gap: `internal/zone/zonemd.go` exists but integration unclear
  - Implementation plan: Integrate ZONEMD computation into zone transfers
  - Affected files: `internal/zone/zonemd.go`, `internal/transfer/axfr.go`
  - Effort: ~2 days

---

## Phase 3: Missing RFCs (Week 5-8)

### Complete RFC implementation plan items

- [ ] **mDNS (RFC 6762)** — Multicast DNS for .local resolution
  - Spec reference: RCP_IMPLEMENTATION.md §1.2
  - Current gap: Not implemented
  - Implementation plan: New `internal/mdns/` package with querier, responder, browser
  - Affected files: `internal/mdns/*` [NEW]
  - Effort: ~4-5 days

- [ ] **DNS-SD (RFC 6763)** — Service discovery
  - Spec reference: RCP_IMPLEMENTATION.md §1.3
  - Current gap: Not implemented
  - Implementation plan: Implement service browser, PTR queries for _service._proto
  - Affected files: `internal/mdns/*` [MODIFY]
  - Effort: ~2 days

- [ ] **DSO (RFC 8490)** — DNS Stateful Operations
  - Spec reference: RCP_IMPLEMENTATION.md §2.1
  - Current gap: Not implemented
  - Implementation plan: Add DSO session management, keepalive, redirect
  - Affected files: `internal/dso/*` [NEW]
  - Effort: ~3-4 days

- [ ] **SIG(0) (RFC 2931)** — Transaction signatures with public keys
  - Spec reference: RCP_IMPLEMENTATION.md §2.7
  - Current gap: Not implemented (only TSIG with shared secrets)
  - Implementation plan: Add SIG(0) record type, sign/verify with public keys
  - Affected files: `internal/transfer/sig0.go` [NEW]
  - Effort: ~3 days

---

## Phase 4: Hardening & Edge Cases (Week 9-10)

### Security, error handling, edge cases

- [ ] **TSIG MD5 Deprecation Warning** — Log warning when HMAC-MD5 used
  - Current state: HMAC-MD5 silently accepted
  - Implementation plan: Add warning log when TSIG algorithm is MD5
  - Affected files: `internal/transfer/tsig.go`
  - Effort: ~0.5 day

- [ ] **NSEC3 Robustness** — Handle NSEC3 chain edge cases
  - Current state: Partial NSEC3 support
  - Implementation plan: Verify opt-out handling, bitmap generation
  - Affected files: `internal/dnssec/`, `internal/protocol/`
  - Effort: ~2 days

- [ ] **DNSSEC Validation Cache Tuning** — Adjust cache TTL
  - Current state: 5-minute TTL hardcoded
  - Implementation plan: Make configurable via config
  - Affected files: `internal/dnssec/validator.go`
  - Effort: ~0.5 day

- [ ] **Graceful Degradation Tests** — Verify behavior under failure
  - Current state: Basic tests pass
  - Implementation plan: Add chaos testing for network partition, node failure
  - Affected files: `internal/cluster/*_test.go`
  - Effort: ~2 days

---

## Phase 5: Testing Completeness (Week 11-12)

### Comprehensive test coverage

- [ ] **Package Coverage Audit** — Identify packages below 70%
  - Current state: Estimated ~75% overall
  - Implementation plan: Run `go test -cover` on each package, target 80%+
  - Affected files: All packages
  - Effort: ~3 days (across all packages)

- [ ] **E2E Test Suite** — Full integration tests
  - Current state: Unit + integration tests present
  - Implementation plan: Add end-to-end DNS resolution tests with real network
  - Affected files: `cmd/nothingdns/main_test.go` or new `e2e/` directory
  - Effort: ~2 days

- [ ] **Fuzz Tests Expansion** — More malformed input testing
  - Current state: `internal/protocol/fuzz_test.go` exists
  - Implementation plan: Add fuzz tests for zone parser, config parser
  - Affected files: `internal/config/parser.go`, `internal/zone/zone.go`
  - Effort: ~2 days

---

## Phase 6: Performance Optimization (Week 13-14)

### Performance tuning and optimization

- [ ] **Cache Performance Analysis** — Profile cache hit rate
  - Current state: Basic metrics exported
  - Implementation plan: Add detailed cache miss analysis, hot key detection
  - Affected files: `internal/cache/cache.go`
  - Effort: ~1 day

- [ ] **Zone Loading Optimization** — Parallel zone loading
  - Current state: Sequential zone file parsing
  - Implementation plan: Parse zones in parallel on startup
  - Affected files: `cmd/nothingdns/main.go`, `internal/zone/`
  - Effort: ~1 day

- [ ] **DNSSEC Signing Cache** — RRSIG caching improvements
  - Current state: 5-minute validation cache
  - Implementation plan: Add RRSIG answer cache to avoid re-signing
  - Affected files: `internal/dnssec/signer.go`
  - Effort: ~2 days

- [ ] **UDP Socket Tuning** — SO_REUSEPORT verification
  - Current state: SO_REUSEPORT used
  - Implementation plan: Verify multi-core scaling, add metrics
  - Affected files: `internal/server/udp.go`
  - Effort: ~0.5 day

---

## Phase 7: Documentation & DX (Week 15-16)

### Documentation and developer experience

- [ ] **API Documentation** — Complete Swagger/OpenAPI spec
  - Current state: OpenAPI 3.0 spec exists
  - Implementation plan: Verify all endpoints documented, add examples
  - Affected files: `internal/api/openapi.go`
  - Effort: ~1 day

- [ ] **Deployment Guide** — Production deployment checklist
  - Current state: Basic systemd service file
  - Implementation plan: Add Kubernetes Helm chart, production hardening guide
  - Affected files: `deploy/` directory
  - Effort: ~2 days

- [ ] **Benchmarking Report** — Document performance targets
  - Current state: SPEC.md §14 has targets
  - Implementation plan: Run benchmarks, document actual vs target
  - Affected files: `docs/PERFORMANCE.md` [NEW]
  - Effort: ~1 day

- [ ] **CLAUDE.md Update** — Ensure accuracy
  - Current state: Needs verification against current code
  - Implementation plan: Re-review for accuracy after recent changes
  - Affected files: `CLAUDE.md`
  - Effort: ~0.5 day

---

## Phase 8: Release Preparation (Week 17-18)

### Final production preparation

- [ ] **Version Bump** — v0.2.0 or v1.0.0
  - Current state: v0.1.0 released 2026-04-05
  - Implementation plan: Evaluate feature completeness, decide version
  - Affected files: `VERSION`, `CHANGELOG.md`, `go.mod`
  - Effort: ~0.5 day

- [ ] **Security Audit** — Third-party review
  - Current state: Internal review
  - Implementation plan: Engage external security researchers
  - Affected files: N/A
  - Effort: ~3-5 days (external)

- [ ] **Release Automation** — goreleaser configuration
  - Current state: Manual builds
  - Implementation plan: Complete `.goreleaser.yml`, add GitHub Actions release workflow
  - Affected files: `.github/workflows/release.yml` [NEW]
  - Effort: ~1 day

---

## Beyond v1.0: Future Enhancements

### Features and improvements for future versions

- [ ] **Multi-Signer DNSSEC (RFC 8901)** — Multiple providers signing same zone
- [ ] **Compact NSEC (RFC 9824)** — NSEC4 for smaller proofs
- [ ] **TKEY (RFC 2930)** — Secret key establishment
- [ ] **CHAIN Queries (RFC 7901)** — Return trust chain in response
- [ ] **DNS Error Reporting (RFC 9567)** — Extended error codes
- [ ] **YANG Types (RFC 9108)** — NETCONF/YANG management
- [ ] **Compacted DNS (RFC 8618)** — C-DNS packet capture format
- [ ] **DNS Catalog Zones (RFC 9432)** — Zone provisioning automation

---

## Effort Summary

| Phase | Estimated Hours | Priority | Dependencies |
|---|---|---|---|
| Phase 1 | ~4-5 days | **CRITICAL** | None |
| Phase 2 | ~8-10 days | **HIGH** | Phase 1 |
| Phase 3 | ~11-14 days | **MEDIUM** | Phase 2 |
| Phase 4 | ~6-7 days | **MEDIUM** | Phase 3 |
| Phase 5 | ~7 days | **MEDIUM** | Phase 4 |
| Phase 6 | ~4-5 days | **LOW** | Phase 5 |
| Phase 7 | ~4-5 days | **LOW** | Phase 6 |
| Phase 8 | ~4-6 days | **HIGH** | All phases |
| **Total** | **~50-60 days** | | |

**Estimated Time to Production Ready (v1.0):** ~12-15 weeks

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| XoT implementation complexity | High | Medium | Use TLS handshake from existing DoT code |
| React frontend rewrite | Medium | High | Option to document exception instead of rewrite |
| Raft stability issues | Low | High | Extensive testing, gradual rollout |
| mDNS multicast complexity | Medium | Medium | Use existing UDP infrastructure |
| External security audit findings | Medium | High | Address critical findings before release |

---

*Document Version: 1.0*
*Generated: 2026-04-11*
*Roadmap based on comprehensive codebase analysis*
