# NothingDNS — Task Breakdown

> Granular task list for implementation. Each task is a self-contained, testable unit.
> Estimated total: ~24 weeks for solo developer.

---

## Legend
- 🔴 Critical Path (blocks other tasks)
- 🟡 Important (needed for milestone)
- 🟢 Enhancement (can be deferred)
- ⏱️ Estimated hours
- 📦 Dependencies (task IDs that must complete first)

---

## Phase 1: Foundation

### P1.1 — Project Bootstrap
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 1.1.1 | Create go.mod (zero dependencies), directory structure per SPEC | 🔴 | 1h | — |
| 1.1.2 | Create cmd/nothingdns/main.go skeleton (flag parsing, signal handling) | 🔴 | 2h | 1.1.1 |
| 1.1.3 | Create cmd/dnsctl/main.go skeleton (subcommand parser) | 🟡 | 2h | 1.1.1 |
| 1.1.4 | Create Makefile (build, test, bench, lint, release, docker targets) | 🟡 | 1h | 1.1.1 |
| 1.1.5 | Create Dockerfile (FROM scratch, multi-stage build) | 🟢 | 1h | 1.1.1 |

### P1.2 — Shared Utilities
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 1.2.1 | internal/util/logger.go — Structured logger (JSON + text, levels) | 🔴 | 3h | 1.1.1 |
| 1.2.2 | internal/util/pool.go — sync.Pool wrappers for byte buffers | 🔴 | 1h | 1.1.1 |
| 1.2.3 | internal/util/ip.go — IP parse, CIDR match, v4/v6 detection | 🔴 | 2h | 1.1.1 |
| 1.2.4 | internal/util/domain.go — Domain validation, normalize, label split | 🔴 | 2h | 1.1.1 |
| 1.2.5 | internal/util/signal.go — Graceful shutdown (SIGINT/SIGTERM/SIGHUP) | 🔴 | 1h | 1.1.1 |
| 1.2.6 | Tests for all util packages | 🔴 | 2h | 1.2.1–1.2.5 |

### P1.3 — DNS Wire Protocol
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 1.3.1 | internal/protocol/constants.go — All DNS constants (opcodes, rcodes, types, classes) | 🔴 | 1h | 1.1.1 |
| 1.3.2 | internal/protocol/wire.go — Binary helpers, buffer pool | 🔴 | 2h | 1.2.2 |
| 1.3.3 | internal/protocol/labels.go — Label compression/decompression with loop detection | 🔴 | 4h | 1.3.2 |
| 1.3.4 | internal/protocol/header.go — 12-byte header marshal/unmarshal with bit flags | 🔴 | 2h | 1.3.2 |
| 1.3.5 | internal/protocol/question.go — Question section marshal/unmarshal | 🔴 | 1h | 1.3.3, 1.3.4 |
| 1.3.6 | internal/protocol/record.go — ResourceRecord base + RData interface | 🔴 | 2h | 1.3.3 |
| 1.3.7 | internal/protocol/types.go — A, AAAA record types | 🔴 | 2h | 1.3.6 |
| 1.3.8 | internal/protocol/types.go — CNAME, NS, PTR record types | 🔴 | 2h | 1.3.6 |
| 1.3.9 | internal/protocol/types.go — MX, TXT, SOA record types | 🔴 | 3h | 1.3.6 |
| 1.3.10 | internal/protocol/types.go — SRV, CAA, NAPTR, SSHFP, TLSA record types | 🟡 | 3h | 1.3.6 |
| 1.3.11 | internal/protocol/edns.go — OPT record, EDNS Client Subnet option | 🔴 | 4h | 1.3.6 |
| 1.3.12 | internal/protocol/message.go — Full Message marshal/unmarshal | 🔴 | 4h | 1.3.4–1.3.11 |
| 1.3.13 | Round-trip tests for all record types (marshal → unmarshal → compare) | 🔴 | 4h | 1.3.12 |
| 1.3.14 | Fuzz tests for message parser (malformed input resilience) | 🟡 | 2h | 1.3.12 |

### P1.4 — Basic Listeners
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 1.4.1 | internal/server/handler.go — Handler interface, ClientInfo, basic pipeline | 🔴 | 2h | 1.3.12 |
| 1.4.2 | internal/server/udp.go — UDP listener with worker pool | 🔴 | 4h | 1.4.1 |
| 1.4.3 | internal/server/tcp.go — TCP listener with length-prefix framing | 🔴 | 3h | 1.4.1 |
| 1.4.4 | Integration test: send UDP query, receive response | 🔴 | 2h | 1.4.2 |
| 1.4.5 | Integration test: send TCP query, receive response | 🔴 | 1h | 1.4.3 |

### P1.5 — Configuration (Basic)
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 1.5.1 | internal/config/config.go — YAML tokenizer (line-by-line, indentation tracking) | 🔴 | 6h | 1.1.1 |
| 1.5.2 | internal/config/config.go — YAML tree builder (maps, sequences, scalars) | 🔴 | 4h | 1.5.1 |
| 1.5.3 | internal/config/config.go — Unmarshal to Config struct (typed parse methods) | 🔴 | 4h | 1.5.2 |
| 1.5.4 | internal/config/config.go — Environment variable expansion (${VAR:-default}) | 🟡 | 2h | 1.5.3 |
| 1.5.5 | internal/config/defaults.go — Default values for all config sections | 🔴 | 2h | 1.5.3 |
| 1.5.6 | internal/config/validate.go — Config validation (required fields, ranges, formats) | 🔴 | 3h | 1.5.3 |
| 1.5.7 | configs/nothingdns.yaml — Example configuration file | 🟡 | 1h | 1.5.3 |
| 1.5.8 | Tests for YAML parser (valid + invalid + edge cases) | 🔴 | 3h | 1.5.3 |

**🏁 Phase 1 Milestone: Binary listens on :53, responds REFUSED to all queries. ~80h**

---

## Phase 2: Authoritative Engine

### P2.1 — Zone Data Structures
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 2.1.1 | internal/auth/zone.go — Zone struct, RRSet, radix tree (insert, lookup, delete) | 🔴 | 6h | 1.3.12 |
| 2.1.2 | Radix tree tests (insert, exact match, longest prefix match, delete) | 🔴 | 3h | 2.1.1 |

### P2.2 — Zone File Parser
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 2.2.1 | internal/auth/zonefile.go — Tokenizer (handle parens, quotes, semicolons) | 🔴 | 4h | 2.1.1 |
| 2.2.2 | internal/auth/zonefile.go — Directive handling ($ORIGIN, $TTL, $INCLUDE) | 🔴 | 3h | 2.2.1 |
| 2.2.3 | internal/auth/zonefile.go — Record line parsing (owner, TTL, class, type, rdata) | 🔴 | 6h | 2.2.1 |
| 2.2.4 | internal/auth/zonefile.go — $GENERATE directive (range expansion) | 🟡 | 3h | 2.2.3 |
| 2.2.5 | internal/auth/zonefile.go — Zone file export (Zone → BIND format text) | 🟡 | 3h | 2.2.3 |
| 2.2.6 | zones/example.com.zone — Example zone file | 🟡 | 1h | 2.2.3 |
| 2.2.7 | Tests: parse various BIND zone files (SOA, multi-line, wildcards, delegations) | 🔴 | 4h | 2.2.3 |

### P2.3 — Zone Store & Query Engine
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 2.3.1 | internal/auth/zonestore.go — Zone store (add, remove, find best zone) | 🔴 | 3h | 2.1.1 |
| 2.3.2 | internal/auth/engine.go — Authoritative resolution (exact match, NODATA, NXDOMAIN) | 🔴 | 6h | 2.3.1 |
| 2.3.3 | internal/auth/wildcard.go — Wildcard matching (closest encloser, synthesis) | 🔴 | 4h | 2.3.2 |
| 2.3.4 | internal/auth/delegation.go — NS delegation (referral responses, glue records) | 🔴 | 3h | 2.3.2 |
| 2.3.5 | internal/auth/engine.go — CNAME chain following (max depth 10) | 🔴 | 2h | 2.3.2 |
| 2.3.6 | internal/auth/engine.go — Additional section generation (NS/MX target A/AAAA) | 🟡 | 2h | 2.3.2 |
| 2.3.7 | Wire handler integration: route queries to authoritative engine | 🔴 | 2h | 2.3.2, 1.4.1 |
| 2.3.8 | Integration tests: load zone file → query various types → verify response | 🔴 | 4h | 2.3.7 |

**🏁 Phase 2 Milestone: Authoritative DNS for zone files. ~60h**

---

## Phase 3: Recursive Resolver

### P3.1 — Cache
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 3.1.1 | internal/resolver/cache.go — LRU doubly-linked list | 🔴 | 3h | 1.1.1 |
| 3.1.2 | internal/resolver/cache.go — Cache struct (Get with TTL adjustment, Set with eviction) | 🔴 | 4h | 3.1.1 |
| 3.1.3 | internal/resolver/negative.go — Negative caching (NXDOMAIN, NODATA, SOA TTL) | 🔴 | 2h | 3.1.2 |
| 3.1.4 | internal/resolver/cache.go — Serve-stale support (expired entries with background refresh) | 🟡 | 3h | 3.1.2 |
| 3.1.5 | internal/resolver/prefetch.go — TTL-based prefetching goroutine | 🟡 | 3h | 3.1.2 |
| 3.1.6 | Cache tests (insert, lookup, TTL expiry, LRU eviction, serve-stale, negative) | 🔴 | 4h | 3.1.4 |

### P3.2 — Forwarder
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 3.2.1 | internal/resolver/forwarder.go — Single forwarder (UDP query to upstream) | 🔴 | 3h | 1.3.12 |
| 3.2.2 | internal/resolver/forwarder.go — TCP fallback on TC=1 | 🔴 | 2h | 3.2.1 |
| 3.2.3 | internal/resolver/forwarder.go — ForwarderGroup (weighted selection, health check) | 🔴 | 3h | 3.2.1 |
| 3.2.4 | internal/resolver/forwarder.go — Per-zone forwarding rules | 🟡 | 2h | 3.2.3 |
| 3.2.5 | internal/resolver/forwarder.go — DoT upstream forwarding | 🟡 | 3h | 3.2.1 |
| 3.2.6 | internal/resolver/forwarder.go — DoH upstream forwarding | 🟡 | 3h | 3.2.1 |

### P3.3 — Iterative Resolver
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 3.3.1 | internal/resolver/hints.go — Embedded root hints | 🔴 | 1h | 1.1.1 |
| 3.3.2 | internal/resolver/iterator.go — Basic iterative resolution (root → TLD → auth) | 🔴 | 8h | 3.3.1, 1.3.12 |
| 3.3.3 | internal/resolver/iterator.go — Bailiwick checking (ignore out-of-zone records) | 🔴 | 2h | 3.3.2 |
| 3.3.4 | internal/resolver/iterator.go — CNAME following during recursion | 🔴 | 2h | 3.3.2 |
| 3.3.5 | internal/resolver/iterator.go — Source port & ID randomization (crypto/rand) | 🔴 | 1h | 3.3.2 |
| 3.3.6 | internal/resolver/qname.go — QNAME minimization | 🟡 | 3h | 3.3.2 |
| 3.3.7 | internal/resolver/iterator.go — 0x20 mixed-case encoding | 🟡 | 2h | 3.3.2 |

### P3.4 — Resolver Engine
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 3.4.1 | internal/resolver/engine.go — Resolver engine (recursive/forwarder/hybrid routing) | 🔴 | 4h | 3.1.2, 3.2.3, 3.3.2 |
| 3.4.2 | Connection pool for upstream queries | 🟡 | 3h | 3.4.1 |
| 3.4.3 | Wire handler integration: cache check → auth → recursive pipeline | 🔴 | 3h | 3.4.1, 2.3.2 |
| 3.4.4 | Integration tests: recursive resolution against real DNS (opt-in) | 🟡 | 3h | 3.4.1 |
| 3.4.5 | Integration tests: forwarder mode with mock upstream | 🔴 | 3h | 3.4.1 |

**🏁 Phase 3 Milestone: Full recursive + forwarder + caching. ~70h**

---

## Phase 4: Security & Filters

### P4.1 — ACL & Rate Limiting
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 4.1.1 | internal/filter/acl.go — ACL rules (CIDR matching, per-zone, default action) | 🔴 | 3h | 1.2.3 |
| 4.1.2 | internal/filter/ratelimit.go — Token bucket implementation | 🔴 | 4h | 1.2.3 |
| 4.1.3 | internal/filter/ratelimit.go — RRL with slip (TC response) | 🔴 | 2h | 4.1.2 |
| 4.1.4 | internal/filter/ratelimit.go — Stale bucket cleanup goroutine | 🟡 | 1h | 4.1.2 |
| 4.1.5 | Tests: ACL matching, rate limit behavior, slip | 🔴 | 3h | 4.1.3 |

### P4.2 — Blocklist
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 4.2.1 | internal/filter/blocklist.go — Domain list parser (domains format) | 🔴 | 2h | 1.2.4 |
| 4.2.2 | internal/filter/blocklist.go — Hosts file parser | 🔴 | 2h | 4.2.1 |
| 4.2.3 | internal/filter/blocklist.go — Adblock format parser (basic ||domain^) | 🟡 | 2h | 4.2.1 |
| 4.2.4 | internal/filter/blocklist.go — Wildcard blocking (suffix match via radix tree) | 🟡 | 3h | 4.2.1 |
| 4.2.5 | internal/filter/blocklist.go — Response modes (NXDOMAIN, zero IP, custom IP) | 🔴 | 2h | 4.2.1 |
| 4.2.6 | internal/filter/blocklist.go — Allowlist override | 🔴 | 1h | 4.2.1 |
| 4.2.7 | internal/filter/blocklist.go — Hot reload (file watch / periodic) | 🟡 | 2h | 4.2.1 |
| 4.2.8 | blocklists/default.txt — Default blocklist (curated) | 🟡 | 1h | — |
| 4.2.9 | Tests: block matching, allowlist override, format parsing | 🔴 | 3h | 4.2.6 |

### P4.3 — GeoDNS
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 4.3.1 | internal/filter/geoip.go — MMDB binary format parser (search tree + data section) | 🟡 | 8h | 1.2.3 |
| 4.3.2 | internal/filter/geoip.go — Lookup function (IP → country/continent/ASN) | 🟡 | 3h | 4.3.1 |
| 4.3.3 | internal/filter/geodns.go — Geo rule matching (country → continent → default) | 🟡 | 3h | 4.3.2 |
| 4.3.4 | internal/filter/geodns.go — ECS awareness (use client subnet IP for lookup) | 🟡 | 2h | 4.3.3, 1.3.11 |
| 4.3.5 | Tests: GeoIP lookup, GeoDNS rule matching | 🟡 | 3h | 4.3.4 |

### P4.4 — Split-Horizon
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 4.4.1 | internal/filter/splithorizon.go — View definition, client matching | 🟡 | 3h | 4.1.1 |
| 4.4.2 | internal/filter/splithorizon.go — Per-view zone store | 🟡 | 2h | 4.4.1, 2.3.1 |
| 4.4.3 | Tests: view selection, per-view zone resolution | 🟡 | 2h | 4.4.2 |

### P4.5 — Pipeline Integration
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 4.5.1 | internal/server/handler.go — Full QueryPipeline (ACL → RRL → Block → View → Auth/Resolve → Geo) | 🔴 | 4h | 4.1–4.4 |
| 4.5.2 | Integration test: full pipeline with all filters | 🔴 | 3h | 4.5.1 |

**🏁 Phase 4 Milestone: Production filtering & security. ~60h**

---

## Phase 5: Encrypted Transports

### P5.1 — DoT
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 5.1.1 | internal/server/dot.go — TLS listener wrapping TCP handler | 🔴 | 3h | 1.4.3 |
| 5.1.2 | TLS config builder (cert loading, min version, cipher suites) | 🔴 | 2h | 5.1.1 |
| 5.1.3 | Tests: DoT query/response | 🔴 | 2h | 5.1.1 |

### P5.2 — DoH
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 5.2.1 | internal/server/doh.go — HTTP server with /dns-query endpoint | 🔴 | 3h | 1.4.1 |
| 5.2.2 | internal/server/doh.go — Wire format (POST body, GET base64url) | 🔴 | 3h | 5.2.1 |
| 5.2.3 | internal/server/doh.go — JSON API format (Cloudflare-compatible) | 🟡 | 4h | 5.2.1 |
| 5.2.4 | internal/server/doh.go — Cache-Control header from min TTL | 🟡 | 1h | 5.2.1 |
| 5.2.5 | Tests: DoH wire + JSON format | 🔴 | 3h | 5.2.3 |

### P5.3 — DoQ (QUIC)
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 5.3.1 | internal/quic/packet.go — QUIC packet format (long header, short header, varint) | 🟡 | 6h | 1.1.1 |
| 5.3.2 | internal/quic/crypto.go — Initial keys derivation (HKDF from DCID) | 🟡 | 6h | 5.3.1 |
| 5.3.3 | internal/quic/crypto.go — TLS 1.3 integration via crypto/tls.QUICConn | 🟡 | 8h | 5.3.2 |
| 5.3.4 | internal/quic/crypto.go — Packet protection (header protection, AEAD encrypt/decrypt) | 🟡 | 6h | 5.3.3 |
| 5.3.5 | internal/quic/connection.go — Connection state machine (handshake → established) | 🟡 | 6h | 5.3.4 |
| 5.3.6 | internal/quic/stream.go — Stream management (open, read, write, close) | 🟡 | 4h | 5.3.5 |
| 5.3.7 | internal/quic/packet.go — ACK frame generation/processing | 🟡 | 4h | 5.3.1 |
| 5.3.8 | internal/quic/congestion.go — New Reno congestion control | 🟡 | 4h | 5.3.7 |
| 5.3.9 | internal/quic/listener.go — QUIC listener (demux by CID, accept) | 🟡 | 4h | 5.3.5 |
| 5.3.10 | internal/server/doq.go — DoQ server using QUIC listener | 🟡 | 3h | 5.3.9 |
| 5.3.11 | 0-RTT support for repeat DoQ clients | 🟢 | 4h | 5.3.10 |
| 5.3.12 | Tests: QUIC handshake, stream, DoQ query/response | 🟡 | 6h | 5.3.10 |

**🏁 Phase 5 Milestone: All 4 DNS transports working. ~85h**

---

## Phase 6: DNSSEC

### P6.1 — Crypto Operations
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 6.1.1 | internal/dnssec/algorithms.go — ECDSAP256SHA256 sign/verify | 🔴 | 3h | 1.1.1 |
| 6.1.2 | internal/dnssec/algorithms.go — ECDSAP384SHA384 sign/verify | 🟡 | 1h | 6.1.1 |
| 6.1.3 | internal/dnssec/algorithms.go — ED25519 sign/verify | 🔴 | 2h | 1.1.1 |
| 6.1.4 | internal/dnssec/algorithms.go — RSASHA256/512 sign/verify | 🟡 | 2h | 1.1.1 |
| 6.1.5 | internal/dnssec/algorithms.go — RRSIG canonical wire format for signing | 🔴 | 3h | 6.1.1 |
| 6.1.6 | Tests: sign → verify round-trips for all algorithms | 🔴 | 3h | 6.1.5 |

### P6.2 — Key Management
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 6.2.1 | internal/dnssec/keys.go — SigningKey struct, KeyTag calculation | 🔴 | 2h | 6.1.1 |
| 6.2.2 | internal/dnssec/keys.go — DNSKEY record types (DS, RRSIG, NSEC, NSEC3, DNSKEY) | 🔴 | 4h | 6.2.1 |
| 6.2.3 | internal/dnssec/keystore.go — Key generation (KSK/ZSK for each algorithm) | 🔴 | 3h | 6.2.1 |
| 6.2.4 | internal/dnssec/keystore.go — Key storage (PEM files) | 🔴 | 2h | 6.2.3 |
| 6.2.5 | internal/dnssec/keystore.go — Key rollover (prepublish method for ZSK) | 🟡 | 4h | 6.2.4 |
| 6.2.6 | internal/dnssec/keystore.go — DS record generation for parent zone | 🔴 | 2h | 6.2.1 |

### P6.3 — Zone Signing
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 6.3.1 | internal/dnssec/signer.go — RRset canonical ordering (RFC 4034 §6.3) | 🔴 | 2h | 1.3.12 |
| 6.3.2 | internal/dnssec/signer.go — RRSIG generation for RRset | 🔴 | 4h | 6.3.1, 6.1.5 |
| 6.3.3 | internal/dnssec/signer.go — NSEC chain generation | 🔴 | 4h | 6.3.2 |
| 6.3.4 | internal/dnssec/signer.go — NSEC3 chain generation (with opt-out) | 🟡 | 5h | 6.3.3 |
| 6.3.5 | internal/dnssec/signer.go — Online signing with RRSIG cache | 🔴 | 3h | 6.3.2 |
| 6.3.6 | Authoritative engine integration: sign responses for DNSSEC-enabled zones | 🔴 | 3h | 6.3.5, 2.3.2 |
| 6.3.7 | Tests: sign zone → query with DO=1 → verify RRSIG in response | 🔴 | 4h | 6.3.6 |

### P6.4 — DNSSEC Validation
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 6.4.1 | internal/dnssec/validator.go — Trust anchor storage (root KSK) | 🔴 | 2h | 6.2.1 |
| 6.4.2 | internal/dnssec/validator.go — Chain of trust validation | 🔴 | 8h | 6.4.1 |
| 6.4.3 | internal/dnssec/validator.go — AD bit setting in responses | 🔴 | 1h | 6.4.2 |
| 6.4.4 | internal/dnssec/validator.go — CD bit honoring (skip validation) | 🟡 | 1h | 6.4.2 |
| 6.4.5 | internal/dnssec/validator.go — Bogus response handling (SERVFAIL) | 🔴 | 2h | 6.4.2 |
| 6.4.6 | Resolver integration: validate DNSSEC for recursive responses | 🔴 | 3h | 6.4.2, 3.4.1 |
| 6.4.7 | Tests: validate known-good signed responses, reject bogus | 🔴 | 4h | 6.4.6 |

**🏁 Phase 6 Milestone: DNSSEC signing + validation. ~70h**

---

## Phase 7: Zone Transfer & Dynamic DNS

### P7.1 — TSIG
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 7.1.1 | internal/transfer/tsig.go — TSIG record format (marshal/unmarshal) | 🔴 | 3h | 1.3.12 |
| 7.1.2 | internal/transfer/tsig.go — HMAC-SHA256/512 signing | 🔴 | 2h | 7.1.1 |
| 7.1.3 | internal/transfer/tsig.go — TSIG verification | 🔴 | 2h | 7.1.2 |
| 7.1.4 | Tests: TSIG sign → verify round-trip | 🔴 | 2h | 7.1.3 |

### P7.2 — AXFR
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 7.2.1 | internal/transfer/axfr.go — AXFR server (send SOA → records → SOA) | 🔴 | 4h | 2.3.1, 7.1.3 |
| 7.2.2 | internal/transfer/axfr.go — AXFR client (receive stream, build zone) | 🔴 | 4h | 7.2.1 |
| 7.2.3 | TCP handler: detect AXFR/IXFR QTYPE and route to transfer handler | 🔴 | 2h | 7.2.1 |
| 7.2.4 | Tests: full AXFR transfer between two instances | 🔴 | 3h | 7.2.2 |

### P7.3 — IXFR
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 7.3.1 | internal/transfer/ixfr.go — IXFR server (diff from journal) | 🟡 | 4h | 7.2.1, 8.2.1 |
| 7.3.2 | internal/transfer/ixfr.go — IXFR client (apply diffs) | 🟡 | 3h | 7.3.1 |
| 7.3.3 | internal/transfer/ixfr.go — Fallback to AXFR when journal insufficient | 🟡 | 1h | 7.3.1 |
| 7.3.4 | Tests: IXFR incremental transfer | 🟡 | 3h | 7.3.2 |

### P7.4 — NOTIFY
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 7.4.1 | internal/auth/notify.go — Send NOTIFY on zone change | 🟡 | 2h | 1.3.12 |
| 7.4.2 | internal/auth/notify.go — Handle incoming NOTIFY (trigger transfer) | 🟡 | 2h | 7.4.1 |
| 7.4.3 | internal/auth/notify.go — Retry with exponential backoff | 🟡 | 1h | 7.4.1 |

### P7.5 — Dynamic DNS
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 7.5.1 | internal/dynamic/update.go — UPDATE message parsing (zone, prereq, update sections) | 🟡 | 4h | 1.3.12 |
| 7.5.2 | internal/dynamic/update.go — Prerequisite evaluation | 🟡 | 3h | 7.5.1 |
| 7.5.3 | internal/dynamic/update.go — Atomic update application (add/delete records) | 🟡 | 4h | 7.5.2 |
| 7.5.4 | internal/dynamic/update.go — SOA serial increment | 🟡 | 1h | 7.5.3 |
| 7.5.5 | internal/dynamic/journal.go — Journal file format (binary, append-only) | 🟡 | 4h | 7.5.3 |
| 7.5.6 | internal/dynamic/journal.go — Journal replay on startup | 🟡 | 2h | 7.5.5 |
| 7.5.7 | internal/dynamic/journal.go — Journal compaction | 🟡 | 2h | 7.5.5 |
| 7.5.8 | Tests: dynamic update + journal + IXFR integration | 🟡 | 4h | 7.5.7 |

**🏁 Phase 7 Milestone: Zone replication + dynamic updates. ~60h**

---

## Phase 8: Storage & Persistence

| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 8.1.1 | internal/storage/serializer.go — TLV encoder/decoder | 🔴 | 3h | 1.1.1 |
| 8.1.2 | internal/storage/wal.go — WAL segment format (CRC32 + data) | 🔴 | 4h | 8.1.1 |
| 8.1.3 | internal/storage/wal.go — Append, ReadAll, Truncate, Sync | 🔴 | 3h | 8.1.2 |
| 8.1.4 | internal/storage/wal.go — Segment rotation (max 64MB per file) | 🟡 | 2h | 8.1.3 |
| 8.1.5 | internal/storage/wal.go — Recovery (read all segments, verify CRC) | 🔴 | 3h | 8.1.3 |
| 8.1.6 | internal/storage/boltlike.go — Page format (meta, branch, leaf, freelist) | 🔴 | 6h | 1.1.1 |
| 8.1.7 | internal/storage/boltlike.go — B+tree insert/lookup/delete | 🔴 | 8h | 8.1.6 |
| 8.1.8 | internal/storage/boltlike.go — Transactions (begin, commit, rollback, COW) | 🔴 | 6h | 8.1.7 |
| 8.1.9 | internal/storage/boltlike.go — Buckets (namespace isolation) | 🔴 | 3h | 8.1.8 |
| 8.1.10 | internal/storage/boltlike.go — Freelist management | 🟡 | 3h | 8.1.8 |
| 8.1.11 | Integrate storage with zone store (persist zones/records) | 🔴 | 4h | 8.1.9, 2.3.1 |
| 8.1.12 | Integrate storage with config (persist runtime config changes) | 🟡 | 2h | 8.1.9 |
| 8.1.13 | Integrate storage with DNSSEC key metadata | 🟡 | 2h | 8.1.9, 6.2.4 |
| 8.1.14 | Tests: WAL crash recovery, KV CRUD, concurrent access | 🔴 | 6h | 8.1.11 |

**🏁 Phase 8 Milestone: Crash-safe persistence. ~55h**

---

## Phase 9: Clustering (Raft)

| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 9.1.1 | internal/cluster/transport.go — Binary RPC protocol (message types, framing) | 🔴 | 4h | 1.1.1 |
| 9.1.2 | internal/cluster/transport.go — TCP connection management (persistent, reconnect) | 🔴 | 3h | 9.1.1 |
| 9.1.3 | internal/cluster/log.go — Raft log (in-memory + WAL persistence) | 🔴 | 4h | 8.1.3 |
| 9.1.4 | internal/cluster/raft.go — RequestVote RPC (send + handle) | 🔴 | 4h | 9.1.1 |
| 9.1.5 | internal/cluster/raft.go — Leader election (timeout, voting, state transitions) | 🔴 | 6h | 9.1.4 |
| 9.1.6 | internal/cluster/raft.go — AppendEntries RPC (send + handle) | 🔴 | 4h | 9.1.1 |
| 9.1.7 | internal/cluster/raft.go — Log replication (leader → followers) | 🔴 | 6h | 9.1.6, 9.1.3 |
| 9.1.8 | internal/cluster/raft.go — Commit advancement (majority acknowledgment) | 🔴 | 3h | 9.1.7 |
| 9.1.9 | internal/cluster/fsm.go — FSM Apply (zone/record mutations) | 🔴 | 4h | 2.3.1 |
| 9.1.10 | internal/cluster/fsm.go — FSM Snapshot (serialize full state) | 🔴 | 3h | 9.1.9, 8.1.1 |
| 9.1.11 | internal/cluster/fsm.go — FSM Restore (from snapshot) | 🔴 | 3h | 9.1.10 |
| 9.1.12 | internal/cluster/snapshot.go — Snapshot storage (file-based) | 🔴 | 3h | 9.1.10 |
| 9.1.13 | internal/cluster/snapshot.go — InstallSnapshot RPC (leader → new follower) | 🟡 | 4h | 9.1.12 |
| 9.1.14 | internal/cluster/raft.go — Log compaction (truncate after snapshot) | 🟡 | 2h | 9.1.12 |
| 9.1.15 | internal/cluster/peer.go — Peer management (add/remove nodes) | 🟡 | 3h | 9.1.5 |
| 9.1.16 | internal/cluster/health.go — Cluster health checks | 🟡 | 2h | 9.1.5 |
| 9.1.17 | internal/api/grpc/* — Inter-node gRPC (zone sync, health, write forwarding) | 🟡 | 6h | 9.1.1 |
| 9.1.18 | Write request forwarding (follower → leader) | 🔴 | 3h | 9.1.5, 9.1.17 |
| 9.1.19 | Tests: 3-node in-memory cluster (election, replication, failover) | 🔴 | 8h | 9.1.18 |
| 9.1.20 | Tests: snapshot + new node bootstrap | 🟡 | 4h | 9.1.13 |

**🏁 Phase 9 Milestone: Raft clustering operational. ~80h**

---

## Phase 10: Management Interfaces

### P10.1 — REST API
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 10.1.1 | internal/api/rest/router.go — Trie-based HTTP router with path params | 🔴 | 4h | 1.1.1 |
| 10.1.2 | internal/api/rest/middleware.go — Auth (Bearer + Basic) | 🔴 | 2h | 10.1.1 |
| 10.1.3 | internal/api/rest/middleware.go — CORS, Logging | 🟡 | 2h | 10.1.1 |
| 10.1.4 | internal/api/rest/zones.go — Zone CRUD endpoints | 🔴 | 4h | 10.1.1, 2.3.1 |
| 10.1.5 | internal/api/rest/zones.go — Zone import/export endpoints | 🟡 | 2h | 10.1.4 |
| 10.1.6 | internal/api/rest/records.go — Record CRUD endpoints | 🔴 | 3h | 10.1.4 |
| 10.1.7 | internal/api/rest/cache.go — Cache stats, flush endpoints | 🟡 | 2h | 10.1.1, 3.1.2 |
| 10.1.8 | internal/api/rest/cluster.go — Cluster status, node management endpoints | 🟡 | 3h | 10.1.1, 9.1.5 |
| 10.1.9 | internal/api/rest/blocklist.go — Blocklist management endpoints | 🟡 | 2h | 10.1.1, 4.2.1 |
| 10.1.10 | internal/api/rest/stats.go — Statistics endpoints (top queries, clients, blocked) | 🟡 | 3h | 10.1.1 |
| 10.1.11 | internal/api/rest/config.go — Runtime config endpoints | 🟡 | 2h | 10.1.1 |
| 10.1.12 | internal/api/rest/swagger.go — Embedded Swagger UI + OpenAPI 3.0 spec | 🟡 | 4h | 10.1.1 |
| 10.1.13 | Tests: API endpoint integration tests | 🔴 | 4h | 10.1.6 |

### P10.2 — MCP Server
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 10.2.1 | internal/api/mcp/server.go — JSON-RPC 2.0 protocol handler | 🔴 | 4h | 1.1.1 |
| 10.2.2 | internal/api/mcp/server.go — stdio transport (for Claude Code) | 🔴 | 2h | 10.2.1 |
| 10.2.3 | internal/api/mcp/server.go — SSE transport (for web clients) | 🟡 | 3h | 10.2.1 |
| 10.2.4 | internal/api/mcp/server.go — Initialize handshake (capabilities, serverInfo) | 🔴 | 2h | 10.2.1 |
| 10.2.5 | internal/api/mcp/tools.go — All MCP tools (zone, record, query, cache, cluster, blocklist, stats, health, config) | 🔴 | 6h | 10.2.1 |
| 10.2.6 | internal/api/mcp/resources.go — MCP resources (dns:// URI scheme) | 🟡 | 3h | 10.2.1 |
| 10.2.7 | internal/api/mcp/prompts.go — MCP prompts (troubleshoot, migrate, optimize, setup) | 🟡 | 3h | 10.2.1 |
| 10.2.8 | Tests: MCP tool invocations | 🔴 | 3h | 10.2.5 |

### P10.3 — Web Dashboard
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 10.3.1 | internal/dashboard/server.go — Static file server with go:embed | 🟡 | 2h | 1.1.1 |
| 10.3.2 | internal/dashboard/websocket.go — WebSocket upgrade (RFC 6455) | 🟡 | 4h | 10.3.1 |
| 10.3.3 | internal/dashboard/websocket.go — Real-time query stream channel | 🟡 | 2h | 10.3.2 |
| 10.3.4 | internal/dashboard/static/index.html — Dashboard shell | 🟡 | 2h | 10.3.1 |
| 10.3.5 | internal/dashboard/static/app.js — Overview page (QPS, cache, uptime) | 🟡 | 4h | 10.3.4 |
| 10.3.6 | internal/dashboard/static/app.js — Query log page (real-time WS) | 🟡 | 3h | 10.3.3 |
| 10.3.7 | internal/dashboard/static/app.js — Zone manager page (CRUD) | 🟡 | 4h | 10.3.4 |
| 10.3.8 | internal/dashboard/static/app.js — Blocklist manager page | 🟡 | 2h | 10.3.4 |
| 10.3.9 | internal/dashboard/static/app.js — Cluster status page | 🟡 | 2h | 10.3.4 |
| 10.3.10 | internal/dashboard/static/app.js — Charts (Canvas 2D) | 🟡 | 4h | 10.3.5 |
| 10.3.11 | internal/dashboard/static/style.css — Dark/light theme | 🟡 | 3h | 10.3.4 |

### P10.4 — CLI Tool (dnsctl)
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 10.4.1 | cmd/dnsctl — Argument parser (subcommand + action + flags) | 🔴 | 3h | 1.1.1 |
| 10.4.2 | cmd/dnsctl — API client (HTTP + JSON, auth token) | 🔴 | 2h | 10.4.1 |
| 10.4.3 | cmd/dnsctl — zone subcommand (list, create, delete, export, import) | 🔴 | 3h | 10.4.2 |
| 10.4.4 | cmd/dnsctl — record subcommand (list, add, delete) | 🔴 | 2h | 10.4.2 |
| 10.4.5 | cmd/dnsctl — cache subcommand (stats, flush) | 🟡 | 1h | 10.4.2 |
| 10.4.6 | cmd/dnsctl — cluster subcommand (status, nodes, add, remove) | 🟡 | 2h | 10.4.2 |
| 10.4.7 | cmd/dnsctl — blocklist subcommand (add, remove, reload, stats) | 🟡 | 1h | 10.4.2 |
| 10.4.8 | cmd/dnsctl — dnssec subcommand (status, sign, rollover, ds) | 🟡 | 2h | 10.4.2 |
| 10.4.9 | cmd/dnsctl — dig subcommand (standalone DNS query using protocol package) | 🔴 | 4h | 1.3.12 |
| 10.4.10 | cmd/dnsctl — Output formatting (table, JSON, YAML) | 🟡 | 3h | 10.4.2 |

### P10.5 — Metrics
| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 10.5.1 | internal/metrics/collector.go — Counter, Gauge, Histogram types | 🔴 | 3h | 1.1.1 |
| 10.5.2 | internal/metrics/prometheus.go — Prometheus exposition format renderer | 🔴 | 3h | 10.5.1 |
| 10.5.3 | internal/metrics/health.go — Health check endpoint | 🔴 | 2h | 10.5.1 |
| 10.5.4 | Instrument query pipeline (queries_total, duration, cache hits, etc.) | 🔴 | 3h | 10.5.1, 4.5.1 |
| 10.5.5 | Tests: metrics collection, Prometheus output format | 🟡 | 2h | 10.5.2 |

**🏁 Phase 10 Milestone: Full management suite. ~120h**

---

## Phase 11: Config Hot Reload

| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 11.1.1 | internal/config/reload.go — SIGHUP handler with callback registry | 🟡 | 3h | 1.5.3 |
| 11.1.2 | Zone file hot reload (re-parse, atomic swap) | 🟡 | 2h | 11.1.1, 2.2.3 |
| 11.1.3 | Blocklist hot reload | 🟡 | 1h | 11.1.1, 4.2.1 |
| 11.1.4 | TLS certificate hot reload (tls.Config.GetCertificate) | 🟡 | 2h | 11.1.1, 5.1.2 |
| 11.1.5 | ACL/Rate limit hot reload | 🟡 | 1h | 11.1.1 |
| 11.1.6 | Log level hot reload | 🟡 | 1h | 11.1.1 |

**~10h**

---

## Phase 12: Polish & Release

| ID | Task | Priority | ⏱️ | 📦 |
|----|------|----------|-----|-----|
| 12.1.1 | README.md — Project overview, quick start, features, comparison table | 🔴 | 4h | — |
| 12.1.2 | Comprehensive test coverage review (target: >80%) | 🔴 | 8h | All |
| 12.1.3 | Benchmark suite (message parse, cache lookup, zone lookup, signing) | 🟡 | 4h | All |
| 12.1.4 | Performance profiling & optimization (pprof) | 🟡 | 8h | 12.1.3 |
| 12.1.5 | CI/CD: GitHub Actions (test, build, release) | 🟡 | 4h | 1.1.4 |
| 12.1.6 | Docker compose (3-node cluster example) | 🟡 | 2h | 1.1.5 |
| 12.1.7 | Systemd service file | 🟡 | 1h | — |
| 12.1.8 | Security review (input validation, buffer overflows, resource limits) | 🔴 | 6h | All |
| 12.1.9 | BRANDING.md — Logo, colors, tagline, social media assets | 🟡 | 4h | — |
| 12.1.10 | v1.0.0 release tag + changelog | 🔴 | 2h | All |

**~43h**

---

## Summary

| Phase | Description | Estimated Hours |
|-------|-------------|----------------|
| 1 | Foundation | ~80h |
| 2 | Authoritative Engine | ~60h |
| 3 | Recursive Resolver | ~70h |
| 4 | Security & Filters | ~60h |
| 5 | Encrypted Transports | ~85h |
| 6 | DNSSEC | ~70h |
| 7 | Zone Transfer & Dynamic DNS | ~60h |
| 8 | Storage & Persistence | ~55h |
| 9 | Clustering (Raft) | ~80h |
| 10 | Management Interfaces | ~120h |
| 11 | Config Hot Reload | ~10h |
| 12 | Polish & Release | ~43h |
| **Total** | | **~793h** |

At 40h/week solo: **~20 weeks**
At 20h/week solo: **~40 weeks**
With Claude Code: **~50% faster = 10-20 weeks**

---

*Document Version: 1.0*
*Created: 2026-03-25*
*Author: Ersin / ECOSTACK TECHNOLOGY OÜ*
*Status: DRAFT — Pending Review*
