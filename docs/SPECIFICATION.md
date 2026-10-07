# NothingDNS — Specification Document

> **Nothing but DNS. Nothing else needed.**
> Minimal-dependency, single-binary, full-featured DNS server written in Go.

---

## 1. Project Overview

### 1.1 Vision
NothingDNS is a modern, production-grade DNS server that combines authoritative and recursive DNS resolution in a single binary with a minimal external dependency set. It supports modern DNS protocols (UDP/TCP, DoT, DoH, DoQ), provides enterprise-grade features like DNSSEC, GeoDNS, split-horizon, and ad-blocking, and can operate as a standalone instance or a Raft-based cluster for high availability.

### 1.2 Philosophy
- **Minimal Dependencies** — Core DNS logic is hand-rolled; external Go deps are limited to necessary transport/platform support.
- **Single Binary** — One binary to rule them all: DNS server, CLI tool, web dashboard.
- **BIND Compatible** — Import existing BIND zone files seamlessly. Familiar zone file syntax.
- **Cloud-Native** — Single binary runs everywhere: bare metal, Docker, Kubernetes, edge.
- **Cluster-First** — Raft consensus for zone replication, leader election, and failover.

### 1.3 Project Identity
- **Name:** NothingDNS
- **Tagline:** "Nothing but DNS. Nothing else needed."
- **Binary:** `nothingdns` (server) + `dnsctl` (CLI management tool)
- **Default Ports:** 53 (UDP/TCP), 853 (DoT/DoQ when enabled), 8080 (API/Dashboard/DoH when configured), 9153 (Metrics), 7946 (cluster gossip/Raft RPC)
- **License:** MIT
- **Language:** Go 1.26.6+
- **Repository:** github.com/nothingdns/nothingdns

---

## 2. Core Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          NothingDNS                                  │
│                                                                      │
│  ┌──────────────────── Protocol Layer ────────────────────────┐     │
│  │  UDP/TCP :53  │  DoT :853  │  DoH :443  │  DoQ :853/UDP   │     │
│  └──────────────────────────┬─────────────────────────────────┘     │
│                              │                                       │
│  ┌──────────────────── Query Pipeline ────────────────────────┐     │
│  │                                                             │     │
│  │  Receive → Parse → ACL Check → Rate Limit → Route          │     │
│  │                                              │              │     │
│  │                          ┌────────────────────┤              │     │
│  │                          ▼                    ▼              │     │
│  │                   Authoritative          Recursive           │     │
│  │                   Engine                 Resolver             │     │
│  │                     │                       │                │     │
│  │                     ▼                       ▼                │     │
│  │               Zone Store              Cache Layer            │     │
│  │                     │                       │                │     │
│  │                     └───────────┬───────────┘                │     │
│  │                                 ▼                            │     │
│  │  Blocklist Check → GeoDNS → Split-Horizon → DNSSEC Sign     │     │
│  │                                 │                            │     │
│  │                                 ▼                            │     │
│  │                          Serialize → Send Response            │     │
│  └─────────────────────────────────────────────────────────────┘     │
│                                                                      │
│  ┌──────────── Cluster Layer (Raft) ─────────────┐                  │
│  │  Leader Election │ Zone Sync │ Zone Batches    │                  │
│  │  Log Replication │ Snapshot  │ UPDATE Forward   │                  │
│  └────────────────────────────────────────────────┘                  │
│                                                                      │
│  ┌──────────── Management Layer ─────────────────┐                  │
│  │  REST API │ WS   │ Web UI │ Prometheus         │                  │
│  └────────────────────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Module Structure

> **Note:** The tree below is aspirational and reflects the planned module
> layout. The actual source tree is flat in `internal/` — see `tree -d` or
> the project README for the current layout. Key differences: there is no
> `internal/api/rest/` or `internal/api/grpc/` (API lives flat in
> `internal/api/`; there is no gRPC at all — nodes talk Raft RPC, see §10.3), no `internal/dynamic/` (DDNS is in `internal/transfer/`),
> and the `internal/util/` used here does not correspond to a single
> `internal/util/` package.

```
nothingdns/
├── cmd/
│   ├── nothingdns/          # Main server binary
│   │   └── main.go
│   └── dnsctl/              # CLI management tool
│       └── main.go
├── internal/
│   ├── protocol/            # DNS wire protocol (RFC 1035)
│   │   ├── message.go       # DNS message struct & marshal/unmarshal
│   │   ├── header.go        # DNS header (12-byte fixed)
│   │   ├── question.go      # Question section
│   │   ├── record.go        # Resource record base
│   │   ├── types.go         # A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA, PTR, NAPTR, SSHFP
│   │   ├── edns.go          # EDNS(0) OPT record, Client Subnet
│   │   ├── labels.go        # DNS label compression/decompression
│   │   └── wire.go          # Binary serialization helpers
│   ├── server/              # Protocol listeners
│   │   ├── udp.go           # UDP listener (:53)
│   │   ├── tcp.go           # TCP listener (:53)
│   │   ├── dot.go           # DNS over TLS (:853)
│   │   ├── doh.go           # DNS over HTTPS (:443)
│   │   ├── doq.go           # DNS over QUIC (:853/UDP)
│   │   └── handler.go       # Common query handler interface
│   ├── auth/                # Authoritative engine
│   │   ├── engine.go        # Authoritative query resolution
│   │   ├── zone.go          # Zone data structure
│   │   ├── zonefile.go      # BIND zone file parser
│   │   ├── zonestore.go     # In-memory zone store
│   │   ├── wildcard.go      # Wildcard matching (*.example.com)
│   │   ├── delegation.go    # NS delegation handling
│   │   └── notify.go        # NOTIFY (RFC 1996)
│   ├── resolver/            # Recursive resolver
│   │   ├── engine.go        # Recursive resolution engine
│   │   ├── iterator.go      # Iterative resolution from root hints
│   │   ├── forwarder.go     # Upstream forwarder mode
│   │   ├── cache.go         # Response cache (TTL-aware)
│   │   ├── negative.go      # Negative caching (NXDOMAIN, NODATA)
│   │   ├── prefetch.go      # TTL-based prefetching
│   │   ├── hints.go         # Root hints (embedded)
│   │   └── qname.go         # QNAME minimization (RFC 7816)
│   ├── dnssec/              # DNSSEC implementation
│   │   ├── signer.go        # Zone signing (RRSIG generation)
│   │   ├── validator.go     # Response validation (chain of trust)
│   │   ├── keys.go          # DNSKEY/DS/RRSIG/NSEC/NSEC3 records
│   │   ├── keystore.go      # Key management & rotation
│   │   └── algorithms.go    # RSA, ECDSA (P-256, P-384), Ed25519
│   ├── transfer/            # Zone transfer
│   │   ├── axfr.go          # Full zone transfer (AXFR)
│   │   ├── ixfr.go          # Incremental zone transfer (IXFR)
│   │   └── tsig.go          # TSIG authentication (RFC 2845)
│   ├── dynamic/             # Dynamic DNS
│   │   ├── update.go        # DNS UPDATE (RFC 2136)
│   │   ├── prereq.go        # Update prerequisites
│   │   └── journal.go       # Update journal for IXFR
│   ├── filter/              # Query filtering & manipulation
│   │   ├── blocklist.go     # Domain blocklist (ad-blocking)
│   │   ├── allowlist.go     # Domain allowlist
│   │   ├── acl.go           # IP-based access control lists
│   │   ├── ratelimit.go     # Response Rate Limiting (RRL)
│   │   ├── geodns.go        # GeoIP-based response routing
│   │   ├── geoip.go         # Embedded GeoIP database (MaxMind GeoLite2 binary format)
│   │   └── splithorizon.go  # Split-horizon / view-based DNS
│   ├── cluster/             # Raft-based clustering
│   │   ├── raft.go          # Raft consensus implementation
│   │   ├── log.go           # Raft log (append-only)
│   │   ├── snapshot.go      # State snapshots
│   │   ├── transport.go     # Raft RPC transport (TCP)
│   │   ├── fsm.go           # Finite state machine (zone store mutations)
│   │   ├── peer.go          # Peer discovery & management
│   │   └── health.go        # Cluster health checks
│   ├── storage/             # Persistent storage
│   │   ├── wal.go           # Write-ahead log
│   │   ├── boltlike.go      # Embedded B+tree key-value store
│   │   └── serializer.go    # Binary serialization for storage
│   ├── config/              # Configuration
│   │   ├── config.go        # YAML config parser (hand-written)
│   │   ├── defaults.go      # Default configuration values
│   │   ├── validate.go      # Config validation
│   │   └── reload.go        # Hot-reload (SIGHUP)
│   ├── api/                 # Management APIs
│   │   ├── rest/            # REST API
│   │   │   ├── router.go    # HTTP router (hand-written)
│   │   │   ├── middleware.go # Auth, CORS, logging middleware
│   │   │   ├── zones.go     # Zone CRUD endpoints
│   │   │   ├── records.go   # Record CRUD endpoints
│   │   │   ├── cluster.go   # Cluster status/management endpoints
│   │   │   ├── config.go    # Runtime config endpoints
│   │   │   ├── stats.go     # Statistics endpoints
│   │   │   ├── blocklist.go # Blocklist management endpoints
│   │   │   └── swagger.go   # Embedded Swagger UI & spec
│   │   ├── grpc/            # gRPC inter-node communication
│   │   │   ├── server.go    # gRPC server (hand-written protobuf encoding)
│   │   │   ├── client.go    # gRPC client
│   │   │   ├── proto.go     # Protocol buffer wire format (manual)
│   │   │   └── services.go  # Zone sync, health, forwarding services
│   ├── dashboard/           # Embedded web dashboard
│   │   ├── server.go        # Static file server
│   │   ├── embed.go         # go:embed for static assets
│   │   ├── websocket.go     # Real-time updates via WebSocket
│   │   └── static/          # Pre-built frontend assets
│   │       ├── index.html
│   │       ├── app.js       # Vanilla JS dashboard (no framework)
│   │       └── style.css
│   ├── metrics/             # Observability
│   │   ├── prometheus.go    # Prometheus-compatible /metrics endpoint
│   │   ├── collector.go     # Metrics collection (queries/sec, latency, cache hit ratio)
│   │   └── health.go        # Health check endpoint
│   ├── quic/                # QUIC protocol (for DoQ)
│   │   ├── listener.go      # QUIC listener
│   │   ├── connection.go    # QUIC connection handling
│   │   ├── stream.go        # QUIC stream management
│   │   ├── crypto.go        # TLS 1.3 handshake for QUIC
│   │   ├── packet.go        # QUIC packet format
│   │   └── congestion.go    # Congestion control (New Reno)
│   └── util/                # Shared utilities
│       ├── logger.go        # Structured logger (JSON + text)
│       ├── pool.go          # Byte buffer pool (sync.Pool)
│       ├── ip.go            # IP address utilities
│       ├── domain.go        # Domain name validation & normalization
│       └── signal.go        # Graceful shutdown signal handling
├── configs/
│   └── nothingdns.yaml      # Example configuration file
├── zones/
│   └── example.com.zone     # Example BIND zone file
├── blocklists/
│   └── default.txt          # Default ad/tracker blocklist
├── go.mod                   # Minimal external dependencies (quic-go, golang.org/x/...)
├── go.sum                   # Module checksums (populated)
├── Makefile
├── Dockerfile
├── README.md
├── docs/
│   ├── SPECIFICATION.md      # This file
│   └── IMPLEMENTATION.md     # Implementation guide
└── README.md
```

---

## 3. Protocol Layer

### 3.1 DNS Wire Protocol (RFC 1035)

Hand-written DNS message parser/serializer using `encoding/binary`. No external DNS libraries.

#### 3.1.1 Message Format
```
+---------------------+
|        Header       |  12 bytes (fixed)
+---------------------+
|       Question      |  Variable (QNAME + QTYPE + QCLASS)
+---------------------+
|        Answer       |  Variable (RRs)
+---------------------+
|      Authority      |  Variable (RRs)
+---------------------+
|      Additional     |  Variable (RRs)
+---------------------+
```

#### 3.1.2 Header Structure (12 bytes)
```go
type Header struct {
    ID      uint16  // Transaction ID
    Flags   uint16  // QR, Opcode, AA, TC, RD, RA, Z, AD, CD, RCODE
    QDCount uint16  // Question count
    ANCount uint16  // Answer count
    NSCount uint16  // Authority count
    ARCount uint16  // Additional count
}
```

#### 3.1.3 Supported Record Types

| Type   | Code | Description                  | RFC      |
|--------|------|------------------------------|----------|
| A      | 1    | IPv4 address                 | RFC 1035 |
| NS     | 2    | Name server                  | RFC 1035 |
| CNAME  | 5    | Canonical name               | RFC 1035 |
| SOA    | 6    | Start of authority           | RFC 1035 |
| PTR    | 12   | Pointer (reverse DNS)        | RFC 1035 |
| MX     | 15   | Mail exchange                | RFC 1035 |
| TXT    | 16   | Text record                  | RFC 1035 |
| AAAA   | 28   | IPv6 address                 | RFC 3596 |
| SRV    | 33   | Service locator              | RFC 2782 |
| NAPTR  | 35   | Naming authority pointer     | RFC 3403 |
| OPT    | 41   | EDNS(0) pseudo-record        | RFC 6891 |
| DS     | 43   | Delegation signer (DNSSEC)   | RFC 4034 |
| RRSIG  | 46   | DNSSEC signature             | RFC 4034 |
| NSEC   | 47   | Next secure (DNSSEC)         | RFC 4034 |
| DNSKEY | 48   | DNS public key (DNSSEC)      | RFC 4034 |
| NSEC3  | 50   | NSEC hashed (DNSSEC)         | RFC 5155 |
| NSEC3PARAM | 51 | NSEC3 parameters           | RFC 5155 |
| TLSA   | 52   | TLS authentication (DANE)    | RFC 6698 |
| SSHFP  | 44   | SSH fingerprint              | RFC 4255 |
| CAA    | 257  | Certificate authority auth   | RFC 8659 |
| TSIG   | 250  | Transaction signature        | RFC 2845 |

#### 3.1.4 Label Compression
DNS label compression (RFC 1035 §4.1.4) using pointer offsets (0xC0 prefix). Both compression and decompression must be implemented for wire format efficiency.

#### 3.1.5 EDNS(0) Support (RFC 6891)
- Extended RCODE & flags
- UDP payload size advertisement (up to 4096 bytes)
- EDNS Client Subnet option (RFC 7871)
- DNSSEC OK (DO) bit
- Padding option (RFC 7830) for DoT/DoH privacy

### 3.2 Transport Protocols

#### 3.2.1 UDP (RFC 1035)
- Port 53 (default)
- Max UDP payload: 512 bytes (legacy) / 4096 bytes (EDNS)
- Truncation (TC bit) → TCP fallback
- Connection-less, one query per packet
- Implementation: `net.ListenPacket("udp", ":53")`

#### 3.2.2 TCP (RFC 7766)
- Port 53 (default)
- 2-byte length prefix before DNS message
- Connection reuse (pipelining) support
- Idle timeout: 30 seconds (configurable)
- Implementation: `net.Listen("tcp", ":53")`

#### 3.2.3 DNS over TLS — DoT (RFC 7858)
- Port 853 (default)
- TLS 1.2+ (prefer TLS 1.3)
- Same wire format as TCP (2-byte length prefix)
- Certificate management via Let's Encrypt or custom certs
- ALPN: not required for DoT
- Implementation: `tls.Listen("tcp", ":853", tlsConfig)`

#### 3.2.4 DNS over HTTPS — DoH (RFC 8484)
- Port 443 (default)
- HTTP/2 required (HTTP/1.1 fallback)
- Content-Type: `application/dns-message` (wire format)
- Also support: `application/dns-json` (JSON API like Google/Cloudflare)
- Methods: GET (base64url query param) and POST (binary body)
- Path: `/dns-query` (configurable)
- Implementation: `net/http` with `crypto/tls` (TLS 1.3)

#### 3.2.5 DNS over QUIC — DoQ (RFC 9250)
- Port 853/UDP (default)
- QUIC transport (hand-written QUIC implementation using `net.UDPConn`)
- TLS 1.3 integrated (QUIC requires it)
- One DNS message per QUIC stream
- 0-RTT support for repeat clients
- ALPN: `doq`
- Connection migration support
- **QUIC Implementation Scope** (minimal, DNS-focused):
  - Initial/Handshake/1-RTT packet types
  - TLS 1.3 handshake integration via `crypto/tls`
  - Stream multiplexing (unidirectional for DoQ)
  - Connection ID management
  - Loss detection & New Reno congestion control
  - 0-RTT early data
  - Connection migration (server-side)
  - QUIC transport parameters negotiation

---

## 4. Authoritative Engine

### 4.1 Zone Management

#### 4.1.1 Zone Store
- In-memory radix tree (trie) indexed by domain name labels (reversed)
- Thread-safe via `sync.RWMutex` per zone
- Supports multiple zones with overlapping namespaces
- DNSSEC-signed zone variants stored alongside unsigned

#### 4.1.2 BIND Zone File Parser
Full RFC 1035 §5 zone file format support:
- `$ORIGIN` directive
- `$TTL` directive (RFC 2308)
- `$INCLUDE` directive (file inclusion)
- `$GENERATE` directive (BIND extension for ranges)
- Relative and absolute domain names
- Shorthand notation (blank owner name = previous)
- Parenthesized multi-line records
- Semicolon comments
- All record types listed in §3.1.3
- Class: IN (default), CH (Chaosnet for version.bind)

#### 4.1.3 Zone Loading
```yaml
zones:
  - /etc/nothingdns/zones/example.com.zone

transfer:
  allow_list:
    - 10.0.0.0/24
  require_tsig: false

slave_zones:
  - zone_name: secondary.example.com.
    masters:
      - 10.0.0.2:53
    transfer_type: ixfr
```

### 4.2 Query Resolution (Authoritative)

1. Find best matching zone for QNAME
2. Exact match → return records
3. Wildcard match (*.example.com) → synthesize response
4. CNAME chain following (max depth: 10)
5. Delegation (NS at zone cut) → return referral
6. NXDOMAIN / NODATA with SOA in authority section
7. DNSSEC signing if zone is signed

### 4.3 Wildcard Processing (RFC 4592)
- Closest encloser proof for DNSSEC
- Wildcard synthesis with proper NSEC/NSEC3 records
- No wildcard at zone apex
- Wildcard does not match delegation points

---

## 5. Recursive Resolver

### 5.1 Resolution Modes

#### 5.1.1 Full Recursive (Iterative from Root)
- Embedded root hints (root-servers.net A/AAAA records)
- Iterative resolution: root → TLD → authoritative
- QNAME minimization (RFC 7816) — send minimal labels per hop
- Glue record handling
- CNAME chain following
- DNAME substitution (RFC 6672)

#### 5.1.2 Forwarder Mode
- Forward to upstream DNS servers (Cloudflare, Google, custom)
- Support for forwarding over UDP/TCP/DoT/DoH
- Upstream health checking with failover
- Per-zone forwarding rules

```yaml
resolution:
  recursive: true
  timeout: 5s
  max_depth: 10

upstream:
  servers:
    - 1.1.1.1:53
    - 8.8.8.8:53
    - 9.9.9.9:53
  strategy: round_robin
```

#### 5.1.3 Hybrid Mode
- Authoritative for configured zones
- Recursive/forwarding for everything else
- Most common deployment mode

### 5.2 Cache Layer

#### 5.2.1 Response Cache
- LRU eviction with TTL expiration
- Maximum cache size (configurable, default 100,000 entries)
- Cache key: (QNAME, QTYPE, QCLASS, DO-bit)
- Honors TTL from responses
- Minimum TTL override (default: 30s)
- Maximum TTL cap (default: 86400s / 24h)
- Serve-stale (RFC 8767) — serve expired entries while refreshing

#### 5.2.2 Negative Cache (RFC 2308)
- Cache NXDOMAIN responses
- Cache NODATA (empty answer) responses
- Negative TTL from SOA MINIMUM field
- Maximum negative TTL cap (default: 3600s)

#### 5.2.3 Prefetching
- Prefetch entries when TTL drops below 10% of original
- Background goroutine for prefetch queries
- Configurable prefetch percentage threshold

### 5.3 Security

#### 5.3.1 Resolver Hardening
- Source port randomization
- Transaction ID randomization (crypto/rand)
- 0x20 encoding (random case in QNAME for forgery resistance)
- Bailiwick checking (ignore out-of-zone glue)
- Maximum referral depth: 20
- Query timeout: 5 seconds (per upstream)
- Total resolution timeout: 30 seconds

---

## 6. DNSSEC

### 6.1 Signing (Authoritative)

#### 6.1.1 Zone Signing
- Online signing (sign at query time) or offline signing (pre-sign zone)
- RRSIG generation for all RRsets
- NSEC chain generation (RFC 4034)
- NSEC3 with opt-out (RFC 5155)
- Automatic NSEC/NSEC3 chain maintenance on zone changes
- Online (query-time) denial: NSEC by default; with `dnssec.signing.nsec3`
  configured, negative answers and referrals carry NSEC3 (opt-out honoured,
  NSEC3PARAM served at the apex). The setting is read per query, so a SIGHUP
  switches the mode immediately.
- `dnssec.signing.nsec3.iterations` is capped at 150 (RFC 9276; 0
  recommended) — larger values fail config validation

#### 6.1.2 Key Management
- KSK (Key Signing Key) and ZSK (Zone Signing Key) separation
- Automatic key rollover (prepublish method)
- Key generation: RSA-2048/4096, ECDSA P-256/P-384, Ed25519
- DS record generation for parent zone
- Key storage: file-based (PEM) or embedded KV store

#### 6.1.3 Algorithms Supported
| Algorithm | Code | Status |
|-----------|------|--------|
| RSASHA256 | 8    | Mandatory |
| RSASHA512 | 10   | Optional |
| ECDSAP256SHA256 | 13 | Recommended |
| ECDSAP384SHA384 | 14 | Optional |
| ED25519 | 15 | Recommended |

Implementation: All using Go's `crypto/rsa`, `crypto/ecdsa`, `crypto/ed25519` — zero dependencies.

### 6.2 Validation (Recursive)

- Full chain of trust validation from root trust anchors
- Trust anchor management (RFC 5011 — automated updates)
- Embedded root trust anchors (IANA root KSK)
- DNSSEC-aware cache (separate DNSSEC and non-DNSSEC entries)
- AD (Authentic Data) bit setting in responses
- CD (Checking Disabled) bit honoring
- Bogus response handling (SERVFAIL with extended error)
- Negative trust anchor support (RFC 7646)

#### 6.2.1 Validation work limits (fixed by design)

The validator bounds the cryptographic and lookup work one response can
cause, as BIND and Unbound do, to defeat KeyTrap-style CPU exhaustion
(CVE-2023-50387: colliding key tags × many RRSIGs; CVE-2023-50868: NSEC3
hash floods). The limits are compile-time constants in
`internal/dnssec/validator.go` / `crypto.go` and are **not configurable**;
they sit far above what legitimate signed zones need (a 10-RRset answer
behind a 3-link chain in the middle of a KSK + ZSK rollover needs about 15
signature verifications).

| Limit | Value | Constant |
|---|---|---|
| Signature verifications per RRset (RRSIG × same-tag DNSKEY) | 8 | `maxSigVerificationsPerRRset` |
| Signature verifications per response (chain + answer + proofs) | 128 | `maxSigVerificationsPerResponse` |
| NSEC3 hash computations per response | 512 | `maxNSEC3HashesPerResponse` |
| Zone-cut DS lookups per response (§6.2.2) | 64 | `maxZoneCutLookupsPerResponse` |
| Answer-section RRsets validated per response | 32 | `maxRRsetsValidated` |
| NSEC/NSEC3 RRsets in a denial (Authority section) | 16 | `maxNSECValidations` |
| DS × DNSKEY comparisons per delegation | 32 | `maxDelegationOps` |
| Chain depth (zone links) | 20 | `ValidatorConfig.MaxDelegationDepth` default (not exposed in YAML) |
| NSEC3 iterations | 150 | `maxNSEC3Iterations` (`NSEC3Hash`) |

Exceeding any limit makes the response **Bogus**, answered SERVFAIL with
EDE 6 (DNSSEC Bogus) while `dnssec.enabled` is true. NSEC3 records with more
than 150 iterations are never hashed, so a denial that depends on them is
unproven and therefore Bogus (RFC 9276 §3.2 lets a validator answer either
insecure or SERVFAIL above its iteration limit; NothingDNS fails closed). The
signer rejects `dnssec.signing.nsec3.iterations` above 150 at config
validation.

#### 6.2.2 Zone-cut trust model

An RRset is authenticated only by the zone that contains it (RFC 4035
§5.3.1). The chain is built down to the RRSIG signer (commit 715f339), so the
validator additionally checks that no zone cut lies between the signer and
the data:

- **Enforced** — for an owner more than one label below the signer, every
  name strictly between them must be proven *not* a zone cut (authenticated
  DS NODATA without NS); a proven cut, a missing proof or a failed lookup →
  Bogus. Negative answers get the same check down to the proven closest
  encloser. Results are cached across responses (TTL-bounded, 4096 entries)
  and lookups are charged to the per-response budget above (§6.2.1).
- **Enforced at zero cost** — a parent's delegation NSEC/NSEC3 (NS set, SOA
  clear) proves only the absence of DS at that name; a DNAME owner's
  NSEC/NSEC3 cannot deny names below it; apex-only types (SOA, DNSKEY,
  NSEC3PARAM, CDS, CDNSKEY, NS) signed by a zone other than their owner are
  Bogus.
- **Accepted by design (trust-model decision)** — parent-signed data of a
  non-apex type (A, AAAA, MX, TXT, …) whose owner name is itself a child
  zone apex is not checked: closing this would cost one DS lookup for nearly
  every answer owner (the www-style names one label below their zone) and
  would reverse 715f339, which avoids DS queries for non-delegation names
  because some upstreams mishandle them. Exploiting it needs a parent-zone
  signature over child-apex data — a stale pre-delegation signature still
  inside its validity window, or a malicious parent, which can already
  replace the child's DS and is inside DNSSEC's trust model.

---

## 7. Zone Transfer

### 7.1 AXFR (RFC 5936)
- Full zone transfer (primary → secondary)
- TCP only (no UDP for AXFR)
- Multi-message transfer for large zones
- SOA serial-based triggering

### 7.2 IXFR (RFC 1995)
- Incremental zone transfer
- Difference sequences (old SOA → changes → new SOA)
- Journal-based (Dynamic DNS updates create journal entries)
- Fallback to AXFR if journal insufficient

### 7.3 NOTIFY (RFC 1996)
- Primary notifies secondaries on every SOA serial change of a transferable
  zone (API/Raft/gossip edits, Dynamic DNS, SIGHUP zone reload), and once
  for every zone after startup when the DNS listeners are up (notify on
  load). Transferred `slave_zones` are not served by AXFR/IXFR downstream, so
  they are not announced.
- Targets are global: `transfer.also_notify` (literal `IP:port` list; a SIGHUP
  applies changes — added targets are notified from the next serial change,
  in-flight NOTIFYs to removed targets are cancelled). Empty (default) = no
  NOTIFY is sent. There is no per-zone target
  list (zones are configured as file paths, without a per-zone section).
- Optional TSIG signing with the `transfer.tsig_keys` entry named by
  `transfer.notify_key`.
- Sent asynchronously (never on the query path): one in-flight NOTIFY per
  zone+target; a change arriving meanwhile cancels the superseded send and
  the latest serial is sent next.
  An unanswered NOTIFY is retransmitted (RFC 1996 §3.6: up to 5 retransmissions,
  5 s each); only a reply with the request's ID counts. In-flight NOTIFYs are
  cancelled on shutdown.
- Incoming NOTIFY for a configured `slave_zones` zone is authorized by that
  zone's `masters` (RFC 1996 §3.10; host names are resolved) and triggers an
  immediate refresh; any other source gets REFUSED. `transfer.allow_list`
  (which lists hosts allowed to transfer *from* this server) does not
  authorize slave-zone NOTIFY; it only covers NOTIFY for other zones
  (deny-by-default when empty).
- Secondary (`slave_zones`) refresh follows the transferred SOA: REFRESH after
  success, RETRY after failure (clamped: REFRESH 30 s–28 d, RETRY 30 s–14 d,
  EXPIRE ≥ REFRESH+RETRY); `retry_interval` applies only until the first
  load. A zone past EXPIRE, or never loaded, is not served.

### 7.4 TSIG Authentication (RFC 8945)
- HMAC-SHA1 (deprecated), HMAC-SHA224, HMAC-SHA256, HMAC-SHA384,
  HMAC-SHA512; HMAC-MD5 is rejected
- Keys from `transfer.tsig_keys` (and `slave_zones[].tsig_key_name`); key
  names are compared as domain names (case-insensitive, trailing dot
  optional) and responses are signed with the canonical name
- TSIG verification on incoming transfers, NOTIFY and UPDATE; signing on
  outgoing transfers and NOTIFY
- Multi-message transfers carry the RFC 8945 TSIG chain

### 7.5 XoT (RFC 9103)
- TLS 1.3 only, ALPN `dot` offered; `server.xot.min_tls_version` values below
  13 have no effect
- Deny-by-default: `server.xot.ca_file` (mTLS) or `server.xot.allowed_networks`
  is required, otherwise the server refuses to start

---

## 8. Dynamic DNS (RFC 2136)

### 8.1 UPDATE Message Processing
- Prerequisites: RRset exists, RRset does not exist, name exists, name does not exist
- Update section: Add RRset, Delete RRset, Delete name
- Atomic updates per zone
- SOA serial auto-increment on successful update
- TSIG authentication always required: unsigned UPDATE → REFUSED; the key must
  list the zone in `transfer.tsig_keys[].allow_update` (else REFUSED); unknown
  key, bad MAC or an address outside the key's `allowed_cidrs` → NOTAUTH
- Raft cluster mode: one UPDATE = one atomic Raft entry (zone batch);
  only the leader applies UPDATEs; a follower answers REFUSED unless
  `cluster.forward_updates: true` (opt-in), in which case it forwards a TSIG-signed UPDATE
  unchanged to the leader's advertised DNS address (`cluster.dns_advertise_addr`,
  RFC 2136 §6) and relays the leader's response unchanged; no leader, no
  advertised address or a forward timeout → SERVFAIL; unsigned → REFUSED;
  more than 1024 record changes or an SOA replacement → REFUSED. A
  forwarded UPDATE reaches the leader from the follower's address, so the
  leader applies `allowed_cidrs` and ACLs to the follower's IP, not the
  client's (§10.3)

### 8.2 Journal
- Append-only journal of all dynamic updates
- Used for IXFR generation
- Periodic journal compaction (merge with zone file)
- Journal replay on startup

---

## 9. Advanced Features

### 9.1 Blocklist / Allowlist (Ad-Blocking)

#### 9.1.1 Blocklist
- Domain blocklist format (hosts file format + domain-only format)
- Support for popular blocklist sources (AdGuard, Steven Black, Pi-hole compatible)
- Local blocklist file(s)
- Response for blocked domains: NXDOMAIN, 0.0.0.0, or custom IP
- Regex pattern matching (optional, hand-written regex engine)
- Wildcard blocking (block *.ads.example.com)

#### 9.1.2 Allowlist
- Override blocklist for specific domains
- Per-client/group allowlists

```yaml
blocklist:
  enabled: true
  files:
    - "/etc/nothingdns/blocklists/default.txt"
  urls:
    - "https://example.com/blocklist.txt"
```

### 9.2 GeoDNS

#### 9.2.1 GeoIP Database
- Support for MaxMind GeoLite2 binary format (.mmdb)
- Embedded GeoIP reader (parse MMDB format natively in Go)
- Country, continent, and ASN-level resolution
- Configurable database path + auto-reload on update

#### 9.2.2 Geo-Based Responses
- Per-record geo routing rules
- Fallback chain: city → country → continent → default
- EDNS Client Subnet awareness (use client's real IP, not resolver IP)

```yaml
geodns:
  enabled: true
  mmdb_file: "/etc/nothingdns/GeoLite2-Country.mmdb"
  rules:
    - domain: "cdn.example.com."
      type: A
      default: "198.51.100.1"
      EU: "185.0.0.1"
      US: "203.0.113.1"
```

### 9.3 Split-Horizon DNS (Views)

- View-based query routing by source IP/subnet
- Each view has its own zone data
- ACL-based view matching
- Default view as fallback

```yaml
views:
  - name: "internal"
    match_clients:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
    zone_files:
      - "/etc/nothingdns/zones/internal.example.com.zone"
  - name: "external"
    match_clients:
      - "any"
    zone_files:
      - "/etc/nothingdns/zones/external.example.com.zone"
```

### 9.4 EDNS Client Subnet (RFC 7871)
- Parse ECS option from incoming queries
- Forward ECS to upstream resolvers
- Use ECS for GeoDNS decisions
- Configurable ECS scope (prefix length limits)
- Privacy mode: strip ECS before forwarding

### 9.5 Response Rate Limiting — RRL (RFC Draft)
- Per-source-IP rate limiting
- Per-response-type limits (NXDOMAIN, referral, nodata, answer)
- Slip rate: probabilistic truncation instead of drop
- Token bucket algorithm
- Configurable window size and rates

```yaml
rrl:
  enabled: true
  rate: 10
  burst: 20
```

---

## 10. Cluster Mode (Raft Consensus)

### 10.1 Architecture

#### 10.1.1 Raft Implementation (from scratch)
- **Leader Election** — randomized election timeout, RequestVote RPC
- **Log Replication** — AppendEntries RPC, log matching property
- **Safety** — election restriction (up-to-date log), commit rules
- **Membership Changes** — joint consensus for cluster resizing
- **Log Compaction** — periodic snapshots + truncation
- **Transport** — custom binary RPC over TCP on `cluster.bind_addr:gossip_port`
  (see §10.3)
- **Snapshot transfer** — a snapshot larger than 4 MiB is sent to followers in
  chunks (rolling-upgrade note in §10.4)

`cluster.consensus_mode: swim` (the alternative to the default `raft`) runs
the SWIM-style gossip protocol over UDP on the same address instead, with
`seed_nodes` and eventual consistency; the rest of this section describes
Raft mode.

#### 10.1.2 State Machine
The Raft FSM applies zone commands to every replica's zone store:
- Zone create / delete
- Record add / update / delete (a whole RRset, or a single RR when the
  command carries RDATA)
- Atomic zone batch — one entry applied all-or-nothing with one SOA serial
  bump and an optional precondition fingerprint (used by Dynamic DNS, §8.1)

Blocklists, ACLs and configuration are not replicated through Raft; each
node reads its own config file and data directory.

#### 10.1.3 Cluster Topology
```
┌──────────┐       ┌──────────┐       ┌──────────┐
│  Node 1  │◄─────►│  Node 2  │◄─────►│  Node 3  │
│ (Leader)  │       │(Follower)│       │(Follower)│
│  :7946    │       │  :7946   │       │  :7946   │
└──────────┘       └──────────┘       └──────────┘
     │                   │                   │
     └───── Raft Consensus (zone sync) ─────┘
```
(`gossip_port`, default 7946, carries the Raft RPC in Raft mode.)

### 10.2 Configuration

```yaml
cluster:
  enabled: true
  node_id: "node-1"
  consensus_mode: "raft"          # default; "swim" = gossip only
  bind_addr: "10.0.0.1"
  gossip_port: 7946               # Raft RPC listens here (TCP)
  data_dir: /var/lib/nothingdns/cluster
  encryption_key: "${NOTHINGDNS_CLUSTER_ENCRYPTION_KEY}"
  peers:                          # the OTHER members
    - node_id: "node-2"
      addr: "10.0.0.2:7946"
    - node_id: "node-3"
      addr: "10.0.0.3:7946"
  # rpc:                          # optional (m)TLS on top of the AEAD framing
  #   enabled: true
  #   tls_cert_file: /etc/nothingdns/cluster.crt
  #   tls_key_file: /etc/nothingdns/cluster.key
  #   tls_ca_cert_file: /etc/nothingdns/cluster-ca.crt
  # forward_updates: false        # see §10.3
  # dns_advertise_addr: "10.0.0.1:53"
```

### 10.3 Inter-Node Communication

There is no gRPC layer and no separate forwarding port. What exists:

- **Raft RPC** — RequestVote, AppendEntries and InstallSnapshot as
  length-prefixed binary messages over TCP on `bind_addr:gossip_port`
  (16 MiB frame limit). Frames are encrypted with AES-256-GCM derived from
  `cluster.encryption_key` (required unless `allow_insecure: true`);
  `cluster.rpc.*` adds optional TLS / mutual TLS on top.
- **Leader DNS address** — each node advertises a DNS TCP address
  (`cluster.dns_advertise_addr`, else the first concrete `server.tcp_bind` /
  `bind` address; a wildcard-only bind advertises nothing). The leader carries
  its address in an optional trailer of every AppendEntries, so followers
  know where to reach it.
- **Dynamic DNS forwarding (opt-in)** — with `cluster.forward_updates: true`
  a follower forwards a TSIG-signed RFC 2136 UPDATE, byte-for-byte, over DNS
  TCP to the leader's advertised address (RFC 2136 §6) and relays the
  leader's signed response unchanged. Default `false`: followers answer
  REFUSED. The leader authorizes the UPDATE and sees the **follower's** IP,
  so `tsig_keys[].allowed_cidrs` and ACLs are evaluated against the follower.
  Unsigned UPDATEs are never forwarded; no leader, no advertised address, a
  5 s timeout or more than 64 concurrent forwards → SERVFAIL.
- **Zone batches** — the leader commits an accepted UPDATE as one atomic
  zone-batch entry. Its precondition (a fingerprint of the touched names, or
  of the whole zone when the UPDATE has an SOA prerequisite) is re-checked by
  every replica under the zone lock; a mismatch applies nothing and makes the
  leader re-plan (retry, then SERVFAIL; a failed SOA prerequisite → NXRRSET).
- No query forwarding, health checking or metrics aggregation between nodes;
  each node serves queries, health and metrics locally.

### 10.4 Rolling Upgrades (mixed-version clusters)

Several replicated formats changed during the 2026 hardening rounds. Each
change is additive so that a mixed cluster does not wedge, but an older node
can diverge. Upgrade **every** node before using the feature in the right
column; an older node that diverged converges again only after it installs a
newer snapshot.

| Change | Older node behaviour | Requirement |
|---|---|---|
| Chunked InstallSnapshot (snapshots > 4 MiB) | cannot install a chunked snapshot and stays behind | upgrade followers before snapshots exceed 4 MiB |
| Per-RR delete (`del_record` with RDATA) | ignores RDATA and deletes the whole RRset | upgrade all nodes before API single-record deletes |
| Atomic zone batch (`create_zone` envelope, payload v1) | logs "create_zone … missing nameservers", applies nothing | upgrade all nodes before Raft-mode Dynamic DNS |
| SOA-prerequisite guard (payload v2, `"zone": true`) | a v1-only node rejects it deterministically (nothing applied, warning logged) | upgrade all nodes before UPDATEs with SOA prerequisites |
| Leader DNS address trailer on AppendEntries | old followers ignore it; an old leader sends none, so forwarding followers answer SERVFAIL | upgrade before enabling `forward_updates` |
| RFC 8945 TSIG chain on multi-message AXFR/IXFR | pre-fix servers sent an unbound chain that new clients reject (keyed AXFR between NothingDNS nodes never worked before the fix) | upgrade primaries and secondaries together for keyed transfers; single-message TSIG is unchanged; third-party interop of the multi-message chain is not yet proven |

---

## 11. Management Interfaces

### 11.1 REST API

Base path: `/api/v1`
Authentication: API key (Bearer token) or basic auth

#### Endpoints

**Zones**
| Method | Path | Description |
|--------|------|-------------|
| GET | /zones | List all zones |
| POST | /zones | Create zone |
| GET | /zones/{name} | Get zone details |
| PUT | /zones/{name} | Update zone |
| DELETE | /zones/{name} | Delete zone |
| POST | /zones/{name}/import | Import BIND zone file |
| GET | /zones/{name}/export | Export BIND zone file |

**Records**
| Method | Path | Description |
|--------|------|-------------|
| GET | /zones/{name}/records | List records |
| POST | /zones/{name}/records | Add record |
| PUT | /zones/{name}/records/{id} | Update record |
| DELETE | /zones/{name}/records/{id} | Delete record |

**Cluster**
| Method | Path | Description |
|--------|------|-------------|
| GET | /cluster/status | Cluster status |
| GET | /cluster/nodes | List nodes |
| POST | /cluster/nodes | Add node |
| DELETE | /cluster/nodes/{id} | Remove node |
| POST | /cluster/snapshot | Trigger snapshot |

**Blocklist**
| Method | Path | Description |
|--------|------|-------------|
| GET | /blocklist | List blocked domains |
| POST | /blocklist | Add domain(s) |
| DELETE | /blocklist/{domain} | Unblock domain |
| POST | /blocklist/reload | Reload blocklists |

**Cache**
| Method | Path | Description |
|--------|------|-------------|
| GET | /cache/stats | Cache statistics |
| DELETE | /cache | Flush entire cache |
| DELETE | /cache/{domain} | Flush domain from cache |

**Config**
| Method | Path | Description |
|--------|------|-------------|
| GET | /config | Current config |
| PATCH | /config | Update runtime config |

**DNSSEC**
| Method | Path | Description |
|--------|------|-------------|
| GET | /zones/{name}/dnssec | DNSSEC status |
| POST | /zones/{name}/dnssec/sign | Sign zone |
| POST | /zones/{name}/dnssec/rollover | Key rollover |
| GET | /zones/{name}/dnssec/ds | Get DS records |

**Statistics**
| Method | Path | Description |
|--------|------|-------------|
| GET | /stats | Query statistics |
| GET | /stats/top-queries | Top queried domains |
| GET | /stats/top-blocked | Top blocked domains |
| GET | /stats/top-clients | Top clients |

**Swagger**
| Method | Path | Description |
|--------|------|-------------|
| GET | /swagger | Swagger UI |
| GET | /swagger/spec.json | OpenAPI 3.0 spec |

### 11.2 CLI Tool (dnsctl)

```bash
# Zone management
dnsctl zone list
dnsctl zone add example.com ns1.example.com.
dnsctl zone remove example.com
dnsctl zone reload example.com
dnsctl zone export example.com > example.com.zone

# Record management
dnsctl record list example.com
dnsctl record add example.com www A 192.168.1.1 3600
dnsctl record update example.com www A 192.168.1.1 192.168.1.2 3600
dnsctl record remove example.com www A

# Cache
dnsctl cache stats
dnsctl cache flush
dnsctl cache flush example.com

# Cluster
dnsctl cluster status
dnsctl cluster peers
dnsctl cluster join 10.0.0.4:7946
dnsctl cluster leave

# Blocklist
dnsctl blocklist status
dnsctl blocklist sources
dnsctl blocklist reload

# DNSSEC
dnsctl dnssec status
dnsctl dnssec keys
dnsctl dnssec generate-key --algorithm 13 --type KSK --zone example.com
dnsctl dnssec ds-from-dnskey --zone example.com --keyfile Kexample.com.+013+12345.key

# Diagnostics
dnsctl dig example.com A                    # Built-in dig-like tool
dnsctl dig @localhost example.com AAAA +dnssec
dnsctl server health
dnsctl server status
dnsctl config get
dnsctl config reload

# Server
dnsctl server health
dnsctl server status
```

### 11.3 Web Dashboard

Embedded React 19 dashboard built from `web/src/` and served from `internal/dashboard/static/dist/` by the Go API server.

#### Features
- **Overview** — queries/sec, cache hit ratio, active clients, active zones
- **Query Log** — real-time query stream via WebSocket `/ws`
- **Zone Manager** — zone listing, zone details, and record editing via REST API
- **Policy Pages** — blocklist, RPZ, ACL, upstream, GeoIP, DNS64/Cookies, and zone transfer views
- **Cluster Status** — node health, consensus status, and cluster metrics
- **Metrics Dashboard** — historical charts, top domains, and API-backed dashboard stats
- **Settings** — grouped settings pages backed by config APIs where supported
- **DNSSEC Status** — validator/key status and DNSSEC operations visibility

### 11.4 Prometheus Metrics

Endpoint: `/metrics` (port 9153, Prometheus exposition format)

Key metrics:
- `nothingdns_queries_total{type, protocol, view}` — counter
- `nothingdns_responses_total{rcode}` — counter (NOERROR, NXDOMAIN, SERVFAIL, etc.)
- `nothingdns_query_duration_seconds{protocol}` — histogram
- `nothingdns_cache_size` — gauge
- `nothingdns_cache_hits_total` — counter
- `nothingdns_cache_misses_total` — counter
- `nothingdns_blocked_queries_total` — counter
- `nothingdns_zone_count` — gauge
- `nothingdns_zone_records_total{zone}` — gauge
- `nothingdns_cluster_is_leader` — gauge (0 or 1)
- `nothingdns_cluster_peers` — gauge
- `nothingdns_cluster_raft_term` — gauge
- `nothingdns_upstream_latency_seconds{upstream}` — histogram
- `nothingdns_dnssec_validations_total{result}` — counter (secure, insecure, bogus)

---

## 12. Configuration

### 12.1 Configuration File Format

Hand-written YAML parser (subset of YAML 1.2 — maps, sequences, scalars,
comments; no anchors/aliases or multi-line strings). No external YAML library.
Loading fails loudly instead of falling back to defaults: tab indentation,
unknown double-quote escapes, invalid booleans, list sections written as a
mapping, duplicate keys, non-positive `resolution.timeout` /
`dnssec.signing.signature_validity` / `cookie.secret_rotation`, and unknown ACL
query types are errors. Durations use Go syntax (`30s`, `5m`, `168h`; no `d`
unit). Field reference: [CONFIG_REFERENCE.md](CONFIG_REFERENCE.md).

### 12.2 Example Configuration

The complete annotated example is [config.example.yaml](../config.example.yaml).
A minimal recursive resolver with one local zone:

```yaml
# /etc/nothingdns/nothingdns.yaml
server:
  port: 53
  bind:
    - 0.0.0.0
    - "::"
  http:
    enabled: true
    bind: "127.0.0.1:8080"
    auth_token: "${NOTHINGDNS_API_TOKEN}"

resolution:
  recursive: true
  qname_minimization: true
  timeout: 5s

cache:
  enabled: true
  size: 100000
  min_ttl: 30
  max_ttl: 86400
  negative_ttl: 3600
  serve_stale: true
  prefetch: true

zones:
  - /etc/nothingdns/zones/example.com.zone

transfer:
  allow_list:
    - 10.0.0.0/24
  require_tsig: false

allow_recursion:
  - 127.0.0.0/8
  - "::1/128"
  - 10.0.0.0/8

acl:
  # `types` narrows a rule to specific QTYPEs; omit it to match all of them.
  # "ANY" is QTYPE 255, not a wildcard.
  - name: allow-internal
    action: allow
    networks:
      - 10.0.0.0/8
      - 127.0.0.0/8

rrl:
  enabled: true
  rate: 10
  burst: 20

metrics:
  enabled: true
  bind: "127.0.0.1:9153"
  path: /metrics

logging:
  level: info                      # debug | info | warn | error
  format: json                     # json | text
  output: stdout                   # stdout | stderr | absolute file path
  query_log: true
  query_log_file: /var/log/nothingdns/queries.log
```

### 12.3 Environment Variables
There is no per-key environment override. Scalar values may reference
environment variables with `${VAR}` or `$VAR`, expanded at load time (e.g.
`auth_token: "${NOTHINGDNS_API_TOKEN}"`).

### 12.4 Hot Reload
SIGHUP (or `POST /api/v1/config/reload`) re-reads the config file through the
same code path (`cmd/nothingdns/reload.go`). Every new component is prepared
first; a config that fails to parse or validate, an unreadable zone file or
an unparsable TSIG key aborts the reload and leaves the running state
untouched. Queries are not interrupted.

| Applied by SIGHUP | Restart required |
|---|---|
| `zones` (files added, changed, removed), `views` | listeners: addresses/ports/workers, `server.tls.enabled`, `server.quic.*`, `server.xot.*` (except certificate contents), all of `server.http.*` (auth token, users, CORS origins, DoH/DoWS/ODoH endpoints) |
| `upstream` (client and load balancer rebuilt, incl. anycast `topology.*`, and `resolution.timeout`) | `cache.enabled` (the cache always exists) |
| the iterative resolver, rebuilt and swapped atomically: `resolution.recursive` (true→false stops iterative resolution at once, false→true starts it), `root_hints`, `max_depth`, `timeout`, `edns0_buffer_size`, `qname_minimization`, `use_0x20`, and the DO bit from `dnssec.enabled`; in-flight queries finish on the old instance | `logging.output`, `logging.query_log`, `logging.query_log_file` |
| `resolution.authoritative_only` (read per request) | `dnssec.signing.enabled`, `signing.keys`, `signing.signature_validity` (zone signers are built at start; a zone added by reload is served unsigned until restart) |
| `cache.size`, `default_ttl`, `max_ttl`, `min_ttl`, `negative_ttl`, `prefetch`, `prefetch_threshold`, `serve_stale`, `stale_grace_secs` (applied to the running cache; its contents are kept) | `metrics.*`, `tracing.*`, `odoh.*`, `memory_limit_mb` |
| `logging.level`, `logging.format` | `idna.check_joiner` (deprecated, no effect) |
| `idna.enabled`, `use_std3_rules`, `allow_unassigned`, `check_bidi` | |
| `dnssec.enabled`, `trust_anchor`, `ignore_time`, `require_dnssec` (validator rebuilt), `dnssec.signing.nsec3` (read per request) | |
| `blocklist` (incl. `base_dir`), `rpz`, `geodns`, `dns64`, `acl`, `allow_recursion`, `server.acl_allow_unrestricted_recursion`, rate limiter / RRL | |
| `transfer.also_notify`, `transfer.notify_key` (added targets notified from the next serial change; in-flight NOTIFYs to removed targets cancelled) | `storage.*`, `server.http.auth_secret`, `transfer.journal_dir` |
| `transfer.tsig_keys` incl. `secret`, `allow_update`, `allowed_cidrs` (AXFR/IXFR, UPDATE, NOTIFY signing; a removed key is rejected as soon as the reload returns) | `cluster.*` except `forward_updates` (incl. `dns_advertise_addr`, `peers`, `weight`, `cache_sync`, keys) |
| `slave_zones[].tsig_secret` (next transfer signs with the new secret) | `slave_zones` membership (zone, `masters`, `tsig_key_name`), `transfer.allow_list`, `transfer.require_tsig` |
| `cluster.forward_updates` (read per request), `shutdown_timeout` (read at the next shutdown) | TLS certificate/key/CA file **paths** (`server.tls.*`, `server.quic.*`, `server.xot.*`, `server.http.tls_*`) |
| TLS certificate/key file **contents** for DoT, DoQ, XoT (plus `server.xot.ca_file`) and the HTTPS API/DoH — re-read on every reload, even when the config file fails to load | `cluster.rpc` TLS certificate (Raft RPC) |

Every reload rebuilds the iterative resolver from the reloaded `resolution.*`
and `dnssec.enabled` values (or removes it when `recursive` is false) and
swaps it under the handler's runtime lock, so in-flight queries finish on the
old instance; the response cache keeps its contents and takes the new
tunables; the logger's level and format and the IDNA settings are applied.
`PUT /api/v1/config/cache` and `PUT /api/v1/config/logging` change the
running components immediately; `PUT /api/v1/config/resolution` applies
`authoritative_only` immediately and the other resolver fields on the next
reload (SIGHUP or `POST /api/v1/config/reload`) or restart. Per-key details
are in the Hot-reload column of `docs/CONFIG_REFERENCE.md`.

`runtime_overrides.json` and `access_policy.json` are re-applied over the
file on every reload (they win).

TLS certificates: each TLS listener (DoT, DoQ, XoT, HTTPS API/DoH) serves its
certificate from an in-memory holder (`server.CertReloader`, consulted through
`tls.Config.GetCertificate` for every handshake, with or without SNI). Every
reload first re-reads each listener's cert/key files (and the XoT `ca_file`,
whose pool is published per handshake through `GetConfigForClient`), before
and independently of the config file. Handshakes that start after the reload
get the new certificate; established connections keep theirs. A listener
whose files fail to load (missing file, key that does not match, CA file
without certificates) keeps its previous certificate/CA pool and the error is
logged — the listener is never taken down. Files are not re-read per
handshake, so send SIGHUP after a renewal (e.g. from a certbot deploy hook).
A CA removed from `xot.ca_file` is refused on session resumption too
(crypto/tls re-checks a resumed session's chains against the current pool).

---

## 13. Storage & Persistence

### 13.1 Write-Ahead Log (WAL)
- Append-only binary log for crash recovery
- All zone mutations logged before applying
- Configurable sync mode: `fsync` every write vs. periodic
- WAL compaction with snapshot

### 13.2 Embedded Key-Value Store
- B+tree based (hand-written, inspired by BoltDB)
- Used for: zone data persistence, DNSSEC keys, cluster state, configuration
- ACID transactions
- Copy-on-write for concurrent reads
- Single-file database

### 13.3 Data Directory Layout
```
/var/lib/nothingdns/
├── data.db              # Embedded KV store
├── wal/                 # Write-ahead log
│   ├── 000001.wal
│   └── 000002.wal
├── raft/                # Raft state
│   ├── log/
│   ├── snapshots/
│   └── stable.db
├── keys/                # DNSSEC keys
│   └── example.com/
│       ├── Kexample.com.+013+12345.key
│       └── Kexample.com.+013+12345.private
└── journal/             # Dynamic DNS journals
    └── example.com.jnl
```

---

## 14. Performance Targets

| Metric | Target |
|--------|--------|
| Queries/sec (UDP, cached) | >500,000 |
| Queries/sec (UDP, authoritative) | >200,000 |
| Queries/sec (DoH) | >100,000 |
| Average latency (cached) | <1ms |
| Average latency (authoritative) | <5ms |
| Memory usage (100K cache + 10 zones) | <256MB |
| Binary size | <30MB |
| Startup time (cold) | <2 seconds |
| Zone load (1M records) | <5 seconds |
| Cluster failover time | <3 seconds |

### 14.1 Performance Design Decisions
- Zero allocation on hot path (sync.Pool for byte buffers)
- Pre-allocated response buffers
- Lock-free cache reads where possible (sync.Map for hot entries)
- Goroutine-per-query model (Go scheduler handles multiplexing)
- UDP batch reading (recvmmsg equivalent via multiple goroutines)
- Connection pooling for upstream resolvers
- EDNS buffer size negotiation to minimize TCP fallback

---

## 15. Security

### 15.1 Network Security
- ACL-based access control (per zone, per operation)
- Response Rate Limiting (RRL) against amplification attacks
- TCP SYN cookies (OS level)
- TSIG for zone transfers, NOTIFY and Dynamic DNS (per-key zone grants)
- XoT: TLS 1.3 only, mTLS or network allow list required
- ODoH: ACL and recursion policy apply to the HTTP peer of the target (the
  oblivious proxy), not to the end client
- API authentication (bearer token / basic auth); users defined in the config
  file cannot be deleted or changed through the API (409)
- TLS 1.3 for DoT/DoH/DoQ
- DNSSEC validation for resolver mode

### 15.2 Operational Security
- Drop privileges after binding to port 53 (run as non-root)
- Chroot support
- Minimal file system access
- No shell execution
- Sandboxed zone file parser
- Config file permission checks
- Secrets via environment variables

---

## 16. Deployment

### 16.1 Single Binary
```bash
# Download and run
curl -fsSL https://github.com/nothingdns/nothingdns/releases/latest/download/nothingdns-linux-amd64 -o nothingdns
chmod +x nothingdns
./nothingdns --config /etc/nothingdns/nothingdns.yaml
```

### 16.2 Docker
```dockerfile
FROM scratch
COPY nothingdns /nothingdns
EXPOSE 53/udp 53/tcp 853 443 8080 9153
ENTRYPOINT ["/nothingdns"]
```

```bash
docker run -d --name nothingdns \
  -p 53:53/udp -p 53:53/tcp \
  -p 853:853 -p 443:443 \
  -p 8080:8080 -p 9153:9153 \
  -v ./config:/etc/nothingdns \
  ghcr.io/ecostack/nothingdns:latest
```

### 16.3 Docker Compose (3-Node Cluster)
```yaml
version: '3.8'
services:
  dns1:
    image: ghcr.io/ecostack/nothingdns:latest
    environment:
      NOTHINGDNS_CLUSTER_ENABLED: "true"
      NOTHINGDNS_CLUSTER_NODE_ID: "node-1"
      NOTHINGDNS_CLUSTER_BIND: "0.0.0.0:4222"
      NOTHINGDNS_CLUSTER_PEERS: "node-2=dns2:4222,node-3=dns3:4222"
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "8080:8080"
    networks:
      - dnsnet

  dns2:
    image: ghcr.io/ecostack/nothingdns:latest
    environment:
      NOTHINGDNS_CLUSTER_ENABLED: "true"
      NOTHINGDNS_CLUSTER_NODE_ID: "node-2"
      NOTHINGDNS_CLUSTER_BIND: "0.0.0.0:4222"
      NOTHINGDNS_CLUSTER_PEERS: "node-1=dns1:4222,node-3=dns3:4222"
    networks:
      - dnsnet

  dns3:
    image: ghcr.io/ecostack/nothingdns:latest
    environment:
      NOTHINGDNS_CLUSTER_ENABLED: "true"
      NOTHINGDNS_CLUSTER_NODE_ID: "node-3"
      NOTHINGDNS_CLUSTER_BIND: "0.0.0.0:4222"
      NOTHINGDNS_CLUSTER_PEERS: "node-1=dns1:4222,node-2=dns2:4222"
    networks:
      - dnsnet

networks:
  dnsnet:
```

### 16.4 Systemd Service
```ini
[Unit]
Description=NothingDNS Server
After=network.target

[Service]
Type=notify
ExecStart=/usr/local/bin/nothingdns -config /etc/nothingdns/nothingdns.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
User=nothingdns
Group=nothingdns
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/nothingdns /var/log/nothingdns
# Pin stdout/stderr to a file under /var/log/nothingdns so the
# /etc/logrotate.d/nothingdns rule (which globs /var/log/nothingdns/*.log)
# actually catches the running app's log stream, not just the query log.
# `append:` (systemd >= 246) preserves the file across restarts and matches
# the audit logger's O_APPEND open mode.
StandardOutput=append:/var/log/nothingdns/server.log
StandardError=append:/var/log/nothingdns/server.log
SyslogIdentifier=nothingdns

[Install]
WantedBy=multi-user.target
```

---

## 17. Build & Cross-Compilation

```makefile
VERSION := $(shell git describe --tags --always)
LDFLAGS := -s -w -X main.Version=$(VERSION)

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/nothingdns ./cmd/nothingdns
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/dnsctl ./cmd/dnsctl

release:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/nothingdns-linux-amd64 ./cmd/nothingdns
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/nothingdns-linux-arm64 ./cmd/nothingdns
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/nothingdns-darwin-amd64 ./cmd/nothingdns
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/nothingdns-darwin-arm64 ./cmd/nothingdns
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/nothingdns-windows-amd64.exe ./cmd/nothingdns
	GOOS=freebsd GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/nothingdns-freebsd-amd64 ./cmd/nothingdns

docker:
	docker build -t ghcr.io/ecostack/nothingdns:$(VERSION) .

test:
	go test -race -cover ./...

bench:
	go test -bench=. -benchmem ./...
```

---

## 18. Comparison with Existing DNS Servers

| Feature | NothingDNS | BIND 9 | CoreDNS | PowerDNS | Unbound |
|---------|-----------|--------|---------|----------|---------|
| Language | Go | C | Go | C++ | C |
| Dependencies | Minimal (2 direct) | Many | Many (plugins) | Many | Several |
| Single Binary | ✅ | ❌ | ✅ | ❌ | ❌ |
| Authoritative | ✅ | ✅ | ✅ (plugin) | ✅ | ❌ |
| Recursive | ✅ | ✅ | ✅ (plugin) | ✅ (recursor) | ✅ |
| DoT | ✅ | ✅ | ✅ | ❌ | ✅ |
| DoH | ✅ | ❌ | ✅ | ❌ | ✅ |
| DoQ | ✅ | ❌ | ❌ | ❌ | ❌ |
| DNSSEC Sign | ✅ | ✅ | ❌ | ✅ | ❌ |
| DNSSEC Validate | ✅ | ✅ | ✅ | ❌ | ✅ |
| Clustering | ✅ (Raft) | ❌ | ❌ | ❌ | ❌ |
| GeoDNS | ✅ | ❌ | ✅ | ✅ | ❌ |
| Split-Horizon | ✅ | ✅ (views) | ❌ | ❌ | ❌ |
| Ad-Blocking | ✅ | ❌ | ✅ (plugin) | ❌ | ❌ |
| Web Dashboard | ✅ | ❌ | ❌ | ✅ | ❌ |
| REST API | ✅ | ❌ | ❌ | ✅ | ❌ |
| BIND Zone Import | ✅ | Native | ❌ | ❌ | ❌ |

---

## 19. RFC Compliance

### Core
- RFC 1034 — Domain Names: Concepts and Facilities
- RFC 1035 — Domain Names: Implementation and Specification
- RFC 2181 — Clarifications to the DNS Specification
- RFC 6895 — DNS IANA Considerations

### Transport
- RFC 7766 — DNS Transport over TCP
- RFC 7858 — DNS over TLS (DoT)
- RFC 8484 — DNS over HTTPS (DoH)
- RFC 9250 — DNS over QUIC (DoQ)

### EDNS
- RFC 6891 — EDNS(0)
- RFC 7871 — EDNS Client Subnet
- RFC 7830 — EDNS Padding

### DNSSEC
- RFC 4033 — DNSSEC Introduction and Requirements
- RFC 4034 — Resource Records for DNSSEC
- RFC 4035 — Protocol Modifications for DNSSEC
- RFC 5155 — NSEC3
- RFC 5011 — Trust Anchor Update
- RFC 6698 — DANE/TLSA

### Zone Transfer & Dynamic DNS
- RFC 1995 — Incremental Zone Transfer (IXFR)
- RFC 1996 — NOTIFY
- RFC 2136 — Dynamic DNS UPDATE
- RFC 2845 — TSIG
- RFC 5936 — AXFR

### Security & Performance
- RFC 2308 — Negative Caching
- RFC 4592 — Wildcard Processing
- RFC 6672 — DNAME
- RFC 7816 — QNAME Minimization
- RFC 8767 — Serve-Stale
- RFC 8914 — Extended DNS Errors

---

## 20. Non-Goals (Out of Scope)

- GUI installer (CLI/config-file only)
- Windows service manager (use NSSM externally)
- LDAP/Active Directory integration
- HTTP-based zone API that replaces zone files entirely (API and zone files coexist)
- Full QUIC implementation beyond DNS-focused subset (mDNS is implemented — see `internal/mdns/`)
- Commercial GeoIP database bundling (user provides their own)

---

## 21. Success Criteria

1. **Functional:** Pass all RFC compliance tests for authoritative + recursive modes
2. **Performance:** Exceed 500K QPS on cached UDP queries (single node)
3. **Reliability:** Zero downtime during leader failover in 3-node cluster (<3s)
4. **Compatibility:** Successfully import and serve 100% of valid BIND zone files
5. **Security:** Pass DNSSEC validation test suites (DNSViz, Verisign Labs)
6. **Usability:** Fresh install to serving first zone in <5 minutes
7. **Size:** Single binary under 30MB, Docker image under 35MB (FROM scratch)

---

*Document Version: 1.0*
*Created: 2026-03-25*
*Author: Ersin / ECOSTACK TECHNOLOGY OÜ*
*Status: DRAFT — Pending Review*
