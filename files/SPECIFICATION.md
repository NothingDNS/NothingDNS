# NothingDNS — Specification Document

> **Nothing but DNS. Nothing else needed.**
> Zero-dependency, single-binary, full-featured DNS server written in pure Go.

---

## 1. Project Overview

### 1.1 Vision
NothingDNS is a modern, production-grade DNS server that combines authoritative and recursive DNS resolution in a single binary with zero external dependencies. It supports all modern DNS protocols (UDP/TCP, DoT, DoH, DoQ), provides enterprise-grade features like DNSSEC, GeoDNS, split-horizon, and ad-blocking, and can operate as a standalone instance or a Raft-based cluster for high availability.

### 1.2 Philosophy
- **Zero Dependencies** — Only Go standard library. No external modules. Ever.
- **Single Binary** — One binary to rule them all: DNS server, CLI tool, web dashboard, MCP server.
- **BIND Compatible** — Import existing BIND zone files seamlessly. Familiar zone file syntax.
- **LLM-Native** — Built-in MCP server for AI-powered DNS management.
- **Cloud-Native** — Single binary runs everywhere: bare metal, Docker, Kubernetes, edge.
- **Cluster-First** — Raft consensus for zone replication, leader election, and failover.

### 1.3 Project Identity
- **Name:** NothingDNS
- **Tagline:** "Nothing but DNS. Nothing else needed."
- **Binary:** `nothingdns` (server) + `dnsctl` (CLI management tool)
- **Default Ports:** 53 (UDP/TCP), 853 (DoT), 443 (DoH), 853/UDP (DoQ), 8080 (API/Dashboard), 9153 (Metrics), 4222 (Raft), 4223 (gRPC inter-node)
- **License:** Apache 2.0
- **Language:** Go 1.22+
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
│  │  Leader Election │ Zone Sync │ Config Repl.    │                  │
│  │  Log Replication │ Snapshot  │ Health Check     │                  │
│  └────────────────────────────────────────────────┘                  │
│                                                                      │
│  ┌──────────── Management Layer ─────────────────┐                  │
│  │  REST API │ gRPC │ MCP │ Web UI │ Prometheus   │                  │
│  └────────────────────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Module Structure

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
│   │   └── mcp/             # MCP Server (LLM-native management)
│   │       ├── server.go    # MCP protocol handler (JSON-RPC 2.0 over stdio/SSE)
│   │       ├── tools.go     # MCP tools (zone management, record ops, diagnostics)
│   │       ├── resources.go # MCP resources (zone data, config, metrics)
│   │       └── prompts.go   # MCP prompts (DNS troubleshooting, migration)
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
├── go.mod                   # Zero dependencies — only "module" line
├── go.sum                   # Empty
├── Makefile
├── Dockerfile
├── README.md
├── SPECIFICATION.md          # This file
├── IMPLEMENTATION.md         # Implementation guide
├── TASKS.md                  # Task breakdown
└── BRANDING.md               # Branding & marketing
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
  - name: "example.com"
    file: "/etc/nothingdns/zones/example.com.zone"
    type: primary          # primary | secondary
    dnssec: true
    notify:
      - 10.0.0.2
      - 10.0.0.3
    allow-transfer:
      - 10.0.0.0/24
    allow-update:
      - 10.0.0.1          # For dynamic DNS
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
resolver:
  mode: recursive          # recursive | forwarder | hybrid
  forwarders:
    - address: "1.1.1.1:53"
      protocol: udp
    - address: "https://dns.google/dns-query"
      protocol: doh
    - address: "9.9.9.9:853"
      protocol: dot
  forward-zones:
    - zone: "internal.corp"
      forwarders:
        - "10.0.0.1:53"
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
- Primary notifies secondaries on zone change
- Configurable notify targets per zone
- Retry with exponential backoff

### 7.4 TSIG Authentication (RFC 2845)
- HMAC-MD5, HMAC-SHA256, HMAC-SHA512
- Shared secret key management
- TSIG verification on incoming transfers
- TSIG signing on outgoing transfers

---

## 8. Dynamic DNS (RFC 2136)

### 8.1 UPDATE Message Processing
- Prerequisites: RRset exists, RRset does not exist, name exists, name does not exist
- Update section: Add RRset, Delete RRset, Delete name
- Atomic updates per zone
- SOA serial auto-increment on successful update
- TSIG authentication required by default

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
blocking:
  enabled: true
  lists:
    - path: "/etc/nothingdns/blocklists/default.txt"
      format: domains           # domains | hosts | adblock
    - url: "https://example.com/blocklist.txt"
      refresh: 24h
  response: nxdomain             # nxdomain | zero | custom
  custom-ip: "0.0.0.0"
  allowlist:
    - path: "/etc/nothingdns/allowlist.txt"
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
  database: "/etc/nothingdns/GeoLite2-Country.mmdb"
  zones:
    - name: "cdn.example.com"
      records:
        - region: "EU"
          type: A
          value: "185.0.0.1"
        - region: "US"
          type: A
          value: "203.0.113.1"
        - region: "default"
          type: A
          value: "198.51.100.1"
```

### 9.3 Split-Horizon DNS (Views)

- View-based query routing by source IP/subnet
- Each view has its own zone data
- ACL-based view matching
- Default view as fallback

```yaml
views:
  - name: "internal"
    match-clients:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
    zones:
      - name: "example.com"
        file: "/etc/nothingdns/zones/internal.example.com.zone"
  - name: "external"
    match-clients:
      - "any"
    zones:
      - name: "example.com"
        file: "/etc/nothingdns/zones/external.example.com.zone"
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
ratelimit:
  enabled: true
  responses-per-second: 10
  nxdomains-per-second: 5
  referrals-per-second: 10
  slip: 2                       # Every Nth dropped response, send TC instead
  window: 15                    # Seconds
  ipv4-prefix-length: 24
  ipv6-prefix-length: 56
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
- Transport: custom TCP-based RPC (binary protocol)

#### 10.1.2 State Machine
Raft FSM applies these operations:
- Zone create/update/delete
- Record add/update/delete
- Dynamic DNS updates
- Blocklist updates
- Configuration changes

#### 10.1.3 Cluster Topology
```
┌──────────┐       ┌──────────┐       ┌──────────┐
│  Node 1  │◄─────►│  Node 2  │◄─────►│  Node 3  │
│ (Leader)  │       │(Follower)│       │(Follower)│
│  :4222    │       │  :4222   │       │  :4222   │
└──────────┘       └──────────┘       └──────────┘
     │                   │                   │
     └───── Raft Consensus (zone sync) ─────┘
```

### 10.2 Configuration

```yaml
cluster:
  enabled: true
  node-id: "node-1"
  bind: "0.0.0.0:4222"
  peers:
    - id: "node-2"
      address: "10.0.0.2:4222"
    - id: "node-3"
      address: "10.0.0.3:4222"
  election-timeout: "1s"
  heartbeat-interval: "150ms"
  snapshot-interval: "5m"
  snapshot-threshold: 10000      # Log entries before snapshot
```

### 10.3 gRPC Inter-Node Communication

Hand-written gRPC-compatible binary protocol (no protobuf dependency):
- Zone synchronization
- Health checking
- Query forwarding (follower → leader for writes)
- Metrics aggregation

Port: 4223 (default)

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
dnsctl zone create example.com --file zone.txt
dnsctl zone delete example.com
dnsctl zone export example.com > example.com.zone
dnsctl zone import example.com < bind-zone.txt

# Record management
dnsctl record list example.com
dnsctl record add example.com A www 192.168.1.1 --ttl 3600
dnsctl record delete example.com www A

# Cache
dnsctl cache stats
dnsctl cache flush
dnsctl cache flush example.com

# Cluster
dnsctl cluster status
dnsctl cluster nodes
dnsctl cluster add-node node-4 10.0.0.4:4222
dnsctl cluster remove-node node-4

# Blocklist
dnsctl blocklist add ads.example.com
dnsctl blocklist remove ads.example.com
dnsctl blocklist reload
dnsctl blocklist stats

# DNSSEC
dnsctl dnssec status example.com
dnsctl dnssec sign example.com --algorithm ECDSAP256SHA256
dnsctl dnssec rollover example.com --type zsk
dnsctl dnssec ds example.com

# Diagnostics
dnsctl dig example.com A                    # Built-in dig-like tool
dnsctl dig @localhost example.com AAAA +dnssec
dnsctl health
dnsctl stats
dnsctl config show
dnsctl config set resolver.mode forwarder

# Server
dnsctl server start
dnsctl server stop
dnsctl server reload
dnsctl server status
```

### 11.3 MCP Server (LLM-Native)

Protocol: JSON-RPC 2.0 over stdio (for Claude Code) and SSE (for web clients)

#### MCP Tools
| Tool | Description |
|------|-------------|
| `dns_zone_list` | List all configured zones |
| `dns_zone_create` | Create a new zone |
| `dns_zone_delete` | Delete a zone |
| `dns_record_list` | List records in a zone |
| `dns_record_add` | Add a DNS record |
| `dns_record_update` | Update a DNS record |
| `dns_record_delete` | Delete a DNS record |
| `dns_query` | Execute a DNS query (dig-like) |
| `dns_cache_stats` | Get cache statistics |
| `dns_cache_flush` | Flush cache |
| `dns_cluster_status` | Get cluster status |
| `dns_blocklist_add` | Add domain to blocklist |
| `dns_blocklist_remove` | Remove domain from blocklist |
| `dns_stats` | Get server statistics |
| `dns_health` | Health check |
| `dns_config_get` | Get current configuration |
| `dns_config_set` | Update runtime configuration |

#### MCP Resources
| URI | Description |
|-----|-------------|
| `dns://zones` | All zones (live) |
| `dns://zones/{name}` | Zone detail with records |
| `dns://config` | Current configuration |
| `dns://stats` | Real-time statistics |
| `dns://cluster` | Cluster topology |
| `dns://blocklist` | Current blocklist |

#### MCP Prompts
| Prompt | Description |
|--------|-------------|
| `troubleshoot_dns` | Diagnose DNS resolution issues |
| `migrate_from_bind` | Help migrate from BIND to NothingDNS |
| `optimize_config` | Analyze and suggest config improvements |
| `setup_dnssec` | Guide through DNSSEC setup |

### 11.4 Web Dashboard

Embedded vanilla JS dashboard (no React/Vue/Angular — zero dependency philosophy extends to frontend).

#### Features
- **Overview** — queries/sec, cache hit ratio, uptime, active zones
- **Query Log** — real-time query stream via WebSocket
- **Zone Manager** — CRUD zones and records via REST API
- **Cache Viewer** — browse cache entries, flush
- **Blocklist Manager** — add/remove domains, import lists
- **Cluster Status** — node health, leader info, replication lag
- **Metrics Dashboard** — charts for QPS, latency, top domains
- **Config Editor** — edit runtime config with validation
- **DNSSEC Status** — key info, signing status, DS records

### 11.5 Prometheus Metrics

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

Hand-written YAML parser (subset of YAML 1.2 — maps, sequences, scalars, comments). No external YAML library.

### 12.2 Example Configuration

```yaml
# /etc/nothingdns/nothingdns.yaml

server:
  hostname: "ns1.example.com"
  listen:
    udp: "0.0.0.0:53"
    tcp: "0.0.0.0:53"
    dot: "0.0.0.0:853"
    doh: "0.0.0.0:443"
    doq: "0.0.0.0:853"           # UDP port for QUIC
  workers: 0                       # 0 = auto (runtime.NumCPU)
  max-udp-size: 4096
  tcp-idle-timeout: "30s"

tls:
  cert: "/etc/nothingdns/tls/cert.pem"
  key: "/etc/nothingdns/tls/key.pem"
  acme:
    enabled: true
    email: "admin@example.com"
    domains:
      - "dns.example.com"

resolver:
  mode: hybrid                     # recursive | forwarder | hybrid
  forwarders:
    - address: "1.1.1.1:53"
      protocol: udp
    - address: "https://dns.google/dns-query"
      protocol: doh
  qname-minimization: true
  zero-twenty-encoding: true       # 0x20 mixed-case defense

cache:
  max-size: 100000
  min-ttl: 30
  max-ttl: 86400
  negative-ttl: 3600
  serve-stale: true
  serve-stale-ttl: 86400
  prefetch: true
  prefetch-threshold: 10           # Percentage of TTL remaining

zones:
  - name: "example.com"
    file: "/etc/nothingdns/zones/example.com.zone"
    type: primary
    dnssec:
      enabled: true
      algorithm: ECDSAP256SHA256
      nsec3: true
    notify:
      - "10.0.0.2"
    allow-transfer:
      - "10.0.0.0/24"
    allow-update:
      - "10.0.0.1"

blocking:
  enabled: true
  lists:
    - path: "/etc/nothingdns/blocklists/default.txt"
      format: domains
  response: nxdomain
  allowlist:
    - path: "/etc/nothingdns/allowlist.txt"

geodns:
  enabled: false
  database: "/etc/nothingdns/GeoLite2-Country.mmdb"

views:
  - name: "internal"
    match-clients:
      - "10.0.0.0/8"
      - "192.168.0.0/16"
    zones:
      - name: "example.com"
        file: "/etc/nothingdns/zones/internal.example.com.zone"

ratelimit:
  enabled: true
  responses-per-second: 10
  nxdomains-per-second: 5
  slip: 2
  window: 15

acl:
  default: allow
  rules:
    - action: deny
      source: "0.0.0.0/0"
      zones:
        - "internal.corp"
    - action: allow
      source: "10.0.0.0/8"
      zones:
        - "internal.corp"

cluster:
  enabled: false
  node-id: "node-1"
  bind: "0.0.0.0:4222"
  grpc: "0.0.0.0:4223"
  peers:
    - id: "node-2"
      address: "10.0.0.2:4222"
    - id: "node-3"
      address: "10.0.0.3:4222"
  election-timeout: "1s"
  heartbeat-interval: "150ms"
  snapshot-interval: "5m"
  snapshot-threshold: 10000

api:
  enabled: true
  listen: "0.0.0.0:8080"
  auth:
    type: bearer                   # bearer | basic | none
    token: "${NOTHINGDNS_API_TOKEN}"

dashboard:
  enabled: true
  listen: "0.0.0.0:8080"          # Shared with API
  path: "/dashboard"

metrics:
  enabled: true
  listen: "0.0.0.0:9153"
  path: "/metrics"

mcp:
  enabled: true
  mode: stdio                      # stdio | sse
  sse-listen: "0.0.0.0:8081"

logging:
  level: info                      # debug | info | warn | error
  format: json                     # json | text
  output: stdout                   # stdout | file
  file: "/var/log/nothingdns/server.log"
  query-log: true
  query-log-file: "/var/log/nothingdns/queries.log"
```

### 12.3 Environment Variable Override
All config values can be overridden via environment variables:
`NOTHINGDNS_SERVER_LISTEN_UDP=0.0.0.0:53`

### 12.4 Hot Reload
- SIGHUP triggers config reload
- Zone files reloaded without restart
- Blocklists refreshed
- TLS certificates reloaded
- ACL rules updated
- No query interruption during reload

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
- TSIG for zone transfers
- API authentication (bearer token / basic auth)
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
ExecStart=/usr/local/bin/nothingdns --config /etc/nothingdns/nothingdns.yaml
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
| Dependencies | Zero | Many | Many (plugins) | Many | Several |
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
| MCP Server | ✅ | ❌ | ❌ | ❌ | ❌ |
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
- mDNS / DNS-SD (multicast DNS for local networks)
- Full QUIC implementation beyond DNS-focused subset
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
