# NothingDNS — Specification Document

> **Nothing but DNS. Nothing else needed.**
> Minimal-dependency, single-binary, full-featured DNS server written in Go.

---

## 1. Project Overview

### 1.1 Vision
NothingDNS is a modern, production-grade DNS server that combines authoritative and recursive DNS resolution in a single binary with a minimal external dependency set. It supports modern DNS protocols (UDP/TCP, DoT, DoH, DoQ), provides enterprise-grade features like DNSSEC, GeoDNS, split-horizon, and ad-blocking, and can operate as a standalone instance or a Raft-based cluster for high availability.

### 1.2 Philosophy
- **Minimal Dependencies** — Core DNS logic is hand-rolled; external Go deps are limited to necessary transport/platform support.
- **Single Server Binary** — `nothingdns` is the DNS server, REST API and embedded web dashboard in one static binary; `dnsctl` is the separate CLI.
- **BIND Compatible** — Import existing BIND zone files seamlessly. Familiar zone file syntax.
- **Cloud-Native** — Single binary runs everywhere: bare metal, Docker, Kubernetes, edge.
- **Cluster-First** — Raft consensus for zone replication, leader election, and failover.

### 1.3 Project Identity
- **Name:** NothingDNS
- **Tagline:** "Nothing but DNS. Nothing else needed."
- **Binary:** `nothingdns` (server) + `dnsctl` (CLI management tool)
- **Default Ports:** 53 (UDP/TCP), 853 (DoT/DoQ when enabled), 8080 (API/Dashboard/DoH when configured), 9153 (Metrics), 7946 (cluster gossip/Raft RPC)
- **License:** MIT
- **Language:** Go (`go.mod`: go 1.26.9, built with toolchain 1.27.2)
- **Repository:** github.com/nothingdns/nothingdns

---

## 2. Core Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          NothingDNS                                  │
│                                                                      │
│  ┌──────────────────── Protocol Layer ────────────────────────┐     │
│  │  UDP/TCP :53  │  DoT :853  │  DoH (API port) │ DoQ :853/UDP│     │
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

The source tree is flat under `internal/`; there is no `internal/api/rest/` or
`internal/api/grpc/`, no `internal/auth/` authoritative engine, no
`internal/dynamic/`, and no gRPC anywhere (nodes talk Raft RPC and gossip, see
§10.3). Dynamic DNS lives in `internal/transfer/`, the authoritative engine in
`cmd/nothingdns` on top of `internal/zone/`. This is the layout in the tree:

```
nothingdns/
├── cmd/
│   ├── nothingdns/      # Server: main.go wiring, request pipeline (pipeline*.go),
│   │                    #   authoritative.go, handler.go, managers (cache_manager,
│   │                    #   upstream_manager, zone_manager, security_manager,
│   │                    #   dnssec_manager, cluster_manager, transfer_manager), reload.go
│   └── dnsctl/          # CLI management tool (§11.2)
├── internal/            # one package per concern, listed below
├── web/                 # React dashboard sources, built into internal/dashboard/static/dist
├── config.example.yaml  # Example configuration
├── deploy/, docs/, scripts/
└── Dockerfile, go.mod, go.sum
```

| Package | Role |
|---|---|
| `protocol` | DNS wire protocol: message, header, question, records, EDNS0/OPT, label compression, RDATA types and their text form |
| `server` | UDP, TCP and DoT listeners, certificate reloading, the handler interface |
| `quic` | DNS over QUIC (DoQ) on `quic-go` |
| `doh` | DNS over HTTPS (wire and JSON) and DNS over WebSocket handlers |
| `odoh` | Oblivious DoH (RFC 9230) with RFC 9180 HPKE |
| `dso` | DNS Stateful Operations (RFC 8490) |
| `dnscookie` | DNS Cookies (RFC 7873) |
| `zone` | Zone-file parser, zone manager, radix tree, WAL journal, KV persistence, ZONEMD, zone writer |
| `resolver` | Iterative resolver: root hints, QNAME minimisation, 0x20, CNAME/DNAME chasing |
| `upstream` | Forwarding client, load balancer, anycast groups, health checks, TCP connection pool |
| `cache` | Response cache (LRU, TTL, negative, stale) and aggressive NSEC caching |
| `dnssec` | Validator, signer, trust anchors, key store and rollover scheduler (the last two are not wired into the server, §6.1.2) |
| `transfer` | AXFR/IXFR, NOTIFY, TSIG, Dynamic DNS (RFC 2136), XoT, secondary-zone management |
| `filter` | ACL, recursion policy, rate limiter, RRL, split-horizon views |
| `blocklist` | Domain blocklists (hosts and domain-per-line files, URLs) |
| `rpz` | Response Policy Zones |
| `geodns` | GeoIP (MMDB) based answers |
| `dns64` | DNS64 synthesis (RFC 6147) |
| `idna` | IDNA / Punycode validation (RFC 5891 to 5893) |
| `cluster` | Gossip membership, Raft consensus (`cluster/raft`), zone batches |
| `storage` | Embedded key-value store and write-ahead log |
| `config` | Hand-written YAML parser, config structs, validation, runtime overrides |
| `api` | REST API server, OpenAPI document, dashboard stats |
| `auth` | Users, roles and session tokens for the API |
| `audit` | Structured query and operation audit log |
| `dashboard`, `websocket` | Embedded SPA and the live query WebSocket |
| `metrics`, `otel` | Prometheus exporter; OpenTelemetry tracing facade |
| `memory` | Memory monitor and cache eviction under pressure |
| `mdns` | mDNS / DNS-SD responder |
| `util` | Logger, buffer pools, IP helpers, shared small utilities |
| `catalog`, `load`, `e2e` | Catalog zones (RFC 9432) and a load-test tool, neither used by the server; end-to-end tests |

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

The table lists the common types. The server also handles AFSDB, APL, CDS,
CDNSKEY, CERT, DHCID, DNAME, HINFO, HIP, HTTPS, IPSECKEY, KEY, KX, LOC,
OPENPGPKEY, RP, SIG, SPF, SVCB, TA, URI and ZONEMD, and any other type in the
RFC 3597 generic form (`TYPE<n>`, `\# <length> <hex>`).

#### 3.1.4 Label Compression
DNS label compression (RFC 1035 §4.1.4) using pointer offsets (0xC0 prefix). Both compression and decompression must be implemented for wire format efficiency.

#### 3.1.5 EDNS(0) Support (RFC 6891)
- Extended RCODE & flags
- UDP payload size advertisement (up to 4096 bytes)
- EDNS Client Subnet option (RFC 7871): parsed into the client info only, never
  acted on (§9.4)
- DNSSEC OK (DO) bit
- Padding option (RFC 7830) on DoH responses; DoT does not pad

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
- Read and write timeout: 30 seconds each (fixed)
- Implementation: `net.Listen("tcp", ":53")`

#### 3.2.3 DNS over TLS — DoT (RFC 7858)
- Port 853 (default)
- TLS 1.3 only (the listener sets it as the minimum)
- Same wire format as TCP (2-byte length prefix)
- Certificate and key files (`server.tls`), re-read on SIGHUP; there is no built-in ACME/Let's Encrypt client
- ALPN: not required for DoT
- Implementation: `tls.Listen("tcp", ":853", tlsConfig)`

#### 3.2.4 DNS over HTTPS — DoH (RFC 8484)
- Served on the API HTTP listener (`server.http.bind`, default `:8080`) when
  `server.http.doh_enabled` is set; with TLS on that listener it speaks HTTP/2
  or HTTP/1.1 like any `net/http` server
- Content-Type: `application/dns-message` (wire format)
- Also support: `application/dns-json` (JSON API like Google/Cloudflare)
- Methods: GET (base64url query param) and POST (binary body)
- Path: `/dns-query` (configurable)
- Implementation: `net/http`

#### 3.2.5 DNS over QUIC — DoQ (RFC 9250)
- Port 853/UDP (default)
- QUIC transport by `github.com/quic-go/quic-go` (the one transport dependency,
  see the dependency policy); TLS 1.3 is part of QUIC
- One DNS message per QUIC stream
- ALPN: `doq`
- Per-address connection limits count an IPv6 client by its /64

---

## 4. Authoritative Engine

### 4.1 Zone Management

#### 4.1.1 Zone Store
- In-memory radix tree (trie) indexed by domain name labels (reversed)
- Thread-safe via `sync.RWMutex` per zone
- Supports multiple zones with overlapping namespaces
- DNSSEC signing is done online when a zone is answered (§6.1); the store holds the unsigned zone data

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
- Class IN. There is no CHAOS responder (`version.bind` and the like are not answered)

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
- Forwarding over UDP, retried over TCP when a response is truncated (no DoT or DoH upstreams)
- Upstream health checking with failover; strategies `random` (default), `round_robin`, `fastest`
- Optional anycast groups (`upstream.anycast_groups`); standalone servers listed beside them are the fallback when no anycast backend is healthy
- One upstream set for all names: there are no per-zone forwarding rules

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
- Maximum cache size (`cache.size`, default 10,000 entries)
- Cache key: (QNAME lower-cased, QTYPE, DO-bit); the class is always IN
- Honors TTL from responses
- Minimum TTL override (`cache.min_ttl`, default 5s)
- Maximum TTL cap (`cache.max_ttl`, default 86400s / 24h)
- Serve-stale (RFC 8767) — serve expired entries while refreshing

#### 5.2.2 Negative Cache (RFC 2308)
- Cache NXDOMAIN responses
- Cache NODATA (empty answer) responses
- Negative TTL from the SOA (RFC 2308), capped by `cache.negative_ttl` (default 60s)

#### 5.2.3 Prefetching
- Settings: `cache.prefetch` (off by default) and `cache.prefetch_threshold`
  (seconds before expiry, default 60). The cache has the hook that fires a
  refresh when an entry crosses the threshold, but the committed server never
  installs the refresh callback, so these settings currently have no effect.

### 5.3 Security

#### 5.3.1 Resolver Hardening
- Source port randomization (a fresh UDP socket per query)
- Transaction ID randomization
- 0x20 encoding (random case in QNAME, `resolution.use_0x20`, off by default)
- Bailiwick checking (ignore out-of-zone glue)
- Maximum delegation depth: `resolution.max_depth` (default 10)
- Query timeout: `resolution.timeout` (default 5 seconds per query)

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
- Automatic key rollover (prepublish method): **not implemented in the server.**
  The server signs with the keys listed in `dnssec.signing.keys` and never
  replaces them; rolling a key is a manual change of that list and a restart
  (zone signers are built at start, §12.4), with the parent DS updated by hand.
  `internal/dnssec/rollover.go` holds an RFC 7583 scheduler with tests, but
  nothing starts it, and it could not be started safely yet: key state and
  timing are not persisted (a restart would return Published and Retired keys
  as Active), and the signer has no path that publishes the new DNSKEY or
  hands the parent a DS. Persisting that state comes first.
- Key generation: RSA-2048/4096, ECDSA P-256/P-384, Ed25519
- DS record generation for parent zone
- Key storage: private key files named in `dnssec.signing.keys`. The embedded
  KV `KeyStore` in `internal/dnssec` is not wired into the server.

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
- Trust anchors: the built-in IANA root KSKs (KSK-2024 and KSK-2017) plus an
  optional file (`dnssec.trust_anchor`, RFC 7958 XML). There is no RFC 5011
  automated update: a root key roll needs a new release or a new anchor file.
- DNSSEC-aware cache (separate DNSSEC and non-DNSSEC entries)
- AD (Authentic Data) bit setting in responses
- CD (Checking Disabled) bit honoring
- Bogus response handling (SERVFAIL with extended error)
- No negative trust anchors (RFC 7646)

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
- Malformed messages are FORMERR (RFC 2136 §3.2.3, §3.4.1.2): a prerequisite or
  update RR whose class is not IN, ANY or NONE; an ANY or NONE RR with a
  non-zero TTL; an ANY RR, or any ANY/NONE prerequisite, with RDATA; a
  prerequisite with a non-zero TTL; an update RR of type IXFR, AXFR, MAILB or
  MAILA, or of type ANY unless its class is ANY
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
- Journal of the changes made by dynamic updates and other zone edits
- Used for IXFR generation; a request the journal cannot cover is answered with
  a full (AXFR-style) transfer
- Kept to the most recent entries per zone (default 100); older ones are
  trimmed, not merged into the zone file
- Reloaded on startup

---

## 9. Advanced Features

### 9.1 Blocklist / Allowlist (Ad-Blocking)

#### 9.1.1 Blocklist
- Sources: local files and HTTPS URLs, in hosts-file format (`0.0.0.0 ads.example.com`)
  or one domain per line; `#` comments
- URL sources must be `https://` with an IP-literal host that is not private,
  loopback or link-local (redirects are checked the same way); response bodies
  and entry counts are capped
- A listed name blocks itself and its subdomains
- A blocked query is answered NXDOMAIN with the Extended DNS Error "Filtered";
  there are no other block responses (no `0.0.0.0` or custom-IP answers, no regex
  or wildcard syntax; subdomain matching covers the wildcard case)
- Managed at runtime through the API and dashboard: add or remove file and URL
  sources, enable or disable one source, switch blocking on or off, reload

#### 9.1.2 Allowlist and overrides
There is no allowlist. A per-name exception or a custom answer is an RPZ rule
(§9.1.3): `PASSTHRU` lets a name through, and `A`/`AAAA`/`CNAME` actions
rewrite it.

#### 9.1.3 Response Policy Zones
RPZ files (`rpz.files`) carry QNAME, client-IP, response-IP, NSDNAME and NSIP
triggers with NXDOMAIN, NODATA, CNAME, address override, DROP, PASSTHRU and
TCP-only actions; rules can also be added and removed through the API.

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
- Configurable database path; the database is re-read when the configuration is
  reloaded (SIGHUP), not on file change

#### 9.2.2 Geo-Based Responses
- Per-domain, per-type geo routing rules
- Fallback chain: ASN → country → continent → default (there is no city level)
- The decision uses the address the query arrived from; EDNS Client Subnet is
  not consulted (§9.4)

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
Not implemented. The OPT option is parsed into the client information and
nothing reads it: it is not used for GeoDNS or cache keys, not forwarded to
upstreams, not echoed in responses, and there is no ECS configuration. Doing it
properly needs a trust policy, a scope-aware cache key and the RFC 7871 §7.2.1
response echo, so a partial "use ECS for Geo" would itself be non-conformant.

### 9.5 Response Rate Limiting — RRL (BIND-style, no RFC)
- Per-client limiting (an IPv4 address, or an IPv6 /64)
- Buckets per client, query type and response code
- Token bucket algorithm; a client that exceeds it is suppressed for a window
  and answered REFUSED. There is no slip (probabilistic truncation) setting.
- Settings: `rrl.rate`, `rrl.burst`, `rrl.max_buckets`

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
- **Membership** — static: the peer list is `cluster.peers`, and changing it
  means editing the config and doing a rolling restart. The joint-consensus
  code exists but is not safe to run, so runtime add/remove fails closed
  (`dnsctl cluster join` answers an error in Raft mode).
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

In Raft mode the SOA serial is bumped the same way on every replica: a single
record command adds one (RFC 1982), and a batch takes the date prefix the
proposer wrote into the entry, so replicas that apply the same log hold the same
serial. Standalone and SWIM servers use the date-style `YYYYMMDDNN` serial.

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
| Deterministic SOA serials for Raft-applied single-record changes (`add_record`, `update_record`, `del_record` bump the serial by plain RFC 1982 increment, not the date-style `YYYYMMDDNN`) | an older node bumps from its own clock, so its serial for the same log entries differs from upgraded nodes (same data, different serial) until the zone is next replaced by a snapshot | upgrade all nodes before relying on equal serials across replicas (for example as AXFR/IXFR sources behind a shared name); serials of Raft-mode zones are no longer date-shaped |
| RFC 8945 TSIG chain on multi-message AXFR/IXFR | pre-fix servers sent an unbound chain that new clients reject (keyed AXFR between NothingDNS nodes never worked before the fix) | upgrade primaries and secondaries together for keyed transfers; single-message TSIG is unchanged; third-party interop of the multi-message chain is not yet proven |

---

## 11. Management Interfaces

### 11.1 REST API

Base path: `/api/v1` (dashboard data under `/api/dashboard`)
Authentication: `Authorization: Bearer <token>`: a session token from
`POST /api/v1/auth/login`, or the shared `server.http.auth_token`. The session
cookie is also accepted for `GET`, `HEAD` and `OPTIONS`. Roles are
`viewer < operator < admin`.

The authoritative route list, with roles, request and response bodies, is
[API_REFERENCE.md](API_REFERENCE.md) §2 onward; the table below is a summary of
the routes the server registers (`internal/api/server.go`). A path in `{}` is a
URL segment; records and blocklist sources are addressed by the JSON body or
query parameter shown, not by an id in the path. Paths starting with `/api/`,
`/health`, `/livez`, `/readyz` and `/ws` are absolute; the others are relative to
`/api/v1`.

#### Endpoints

**Health and status**
| Method | Path | Description |
|--------|------|-------------|
| GET | /health, /livez | Liveness (public) |
| GET | /readyz | Readiness: 503 when no upstream is healthy (public) |
| GET | /api/v1/status | Server status |
| GET | /api/v1/server/config | Server configuration summary |

**Authentication**
| Method | Path | Description |
|--------|------|-------------|
| POST | /api/v1/auth/login | Log in, returns a token |
| POST | /api/v1/auth/bootstrap | First admin or password reset (localhost only) |
| GET | /api/v1/auth/session | Restore the dashboard session from the cookie |
| POST | /api/v1/auth/logout | Revoke the current token |
| GET | /api/v1/auth/roles | List roles |
| GET, POST, DELETE | /api/v1/auth/users | List, create, delete users (`DELETE /auth/users/{username}` also works) |

**Zones and records**
| Method | Path | Description |
|--------|------|-------------|
| GET, POST | /zones | List zones, create a zone |
| GET, DELETE | /zones/{name} | Zone details, delete a zone |
| POST | /zones/reload?zone= | Reload a zone from its file |
| GET | /zones/transfers | Secondary-zone transfer state |
| GET, POST, PUT, DELETE | /zones/{name}/records | List, add, update, delete records (JSON body names the record) |
| GET | /zones/{name}/export | Export a BIND zone file |
| POST | /zones/{name}/ptr-bulk | Bulk PTR (and A) creation from a CIDR |
| GET | /zones/{name}/ptr6-lookup?ip= | IPv6 reverse lookup in an ip6.arpa zone |

**Cluster**
| Method | Path | Description |
|--------|------|-------------|
| GET | /cluster/status | Cluster status |
| GET | /cluster/nodes | List nodes |
| POST | /cluster/join | Join a cluster |
| DELETE | /cluster/leave | Leave the cluster |

**Blocklists**
| Method | Path | Description |
|--------|------|-------------|
| GET, POST | /blocklists | Statistics, add a file or URL source |
| GET | /blocklists/sources | List sources |
| POST | /blocklists/toggle | Enable or disable blocking |
| POST | /blocklists/{source}/toggle | Enable or disable one source |
| DELETE | /blocklists/{source} | Remove a source |

**RPZ**
| Method | Path | Description |
|--------|------|-------------|
| GET | /rpz | RPZ statistics |
| GET, POST, DELETE | /rpz/rules | List, add, delete rules (`DELETE ?pattern=[&trigger=]`) |
| POST | /rpz/toggle | Enable or disable RPZ |

**Access control, upstreams, GeoDNS**
| Method | Path | Description |
|--------|------|-------------|
| GET, PUT | /acl | ACL rules |
| GET, PUT | /acl/recursion | Recursion allow list |
| GET, PUT | /upstreams | Upstream servers |
| GET | /geoip/stats | GeoDNS statistics |

**Cache**
| Method | Path | Description |
|--------|------|-------------|
| GET | /cache/stats | Cache statistics |
| POST | /cache/flush | Flush the cache |

**Config**
| Method | Path | Description |
|--------|------|-------------|
| GET | /config | Current config (secrets redacted) |
| POST | /config/reload | Reload the config file (same as SIGHUP) |
| PUT | /config/{logging,rrl,cache,resolution,dns64,cookie} | Change a runtime tunable (persisted in `runtime_overrides.json`) |

**DNSSEC**
| Method | Path | Description |
|--------|------|-------------|
| GET | /dnssec/status | Validation and signing status |
| GET | /dnssec/keys | Signing keys (admin) |

There is no zone-signing or key-rollover endpoint (see §6.1.2).

**Statistics and query log**
| Method | Path | Description |
|--------|------|-------------|
| GET | /api/dashboard/stats, /api/dashboard/queries, /api/dashboard/zones | Dashboard data |
| GET | /queries | Query log |
| GET | /topdomains | Top queried domains |
| GET | /metrics/history | Metrics history |
| GET | /ws | WebSocket query stream |

**OpenAPI**
| Method | Path | Description |
|--------|------|-------------|
| GET | /api/openapi.json | OpenAPI 3.0 spec |
| GET | /api/docs | API explorer |

### 11.2 CLI Tool (dnsctl)

`dnsctl` talks to the REST API (§11.1). Global options go before the command:
`-server URL` (default `http://localhost:8080`, or `NOTHINGDNS_SERVER`) and
`-api-key KEY` (or `NOTHINGDNS_API_KEY`). `dnsctl help [command]` and
`dnsctl version` are built in. The commands below are the ones in `cmd/dnsctl`.

```bash
# Zone management
dnsctl zone list
dnsctl zone add example.com [ns1.example.com.]   # nameserver defaults to ns1.<zone>.
dnsctl zone remove example.com
dnsctl zone reload example.com
dnsctl zone export example.com > example.com.zone

# Record management (ttl is optional: 300 on add, unchanged on update)
dnsctl record list example.com
dnsctl record add example.com www A 192.168.1.1 [3600]
dnsctl record update example.com www A 192.168.1.1 192.168.1.2 [3600]
dnsctl record remove example.com www A           # removes the whole RRset

# Cache
dnsctl cache stats
dnsctl cache flush
dnsctl cache flush example.com

# Cluster
dnsctl cluster status
dnsctl cluster peers
dnsctl cluster join 10.0.0.4:7946
dnsctl cluster leave                              # removes the local node

# Blocklist
dnsctl blocklist status
dnsctl blocklist sources
dnsctl blocklist reload                           # reloads the whole config, like `config reload`

# DNSSEC
dnsctl dnssec status
dnsctl dnssec keys
dnsctl dnssec generate-key --algorithm 13 --type KSK --zone example.com
dnsctl dnssec ds-from-dnskey --zone example.com --keyfile Kexample.com.+013+12345.key
dnsctl dnssec sign-zone --zone example.com --input example.com.zone   # offline signing of a zone file
dnsctl dnssec verify-anchor <trust-anchor-file>
dnsctl dnssec validate-zone --zone example.com.zone.signed [--ignore-time]

# Diagnostics
dnsctl dig example.com A                          # Built-in dig-like tool
dnsctl dig @localhost example.com AAAA +dnssec    # UDP only; options: +dnssec, +cd (others are rejected)

# Server and config
dnsctl server status
dnsctl server health
dnsctl server bootstrap --username admin          # first dashboard admin; run on the server host
dnsctl config get
dnsctl config reload
```

`dnsctl dnssec sign-zone` reads its input with the server's zone-file parser, so
a standard BIND file (`$ORIGIN`, `$TTL`, `$INCLUDE`, `$GENERATE`, multi-line
records, omitted TTL or class, inherited owners) is signed as the server would
load it. A file with no `$ORIGIN` takes `--zone` as its origin. A line the parser
cannot read, a class other than IN, or RDATA that does not parse is an error
naming the line (`line N: ...`), and no output file is written.

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

Endpoint: `metrics.path` (default `/metrics`) on `metrics.bind` (default
`:9153`), Prometheus text exposition format (`text/plain; version=0.0.4`). It
is off unless `metrics.enabled` is true. The same listener serves `/health`
(`{"status":"healthy","uptime":"…"}`).

The endpoint fails closed: with `metrics.auth_token` set, scrapers send
`Authorization: Bearer <token>` and any bind address is allowed; without a token
it may bind only to loopback, and the server refuses to start (and
`-validate-config` reports an error) on any other address. Bind and token
changes need a restart (§12.4).

The metrics below are all that the exporter writes (`internal/metrics`). Counters
reset when the process restarts.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `nothingdns_server_uptime_seconds` | gauge | | Seconds since start |
| `nothingdns_queries_total` | counter | `type` | Queries received, by query type. A type the server does not know is labelled `OTHER`, which bounds cardinality. |
| `nothingdns_responses_total` | counter | `rcode` | Responses sent, by numeric RCODE (`0` NOERROR, `2` SERVFAIL, `3` NXDOMAIN, …) |
| `nothingdns_cache_hits_total` | counter | | Cache hits |
| `nothingdns_cache_misses_total` | counter | | Cache misses |
| `nothingdns_blocklist_blocks_total` | counter | | Queries refused by the blocklist or an RPZ rule |
| `nothingdns_rate_limited_total` | counter | | Queries dropped by rate limiting |
| `nothingdns_upstream_queries_total` | counter | `server` | Queries sent to each upstream (no sample until one is sent) |
| `nothingdns_query_duration_seconds` | histogram | `type` | Query processing time, buckets 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0 s and `+Inf`, plus `_sum` and `_count` |
| `nothingdns_cluster_nodes_total` | gauge | | Known cluster nodes (a gauge, despite the `_total` name) |
| `nothingdns_cluster_nodes_alive` | gauge | | Nodes currently alive |
| `nothingdns_cluster_healthy` | gauge | | `1` when the cluster is healthy, else `0` |
| `nothingdns_cluster_gossip_messages_sent_total` | counter | | Gossip messages sent |
| `nothingdns_cluster_gossip_messages_received_total` | counter | | Gossip messages received |
| `nothingdns_udp_packets_received_total` | counter | | UDP datagrams received |
| `nothingdns_udp_packets_sent_total` | counter | | UDP datagrams sent |
| `nothingdns_udp_errors_total` | counter | | UDP errors |
| `nothingdns_tcp_connections_accepted_total` | counter | | TCP connections accepted |
| `nothingdns_tcp_connections_closed_total` | counter | | TCP connections closed |
| `nothingdns_tcp_messages_received_total` | counter | | TCP messages received |
| `nothingdns_tcp_errors_total` | counter | | TCP errors |

The cluster metrics are present, at zero, when clustering is off. The transport
counters are copied from the UDP and TCP servers periodically. The exporter has
no per-protocol or per-view labels and does not export cache size, zone,
Raft, per-upstream latency or DNSSEC validation metrics; those are visible
through the REST API (`/api/v1/cache/stats`, `/api/v1/zones`,
`/api/v1/cluster/status`, `/api/v1/dnssec/status`) and the dashboard.

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
  size: 100000                     # default 10000
  min_ttl: 30                      # default 5 (seconds)
  max_ttl: 86400
  negative_ttl: 300                # default 60 (cap, seconds)
  serve_stale: true

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
- `internal/storage` has an append-only WAL: CRC32-checked entries in
  `wal-*.log` segments (up to 64 MiB each), synced every 100 ms
- Zones also keep their own journal for incremental transfers (§8.2)

### 13.2 Embedded Key-Value Store
- A bucketed key-value store held in memory and saved to a single file,
  `<storage.data_dir>/data.db`, in a TLV format protected by an HMAC (an
  AES-256-GCM variant is used when an encryption key is set); it is not a B+tree
- Transactions (`Begin`/`Update`/`View`) with one writer and concurrent readers
- Used for: zones created through the API (`KVPersistence`) and their records
- DNSSEC keys are not stored in it: the server signs with the private key files
  named in `dnssec.signing.keys` (§6.1.2)

### 13.3 Data Directory Layout
What the server writes under `storage.data_dir` and the other configured
directories:
```
<storage.data_dir>/
├── data.db              # key-value store (API-created zones)
├── users.json           # dashboard users (server.http.users_file)
├── access_policy.json   # ACL and recursion allow list edited through the API
└── runtime_overrides.json  # settings changed through PUT /api/v1/config/*
<zone_dir>/*.zone        # zone files written for zones created through the API
<transfer.journal_dir>/  # IXFR journals; slave-zones/*.zone holds secondary zones
<cluster.data_dir>/      # Raft log, hard state and snapshots (Raft mode)
```

---

## 14. Performance Targets

These are design goals, not guarantees. The Status column records what has
been measured on the development machine (12-core Linux, loopback, load
generator on the same host, release flags `-trimpath -ldflags "-s -w"`). Where
nothing was measured the table says so. [PERFORMANCE.md](PERFORMANCE.md) holds
the operational thresholds and tuning notes; its QPS figure (50,000+) is a
monitoring threshold, lower than the goals here.

| Metric | Target | Status |
|--------|--------|--------|
| Queries/sec (UDP, cached) | >500,000 | Not measured end to end. The cache lookup alone costs about 150 ns (single thread) and 96 ns (parallel), `go test ./internal/cache -bench Get` |
| Queries/sec (UDP, authoritative) | >200,000 | **Not met**, and not testable on one host. With the local flood (`go test -tags perf -run TestLocalUDPFlood ./internal/load/`, per-IP UDP cap disabled via `server.udp_rate_per_ip: 0`) the default single UDP socket gives about 89,000 to 92,000; `server.udp_listeners: 4` gives about 131,000 to 138,000, and 8 adds nothing. The load generator shares the 12 cores: a trivial one-thread Go UDP echo server (no DNS) reached only about 170,000 with the same client. With the default cap of 100 per client IP, one source gets about 100 |
| Queries/sec (DoH) | >100,000 | Not measured |
| Average latency (cached) | <1ms | Not measured |
| Average latency (authoritative) | <5ms | Not measured |
| Memory usage (100K cache + 10 zones) | <256MB | Not measured; idle with one small zone: about 20 MB RSS. A 1M-record zone takes about 240 MB of heap once parsed |
| Binary size | <30MB | Met: `nothingdns` 21.6 MB, `dnsctl` 7.8 MB (29.4 MB together) |
| Startup time (cold) | <2 seconds | Met: about 0.15 s to a healthy `/health` with a small config |
| Zone load (1M records) | <5 seconds | Met for parsing: 1.7 s for 1,000,000 A records (`zone.ParseFile`); validation and indexing were not timed |
| Cluster failover time | <3 seconds | Not measured |

### 14.1 Performance Design Decisions
- Pooled buffers on the hot path: `sync.Pool` for UDP request and response
  buffers and for DNS messages
- A sharded response cache: each shard has its own `RWMutex`, reads take the read
  lock, and LRU promotion is probabilistic so most hits never take the write lock
- UDP: one socket per bind address (created with `SO_REUSEPORT` where the
  platform has it), a reader goroutine and a worker pool of `NumCPU × 4` per
  socket; no `recvmmsg` batching
- Raising `server.udp_listeners` (extra `SO_REUSEPORT` sockets per address,
  default 1) is the measured way to scale UDP reads on a multi-core Linux host:
  about +50% in the local flood at 4 listeners, nothing further beyond that.
  A CPU profile of the single-listener case (taken before the dashboard JSON fix, which was about 7% of it) showed the server about 15%
  idle-scheduling and 27% in `sendmsg`/`recvmsg` syscalls, using about 2.9 of 12
  cores; the DNS logic is not the bottleneck
- TCP and DoT: a goroutine per connection, with per-IP connection caps
- Connection pooling for upstream TCP
- EDNS buffer size negotiation to minimise TCP fallback

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
- API authentication (bearer token; session or shared token, §11.1); users
  defined in the config file cannot be deleted or changed through the API (409)
- TLS: DoT, DoQ and XoT require TLS 1.3; DoH and the API share one HTTP
  listener that uses Go's default minimum (TLS 1.2)
- DNSSEC validation for resolver mode

### 15.2 Operational Security
- Run as a non-root user and give the binary the capability to bind port 53
  (the systemd unit and the container image do this); the server does not drop
  privileges after binding and has no chroot support
- No shell execution
- Zone `$INCLUDE` files must live next to the including file (no absolute paths,
  `..` or symlinks)
- Placeholder secrets are rejected by config validation
- Secrets can come from environment variables (`${VAR}` in the config)

---

## 16. Deployment

### 16.1 Single Binary
Release binaries for linux, darwin and windows (amd64 and arm64) come from
`scripts/build-release.sh` (§17), named `nothingdns-<os>-<arch>` and
`dnsctl-<os>-<arch>` with a `SHA256SUMS` file:
```bash
curl -fsSLO https://github.com/nothingdns/nothingdns/releases/latest/download/nothingdns-linux-amd64
curl -fsSLO https://github.com/nothingdns/nothingdns/releases/latest/download/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
chmod +x nothingdns-linux-amd64
./nothingdns-linux-amd64 -config /etc/nothingdns/nothingdns.yaml
```
Check a file first with `nothingdns -config <file> -validate-config`.

### 16.2 Docker
The `Dockerfile` is multi-stage: `golang:1.27.2-alpine` builds `nothingdns` and
`dnsctl` statically (`CGO_ENABLED=0`, `-trimpath`), and the final image is
`FROM scratch` with both binaries in `/usr/local/bin`, the CA bundle, a default
config at `/etc/nothingdns/nothingdns.yaml` (`deploy/docker/nothingdns.yaml`) and
a writable `/data` volume. It runs as UID 1000. Published ports: `53/udp`,
`53/tcp`, `853`, `8853` (XoT), `443`, `8080` (REST API, dashboard) and `9153`
(metrics, off in the default config).

```bash
docker run -d --name nothingdns \
  -p 53:53/udp -p 53:53/tcp -p 8080:8080 \
  -v nothingdns-data:/data \
  ghcr.io/nothingdns/nothingdns:latest
# your own config: -v ./nothingdns.yaml:/etc/nothingdns/nothingdns.yaml:ro
```

The image has no shell or `wget`; its health check is `dnsctl server health`.
`docker-compose.yml` is the single-node setup for development and testing.

### 16.3 Multi-node
For a Raft cluster, give each node a `cluster:` section as in §10.2 (the same
`peers` list on every node, a distinct `node_id` and a shared
`encryption_key`) and its own data directory. `deploy/config-node{1,2,3}.yaml`
are example node configs. Production multi-node deployments use the Helm chart
in `deploy/helm/nothingdns` or the manifests in `deploy/k8s`. Cluster settings
are not read from environment variables (§12.3); put them in the config file.

### 16.4 Systemd Service
`deploy/nothingdns.service`:
```ini
[Unit]
Description=NothingDNS Server
Documentation=https://github.com/nothingdns/nothingdns
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
# Dedicated system account created by install.sh / setup.sh:
#   useradd --system --no-create-home --shell /usr/sbin/nologin nothingdns
User=nothingdns
Group=nothingdns

# Main executable
ExecStart=/usr/local/bin/nothingdns -config /etc/nothingdns/nothingdns.yaml

# Reload configuration on SIGHUP
ExecReload=/bin/kill -HUP $MAINPID

# Restart policy
Restart=on-failure
RestartSec=5

# Resource limits
LimitNOFILE=65535
LimitNPROC=512

# Security - bind to privileged ports
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
PrivateTmp=true
PrivateDevices=true

# Allow write access to data (including Raft under cluster/), logs, and
# zone files the API edits ("-" ignores the path if it does not exist).
ReadWritePaths=/var/lib/nothingdns /var/log/nothingdns -/etc/nothingdns/zones

# Pin stdout/stderr to a file under /var/log/nothingdns so the logrotate
# rule written by install.sh/setup.sh (which globs /var/log/nothingdns/*.log)
# actually catches the running app's log stream, not just the query log.
# `append:` (systemd >= 246) preserves the existing file across restarts and
# matches the O_APPEND open mode used by the audit logger.
StandardOutput=append:/var/log/nothingdns/server.log
StandardError=append:/var/log/nothingdns/server.log
SyslogIdentifier=nothingdns

# Environment
Environment=NOTHINGDNS_CONFIG=/etc/nothingdns/nothingdns.yaml

# Working directory
WorkingDirectory=/var/lib/nothingdns

# Timeout settings
TimeoutStartSec=30
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
```

---

## 17. Build & Cross-Compilation

Go 1.26.9 or later (`go.mod`; CI and the image use toolchain 1.27.2) and no C
toolchain: every build is `CGO_ENABLED=0`.

```bash
make build            # nothingdns and dnsctl, with -trimpath -ldflags "-s -w"
make build-web        # the React dashboard (web/, needs npm)
make build-release    # scripts/build-release.sh: cross-platform binaries + SHA256SUMS in dist/
make build-docker     # docker build -t nothingdns:latest .
make test             # go test ./... -count=1 -short
make test-race        # the same with the race detector
make ci               # fmt-check, vet, staticcheck, test, build
```

`scripts/build-release.sh` builds linux, darwin and windows for amd64 and arm64
(override with `TARGETS="linux/amd64 ..."`). It bakes the version into the
binaries with
`-X github.com/nothingdns/nothingdns/internal/util.Version=<version>`, taking it
from the exact git tag, else the `VERSION` file. The Dockerfile does the same
with its `VERSION` build argument. The static-analysis checks that must pass
before a merge are listed in `AGENTS.md`.

---

## 18. Comparison with Existing DNS Servers

| Feature | NothingDNS | BIND 9 | CoreDNS | PowerDNS | Unbound |
|---------|-----------|--------|---------|----------|---------|
| Language | Go | C | Go | C++ | C |
| Dependencies | Minimal (6 direct modules: quic-go, OpenTelemetry, x/sys) | Many | Many (plugins) | Many | Several |
| Single Binary | ✅ | ❌ | ✅ | ❌ | ❌ |
| Authoritative | ✅ | ✅ | ✅ (plugin) | ✅ | ❌ |
| Recursive | ✅ | ✅ | ✅ (plugin) | ✅ (recursor) | ✅ |
| DoT | ✅ | ✅ | ✅ | ❌ | ✅ |
| DoH | ✅ | ✅ (9.18+) | ✅ | ❌ | ✅ |
| DoQ | ✅ | ❌ | ❌ | ❌ | ❌ |
| DNSSEC Sign | ✅ | ✅ | ❌ | ✅ | ❌ |
| DNSSEC Validate | ✅ | ✅ | ✅ | ❌ | ✅ |
| Clustering | ✅ (Raft, static membership) | ❌ | ❌ | ❌ | ❌ |
| GeoDNS | ✅ | ❌ | ✅ | ✅ | ❌ |
| Split-Horizon | ✅ | ✅ (views) | ❌ | ❌ | ❌ |
| Ad-Blocking | ✅ | ❌ | ✅ (plugin) | ❌ | ❌ |
| Web Dashboard | ✅ | ❌ | ❌ | ✅ | ❌ |
| REST API | ✅ | ❌ | ❌ | ✅ | ❌ |
| BIND Zone Import | ✅ | Native | ❌ | ❌ | ❌ |

The NothingDNS column was checked against the code (see §6 to §11 for what each
✅ covers and what it does not: no ECS, no automatic key rollover, no
allowlist). The other columns are general knowledge of those products and were
not re-checked; verify them before relying on the comparison.

---

## 19. RFC Compliance

What the code implements. Where an RFC is only partly covered, the line says so.

### Core
- RFC 1034, RFC 1035 — Domain Names
- RFC 2181 — Clarifications to the DNS Specification
- RFC 3597 — Handling of unknown RR types (`TYPE<n>`, `\# <len> <hex>`)
- RFC 4343 — Case insensitivity of names
- RFC 6895 — DNS IANA Considerations
- RFC 5891, RFC 5892, RFC 5893 — IDNA (A-label validation, derived properties, Bidi)

### Transport
- RFC 7766 — DNS Transport over TCP
- RFC 7858 — DNS over TLS (DoT)
- RFC 8484 — DNS over HTTPS (DoH); DNS over WebSocket on the same listener
- RFC 9250 — DNS over QUIC (DoQ), through `quic-go`
- RFC 9103 — Zone transfer over TLS (XoT)
- RFC 9230 — Oblivious DoH, with RFC 9180 HPKE
- RFC 8490 — DNS Stateful Operations

### EDNS
- RFC 6891 — EDNS(0)
- RFC 7830 — EDNS Padding (DoH responses)
- RFC 7873 — DNS Cookies
- RFC 8914 — Extended DNS Errors
- RFC 7871 — EDNS Client Subnet: the option is parsed only; not implemented (§9.4)

### DNSSEC
- RFC 4033, RFC 4034, RFC 4035 — DNSSEC (validation and online/offline signing)
- RFC 5155 — NSEC3; RFC 9276 — NSEC3 parameter guidance (iterations capped at 150)
- RFC 8198 — Aggressive use of NSEC
- RFC 8976 — ZONEMD
- RFC 6698 — TLSA record type (stored and served; DANE validation is not performed)
- RFC 5011 — Trust Anchor Update: not implemented (§6.2)
- RFC 7583 — Key rollover timing: a scheduler exists but is not wired in (§6.1.2)

### Zone Transfer & Dynamic DNS
- RFC 1995 — Incremental Zone Transfer (IXFR)
- RFC 1996 — NOTIFY
- RFC 2136 — Dynamic DNS UPDATE
- RFC 8945 — TSIG (this supersedes RFC 2845)
- RFC 5936 — AXFR

### Resolution, policy and performance
- RFC 2308 — Negative Caching
- RFC 4592 — Wildcard Processing
- RFC 6672 — DNAME
- RFC 7816 — QNAME Minimization
- RFC 8767 — Serve-Stale
- RFC 6147 — DNS64
- Response rate limiting follows the BIND-style RRL design (not an RFC; §9.5)
- RFC 6762, RFC 6763 — mDNS and DNS-SD responder

---

## 20. Non-Goals (Out of Scope)

- GUI installer (CLI/config-file only)
- Windows service manager (use NSSM externally)
- LDAP/Active Directory integration
- HTTP-based zone API that replaces zone files entirely (API and zone files coexist)
- A QUIC stack of its own: DoQ uses `quic-go` (§3.2.5)
- Commercial GeoIP database bundling (user provides their own)

### 20.1 Described earlier, not implemented
Features this document once presented as part of the design that the code does
not have; treat them as not implemented:

- Automatic DNSSEC key rollover and the embedded key store (§6.1.2)
- RFC 5011 trust anchor updates and negative trust anchors (§6.2)
- EDNS Client Subnet handling (§9.4)
- A blocklist allowlist, regex or custom-IP block responses (§9.1)
- A GeoDNS city level and automatic database reload on file change (§9.2)
- DoT or DoH upstreams and per-zone forwarding (§5.1.2)
- RRL slip (§9.5)
- Raft membership changes at runtime (§10.1.1)
- A CHAOS (`version.bind`) responder (§4.1.2)
- Prometheus metrics for cache size, zones, Raft, per-upstream latency and
  DNSSEC validation (§11.4)

---

## 21. Success Criteria

| # | Criterion | Status |
|---|---|---|
| 1 | **Functional:** pass RFC compliance tests for authoritative and recursive modes | Not demonstrated: the repository has unit and end-to-end tests but runs no external conformance suite (CI workflows run only on demand or on a release tag) |
| 2 | **Performance:** exceed 500K QPS on cached UDP queries (single node) | Not measured (§14) |
| 3 | **Reliability:** zero downtime during leader failover in a 3-node cluster (<3 s) | Not measured; cluster tests exist, none times a failover |
| 4 | **Compatibility:** import and serve 100% of valid BIND zone files | Not demonstrated: the parser covers `$ORIGIN`, `$TTL`, `$INCLUDE`, `$GENERATE`, multi-line records and inherited owners, with many unit tests, but it has not been run against a BIND test corpus |
| 5 | **Security:** pass DNSSEC validation test suites (DNSViz, Verisign Labs) | Not demonstrated: no such suite is run in the repository |
| 6 | **Usability:** fresh install to serving the first zone in under 5 minutes | Not measured |
| 7 | **Size:** single binary under 30 MB, Docker image under 35 MB (`FROM scratch`) | Binary met (21.6 MB). The image holds both binaries (29.4 MB), the CA bundle and small config files, so it should be near 30 MB; it was not built here |

---

*Document Version: 1.0*
*Created: 2026-03-25*
*Author: Ersin / ECOSTACK TECHNOLOGY OÜ*
*Status: DRAFT — Pending Review*
