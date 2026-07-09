# Changelog

All notable changes to NothingDNS are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Go toolchain bump 1.26.4 → 1.26.5** across the root module,
  embedded web module, and Docker builder to pull in the patched
  `crypto/tls` stdlib release for GO-2026-5856. `govulncheck` is
  expected to pass on CI with the patched toolchain.
- **Go toolchain bump 1.26.2 → 1.26.4** across the root module and
  embedded web module to pull in patched stdlib releases.
- **Web tooling Babel pin**: `web/package.json` now overrides transitive
  `@babel/core` to `7.29.7`, resolving GHSA-4x5r-pxfx-6jf8 /
  CVE-2026-49356 in development/build tooling. `npm audit --audit-level=low`
  is clean after the lockfile update.
- **Data race on `enabled` flag** in `RateLimiter`, `RRL`, and
  `Blocklist`: hot-path predicate read the bool without a lock while
  `SetEnabled`/`Reload` wrote it under the package mutex. Converted
  to `sync/atomic.Bool` — wait-free reads, visibility-guaranteed
  writes.
- **GOST DS digest type 3 explicitly rejected** (previous
  `hashGOST94` used a placeholder S-box that produced
  non-conformant hashes — silent miscompare risk). Deprecated by
  RFC 8624 §3.2 anyway.

### Added

#### Dashboard and management API

- **Real active-client metric**: the management metrics API now reports
  connected dashboard/websocket clients, and the embedded React dashboard
  displays it as a first-class status tile.
- **Web build token guard**: `npm run build` in `web/` now runs
  `scripts/verify-css-tokens.mjs` so required design-system color tokens
  cannot disappear silently.

#### Real implementations replacing previous honest-fail stubs

- **F127/F129 — DSO TLV wire-format pipeline (RFC 8490)**:
  `protocol.Message.RawBody` captures DSO bodies; `OpcodeDSO=6`
  constant. `extractTLVs` enforces RFC 8490 §5.2 (DSO opcode +
  zero section counts). `SendKeepalive` frames a real DSO
  keepalive TLV + DNS header + TCP length prefix and writes to the
  session connection.
- **F138 — Real MaxMind DB binary-format parser**
  (`internal/geodns/mmdb.go`, ~440 LOC) with the MMDB §1.4 IPv4-in-
  IPv6 expansion, all 15 type codes, 24/28/32-bit record sizes, and
  MSB-first BST traversal. Earlier follow-up fixed a
  data-pointer arithmetic bug (was double-adding `treeBytes`).
- **F122 — RFC 9180 HPKE base mode + RFC 9230 ODoH wire format**
  (`internal/odoh/hpke.go` + `rfc9230.go`). Hand-rolled with
  Go stdlib only (`crypto/ecdh` X25519, `crypto/hkdf` HKDF-SHA256,
  `crypto/aes`+`crypto/cipher` AES-GCM). HPKE math validated
  byte-for-byte against RFC 9180 §A.1 test vectors (DHKEM
  shared_secret, KeySchedule base_nonce, AEAD seal[0]). Full
  Client→Proxy→Target→handler round-trip green.

#### Raft consensus

- **Leader-redirect error type**: `*raft.ErrNotLeader` now carries
  the known leader's `NodeID` so admin clients calling
  `AddNodeViaLeader` / `RemoveNodeViaLeader` on a follower can
  retry directly against the leader instead of probing every peer.
  Followers track `leaderID` from `AppendEntries.LeaderID`.

#### Test infrastructure

- **Fuzz harnesses** for all attacker-controlled wire-format
  parsers (none run by default; invoke with `-fuzz=Name`):
  - `protocol`: FuzzUnpackMessage, FuzzUnpackName,
    FuzzUnpackResourceRecord
  - `zone`: FuzzParseZoneFile
  - `dso`: FuzzUnpackTLV, FuzzHandleDSORequest
  - `odoh`: FuzzParseODoHMessage, FuzzParseConfigContents,
    FuzzDecryptQuery
  Local 3-minute runs reached 25M+ iterations on
  `FuzzUnpackMessage` with zero panics.
- **CI fuzz job**: `go.yml` runs each target 30s on every PR with
  corpus caching; on any panic, the corpus and any
  `internal/*/testdata/fuzz` artifacts are uploaded.
- **mmdb_writer_test.go**: small in-memory MMDB binary-format
  writer so unit tests can produce real fixtures the production
  parser decodes, replacing six tests that were skipped because
  hand-crafted bytes from the honest-fail era didn't form valid
  records.

### Fixed

- **DNSSEC validation end-to-end**: direct handler and pipeline serving
  paths now both perform DNSSEC validation correctly, including chain
  building, DS authentication, and denial proof handling.
- **Resolver cache correctness**: side records no longer clobber primary
  cache entries, and negative DNSSEC denial proofs are preserved instead
  of being dropped during cache writes.
- **Extended DNS Error codes**: protocol constants and OPT handling now
  align with the IANA EDE registry.
- **Management API hardening**: cache-disable requests are rejected
  explicitly, duration headers are parsed safely, server configuration is
  populated consistently, and API responses use stronger error handling.
- **Web dashboard UX and record editing**: pages now show real error/empty
  states with mutation feedback and accessibility fixes; the zone editor
  uses stable record identity/edit semantics instead of ambiguous display
  values.
- **Blocklist plain-domain input**: file loading now accepts simple
  domain-per-line blocklists in addition to hosts-style entries.
- **JoinSeed nil-deref before Start**: calling `Cluster.JoinSeed`
  on a non-started cluster panicked because the gossip layer
  reached `gp.conn.WriteToUDP` on a nil conn. Added an explicit
  "cluster must be started" guard.
- **MMDB pointer arithmetic** (`internal/geodns/mmdb.go`):
  `mmdbLookup` returned `rec - nodeCount - 16 + treeBytes` and the
  caller in `geodns.go` added `treeBytes + 16` on top, double-adding
  the tree size. Records were decoded from an offset 12+ bytes
  past the real one. Replaced with the canonical
  `abs_file_offset = treeBytes + (rec - nodeCount)` formula used
  by MaxMind-DB-Reader-python.
- **DNSSL multi-label encoder** (`internal/resolver/rdnss.go`):
  `encodeDNSSLLabel` was a single-label calculator misnamed and
  called with full domains. Renamed to `encodeDNSSLDomain`, split
  on ".", and the RFC 8106 §5.2 8-byte padding fixed.
- **NSEC3 closest-encloser SECURE test** rebuilt with a 3-record
  fixture satisfying RFC 5155 §8.4 (closest encloser exact match +
  next-closer cover + wildcard cover). Was a stale skip.
- **KV Close-with-active-tx** stale skip: F060 changed
  `Begin` to hold the store lock for tx lifetime, so `Close` now
  blocks on in-flight tx. Replaced the skip with a real
  concurrency test that exercises the new behavior.

### Coverage

Lifted across multiple packages:

| Package | Before | After | Δ |
|---|---|---|---|
| filter | 57.8% | 92.4% | +34.6 |
| geodns | 70.3% | 85.0% | +14.7 |
| cluster/raft | 51.9% | 63.8% | +11.9 |
| api | 79.2% | 82.3% | +3.1 |
| dso | 89.1% | 91.9% | +2.8 |
| cmd/nothingdns | 69.3% | 71.3% | +2.0 |

### Removed

- Dead code: legacy `hashGOST94` (placeholder S-box),
  `loadMMDBFromBytes`, `mocks.go` → `mocks_test.go` (test-only
  symbols no longer shipped in the production binary),
  `ErrMMDBNotSupported` sentinel (LoadMMDB returns specific decode
  errors now), unused `DynamicDNSHandler.closed` field.

## [0.1.1] — 2026-04-12

### Added

#### E2E Tests
- **DoT (DNS over TLS) Tests**: Full test suite with self-signed certificates for TLS handshake, multiple connections, connection reuse, and error handling
- **AXFR/IXFR Zone Transfer Tests**: Comprehensive tests for full zone transfers (AXFR) and incremental zone transfers (IXFR) with real TCP streaming
- **Real Server Tests**: UDP/TCP server tests with concurrent query handling, graceful shutdown, and panic recovery
- **DoH (DNS over HTTPS) Tests**: HTTP-based DNS query tests with POST and GET methods

#### Web UI
- **Error Handling**: Fixed 401 API error handling with proper non-JSON response parsing
- **WebSocket Reconnection**: Added exponential backoff with maximum 10 retry attempts
- **Race Condition Fixes**: Fixed RAF cleanup race condition in query-log page using cancellation pattern
- **Key Prop Issues**: Fixed React key prop warnings in dashboard and top-domains components

### Fixed

#### Web UI
- `api.ts`: Fixed 401 errors not being caught properly for non-JSON responses
- `useWebSocket.ts`: Fixed token double-encoding issue and improved reconnection logic
- `query-log.tsx`: Fixed index-as-key warnings, fixed RAF cleanup race condition
- `dashboard.tsx`: Fixed key prop issues
- `blocklist.tsx`: Fixed total_rules display using `!= null` instead of `??`
- `upstreams.tsx`: Fixed health bar to show success percentage (queries/total) instead of failure percentage
- `zone-editor.tsx`: Fixed deleteSelected to track failures with alert, fixed deleteRecord revert on API failure

### Changed
- **Pre-commit Hook**: Improved version-sensitive checks and local CI validation

## [0.1.0] — 2026-04-05

### Added

#### Protocol
- **DNAME (RFC 6672)**: Full DNAME record support with chain following in the resolver and synthesis in authoritative responses. DNAME at a superdomain synthesizes a CNAME for matching subdomains.
- **NSEC3 Hardening (RFC 5155)**: NSEC3 validation now verifies the type bitmap for exact hash matches per RFC 5155 §8.2. NSEC3PARAM records are fetched during chain building to validate algorithm and iteration parameters.
- **IXFR Journal Persistence**: IXFR incremental transfer journal is persisted to disk via `KVJournalStore` (file-per-serial layout under `dataDir/ixfr-journals/<zone>/<serial>.journal`). Reloaded on restart.

#### Performance
- **Response Buffer Pooling**: UDP and TCP response paths now use `sync.Pool` for zero-alloc buffer reuse. `UDPServer.responsePool` and `TCPServer.responsePool` eliminate per-query heap allocations in the hot path.
- **KVStore Read Lock Fix**: `KVStore.Begin(false)` now acquires a read lock instead of a write lock for read-only transactions, allowing concurrent readers.
- **ZoneStore RWMutex**: `ZoneStore` upgraded from `sync.Mutex` to `sync.RWMutex`, enabling concurrent read access for `LoadZone` and `ListZones`.
- **DNSSEC Validation Cache**: `Validator` now caches validation results by `(name, qtype)` with a 5-minute TTL, avoiding repeated cryptographic chain building.

#### Storage
- **WAL Journal**: Write-Ahead Log for zone changes enables crash recovery by replaying committed entries on startup.
- **KV Store Persistence**: Custom B-tree based KV store with transaction support, atomic disk persistence via `gob` encoding, and `ZoneStore` for zone-scoped key storage.

### Changed
- **`go vet ./...`**: Zero warnings. All code passes strict static analysis.
- **Build**: current release builds use `scripts/build-release.sh` via `make build-release`, producing `nothingdns` and `dnsctl` assets for Linux and macOS amd64/arm64 plus `SHA256SUMS`.

### Fixed
- `KVStore.Rollback()`: Fixed to handle read-only transactions without spurious write-lock acquisition.
- Phase 4.6 IXFR completeness: `generateIncrementalIXFR` now loads from persistent journal when in-memory journal is empty.

### Security
- See [SECURITY.md](SECURITY.md) for responsible disclosure policy.

### Dependencies
**Minimal external dependencies.** Core DNS logic is hand-rolled; current external modules are limited to necessary DoQ/platform/crypto/network support.
