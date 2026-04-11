# Changelog

All notable changes to NothingDNS are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **Build**: `make release` cross-compiles for Linux (amd64/arm64/armv7), macOS (amd64/arm64), Windows (amd64), FreeBSD (amd64) via goreleaser.

### Fixed
- `KVStore.Rollback()`: Fixed to handle read-only transactions without spurious write-lock acquisition.
- Phase 4.6 IXFR completeness: `generateIncrementalIXFR` now loads from persistent journal when in-memory journal is empty.

### Security
- See [SECURITY.md](SECURITY.md) for responsible disclosure policy.

### Dependencies
**Zero external dependencies.** NothingDNS is built with pure Go standard library only.
