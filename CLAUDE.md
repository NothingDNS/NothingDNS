# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with this repository.

## Mandatory Pre-Work

Before any work in this project, read and obey `AGENT_DIRECTIVES.md` in the project root. It contains hard rules that override default LLM behavior: phased execution, forced verification, edit safety, commit discipline, and more. Violation of any rule is a blocking issue.

## Build, Lint & Test

```bash
go build -o nothingdns ./cmd/nothingdns        # Server binary
go build -o dnsctl ./cmd/dnsctl                # CLI binary
go vet ./...                                   # Lint
go test ./... -count=1 -short                  # All tests (short mode)
go test ./internal/protocol/ -run TestName    # Single test
go test ./internal/e2e/... -v                  # End-to-end tests
```

**Go version**: 1.25.0+ (toolchain go1.26.2). `CGO_ENABLED=0` for static builds.

**Docker**: Multi-stage `Dockerfile` builds both binaries from scratch — `golang:1.26.2-alpine` compiles with `-trimpath -ldflags "-s -w -extldflags '-static'"`, then copies to `FROM scratch`.

### RTK Commands (Token-Optimized Output)

This project uses [RTK](https://github.com/nothingdns/rtk) for compact output:
- `rtk go build ./...` — compact build output
- `rtk go test ./...` — failures only (90%+ token savings)
- `rtk go vet ./...` — grouped violations
- `rtk go fmt ./...` — format check
- `rtk git status` / `rtk git diff` / `rtk git log` — compact git output
- `rtk gh pr view <num>` / `rtk gh run list` — compact GitHub output

RTK passes through unlisted subcommands (e.g., `rtk git branch -a`).

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  UDP Server │ TCP Server │ DoH Server │ DoT Server │ DoQ Server    │
├─────────────────────────────────────────────────────────────────────┤
│                        Request Handler                               │
│  Cache → Auth Zones → Upstream/Resolver → DNSSEC Validator          │
├─────────────────────────────────────────────────────────────────────┤
│  Cluster Manager (Gossip + Raft) │ Storage (KV + WAL)              │
├─────────────────────────────────────────────────────────────────────┤
│  API Layer (HTTP + WebSocket + MCP) │ Config (Hot Reload)           │
└─────────────────────────────────────────────────────────────────────┘
```

**Request flow**: Transport → Protocol parser → Cache → Zone lookup → Upstream/Resolver → DNSSEC → Response

### Request Pipeline (integratedHandler.ServeDNS)

The core request handler in `cmd/nothingdns/handler.go` processes queries through 21 stages:

1. **Panic recovery** — defer recovers any panic, returns SERVFAIL
2. **IDNA validation** (RFC 5891) — validate internationalized domain names
3. **ACL check** — allow/deny by client IP
4. **RPZ client IP policy** — check if client IP triggers an RPZ rule
5. **Rate limiting** — per-client token bucket
6. **DNS Cookie validation** (RFC 7873) — anti-spoofing
7. **AXFR/IXFR/NOTIFY/UPDATE** — special request type handling
8. **Blocklist check** — return NXDOMAIN with EDE Filtered
9. **RPZ QNAME policy** — check if queried domain is blocked
10. **Cache lookup** — positive cache hit returns immediately
11. **NSEC aggressive cache** (RFC 8198) — synthesize negative from cached NSEC
12. **Split-horizon view zones** — view-specific zone lookup
13. **Authoritative zone lookup** — radix tree O(log n) matching
14. **CNAME chasing** — follow CNAME chains within zones
15. **Iterative recursive resolver** — full recursion with QNAME minimization
16. **Upstream forwarding** — load-balanced upstream with health checks
17. **DNSSEC validation** — validate signatures on signed responses
18. **RPZ response IP/NSDNAME checks** — resolved IP policy
19. **DNS64 synthesis** (RFC 6147) — synthesize AAAA from A
20. **Cache the response** — positive or negative (RFC 2308)
21. **Stale serving** — serve stale entries on upstream failure (RFC 8767)

### Manager Pattern

`cmd/nothingdns/` uses manager constructors to encapsulate subsystem initialization:
- `cache_manager.go` — cache with persistence and prefetch
- `upstream_manager.go` — upstream pool with health checks
- `zone_manager.go` — zone file loading and radix tree
- `security_manager.go` — blocklist, RPZ, geo, ACL, rate limiter
- `dnssec_manager.go` — validator and key rollover
- `cluster_manager.go` — gossip membership + Raft consensus
- `transfer_manager.go` — AXFR/IXFR/NOTIFY/DDNS

All are wired into a single `integratedHandler` in `handler.go` (1255 lines).

### Hot Config Reload

SIGHUP triggers config reload without downtime: zones, blocklists, RPZ rules, split-horizon views, and TLS certs are reloaded in-place. Validate config beforehand with `-validate-config` flag.

### Key packages

- `internal/protocol/` — DNS wire protocol (RFC 1035), no external dependencies
- `internal/server/` — UDP, TCP, TLS, DoH transports
- `internal/cache/` — Thread-safe LRU with TTL, negative caching, stale serving, NSEC aggressive caching
- `internal/cluster/` — Gossip-based membership (SWIM-like) with AES-256-GCM encryption; Raft consensus in `cluster/raft/` with optional TLS RPC
- `internal/config/` — Custom YAML parser (tokenizer → parser → node tree, no gopkg.in/yaml)
- `internal/resolver/` — Iterative recursive resolver with CNAME chasing
- `internal/dnssec/` — Validation, signing, key rollover (RFC 7583), Ed25519/ECDSA/RSA
- `internal/storage/` — KV store with WAL, ACID transactions, TLV serialization
- `internal/zone/` — BIND-format zone file parser with `$GENERATE`, radix tree, WAL journal, ZONEMD
- `internal/api/mcp/` — MCP server for AI assistant integration
- `internal/transfer/` — AXFR/IXFR zone transfers, NOTIFY, Dynamic DNS (RFC 2136), XoT (RFC 9103)
- `internal/dashboard/` — Embedded React 19 SPA served from `static/dist/`

## Project Structure

```
cmd/
├── nothingdns/     # Main DNS server (1020-line main.go + 12 supporting files)
└── dnsctl/        # CLI management tool (zone, record, cache, cluster, blocklist, config, dig, dnssec, server)

internal/
├── api/            # HTTP REST API + OpenAPI/Swagger
│   └── mcp/        # MCP server for AI integration
├── audit/          # Structured query audit logging
├── auth/           # JWT-based multi-user authentication with RBAC
├── blocklist/      # Domain blocklist engine (hosts-file + URL-based)
├── cache/          # LRU cache with TTL, prefetch, negative caching, stale serving
├── catalog/        # Zone catalog for managing zone metadata (RFC 9432)
├── cluster/        # Gossip-based HA clustering with raft consensus
├── config/         # Custom YAML parser (handles most YAML, not anchors/multiline)
├── dashboard/      # Embedded React 19 SPA (served from internal/dashboard/static/)
├── dns64/          # DNS64/NAT64 synthesis (RFC 6147)
├── dnscookie/      # DNS Cookies (RFC 7873)
├── dnssec/         # DNSSEC validation/signing, Ed25519/ECDSA/RSA
├── doh/            # DNS over HTTPS (RFC 8484)
├── e2e/            # End-to-end tests
├── filter/         # Split-horizon views, rate limiting, ACL
├── geodns/         # GeoIP DNS with MMDB support
├── idna/           # Internationalized domain name validation
├── load/           # Load balancing and anycast
├── memory/         # Runtime memory monitoring and OOM protection
├── metrics/        # Prometheus metrics export
├── odoh/           # Oblivious DNS over HTTPS (RFC 9230)
├── otel/           # OpenTelemetry tracing
├── protocol/       # DNS wire protocol parser (RFC 1035)
├── quic/           # DNS over QUIC transport
├── resolver/       # Iterative recursive resolver with CNAME chasing
├── rpz/            # Response Policy Zones for DNS filtering
├── server/         # UDP/TCP/TLS transport handlers
├── storage/        # KV store with WAL and TLV serialization
├── transfer/       # AXFR/IXFR zone transfers, NOTIFY, DDNS, XoT
├── upstream/       # Upstream forwarding with health checks and load balancing
├── websocket/      # WebSocket server for live query streaming
└── zone/           # BIND format zone file parser with $GENERATE support
```

## Dependency Policy

**ZERO external dependencies** — entire codebase uses Go stdlib only (`golang.org/x/sys` for platform-specific socket ops). Do not add any third-party imports.

## Known Gotchas

- **Port 53** requires root on Unix; use 5354+ for testing
- **YAML parser** is custom — does not support anchors/aliases or multiline strings
- **`protocol.CanonicalWireName()`** is the shared canonical name encoder — do not create new ones
- **`advance()` and `peek()`** skip `TokenComment` automatically — never handle comments in parse logic
- **Health check goroutines** use per-round `sync.WaitGroup` — do not reuse the main WG
- **`sync.Pool` buffers**: copy before passing to `defer pool.Put()` — the reference may be reclaimed
- **Upstream TCP** messages must check `len(packed) > 65535` before sending
- **UDP truncation** must be record-boundary-aware (remove answers from end, not byte-level cut)
- **Default config path**: `/etc/nothingdns/nothingdns.yaml`; override with `--config` flag
