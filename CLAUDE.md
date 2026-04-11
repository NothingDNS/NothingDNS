# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build, Lint & Test

```bash
go build -o nothingdns ./cmd/nothingdns        # Server binary
go build -o dnsctl ./cmd/dnsctl                # CLI binary
go vet ./...                                   # Lint
go test ./... -count=1 -short                  # All tests (short mode)
go test ./internal/protocol/ -run TestName    # Single test
```

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

**Key packages**:
- `internal/protocol/` — DNS wire protocol (RFC 1035), no external dependencies
- `internal/server/` — UDP, TCP, TLS, DoH transports
- `internal/cache/` — Thread-safe LRU with TTL and negative caching
- `internal/cluster/` — Gossip-based membership with AES-256-GCM encryption; uses raft for consensus
- `internal/config/` — Custom YAML parser (no gopkg.in/yaml)
- `internal/resolver/` — Iterative recursive resolver with CNAME chasing
- `internal/dnssec/` — Validation, signing, key rollover (RFC 7583)
- `internal/storage/` — KV store with WAL and TLV serialization
- `internal/api/mcp/` — MCP server for AI assistant integration

## Project Structure

```
cmd/
├── nothingdns/     # Main DNS server
└── dnsctl/        # CLI management tool

internal/
├── api/            # HTTP REST API + OpenAPI/Swagger
│   └── mcp/        # MCP server for AI integration
├── audit/          # Structured query audit logging
├── auth/           # Authentication middleware
├── blocklist/      # Domain blocklist engine
├── cache/          # LRU cache with TTL, prefetch, negative caching
├── catalog/        # Zone catalog for managing zone metadata
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
├── transfer/       # AXFR/IXFR zone transfers
├── upstream/       # Upstream forwarding with health checks and load balancing
├── websocket/      # WebSocket server for live query streaming
└── zone/           # BIND format zone file parser with $GENERATE support
```

## Dependency Policy

**ZERO external dependencies** — entire codebase uses Go stdlib only. Do not add any third-party imports.

## Known Gotchas

- **Port 53** requires root on Unix; use 5354+ for testing
- **YAML parser** is custom — does not support anchors/aliases or multiline strings
- **`protocol.CanonicalWireName()`** is the shared canonical name encoder — do not create new ones
- **`advance()` and `peek()`** skip `TokenComment` automatically — never handle comments in parse logic
- **Health check goroutines** use per-round `sync.WaitGroup` — do not reuse the main WG
- **`sync.Pool` buffers**: copy before passing to `defer pool.Put()` — the reference may be reclaimed
- **Upstream TCP** messages must check `len(packed) > 65535` before sending
- **UDP truncation** must be record-boundary-aware (remove answers from end, not byte-level cut)
