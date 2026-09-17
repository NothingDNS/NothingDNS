# AGENTS.md

This file provides guidance to coding agents and contributors working with this repository.

## Build, Lint & Test

```bash
go build -o nothingdns ./cmd/nothingdns        # Server binary
go build -o dnsctl ./cmd/dnsctl                # CLI binary
go vet ./...                                   # Lint
go test ./... -count=1 -short                  # All tests (short mode)
go test ./internal/protocol/ -run TestName    # Single test
go test ./internal/e2e/... -v                  # End-to-end tests
```

**Static analysis (CI `Go` workflow / `security` job)** — must pass before merge:

```bash
staticcheck ./...
errcheck -ignoretests -exclude .errcheck-excludes.txt ./...   # see note below
go-errorlint -test=false ./...                                # production code only
govulncheck ./...                                             # Go stdlib + deps CVEs
```

`.errcheck-excludes.txt` is errcheck's exclude list (one fully-qualified
function/method signature per line, **no comments** — errcheck reads every
line as a symbol). It suppresses conventionally-safe, deliberately-ignored
calls (`fmt.Fprint*` to writers, `io`/`net` `Close`, `os.Remove`, deadline/
buffer setters, `(net/http.ResponseWriter).Write`, …) so errcheck flags only
genuine unhandled errors. Both errcheck and go-errorlint are scoped to
production code (`-ignoretests` / `-test=false`); test files are not linted.
When a new deliberate-ignore is genuinely safe and broadly applicable, add its
signature here rather than scattering `_ =` — otherwise annotate the call site
with `_ =` / `_, _ =`.

**Go version**: 1.26.6+ (root `go.mod`). `CGO_ENABLED=0` for static builds.

**Docker**: Multi-stage `Dockerfile` builds both binaries from scratch — `golang:1.26.6-alpine` compiles with `CGO_ENABLED=0`, `-trimpath`, and stripped/static link flags, then copies to `FROM scratch`.

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
│  API Layer (HTTP + WebSocket) │ Config (Hot Reload)                 │
└─────────────────────────────────────────────────────────────────────┘
```

**Request flow**: Transport → Protocol parser → Cache → Zone lookup → Upstream/Resolver → DNSSEC → Response

### Request Pipeline (integratedHandler.ServeDNS)

`integratedHandler.ServeDNS` delegates to the stage pipeline built in `cmd/nothingdns/pipeline.go` (`NewPipeline`); stage functions live in `pipeline_stages.go`. Every response passes through `headerPolicyResponseWriter` (`response_header_policy.go`), which echoes OPCODE/RD/CD and clears RA when recursion is unavailable or not allowed for the client. Stage order:

1. **setup / queryDirection / validation** — request IDs, drop responses, FORMERR on bad questions, IDNA (RFC 5891)
2. **metrics**
3. **acl** — general ACL for every query (first match wins; unmatched clients are refused once any rule exists)
4. **recursionPolicy** — marks whether the client may recurse (`allow_recursion`)
5. **rpzClient** — RPZ client-IP policy
6. **rateLimit** — per-client token bucket
7. **requestPolicy / cookie** — EDNS/opcode policy, DNS Cookies (RFC 7873)
8. **any / transfer** — ANY handling, AXFR/IXFR/NOTIFY/UPDATE
9. **blocklist / rpzQname** — filtering before the cache
10. **doBit / splitHorizon / authoritative / cname** — local zones and in-zone CNAME chasing, before the caches so cached upstream data (an NXDOMAIN or aggressive NSEC proof for a parent name) never shadows a local zone
11. **cache / nsecCache** — cache lookups (skipped for clients without recursion)
12. **authoritativeOnly** — REFUSED outside zones when `resolution.authoritative_only`
13. **recursionRefused** — REFUSED (EDE 18) outside zones for clients without recursion
14. **resolver / upstream / noUpstream** — iterative resolution or forwarding, DNSSEC validation, RPZ response checks, DNS64, caching, stale serving (RFC 8767)

### Manager Pattern

`cmd/nothingdns/` uses manager constructors to encapsulate subsystem initialization:
- `cache_manager.go` — cache with persistence and prefetch
- `upstream_manager.go` — upstream pool with health checks
- `zone_manager.go` — zone file loading and radix tree
- `security_manager.go` — blocklist, RPZ, geo, ACL + recursion allow list (and the persisted `access_policy.json`), rate limiter
- `dnssec_manager.go` — validator and key rollover
- `cluster_manager.go` — gossip membership + Raft consensus
- `transfer_manager.go` — AXFR/IXFR/NOTIFY/DDNS

All are wired into a single `integratedHandler` (`handler.go`, `handler_deps.go`).

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
- `internal/transfer/` — AXFR/IXFR zone transfers, NOTIFY, Dynamic DNS (RFC 2136), XoT (RFC 9103)
- `internal/dashboard/` — Embedded React 19 SPA served from `static/dist/`
- `internal/dso/` — DNS Stateful Operations (RFC 8490): TCP/TLS keepalive sessions, max-payload negotiation, TLV stream parser. Body lives in `protocol.Message.RawBody` (opcode 6).
- `internal/odoh/` — Oblivious DNS over HTTPS (RFC 9230) with RFC 9180 base-mode HPKE (DHKEM-X25519 / HKDF-SHA256 / AES-GCM), stdlib-only. HPKE math validated against RFC 9180 §A.1 vectors in `hpke_vectors_test.go`. Legacy non-RFC-9230 helpers in `odoh.go` are retained for test compatibility only — do not extend them; build on `hpke.go` / `rfc9230.go`.

## Project Structure

```
cmd/
├── nothingdns/     # Main DNS server (main.go wiring, pipeline, managers, transports)
└── dnsctl/        # CLI management tool (zone, record, cache, cluster, blocklist, config, dig, dnssec, server)

internal/
├── api/            # HTTP REST API + OpenAPI/Swagger
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
├── dso/            # DNS Stateful Operations (RFC 8490)
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

**Minimal external dependencies** — direct deps are `github.com/quic-go/quic-go` (DoQ transport), `golang.org/x/sys`, and the official OpenTelemetry SDK (`go.opentelemetry.io/otel`, `otel/sdk`, `otel/trace`, and the `otlptracehttp` exporter; added 2026-08-19 when the hand-rolled tracer/OTLP/Jaeger exporters were replaced by the SDK — see `internal/otel/`). `golang.org/x/{net,crypto,text}` and `go.uber.org/mock` are indirect (see `go.mod`). Everything else is hand-rolled on stdlib (including the YAML parser — no `gopkg.in/yaml`). Adding any new third-party import requires explicit discussion and justification.

> Note: there is **no PostgreSQL/`pgx` backend**. Zone/KV storage is the embedded WAL-backed KV store in `internal/storage/`. (Earlier revisions of this file documented a `pgx/v5` `postgres_zonestore.go` backend that was never committed; that text has been removed to match the code.)

## Known Gotchas

- **Config struct tags are documentation only** — `yaml:"..."` tags do not drive parsing. Every new key must also be read in the matching `unmarshal*` function in `internal/config` (and listed in `knownTopLevelKeys` for top-level keys), otherwise it is silently ignored. Add a parse test (`UnmarshalYAML`) for each new key.
- **Dashboard-managed state overrides the config file**: users created at runtime live in `server.http.users_file` (default `<storage.data_dir>/users.json`); ACL and `allow_recursion` changes made via API/dashboard live in `<storage.data_dir>/access_policy.json`, which replaces the config's `acl`/`allow_recursion` at start and on reload.
- **ODoH suite ids are RFC 9180 values** (KEM 0x0020, KDF 0x0001, AEAD 0x0001/0x0002) in both config and `internal/odoh`.
- **Shipped configs are validated in CI** by `scripts/validate-shipped-configs.sh` (example, deploy, Docker, k8s and installer-generated configs) — run it after touching any of them.
- **Port 53** requires root on Unix; use 5354+ for testing
- **YAML parser** is custom — does not support anchors/aliases or multiline strings. Block-sequence indent handling in `parseBlockSequence` uses column-based peek: the inline-mapping continuation loops break on `TokenDedent` when the post-dedent token doesn't share the item's first-key column, and the sequence main loop absorbs dedents only when a Dash at the sequence's own column waits behind them. Regression test: `TestParser_BlockSeqOfInlineMaps_ThenSiblingKey` in `parser_test.go`; smoke-test via `nothingdns -config config.example.yaml -validate-config`.
- **`protocol.CanonicalWireName()`** is the shared canonical name encoder — do not create new ones
- **`advance()` and `peek()`** skip `TokenComment` automatically — never handle comments in parse logic
- **Health check goroutines** use per-round `sync.WaitGroup` — do not reuse the main WG
- **`sync.Pool` buffers**: copy before passing to `defer pool.Put()` — the reference may be reclaimed
- **Upstream TCP** messages must check `len(packed) > 65535` before sending
- **UDP truncation** must be record-boundary-aware (remove answers from end, not byte-level cut)
- **Default config path**: `/etc/nothingdns/nothingdns.yaml`; override with `--config` flag
