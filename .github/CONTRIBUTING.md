# Contributing to NothingDNS

Thank you for your interest in contributing to NothingDNS!

## Ground Rules

### Zero-Dependency Policy

NothingDNS is a **zero external dependency** project. All code must use only Go standard library packages. Before adding any import, ask yourself: can this be implemented with `sync`, `net`, `os`, `encoding`, `crypto`, etc.?

Run `make verify-zero-deps` before committing. If `go.sum` is not empty, your PR will be rejected.

### Code Quality

- `go vet ./...` must pass with zero warnings
- `go fmt ./...` must be run on every changed file
- All new code must have test coverage
- No `//nolint:` comments without justification
- Errors must be handled or explicitly annotated with `// error intentionally ignored`

### Commit Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`

Examples:
- `feat(dnssec): add NSEC3PARAM chain validation`
- `fix(server): correct UDP buffer pool return on nil server`
- `perf(cache): reduce Lock contention in Get path`

## Development Setup

### Prerequisites

- Go 1.22+
- `make`
- Optional: `golangci-lint` for linting (`make lint`)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/NothingDNS/NothingDNS.git
cd NothingDNS

# Build the project
make build

# Run tests
make test

# Verify zero dependencies
make verify-zero-deps
```

### Running Specific Tests

```bash
# Unit tests
go test ./internal/...

# With race detector
go test -race ./...

# Single package
go test ./internal/dnssec/...

# With coverage
go test -coverprofile=coverage.out ./...
```

### Project Structure

```
cmd/nothingdns/     — Main DNS server binary
cmd/dnsctl/          — CLI management tool
internal/            — All packages (zero external deps)
  auth/              — JWT authentication + RBAC
  blocklist/         — DNS-based ad-blocking
  cache/             — DNS response cache
  cluster/           — Cluster (Raft + gossip)
  config/            — YAML config parser
  dns64/             — DNS64 synthesis
  dnscookie/         — RFC 7873 DNS cookies
  dnssec/            — DNSSEC signing + validation
  doh/               — DNS-over-HTTPS
  filter/            — ACL + rate limiting
  geodns/            — GeoDNS + MMDB
  memory/            — Memory pressure monitor
  metrics/           — Prometheus metrics
  protocol/          — Wire-format DNS parser
  quic/              — DNS-over-QUIC
  resolver/          — Iterative recursive resolver
  rpz/               — Response Policy Zones
  server/            — UDP/TCP/TLS/DoT/DoQ/DoH servers
  storage/           — KV store + WAL
  transfer/          — AXFR/IXFR/NOTIFY/DDNS
  upstream/          — Upstream resolver client
  websocket/         — DNS-over-WebSocket
  zone/              — Zone file parser + manager
web/                 — React/TypeScript dashboard
```

## Adding a New DNS Record Type

1. Add the type constant to `internal/protocol/types.go`
2. Add the RData struct (e.g., `RDataTYPE`) to `internal/protocol/types.go`
3. Register in the `createRData` factory in `internal/protocol/record.go`
4. Add pack/unpack/len/string methods
5. Add wire-format tests
6. Add handler support in `cmd/nothingdns/`

## Adding a New API Endpoint

1. Add the route in `internal/api/server.go`
2. Add handler function with request validation
3. Add OpenAPI annotation comments
4. Add tests in `internal/api/`
5. Update Swagger UI (auto-generated from annotations)

## Performance Guidelines

- Profile before optimizing: `go test -bench=. -benchmem`
- Use `sync.Pool` for buffers that are allocated per-request
- Use `sync.RWMutex` over `sync.Mutex` when reads dominate writes
- Avoid allocations in the DNS query hot path

## Getting Help

- [GitHub Issues](https://github.com/NothingDNS/NothingDNS/issues)
- [GitHub Discussions](https://github.com/NothingDNS/NothingDNS/discussions)
