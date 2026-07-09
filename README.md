# NothingDNS

<p align="center">
  <img src="assets/banner.jpeg" alt="NothingDNS" width="100%">
</p>

[![Go Version](https://img.shields.io/badge/Go-1.26.5%2B-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/nothingdns/nothingdns)](https://goreportcard.com/report/github.com/nothingdns/nothingdns)
[![CI](https://github.com/NothingDNS/NothingDNS/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/NothingDNS/NothingDNS/actions/workflows/go.yml)

NothingDNS is a self-contained DNS server written in Go. It includes authoritative DNS, recursive forwarding/resolution, DNSSEC, encrypted transports, policy filtering, clustering, a REST management API, `dnsctl`, and an embedded React dashboard.

## What is included

- **DNS serving**: UDP/TCP DNS, authoritative zones, forwarding, iterative resolution, DNS64, SVCB/HTTPS, IDNA, and QNAME minimization.
- **Security and policy**: DNSSEC validation/signing, DNS Cookies, DoH, DoT, DoQ, ODoH, DSO, ACLs, RRL, RPZ, and blocklists from hosts-style, URL, or plain domain-per-line sources.
- **Operations**: hot reload, Prometheus metrics, structured audit logs, memory protection, systemd/Docker/Kubernetes deployment assets, and backup/health-check scripts.
- **Management**: REST API with OpenAPI/Swagger, `dnsctl`, and an embedded React 19 dashboard with WebSocket query streaming and zone management.
- **Persistence and HA**: built-in KV/WAL storage, AXFR/IXFR support, slave zones, split-horizon views, GeoIP responses, and gossip/Raft clustering.

## Quick start

```bash
# Build the server and CLI with Go 1.26.5+
make build

# Run using the example configuration
go run ./cmd/nothingdns --config config.example.yaml

# Build the embedded web dashboard when frontend assets change
make build-web

# Run the short test suite
go test ./... -count=1 -short
```

Install scripts are available for packaged/binary-style setups:

```bash
# Linux/macOS
curl -fsSL https://raw.githubusercontent.com/NothingDNS/NothingDNS/main/install.sh | bash

# Windows PowerShell as Administrator
irm https://raw.githubusercontent.com/NothingDNS/NothingDNS/main/install.ps1 | iex
```

For Docker and Kubernetes examples, see [QUICK_START.md](QUICK_START.md) and [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Repository map

| Path | Purpose |
|---|---|
| `cmd/nothingdns/` | Server entry point and runtime wiring |
| `cmd/dnsctl/` | Management CLI |
| `internal/` | DNS protocol, resolver, API, DNSSEC, storage, clustering, transports, and support packages |
| `web/` | React dashboard source and build tooling |
| `internal/dashboard/static/dist/` | Embedded dashboard build output served by the Go binary |
| `deploy/` | systemd, Docker/Kubernetes, and Helm deployment assets |
| `docs/` | Architecture, configuration, operations, API, CLI, testing, performance, and release documentation |
| `examples/` | Example-oriented documentation |
| `scripts/` | Development, smoke-test, backup, and health-check helpers |

Generated runtime state and local build artifacts such as `nothingdns`, `dnsctl`, `bin/`, `logs/`, `zones/`, `clusters/`, `*.db`, and `cache.json` are intentionally ignored.

## Documentation

Start with the [documentation index](docs/README.md). Common entry points:

| Need | Document |
|---|---|
| Configuration fields and defaults | [docs/CONFIG_REFERENCE.md](docs/CONFIG_REFERENCE.md) |
| Operations, deployment, backup, monitoring | [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| REST API endpoints | [docs/API_REFERENCE.md](docs/API_REFERENCE.md) |
| Zone API details | [docs/API_ZONES.md](docs/API_ZONES.md) |
| `dnsctl` commands | [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) |
| Architecture and request pipeline | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Implementation notes | [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md) |
| Testing and fuzzing | [docs/TESTING.md](docs/TESTING.md) |
| Performance tuning/backlog | [docs/PERFORMANCE.md](docs/PERFORMANCE.md), [docs/PERF_BACKLOG.md](docs/PERF_BACKLOG.md) |
| Security policy | [SECURITY.md](SECURITY.md), [docs/SECURITY.md](docs/SECURITY.md) |
| Dependencies | [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) |
| Release history | [docs/CHANGELOG.md](docs/CHANGELOG.md) |
| Troubleshooting | [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) |

## Development

```bash
make build        # server + dnsctl
make build-web    # dashboard bundle
make test         # short Go tests
make test-full    # full Go tests
make lint         # go vet + gofmt check
make clean        # remove local binaries and coverage files
```

The web package uses npm scripts:

```bash
cd web
npm install
npm run build
npm run lint
```

## Configuration

Use [config.example.yaml](config.example.yaml) as the source-aligned example configuration. The full schema and hot-reload behavior are documented in [docs/CONFIG_REFERENCE.md](docs/CONFIG_REFERENCE.md).

## Contributing and license

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). NothingDNS is released under the [MIT License](LICENSE).
