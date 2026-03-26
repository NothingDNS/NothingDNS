# NothingDNS

A zero-dependency DNS server written in pure Go. NothingDNS is designed to be lightweight, fast, and self-contained with no external dependencies.

## Features

- **Zero Dependencies** - Pure Go implementation, no external libraries
- **DNS Protocol Support** - Full RFC 1035 compliant DNS message handling
- **Caching** - Thread-safe LRU cache with TTL support and prefetching
- **Upstream Forwarding** - Multiple upstream servers with health checking and failover strategies (round_robin, random, fastest, backup)
- **Authoritative Zones** - Zone file support for hosting your own DNS records
- **UDP & TCP** - Support for both UDP and TCP DNS queries
- **DNS over HTTPS (DoH)** - RFC 8484 compliant DoH support via HTTP API
- **Signal Handling** - Graceful shutdown (SIGINT/SIGTERM) and configuration reload (SIGHUP)
- **Blocklist Support** - Block domains using hosts file format
- **Prometheus Metrics** - Export metrics for monitoring and observability
- **HTTP API** - RESTful API for server management and monitoring
- **Management CLI** - `dnsctl` tool for zone and server management

## Quick Start

### Build

```bash
# Build the server
go build -o nothingdns ./cmd/nothingdns

# Build the CLI tool
go build -o dnsctl ./cmd/dnsctl
```

### Run

```bash
# Start with default configuration
./nothingdns

# Start with custom config
./nothingdns -config /path/to/config.yaml
```

### Test

```bash
go test ./...
```

## Configuration

Create a `nothingdns.yaml` file:

```yaml
server:
  port: 5353
  bind:
    - 0.0.0.0
  tls_enabled: false

upstream:
  strategy: round_robin
  servers:
    - 1.1.1.1:53
    - 8.8.8.8:53
  timeout: 5
  tls_preferred: true

cache:
  size: 10000
  min_ttl: 300
  max_ttl: 86400
  default_ttl: 3600
  negative_ttl: 60
  prefetch: true
  prefetch_threshold: 28800

logging:
  level: info
  format: text
  output: stdout

zones:
  - /etc/nothingdns/zones/example.com.zone

acl:
  - action: allow
    cidr: 127.0.0.1/32
  - action: allow
    cidr: 10.0.0.0/8
  - action: deny
    cidr: 0.0.0.0/0
```

## Zone File Format

NothingDNS uses a simple zone file format:

```
$ORIGIN example.com.
$TTL 3600

@   IN  SOA ns1.example.com. admin.example.com. (
            2024010101  ; Serial
            3600        ; Refresh
            1800        ; Retry
            604800      ; Expire
            86400 )     ; Minimum TTL

@       IN  A       192.0.2.1
www     IN  A       192.0.2.2
mail    IN  A       192.0.2.3
@       IN  MX  10  mail.example.com.
@       IN  NS      ns1.example.com.
@       IN  TXT     "v=spf1 include:_spf.example.com ~all"
```

## CLI Usage

The `dnsctl` tool provides management capabilities:

```bash
# Check server status
dnsctl server status

# List zones
dnsctl zone list

# Reload zones
dnsctl zone reload example.com

# Cache operations
dnsctl cache stats
dnsctl cache flush

# Configuration reload
dnsctl config reload
```

## HTTP API

NothingDNS provides a RESTful HTTP API for management and monitoring:

```yaml
server:
  http:
    enabled: true
    bind: "127.0.0.1:8080"
    auth_token: "your-secret-token"  # Optional
```

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/v1/status` | GET | Server status and cache stats |
| `/api/v1/zones` | GET | List loaded zones |
| `/api/v1/zones/reload?zone=<name>` | POST | Reload a zone |
| `/api/v1/cache/stats` | GET | Cache statistics |
| `/api/v1/cache/flush` | POST | Flush the cache |
| `/api/v1/config/reload` | POST | Reload configuration |

### Authentication

When `auth_token` is configured, include it via header or query parameter:

```bash
# Via header
curl -H "Authorization: Bearer your-secret-token" http://localhost:8080/api/v1/status

# Via query parameter
curl http://localhost:8080/api/v1/status?token=your-secret-token
```

## DNS over HTTPS (DoH)

NothingDNS supports RFC 8484 compliant DNS over HTTPS (DoH). DoH provides encrypted DNS resolution over HTTPS, preventing eavesdropping and tampering.

### Configuration

```yaml
server:
  http:
    enabled: true
    bind: "0.0.0.0:8080"
    auth_token: "your-secret-token"  # Optional - not required for DoH
    doh_enabled: true                # Enable DoH endpoint
    doh_path: "/dns-query"           # DoH endpoint path (default: /dns-query)
```

### Usage

DoH supports both GET and POST methods as per RFC 8484:

**GET Request:**
```bash
# Encode DNS query in base64url
dns_query=$(echo -n 'AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB' | base64 -d | base64 -w0 | tr '+/' '-_' | tr -d '=')
curl "http://localhost:8080/dns-query?dns=${dns_query}"
```

**POST Request:**
```bash
curl -X POST http://localhost:8080/dns-query \
  -H "Content-Type: application/dns-message" \
  --data-binary @dns-query.bin
```

**Using dig:**
```bash
dig @localhost -p 8080 +https www.example.com
```

### Security Notes

- The DoH endpoint does not require authentication (following RFC 8484)
- Management API endpoints still require auth_token when configured
- DoH responses include `X-Content-Type-Options: nosniff` header

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        NothingDNS                            │
├─────────────────────────────────────────────────────────────┤
│  UDP Server    │    TCP Server    │    Signal Handler       │
├────────────────┴──────────────────┴─────────────────────────┤
│                    Request Handler                           │
│  ┌─────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  Cache  │→ │Auth Zones   │→ │   Upstream Client       │  │
│  │ (LRU)   │  │             │  │  (Health Check/Failover)│  │
│  └─────────┘  └─────────────┘  └─────────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                    Config Parser (YAML)                      │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
.
├── cmd/
│   ├── nothingdns/     # Main DNS server binary
│   └── dnsctl/         # CLI management tool
├── internal/
│   ├── api/            # HTTP API for management
│   ├── cache/          # LRU cache with TTL
│   ├── config/         # YAML configuration parser
│   ├── doh/            # DNS over HTTPS (RFC 8484)
│   ├── metrics/        # Prometheus metrics export
│   ├── protocol/       # DNS protocol implementation
│   ├── server/         # UDP/TCP server handlers
│   ├── upstream/       # Upstream DNS client
│   ├── util/           # Logging utilities
│   └── zone/           # Zone file parser
└── go.mod
```

## Supported Record Types

- A (IPv4 address)
- AAAA (IPv6 address)
- CNAME (Canonical name)
- MX (Mail exchange)
- NS (Name server)
- TXT (Text record)
- SOA (Start of authority)
- PTR (Pointer)
- SRV (Service locator)

## Upstream Strategies

- **round_robin** - Rotate through upstream servers
- **random** - Random selection
- **fastest** - Use the fastest responding server
- **backup** - Use primary unless it fails

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass (`go test ./...`)
2. Code follows Go conventions (`go fmt`, `go vet`)
3. New features include tests

## Roadmap

- [ ] DNSSEC validation and signing
- [x] HTTP API for management
- [ ] Clustering support
- [x] Blocklist support (hosts file format)
- [x] Metrics export (Prometheus)
- [x] DoH (DNS over HTTPS) support
- [ ] DoT (DNS over TLS) support
