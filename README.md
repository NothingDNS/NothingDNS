# NothingDNS

[![Go Version](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/nothingdns/nothingdns)](https://goreportcard.com/report/github.com/nothingdns/nothingdns)

A zero-dependency DNS server written in pure Go. NothingDNS is designed to be lightweight, fast, and self-contained with no external dependencies.

## Features

### Core DNS
- **Zero Dependencies** - Pure Go implementation, no external libraries
- **DNS Protocol Support** - Full RFC 1035 compliant DNS message handling
- **UDP & TCP** - Support for both UDP and TCP DNS queries
- **Caching** - Thread-safe LRU cache with TTL support and prefetching
- **Upstream Forwarding** - Multiple upstream servers with health checking and failover strategies

### Security
- **DNSSEC** - DNS Security Extensions validation and zone signing (RFC 4033/4034/4035)
- **DNS over HTTPS (DoH)** - RFC 8484 compliant DoH support
- **DNS over TLS (DoT)** - RFC 7858 compliant DoT support
- **Blocklist Support** - Block domains using hosts file format
- **ACL** - Access control lists for client filtering

### Authoritative
- **Authoritative Zones** - Zone file support for hosting your own DNS records
- **Slave Zones** - AXFR/IXFR zone transfer from master servers
- **Zone Transfer** - AXFR support for serving zones to secondary servers

### High Availability
- **Clustering** - Gossip-based cluster membership with cache synchronization
- **Anycast/Load Balancing** - Geographic load balancing with health checks
- **Hot Reload** - SIGHUP for configuration reload without downtime

### Storage & Persistence
- **KV Store** - Built-in key-value store with ACID transactions
- **WAL** - Write-ahead logging for crash recovery
- **TLV Serialization** - Efficient binary serialization

### Management & Observability
- **Web Dashboard** - Real-time query stream and statistics
- **HTTP API** - RESTful API for server management
- **MCP Server** - Model Context Protocol for AI assistant integration
- **Prometheus Metrics** - Export metrics for monitoring
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
  tls:
    enabled: false

resolution:
  timeout: "5s"

upstream:
  strategy: round_robin
  servers:
    - 1.1.1.1:53
    - 8.8.8.8:53

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
    networks:
      - 127.0.0.1/32
  - action: allow
    networks:
      - 10.0.0.0/8
  - action: deny
    networks:
      - 0.0.0.0/0
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

# DNSSEC operations
dnsctl dnssec generate-key --algorithm 13 --type KSK --zone example.com
dnsctl dnssec ds-from-dnskey --zone example.com --key-file Kexample.com.+013+12345.key

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
| `/api/v1/cluster/status` | GET | Cluster health and statistics |
| `/api/v1/cluster/nodes` | GET | List all cluster nodes |
| `/api/dashboard/stats` | GET | Dashboard statistics |
| `/api/dashboard/queries` | GET | Recent queries |
| `/api/dashboard/zones` | GET | Zone list for dashboard |
| `/ws` | WS | WebSocket for live query stream |
| `/` | GET | Web dashboard UI |

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

## DNS over TLS (DoT)

NothingDNS supports RFC 7858 compliant DNS over TLS (DoT). DoT provides encrypted DNS resolution using TLS on port 853, preventing eavesdropping and tampering.

### Configuration

```yaml
server:
  port: 5353
  bind:
    - 0.0.0.0
  tls:
    enabled: true
    bind: "0.0.0.0:853"
    cert_file: "/etc/nothingdns/certs/server.crt"
    key_file: "/etc/nothingdns/certs/server.key"
```

### Usage

DoT uses standard DNS message format over a TLS connection on port 853:

**Using kdig:**
```bash
kdig @localhost +tls-ca +tls-host=localhost www.example.com
```

**Using systemd-resolved:**
```bash
# Add to /etc/systemd/resolved.conf.d/dot.conf
[Resolve]
DNS=localhost:853
DNSOverTLS=yes
```

**Using Android/iOS:**
Configure private DNS with hostname pointing to your DoT server.

### Security Notes

- TLS certificate must be valid and trusted by clients
- Default port is 853 (can be customized via bind address)
- Certificate should include the hostname clients use to connect
- Self-signed certificates work for testing but require client configuration

## DNSSEC

NothingDNS supports DNSSEC (DNS Security Extensions) for both validation and zone signing. DNSSEC provides authentication and integrity protection for DNS data through digital signatures.

### DNSSEC Validation

When enabled, NothingDNS validates DNSSEC signatures from upstream servers:

```yaml
dnssec:
  enabled: true
  require_dnssec: false    # Fail queries if DNSSEC validation fails
  ignore_time: false       # Ignore signature timestamps (for testing)
  trust_anchor: ""         # Path to RFC 7958 trust anchor file (optional)
```

### Zone Signing

NothingDNS can sign authoritative zones with DNSSEC:

```yaml
dnssec:
  enabled: true
  signing:
    enabled: true
    signature_validity: "720h"    # 30 days
    keys:
      - private_key: /etc/nothingdns/keys/ksk.pem
        type: ksk
        algorithm: 13               # ECDSAP256SHA256
      - private_key: /etc/nothingdns/keys/zsk.pem
        type: zsk
        algorithm: 13
    nsec3:
      iterations: 10
      salt: "aabbccdd"
      opt_out: false
```

### Supported Algorithms

| Algorithm | Number | Status |
|-----------|--------|--------|
| RSA/SHA-256 | 8 | Supported |
| RSA/SHA-512 | 10 | Supported |
| ECDSA P-256/SHA-256 | 13 | Recommended |
| ECDSA P-384/SHA-384 | 14 | Supported |

### DNSSEC CLI Commands

The `dnsctl` tool provides DNSSEC management:

```bash
# Generate a KSK (Key Signing Key)
dnsctl dnssec generate-key \
  --algorithm 13 \
  --type KSK \
  --zone example.com \
  --output /etc/nothingdns/keys/

# Generate a ZSK (Zone Signing Key)
dnsctl dnssec generate-key \
  --algorithm 13 \
  --type ZSK \
  --zone example.com \
  --output /etc/nothingdns/keys/

# Create DS record from DNSKEY
dnsctl dnssec ds-from-dnskey \
  --zone example.com \
  --key-file Kexample.com.+013+12345.key

# Sign a zone file
dnsctl dnssec sign-zone \
  --input example.com.zone \
  --output example.com.signed

# Verify trust anchor file
dnsctl dnssec verify-anchor root-anchors.xml
```

### DNSSEC Testing

Test DNSSEC validation using `dig`:

```bash
# Query with DNSSEC (requests RRSIG records)
dig @localhost +dnssec www.isc.org

# Check AD (Authenticated Data) bit
dig @localhost +dnssec +adflag www.isc.org | grep "flags:"

# Trace DNSSEC validation
dig @localhost +dnssec +trace www.isc.org
```

## Clustering

NothingDNS supports clustering for high availability and cache synchronization across multiple nodes. The clustering implementation uses a gossip-based membership protocol (SWIM-like) with UDP-based communication.

### Features

- **Automatic Node Discovery** - Nodes automatically join and discover other cluster members
- **Failure Detection** - Automatic detection of failed nodes with suspect/dead states
- **Cache Synchronization** - Cross-node cache invalidation broadcasts
- **Quorum-based Health** - Cluster health based on majority of alive nodes
- **Region/Zone Support** - Organize nodes by region and zone for topology awareness
- **Prometheus Metrics** - Export cluster metrics (node count, health, gossip stats)

### Configuration

```yaml
cluster:
  enabled: true
  node_id: ""              # Auto-generated if empty
  bind_addr: ""            # Auto-detect if empty
  gossip_port: 7946        # UDP port for gossip protocol
  region: "us-east"
  zone: "us-east-1a"
  weight: 100              # Load balancing weight
  seed_nodes:              # Initial nodes to join
    - "10.0.1.10:7946"
    - "10.0.1.11:7946"
  cache_sync: true         # Enable cache invalidation sync
```

### How It Works

1. **Node Join**: When a node starts, it joins the cluster by connecting to seed nodes
2. **Gossip Protocol**: Nodes periodically exchange membership information via UDP
3. **Failure Detection**: Uses indirect pings and suspect state before marking nodes dead
4. **Cache Sync**: Cache invalidations are broadcast to all nodes when entries are deleted
5. **Health Check**: Cluster is healthy when majority of nodes (quorum) are alive

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/cluster/status` | GET | Cluster health and statistics |
| `/api/v1/cluster/nodes` | GET | List all cluster nodes |

### Prometheus Metrics

Cluster metrics are automatically exported:

```
nothingdns_cluster_nodes_total 3
nothingdns_cluster_nodes_alive 3
nothingdns_cluster_healthy 1
nothingdns_cluster_gossip_messages_sent_total 1234
nothingdns_cluster_gossip_messages_received_total 1230
```

### Running a Cluster

**Node 1:**
```bash
# config-node1.yaml
cluster:
  enabled: true
  node_id: "node-1"
  bind_addr: "10.0.1.10"
  gossip_port: 7946
  region: "us-east"
  cache_sync: true

./nothingdns -config config-node1.yaml
```

**Node 2:**
```bash
# config-node2.yaml
cluster:
  enabled: true
  node_id: "node-2"
  bind_addr: "10.0.1.11"
  gossip_port: 7946
  region: "us-east"
  seed_nodes:
    - "10.0.1.10:7946"
  cache_sync: true

./nothingdns -config config-node2.yaml
```

**Node 3:**
```bash
# config-node3.yaml
cluster:
  enabled: true
  node_id: "node-3"
  bind_addr: "10.0.1.12"
  gossip_port: 7946
  region: "us-east"
  seed_nodes:
    - "10.0.1.10:7946"
  cache_sync: true

./nothingdns -config config-node3.yaml
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           NothingDNS                                     │
├─────────────────────────────────────────────────────────────────────────┤
│  UDP Server  │  TCP Server  │  DoH Server  │  DoT Server  │  Dashboard  │
├──────────────────────────────────────────────────────────────────────────┤
│                          Request Handler                                  │
│  ┌─────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────────────┐  │
│  │  Cache  │→ │ Auth Zones  │→ │  Upstream   │→ │ DNSSEC Validator   │  │
│  │ (LRU)   │  │ + Transfer  │  │ + Anycast   │  │                    │  │
│  └────↑────┘  └─────────────┘  └─────────────┘  └────────────────────┘  │
│       │                       ┌───────────────────────────────────────┐  │
│       │                       │         Storage Layer                 │  │
│       └───────────────────────│  KV Store │ WAL │ TLV Serialization  │  │
│                               └───────────────────────────────────────┘  │
│       │         ┌──────────────────────────────┐                        │
│       └────────→│      Cluster Manager         │                        │
│                 │   (Gossip / Cache Sync)      │                        │
│                 └──────────────────────────────┘                        │
├─────────────────────────────────────────────────────────────────────────┤
│                    API Layer (HTTP + MCP)                                │
├─────────────────────────────────────────────────────────────────────────┤
│                    Config Parser (YAML) + Hot Reload                     │
└─────────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
.
├── cmd/
│   ├── nothingdns/     # Main DNS server binary
│   └── dnsctl/         # CLI management tool
├── internal/
│   ├── api/            # HTTP API for management
│   │   └── mcp/        # MCP server for AI integration
│   ├── cache/          # LRU cache with TTL
│   ├── cluster/        # Gossip-based clustering
│   ├── config/         # YAML configuration parser
│   ├── dashboard/      # Web dashboard
│   ├── dnssec/         # DNSSEC validation and signing
│   ├── doh/            # DNS over HTTPS (RFC 8484)
│   ├── dot/            # DNS over TLS (RFC 7858)
│   ├── metrics/        # Prometheus metrics export
│   ├── protocol/       # DNS protocol implementation
│   ├── server/         # UDP/TCP server handlers
│   ├── storage/        # KV store with WAL
│   ├── transfer/       # Zone transfer (AXFR/IXFR)
│   ├── upstream/       # Upstream DNS client
│   ├── util/           # Logging utilities
│   └── zone/           # Zone file parser
├── Dockerfile
├── docker-compose.yml
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
- DS (Delegation Signer)
- DNSKEY (DNS Public Key)
- RRSIG (Resource Record Signature)
- NSEC/NSEC3 (Authenticated Denial of Existence)

## Upstream Strategies

- **round_robin** - Rotate through upstream servers
- **random** - Random selection
- **fastest** - Use the fastest responding server

## Docker

### Quick Start with Docker

```bash
# Build the image
docker build -t nothingdns:latest .

# Run with default configuration
docker run -d -p 53:53/udp -p 53:53 -p 8080:8080 nothingdns:latest

# Run with custom configuration
docker run -d \
  -p 53:53/udp \
  -p 53:53 \
  -p 8080:8080 \
  -v /etc/nothingdns:/etc/nothingdns \
  nothingdns:latest -config /etc/nothingdns/config.yaml
```

### Docker Compose Cluster

```yaml
# docker-compose.yml
version: '3.8'

services:
  nothingdns-1:
    image: nothingdns:latest
    hostname: nothingdns-1
    ports:
      - "53:53/udp"
      - "53:53"
      - "8080:8080"
    volumes:
      - ./config-node1.yaml:/etc/nothingdns/config.yaml
      - ./zones:/etc/nothingdns/zones
    networks:
      - dns-net

  nothingdns-2:
    image: nothingdns:latest
    hostname: nothingdns-2
    ports:
      - "5354:53/udp"
      - "5354:53"
      - "8081:8080"
    volumes:
      - ./config-node2.yaml:/etc/nothingdns/config.yaml
      - ./zones:/etc/nothingdns/zones
    networks:
      - dns-net

  nothingdns-3:
    image: nothingdns:latest
    hostname: nothingdns-3
    ports:
      - "5355:53/udp"
      - "5355:53"
      - "8082:8080"
    volumes:
      - ./config-node3.yaml:/etc/nothingdns/config.yaml
      - ./zones:/etc/nothingdns/zones
    networks:
      - dns-net

networks:
  dns-net:
    driver: bridge
```

## Web Dashboard

NothingDNS includes a built-in web dashboard for real-time monitoring:

```yaml
server:
  http:
    enabled: true
    bind: "0.0.0.0:8080"
```

Access the dashboard at `http://localhost:8080/`

### Dashboard Features

- Real-time query stream via WebSocket
- Statistics cards (queries, cache hit rate, blocked, zones)
- Live query visualization with status badges
- Auto-reconnecting WebSocket connection

## MCP Server (AI Integration)

NothingDNS provides a Model Context Protocol (MCP) server for AI assistant integration:

```yaml
server:
  http:
    enabled: true
    bind: "0.0.0.0:8080"
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `dns_query` | Query DNS records for a domain |
| `zone_list` | List all configured zones |
| `zone_get` | Get details of a specific zone |
| `zone_create` | Create a new zone |
| `zone_delete` | Delete a zone |
| `record_add` | Add a DNS record to a zone |
| `record_delete` | Delete a DNS record |
| `record_list` | List records in a zone |
| `cache_stats` | Get cache statistics |
| `cache_flush` | Flush the DNS cache |
| `blocklist_check` | Check if a domain is blocked |
| `server_stats` | Get server statistics |

## Storage & Persistence

NothingDNS includes a built-in key-value store with WAL support.

### Features

- ACID transactions with atomic writes
- Write-ahead logging (WAL) for crash recovery
- TLV binary serialization for efficiency
- Cursor-based iteration
- Bucket-based organization

## Hot Reload

Send `SIGHUP` to reload configuration without downtime:

```bash
# Reload configuration
kill -HUP $(pidof nothingdns)

# Or via CLI
dnsctl config reload
```

### Reloadable Components

- Zone files
- Blocklist files
- ACL rules
- Rate limits
- TLS certificates
- Log level

## Comparison

| Feature | NothingDNS | CoreDNS | PowerDNS | Unbound |
|---------|------------|---------|----------|---------|
| Zero Dependencies | ✅ | ❌ | ❌ | ❌ |
| Pure Go | ✅ | ✅ | ❌ | ❌ |
| DNSSEC Validation | ✅ | ✅ | ✅ | ✅ |
| DNSSEC Signing | ✅ | ❌ | ✅ | ❌ |
| DoH Support | ✅ | ✅ | ✅ | ✅ |
| DoT Support | ✅ | ✅ | ✅ | ✅ |
| Web Dashboard | ✅ | ❌ | ✅ | ❌ |
| MCP/AI Integration | ✅ | ❌ | ❌ | ❌ |
| Built-in Clustering | ✅ | ✅ | ✅ | ❌ |
| Zone Transfer (AXFR) | ✅ | ✅ | ✅ | ❌ |
| Anycast LB | ✅ | ❌ | ❌ | ❌ |
| Hot Reload | ✅ | ✅ | ✅ | ✅ |
| Memory Footprint | ~10MB | ~30MB | ~50MB | ~20MB |

## Systemd Service

Create `/etc/systemd/system/nothingdns.service`:

```ini
[Unit]
Description=NothingDNS Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/nothingdns -config /etc/nothingdns/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
systemctl enable nothingdns
systemctl start nothingdns

# Reload configuration
systemctl reload nothingdns
```

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass (`go test ./...`)
2. Code follows Go conventions (`go fmt`, `go vet`)
3. New features include tests

## Roadmap

- [x] DNSSEC validation and signing
- [x] HTTP API for management
- [x] Clustering support
- [x] Blocklist support (hosts file format)
- [x] Metrics export (Prometheus)
- [x] DoH (DNS over HTTPS) support
- [x] DoT (DNS over TLS) support
- [x] Web dashboard
- [x] MCP server for AI integration
- [x] Storage & persistence (KV store + WAL)
- [x] Anycast/Load balancing
- [x] Slave zone support (AXFR/IXFR)
- [x] Configuration hot reload
- [x] Production-ready code quality (see [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md))
- [ ] Web GUI for zone management
- [ ] DNS64/NAT64 support
- [ ] Response Rate Limiting (RRL)
- [ ] Ed25519 DNSSEC signing support
