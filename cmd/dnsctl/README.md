# dnsctl - NothingDNS CLI Tool

> Command-line management tool for NothingDNS

## Overview

`dnsctl` is the official CLI tool for managing NothingDNS servers. It communicates with the NothingDNS REST API to perform zone management, record operations, cache control, cluster administration, and more.

## Installation

```bash
# Build from source
go build -o dnsctl ./cmd/dnsctl

# Or install directly
go install github.com/nothingdns/nothingdns/cmd/dnsctl@latest
```

## Global Options

| Option | Default | Description |
|--------|---------|-------------|
| `-server` | `http://localhost:8080` | NothingDNS API server URL |
| `-api-key` | (none) | API key for authentication |

## Commands

### `zone` - DNS Zone Management

Manage DNS zones (authoritative domains).

```bash
# List all zones
dnsctl zone list

# Add a new zone
dnsctl zone add example.com

# Add a zone with custom nameserver
dnsctl zone add example.com ns1.example.com.

# Remove a zone
dnsctl zone remove example.com

# Reload zone from file
dnsctl zone reload example.com

# Export zone to BIND format
dnsctl zone export example.com
```

**Note**: All `zone` subcommands are fully implemented.

---

### `record` - DNS Record Management

Manage DNS records within zones.

```bash
# List records in a zone
dnsctl record list example.com

# Add an A record
dnsctl record add example.com www A 192.0.2.1 300

# Add an AAAA record
dnsctl record add example.com www AAAA 2001:db8::1 300

# Add a CNAME record
dnsctl record add example.com blog CNAME example.wordpress.com. 300

# Remove a record
dnsctl record remove example.com www A

# Update a record
dnsctl record update example.com www A 192.0.2.1 192.0.2.2 300
```

**Note**: All `record` subcommands are fully implemented.

---

### `cache` - Cache Operations

Control the DNS cache.

```bash
# Flush all cache entries
dnsctl cache flush

# Flush cache for specific name
dnsctl cache flush www.example.com

# Show cache statistics
dnsctl cache stats
```

---

### `cluster` - Cluster Management

View cluster status and peers.

```bash
# Show cluster status
dnsctl cluster status

# List cluster peers/nodes
dnsctl cluster peers
```

**Note**: Clustering must be enabled in NothingDNS configuration.

---

### `blocklist` - Blocklist Management

Manage DNS blocklists.

```bash
# Show blocklist statistics
dnsctl blocklist status

# List blocklist sources
dnsctl blocklist sources
```

---

### `config` - Configuration Operations

Manage server configuration.

```bash
# Get current configuration
dnsctl config get

# Reload configuration from disk
dnsctl config reload
```

---

### `dig` - DNS Query Tool

Built-in DNS query tool (similar to standard `dig`).

```bash
# Simple query
dnsctl dig example.com

# Query specific server
dnsctl dig @localhost example.com

# Query specific type
dnsctl dig example.com AAAA

# Query with DNSSEC
dnsctl dig @localhost example.com A +dnssec
```

---

### `dnssec` - DNSSEC Operations

Manage DNSSEC keys and signing.

```bash
# Generate a new DNSSEC key pair
dnsctl dnssec generate-key --algorithm 13 --type KSK --zone example.com

# Create DS record from DNSKEY
dnsctl dnssec ds-from-dnskey --zone example.com --keyfile Kexample.com.+013+12345.key

# Sign a zone file
dnsctl dnssec sign-zone --zone example.com --input example.com.zone

# Verify trust anchor file
dnsctl dnssec verify-anchor --file /etc/nothingdns/dnssec/trust-anchor.conf
```

**Supported Algorithms**:
- 5 (RSA/SHA-1) - Not recommended
- 7 (RSASHA1-NSEC3-SHA1) - Not recommended
- 8 (RSA/SHA-256)
- 10 (RSA/SHA-512)
- 13 (ECDSA P-256 with SHA-256)
- 14 (ECDSA P-384 with SHA-384)
- 15 (Ed25519)

---

### `server` - Server Operations

Check server health and statistics.

```bash
# Show server status
dnsctl server status

# Show query statistics
dnsctl server stats

# Check server health
dnsctl server health
```

---

## Authentication

`dnsctl` supports API key authentication via the `-api-key` flag:

```bash
dnsctl -server https://dns.example.com:8080 -api-key "my-api-key" zone list
```

Alternatively, set the `NONDNS_API_KEY` environment variable:

```bash
export NONDNS_API_KEY="my-api-key"
dnsctl -server https://dns.example.com:8080 zone list
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error (command failed, connection error) |
| 2 | Invalid arguments or usage error |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NONDNS_SERVER` | Default server URL (overrides `-server` default) |
| `NONDNS_API_KEY` | API key for authentication |

---

## Examples

### Complete Zone Setup

```bash
# Create a new zone
dnsctl zone add example.com ns1.example.com.

# Add A records
dnsctl record add example.com @ A 192.0.2.1 3600
dnsctl record add example.com www A 192.0.2.1 3600
dnsctl record add example.com mail A 192.0.2.2 3600

# Add MX record
dnsctl record add example.com @ MX "10 mail.example.com." 3600

# Add TXT record for SPF
dnsctl record add example.com @ TXT "v=spf1 mx ~all" 3600
```

### DNSSEC Setup

```bash
# Generate KSK
dnsctl dnssec generate-key --algorithm 13 --type KSK --zone example.com

# Generate ZSK
dnsctl dnssec generate-key --algorithm 13 --type ZSK --zone example.com

# Sign the zone
dnsctl dnssec sign-zone --zone example.com --input /etc/nothingdns/zones/example.com.zone

# Get DS record for parent zone
dnsctl dnssec ds-from-dnskey --zone example.com --keyfile Kexample.com.+013+12345.key
```

---

## REST API Mapping

All `dnsctl` commands map to REST API endpoints:

| Command | HTTP Method | Endpoint |
|---------|-------------|----------|
| `zone list` | GET | `/api/v1/zones` |
| `zone add` | POST | `/api/v1/zones` |
| `zone remove` | DELETE | `/api/v1/zones/{zone}` |
| `zone reload` | POST | `/api/v1/zones/reload?zone={zone}` |
| `record list` | GET | `/api/v1/zones/{zone}/records` |
| `record add` | POST | `/api/v1/zones/{zone}/records` |
| `record remove` | DELETE | `/api/v1/zones/{zone}/records` |
| `record update` | PUT | `/api/v1/zones/{zone}/records` |
| `cache flush` | POST | `/api/v1/cache/flush` |
| `cache stats` | GET | `/api/v1/cache/stats` |
| `cluster status` | GET | `/api/v1/cluster/status` |
| `cluster peers` | GET | `/api/v1/cluster/nodes` |
| `blocklist status` | GET | `/api/v1/blocklists` |
| `config get` | GET | `/api/v1/server/config` |
| `config reload` | POST | `/api/v1/config/reload` |
| `server status` | GET | `/api/v1/status` |
| `server stats` | GET | `/api/dashboard/stats` |
| `server health` | GET | `/health` |

---

## See Also

- [NothingDNS Documentation](../docs/)
- [API Reference](../docs/SPECIFICATION.md)
- [Security Policy](../docs/SECURITY.md)
