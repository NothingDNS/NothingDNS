# NothingDNS CLI Reference

`dnsctl` is the command-line management tool for NothingDNS. It communicates with the NothingDNS server via REST API.

## Usage

```bash
dnsctl [global-flags] <command> [command-flags] [arguments]
```

### Global Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | `http://localhost:8080` | NothingDNS API server URL |
| `-api-key` | (empty) | API key for authentication |

### Examples

```bash
# Connect to local server (default)
dnsctl zone list

# Connect to remote server
dnsctl -server http://192.168.1.100:8080 zone list

# Use API key
dnsctl -api-key my-secret-key zone list
```

---

## zone — Zone Management

```bash
dnsctl zone [subcommand]
```

### zone list

List all configured zones.

```bash
dnsctl zone list
```

**Output**:
```
example.com.          3600    45 records   signed
internal.example.com. 1800    120 records  unsigned
```

### zone add

Add a new zone.

```bash
dnsctl zone add <zone-name> [nameserver]
```

**Examples**:
```bash
dnsctl zone add example.com
dnsctl zone add example.com ns1.example.com.
```

### zone remove

Remove a zone.

```bash
dnsctl zone remove <zone-name>
```

```bash
dnsctl zone remove example.com
```

### zone reload

Reload one zone from disk.

```bash
dnsctl zone reload <zone-name>
```

### zone export

Export zone to BIND format.

```bash
dnsctl zone export <zone-name>
```

```bash
dnsctl zone export example.com
# Save to a file with shell redirection
dnsctl zone export example.com > example.com.zone
```

---

## record — Record Management

```bash
dnsctl record [subcommand]
```

### record add

Add a DNS record.

```bash
dnsctl record add <zone> <name> <type> <value> [ttl]
```

**Examples**:
```bash
dnsctl record add example.com www A 192.168.1.100 3600
dnsctl record add example.com @ MX "10 mail.example.com." 3600
dnsctl record add example.com _sip._tcp SRV "10 60 5060 sip.example.com."
dnsctl record add example.com mail TXT "v=spf1 mx ~all"
```

### record remove

Remove a DNS record.

```bash
dnsctl record remove <zone> <name> <type>
```

```bash
dnsctl record remove example.com www A
dnsctl record remove example.com @ MX
```

### record update

Update a DNS record.

```bash
dnsctl record update <zone> <name> <type> <old-data> <new-data> [ttl]
```

### record list

List records in a zone.

```bash
dnsctl record list <zone>
```

```bash
dnsctl record list example.com
```

---

## cache — Cache Operations

```bash
dnsctl cache [subcommand]
```

### cache stats

Show cache statistics.

```bash
dnsctl cache stats
```

**Output**:
```
Cache Statistics
-----------------
Hits:         15,234
Misses:       1,234
Size:         5,432 / 10,000
Hit Ratio:    92.5%
Evictions:    12
Stale Hits:   45
```

### cache flush

Flush (clear) the cache.

```bash
dnsctl cache flush
```

---

## cluster — Cluster Management

```bash
dnsctl cluster [subcommand]
```

### cluster status

Show cluster status.

```bash
dnsctl cluster status
```

**Output**:
```
Cluster Status
--------------
Enabled:      Yes
Mode:         SWIM
Node ID:      node-1
Nodes:        3
Leader:       node-1
Cache Sync:   Enabled
```

### cluster peers

List cluster peers/nodes.

```bash
dnsctl cluster peers
```

**Output**:
```
NODE     ADDR              STATE    REGION    QUERIES/S  CACHE-HIT  LATENCY
node-1   172.28.0.10:7946  Alive    us-east   1,000      95%        2ms
node-2   172.28.0.11:7946  Alive    us-west   950        94%        3ms
node-3   172.28.0.12:7946  Alive    eu-west   980        93%        4ms
```

### cluster join

Join a cluster (from seed node).

```bash
dnsctl cluster join <seed-node-addr>
```

### cluster leave

Leave the cluster gracefully.

```bash
dnsctl cluster leave
```

---

## blocklist — Blocklist Management

```bash
dnsctl blocklist [subcommand]
```

### blocklist status

Show blocklist status.

```bash
dnsctl blocklist status
```

### blocklist sources

List configured blocklist sources.

```bash
dnsctl blocklist sources
```

### blocklist reload

Reload all blocklists.

```bash
dnsctl blocklist reload
```

---

## config — Configuration

```bash
dnsctl config [subcommand]
```

### config get

Get current configuration.

```bash
dnsctl config get
dnsctl config get server.http.bind
```

### config reload

Reload configuration from file.

```bash
dnsctl config reload
```

---

## dig — DNS Query Tool

A `dig`-compatible DNS query tool.

```bash
dnsctl dig [@server] [name] [type] [class] [options]
```

### Basic Queries

```bash
# A record
dnsctl dig example.com A

# AAAA record
dnsctl dig example.com AAAA

# MX record
dnsctl dig example.com MX

# TXT record
dnsctl dig example.com TXT

# SOA record
dnsctl dig example.com SOA
```

### Query Options

```bash
# Specific DNS server
dnsctl dig @1.1.1.1 example.com A

# DNSSEC validation
dnsctl dig +dnssec example.com A

# Check AD (Authentic Data) bit
dnsctl dig +ad example.com DNSKEY

# Short output
dnsctl dig +short example.com A

# TCP instead of UDP
dnsctl dig +tcp example.com A

# Trace delegation
dnsctl dig +trace example.com NS

# Reverse lookup
dnsctl dig -x 1.2.3.4
```

### Examples

```bash
# Full dig-compatible output
dnsctl dig example.com MX +multiline

# Time out after 5 seconds
dnsctl dig example.com A +time=5

# Use TCP
dnsctl dig example.com AXFR +tcp
```

---

## dnssec — DNSSEC Operations

```bash
dnsctl dnssec [subcommand]
```

### dnssec status

Show DNSSEC status.

```bash
dnsctl dnssec status
```

### dnssec generate-key

Generate DNSSEC key pair.

```bash
dnsctl dnssec generate-key --zone=<zone> [--algorithm=<algo>] [--bits=<size>] [--ksk|--zsk]
```

**Algorithms**: `rsasha256` (default), `rsasha512`, `ecdsap256sha256`, `ecdsap384sha384`, `ed25519`

**Examples**:
```bash
# Generate KSK
dnsctl dnssec generate-key --zone=example.com --ksk --algorithm=ecdsap256sha256

# Generate ZSK
dnsctl dnssec generate-key --zone=example.com --zsk --bits=1024
```

### dnssec sign-zone

Sign a zone.

```bash
dnsctl dnssec sign-zone --zone=<zone> [--active-keys]
```

```bash
dnsctl dnssec sign-zone --zone=example.com
```

### dnssec ds-from-dnskey

Get DS record from DNSKEY.

```bash
dnsctl dnssec ds-from-dnskey --zone=<zone> [--digest=<algorithm>]
```

**Algorithms**: `sha256` (default), `sha384`

```bash
dnsctl dnssec ds-from-dnskey --zone=example.com
dnsctl dnssec ds-from-dnskey --zone=example.com --digest=sha384
```

### dnssec verify

Verify DNSSEC signatures.

```bash
dnsctl dnssec verify --zone=<zone>
```

### dnssec key

Manage DNSSEC keys.

```bash
dnsctl dnssec key list --zone=<zone>
dnsctl dnssec key activate --zone=<zone> --key-id=<id>
dnsctl dnssec key deactivate --zone=<zone> --key-id=<id>
dnsctl dnssec key remove --zone=<zone> --key-id=<id>
```

---

## server — Server Operations

```bash
dnsctl server [subcommand]
```

### server status

Show server status.

```bash
dnsctl server status
```

**Output**:
```
Server Status:
  Status:    ok
  Version:   1.2.16
  Timestamp: 2026-07-06T12:00:00Z
  Cache:
    Size:     123
    Capacity: 10000
    Hits:     456
    Misses:   78
    Hit Ratio: 85.37%
  Cluster:
    Enabled: false
```

### server health

Check server health.

```bash
dnsctl server health
```

### server bootstrap

Create the first dashboard admin, or reset an admin's password, through the
localhost-only `POST /api/v1/auth/bootstrap` endpoint. Run it on the server host
(for the container image: `docker exec -i nothingdns dnsctl server bootstrap`).

The password is read from `NOTHINGDNS_ADMIN_PASSWORD` or the first line of
stdin — never from the command line, so it does not show up in process listings
or shell history.

| Flag | Default | Description |
|---|---|---|
| `--username NAME` | `admin` | Admin account to create or reset |
| `--old-password` | off | Also read the current password (`NOTHINGDNS_ADMIN_OLD_PASSWORD` or the second stdin line); needed to reset an existing, non-placeholder admin |

```bash
# Interactive (prompts on stderr, reads stdin)
dnsctl server bootstrap --username admin

# From a secret file inside the container
docker exec -i nothingdns dnsctl server bootstrap < admin-password.txt

# Reset an existing admin's password
printf '%s\n%s\n' "$NEW_PASSWORD" "$OLD_PASSWORD" | dnsctl server bootstrap --old-password
```

**Output**:
```
Admin account "admin" is ready. Sign in to the dashboard with it.
```

Users created this way persist in `server.http.users_file`
(default `<storage.data_dir>/users.json`).

---

## Global Commands

### version

Show version information.

```bash
dnsctl version
```

**Output**:
```
dnsctl version 1.2.16
```

`dnsctl -version` prints the same version line.

### help

Show help.

```bash
dnsctl help
dnsctl help <command>
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (see error message) |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NOTHINGDNS_SERVER` | Default server URL |
| `NOTHINGDNS_API_KEY` | Default API key |

---

## Configuration File

`dnsctl` can read defaults from `~/.config/dnsctl/config.yaml`:

```yaml
server: http://localhost:8080
api_key: your-api-key
timeout: 30s
```

---

## Examples

### Common Workflows

```bash
# Check server is running
dnsctl server health

# View all zones
dnsctl zone list

# Add a new record
dnsctl record add example.com api A 192.168.1.50 --ttl=3600

# Check cache performance
dnsctl cache stats

# View cluster status
dnsctl cluster status

# Flush cache after config change
dnsctl cache flush

# Reload a zone after editing its zone file
dnsctl zone reload example.com

# Verify DNSSEC is working
dnsctl dig +dnssec +ad example.com DNSKEY
```

### Scripting Examples

```bash
# Monitor cache statistics
watch -n1 'dnsctl cache stats'

# List records in a zone
dnsctl record list example.com

# Backup all zones
for zone in $(dnsctl zone list | awk '{print $1}'); do
  dnsctl zone export "$zone" > "${zone}.zone.bak"
done

# Check cache hit ratio
dnsctl cache stats | grep "Hit Ratio"
```
