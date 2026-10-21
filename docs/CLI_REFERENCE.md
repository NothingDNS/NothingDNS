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

A small `dig`-style query tool: one question, sent over UDP, printed in dig's
section layout. It is not a full `dig`; the options it supports are listed below.

```bash
dnsctl dig [@server] <name> [<type>] [IN] [+dnssec] [+cd]
```

The arguments may come in any order: `@server`, the name, the type, and the
`+` option. It does not read the global `-server` option and does not use the API.

| Argument | Meaning |
|---|---|
| `@server` | Resolver to query: an IPv4 or IPv6 address or a host name, with an optional port (`@1.1.1.1`, `@[2001:db8::1]:5353`, `@2001:db8::1`). Default `127.0.0.1`, port 53. |
| `<name>` | Name to look up; a trailing dot is optional. Required. |
| `<type>` | Record type mnemonic (`A`, `AAAA`, `MX`, `TXT`, `SOA`, `NS`, `DNSKEY`, …). Default `A`. An unknown mnemonic is an error. |
| `+dnssec` | Set the DO bit in an EDNS0 OPT record (4096-byte payload), so the answer carries DNSSEC records. |
| `+cd` | Set the CD (checking disabled) bit in the query. |
| `IN` | The query class; accepted (before or after the type) and ignored, because queries are always class IN. |

```bash
dnsctl dig example.com A
dnsctl dig example.com MX
dnsctl dig @1.1.1.1 example.com AAAA
dnsctl dig @localhost example.com DNSKEY +dnssec
dnsctl dig @127.0.0.1:5354 example.com SOA
```

### Behavior

- One query goes out over UDP with a 5-second deadline. A response with the TC
  bit set is retried once over TCP; if that fails, a warning is printed and the
  truncated answer is shown.
- Only a datagram that answers this query (same ID, QR set) is accepted; others
  are skipped until the deadline.
- The output shows the header and flags, then the question, answer, authority
  and additional sections, `SERVER` and `WHEN`. The `Query time` line is a fixed
  `~0ms` placeholder, not a measurement.

### Rejected, not ignored

dnsctl dig stops with an error, and sends no query, for anything it does not do:

- Any `+option` other than `+dnssec` and `+cd` (`+short`, `+tcp`, `+trace`,
  `+multiline`, `+time=N`, `+ad`, …): `unsupported option +short (dnsctl dig
  supports +dnssec and +cd)`.
- A class other than IN (`CH`, `HS`): `query class CH is not supported (only IN)`.
- Any argument starting with `-` (`-x`, `-p`, `--server`, …).
- A third positional argument (`unexpected argument …`). `ANY` after the name is
  the record type, not a class.

There is no delegation tracing, zone transfer or output formatting. For a
reverse lookup, query the `in-addr.arpa` / `ip6.arpa` name with type `PTR`:

```bash
dnsctl dig @127.0.0.1 10.2.0.192.in-addr.arpa PTR
```

---

## dnssec — DNSSEC Operations

```bash
dnsctl dnssec <subcommand> [options]
```

`status` and `keys` ask the server over the API. The other subcommands work on
local files and need no server. Options are Go-style flags: `--zone example.com`
and `--zone=example.com` are both accepted.

### dnssec status

Show the server's DNSSEC validation and signing status.

```bash
dnsctl dnssec status
```

### dnssec keys

List the signing keys of each signed zone (zone, key tag, algorithm, KSK/ZSK).
Requires the admin role.

```bash
dnsctl dnssec keys
```

### dnssec generate-key

Generate a key pair and write the key files.

```bash
dnsctl dnssec generate-key --zone <zone> [--algorithm <n>] [--type KSK|ZSK] [--keysize <bits>] [--output <dir>]
```

| Option | Default | Meaning |
|---|---|---|
| `--zone` | (required) | Zone name |
| `--algorithm` | `13` | DNSSEC algorithm number: `8` RSASHA256, `10` RSASHA512, `13` ECDSAP256SHA256, `14` ECDSAP384SHA384, `15` ED25519 |
| `--type` | `ZSK` | `KSK` or `ZSK` |
| `--keysize` | `0` (RSA: 2048) | Key size in bits, RSA only |
| `--output` | `.` | Directory for the key files |

It writes `K<zone>.+<algorithm>+<tag>.key` and `.private`, and prints the key
tag and, for a KSK, its DS record.

```bash
dnsctl dnssec generate-key --zone example.com --type KSK --algorithm 13
dnsctl dnssec generate-key --zone example.com --type ZSK --algorithm 8 --keysize 2048
```

### dnssec ds-from-dnskey

Print the DS record for a public key file.

```bash
dnsctl dnssec ds-from-dnskey --zone <zone> --keyfile <file.key> [--digest <n>]
```

`--digest` is a digest type number: `2` SHA-256 (default), `1` SHA-1, `4` SHA-384.

```bash
dnsctl dnssec ds-from-dnskey --zone example.com --keyfile Kexample.com.+013+12345.key
dnsctl dnssec ds-from-dnskey --zone example.com --keyfile Kexample.com.+013+12345.key --digest 4
```

### dnssec sign-zone

Sign a zone file offline and write the signed zone. This does not touch the
running server.

```bash
dnsctl dnssec sign-zone --zone <zone> --input <zonefile> [--output <file>] [--keydir <dir>]
                        [--algorithm <n>] [--keysize <bits>] [--nsec3 [--iterations <n>] [--salt <hex>]]
                        [--validity <duration>]
```

| Option | Default | Meaning |
|---|---|---|
| `--zone` | (required) | Zone name |
| `--input` | (required) | Zone file to sign |
| `--output` | `<input>.signed` | Signed zone file to write |
| `--keydir` | `.` | Directory searched for the zone's `K<zone>.+…` key files |
| `--algorithm` | `13` | Algorithm for keys generated when `--keydir` has none (3 to 16) |
| `--keysize` | `0` | RSA key size in bits; required for RSA algorithms |
| `--nsec3` | off | Use NSEC3 instead of NSEC |
| `--iterations` | `0` | NSEC3 iterations, 0 to 65535 (RFC 9276 recommends 0; the server rejects more than 150 in its own config) |
| `--salt` | none | NSEC3 salt, hex |
| `--validity` | `720h` | Signature validity, a Go duration |

The input is read with the server's zone-file parser, so a standard BIND file
works (`$ORIGIN`, `$TTL`, `$INCLUDE`, `$GENERATE`, multi-line records, omitted
TTL and class). A file with no `$ORIGIN` takes `--zone` as its origin. A line that
cannot be read, a class other than IN, or RDATA that does not parse stops the
run with `line N: ...` and no output is written.

The keys found in `--keydir` are used. When there are none, a KSK and a ZSK are
generated for this run only: they are not saved, so generate and keep the keys
first (`generate-key`) if the zone will be re-signed or a DS published.

```bash
dnsctl dnssec sign-zone --zone example.com --input example.com.zone
dnsctl dnssec sign-zone --zone example.com --input example.com.zone --keydir ./keys \
    --nsec3 --iterations 1 --salt abcdef --validity 336h
```

### dnssec validate-zone

Check the RRSIGs of a signed zone file against its DNSKEYs and report how many
are valid, invalid and expired.

```bash
dnsctl dnssec validate-zone --zone <signed-zone-file> [--ignore-time]
```

`--ignore-time` skips the inception and expiration check (for testing).

### dnssec verify-anchor

Check a trust anchor file and list the anchors it holds per zone.

```bash
dnsctl dnssec verify-anchor <trust-anchor-file>
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
  Version:   1.2.17
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
dnsctl version 1.2.17
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
