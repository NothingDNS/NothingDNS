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
| `-api-key` | (empty) | API key for authentication (the bearer token: `server.http.auth_token` or a session token) |

Global flags go before the command. `NOTHINGDNS_SERVER` and `NOTHINGDNS_API_KEY`
set their defaults; `dnsctl -version` is the same as `dnsctl version`.

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
ZONE                                     RECORDS
---------------------------------------- ----------
example.com.                             4
test.org.                                2
```

### zone add

Add a new zone.

```bash
dnsctl zone add <zone-name> [nameserver]
```

The nameserver defaults to `ns1.<zone>.`. The zone gets an SOA with admin
mailbox `admin.<zone>.`, TTL 3600 and the usual timers, and one NS record. It is
written to `zone_dir` when one is configured.

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

Reload one zone from its file.

```bash
dnsctl zone reload <zone-name>
```

The name may be given with or without the trailing dot, in any case.

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

### zone soa

Show a zone's SOA, or change some of its fields. Fields not given keep their
value; the server bumps the serial, so secondaries are notified.

```bash
dnsctl zone soa <zone-name> [field=value ...]
```

Fields: `mname`, `rname` (`user@domain` or DNS form), `ttl`, `refresh`,
`retry`, `expire`, `minimum` (seconds). The serial cannot be set.

```bash
dnsctl zone soa example.com
dnsctl zone soa example.com refresh=7200 minimum=300 rname=dns@example.com
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

`<value>` is one argument, so quote RDATA that has spaces. The TTL is a
positional number (default 300), not a flag. `<name>` is relative to the zone,
or `@` for the apex.

**Examples**:
```bash
dnsctl record add example.com www A 192.168.1.100 3600
dnsctl record add example.com @ MX "10 mail.example.com." 3600
dnsctl record add example.com _sip._tcp SRV "10 60 5060 sip.example.com."
dnsctl record add example.com mail TXT "v=spf1 mx ~all"
```

### record remove

Remove a record set: every record of that type at the name.

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

Replaces the record whose data is `<old-data>`. Without `[ttl]` the record keeps
its current TTL.

### record list

List records in a zone.

```bash
dnsctl record list <zone>
```

```bash
dnsctl record list example.com
```

**Output**:
```
NAME                                     TYPE     TTL      DATA
---------------------------------------- -------- -------- --------------------
www.example.com.                         A        300      192.0.2.10
example.com.                             SOA      300      ns1.example.com. hostmaster.example.com. 1 3600 900 604800 300
example.com.                             NS       300      ns1.example.com.
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
Cache Statistics:
  Size:      0
  Capacity:  10000
  Hits:      0
  Misses:    0
  Hit Ratio: 0.00%
```

### cache flush

Flush (clear) the cache. Requires the admin role.

```bash
dnsctl cache flush [name]
```

With a name, only the entries of exactly that name are removed (every record
type, with and without the DO bit; case and a trailing dot do not matter); its
subdomains stay cached. It prints the count, for example
`Flushed 3 cache entries for www.example.com`. Without a name the whole cache
is cleared and it prints `Cache flushed`.

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

Prints the `GET /api/v1/cluster/status` response as an indented tree (cluster
health, gossip and Raft counters, query metrics); the fields depend on the
consensus mode. Without clustering it shows `healthy: false` and zero counters.

### cluster peers

List cluster peers/nodes.

```bash
dnsctl cluster peers
```

**Output**:
```
ID                                   ADDRESS              PORT   STATE      REGION
------------------------------------ -------------------- ------ ---------- ----------
node-1                               172.28.0.10          7946   alive      us-east
```

With clustering disabled it prints `No cluster nodes found (clustering may be disabled)`.

### cluster join

Join a cluster through a seed node.

```bash
dnsctl cluster join <address>[:port]
```

Admin role. With clustering disabled the server answers `503 Cluster not available`.

### cluster leave

Remove the node the API is talking to from the cluster. It takes no node
argument and cannot evict another node. Admin role; `503 Cluster not available`
when clustering is disabled.

```bash
dnsctl cluster leave
```

---

## blocklist — Blocklist Management

```bash
dnsctl blocklist [subcommand]
```

### blocklist status

Show blocklist statistics.

```bash
dnsctl blocklist status
```

**Output**:
```
Blocklist Status:
  Enabled:    false
  Total Rules: 0
  Files:      0
  URLs:       0
```

### blocklist sources

List configured blocklist sources (file and URL), or print
`No sources information available` when there are none.

```bash
dnsctl blocklist sources
```

### blocklist reload

Reload the server configuration, which reloads the blocklists with everything
else. It calls `POST /api/v1/config/reload`, exactly like `dnsctl config reload`,
and prints `Configuration reloaded`; there is no blocklist-only reload.

```bash
dnsctl blocklist reload
```

---

## config — Configuration

```bash
dnsctl config [subcommand]
```

### config get

Print the running configuration (secrets are redacted by the server), or one
value by its dotted key.

```bash
dnsctl config get
dnsctl config get server.http.bind
```

**Output** of the second command:
```
server.http.bind: 127.0.0.1:18080
```

An unknown key is `no such config key: <key>`.

### config reload

Reload the configuration file, the same as sending SIGHUP. Admin role. Prints
`Configuration reloaded`.

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
generated and written to `--keydir`, so the next run signs with the same keys
and a published DS keeps matching. Back those files up; the private keys are
needed to re-sign the zone.

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
  Status:    running
  Version:   1.4.1
  Timestamp: 2026-10-21T00:11:16Z
  Cache:
    Size:     0
    Capacity: 10000
    Hits:     0
    Misses:   0
    Hit Ratio: 0.00%
  Cluster:
    Enabled: false
```

### server health

Check server health.

```bash
dnsctl server health
```

**Output**:
```
Server healthy: {"status":"healthy","timestamp":"2026-10-21T00:11:16Z"}
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
dnsctl version 1.4.1
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

## Examples

### Common Workflows

```bash
# Check server is running
dnsctl server health

# View all zones
dnsctl zone list

# Add a new record
dnsctl record add example.com api A 192.168.1.50 3600

# Check cache performance
dnsctl cache stats

# View cluster status
dnsctl cluster status

# Flush cache after config change
dnsctl cache flush

# Reload a zone after editing its zone file
dnsctl zone reload example.com

# Verify DNSSEC is working
dnsctl dig example.com DNSKEY +dnssec
```

### Scripting Examples

```bash
# Monitor cache statistics
watch -n1 'dnsctl cache stats'

# List records in a zone
dnsctl record list example.com

# Backup all zones
for zone in $(dnsctl zone list | awk 'NR>2 {print $1}'); do
  dnsctl zone export "$zone" > "${zone}.zone.bak"
done

# Check cache hit ratio
dnsctl cache stats | grep "Hit Ratio"
```
