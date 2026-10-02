# NothingDNS Python SDK

Typed Python client for the [NothingDNS](https://github.com/nothingdns/nothingdns) DNS
server management API. It covers every operation the server exposes over HTTP —
zones, records, cache, configuration, ACLs, blocklists, RPZ, DNSSEC, upstreams,
GeoDNS, clustering, users and the dashboard/metrics endpoints.

The SDK is a thin, well-typed layer over the REST API. It does **not** speak the
DNS wire protocols; use a DNS library (for example `dnspython`) for actual lookups.

- **API version covered:** NothingDNS 1.2.17 (see `GET /api/openapi.json`)
- **Python:** 3.9+
- **Runtime dependency:** `requests` only

---

## Table of contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Creating a client](#creating-a-client)
- [Authentication](#authentication)
- [Roles and permissions](#roles-and-permissions)
- [Error handling](#error-handling)
- [API reference by namespace](#api-reference-by-namespace)
  - [Health and status](#health-and-status)
  - [Auth — users and roles](#auth--users-and-roles)
  - [Zones and records](#zones-and-records)
  - [Cache](#cache)
  - [Configuration](#configuration)
  - [ACL](#acl)
  - [Blocklists](#blocklists)
  - [RPZ](#rpz)
  - [DNSSEC](#dnssec)
  - [Upstreams](#upstreams)
  - [GeoDNS](#geoip)
  - [Cluster](#cluster)
  - [Dashboard and metrics](#dashboard-and-metrics)
- [Method → endpoint coverage](#method--endpoint-coverage)
- [Conventions](#conventions)
- [Examples](#examples)
- [Development](#development)

---

## Installation

```bash
pip install nothingdns
```

From a source checkout:

```bash
pip install ./sdk/python
```

Requires `requests>=2.28`, which pip installs automatically.

---

## Quick start

```python
import os

from nothingdns import NothingDNSClient

with NothingDNSClient("http://dns.example.com:8080") as client:
    # Authenticate once; the token is reused for every later call.
    client.auth.login(os.environ["NDNS_USER"], os.environ["NDNS_PASSWORD"])

    # List zones and print their record counts.
    for zone in client.zones.list().zones:
        print(f"{zone.name}: {zone.records} records (serial {zone.serial})")

    # Add a record.
    client.zones.add_record("example.com", "api", "A", "192.0.2.10", ttl=300)

    # Read cache statistics.
    stats = client.cache.stats()
    print(f"cache {stats.size}/{stats.capacity}, hit ratio {stats.hit_ratio:.1%}")
```

---

## Creating a client

```python
from nothingdns import NothingDNSClient

client = NothingDNSClient(
    "http://dns.example.com:8080",  # server.http bind address
    timeout=30.0,                    # per-request timeout, seconds
    verify=True,                     # True | False | "/path/to/ca-bundle.pem"
    headers={"X-Request-Source": "provisioning"},
)
```

| Argument | Default | Purpose |
| --- | --- | --- |
| `base_url` | `http://localhost:8080` | The server's HTTP listener (`server.http` in the config). |
| `token` | `None` | Bearer token to start with — a login JWT or `server.http.auth_token`. |
| `timeout` | `30.0` | Per-request timeout in seconds. |
| `verify` | `True` | TLS verification: `True`, `False`, or a CA bundle path. |
| `headers` | `None` | Extra headers merged into every request. |
| `session` | `None` | A pre-built `requests.Session` to reuse (proxy, pool, retries). |

Prefer environment variables over hardcoding anything secret:

```python
from nothingdns import from_env

# NOTHINGDNS_URL, NOTHINGDNS_TOKEN, NOTHINGDNS_TIMEOUT
client = from_env()
```

The client is a context manager (`with NothingDNSClient(...) as client:`) and
closes its connection pool on exit. Use one client per thread.

---

## Authentication

Everything except the health probes requires a bearer token. There are two ways
to get one.

**1. Log in with a user account** (recommended):

```python
session = client.auth.login(os.environ["NDNS_USER"], os.environ["NDNS_PASSWORD"])
print(session.username, session.role, session.expires)
```

`login()` stores the returned token on the client, so subsequent calls are
authenticated. Pass `store_token=False` to keep it out of the client, then set it
yourself with `client.set_token(session.token)`.

**2. Use the static service token** from the server config
(`server.http.auth_token`):

```python
client.set_token(os.environ["NOTHINGDNS_TOKEN"])
```

**First-run provisioning.** On a fresh server with no admin account, create one:

```python
session = client.auth.bootstrap("admin", os.environ["NDNS_INITIAL_PASSWORD"])
```

`bootstrap()` also resets an existing account's password when the current one is
passed as `old_password=`.

`auth.session()` returns the current token's username and role — useful to check
whether a stored token is still valid. `auth.logout()` invalidates it.

---

## Roles and permissions

The server enforces three roles, ordered `viewer < operator < admin`. The
requirement is per operation, not per client:

| Role | Can do |
| --- | --- |
| `viewer` | Health probes, `GET /api/v1/status`, `auth.session`. |
| `operator` | Everything a viewer can, plus read access to zones, cache stats, config, ACL, blocklists, RPZ, DNSSEC status, upstreams, cluster status, dashboard and metrics — and zone/record **writes** (`POST`/`PUT`/`DELETE` records, create/delete zones, PTR bulk). |
| `admin` | Everything an operator can, plus user management, cache flush, zone reload, runtime config changes, ACL replacement, blocklist/RPZ changes, cluster join/leave and DNSSEC key listing. |

A `403` from the server means the token's role is too low for that call.

---

## Error handling

Every non-2xx response raises `NothingDNSApiError`, which carries the status
code, the server's message and the decoded body:

```python
from nothingdns import (
    NothingDNSApiError,
    NothingDNSConnectionError,
    NothingDNSValidationError,
    is_forbidden,
    is_not_found,
    is_rate_limited,
    is_unauthorized,
)

try:
    client.zones.get("example.com")
except NothingDNSApiError as exc:
    print(exc.status_code, exc.message, exc.payload)
    if is_not_found(exc):
        print("no such zone")
    elif is_forbidden(exc):
        print("token needs the operator role")
except NothingDNSConnectionError as exc:
    print("server unreachable:", exc)
except NothingDNSValidationError as exc:
    print("bad request or undecodable response:", exc)
```

| Exception | Raised when |
| --- | --- |
| `NothingDNSApiError` | The server answered 4xx/5xx. Has `.status_code`, `.message`, `.payload`. |
| `NothingDNSConnectionError` | DNS failure, refused connection, TLS error or timeout. |
| `NothingDNSValidationError` | A local argument check failed, or a 2xx body was not valid JSON. |

Common status codes: `400` bad input · `401` missing/expired token · `403` role
too low · `404` not found · `409` conflict (duplicate zone, user or upstream) ·
`421` name conflict (zone/record collides with an existing one) · `429` rate
limited · `500`/`503` server-side failure or subsystem unavailable.

---

## API reference by namespace

### Health and status

```python
client.health()          # GET /health     — no auth required
client.ready()           # GET /readyz     — raises NothingDNSApiError(503) when not ready
client.live()            # GET /livez      — no auth required
client.status()          # GET /api/v1/status — version, cache and cluster summary
client.server_config()   # GET /api/v1/server/config — port, log level, DNS64, cookies
client.openapi_spec()    # GET /api/openapi.json — the server's own OpenAPI document
```

`status()` works for any authenticated role; the `cache` field is only populated
for operators and admins.

### Auth — users and roles

| Method | Endpoint | Role |
| --- | --- | --- |
| `auth.login(username, password)` | `POST /api/v1/auth/login` | anonymous |
| `auth.bootstrap(username, password, old_password=None)` | `POST /api/v1/auth/bootstrap` | anonymous / owner |
| `auth.session()` | `GET /api/v1/auth/session` | any |
| `auth.logout()` | `POST /api/v1/auth/logout` | any |
| `auth.roles()` | `GET /api/v1/auth/roles` | operator |
| `auth.list_users()` | `GET /api/v1/auth/users` | operator |
| `auth.create_user(username, password, role="viewer")` | `POST /api/v1/auth/users` | admin |
| `auth.delete_user(username)` | `DELETE /api/v1/auth/users/{username}` | admin |

```python
for user in client.auth.list_users():
    print(user.username, user.role, user.created_at)

client.auth.create_user("ops", os.environ["NDNS_OPS_PASSWORD"], role="operator")
client.auth.delete_user("ops")
```

### Zones and records

| Method | Endpoint | Role |
| --- | --- | --- |
| `zones.list()` | `GET /api/v1/zones` | operator |
| `zones.create(name, nameservers, admin_email=None, ttl=None)` | `POST /api/v1/zones` | operator |
| `zones.get(zone)` | `GET /api/v1/zones/{zone}` | operator |
| `zones.delete(zone)` | `DELETE /api/v1/zones/{zone}` | operator |
| `zones.reload(zone)` | `POST /api/v1/zones/reload` | admin |
| `zones.transfers()` | `GET /api/v1/zones/transfers` | operator |
| `zones.list_records(zone, name=None)` | `GET /api/v1/zones/{zone}/records` | operator |
| `zones.add_record(zone, name, type, data, ttl=None)` | `POST /api/v1/zones/{zone}/records` | operator |
| `zones.replace_record(zone, name, type, old_data, data, ttl=None)` | `PUT /api/v1/zones/{zone}/records` | operator |
| `zones.delete_records(zone, name, type)` | `DELETE /api/v1/zones/{zone}/records` | operator |
| `zones.export(zone)` | `GET /api/v1/zones/{zone}/export` | operator |
| `zones.ptr_bulk(zone, cidr, pattern, ...)` | `POST /api/v1/zones/{zone}/ptr-bulk` | operator |
| `zones.ptr6_lookup(zone, ip)` | `GET /api/v1/zones/{zone}/ptr6-lookup` | operator |

```python
# Create a zone and populate it.
client.zones.create(
    "example.com",
    nameservers=["ns1.example.com", "ns2.example.com"],
    admin_email="hostmaster@example.com",
    ttl=3600,
)

client.zones.add_record("example.com", "www", "A", "192.0.2.1")
client.zones.add_record("example.com", "mail", "A", "192.0.2.2", ttl=600)
client.zones.add_record("example.com", "@", "MX", "10 mail.example.com")
client.zones.add_record("example.com", "@", "TXT", '"v=spf1 mx -all"')

# Change an address in place (the server matches on the current data).
client.zones.replace_record("example.com", "www", "A", "192.0.2.1", "192.0.2.9")

# Inspect and export.
detail = client.zones.get("example.com")
print(detail.soa.serial, detail.nameservers)

for record in client.zones.list_records("example.com", name="www").records:
    print(record.type, record.ttl, record.data)

print(client.zones.export("example.com"))  # BIND zone-file text
```

**Bulk PTR generation** — preview first, then apply:

```python
zone = "2.0.192.in-addr.arpa"

preview = client.zones.ptr_bulk(zone, "192.0.2.0/24", "host-{ip}.example.com")
print(preview.willAdd, preview.willSkip, preview.willOverride)

result = client.zones.ptr_bulk(
    zone, "192.0.2.0/24", "host-{ip}.example.com", preview=False, add_a=True
)
print(result.added, result.addedA)
```

**IPv6 reverse lookups:**

```python
lookup = client.zones.ptr6_lookup("8.b.d.0.1.0.0.2.ip6.arpa", "2001:db8::1")
if lookup.found:
    print(lookup.target, lookup.ttl)
```

### Cache

```python
stats = client.cache.stats()   # GET /api/v1/cache/stats  (operator)
print(stats.size, stats.capacity, stats.hit_ratio)
client.cache.flush()           # POST /api/v1/cache/flush (admin)
```

### Configuration

`config.get()` returns the effective configuration with secrets redacted
(operator). All setters require admin and are **partial updates** — omitted
arguments keep their current value. Changes are persisted to
`runtime_overrides.json` in the data directory and survive a restart.

| Method | Endpoint | Arguments |
| --- | --- | --- |
| `config.get()` | `GET /api/v1/config` | — |
| `config.reload()` | `POST /api/v1/config/reload` | — |
| `config.set_logging(level)` | `PUT /api/v1/config/logging` | `debug`\|`info`\|`warn`\|`warning`\|`error`\|`fatal` |
| `config.set_rrl(...)` | `PUT /api/v1/config/rrl` | `enabled`, `rate`, `burst`, `max_buckets` |
| `config.set_cache(...)` | `PUT /api/v1/config/cache` | `enabled`, `size`, `default_ttl`, `max_ttl`, `min_ttl`, `negative_ttl`, `prefetch`, `prefetch_threshold`, `serve_stale`, `stale_grace_secs` |
| `config.set_resolution(...)` | `PUT /api/v1/config/resolution` | `recursive`, `authoritative_only`, `max_depth`, `timeout`, `edns0_buffer_size`, `qname_minimization`, `use_0x20` |
| `config.set_dns64(enabled)` | `PUT /api/v1/config/dns64` | `enabled` |
| `config.set_cookie(enabled)` | `PUT /api/v1/config/cookie` | `enabled` |

```python
client.config.set_logging("debug")
client.config.set_cache(size=100_000, serve_stale=True, stale_grace_secs=3600)
client.config.set_resolution(recursive=True, qname_minimization=True, timeout="2s")
client.config.set_dns64(True)
```

### ACL

```python
from nothingdns import ACLRule

current = client.acl.get()
print(current.persistent, current.policy_file)

# acl.set() REPLACES the whole list — read, extend, write back.
rules = list(current.rules)
rules.append(ACLRule(name="resolvers", networks=["10.0.0.0/8"], action="allow", types=["A", "AAAA"]))
rules.append(ACLRule(name="blocked-net", networks=["203.0.113.0/24"], action="deny"))
client.acl.set(rules)

client.acl.set_recursion(["10.0.0.0/8", "192.168.1.0/24"])
```

Rules are evaluated in order and the first match wins; once any rule exists a
client matching none of them is refused.

### Blocklists

```python
stats = client.blocklists.stats()
sources = client.blocklists.sources()

client.blocklists.add(url="https://example.invalid/hosts.txt")
client.blocklists.add(file="/etc/nothingdns/blocklist.hosts")
client.blocklists.toggle_source("hosts-file-1")
client.blocklists.remove("hosts-file-1")
client.blocklists.toggle()   # global on/off
```

### RPZ

```python
stats = client.rpz.stats()
rules = client.rpz.rules()

client.rpz.add_rule("ads.example.com")                       # NXDOMAIN
client.rpz.add_rule("*.tracker.example", action="CNAME", override_data="sinkhole.example.com")
client.rpz.delete_rule("ads.example.com")
client.rpz.toggle()
```

Actions: `NXDOMAIN`, `NODATA`, `CNAME`, `OVERRIDE`, `DROP`, `PASSTHROUGH`, `TCPONLY`.

### DNSSEC

```python
client.dnssec.status()   # enabled, require_dnssec  (operator)
client.dnssec.keys()     # public signing-key metadata (admin); never private keys
```

### Upstreams

```python
pool = client.upstreams.list()
for server in pool.servers:
    print(server.address, server.healthy, f"{server.latency_ms:.1f} ms")

client.upstreams.add("9.9.9.9:53")
client.upstreams.remove("9.9.9.9:53")
```

### GeoDNS

```python
stats = client.geoip.stats()   # enabled, rules, mmdb_loaded, lookups, hits, misses
```

### Cluster

```python
status = client.cluster.status()
print(status.node_id, status.consensus, status.raft.is_leader)

for node in client.cluster.nodes():
    print(node.id, node.addr, node.state, node.health_score)

client.cluster.join("10.0.0.10:7946")   # admin; run on a fresh node only
client.cluster.leave()                  # admin
```

### Dashboard and metrics

```python
counters = client.dashboard.stats()
print(counters.queriesPerSec, counters.cacheHitRate)

for event in client.dashboard.queries()[-5:]:
    print(event.timestamp, event.clientIp, event.domain, event.responseCode, event.cached)

page = client.metrics.query_log(limit=100, q="example.com")
print(page.total, len(page.queries))

top = client.metrics.top_domains(limit=10)
for entry in top.domains:
    print(entry.domain, entry.count)

history = client.metrics.history()
# Parallel series: history.queries[i] was recorded at history.timestamps[i]
```

---

## Method → endpoint coverage

Every operation in the server's OpenAPI document is covered. The documentation
and script endpoints (`/api/docs`, `/api/docs/app.js`, `POST /api/v1/csp-report`)
are browser-facing and have no SDK method.

| Namespace | Operations |
| --- | --- |
| `health`, `ready`, `live` | `/health`, `/readyz`, `/livez` |
| `status`, `server_config`, `openapi_spec` | `/api/v1/status`, `/api/v1/server/config`, `/api/openapi.json` |
| `auth` | `login`, `bootstrap`, `session`, `logout`, `roles`, `list_users`, `create_user`, `delete_user` |
| `zones` | `list`, `create`, `get`, `delete`, `reload`, `transfers`, `list_records`, `add_record`, `replace_record`, `delete_records`, `export`, `ptr_bulk`, `ptr6_lookup` |
| `cache` | `stats`, `flush` |
| `config` | `get`, `reload`, `set_logging`, `set_rrl`, `set_cache`, `set_resolution`, `set_dns64`, `set_cookie` |
| `acl` | `get`, `set`, `recursion`, `set_recursion` |
| `blocklists` | `stats`, `add`, `sources`, `toggle`, `toggle_source`, `remove` |
| `rpz` | `stats`, `rules`, `add_rule`, `delete_rule`, `toggle` |
| `dnssec` | `status`, `keys` |
| `upstreams` | `list`, `add`, `remove` |
| `geoip` | `stats` |
| `cluster` | `status`, `nodes`, `join`, `leave` |
| `dashboard` | `stats`, `queries`, `zones` |
| `metrics` | `query_log`, `top_domains`, `history` |

---

## Conventions

**Field names match the API.** Model attributes use the server's JSON names
(`snake_case`), so `hit_ratio` and `require_dnssec` read exactly as documented in
the API reference. The two camelCase endpoints — `/api/dashboard/queries` and the
PTR helpers — keep their camelCase names (`clientIp`, `ptrFQDN`).

**Models are immutable.** Every response model is a frozen dataclass. Missing
fields fall back to documented defaults, so a newer server never breaks an older
client.

**`class` is `class_`.** `Record.class_` maps the wire field `class`, since
`class` is a Python keyword.

**Mutating calls return the server's message string** (for example
`"zone created"`), while reads return typed models.

**Errors, not `None`.** Anything other than 2xx raises; the SDK never silently
returns an empty result.

---

## Examples

Runnable scripts live in [`examples/`](examples):

| File | What it shows |
| --- | --- |
| [`quickstart.py`](examples/quickstart.py) | Login, health, zone listing, record management, cache stats. |
| [`provision_zone.py`](examples/provision_zone.py) | Idempotent zone + record provisioning with a dry-run mode. |
| [`monitor.py`](examples/monitor.py) | Polling loop printing cache, query-rate and cluster health. |

All examples read connection details from the environment:

```bash
export NDNS_URL="http://dns.example.com:8080"
export NDNS_USER="admin"
export NDNS_PASSWORD="..."        # or NDNS_TOKEN for the static service token
python examples/quickstart.py
```

---

## Development

```bash
cd sdk/python
python -m pip install -e ".[dev]"
pytest                    # 33 tests against an in-process mock API
ruff check .
mypy .
```

The SDK has no server-side dependency: it only speaks HTTP to the management API.
When the server adds an endpoint, update `internal/api/openapi.go` first (a
drift test enforces that every registered route is documented), then add the
matching method here.

## License

MIT
