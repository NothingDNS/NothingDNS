# NothingDNS TypeScript SDK

Typed TypeScript/JavaScript client for the [NothingDNS](https://github.com/nothingdns/nothingdns)
DNS server management API. It covers every operation the server exposes over
HTTP — zones, records, cache, configuration, ACLs, blocklists, RPZ, DNSSEC,
upstreams, GeoDNS, clustering, users and the dashboard/metrics endpoints.

The SDK is a thin, well-typed layer over the REST API. It does **not** speak the
DNS wire protocols; use a DNS library (for example `dns-packet`) for actual
lookups.

- **API version covered:** NothingDNS 1.2.17 (see `GET /api/openapi.json`)
- **Runtime:** Node.js 18+, Deno, Bun, Cloudflare Workers, browsers
- **Dependencies:** none — uses the platform `fetch`

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
npm install @nothingdns/sdk
```

From a source checkout:

```bash
npm install ./sdk/typescript
```

---

## Quick start

```ts
import { NothingDNSClient } from '@nothingdns/sdk';

const client = new NothingDNSClient({ baseUrl: 'http://dns.example.com:8080' });

// Authenticate once; the token is reused for every later call.
await client.auth.login(process.env.NDNS_USER!, process.env.NDNS_PASSWORD!);

for (const zone of (await client.zones.list()).zones) {
  console.log(`${zone.name}: ${zone.records} records (serial ${zone.serial})`);
}

await client.zones.addRecord('example.com', 'api', 'A', '192.0.2.10', { ttl: 300 });

const cache = await client.cache.stats();
console.log(`cache ${cache.size}/${cache.capacity}, hit ratio ${(cache.hitRatio * 100).toFixed(1)}%`);
```

---

## Creating a client

```ts
const client = new NothingDNSClient({
  baseUrl: 'http://dns.example.com:8080', // server.http bind address
  token: process.env.NDNS_TOKEN,         // optional; login also sets it
  timeoutMs: 30_000,                     // per-request timeout
  headers: { 'X-Request-Source': 'provisioning' },
  fetch: myInstrumentedFetch,            // optional custom fetch
  signal: controller.signal,             // optional global abort signal
});
```

| Option | Default | Purpose |
| --- | --- | --- |
| `baseUrl` | `http://localhost:8080` | The server's HTTP listener (`server.http` in the config). |
| `token` | `null` | Bearer token to start with — a login JWT or `server.http.auth_token`. |
| `timeoutMs` | `30000` | Per-request timeout in milliseconds. |
| `headers` | `{}` | Extra headers merged into every request. |
| `fetch` | global `fetch` | Custom fetch implementation (proxies, instrumentation, tests). |
| `signal` | – | `AbortSignal` applied to every request. |

Read connection details from the environment rather than hardcoding anything
secret:

```ts
const client = new NothingDNSClient({
  baseUrl: process.env.NDNS_URL ?? 'http://localhost:8080',
});
```

---

## Authentication

Everything except the health probes requires a bearer token. There are two ways
to get one.

**1. Log in with a user account** (recommended):

```ts
const session = await client.auth.login(
  process.env.NDNS_USER!,
  process.env.NDNS_PASSWORD!,
);
console.log(session.username, session.role, session.expires);
```

`login()` stores the returned token on the client, so subsequent calls are
authenticated. Pass `{ storeToken: false }` to keep it out of the client, then
set it yourself with `client.setToken(session.token)`.

**2. Use the static service token** from the server config
(`server.http.auth_token`):

```ts
client.setToken(process.env.NDNS_TOKEN!);
```

**First-run provisioning.** On a fresh server with no admin account, create one:

```ts
const session = await client.auth.bootstrap('admin', process.env.NDNS_INITIAL_PASSWORD!);
```

`bootstrap()` also resets an existing account's password when the current one is
passed as `{ oldPassword }`.

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

Every non-2xx response throws a `NothingDNSApiError`, which carries the status
code, the server's message and the decoded body:

```ts
import {
  isForbidden,
  isNotFound,
  NothingDNSApiError,
  NothingDNSConnectionError,
  NothingDNSValidationError,
} from '@nothingdns/sdk';

try {
  await client.zones.get('example.com');
} catch (error) {
  if (error instanceof NothingDNSApiError) {
    console.error(error.statusCode, error.message, error.payload);
    if (isNotFound(error)) console.error('no such zone');
    if (isForbidden(error)) console.error('token needs the operator role');
  } else if (error instanceof NothingDNSConnectionError) {
    console.error('server unreachable:', error.message);
  } else if (error instanceof NothingDNSValidationError) {
    console.error('bad request or undecodable response:', error.message);
  } else {
    throw error;
  }
}
```

| Error | Thrown when |
| --- | --- |
| `NothingDNSApiError` | The server answered 4xx/5xx. Has `.statusCode`, `.message`, `.payload`. |
| `NothingDNSConnectionError` | DNS failure, refused connection, TLS error or timeout. |
| `NothingDNSValidationError` | A local argument check failed, or a 2xx body was not valid JSON. |

Common status codes: `400` bad input · `401` missing/expired token · `403` role
too low · `404` not found · `409` conflict (duplicate zone, user or upstream) ·
`421` name conflict (zone/record collides with an existing one) · `429` rate
limited · `500`/`503` server-side failure or subsystem unavailable.

Since the SDK is promise-based, `Promise.allSettled` is a convenient way to fan
out independent calls and collect partial failures.

---

## API reference by namespace

### Health and status

```ts
await client.health();        // GET /health — no auth required
await client.ready();         // GET /readyz — throws NothingDNSApiError(503) when not ready
await client.live();          // GET /livez — no auth required
await client.status();        // GET /api/v1/status — version, cache and cluster summary
await client.serverConfig();  // GET /api/v1/server/config — port, log level, DNS64, cookies
await client.openapiSpec();   // GET /api/openapi.json — the server's own OpenAPI document
```

`status()` works for any authenticated role; the `cache` field is only populated
for operators and admins.

### Auth — users and roles

| Method | Endpoint | Role |
| --- | --- | --- |
| `auth.login(username, password)` | `POST /api/v1/auth/login` | anonymous |
| `auth.bootstrap(username, password, { oldPassword })` | `POST /api/v1/auth/bootstrap` | anonymous / owner |
| `auth.session()` | `GET /api/v1/auth/session` | any |
| `auth.logout()` | `POST /api/v1/auth/logout` | any |
| `auth.roles()` | `GET /api/v1/auth/roles` | operator |
| `auth.listUsers()` | `GET /api/v1/auth/users` | operator |
| `auth.createUser(username, password, role)` | `POST /api/v1/auth/users` | admin |
| `auth.deleteUser(username)` | `DELETE /api/v1/auth/users/{username}` | admin |

```ts
for (const user of await client.auth.listUsers()) {
  console.log(user.username, user.role, user.createdAt);
}

await client.auth.createUser('ops', process.env.NDNS_OPS_PASSWORD!, 'operator');
await client.auth.deleteUser('ops');
```

### Zones and records

| Method | Endpoint | Role |
| --- | --- | --- |
| `zones.list()` | `GET /api/v1/zones` | operator |
| `zones.create(name, nameservers, { adminEmail, ttl })` | `POST /api/v1/zones` | operator |
| `zones.get(zone)` | `GET /api/v1/zones/{zone}` | operator |
| `zones.delete(zone)` | `DELETE /api/v1/zones/{zone}` | operator |
| `zones.reload(zone)` | `POST /api/v1/zones/reload` | admin |
| `zones.transfers()` | `GET /api/v1/zones/transfers` | operator |
| `zones.listRecords(zone, { name })` | `GET /api/v1/zones/{zone}/records` | operator |
| `zones.addRecord(zone, name, type, data, { ttl })` | `POST /api/v1/zones/{zone}/records` | operator |
| `zones.replaceRecord(zone, name, type, oldData, data, { ttl })` | `PUT /api/v1/zones/{zone}/records` | operator |
| `zones.deleteRecords(zone, name, type)` | `DELETE /api/v1/zones/{zone}/records` | operator |
| `zones.export(zone)` | `GET /api/v1/zones/{zone}/export` | operator |
| `zones.ptrBulk(zone, cidr, pattern, options)` | `POST /api/v1/zones/{zone}/ptr-bulk` | operator |
| `zones.ptr6Lookup(zone, ip)` | `GET /api/v1/zones/{zone}/ptr6-lookup` | operator |

```ts
// Create a zone and populate it.
await client.zones.create(
  'example.com',
  ['ns1.example.com', 'ns2.example.com'],
  { adminEmail: 'hostmaster@example.com', ttl: 3600 },
);

await client.zones.addRecord('example.com', 'www', 'A', '192.0.2.1');
await client.zones.addRecord('example.com', 'mail', 'A', '192.0.2.2', { ttl: 600 });
await client.zones.addRecord('example.com', '@', 'MX', '10 mail.example.com');
await client.zones.addRecord('example.com', '@', 'TXT', '"v=spf1 mx -all"');

// Change an address in place (the server matches on the current data).
await client.zones.replaceRecord('example.com', 'www', 'A', '192.0.2.1', '192.0.2.9');

// Inspect and export.
const detail = await client.zones.get('example.com');
console.log(detail.soa?.serial, detail.nameservers);

for (const record of (await client.zones.listRecords('example.com', { name: 'www' })).records) {
  console.log(record.type, record.ttl, record.data);
}

console.log(await client.zones.export('example.com')); // BIND zone-file text
```

**Bulk PTR generation** — preview first, then apply:

```ts
const zone = '2.0.192.in-addr.arpa';

const preview = await client.zones.ptrBulk(zone, '192.0.2.0/24', 'host-{ip}.example.com');
if ('willAdd' in preview) console.log('would add', preview.willAdd, 'skip', preview.willSkip);

const result = await client.zones.ptrBulk(zone, '192.0.2.0/24', 'host-{ip}.example.com', {
  preview: false,
  addA: true,
});
if ('added' in result) console.log('added', result.added, 'A records', result.addedA);
```

**IPv6 reverse lookups:**

```ts
const lookup = await client.zones.ptr6Lookup('8.b.d.0.1.0.0.2.ip6.arpa', '2001:db8::1');
if (lookup.found) console.log(lookup.target, lookup.ttl);
```

### Cache

```ts
const stats = await client.cache.stats();   // GET /api/v1/cache/stats (operator)
console.log(stats.size, stats.capacity, stats.hitRatio);
await client.cache.flush();                 // POST /api/v1/cache/flush (admin)
```

### Configuration

`config.get()` returns the effective configuration with secrets redacted
(operator). All setters require admin and are **partial updates** — omitted
options keep their current value. Changes are persisted to
`runtime_overrides.json` in the data directory and survive a restart.

| Method | Endpoint | Options |
| --- | --- | --- |
| `config.get()` | `GET /api/v1/config` | — |
| `config.reload()` | `POST /api/v1/config/reload` | — |
| `config.setLogging(level)` | `PUT /api/v1/config/logging` | `'debug'`\|`'info'`\|`'warn'`\|`'warning'`\|`'error'`\|`'fatal'` |
| `config.setRRL(options)` | `PUT /api/v1/config/rrl` | `enabled`, `rate`, `burst`, `maxBuckets` |
| `config.setCache(options)` | `PUT /api/v1/config/cache` | `enabled`, `size`, `defaultTtl`, `maxTtl`, `minTtl`, `negativeTtl`, `prefetch`, `prefetchThreshold`, `serveStale`, `staleGraceSecs` |
| `config.setResolution(options)` | `PUT /api/v1/config/resolution` | `recursive`, `authoritativeOnly`, `maxDepth`, `timeout`, `edns0BufferSize`, `qnameMinimization`, `use0x20` |
| `config.setDns64(enabled)` | `PUT /api/v1/config/dns64` | `enabled` |
| `config.setCookie(enabled)` | `PUT /api/v1/config/cookie` | `enabled` |

```ts
await client.config.setLogging('debug');
await client.config.setCache({ size: 100_000, serveStale: true, staleGraceSecs: 3600 });
await client.config.setResolution({ recursive: true, qnameMinimization: true, timeout: '2s' });
await client.config.setDns64(true);
```

### ACL

```ts
import type { ACLRule } from '@nothingdns/sdk';

const current = await client.acl.get();
console.log(current.persistent, current.policyFile);

// acl.set() REPLACES the whole list — read, extend, write back.
const extra: ACLRule[] = [
  { name: 'resolvers', networks: ['10.0.0.0/8'], action: 'allow', types: ['A', 'AAAA'] },
  { name: 'blocked-net', networks: ['203.0.113.0/24'], action: 'deny' },
];
await client.acl.set([...current.rules, ...extra]);

await client.acl.setRecursion(['10.0.0.0/8', '192.168.1.0/24']);
```

Rules are evaluated in order and the first match wins; once any rule exists a
client matching none of them is refused.

### Blocklists

```ts
const stats = await client.blocklists.stats();
const sources = await client.blocklists.sources();

await client.blocklists.add({ url: 'https://example.invalid/hosts.txt' });
await client.blocklists.add({ file: '/etc/nothingdns/blocklist.hosts' });
await client.blocklists.toggleSource('hosts-file-1');
await client.blocklists.remove('hosts-file-1');
await client.blocklists.toggle(); // global on/off
```

### RPZ

```ts
const stats = await client.rpz.stats();
const rules = await client.rpz.rules();

await client.rpz.addRule('ads.example.com'); // NXDOMAIN
await client.rpz.addRule('*.tracker.example', 'CNAME', {
  overrideData: 'sinkhole.example.com',
});
await client.rpz.deleteRule('ads.example.com');
await client.rpz.toggle();
```

Actions: `NXDOMAIN`, `NODATA`, `CNAME`, `OVERRIDE`, `DROP`, `PASSTHROUGH`, `TCPONLY`.

### DNSSEC

```ts
await client.dnssec.status(); // { enabled, requireDnssec } (operator)
await client.dnssec.keys();   // public signing-key metadata (admin); never private keys
```

### Upstreams

```ts
const pool = await client.upstreams.list();
for (const server of pool.servers) {
  console.log(server.address, server.healthy, `${server.latencyMs.toFixed(1)} ms`);
}

await client.upstreams.add('9.9.9.9:53');
await client.upstreams.remove('9.9.9.9:53');
```

### GeoDNS

```ts
const stats = await client.geoip.stats();
// { enabled, rules, mmdbLoaded, lookups, hits, misses }
```

### Cluster

```ts
const status = await client.cluster.status();
console.log(status.nodeId, status.consensus, status.raft?.isLeader);

for (const node of await client.cluster.nodes()) {
  console.log(node.id, node.addr, node.state, node.healthScore);
}

await client.cluster.join('10.0.0.10:7946'); // admin; run on a fresh node only
await client.cluster.leave();                // admin
```

### Dashboard and metrics

```ts
const counters = await client.dashboard.stats();
console.log(counters.queriesPerSecond, counters.cacheHitRate);

for (const event of (await client.dashboard.queries()).slice(-5)) {
  console.log(event.timestamp, event.clientIp, event.domain, event.responseCode, event.cached);
}

const page = await client.metrics.queryLog({ limit: 100, q: 'example.com' });
console.log(page.total, page.queries.length);

const top = await client.metrics.topDomains({ limit: 10 });
for (const entry of top.domains) console.log(entry.domain, entry.count);

const history = await client.metrics.history();
// Parallel series: history.queries[i] was recorded at history.timestamps[i]
```

---

## Method → endpoint coverage

Every operation in the server's OpenAPI document is covered. The documentation
and script endpoints (`/api/docs`, `/api/docs/app.js`, `POST /api/v1/csp-report`)
are browser-facing and have no SDK method.

| Namespace | Operations |
| --- | --- |
| `health`, `ready`, `live` | `/health`, `/readyz`, `/livez` |
| `status`, `serverConfig`, `openapiSpec` | `/api/v1/status`, `/api/v1/server/config`, `/api/openapi.json` |
| `auth` | `login`, `bootstrap`, `session`, `logout`, `roles`, `listUsers`, `createUser`, `deleteUser` |
| `zones` | `list`, `create`, `get`, `delete`, `reload`, `transfers`, `listRecords`, `addRecord`, `replaceRecord`, `deleteRecords`, `export`, `ptrBulk`, `ptr6Lookup` |
| `cache` | `stats`, `flush` |
| `config` | `get`, `reload`, `setLogging`, `setRRL`, `setCache`, `setResolution`, `setDns64`, `setCookie` |
| `acl` | `get`, `set`, `recursion`, `setRecursion` |
| `blocklists` | `stats`, `add`, `sources`, `toggle`, `toggleSource`, `remove` |
| `rpz` | `stats`, `rules`, `addRule`, `deleteRule`, `toggle` |
| `dnssec` | `status`, `keys` |
| `upstreams` | `list`, `add`, `remove` |
| `geoip` | `stats` |
| `cluster` | `status`, `nodes`, `join`, `leave` |
| `dashboard` | `stats`, `queries`, `zones` |
| `metrics` | `queryLog`, `topDomains`, `history` |

---

## Conventions

**Property names are idiomatic TypeScript.** The wire format is `snake_case`, so
`hit_ratio` becomes `hitRatio` and `require_dnssec` becomes `requireDnssec`. The
mappers that perform the translation live in `src/models.ts` — one place per
model, and they tolerate missing or unknown fields, so a newer server never
breaks an older client.

**The record type is `DNSRecord`, not `Record`.** Exporting a type named
`Record` would shadow TypeScript's built-in `Record<K, V>` utility for anyone
importing from this package.

**The two camelCase endpoints keep their names.** `/api/dashboard/*` and the PTR
helpers are camelCase on the wire, so `QueryEvent.clientIp` and
`PTRLookup.ptrFQDN` read exactly as documented in the API reference.

**Mutating calls resolve to the server's message string** (for example
`"zone created"`), while reads resolve to typed models.

**Errors, never `null`.** Anything other than 2xx throws; the SDK never silently
returns an empty result.

---

## Examples

Runnable scripts live in [`examples/`](examples):

| File | What it shows |
| --- | --- |
| [`quickstart.ts`](examples/quickstart.ts) | Login, health, zone listing, record management, cache stats. |
| [`provisionZone.ts`](examples/provisionZone.ts) | Idempotent zone + record reconciliation with a dry-run mode. |
| [`monitor.ts`](examples/monitor.ts) | Polling loop printing cache, query-rate and cluster health. |

All examples read connection details from the environment:

```bash
export NDNS_URL="http://dns.example.com:8080"
export NDNS_USER="admin"
export NDNS_PASSWORD="..."       # or NDNS_TOKEN for the static service token
npx tsx examples/quickstart.ts
```

---

## Development

```bash
cd sdk/typescript
npm install
npm run typecheck     # tsc --noEmit, strict (src + examples)
npm run build         # emit dist/ with .d.ts
npm test              # builds, then runs the mock-server suite with node --test
```

The SDK has no server-side dependency: it only speaks HTTP to the management
API. When the server adds an endpoint, update `internal/api/openapi.go` first (a
drift test enforces that every registered route is documented), then add the
matching method here.

## License

MIT
