# NothingDNS Java SDK

A typed Java client for the [NothingDNS](../) management API. It covers all
**71 documented operations** — authentication, zones and records, the response
cache, runtime configuration, ACLs, blocklists, response policy zones, DNSSEC,
upstreams, GeoDNS, clustering, the dashboard and metrics.

- **Java 17+**, one runtime dependency: [Gson](https://github.com/google/gson) 2.11.0
- **Transport:** the JDK's `java.net.http.HttpClient` — no other libraries
- **Models:** immutable-style POJOs with getters; every field tolerates absence,
  so a newer server never breaks an older client
- **Errors:** one unchecked exception type, `NothingDnsException`, carrying the
  status code and the raw response body

## Contents

- [Features](#features)
- [Install](#install)
- [Quick start](#quick-start)
- [Authentication](#authentication)
- [Configuration options](#configuration-options)
- [Namespaces](#namespaces)
  - [Health and status](#health-and-status)
  - [Auth](#auth)
  - [Zones](#zones)
  - [Cache](#cache)
  - [Config](#config)
  - [ACL](#acl)
  - [Blocklists](#blocklists)
  - [RPZ](#rpz)
  - [DNSSEC](#dnssec)
  - [Upstreams](#upstreams)
  - [GeoDNS](#geodns)
  - [Cluster](#cluster)
  - [Dashboard](#dashboard)
  - [Metrics](#metrics)
- [Error handling](#error-handling)
- [Role requirements](#role-requirements)
- [Operation coverage](#operation-coverage)

## Features

- **Complete.** All 71 contract operations, one Java method each.
- **Typed.** Every response decodes into a documented model class; no raw JSON
  except for the effective config and the OpenAPI document, whose shape is
  server-defined.
- **Namespaced.** The client mirrors the server's API groups, so the Java call
  reads like the endpoint:
  `client.zones().addRecord(...)`, `client.rpz().addRule(...)`.
- **Correct on the wire.** Java camelCase fields map to the server's snake_case
  via `@SerializedName`; the three camelCase groups (`/api/dashboard`,
  `ptr6-lookup`, `ptr-bulk`) keep their wire names.
- **Safe partial updates.** Runtime-config setters omit `null` arguments rather
  than sending `null`, so "leave unchanged" means what it says.
- **Safe paths.** Every dynamic path segment is percent-encoded, so a zone name
  or username can never break out of its position.
- **Typed errors.** `NothingDnsException` exposes the status code and raw body;
  static helpers turn a status into a decision.

## Install

Maven coordinates:

```xml
<dependency>
  <groupId>io.nothingdns</groupId>
  <artifactId>nothingdns-sdk</artifactId>
  <version>1.0.0</version>
</dependency>
```

Build it from this directory with:

```bash
mvn package        # produces target/nothingdns-sdk-1.0.0.jar
```

Requires JDK 17 or newer (`maven.compiler.release` is 17). Gson is pulled in
transitively; the SDK uses the JDK's `HttpClient` for transport, so there is
nothing else to install.

## Quick start

```java
import io.nothingdns.sdk.NothingDnsClient;
import io.nothingdns.sdk.model.CacheStats;
import io.nothingdns.sdk.model.Zone;

import java.time.Duration;

public class Example {
    public static void main(String[] args) {
        try (NothingDnsClient client =
                     new NothingDnsClient("http://dns.example.com:8080",
                                          null, Duration.ofSeconds(30), null, null)) {

            // Health needs no credentials — a good first call.
            System.out.println(client.health().getStatus());

            // login() stores the token, so everything after it is authenticated.
            client.auth().login(System.getenv("NDNS_USER"),
                                System.getenv("NDNS_PASSWORD"));

            for (Zone zone : client.zones().list().getZones()) {
                System.out.println(zone.getName() + " (" + zone.getRecords() + " records)");
            }

            client.zones().addRecord("example.com", "www", "A", "192.0.2.1", 3600);

            CacheStats cache = client.cache().stats();
            System.out.printf("cache %d/%d, hit ratio %.3f%n",
                    cache.getSize(), cache.getCapacity(), cache.getHitRatio());
        }
    }
}
```

A fuller, runnable tour lives in
[`src/main/java/io/nothingdns/sdk/examples/QuickStart.java`](src/main/java/io/nothingdns/sdk/examples/QuickStart.java).
It reads `NDNS_URL`, `NDNS_USER` and `NDNS_PASSWORD` from the environment —
never hardcode credentials — and prints a zone export at the end.

## Authentication

There are two ways to authenticate, and the client supports both.

### 1. Log in with a username and password

The most common path. `login()` returns a `Session` and, by default, stores the
token on the client so every later call is authenticated.

```java
import io.nothingdns.sdk.model.Session;

Session session = client.auth().login("admin", "s3cret");
System.out.println("role = " + session.getRole());   // viewer | operator | admin
System.out.println("expires = " + session.getExpires());
```

The token is kept in memory only. To reuse it in a later process, read
`session.getToken()` and hand it back to a new client via `setToken()`.

### 2. Use the static `server.http.auth_token`

The server config's `server.http.auth_token` is a long-lived shared bearer.
Construct the client with it and skip login entirely — useful for automation
that provisions the server before any user account exists.

```java
NothingDnsClient client =
        new NothingDnsClient("http://dns.example.com:8080",
                             System.getenv("NDNS_TOKEN"));
```

Or set it later on an existing client:

```java
client.setToken(System.getenv("NDNS_TOKEN"));
```

`setToken(null)` returns the client to an anonymous state. Note that the
session-restoration call `auth().session()` requires a real login JWT — the
server rejects the static token there.

### From the environment

`fromEnv()` reads `NDNS_URL` (default `http://localhost:8080`), `NDNS_TOKEN` and
`NDNS_TIMEOUT` (seconds, default 30):

```java
NothingDnsClient client = NothingDnsClient.fromEnv();
```

### Bootstrap

`bootstrap()` creates the very first admin on a fresh server, or resets an
existing account's password when you supply the current one:

```java
// First run: create the initial admin.
client.auth().bootstrap("admin", "initial-password");

// Later: reset a password (requires the current one).
client.auth().bootstrap("admin", "new-password", "old-password");
```

## Configuration options

The full constructor takes everything; the short ones fill in defaults.

```java
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;

new NothingDnsClient(
    "http://dns.example.com:8080",   // baseUrl  — required
    "jwt-or-static-token",           // token    — null for anonymous
    Duration.ofSeconds(30),          // timeout  — null → 30s
    Map.of("X-Trace-Id", "abc123"),  // headers  — merged into every request
    null                             // httpClient — null → one is created
);
```

| Option | Meaning | Default |
| --- | --- | --- |
| `baseUrl` | The server's HTTP listener, from the `server.http` config section. | `http://localhost:8080` |
| `token` | A JWT from `login()`, or the static `server.http.auth_token`. | none (anonymous) |
| `timeout` | Per-request timeout, as a `java.time.Duration`. Applies to connect and to each request. | 30 seconds |
| `headers` | Extra headers merged into every request (e.g. a trace id). | none |
| `httpClient` | An `HttpClient` to reuse — share a connection pool, a proxy, or a custom TLS context. | a new one is created |

Reuse a single `HttpClient` across clients so they share a connection pool:

```java
HttpClient shared = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .proxy(ProxySelector.getDefault())
        .build();

NothingDnsClient a = new NothingDnsClient(url, token, null, null, shared);
NothingDnsClient b = new NothingDnsClient(url, token, null, null, shared);
```

The client is safe to share between threads. `close()` (or try-with-resources)
releases it; the JDK `HttpClient` owns the connection pool.

## Namespaces

### Health and status

On the client itself, since these are not a resource group.

```java
client.health();        // GET /health          — no auth
client.ready();         // GET /readyz          — no auth
client.live();          // GET /livez           — no auth
client.status();        // GET /api/v1/status   — any authenticated user
client.serverConfig();  // GET /api/v1/server/config — operator+
```

`ready()` throws with status 503 when the server is not ready; catch it and
treat that as "not ready", not as a hard failure:

```java
try {
    System.out.println("ready: " + client.ready().getStatus());
} catch (NothingDnsException e) {
    if (e.getStatusCode() == 503) {
        System.out.println("still starting up");
    } else {
        throw e;
    }
}
```

`serverConfig()` shows the listen port, log level and the DNS64/Cookie toggles:

```java
System.out.println("port " + client.serverConfig().getListenPort()
        + ", log " + client.serverConfig().getLogLevel()
        + ", dns64 " + client.serverConfig().getDns64().isEnabled());
```

### Auth

```java
var roles = client.auth().roles();                 // the server's role table
var users = client.auth().listUsers();             // accounts (no passwords)
var me    = client.auth().session();               // the current session

client.auth().createUser("alice", "pw", "operator");   // admin only
client.auth().deleteUser("alice");                      // admin only

client.auth().logout();
```

`createUser` rejects an unknown role locally with `IllegalArgumentException`
before making a request. The valid roles are `viewer`, `operator`, `admin`.

### Zones

```java
// List and inspect
var zoneList = client.zones().list();
var detail   = client.zones().get("example.com");
System.out.println(detail.getSoa().getMname());
System.out.println(detail.getNameservers());

for (var slave : client.zones().transfers()) {
    System.out.println(slave.getZone() + " " + slave.getStatus());
}

// Create
client.zones().create("example.com",
                      List.of("ns1.example.com", "ns2.example.com"),
                      "hostmaster@example.com",
                      3600);

// Records
client.zones().addRecord("example.com", "www", "A", "192.0.2.1", 3600);
client.zones().replaceRecord("example.com", "www", "A", "192.0.2.1", "192.0.2.2", 3600);
client.zones().deleteRecords("example.com", "www", "A");

var records = client.zones().listRecords("example.com", "www");  // name filter
for (var r : records.getRecords()) {
    System.out.println(r.getName() + " " + r.getTtl() + " " + r.getData());
}

// Export a BIND zone file
System.out.println(client.zones().export("example.com"));

// Reverse DNS
var preview = client.zones().ptrBulkPreview("2.0.192.in-addr.arpa",
                                           "192.0.2.0/24",
                                           "host-{ip}.example.com",
                                           false, false);
System.out.println(preview.getWillAdd() + " PTR records would be added");

var applied = client.zones().ptrBulk("2.0.192.in-addr.arpa",
                                     "192.0.2.0/24",
                                     "host-{ip}.example.com",
                                     false, true);
System.out.println(applied.getAdded() + " added, " + applied.getAddedA() + " A records");

var ptr6 = client.zones().ptr6Lookup("8.b.d.0.1.0.0.2.ip6.arpa", "2001:db8::1");
if (ptr6.isFound()) {
    System.out.println(ptr6.getPtrFQDN() + " -> " + ptr6.getTarget());
}

// Admin: re-read a zone from its file on disk
client.zones().reload("example.com");
```

`ptrBulkPreview` writes nothing and returns the planned changes;
`ptrBulk` applies the change and returns the counts. Preview first — the
endpoint refuses ranges larger than a `/16`.

### Cache

```java
var stats = client.cache().stats();
System.out.printf("%d/%d entries, hit ratio %.3f%n",
        stats.getSize(), stats.getCapacity(), stats.getHitRatio());

client.cache().flush();   // admin
```

### Config

Every setter is a **partial update**: pass `null` for an argument and it is
omitted from the request, which the server reads as "leave unchanged".

```java
// The effective config, secrets redacted. Server-defined shape.
JsonObject effective = client.config().get();

client.config().reload();                              // admin
client.config().setLogging("debug");                  // admin
client.config().setDns64(true);                       // admin
client.config().setCookie(true);                      // admin

// Rate limiter: enabled, 100 q/s, burst 200, 10k buckets
client.config().setRrl(true, 100.0, 200, 10_000);     // admin

// Cache tuning
client.config().setCache(true, 100_000,
                         300, 3600, 30, 60,
                         true, 10,
                         true, 3600);                // admin

// Resolution tuning
client.config().setResolution(true, false, 32, "5s",
                              1232, true, true);      // admin
```

Accepted log levels are listed in `ConfigResource.LOG_LEVELS`:
`debug`, `info`, `warn`, `warning`, `error`, `fatal`. An unknown level throws
`IllegalArgumentException` locally.

### ACL

Rules are evaluated in order, first match wins, against **every** query. Once
any rule exists, a client matched by none is refused.

```java
var config = client.acl().get();
for (var rule : config.getRules()) {
    System.out.println(rule.getName() + " " + rule.getAction() + " " + rule.getNetworks());
}

// Replace the whole rule set (admin) — read, edit, send back.
var rules = new ArrayList<>(config.getRules());
rules.add(AclRule.of("block-bad-net",
                     List.of("203.0.113.0/24"),
                     "deny"));
client.acl().set(rules);

// Recursion allow list
System.out.println(client.acl().recursion().isAllowAll());
client.acl().setRecursion(List.of("10.0.0.0/8", "192.168.0.0/16"));  // admin
```

`acl().set(...)` is a **full replacement**, not a merge.

### Blocklists

```java
var stats = client.blocklists().stats();
System.out.println(stats.getTotalRules() + " domains from "
        + stats.getFilesCount() + " files and " + stats.getUrlsCount() + " URLs");

client.blocklists().addUrl("https://example.com/hosts.txt");   // admin
client.blocklists().addFile("/etc/nothingdns/extra.hosts");     // admin

for (var source : client.blocklists().sources()) {
    System.out.println(source.getId() + " " + source.getType() + " " + source.getDomains());
    client.blocklists().toggleSource(source.getId());            // admin
    client.blocklists().remove(source.getId());                  // admin
}

client.blocklists().toggle();   // admin — the whole engine
```

### RPZ

```java
var stats = client.rpz().stats();
System.out.println(stats.getTotalRules() + " rules, "
        + stats.getTotalMatches() + " matches");

var page = client.rpz().rules();
for (var rule : page.getRules()) {
    System.out.println(rule.getPattern() + " -> " + rule.getAction());
}

client.rpz().addRule("ads.example.com", "NXDOMAIN", null);              // admin
client.rpz().addRule("track.example.com", "CNAME", "block.example.net"); // admin
client.rpz().deleteRule("ads.example.com");                            // admin
client.rpz().toggle();                                                 // admin
```

Valid actions are in `RpzResource.ACTIONS`: `NXDOMAIN`, `NODATA`, `CNAME`,
`OVERRIDE`, `DROP`, `PASSTHROUGH`, `TCPONLY`. An unknown action throws
`IllegalArgumentException` locally.

### DNSSEC

```java
var status = client.dnssec().status();
System.out.println("enabled=" + status.isEnabled()
        + " require=" + status.isRequireDnssec());

for (var key : client.dnssec().keys().getZones()) {   // admin
    System.out.println(key.getZone() + " tag=" + key.getKeyTag()
            + " alg=" + key.getAlgorithm()
            + (key.isKSK() ? " KSK" : "") + (key.isZSK() ? " ZSK" : ""));
}
```

Only public key metadata is returned; private key material never leaves the
server.

### Upstreams

```java
var pool = client.upstreams().list();
for (var u : pool.getUpstreams()) {
    System.out.println(u.getAddress() + " healthy=" + u.isHealthy()
            + " queries=" + u.getQueries() + " failed=" + u.getFailed());
}
for (var s : pool.getServers()) {
    System.out.println(s.getAddress() + " " + s.getLatencyMs() + "ms");
}

client.upstreams().add("1.1.1.1:53");      // admin
client.upstreams().remove("1.1.1.1:53");   // admin
```

### GeoDNS

```java
var geo = client.geoip().stats();
System.out.println("enabled=" + geo.isEnabled()
        + " rules=" + geo.getRules()
        + " hits=" + geo.getHits() + "/" + geo.getLookups());
```

### Cluster

```java
var status = client.cluster().status();
System.out.println(status.getNodeId() + " " + status.getConsensus()
        + " " + status.getAliveCount() + "/" + status.getNodeCount()
        + " healthy=" + status.isHealthy());
System.out.println("raft: " + status.getRaft().getState()
        + ", leader=" + status.getRaft().isLeader());

for (var node : client.cluster().nodes()) {
    System.out.println(node.getId() + " " + node.getAddr()
            + " qps=" + node.getQueriesPerSecond());
}

client.cluster().join("10.0.0.1:7946");   // admin
client.cluster().leave();                // admin — drains this node
```

### Dashboard

```java
var stats = client.dashboard().stats();
System.out.println(stats.getQueriesTotal() + " queries, "
        + stats.getBlockedQueries() + " blocked, "
        + stats.getCacheHitRate() + " hit rate");

for (var event : client.dashboard().queries()) {   // last 100 events
    System.out.println(event.getTimestamp() + " " + event.getClientIp()
            + " " + event.getDomain() + " " + event.getQueryType()
            + " -> " + event.getResponseCode()
            + (event.isBlocked() ? " BLOCKED" : ""));
}

for (var zone : client.dashboard().zones()) {
    System.out.println(zone.getName() + " " + zone.getRecords() + " records");
}
```

### Metrics

```java
// Paginated, filterable query log.
var page = client.metrics().queryLog(0, 50, "example.com");
System.out.println(page.getTotal() + " matching, showing " + page.getQueries().size());
for (var row : page.getQueries()) {
    System.out.println(row.getClientIp() + " " + row.getDomain()
            + " " + row.getDurationMs() + "ms"
            + (row.isCached() ? " cached" : ""));
}

// Most-queried domains.
for (var top : client.metrics().topDomains(10).getDomains()) {
    System.out.println(top.getCount() + "  " + top.getDomain());
}

// Metrics history ring buffer; the arrays are parallel.
var history = client.metrics().history();
for (int i = 0; i < history.getCount(); i++) {
    System.out.println(history.getTimestamps().get(i)
            + " q=" + history.getQueries().get(i)
            + " hits=" + history.getCacheHits().get(i)
            + " p=" + history.getLatencyMs().get(i));
}
```

## Error handling

Every failure surfaces as one unchecked exception. Two subclasses carry the
detail:

- `NothingDnsException` — an HTTP 4xx/5xx response, or a 2xx body that was not
  valid JSON. Carries `getStatusCode()`, `getMessage()` and the raw
  `getPayload()`.
- `NothingDnsConnectionException` — the server could not be reached: DNS
  failure, refused connection, TLS error or timeout. `getStatusCode()` is `0`.

```java
import io.nothingdns.sdk.NothingDnsException;
import io.nothingdns.sdk.NothingDnsConnectionException;

try {
    client.zones().get("example.com");
} catch (NothingDnsException e) {
    if (NothingDnsException.isNotFound(e)) {
        System.out.println("no such zone");
    } else if (NothingDnsException.isForbidden(e)) {
        System.out.println("needs admin — this account is only a viewer");
    } else {
        System.err.println("HTTP " + e.getStatusCode() + ": " + e.getMessage());
        System.err.println("raw body: " + e.getPayload());
    }
} catch (NothingDnsConnectionException e) {
    System.err.println("cannot reach the server: " + e.getMessage());
}
```

Static helpers: `isNotFound`, `isUnauthorized`, `isForbidden`, `isRateLimited`.

### Status codes

| Status | Meaning | Typical SDK response |
| --- | --- | --- |
| `200` | Success with a body | Model returned |
| `201` | Created (zone, record, user, rule, blocklist) | Confirmation message returned |
| `204` | No content (CSP report sink) | `cspReport()` returns `void` |
| `400` | Malformed request or bad argument | Throws — check the message |
| `401` | Missing, invalid or expired token | Throws — log in again |
| `403` | Role too low for this endpoint | Throws — needs a higher role |
| `404` | Zone, record, user or source not found | Throws |
| `405` | Method not allowed on this endpoint | Throws |
| `409` | Conflict — zone or username already exists | Throws |
| `421` | Zone name out of range (label too long) | Throws |
| `429` | Rate limited | Throws — back off and retry |
| `500` | Server error while reloading config or a zone | Throws — usually a bad file |
| `503` | Not ready, or the subsystem is unavailable | `ready()` throws; treat as "not ready" |

Local validation throws `IllegalArgumentException` **before** any request is
made: an unknown role in `createUser`, an unknown log level in `setLogging`, an
unknown RPZ action in `addRule`.

## Role requirements

The server enforces a three-level hierarchy: **viewer < operator < admin**.
Higher roles include everything below them.

| Role | Can do |
| --- | --- |
| `viewer` | Read-only access. Essentially limited to `status()` and `session()`. |
| `operator` | Everything a viewer can, plus all reads: zones, records, cache stats, effective config, ACL, blocklists, RPZ, DNSSEC status, upstreams, GeoDNS, cluster, dashboard, metrics. Also zone and record **writes** — create, delete, add, replace, PTR generation. |
| `admin` | Everything an operator can, plus the privileged operations: user management, zone reload, cache flush, config reload, all runtime-config setters, blocklist changes, RPZ rule changes, DNSSEC key listing, upstream changes, and cluster join/leave. |

A 403 means the token is valid but the role is too low — re-authenticate as a
higher role rather than retrying.

## Operation coverage

All 71 operations in the API contract. `GET`/`POST`/`PUT`/`DELETE` is the HTTP
verb; the last column is the exact SDK method.

| # | Method | Endpoint | SDK call | Min. role |
| --- | --- | --- | --- | --- |
| 1 | GET | `/health` | `client.health()` | none |
| 2 | GET | `/readyz` | `client.ready()` | none |
| 3 | GET | `/livez` | `client.live()` | none |
| 4 | GET | `/api/v1/status` | `client.status()` | any |
| 5 | GET | `/api/v1/server/config` | `client.serverConfig()` | operator |
| 6 | GET | `/api/openapi.json` | `client.openapiSpec()` | any |
| 7 | GET | `/api/docs` | `client.docs()` | any |
| 8 | GET | `/api/docs/app.js` | `client.docsApp()` | any |
| 9 | POST | `/api/v1/csp-report` | `client.cspReport(map)` | none |
| 10 | POST | `/api/v1/auth/login` | `client.auth().login(user, pass)` | none |
| 11 | POST | `/api/v1/auth/bootstrap` | `client.auth().bootstrap(user, pass[, old])` | none |
| 12 | GET | `/api/v1/auth/session` | `client.auth().session()` | any |
| 13 | POST | `/api/v1/auth/logout` | `client.auth().logout()` | any |
| 14 | GET | `/api/v1/auth/roles` | `client.auth().roles()` | operator |
| 15 | GET | `/api/v1/auth/users` | `client.auth().listUsers()` | operator |
| 16 | POST | `/api/v1/auth/users` | `client.auth().createUser(user, pass, role)` | admin |
| 17 | DELETE | `/api/v1/auth/users?username=` | `client.auth().deleteUserByQuery(name)` | admin |
| 18 | DELETE | `/api/v1/auth/users/{username}` | `client.auth().deleteUser(name)` | admin |
| 19 | GET | `/api/v1/zones` | `client.zones().list()` | operator |
| 20 | POST | `/api/v1/zones` | `client.zones().create(name, ns[, email, ttl])` | operator |
| 21 | POST | `/api/v1/zones/reload?zone=` | `client.zones().reload(zone)` | admin |
| 22 | GET | `/api/v1/zones/transfers` | `client.zones().transfers()` | operator |
| 23 | GET | `/api/v1/zones/{zone}` | `client.zones().get(zone)` | operator |
| 24 | DELETE | `/api/v1/zones/{zone}` | `client.zones().delete(zone)` | operator |
| 25 | GET | `/api/v1/zones/{zone}/records` | `client.zones().listRecords(zone[, name])` | operator |
| 26 | POST | `/api/v1/zones/{zone}/records` | `client.zones().addRecord(zone, name, type, data[, ttl])` | operator |
| 27 | PUT | `/api/v1/zones/{zone}/records` | `client.zones().replaceRecord(zone, name, type, old, data[, ttl])` | operator |
| 28 | DELETE | `/api/v1/zones/{zone}/records` | `client.zones().deleteRecords(zone, name, type)` | operator |
| 29 | GET | `/api/v1/zones/{zone}/export` | `client.zones().export(zone)` | operator |
| 30 | POST | `/api/v1/zones/{zone}/ptr-bulk` | `client.zones().ptrBulkPreview(...)` / `ptrBulk(...)` | operator |
| 31 | GET | `/api/v1/zones/{zone}/ptr6-lookup?ip=` | `client.zones().ptr6Lookup(zone, ip)` | operator |
| 32 | GET | `/api/v1/cache/stats` | `client.cache().stats()` | operator |
| 33 | POST | `/api/v1/cache/flush` | `client.cache().flush()` | admin |
| 34 | GET | `/api/v1/config` | `client.config().get()` | operator |
| 35 | POST | `/api/v1/config/reload` | `client.config().reload()` | admin |
| 36 | PUT | `/api/v1/config/logging` | `client.config().setLogging(level)` | admin |
| 37 | PUT | `/api/v1/config/rrl` | `client.config().setRrl(enabled, rate, burst, maxBuckets)` | admin |
| 38 | PUT | `/api/v1/config/cache` | `client.config().setCache(...)` | admin |
| 39 | PUT | `/api/v1/config/resolution` | `client.config().setResolution(...)` | admin |
| 40 | PUT | `/api/v1/config/dns64` | `client.config().setDns64(enabled)` | admin |
| 41 | PUT | `/api/v1/config/cookie` | `client.config().setCookie(enabled)` | admin |
| 42 | GET | `/api/v1/acl` | `client.acl().get()` | operator |
| 43 | PUT | `/api/v1/acl` | `client.acl().set(rules)` | admin |
| 44 | GET | `/api/v1/acl/recursion` | `client.acl().recursion()` | operator |
| 45 | PUT | `/api/v1/acl/recursion` | `client.acl().setRecursion(networks)` | admin |
| 46 | GET | `/api/v1/blocklists` | `client.blocklists().stats()` | operator |
| 47 | POST | `/api/v1/blocklists` | `client.blocklists().add(file, url)` | admin |
| 48 | GET | `/api/v1/blocklists/sources` | `client.blocklists().sources()` | operator |
| 49 | POST | `/api/v1/blocklists/toggle` | `client.blocklists().toggle()` | admin |
| 50 | DELETE | `/api/v1/blocklists/{source}` | `client.blocklists().remove(source)` | admin |
| 51 | POST | `/api/v1/blocklists/{source}/toggle` | `client.blocklists().toggleSource(source)` | admin |
| 52 | GET | `/api/v1/rpz` | `client.rpz().stats()` | operator |
| 53 | GET | `/api/v1/rpz/rules` | `client.rpz().rules()` | operator |
| 54 | POST | `/api/v1/rpz/rules` | `client.rpz().addRule(pattern[, action, overrideData])` | admin |
| 55 | DELETE | `/api/v1/rpz/rules?pattern=` | `client.rpz().deleteRule(pattern)` | admin |
| 56 | POST | `/api/v1/rpz/toggle` | `client.rpz().toggle()` | admin |
| 57 | GET | `/api/v1/dnssec/status` | `client.dnssec().status()` | operator |
| 58 | GET | `/api/v1/dnssec/keys` | `client.dnssec().keys()` | admin |
| 59 | GET | `/api/v1/upstreams` | `client.upstreams().list()` | operator |
| 60 | PUT | `/api/v1/upstreams` | `client.upstreams().add(server)` / `remove(server)` | admin |
| 61 | GET | `/api/v1/geoip/stats` | `client.geoip().stats()` | operator |
| 62 | GET | `/api/v1/cluster/status` | `client.cluster().status()` | operator |
| 63 | GET | `/api/v1/cluster/nodes` | `client.cluster().nodes()` | operator |
| 64 | POST | `/api/v1/cluster/join` | `client.cluster().join(seedAddress)` | admin |
| 65 | DELETE | `/api/v1/cluster/leave` | `client.cluster().leave()` | admin |
| 66 | GET | `/api/dashboard/stats` | `client.dashboard().stats()` | operator |
| 67 | GET | `/api/dashboard/queries` | `client.dashboard().queries()` | operator |
| 68 | GET | `/api/dashboard/zones` | `client.dashboard().zones()` | operator |
| 69 | GET | `/api/v1/queries` | `client.metrics().queryLog([offset, limit, q])` | operator |
| 70 | GET | `/api/v1/topdomains` | `client.metrics().topDomains([limit])` | operator |
| 71 | GET | `/api/v1/metrics/history` | `client.metrics().history()` | operator |

Operations 17 and 18 are the two documented forms of the same delete-user
endpoint. `deleteUser(name)` uses the path form (the usual choice) and
`deleteUserByQuery(name)` the query form; both are provided for full contract
coverage.

## Wire-format notes

- Most groups use **snake_case** on the wire. Java fields are camelCase and
  carry `@SerializedName` to map them (`getHitRatio()` ↔ `hit_ratio`).
- Three groups use **camelCase** on the wire and the Java fields match it
  directly: `/api/dashboard` (`clientIp`, `queryType`, `queriesTotal`),
  `ptr6-lookup` (`ptrFQDN`) and `ptr-bulk` (`willAdd`, `addedA`).
- Timestamps are ISO-8601 strings, exposed as `String` rather than
  `Instant`, so no date format is imposed on callers.
- The effective config (`config().get()`) and the OpenAPI document
  (`openapiSpec()`) are returned as `JsonObject`, because their shape is
  server-defined and can grow between releases.

## License

Distributed under the same license as the NothingDNS project.
