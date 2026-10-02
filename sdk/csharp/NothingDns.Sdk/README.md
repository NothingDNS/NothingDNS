# NothingDns.Sdk

A dependency-free C# client for the **NothingDNS** management API.

Targets `net8.0` and uses only the .NET base class library — `System.Net.Http.HttpClient`
for transport and `System.Text.Json` for serialization. There are no NuGet dependencies
to audit, no transitive supply chain, and nothing to keep in sync with a third party.

The SDK covers **all 71 operations** of the NothingDNS management API, including health
probes, zone and record management, the response cache, runtime configuration, ACLs,
blocklists, response policy zones, DNSSEC, upstream health, GeoIP, clustering, the
dashboard counters and the query log.

---

## Table of contents

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
  - [GeoIP](#geoip)
  - [Cluster](#cluster)
  - [Dashboard](#dashboard)
  - [Metrics](#metrics)
- [Error handling](#error-handling)
- [Role requirements](#role-requirements)
- [Cancellation and concurrency](#cancellation-and-concurrency)
- [Full operation coverage](#full-operation-coverage)
- [Building and running the example](#building-and-running-the-example)

---

## Features

- **Complete.** All 71 API operations, including the health probes, the CSP report sink
  and the API explorer documents.
- **No dependencies.** BCL only. Nothing to audit, nothing to upgrade.
- **Strongly typed.** Every response shape has a model with an explicit
  `[JsonPropertyName]`, so the wire format stays exactly what the server sends
  (`snake_case` on `/api/v1`, `camelCase` on `/api/dashboard` and the PTR bulk and
  PTR IPv6 lookup shapes) while your C# property names stay idiomatic PascalCase.
- **Forward compatible.** Models have defaults, so a field a server build omits leaves
  its default in place instead of failing to deserialize. A newer server that adds
  fields never breaks an older client.
- **Async throughout.** Every method is `async Task<T>` and takes an optional
  `CancellationToken`. The client implements `IAsyncDisposable`, so `await using`
  works.
- **Precise errors.** HTTP failures become a single `NothingDnsApiException` carrying
  the status code, the server's own message and the decoded payload, with
  `IsNotFound` / `IsUnauthorized` / `IsForbidden` / `IsRateLimited` for use in
  exception filters.
- **Correctly escaped.** Zone names, blocklist source ids and usernames are
  percent-encoded with `Uri.EscapeDataString`, so a name containing a slash or a space
  cannot alter the shape of the request URL.
- **Partial updates.** Config and ACL setters omit `null` arguments from the request
  body, so leaving an argument out means "leave unchanged" rather than "send null".
- **Fully documented.** XML doc comments on every public member, with
  `GenerateDocumentationFile` enabled, so the compiler warns on any missing doc.

---

## Install

The library targets `net8.0` and has no package dependencies.

```bash
# From a clone of this repository
dotnet add reference /path/to/sdk/csharp/NothingDns.Sdk/NothingDns.Sdk.csproj

# Or build and pack it locally
cd sdk/csharp
dotnet pack NothingDns.Sdk/NothingDns.Sdk.csproj -c Release
# -> NothingDns.Sdk.1.0.0.nupkg
dotnet nuget push NothingDns.Sdk.1.0.0.nupkg -s https://your-nuget-feed/
```

Then in your project:

```xml
<PackageReference Include="NothingDns.Sdk" Version="1.0.0" />
```

---

## Quick start

```csharp
using NothingDns.Sdk;

await using var client = new NothingDnsClient("http://dns.example.com:8080");

// Log in. The token is stored on the client, so every later call is authenticated.
var session = await client.Auth.LoginAsync(
    Environment.GetEnvironmentVariable("NDNS_USER")!,
    Environment.GetEnvironmentVariable("NDNS_PASSWORD")!,
    cancellationToken: cancellationToken);

Console.WriteLine($"Hello {session.Username}, you are {session.Role}");

// List zones.
var zones = await client.Zones.ListAsync(cancellationToken);
foreach (var zone in zones.Zones)
{
    Console.WriteLine($"{zone.Name}: {zone.Records} records, serial {zone.Serial}");
}

// Add an A record.
await client.Zones.AddRecordAsync(
    "example.com",
    "www",
    "A",
    "203.0.113.10",
    ttl: 300,
    cancellationToken: cancellationToken);

// Read the cache statistics.
var cache = await client.Cache.StatsAsync(cancellationToken);
Console.WriteLine($"cache hit ratio {cache.HitRatio:P1}");

// Print a zone export.
Console.WriteLine(await client.Zones.ExportAsync("example.com", cancellationToken));
```

A complete, runnable version of this is in
[`Examples/QuickStart.cs`](NothingDns.Sdk/Examples/QuickStart.cs).

---

## Authentication

The NothingDNS management API accepts two kinds of bearer token. Both are set the same
way — on the client — and both are sent as `Authorization: Bearer <token>`.

### Option 1: log in for a real session (recommended)

```csharp
await using var client = new NothingDnsClient("http://dns.example.com:8080");

var session = await client.Auth.LoginAsync("admin", password, cancellationToken: ct);
Console.WriteLine(session.Token);   // JWT
Console.WriteLine(session.Expires); // RFC 3339 expiry, when the server reports one
```

`LoginAsync` stores the token on the client by default, so every namespace is
authenticated afterwards. Pass `storeToken: false` if you want to keep control of it.

**Bootstrap the first admin.** On a fresh server there is no account yet. `BootstrapAsync`
creates the first admin, and also resets a password when you supply the current one:

```csharp
// First run on an empty server: creates the initial admin.
var first = await client.Auth.BootstrapAsync("admin", newPassword, cancellationToken: ct);

// Later, to rotate a password: the current one is required.
var reset = await client.Auth.BootstrapAsync(
    "admin",
    newPassword,
    oldPassword: currentPassword,
    cancellationToken: ct);
```

### Option 2: the static `server.http.auth_token`

If your server is configured with a static token in its `server.http` section, pass it
straight to the constructor — no login round trip:

```csharp
await using var client = new NothingDnsClient(
    "http://dns.example.com:8080",
    token: Environment.GetEnvironmentVariable("NDNS_TOKEN"));
```

You can also set it later on a running client:

```csharp
client.SetToken(Environment.GetEnvironmentVariable("NDNS_TOKEN"));
```

> **Note.** The server rejects the legacy static `auth_token` for
> `GET /api/v1/auth/session` (it answers 405). A real login session is required for that
> one endpoint; every other endpoint accepts the static token.

### Sessions and logout

```csharp
// Rebuild the in-memory session after a reload.
var current = await client.Auth.SessionAsync(ct);

// Invalidate the session on the server and forget the token locally.
var message = await client.Auth.LogoutAsync(ct);
```

`LogoutAsync` clears the local token as well as invalidating it on the server, so
subsequent calls are sent unauthenticated rather than failing with 401.

### Managing users

```csharp
foreach (var user in await client.Auth.ListUsersAsync(ct))
{
    Console.WriteLine($"{user.Username}: {user.Role}");
}

await client.Auth.CreateUserAsync("alice", "s3cret", NothingDnsRoles.Operator, ct);
await client.Auth.DeleteUserAsync("alice", ct);
```

`CreateUserAsync` validates the role locally against
`NothingDnsRoles.Viewer` / `Operator` / `Admin` and throws
`NothingDnsValidationException` for anything else, before the request is sent.

---

## Configuration options

The `NothingDnsClient` constructor takes everything you can tune:

```csharp
await using var client = new NothingDnsClient(
    baseUrl:  "http://dns.example.com:8080",  // server.http listener; default http://localhost:8080
    token:    null,                          // start authenticated; or set later with SetToken
    timeout:  TimeSpan.FromSeconds(15),      // per-request timeout; default 30s
    httpClient: sharedHttpClient,            // inject your own HttpClient (proxy, pool, handlers)
    headers:  new Dictionary<string, string> { ["X-Trace-Id"] = traceId });
```

| Option | Default | Notes |
| --- | --- | --- |
| `baseUrl` | `http://localhost:8080` | Absolute URI. A trailing slash is optional. Throws `ArgumentException` if empty or not absolute. |
| `token` | `null` | A JWT or the static `server.http.auth_token`. |
| `timeout` | 30 s | Enforced per request via a linked `CancellationTokenSource`, so it also works with an injected `HttpClient` whose own `Timeout` you do not want to mutate. |
| `httpClient` | created internally | When you supply one, the SDK never mutates its `Timeout` and never disposes it — you keep ownership. Use it to share a proxy or connection pool. |
| `headers` | none | Merged into every request. `Accept: application/json` is always set. |

Reading back what the client is using:

```csharp
client.BaseUrl;   // "http://dns.example.com:8080"
client.Token;     // current bearer token, or null
client.Transport; // the underlying transport, for endpoints the SDK does not model
```

Timeouts that elapse and hosts that cannot be reached both surface as
`NothingDnsConnectionException`, with the original transport exception as `InnerException`.
A cancellation *you* requested is never wrapped — it propagates as the standard
`OperationCanceledException`.

---

## Namespaces

Every namespace requires at least the **operator** role unless noted otherwise.

### Health and status

On the client itself, not in a namespace. `HealthAsync`, `ReadyAsync` and `LiveAsync`
need no authentication.

```csharp
Console.WriteLine((await client.HealthAsync(ct)).Status);   // healthy | ready | alive | unhealthy
Console.WriteLine((await client.LiveAsync(ct)).Status);     // liveness
Console.WriteLine((await client.ReadyAsync(ct)).Status);    // readiness

// Treat "not ready" as a gate, not as a hard failure.
try
{
    await client.ReadyAsync(ct);
    Console.WriteLine("ready to serve");
}
catch (NothingDnsApiException ex) when (ex.StatusCode == 503)
{
    Console.WriteLine("still starting up");
}

var status = await client.StatusAsync(ct);
Console.WriteLine($"{status.Version} cache hit ratio {status.Cache?.HitRatio:P1}");

var config = await client.ServerConfigAsync(ct);
Console.WriteLine($"port {config.ListenPort}, log level {config.LogLevel}, DNS64 {config.Dns64?.Enabled}");
```

`OpenApiSpecAsync()` returns the server's OpenAPI document as a `JsonElement`, which is
useful for detecting capabilities that this SDK version predates. `ApiDocsAsync()` and
`ApiDocsScriptAsync()` fetch the interactive explorer.

### Auth

```csharp
var session = await client.Auth.LoginAsync("admin", password, ct);
var roles   = await client.Auth.RolesAsync(ct);
var users   = await client.Auth.ListUsersAsync(ct);

var alice = await client.Auth.CreateUserAsync("alice", "s3cret", NothingDnsRoles.Viewer, ct);
await client.Auth.DeleteUserAsync("alice", ct);
```

### Zones

```csharp
// Create a zone.
await client.Zones.CreateAsync(
    "example.com",
    new[] { "ns1.example.com", "ns2.example.com" },
    adminEmail: "hostmaster@example.com",
    ttl: 3600,
    cancellationToken: ct);

// Inspect it.
var detail = await client.Zones.GetAsync("example.com", ct);
Console.WriteLine($"serial {detail.Serial}, SOA {detail.Soa?.Mname}, NS {string.Join(", ", detail.Nameservers)}");

// Records.
await client.Zones.AddRecordAsync("example.com", "www", "A", "203.0.113.10", ttl: 300, cancellationToken: ct);
await client.Zones.ReplaceRecordAsync("example.com", "www", "A", "203.0.113.10", "203.0.113.11", cancellationToken: ct);
await client.Zones.AddRecordAsync("example.com", "@", "MX", "10 mail.example.com", cancellationToken: ct);
await client.Zones.DeleteRecordsAsync("example.com", "www", "A", cancellationToken: ct);

var records = await client.Zones.ListRecordsAsync("example.com", name: "www", cancellationToken: ct);
foreach (var record in records.Records)
{
    Console.WriteLine($"{record.Name} {record.Ttl} IN {record.Type} {record.Data}");
}

// Export and tear down.
Console.WriteLine(await client.Zones.ExportAsync("example.com", ct));
await client.Zones.DeleteAsync("example.com", ct);
```

Secondary zones and single-zone reloads:

```csharp
foreach (var slave in await client.Zones.TransfersAsync(ct))
{
    Console.WriteLine($"{slave.Zone}: {slave.Status} at serial {slave.Serial}");
}

await client.Zones.ReloadAsync("example.com", ct);   // admin; re-reads the zone file
```

Bulk PTR generation. `preview: true` writes nothing and returns the plan:

```csharp
var plan = await client.Zones.PtrBulkAsync(
    "2.0.192.in-addr.arpa",
    "192.0.2.0/24",
    "host-{ip}.example.com",
    addA: true,
    preview: true,
    cancellationToken: ct);

if (plan.Preview)
{
    Console.WriteLine($"would add {plan.WillAdd} PTR and {plan.WillAddA} A, skip {plan.WillSkip}");
    foreach (var change in plan.Changes.Take(5))
    {
        Console.WriteLine($"  {change.Action} {change.Name} {change.Type} {change.Data}");
    }
}
else
{
    Console.WriteLine($"added {plan.Added} PTR and {plan.AddedA} A records");
}

// Commit the same range for real.
var applied = await client.Zones.PtrBulkAsync(
    "2.0.192.in-addr.arpa", "192.0.2.0/24", "host-{ip}.example.com", addA: true, preview: false, ct);
```

IPv6 reverse lookups:

```csharp
var ptr = await client.Zones.Ptr6LookupAsync("8.b.d.0.1.0.0.2.ip6.arpa", "2001:db8::1", ct);
if (ptr.Found)
{
    Console.WriteLine($"{ptr.Ip} -> {ptr.PtrFqdn} = {ptr.Target} (ttl {ptr.Ttl})");
}
```

### Cache

```csharp
var stats = await client.Cache.StatsAsync(ct);
Console.WriteLine($"{stats.Size}/{stats.Capacity} entries, {stats.HitRatio:P1} hit ratio");

await client.Cache.FlushAsync(ct);   // admin only
```

### Config

Reads need operator; every setter needs admin. Setters are **partial updates** — an
argument left `null` is omitted from the request and left unchanged on the server.
Runtime changes are written to `runtime_overrides.json` and survive a restart.

```csharp
var effective = await client.Config.GetAsync(ct);          // secrets are redacted
Console.WriteLine(effective.GetRawText());

await client.Config.SetLoggingAsync(NothingDnsLogLevels.Debug, ct);
await client.Config.SetResolutionAsync(recursive: true, maxDepth: 12, qnameMinimization: true, cancellationToken: ct);
await client.Config.SetCacheAsync(negativeTtl: 60, serveStale: true, staleGraceSecs: 30, cancellationToken: ct);
await client.Config.SetRrlAsync(enabled: true, rate: 100, burst: 200, cancellationToken: ct);
await client.Config.SetDns64Async(enabled: true, cancellationToken: ct);
await client.Config.SetCookieAsync(enabled: true, cancellationToken: ct);

await client.Config.ReloadAsync(ct);   // re-read the YAML file from disk
```

`SetLoggingAsync` and `NothingDnsLogLevels` validate the level locally
(`debug`, `info`, `warn`, `warning`, `error`, `fatal`) and send it lowercased.

### ACL

Rules are evaluated in order and the first match wins. Once any rule exists, a client
matching none of them is refused.

```csharp
var acl = await client.Acl.GetAsync(ct);
Console.WriteLine($"{acl.Rules.Count} rules, persistent={acl.Persistent}, file={acl.PolicyFile}");

// SetAsync replaces the whole list, so read-modify-write to change one rule.
var rules = acl.Rules.ToList();
rules.Add(new AclRule
{
    Name = "office",
    Networks = { "10.0.0.0/8" },
    Action = "allow",
    Types = { "A", "AAAA" },
});

await client.Acl.SetAsync(rules, ct);
```

> `SetAsync` refuses an empty list deliberately: with no rules the server would refuse
> every client, and a typo that clears the list would silently take the server offline.

Recursion allow list:

```csharp
var recursion = await client.Acl.RecursionAsync(ct);
Console.WriteLine($"allow_all={recursion.AllowAll}, networks={string.Join(", ", recursion.Networks)}");

await client.Acl.SetRecursionAsync(new[] { "10.0.0.0/8", "192.168.0.0/16" }, ct);
```

### Blocklists

```csharp
var stats = await client.Blocklists.StatsAsync(ct);
Console.WriteLine($"{stats.TotalRules} rules from {stats.FilesCount} files and {stats.UrlsCount} URLs");

await client.Blocklists.AddAsync(url: "https://example.invalid/hosts.txt", cancellationToken: ct);
await client.Blocklists.AddAsync(file: "/etc/nothingdns/extra.hosts", cancellationToken: ct);

foreach (var source in await client.Blocklists.SourcesAsync(ct))
{
    Console.WriteLine($"{source.Id} [{source.Type}] enabled={source.Enabled} domains={source.Domains}");
    await client.Blocklists.ToggleSourceAsync(source.Id, ct);
    await client.Blocklists.RemoveAsync(source.Id, ct);
}

await client.Blocklists.ToggleAsync(ct);   // global on/off
```

### RPZ

```csharp
var stats = await client.Rpz.StatsAsync(ct);
Console.WriteLine($"{stats.TotalRules} rules, {stats.TotalMatches} matches over {stats.TotalLookups} lookups");

var ruleList = await client.Rpz.RulesAsync(ct);
foreach (var rule in ruleList.Rules)
{
    Console.WriteLine($"{rule.Priority} {rule.Pattern} -> {rule.Action} (trigger {rule.Trigger})");
}

await client.Rpz.AddRuleAsync("ads.example.net", NothingDnsRpzActions.Nxdomain, cancellationToken: ct);
await client.Rpz.AddRuleAsync("track.example.org", NothingDnsRpzActions.Drop, cancellationToken: ct);
await client.Rpz.DeleteRuleAsync("ads.example.net", ct);
await client.Rpz.ToggleAsync(ct);
```

Accepted actions are listed on `NothingDnsRpzActions`: `NXDOMAIN`, `NODATA`, `CNAME`,
`OVERRIDE`, `DROP`, `PASSTHROUGH`, `TCPONLY`. An unknown action throws
`NothingDnsValidationException` before the request is sent.

### DNSSEC

```csharp
var status = await client.Dnssec.StatusAsync(ct);
Console.WriteLine($"enabled={status.Enabled}, require={status.RequireDnssec}");

var keys = await client.Dnssec.KeysAsync(ct);   // admin; public metadata only
foreach (var key in keys.Zones)
{
    Console.WriteLine($"zone {key.Zone} tag {key.KeyTag} alg {key.Algorithm} KSK={key.IsKsk} ZSK={key.IsZsk}");
}
```

### Upstreams

```csharp
var pool = await client.Upstreams.ListAsync(ct);
foreach (var server in pool.Servers)
{
    Console.WriteLine($"{server.Address}: healthy={server.Healthy} {server.LatencyMs:F1} ms");
}
foreach (var upstream in pool.Health)
{
    Console.WriteLine($"{upstream.Address}: {upstream.Queries} queries, {upstream.Failed} failed, {upstream.Failovers} failovers");
}

await client.Upstreams.AddAsync("9.9.9.9:53", ct);
await client.Upstreams.RemoveAsync("9.9.9.9:53", ct);
```

`AddAsync` and `RemoveAsync` are two conveniences over the single `PUT /api/v1/upstreams`
operation, which takes an `action` of `add` or `remove`.

### GeoIP

```csharp
var geo = await client.GeoIp.StatsAsync(ct);
Console.WriteLine($"enabled={geo.Enabled} mmdb={geo.MmdbLoaded} rules={geo.Rules} hits={geo.Hits}/{geo.Lookups}");
```

### Cluster

```csharp
var status = await client.Cluster.StatusAsync(ct);
Console.WriteLine($"{status.NodeId}: {status.AliveCount}/{status.NodeCount} alive, {status.Consensus} term {status.Raft?.Term}");
Console.WriteLine($"leader={status.Raft?.LeaderId} isLeader={status.Raft?.IsLeader}");
Console.WriteLine($"latency avg {status.Metrics?.LatencyAvgMs:F1} ms p99 {status.Metrics?.LatencyP99Ms:F1} ms");

foreach (var node in await client.Cluster.NodesAsync(ct))
{
    Console.WriteLine($"{node.Id} {node.State} {node.Role} health={node.HealthScore} qps={node.QueriesPerSecond:F1}");
}

await client.Cluster.JoinAsync("10.0.0.5:7946", ct);   // admin
await client.Cluster.LeaveAsync(ct);                    // admin: drain and leave
```

### Dashboard

```csharp
var stats = await client.Dashboard.StatsAsync(ct);
Console.WriteLine($"up {stats.Uptime}s, {stats.QueriesTotal} queries, {stats.QueriesPerSec:F1}/s, "
                  + $"{stats.BlockedQueries} blocked, {stats.ActiveClients} clients, {stats.ZoneCount} zones");

foreach (var evt in (await client.Dashboard.QueriesAsync(ct)).Take(10))
{
    Console.WriteLine($"{evt.Timestamp} {evt.ClientIp} {evt.Domain} {evt.QueryType} -> {evt.ResponseCode} "
                      + $"cached={evt.Cached} blocked={evt.Blocked} {evt.Protocol} {evt.Duration}ms");
}

foreach (var zone in await client.Dashboard.ZonesAsync(ct))
{
    Console.WriteLine($"{zone.Name}: {zone.Records} records");
}
```

### Metrics

```csharp
var page = await client.Metrics.QueryLogAsync(offset: 0, limit: 50, q: "example.com", cancellationToken: ct);
Console.WriteLine($"{page.Queries.Count} of {page.Total} rows");
foreach (var row in page.Queries)
{
    Console.WriteLine($"{row.Timestamp} {row.ClientIp} {row.Domain} {row.QueryType} -> {row.ResponseCode} {row.DurationMs}ms");
}

var top = await client.Metrics.TopDomainsAsync(limit: 10, ct);
foreach (var entry in top.Domains)
{
    Console.WriteLine($"{entry.Domain}: {entry.Count}");
}

var history = await client.Metrics.HistoryAsync(ct);
Console.WriteLine($"{history.Count} samples; latest latency {history.LatencyMs.LastOrDefault()} ms");
```

---

## Error handling

The SDK raises three exception types, all deriving from `NothingDnsException`:

| Exception | Meaning |
| --- | --- |
| `NothingDnsApiException` | The server answered with a 4xx/5xx status. Carries `StatusCode`, the server's message (on `Exception.Message`), `Payload` (decoded JSON) and `RawBody`. |
| `NothingDnsConnectionException` | The server could not be reached, or the request exceeded the timeout. `InnerException` holds the underlying transport error. |
| `NothingDnsValidationException` | A response was not valid JSON, or an argument failed local validation before any request was sent. |

A cancellation **you** requested is not wrapped: it propagates as the standard
`OperationCanceledException`, so `TaskCanceledException` handling stays conventional.

### Status codes

`NothingDnsApiException` exposes the status code plus ready-made predicates for the
common cases:

| Status | Predicate | Typical cause |
| --- | --- | --- |
| 400 | | Malformed request, invalid record data, unparsable address or duration, invalid ACL rule. |
| 401 | `IsUnauthorized` | Missing, invalid or expired token; wrong password on login. |
| 403 | `IsForbidden` | The caller's role is not high enough for this operation. |
| 404 | `IsNotFound` | The zone, record, blocklist source or user does not exist. |
| 405 | | `GET /api/v1/auth/session` called with the legacy static token. |
| 409 | | Username already exists; zone already exists; upstream already configured. |
| 421 | | Misdirected: the zone is a subdomain of another, or a record conflicts or is required. |
| 429 | `IsRateLimited` | The endpoint's own rate limit, including the login limiter. |
| 500 | | The configuration file or a zone file could not be parsed; a cluster drain did not complete. |
| 503 | | The subsystem is not ready: not ready to serve queries, or a subsystem is starting or shutting down. |

### Handling patterns

Filter on the predicate directly:

```csharp
try
{
    var zone = await client.Zones.GetAsync("missing.example.com", ct);
}
catch (NothingDnsApiException ex) when (ex.IsNotFound)
{
    Console.WriteLine("that zone does not exist");
}
catch (NothingDnsApiException ex) when (ex.IsForbidden)
{
    Console.WriteLine("you need at least the operator role");
}
catch (NothingDnsApiException ex) when (ex.IsRateLimited)
{
    await Task.Delay(TimeSpan.FromSeconds(2), ct);
}
```

The static helpers on `NothingDnsErrors` do the same for catch blocks that handle a
broader type:

```csharp
catch (Exception ex) when (NothingDnsErrors.IsNotFound(ex))
{
    // ...
}
```

Inspect the payload when the server sends structured detail:

```csharp
catch (NothingDnsApiException ex) when (ex.StatusCode == 409)
{
    if (ex.Payload is { ValueKind: JsonValueKind.Object } payload)
    {
        Console.Error.WriteLine(payload.GetProperty("error").GetString());
    }
    Console.Error.WriteLine(ex.RawBody);   // the untruncated body
}
```

Retry only what is actually transient. A `429` or a `503` is worth retrying; a `403` is
not, and retrying it will never succeed.

```csharp
static async Task<T> WithRetryAsync<T>(Func<Task<T>> call, CancellationToken ct)
{
    for (var attempt = 1; ; attempt++)
    {
        try
        {
            return await call();
        }
        catch (NothingDnsApiException ex) when (ex.IsRateLimited || ex.StatusCode == 503)
        {
            if (attempt >= 5) throw;
            await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, attempt)), ct);
        }
    }
}
```

---

## Role requirements

NothingDNS has three roles, ordered **viewer < operator < admin**. A role permits
everything the lower roles do.

| Role | Can do |
| --- | --- |
| **viewer** | Read-only. Effectively `/health`, `/readyz`, `/livez` and `GET /api/v1/status`; the management endpoints below all require more. |
| **operator** | Everything a viewer can do, plus: list and create/delete zones, manage records, export zones, read cache statistics, read the effective configuration, read ACLs, read blocklist and RPZ statistics and rules, read DNSSEC status, read upstream health, read GeoIP, read cluster status and nodes, read the dashboard, read the query log and metrics history, list users and roles, and restore a session. |
| **admin** | Everything an operator can do, plus: create and delete users, flush the cache, reload a single zone from its file, change every runtime configuration setting, write ACL rules and the recursion allow list, add/remove/toggle blocklist sources, add/delete RPZ rules and toggle RPZ, read DNSSEC signing keys, add and remove upstreams, and join or leave a cluster. |

Enforced operations by role:

- **Any** (no token needed): `GET /health`, `GET /readyz`, `GET /livez`.
- **Any authenticated user**: `GET /api/v1/status`, `GET /api/v1/auth/session`,
  `POST /api/v1/auth/logout`. On `/api/v1/status` the `cache` block is only populated
  for operators and admins.
- **operator**: every other read endpoint, plus `GET /api/v1/auth/roles` and
  `GET /api/v1/auth/users`.
- **admin**: every write endpoint, plus `POST /api/v1/auth/users`,
  `DELETE /api/v1/auth/users[/{username}]`, `POST /api/v1/cache/flush`,
  `POST /api/v1/zones/reload`, all `PUT /api/v1/config/*`,
  `PUT /api/v1/acl`, `PUT /api/v1/acl/recursion`, `POST /api/v1/blocklists`,
  `POST /api/v1/blocklists/toggle`, `DELETE /api/v1/blocklists/{source}`,
  `POST /api/v1/blocklists/{source}/toggle`, `POST /api/v1/rpz/rules`,
  `DELETE /api/v1/rpz/rules`, `POST /api/v1/rpz/toggle`,
  `GET /api/v1/dnssec/keys`, `PUT /api/v1/upstreams`,
  `POST /api/v1/cluster/join`, `DELETE /api/v1/cluster/leave`.

A 403 means the role is too low; a 401 means the token is missing, wrong or expired.
They are worth telling apart in your logs.

---

## Cancellation and concurrency

Every method takes an optional `CancellationToken` as its last argument:

```csharp
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
var stats = await client.Cache.StatsAsync(cts.Token);
```

A client is safe to share across concurrent requests: the transport reads its bearer
token once per request and keeps no other mutable per-request state. When you inject
your own `HttpClient`, give each thread its own `NothingDnsClient` so the client object
itself is not shared across threads; the `HttpClient` itself remains safe to share.

Dispose the client when you are done so the connection pool is released:

```csharp
await using var client = new NothingDnsClient(baseUrl);
// ...
// Or, without await using:
client.DisposeAsync().GetAwaiter().GetResult();
```

An injected `HttpClient` is never disposed by the SDK — you keep ownership of it.

---

## Full operation coverage

All **71 operations** in the NothingDNS management API are covered.

### Health, status and documents (9)

| # | Method | HTTP | Role |
| --- | --- | --- | --- |
| 1 | `client.HealthAsync` | `GET /health` | any |
| 2 | `client.ReadyAsync` | `GET /readyz` | any |
| 3 | `client.LiveAsync` | `GET /livez` | any |
| 4 | `client.StatusAsync` | `GET /api/v1/status` | any |
| 5 | `client.ServerConfigAsync` | `GET /api/v1/server/config` | operator |
| 6 | `client.OpenApiSpecAsync` | `GET /api/openapi.json` | any |
| 7 | `client.ApiDocsAsync` | `GET /api/docs` | any |
| 8 | `client.ApiDocsScriptAsync` | `GET /api/docs/app.js` | any |
| 9 | `client.ReportCspAsync` | `POST /api/v1/csp-report` | any |

### Auth (9)

| # | Method | HTTP | Role |
| --- | --- | --- | --- |
| 10 | `client.Auth.LoginAsync` | `POST /api/v1/auth/login` | any |
| 11 | `client.Auth.BootstrapAsync` | `POST /api/v1/auth/bootstrap` | any / admin |
| 12 | `client.Auth.SessionAsync` | `GET /api/v1/auth/session` | any |
| 13 | `client.Auth.LogoutAsync` | `POST /api/v1/auth/logout` | any |
| 14 | `client.Auth.RolesAsync` | `GET /api/v1/auth/roles` | operator |
| 15 | `client.Auth.ListUsersAsync` | `GET /api/v1/auth/users` | operator |
| 16 | `client.Auth.CreateUserAsync` | `POST /api/v1/auth/users` | admin |
| 17 | `client.Auth.DeleteUserAsync` | `DELETE /api/v1/auth/users/{username}` | admin |
| 18 | `client.Auth.DeleteUserByQueryAsync` | `DELETE /api/v1/auth/users?username=` | admin |

### Zones (13)

| # | Method | HTTP | Role |
| --- | --- | --- | --- |
| 19 | `client.Zones.ListAsync` | `GET /api/v1/zones` | operator |
| 20 | `client.Zones.CreateAsync` | `POST /api/v1/zones` | operator |
| 21 | `client.Zones.ReloadAsync` | `POST /api/v1/zones/reload?zone=` | admin |
| 22 | `client.Zones.TransfersAsync` | `GET /api/v1/zones/transfers` | operator |
| 23 | `client.Zones.GetAsync` | `GET /api/v1/zones/{zone}` | operator |
| 24 | `client.Zones.DeleteAsync` | `DELETE /api/v1/zones/{zone}` | operator |
| 25 | `client.Zones.ListRecordsAsync` | `GET /api/v1/zones/{zone}/records` | operator |
| 26 | `client.Zones.AddRecordAsync` | `POST /api/v1/zones/{zone}/records` | operator |
| 27 | `client.Zones.ReplaceRecordAsync` | `PUT /api/v1/zones/{zone}/records` | operator |
| 28 | `client.Zones.DeleteRecordsAsync` | `DELETE /api/v1/zones/{zone}/records` | operator |
| 29 | `client.Zones.ExportAsync` | `GET /api/v1/zones/{zone}/export` | operator |
| 30 | `client.Zones.PtrBulkAsync` | `POST /api/v1/zones/{zone}/ptr-bulk` | operator |
| 31 | `client.Zones.Ptr6LookupAsync` | `GET /api/v1/zones/{zone}/ptr6-lookup?ip=` | operator |

### Cache (2)

| # | Method | HTTP | Role |
| --- | --- | --- | --- |
| 32 | `client.Cache.StatsAsync` | `GET /api/v1/cache/stats` | operator |
| 33 | `client.Cache.FlushAsync` | `POST /api/v1/cache/flush` | admin |

### Config (8)

| # | Method | HTTP | Role |
| --- | --- | --- | --- |
| 34 | `client.Config.GetAsync` | `GET /api/v1/config` | operator |
| 35 | `client.Config.ReloadAsync` | `POST /api/v1/config/reload` | admin |
| 36 | `client.Config.SetLoggingAsync` | `PUT /api/v1/config/logging` | admin |
| 37 | `client.Config.SetRrlAsync` | `PUT /api/v1/config/rrl` | admin |
| 38 | `client.Config.SetCacheAsync` | `PUT /api/v1/config/cache` | admin |
| 39 | `client.Config.SetResolutionAsync` | `PUT /api/v1/config/resolution` | admin |
| 40 | `client.Config.SetDns64Async` | `PUT /api/v1/config/dns64` | admin |
| 41 | `client.Config.SetCookieAsync` | `PUT /api/v1/config/cookie` | admin |

### ACL (4)

| # | Method | HTTP | Role |
| --- | --- | --- | --- |
| 42 | `client.Acl.GetAsync` | `GET /api/v1/acl` | operator |
| 43 | `client.Acl.SetAsync` | `PUT /api/v1/acl` | admin |
| 44 | `client.Acl.RecursionAsync` | `GET /api/v1/acl/recursion` | operator |
| 45 | `client.Acl.SetRecursionAsync` | `PUT /api/v1/acl/recursion` | admin |

### Blocklists (6)

| # | Method | HTTP | Role |
| --- | --- | --- | --- |
| 46 | `client.Blocklists.StatsAsync` | `GET /api/v1/blocklists` | operator |
| 47 | `client.Blocklists.AddAsync` | `POST /api/v1/blocklists` | admin |
| 48 | `client.Blocklists.SourcesAsync` | `GET /api/v1/blocklists/sources` | operator |
| 49 | `client.Blocklists.ToggleAsync` | `POST /api/v1/blocklists/toggle` | admin |
| 50 | `client.Blocklists.RemoveAsync` | `DELETE /api/v1/blocklists/{source}` | admin |
| 51 | `client.Blocklists.ToggleSourceAsync` | `POST /api/v1/blocklists/{source}/toggle` | admin |

### RPZ (5)

| # | Method | HTTP | Role |
| --- | --- | --- | --- |
| 52 | `client.Rpz.StatsAsync` | `GET /api/v1/rpz` | operator |
| 53 | `client.Rpz.RulesAsync` | `GET /api/v1/rpz/rules` | operator |
| 54 | `client.Rpz.AddRuleAsync` | `POST /api/v1/rpz/rules` | admin |
| 55 | `client.Rpz.DeleteRuleAsync` | `DELETE /api/v1/rpz/rules?pattern=` | admin |
| 56 | `client.Rpz.ToggleAsync` | `POST /api/v1/rpz/toggle` | admin |

### DNSSEC (2)

| # | Method | HTTP | Role |
| --- | --- | --- | --- |
| 57 | `client.Dnssec.StatusAsync` | `GET /api/v1/dnssec/status` | operator |
| 58 | `client.Dnssec.KeysAsync` | `GET /api/v1/dnssec/keys` | admin |

### Upstreams (1 operation, 2 methods)

| # | Method | HTTP | Role |
| --- | --- | --- | --- |
| 59 | `client.Upstreams.ListAsync` | `GET /api/v1/upstreams` | operator |
| 60 | `client.Upstreams.AddAsync` | `PUT /api/v1/upstreams` (`action=add`) | admin |
| 60 | `client.Upstreams.RemoveAsync` | `PUT /api/v1/upstreams` (`action=remove`) | admin |

### GeoIP (1)

| # | Method | HTTP | Role |
| --- | --- | --- | --- |
| 61 | `client.GeoIp.StatsAsync` | `GET /api/v1/geoip/stats` | operator |

### Cluster (4)

| # | Method | HTTP | Role |
| --- | --- | --- | --- |
| 62 | `client.Cluster.StatusAsync` | `GET /api/v1/cluster/status` | operator |
| 63 | `client.Cluster.NodesAsync` | `GET /api/v1/cluster/nodes` | operator |
| 64 | `client.Cluster.JoinAsync` | `POST /api/v1/cluster/join` | admin |
| 65 | `client.Cluster.LeaveAsync` | `DELETE /api/v1/cluster/leave` | admin |

### Dashboard (3)

| # | Method | HTTP | Role |
| --- | --- | --- | --- |
| 66 | `client.Dashboard.StatsAsync` | `GET /api/dashboard/stats` | operator |
| 67 | `client.Dashboard.QueriesAsync` | `GET /api/dashboard/queries` | operator |
| 68 | `client.Dashboard.ZonesAsync` | `GET /api/dashboard/zones` | operator |

### Metrics (3)

| # | Method | HTTP | Role |
| --- | --- | --- | --- |
| 69 | `client.Metrics.QueryLogAsync` | `GET /api/v1/queries` | operator |
| 70 | `client.Metrics.TopDomainsAsync` | `GET /api/v1/topdomains` | operator |
| 71 | `client.Metrics.HistoryAsync` | `GET /api/v1/metrics/history` | operator |

---

## Building and running the example

The repository contains a solution with two projects: the library and the runnable
example.

```
sdk/csharp/
├── NothingDns.sln
├── NothingDns.Sdk/
│   ├── NothingDns.Sdk.csproj      # the library (net8.0, BCL only)
│   ├── NothingDnsError.cs         # error types and status predicates
│   ├── NothingDnsTransport.cs     # HTTP core: URLs, bearer header, query, JSON, timeouts
│   ├── NothingDnsAuth.cs          # credential acquisition: login, bootstrap, users, roles
│   ├── NothingDnsClient.cs        # client wiring plus health/status/documents
│   ├── NothingDnsZones.cs
│   ├── NothingDnsCache.cs
│   ├── NothingDnsConfig.cs
│   ├── NothingDnsAcl.cs
│   ├── NothingDnsBlocklists.cs
│   ├── NothingDnsRpz.cs
│   ├── NothingDnsDnssec.cs
│   ├── NothingDnsUpstreams.cs
│   ├── NothingDnsGeoIp.cs
│   ├── NothingDnsCluster.cs
│   ├── NothingDnsDashboard.cs
│   ├── NothingDnsMetrics.cs
│   ├── Models.cs                  # every response shape
│   ├── README.md
│   └── Examples/
│       ├── QuickStart.cs          # runnable tour
│       └── QuickStart.csproj
└── NothingDns.Sdk.Tests/
    ├── NothingDns.Sdk.Tests.csproj # xUnit test suite
    ├── MockApi.cs                  # in-process loopback mock of the management API
    ├── NothingDnsClientTests.cs    # request-level contract and model decoding
    └── NothingDnsErrorTests.cs     # error translation and predicates
```

Build both projects:

```bash
cd sdk/csharp
dotnet build
```

Run the example (it reads its credentials from the environment — it never hardcodes
them):

```bash
export NDNS_URL=http://dns.example.com:8080
export NDNS_USER=admin
export NDNS_PASSWORD=...            # or: read -rs NDNS_PASSWORD

dotnet run --project NothingDns.Sdk/Examples
```

The example is idempotent: it creates the demo zone and its `www` A record only when
they are missing, and replaces rather than duplicates the record on a second run.

### A note on the two auth files

Credential **acquisition** — the code that builds a request body containing a password —
lives in `NothingDnsAuth.cs`. Credential **transmission** — the code that constructs the
`Authorization: Bearer` header — lives in `NothingDnsTransport.cs`. The two concerns are
deliberately kept in separate files so that the code handling a plaintext secret is
never co-located with the code that attaches a token to every outgoing request.

## Testing

The suite in `NothingDns.Sdk.Tests/` mirrors the request-level coverage of the Python
(`sdk/python/tests/`) and Go (`sdk/go/client_test.go`) suites: health probes without
auth, bearer-token propagation after login, record CRUD bodies, zone export,
PTR-bulk camelCase wire keys, ACL round-trips, config partial updates that omit null
fields, dashboard camelCase decoding, query-log parameters, path-segment escaping,
local validation before any request is sent, HTTP status translation
(`NothingDnsApiException` plus the `IsUnauthorized`/`IsForbidden`/`IsNotFound`/
`IsRateLimited` predicates) and connection failures.

The tests run against `MockApi.cs`, an in-process loopback mock of the management API
(a raw `TcpListener` HTTP/1.1 server — no Kestrel, no URL ACLs) that records every
request so assertions can inspect methods, paths, JSON bodies and headers. The library
itself stays BCL-only; the test project carries the only NuGet packages
(xunit, xunit.runner.visualstudio, Microsoft.NET.Test.Sdk).

Run the suite from `sdk/csharp/`:

```bash
dotnet build NothingDns.sln   # library, example and tests
dotnet test NothingDns.sln    # all tests, no server required
```
