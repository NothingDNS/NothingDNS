# NothingDNS Go SDK

A typed, **dependency-free** Go client for the [NothingDNS](https://github.com/nothingdns/nothingdns) management API. Standard library only — no third-party modules — covering all **71** operations of the management API.

The SDK mirrors the server's API groups as namespaced services on a `Client`, returns typed models for every response, and takes a `context.Context` on every call.

---

## Features

- **Complete** — all 71 management operations, including health probes, cluster management, dashboard and metrics endpoints.
- **Typed** — dedicated structs for every response shape, with `json` tags that match the wire format exactly (snake_case, plus camelCase for `/api/dashboard` and the `ptr6`/`ptr-bulk` shapes).
- **Context-aware** — every method takes a `context.Context`, so calls support cancellation and deadlines.
- **Zero dependencies** — stdlib only (`net/http`, `encoding/json`, `context`, `time`, `net/url`, `errors`, `strings`).
- **Forgiving decoding** — missing and unknown JSON fields are tolerated, so a newer server never breaks an older client.
- **Precise errors** — typed `ErrAPIError` / `ErrConnectionError` / `ErrValidationError`, with `errors.Is`-friendly sentinels and helpers (`IsNotFound`, `IsUnauthorized`, `IsForbidden`, `IsRateLimited`, `IsBadRequest`, `IsConflict`).
- **Concurrent** — a `Client` is safe to share across goroutines as long as the token is not swapped mid-flight.
- **Documented** — Go doc comments on every exported type, method and field.

---

## Install

```bash
go get github.com/nothingdns/nothingdns/sdk/go
```

Import it as:

```go
import nothingdns "github.com/nothingdns/nothingdns/sdk/go"
```

Requires **Go 1.26+**. To work on the SDK inside the server repository itself, add a `replace` directive:

```go
// go.mod
require github.com/nothingdns/nothingdns/sdk/go v0.0.0
replace github.com/nothingdns/nothingdns/sdk/go => ./sdk/go
```

---

## Quick start

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	nothingdns "github.com/nothingdns/nothingdns/sdk/go"
)

func main() {
	ctx := context.Background()

	client := nothingdns.NewClient("http://dns.example.com:8080", "", 10*time.Second, nil, nil)
	defer client.Close()

	// Log in; the token is stored on the client automatically.
	session, err := client.Auth.Login(ctx, os.Getenv("NDNS_USER"), os.Getenv("NDNS_PASSWORD"), true)
	if err != nil {
		log.Fatalf("login failed: %v", err)
	}
	fmt.Printf("logged in as %s (%s)\n", session.Username, session.Role)

	// List the zones.
	zones, err := client.Zones.List(ctx)
	if err != nil {
		log.Fatalf("list zones failed: %v", err)
	}
	for _, z := range zones.Zones {
		fmt.Println(z.Name, z.Records)
	}
}
```

A complete, runnable walkthrough lives in [`examples/quickstart/main.go`](examples/quickstart/main.go). It logs in, lists zones, adds a record, reads cache statistics and prints a zone export — reading its configuration from `NDNS_URL`, `NDNS_USER` and `NDNS_PASSWORD`:

```bash
export NDNS_URL="http://localhost:8080"
export NDNS_USER="admin"
export NDNS_PASSWORD="…"
go run ./examples/quickstart
```

---

## Authentication

There are two ways to authenticate.

### 1. Log in with a username and password

`Auth.Login` exchanges credentials for a bearer token and, by default (`storeToken = true`), stores it on the client so every later call is authenticated.

```go
session, err := client.Auth.Login(ctx, username, password, true)
fmt.Println(session.Token, session.Username, session.Role, session.Expires)
```

To **create the first admin** on a fresh server, or reset a password, use `Auth.Bootstrap`. When resetting an existing account, pass the current password as `oldPassword`:

```go
// First admin on a brand-new server
session, err := client.Auth.Bootstrap(ctx, "admin", newPassword, nil, true)

// Reset an existing account's password
old := "current-password"
session, err := client.Auth.Bootstrap(ctx, "admin", newPassword, &old, true)
```

If you want to keep the client anonymous and manage the token yourself, pass `storeToken = false` and call `client.SetToken(session.Token)` later.

### 2. Use the static `server.http.auth_token`

The server also supports a static shared token configured under `server.http.auth_token` in its config file. Pass it directly when constructing the client (or set it later with `SetToken`):

```go
client := nothingdns.NewClient("http://dns.example.com:8080", os.Getenv("NOTHINGDNS_TOKEN"), 0, nil, nil)
```

> The static `auth_token` is rejected by `Auth.Session` — that endpoint requires a real login session. Every other endpoint accepts it.

### Session helpers

```go
sess, err := client.Auth.Session(ctx)         // GET  /api/v1/auth/session  (current session)
msg, err := client.Auth.Logout(ctx)           // POST /api/v1/auth/logout   (invalidate session)
```

---

## Configuration options

`NewClient` takes a base URL, an optional starting token, a timeout, an optional `*http.Client` and optional extra headers:

```go
client := nothingdns.NewClient(
    "https://dns.example.com:8080",  // base URL of the server.http listener
    "",                              // starting bearer token ("" = anonymous)
    20*time.Second,                  // per-request timeout (0 = DefaultTimeout of 30s)
    nil,                             // custom *http.Client (nil = default)
    map[string]string{"X-Trace-Id": "abc123"}, // extra headers on every request
)
defer client.Close()
```

To control TLS verification, proxies or connection pooling, supply your own `*http.Client`:

```go
httpClient := &http.Client{
    Timeout: 15 * time.Second,
    Transport: &http.Transport{
        Proxy: http.ProxyFromEnvironment,
        TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
    },
}
client := nothingdns.NewClient("https://dns.example.com:8080", "", 0, httpClient, nil)
```

### Roles

The server enforces a role hierarchy:

| Role | Powers |
|------|--------|
| `viewer` | Read-only access to permitted resources. |
| `operator` | Everything `viewer` can do, plus most reads (zones, cache, config, metrics, cluster, dashboard, DNS status, …). |
| `admin` | Everything `operator` can do, plus all mutations (users, runtime config changes, cache flush, blocklist/RPZ changes, cluster join/leave, …). |

A "role" column appears in the [coverage table](#method--http-endpoint-coverage) below, so you can see the required role for every operation at a glance.

---

## Namespaces

Every namespace hangs off the `Client` and shares one transport (and therefore one connection pool and one token).

### Auth — `/api/v1/auth`

```go
// Roles (operator+)
roles, err := client.Auth.Roles(ctx)
for _, r := range roles {
    fmt.Println(r.Name, "-", r.Description)
}

// Users
users, err := client.Auth.ListUsers(ctx)               // operator+
// users[i].ConfigDefined is true for accounts from the server config file;
// deleting or resetting those is refused with 409 (nothingdns.IsConflict).
user, err := client.Auth.CreateUser(ctx, "alice", pw, "viewer")  // admin
err := client.Auth.DeleteUser(ctx, "alice")            // admin (path form)
err := client.Auth.DeleteUserByQuery(ctx, "alice")     // admin (query form)
```

### Zones — `/api/v1/zones`

```go
zones, err := client.Zones.List(ctx)
zone, err := client.Zones.Get(ctx, "example.com")
detail, err := client.Zones.Get(ctx, "example.com")
fmt.Println(detail.SOA.Serial, detail.NameServers)

// Create a zone
ns := []string{"ns1.example.com", "ns2.example.com"}
admin := "hostmaster@example.com"
ttl := 3600
_, err = client.Zones.Create(ctx, "example.com", ns, &nothingdns.CreateZoneOptions{
    AdminEmail: &admin,
    TTL:        &ttl,
})

// Records
records, err := client.Zones.ListRecords(ctx, "example.com", "")            // all
records, err = client.Zones.ListRecords(ctx, "example.com", "www")           // filtered
_, err = client.Zones.AddRecord(ctx, "example.com", "www", "A", "192.0.2.1", &nothingdns.AddRecordOptions{TTL: &ttl})
_, err = client.Zones.ReplaceRecord(ctx, "example.com", "www", "A", "192.0.2.1", "192.0.2.2", nil)
_, err = client.Zones.DeleteRecord(ctx, "example.com", "www", "A", "192.0.2.2") // one record; 404 if absent
_, err = client.Zones.DeleteRecords(ctx, "example.com", "www", "A")              // the whole RRset

// Export (BIND zone-file text)
export, err := client.Zones.Export(ctx, "example.com")
fmt.Println(export)

// Reload from disk (admin), secondaries, bulk PTR, IPv6 PTR lookup
_, err = client.Zones.Reload(ctx, "example.com")
slaves, err := client.Zones.Transfers(ctx)
preview := true
resp, err := client.Zones.PTRBulk(ctx, "2.0.192.in-addr.arpa", "192.0.2.0/24", "host-{ip}.example.com", &nothingdns.PTRBulkOptions{Preview: &preview})
fmt.Println(resp.WillAdd, len(resp.Changes))
lookup, err := client.Zones.PTR6Lookup(ctx, "8.b.d.0.1.0.0.2.ip6.arpa", "2001:db8::1")
```

### Cache — `/api/v1/cache`

```go
stats, err := client.Cache.Stats(ctx)   // operator+
fmt.Println(stats.Size, stats.Capacity, stats.Hits, stats.Misses, stats.HitRatio)

msg, err := client.Cache.Flush(ctx)     // admin
```

### Config — `/api/v1/config`

```go
cfg, err := client.Config.Get(ctx)          // operator+; secrets redacted
_, err = client.Config.Reload(ctx)          // admin

_, err = client.Config.SetLogging(ctx, "debug")   // admin

// Partial updates: nil fields keep their current value.
enabled := true
rate := 50.0
_, err = client.Config.SetRRL(ctx, &nothingdns.RRLOptions{Enabled: &enabled, Rate: &rate})      // admin
_, err = client.Config.SetCache(ctx, &nothingdns.CacheConfigOptions{Size: &ttl})                  // admin
timeout := "2s"
_, err = client.Config.SetResolution(ctx, &nothingdns.ResolutionOptions{Timeout: &timeout})       // admin
_, err = client.Config.SetDNS64(ctx, true)   // admin (RFC 6147)
_, err = client.Config.SetCookie(ctx, true)  // admin (RFC 7873)
```

### ACL — `/api/v1/acl`

```go
cfg, err := client.ACL.Get(ctx)   // operator+
for _, r := range cfg.Rules {
    fmt.Println(r.Name, r.Action, r.Networks)
}

rule := nothingdns.ACLRule{Name: "block-badnet", Networks: []string{"198.51.100.0/24"}, Action: "deny"}
_, err = client.ACL.Set(ctx, []nothingdns.ACLRule{rule})   // admin; replaces the whole list

rec, err := client.ACL.Recursion(ctx)                       // operator+
rec, err = client.ACL.SetRecursion(ctx, []string{"10.0.0.0/8"}) // admin
```

### Blocklists — `/api/v1/blocklists`

```go
stats, err := client.Blocklists.Stats(ctx)   // operator+

url := "https://example.com/hosts.txt"
_, err = client.Blocklists.Add(ctx, &nothingdns.AddBlocklistOptions{URL: &url})  // admin; exactly one of File/URL
sources, err := client.Blocklists.Sources(ctx)                                       // operator+
_, err = client.Blocklists.Toggle(ctx)                                                // admin (global)
_, err = client.Blocklists.ToggleSource(ctx, "source-id")                             // admin
_, err = client.Blocklists.Remove(ctx, "source-id")                                   // admin
```

### RPZ — `/api/v1/rpz`

```go
stats, err := client.RPZ.Stats(ctx)   // operator+
rules, err := client.RPZ.Rules(ctx)   // operator+

_, err = client.RPZ.AddRule(ctx, "ads.example.com", "NXDOMAIN", nil)         // admin
data := "blocked.example.com"
_, err = client.RPZ.AddRule(ctx, "*.tracker.com", "CNAME", &data)             // admin
_, err = client.RPZ.DeleteRule(ctx, "ads.example.com")                        // admin
_, err = client.RPZ.Toggle(ctx)                                               // admin
```

### DNSSEC — `/api/v1/dnssec`

```go
status, err := client.DNSSEC.Status(ctx)   // operator+
fmt.Println(status.Enabled, status.RequireDNSSEC)

keys, err := client.DNSSEC.Keys(ctx)       // admin; public metadata only
for _, k := range keys.Zones {
    fmt.Println(k.Zone, k.KeyTag, k.Algorithm, k.IsKSK, k.IsZSK)
}
```

### Upstreams — `/api/v1/upstreams`

```go
pool, err := client.Upstreams.List(ctx)   // operator+
for _, s := range pool.Servers {
    fmt.Println(s.Address, s.Healthy, s.LatencyMS)
}

_, err = client.Upstreams.Add(ctx, "9.9.9.9:53")     // admin
_, err = client.Upstreams.Remove(ctx, "9.9.9.9:53")  // admin
```

### GeoIP — `/api/v1/geoip`

```go
stats, err := client.GeoIP.Stats(ctx)   // operator+
fmt.Println(stats.Enabled, stats.MMDBLoaded, stats.Hits, stats.Misses)
```

### Cluster — `/api/v1/cluster`

```go
status, err := client.Cluster.Status(ctx)   // operator+
if status.Raft != nil {
    fmt.Println(status.Raft.State, status.Raft.IsLeader, status.Raft.LeaderID)
}
nodes, err := client.Cluster.Nodes(ctx)     // operator+
_, err = client.Cluster.Join(ctx, "10.0.0.1:7946")  // admin — run once on a fresh node
_, err = client.Cluster.Leave(ctx)                 // admin — drain and leave
```

### Dashboard — `/api/dashboard`

```go
stats, err := client.Dashboard.Stats(ctx)     // operator+
fmt.Println(stats.QueriesTotal, stats.CacheHitRate, stats.BlockedQueries)
events, err := client.Dashboard.Queries(ctx)  // operator+; last 100 events
zones, err := client.Dashboard.Zones(ctx)     // operator+
```

### Metrics — query log, top domains, history

```go
page, err := client.Metrics.QueryLog(ctx, &nothingdns.QueryLogOptions{Limit: 50, Q: "example.com"}) // operator+
top, err := client.Metrics.TopDomains(ctx, 10)                                                    // operator+
hist, err := client.Metrics.History(ctx)                                                          // operator+
// hist.Queries[i] was recorded at hist.Timestamps[i]
```

### Health, status, and API docs (on the `Client`)

```go
health, err := client.Health(ctx)   // GET /health     (no auth)
ready, err := client.Ready(ctx)     // GET /readyz     (no auth)
live, err := client.Live(ctx)       // GET /livez      (no auth)
status, err := client.Status(ctx)   // GET /api/v1/status (any role)
cfg, err := client.ServerConfig(ctx)  // GET /api/v1/server/config (operator+)
spec, err := client.OpenAPISpec(ctx)  // GET /api/openapi.json
page, err := client.APIDocs(ctx)      // GET /api/docs (HTML)
script, err := client.APIDocsScript(ctx) // GET /api/docs/app.js (JS)
err = client.ReportCSPViolation(ctx, report) // POST /api/v1/csp-report
```

---

## Error handling

Every non-2xx response is returned as an `*ErrAPIError`:

```go
type ErrAPIError struct {
    StatusCode int           // HTTP status code
    Message    string        // server's "error" text (or raw body)
    Payload    map[string]any // decoded JSON body, when available
}
```

- `*ErrConnectionError` — the server could not be reached (DNS failure, refused connection, TLS error, timeout). Unwraps to the underlying transport error.
- `*ErrValidationError` — a response body could not be decoded, or an argument failed local validation before any request was made (e.g. an empty ACL rule list, an unknown role, an unknown log level).

Use the sentinel helpers (or `errors.Is` with the package sentinels) to branch on the semantic failure:

```go
import "errors"

zone, err := client.Zones.Get(ctx, "example.com")
switch {
case nothingdns.IsNotFound(err):
    fmt.Println("no such zone")
case nothingdns.IsForbidden(err):
    fmt.Println("your role is insufficient")
case nothingdns.IsRateLimited(err):
    fmt.Println("slow down")
case nothingdns.IsBadRequest(err), nothingdns.IsConflict(err):
    fmt.Println("refused:", err) // the server message says why
case nothingdns.IsUnauthorized(err):
    fmt.Println("token expired — log in again")
case err != nil:
    log.Fatal(err)
default:
    fmt.Println(zone.Name)
}

// Or with errors.Is directly:
if errors.Is(err, nothingdns.ErrNotFound) { /* … */ }
```

Inspect a full API error for its status and payload:

```go
var apiErr *nothingdns.ErrAPIError
if errors.As(err, &apiErr) {
    fmt.Println(apiErr.StatusCode, apiErr.Message, apiErr.Payload)
}
```

### Status codes

| Status | Meaning | Common operations |
|--------|---------|-------------------|
| `200` | Success (JSON or plain text) | most reads and mutations; `Zones.Export` returns the zone file |
| `201` | Created | `Zones.Create`, `Zones.AddRecord`, `Auth.CreateUser`, `RPZ.AddRule`, `Blocklists.Add` |
| `204` | No content | `Client.ReportCSPViolation` |
| `400` | Bad request / invalid data (`IsBadRequest`) | `Login`, `Zones.Create`, `Zones.AddRecord`/`ReplaceRecord` (RDATA that does not parse for the type, SOA), `Zones.DeleteRecord(s)` (SOA, apex NS), `Config.Set*` (a value the config loader would reject), `Blocklists.Add`, `RPZ.AddRule` (CNAME/OVERRIDE without valid override data), `Upstreams.Add`/`Remove` (no port, last server), `ACL.Set` |
| `401` | Unauthorized (missing/expired/rejected token) | any authenticated call |
| `403` | Forbidden (role too low) | any admin-only or operator-only call |
| `404` | Not found | `Zones.Get`/`Delete`, `Zones.ListRecords`, `Zones.DeleteRecord` (no record with that data), `RPZ`/`Blocklists` targets |
| `405` | Method not allowed | `Auth.Session` on some deployments |
| `409` | Conflict (`IsConflict`) | `Auth.CreateUser`, `Zones.Create`, `Upstreams.Add`, `Zones.AddRecord`/`ReplaceRecord` (duplicate record, CNAME conflict), `Auth.DeleteUser`/`DeleteUserByQuery`/`Bootstrap` (account defined in the config file) |
| `421` | Misdirected (this node is not the Raft leader) | `Zones.Create`, `Zones.AddRecord`/`ReplaceRecord`/`DeleteRecord(s)` |
| `429` | Rate limited | any endpoint that has its own rate limit; `Auth.Login` also when another login from the same IP is in flight |
| `500` | Internal server error (nothing was changed when a save failed) | `Config.Reload`, `Cluster.Leave`, `Config.Set*` (overrides file not writable), `Auth.CreateUser`/`DeleteUser`/`Bootstrap` (users file not writable) |
| `503` | Service unavailable / not ready | `Client.Ready`, `Zones.Transfers`, `Cache.Flush`, `Metrics.*` |

---

## Concurrency and context

A `Client` and its `Transport` are safe for concurrent use by multiple goroutines as long as the token is not changed while requests are in flight. Give each goroutine its own `Client` only if you also want a separate connection pool.

Every method takes a `context.Context` as its first argument:

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
stats, err := client.Cache.Stats(ctx)
```

---

## Method → HTTP endpoint coverage

All 71 operations of the management API, in contract order. The **Role** column shows the minimum role the server requires (`—` = no authentication).

| # | Go method | HTTP | Role |
|---|-----------|------|------|
| 1 | `Client.Health` | `GET /health` | — |
| 2 | `Client.Ready` | `GET /readyz` | — |
| 3 | `Client.Live` | `GET /livez` | — |
| 4 | `Auth.Login` | `POST /api/v1/auth/login` | — |
| 5 | `Auth.Bootstrap` | `POST /api/v1/auth/bootstrap` | — |
| 6 | `Auth.Session` | `GET /api/v1/auth/session` | any |
| 7 | `Auth.Logout` | `POST /api/v1/auth/logout` | any |
| 8 | `Auth.Roles` | `GET /api/v1/auth/roles` | operator |
| 9 | `Auth.ListUsers` | `GET /api/v1/auth/users` | operator |
| 10 | `Auth.CreateUser` | `POST /api/v1/auth/users` | admin |
| 11 | `Auth.DeleteUserByQuery` | `DELETE /api/v1/auth/users?username=` | admin |
| 12 | `Auth.DeleteUser` | `DELETE /api/v1/auth/users/{username}` | admin |
| 13 | `Client.Status` | `GET /api/v1/status` | any |
| 14 | `Client.ServerConfig` | `GET /api/v1/server/config` | operator |
| 15 | `Zones.List` | `GET /api/v1/zones` | operator |
| 16 | `Zones.Create` | `POST /api/v1/zones` | operator |
| 17 | `Zones.Reload` | `POST /api/v1/zones/reload?zone=` | admin |
| 18 | `Zones.Transfers` | `GET /api/v1/zones/transfers` | operator |
| 19 | `Zones.Get` | `GET /api/v1/zones/{zone}` | operator |
| 20 | `Zones.Delete` | `DELETE /api/v1/zones/{zone}` | operator |
| 21 | `Zones.ListRecords` | `GET /api/v1/zones/{zone}/records` | operator |
| 22 | `Zones.AddRecord` | `POST /api/v1/zones/{zone}/records` | operator |
| 23 | `Zones.ReplaceRecord` | `PUT /api/v1/zones/{zone}/records` | operator |
| 24 | `Zones.DeleteRecords`, `Zones.DeleteRecord` (with `data`) | `DELETE /api/v1/zones/{zone}/records` | operator |
| 25 | `Zones.Export` | `GET /api/v1/zones/{zone}/export` | operator |
| 26 | `Zones.PTRBulk` | `POST /api/v1/zones/{zone}/ptr-bulk` | operator |
| 27 | `Zones.PTR6Lookup` | `GET /api/v1/zones/{zone}/ptr6-lookup?ip=` | operator |
| 28 | `Cache.Stats` | `GET /api/v1/cache/stats` | operator |
| 29 | `Cache.Flush` | `POST /api/v1/cache/flush` | admin |
| 30 | `Config.Get` | `GET /api/v1/config` | operator |
| 31 | `Config.Reload` | `POST /api/v1/config/reload` | admin |
| 32 | `Config.SetLogging` | `PUT /api/v1/config/logging` | admin |
| 33 | `Config.SetRRL` | `PUT /api/v1/config/rrl` | admin |
| 34 | `Config.SetCache` | `PUT /api/v1/config/cache` | admin |
| 35 | `Config.SetResolution` | `PUT /api/v1/config/resolution` | admin |
| 36 | `Config.SetDNS64` | `PUT /api/v1/config/dns64` | admin |
| 37 | `Config.SetCookie` | `PUT /api/v1/config/cookie` | admin |
| 38 | `ACL.Get` | `GET /api/v1/acl` | operator |
| 39 | `ACL.Set` | `PUT /api/v1/acl` | admin |
| 40 | `ACL.Recursion` | `GET /api/v1/acl/recursion` | operator |
| 41 | `ACL.SetRecursion` | `PUT /api/v1/acl/recursion` | admin |
| 42 | `Blocklists.Stats` | `GET /api/v1/blocklists` | operator |
| 43 | `Blocklists.Add` | `POST /api/v1/blocklists` | admin |
| 44 | `Blocklists.Sources` | `GET /api/v1/blocklists/sources` | operator |
| 45 | `Blocklists.Toggle` | `POST /api/v1/blocklists/toggle` | admin |
| 46 | `Blocklists.Remove` | `DELETE /api/v1/blocklists/{source}` | admin |
| 47 | `Blocklists.ToggleSource` | `POST /api/v1/blocklists/{source}/toggle` | admin |
| 48 | `RPZ.Stats` | `GET /api/v1/rpz` | operator |
| 49 | `RPZ.Rules` | `GET /api/v1/rpz/rules` | operator |
| 50 | `RPZ.AddRule` | `POST /api/v1/rpz/rules` | admin |
| 51 | `RPZ.DeleteRule` | `DELETE /api/v1/rpz/rules?pattern=` | admin |
| 52 | `RPZ.Toggle` | `POST /api/v1/rpz/toggle` | admin |
| 53 | `DNSSEC.Status` | `GET /api/v1/dnssec/status` | operator |
| 54 | `DNSSEC.Keys` | `GET /api/v1/dnssec/keys` | admin |
| 55 | `Upstreams.List` | `GET /api/v1/upstreams` | operator |
| 56 | `Upstreams.Add` / `Upstreams.Remove` | `PUT /api/v1/upstreams` (`action=add`/`remove`) | admin |
| 57 | `GeoIP.Stats` | `GET /api/v1/geoip/stats` | operator |
| 58 | `Cluster.Status` | `GET /api/v1/cluster/status` | operator |
| 59 | `Cluster.Nodes` | `GET /api/v1/cluster/nodes` | operator |
| 60 | `Cluster.Join` | `POST /api/v1/cluster/join` | admin |
| 61 | `Cluster.Leave` | `DELETE /api/v1/cluster/leave` | admin |
| 62 | `Dashboard.Stats` | `GET /api/dashboard/stats` | operator |
| 63 | `Dashboard.Queries` | `GET /api/dashboard/queries` | operator |
| 64 | `Dashboard.Zones` | `GET /api/dashboard/zones` | operator |
| 65 | `Metrics.QueryLog` | `GET /api/v1/queries` | operator |
| 66 | `Metrics.TopDomains` | `GET /api/v1/topdomains` | operator |
| 67 | `Metrics.History` | `GET /api/v1/metrics/history` | operator |
| 68 | `Client.ReportCSPViolation` | `POST /api/v1/csp-report` | — |
| 69 | `Client.OpenAPISpec` | `GET /api/openapi.json` | any |
| 70 | `Client.APIDocsScript` | `GET /api/docs/app.js` | any |
| 71 | `Client.APIDocs` | `GET /api/docs` | any |

---

## License

Distributed under the same license as the NothingDNS project.

---

## Testing

The suite is stdlib-only (`net/http/httptest` + `encoding/json`, no testify) and runs entirely in-process against a mock of the management API:

```bash
cd sdk/go
go test ./...
```

`mockserver_test.go` starts a fresh mock server per test and records every request (method, raw path including query string, JSON body, `Authorization` header), so `client_test.go` and `errors_test.go` can assert on paths, query strings, JSON bodies, bearer-token propagation, camelCase/snake_case wire mapping and typed error translation — mirroring the Python (`sdk/python/tests/`) and TypeScript (`sdk/typescript/test/`) suites. Local validation failures (unknown role, unknown log level, unknown RPZ action, …) are checked to reject *before* any request is made, and path-segment escaping (`%2F`, `%20`), config partial updates (nil fields omitted) and connection errors are covered as well.

