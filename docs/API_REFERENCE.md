# NothingDNS REST API Reference

This guide covers the HTTP API served by `nothingdns` on `server.http.bind`
(default `0.0.0.0:8080`): management endpoints, the dashboard data feeds, and
the DNS transports that share the listener. It is written for operators and
integrators and describes the behaviour of the current code, including its
quirks.

- Zone and record endpoints have their own detailed page: [API_ZONES.md](API_ZONES.md).
- The server also publishes a machine-readable OpenAPI 3.0 document at
  `GET /api/openapi.json` (see [OpenAPI and API explorer](#18-openapi-and-api-explorer)).

All examples use `http://127.0.0.1:8080` and a token in `$TOKEN`. If you run
the API over TLS, replace the scheme with `https`.

## Table of contents

1. [Conventions](#1-conventions)
2. [Route overview](#2-route-overview)
3. [Authentication and users](#3-authentication-and-users)
4. [Health](#4-health)
5. [Status and server information](#5-status-and-server-information)
6. [Zones and records (summary)](#6-zones-and-records-summary)
7. [Cache](#7-cache)
8. [Configuration](#8-configuration)
9. [ACL and recursion](#9-acl-and-recursion)
10. [Blocklists](#10-blocklists)
11. [RPZ](#11-rpz)
12. [DNSSEC](#12-dnssec)
13. [Upstreams](#13-upstreams)
14. [GeoIP](#14-geoip)
15. [Cluster](#15-cluster)
16. [Zone transfers](#16-zone-transfers)
17. [Dashboard data, query log, metrics and WebSocket](#17-dashboard-data-query-log-metrics-and-websocket)
18. [OpenAPI and API explorer](#18-openapi-and-api-explorer)
19. [DNS privacy transports (DoH, DoWS, ODoH)](#19-dns-privacy-transports-doh-dows-odoh)
20. [Errors, limits and cross-cutting behaviour](#20-errors-limits-and-cross-cutting-behaviour)

---

## 1. Conventions

- **Content type.** Request bodies are JSON (`Content-Type: application/json`).
  Responses are JSON unless stated otherwise (zone export is plain text, DoH is
  binary DNS).
- **Body size.** Request bodies are limited to 64 KiB. A body that is too large
  or is not valid JSON returns `400 {"error":"Invalid request body"}`.
- **Errors.** Every API error has the shape `{"error": "<message>"}`. Simple
  acknowledgements have the shape `{"message": "<text>"}`.
- **Roles.** There are three roles, ordered `viewer < operator < admin`. A
  route that requires `operator` also accepts `admin`. See
  [Roles](#roles-and-what-they-can-do).
- **Unknown methods.** Unsupported methods return `405`. Most handlers also set
  an `Allow` header listing the accepted methods.
- **Unknown paths.** Any other path under `/api/` returns
  `404 {"error":"Not found"}` (after authentication); only non-API paths serve
  the dashboard.
- **Timestamps.** RFC 3339. Some fields use UTC (`Z`), others the server's
  local offset (for example login `expires`, RPZ `last_reload`).
- **Persistence.** Unless a section says otherwise, runtime changes are held in
  memory only and are not written back to the YAML config file.

---

## 2. Route overview

"Public" means no token is needed. `any` means any authenticated user,
including `viewer`.

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/health` | public | Always 200 while the HTTP server runs |
| GET | `/readyz` | public | 503 when no upstream is healthy |
| GET | `/livez` | public | Always 200 |
| POST | `/api/v1/auth/login` | public | Returns token, sets cookie |
| GET | `/api/v1/auth/session` | any | Restore SPA bearer from cookie after reload |
| POST | `/api/v1/auth/bootstrap` | public, localhost only | First admin / password reset |
| POST | `/api/v1/auth/logout` | any | Revokes current token |
| GET | `/api/v1/auth/roles` | operator | |
| GET | `/api/v1/auth/users` | operator | |
| POST | `/api/v1/auth/users` | admin | Persisted to users file |
| DELETE | `/api/v1/auth/users/{username}` | admin | Also `DELETE /api/v1/auth/users?username=` |
| GET | `/api/v1/status` | any | Extra detail for operator+ |
| GET | `/api/v1/server/config` | operator | |
| GET | `/api/v1/zones` | operator | See [API_ZONES.md](API_ZONES.md) |
| POST | `/api/v1/zones` | operator | |
| POST | `/api/v1/zones/reload?zone=` | admin | |
| GET | `/api/v1/zones/transfers` | operator | Secondary zones |
| GET, DELETE | `/api/v1/zones/{zone}` | operator | |
| GET, POST, PUT, DELETE | `/api/v1/zones/{zone}/records` | operator | |
| GET | `/api/v1/zones/{zone}/export` | operator | BIND text |
| POST | `/api/v1/zones/{zone}/ptr-bulk` | operator | |
| GET | `/api/v1/zones/{zone}/ptr6-lookup?ip=` | operator | |
| GET | `/api/v1/cache/stats` | operator | |
| POST | `/api/v1/cache/flush` | admin | |
| GET | `/api/v1/config` | operator | Secrets redacted |
| POST | `/api/v1/config/reload` | admin | Same as SIGHUP |
| PUT | `/api/v1/config/logging` | admin | Persisted to runtime overrides file |
| PUT | `/api/v1/config/rrl` | admin | Persisted to runtime overrides file |
| PUT | `/api/v1/config/cache` | admin | Persisted to runtime overrides file |
| PUT | `/api/v1/config/resolution` | admin | Persisted to runtime overrides file |
| PUT | `/api/v1/config/dns64` | admin | Persisted to runtime overrides file |
| PUT | `/api/v1/config/cookie` | admin | Persisted to runtime overrides file |
| GET | `/api/v1/acl` | operator | |
| PUT | `/api/v1/acl` | admin | Persisted to access policy file |
| GET | `/api/v1/acl/recursion` | operator | |
| PUT | `/api/v1/acl/recursion` | admin | Persisted to access policy file |
| GET | `/api/v1/blocklists` | operator | |
| POST | `/api/v1/blocklists` | admin | |
| GET | `/api/v1/blocklists/sources` | operator | |
| POST | `/api/v1/blocklists/toggle` | admin | |
| POST | `/api/v1/blocklists/{source}/toggle` | admin | |
| DELETE | `/api/v1/blocklists/{source}` | admin | |
| GET | `/api/v1/rpz` | operator | |
| GET | `/api/v1/rpz/rules` | operator | |
| POST | `/api/v1/rpz/rules` | admin | |
| DELETE | `/api/v1/rpz/rules?pattern=` | admin | |
| POST | `/api/v1/rpz/toggle` | admin | |
| GET | `/api/v1/dnssec/status` | operator | |
| GET | `/api/v1/dnssec/keys` | admin | |
| GET | `/api/v1/upstreams` | operator | |
| PUT | `/api/v1/upstreams` | admin | |
| GET | `/api/v1/geoip/stats` | operator | |
| GET | `/api/v1/cluster/status` | operator | |
| GET | `/api/v1/cluster/nodes` | operator | |
| POST | `/api/v1/cluster/join` | admin | |
| DELETE | `/api/v1/cluster/leave` | admin | |
| GET | `/api/dashboard/stats` | operator | |
| GET | `/api/dashboard/queries` | operator | |
| GET | `/api/dashboard/zones` | operator | |
| GET | `/api/v1/queries` | operator | IPs masked for non-admins |
| GET | `/api/v1/topdomains` | operator | |
| GET | `/api/v1/metrics/history` | operator | |
| GET | `/ws` | any | WebSocket query stream |
| GET | `/api/openapi.json` | any | |
| GET | `/api/docs` | any | API explorer page |
| GET | `/api/docs/app.js` | any | API explorer script |
| POST | `/api/v1/csp-report` | public | Browser CSP reports |
| GET, POST | `server.http.doh_path` (default `/dns-query`) | public | When `doh_enabled` |
| GET (upgrade) | `server.http.dows_path` (default `/dns-ws`) | public | When `dows_enabled` |
| POST | `server.http.odoh_path` (default `/odoh`) | public | When `odoh_enabled` |
| GET | `/.well-known/odoh-config` | public | When `odoh_enabled` |

Any other path that does not start with `/api/` serves the embedded web
dashboard (single-page app).

The auth routes (`/api/v1/auth/*`) are registered only when the auth store is
present, which is always the case in the shipped server.

---

## 3. Authentication and users

### How requests are authenticated

The API accepts two kinds of credentials, checked in this order:

1. **Legacy shared token.** If `server.http.auth_token` is set and the request
   presents exactly that value, the request runs as a synthetic user
   (`__legacy_auth_token__`) with the role from `server.http.auth_token_role`
   (`viewer`, `operator` or `admin`; empty or unknown values mean `viewer`).
2. **Session token.** A token issued by `POST /api/v1/auth/login` or
   `POST /api/v1/auth/bootstrap`.

The credential can be sent two ways:

| Transport | Accepted for | Notes |
|---|---|---|
| `Authorization: Bearer <token>` | every method | Use this for scripts and the CLI |
| `ndns_token` cookie | `GET`, `HEAD`, `OPTIONS` only | Set by login/bootstrap; ignored on `POST`/`PUT`/`DELETE` to prevent CSRF |

A state-changing request that carries only the cookie is rejected with
`401 {"error":"Unauthorized"}`.

Paths that never need a token: `/health`, `/readyz`, `/livez`,
`/api/v1/auth/login`, `/api/v1/auth/bootstrap`, `/api/v1/csp-report`, the
enabled DoH/DoWS/ODoH paths, `/.well-known/odoh-config` (when ODoH is enabled)
and static dashboard assets.

### Tokens and sessions

- Session tokens are opaque random strings (32 random bytes, base64url). They
  are not JWTs and carry no readable claims.
- Lifetime is **24 hours**. The cookie is `HttpOnly`, `SameSite=Strict`,
  `Path=/`, `Max-Age=86400`, and `Secure` when the request came over TLS or
  through a trusted proxy that sent `X-Forwarded-Proto: https`.
- The dashboard keeps the bearer only in memory. After a hard refresh it calls
  `GET /api/v1/auth/session` with the cookie to rebuild the bearer for
  mutations; it does not store the token in `localStorage`.
- **A new login revokes every earlier token of that user.** Logging in from the
  dashboard therefore invalidates a token a script obtained for the same user.
  Use a separate account for automation.
- Changing a user's password (bootstrap reset) or deleting the user revokes that
  user's tokens.
- `server.http.max_sessions_per_user` (default 0, unlimited) caps concurrent
  tokens; the oldest is evicted when the cap is reached.
- Tokens live in memory and are lost on restart, unless
  `server.http.token_persistence_path` is set. That option requires a stable
  `server.http.auth_secret`; without `auth_secret` the server generates a
  random signing secret at every start.

### Roles and what they can do

| Role | Access |
|---|---|
| `viewer` | `GET /api/v1/status` (basic fields only), `POST /api/v1/auth/logout`, `/api/openapi.json`, `/api/docs`, and the `/ws` live query stream (client IPs masked). Every other management endpoint returns 403. In the dashboard a viewer sees only the Dashboard live stream and About. |
| `operator` | All read endpoints; zone and record changes (create, edit, delete, bulk PTR). |
| `admin` | Everything, including users, ACL/recursion, cache flush and cache/RRL/logging settings, config reload, zone reload, blocklist and RPZ changes, upstream changes, DNSSEC keys, cluster join/leave. Only admins see unmasked client IPs in `/api/v1/queries`. |

Missing role: `403 {"error":"Operator role required"}` or
`403 {"error":"Admin role required"}`.

### POST /api/v1/auth/login

Public. Rate limited (see below).

Request:

| Field | Type | Required |
|---|---|---|
| `username` | string | yes |
| `password` | string | yes |

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"S3cure-Passw0rd"}'
```

Response `200`, plus `Set-Cookie: ndns_token=...`:

```json
{
  "token": "tGQ3pduzcDl8Wjnp-0RgIgrC8ST5L3662Uh_1IeZ-EU=",
  "username": "admin",
  "role": "admin",
  "expires": "2026-09-17T20:06:51+03:00"
}
```

Store the token for later calls:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"S3cure-Passw0rd"}' | jq -r .token)
```

| Status | Body | When |
|---|---|---|
| 400 | `Invalid request body` | Malformed JSON |
| 401 | `Invalid credentials` | Unknown user or wrong password |
| 429 | `Too many requests, try again later` | The client IP failed a login less than 30 s ago, or has 5 failed attempts (locked for 5 minutes). `Retry-After` is set. |
| 429 | `Account locked due to too many failed attempts` | 5 failures for this IP and username pair (5 minutes). `Retry-After` is set. |
| 503 | `Auth not configured` | No auth store |

Login throttling in practice: **after one wrong password, every login from
that client IP is refused for 30 seconds**, whatever the username. A
successful login clears the counters for that IP and username.

### GET /api/v1/auth/session

Role: any authenticated user (Bearer **or** the HttpOnly `ndns_token` cookie
on this safe GET). Used by the dashboard after a hard refresh to rebuild the
in-memory bearer without storing it in `localStorage`. Same response shape as
login. The legacy shared `auth_token` is rejected.

```bash
curl -s http://127.0.0.1:8080/api/v1/auth/session -b 'ndns_token=…'
```

| Status | Body | When |
|---|---|---|
| 401 | `Not authenticated` | Missing/invalid cookie or bearer, or legacy shared token |
| 405 | `Method not allowed` | Not GET |

### POST /api/v1/auth/bootstrap

Public, but only accepted when the client IP is `127.0.0.1` or `::1`. The IP
is the TCP peer, or the forwarded client address when the peer is listed in
`server.http.trusted_proxies`. Requests from elsewhere get `403`.

When no users are defined in the config or the users file, the server creates
a placeholder `admin` account with a random password that nobody knows. The
bootstrap endpoint turns that state into a usable account:

| Current state | Effect |
|---|---|
| Only the placeholder `admin` exists | The placeholder is removed and `username` is created with role `admin`. `old_password` is ignored. |
| Real users exist | Password reset for `username` (any role). `old_password` is required and must match. The user's existing tokens are revoked. |

Request:

| Field | Type | Required | Constraints |
|---|---|---|---|
| `username` | string | yes | 2-64 characters |
| `password` | string | yes | 8-128 bytes |
| `old_password` | string | when real users exist | current password of `username` |

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/auth/bootstrap \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"S3cure-Passw0rd"}'
```

Response `200`, plus `Set-Cookie: ndns_token=...`:

```json
{"token":"0-SEu5q6qxVdnhD440PKEcuYjiIcn40ENWcrzwdRZDo=","username":"admin","role":"admin"}
```

| Status | Body | When |
|---|---|---|
| 400 | `Username and password required`, `Username must be 2-64 characters`, `Password must be at least 8 characters`, `Password must be at most 128 bytes`, `Old password required` | Validation |
| 401 | `Invalid old password` | Reset with a wrong `old_password` |
| 403 | `Bootstrap is only allowed from localhost...` | Not a loopback client |
| 400 | validation error from the user store | Invalid username or password |
| 409 | `user already exists` | Username taken |

Created accounts are written to the users file (see [Persistence of users](#persistence-of-users)).

**From the CLI.** `dnsctl server bootstrap` calls this endpoint and never takes
the password from the command line:

```bash
# Password from the environment
NOTHINGDNS_ADMIN_PASSWORD='S3cure-Passw0rd' dnsctl server bootstrap --username admin

# Password from the first line of stdin (for example inside the container)
docker exec -i nothingdns dnsctl server bootstrap < password.txt

# Reset: new password on line 1 (or NOTHINGDNS_ADMIN_PASSWORD),
# current password on line 2 (or NOTHINGDNS_ADMIN_OLD_PASSWORD)
dnsctl server bootstrap --username admin --old-password
```

`--username` defaults to `admin`. The target server comes from `-server` or
`NOTHINGDNS_SERVER` (default `http://localhost:8080`). Run it on the server
host so the request arrives from loopback.

### POST /api/v1/auth/logout

Role: any. Revokes the bearer token and the token in the `ndns_token` cookie
(if present) and clears the cookie.

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/auth/logout -H "Authorization: Bearer $TOKEN"
```

```json
{"message":"Logged out"}
```

A request without a valid token gets `401` (the route is not public). Logging
out with the legacy `auth_token` returns 200 but does not disable that token.

### GET /api/v1/auth/users

Role: operator. Returns a JSON **array** (not an object).

```bash
curl -s http://127.0.0.1:8080/api/v1/auth/users -H "Authorization: Bearer $TOKEN"
```

```json
[
  {"username":"admin","role":"admin","created_at":"2026-09-16T17:06:19Z","updated_at":"2026-09-16T17:06:19Z"},
  {"username":"ops","role":"operator","created_at":"2026-09-16T17:07:00Z","updated_at":"2026-09-16T17:07:00Z"}
]
```

Order is not stable.

### POST /api/v1/auth/users

Role: admin.

| Field | Type | Required | Constraints |
|---|---|---|---|
| `username` | string | yes | non-empty, no control characters |
| `password` | string | yes | 8-128 bytes |
| `role` | string | no | `admin`, `operator` or `viewer` (default `viewer`) |

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/auth/users \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"username":"ops","password":"Operator-Pass1","role":"operator"}'
```

Response `201`:

```json
{"username":"ops","role":"operator","created_at":"2026-09-16T17:07:00Z","updated_at":"2026-09-16T17:07:00Z"}
```

| Status | Body | When |
|---|---|---|
| 400 | `Username and password required` / `Invalid role` | Validation |
| 409 | `user already exists` | Duplicate |
| 400 | `password must be at least 8 characters` (or the 128-byte limit) | Weak or oversized password |

There is no endpoint to change a user's role or password other than the
localhost bootstrap reset. `PUT /api/v1/auth/users` returns 405.

### DELETE /api/v1/auth/users/{username}

Role: admin. The username can also be passed as a query parameter:
`DELETE /api/v1/auth/users?username=ops`.

```bash
curl -s -X DELETE http://127.0.0.1:8080/api/v1/auth/users/ops -H "Authorization: Bearer $TOKEN"
```

```json
{"message":"User deleted"}
```

| Status | Body | When |
|---|---|---|
| 400 | `username required` | No name given |
| 400 | `Cannot delete current user` | Deleting yourself |
| 400 | `Cannot delete the last admin user` | Would leave no admin |
| 404 | `user not found` | Unknown user |

Any method other than `DELETE` on `/api/v1/auth/users/{username}` returns 405.

### GET /api/v1/auth/roles

Role: operator.

```json
{"roles":[
  {"name":"admin","description":"Full access to all resources"},
  {"name":"operator","description":"Can modify zones and view operational data"},
  {"name":"viewer","description":"Read-only access"}
]}
```

### Persistence of users

- Users defined under `server.http.users` in the config file are loaded at
  start and are never written anywhere else. A config user wins over a
  same-named user in the users file.
- Users created or changed at runtime (bootstrap, `POST /api/v1/auth/users`,
  deletions) are saved to `server.http.users_file`, which defaults to
  `<storage.data_dir>/users.json` (mode 0600). The file stores password hashes
  only.
- With neither `users_file` nor `storage.data_dir`, runtime users are lost on
  restart (the server logs a warning at start).

---

## 4. Health

These endpoints need no token and are not API rate limited.

### GET /health

Always `200` while the HTTP server is running.

```bash
curl -s http://127.0.0.1:8080/health
```

```json
{"status":"healthy","timestamp":"2026-09-16T17:06:10Z"}
```

### GET /readyz

Kubernetes readiness probe. Returns `200 {"status":"ready"}`, or
`503 {"status":"unhealthy"}` when an upstream client or load balancer is
configured and none of its servers is healthy. Zone state is not checked.

```json
{"status":"ready","timestamp":"2026-09-16T17:06:19Z"}
```

### GET /livez

Kubernetes liveness probe. Always `200` while the handler runs.

```json
{"status":"alive","timestamp":"2026-09-16T17:06:19Z"}
```

Prometheus metrics are not served on this listener. They use the separate
`metrics.bind`/`metrics.path` endpoint (default `:9153/metrics`, bearer
`metrics.auth_token`).

---

## 5. Status and server information

### GET /api/v1/status

Role: any. Viewers get only `status`, `timestamp`, `version` and
`cluster.enabled`; operators and admins also get cache statistics and cluster
details.

```bash
curl -s http://127.0.0.1:8080/api/v1/status -H "Authorization: Bearer $TOKEN"
```

Operator or admin:

```json
{
  "status": "running",
  "timestamp": "2026-09-16T17:07:00Z",
  "version": "1.2.11",
  "cache": {"size": 0, "capacity": 10000, "hits": 0, "misses": 0, "hit_ratio": 0},
  "cluster": {"enabled": false}
}
```

Viewer:

```json
{"status":"running","timestamp":"2026-09-16T17:07:10Z","version":"1.2.2","cluster":{"enabled":false}}
```

With clustering enabled, `cluster` also carries `node_id`, `node_count`,
`alive_count` and `healthy` (fields with zero values are omitted).

### GET /api/v1/server/config

Role: operator. A short summary of selected settings.

```json
{
  "version": "1.2.11",
  "listen_port": 5399,
  "log_level": "info",
  "dns64": {"enabled": false, "prefix": "64:ff9b::", "prefix_len": 96},
  "cookie": {"enabled": true, "secret_rotation": "1h"}
}
```

`log_level` is the level from the config file, not a level changed through
`PUT /api/v1/config/logging`.

---

## 6. Zones and records (summary)

Full request/response details, examples and error tables are in
[API_ZONES.md](API_ZONES.md). Key points:

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/v1/zones` | operator | List zones (`name`, `serial`, `records`; max 5000) |
| POST | `/api/v1/zones` | operator | Create a zone: `{"name","nameservers":[...],"admin_email","ttl"}` |
| GET | `/api/v1/zones/{zone}` | operator | Zone detail with SOA and nameservers |
| DELETE | `/api/v1/zones/{zone}` | operator | Delete a zone (its file is removed only when it lives in `zone_dir`) |
| GET | `/api/v1/zones/{zone}/records?name=` | operator | List records (exact owner filter; max 5000) |
| POST | `/api/v1/zones/{zone}/records` | operator | Add `{"name","type","ttl","data"}` |
| PUT | `/api/v1/zones/{zone}/records` | operator | Replace `{"name","type","old_data","data","ttl"}` |
| DELETE | `/api/v1/zones/{zone}/records` | operator | Delete all records of `{"name","type"}` |
| GET | `/api/v1/zones/{zone}/export` | operator | BIND zone file (`text/plain`, attachment) |
| POST | `/api/v1/zones/{zone}/ptr-bulk` | operator | Generate PTR (and A) records for an IPv4 CIDR |
| GET | `/api/v1/zones/{zone}/ptr6-lookup?ip=` | operator | Find the PTR of an IPv6 address |
| POST | `/api/v1/zones/reload?zone=` | admin | Re-read one file-backed zone from disk |

- Zone names in paths should be lowercase with a trailing dot
  (`example.com.`). `GET /api/v1/zones/{zone}` and the reload endpoint match the
  name exactly; the record endpoints also accept the name without the dot.
- Zone and record changes are persisted to the embedded store under
  `storage.data_dir` (reloaded at start) and, when `zone_dir` is set, written
  to zone files. In a Raft cluster the write is replicated first; a follower
  answers `421` with the leader to retry against.
- Viewers have no access to zone endpoints.

```bash
curl -s http://127.0.0.1:8080/api/v1/zones -H "Authorization: Bearer $TOKEN"
```

```json
{"zones":[{"name":"example.com.","serial":2024010101,"records":12}],"total":1}
```

---

## 7. Cache

### GET /api/v1/cache/stats

Role: operator.

```bash
curl -s http://127.0.0.1:8080/api/v1/cache/stats -H "Authorization: Bearer $TOKEN"
```

```json
{"size":5432,"capacity":10000,"hits":15234,"misses":1234,"hit_ratio":0.925}
```

`hit_ratio` is between 0 and 1. `503 {"error":"Cache not available"}` when the
cache is disabled.

### POST /api/v1/cache/flush

Role: admin. Removes every cached entry. No request body.

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/cache/flush -H "Authorization: Bearer $TOKEN"
```

```json
{"message":"Cache flushed"}
```

`503` when the cache is disabled. To change cache sizing and TTLs, see
[PUT /api/v1/config/cache](#put-apiv1configcache).

---

## 8. Configuration

### GET /api/v1/config

Role: operator. Returns the configuration as loaded from the file (at start or
at the last reload), with the runtime overrides applied on top, plus a
`Version` key. Keys are Go field names in PascalCase, for example
`Server.HTTP.Bind`, `Cache.Size`, `AllowRecursion`. The settings changed
through `PUT /api/v1/config/*` are reflected here; other runtime changes
(blocklist sources, RPZ rules) are not.

These fields are always blanked: `Server.HTTP.AuthToken`,
`Server.HTTP.AuthSecret`, `Server.HTTP.Users[].Password`,
`Cluster.EncryptionKey`, `Cluster.SnapshotEncryptionKey`,
`Storage.EncryptionKey`, `Metrics.AuthToken`,
`DNSSEC.Signing.Keys[].PrivateKey`, `SlaveZones[].TSIGSecret`.

```bash
curl -s http://127.0.0.1:8080/api/v1/config -H "Authorization: Bearer $TOKEN" | jq '.Cache'
```

```json
{"DefaultTTL":3600,"Enabled":true,"MaxTTL":86400,"MinTTL":300,"NegativeTTL":60,
 "Prefetch":true,"PrefetchThreshold":60,"ServeStale":true,"Size":10000,"StaleGraceSecs":604800}
```

`Logging.Level` is always the level in effect, which
`PUT /api/v1/config/logging` may have changed at runtime.

`503 {"error":"Config not available"}` if the server has no config getter.

### POST /api/v1/config/reload

Role: admin. Re-reads the config file, exactly like `SIGHUP`: zones, views,
blocklists, RPZ, ACL and recursion policy, rate limiter and TLS certificates
are rebuilt. No request body.

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/config/reload -H "Authorization: Bearer $TOKEN"
```

```json
{"message":"Configuration reloaded"}
```

`500` with the reload error (for example an invalid config), `503` if reload is
not wired. Reloading rebuilds the blocklist, RPZ engine and rate limiter from
the file, so blocklist sources and RPZ rules added through the API are
discarded. The ACL and recursion list come back from `access_policy.json`, and
the settings changed through `PUT /api/v1/config/*` come back from
`runtime_overrides.json`, when those files exist.

### Runtime overrides file

The `PUT /api/v1/config/*` endpoints below change the running server *and*
record the new value in `<storage.data_dir>/runtime_overrides.json`. Every
config load — start-up and every reload — re-applies that file on top of the
YAML, so a setting changed from the dashboard is not reverted by the next
`SIGHUP`. Only the keys present in the file win over the config file;
everything else keeps coming from the YAML.

Without `storage.data_dir` there is no file: the change applies to the running
server, the request still succeeds, and the value is lost on restart (the same
contract as the ACL without an access policy file).

The file is validated section by section when it is loaded. A section that
would produce an invalid configuration is logged and skipped, and the config
file value is used for it; the remaining sections still apply. A corrupt file is
logged and ignored entirely.

Settings that need file or socket validation before they can be trusted
(`resolution.root_hints`, bind addresses, TLS files, zone paths, the DNS64
prefix) are deliberately not settable here — they still require a config file
edit so `-validate-config` can reject them up front.

### PUT /api/v1/config/logging

Role: admin. Changes the log level of the running process. Persisted (`warning`
is stored as `warn`).

| Field | Type | Values |
|---|---|---|
| `level` | string | `debug`, `info`, `warn` (or `warning`), `error`, `fatal` (case-insensitive) |

```bash
curl -s -X PUT http://127.0.0.1:8080/api/v1/config/logging \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"level":"debug"}'
```

```json
{"message":"Logging level updated"}
```

`400 {"error":"Invalid log level"}` for anything else. There is no `format`
field.

### PUT /api/v1/config/rrl

Role: admin. Adjusts the per-client query token bucket built from the `rrl`
config section (`rrl.enabled`, `rrl.rate`, `rrl.burst`, `rrl.max_buckets`). The
separate response-side RRL is not changed. Persisted.

| Field | Type | Notes |
|---|---|---|
| `enabled` | boolean | optional |
| `rate` | number | queries per second per client; ignored unless > 0 |
| `burst` | integer | ignored unless > 0 |
| `max_buckets` | integer | >= 1; tracked clients before eviction |

Omitted fields keep their current value.

```bash
curl -s -X PUT http://127.0.0.1:8080/api/v1/config/rrl \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"rate":150,"burst":300}'
```

```json
{"message":"RRL configuration updated"}
```

`400 {"error":"max_buckets must be at least 1"}` for a non-positive bucket cap.
`503 {"error":"Rate limiter not available"}` when `rrl.enabled` was false at
start or at the last reload. A `rate` or `burst` of 0 is ignored by the live
limiter and is not persisted either.

### PUT /api/v1/config/cache

Role: admin. Only `PUT` exists (`GET` returns 405; read the values from
`GET /api/v1/config`). Persisted. Every field is optional; omitted fields keep
their current values.

| Field | Type | Constraint |
|---|---|---|
| `enabled` | boolean | only `true` is accepted; the cache cannot be disabled at runtime |
| `size` | integer | >= 1 |
| `default_ttl`, `max_ttl`, `min_ttl`, `negative_ttl` | integer (seconds) | >= 0 |
| `prefetch` | boolean | |
| `prefetch_threshold` | integer (seconds) | >= 0 |
| `serve_stale` | boolean | |
| `stale_grace_secs` | integer (seconds) | >= 0 |

```bash
curl -s -X PUT http://127.0.0.1:8080/api/v1/config/cache \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"size":20000,"min_ttl":60,"serve_stale":true}'
```

```json
{"message":"Cache configuration updated"}
```

| Status | Body |
|---|---|
| 400 | `size must be at least 1`, `<field> cannot be negative`, `<field> is too large` |
| 400 | `cache cannot be disabled at runtime; set cache.enabled=false in the config file and reload` |
| 503 | `Cache not available` |

### PUT /api/v1/config/resolution

Role: admin. Persisted. Every field is optional; omitted fields keep their
current value.

| Field | Type | Constraint |
|---|---|---|
| `recursive` | boolean | |
| `authoritative_only` | boolean | |
| `max_depth` | integer | >= 0 |
| `timeout` | string | Go duration, e.g. `5s` |
| `edns0_buffer_size` | integer | 0-65535 |
| `qname_minimization` | boolean | |
| `use_0x20` | boolean | |

`authoritative_only` takes effect on the next query. The other fields are read
when the iterative resolver is built, so they take effect on the next reload or
restart — persisting them is what makes that reload keep the new value.
`resolution.root_hints` is not settable here.

```bash
curl -s -X PUT http://127.0.0.1:8080/api/v1/config/resolution \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"qname_minimization":true,"timeout":"3s"}'
```

```json
{"message":"Resolution configuration updated"}
```

`400` for a negative `max_depth`, an `edns0_buffer_size` outside 0-65535, or a
`timeout` that is not a duration.

### PUT /api/v1/config/dns64

Role: admin. Enables or disables DNS64/NAT64 synthesis (RFC 6147) on the
running server. Persisted.

| Field | Type | Notes |
|---|---|---|
| `enabled` | boolean | required |

```bash
curl -s -X PUT http://127.0.0.1:8080/api/v1/config/dns64 \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"enabled":true}'
```

```json
{"message":"DNS64 configuration updated"}
```

| Status | Body |
|---|---|
| 400 | `enabled is required` |
| 400 | `dns64 not configured at startup; set dns64 in the config file and reload` |

The second error means no synthesizer exists, because there is no prefix to
synthesize from — the prefix is read at start-up and cannot be set at runtime.

### PUT /api/v1/config/cookie

Role: admin. Enables or disables DNS Cookies (RFC 7873). Enabling creates a
cookie jar (rotating the server secret every `cookie.secret_rotation`,
default 1h); disabling drops it, so clients stop being challenged. Persisted.

| Field | Type | Notes |
|---|---|---|
| `enabled` | boolean | required |

```bash
curl -s -X PUT http://127.0.0.1:8080/api/v1/config/cookie \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"enabled":true}'
```

```json
{"message":"DNS cookie configuration updated"}
```

| Status | Body |
|---|---|
| 400 | `enabled is required` |
| 503 | `Cookie control not available` |

---

## 9. ACL and recursion

NothingDNS applies two independent lists to DNS clients:

- **ACL** (`acl` in the config) is applied to every query, including queries
  for the server's own zones. With no rules, every client may query. Rules are
  checked in order and the first match wins; **once at least one rule exists,
  a client that matches no rule is refused.** Make sure your own management
  networks are covered before you add rules.
- **Recursion allow list** (`allow_recursion`) decides who may use recursion:
  upstream forwarding, iterative resolution and answers from the shared cache.
  Clients outside the list still get answers from the server's own zones; for
  any other name they get `REFUSED` with Extended DNS Error 18 (Prohibited).
  Entries are CIDRs or single IP addresses. `[]` denies recursion to everyone.

When `allow_recursion` is not set in the config file, recursion is allowed for
loopback and private networks (`127.0.0.0/8`, `::1/128`, `10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, `fe80::/10`), or for every client
the ACL admits when ACL rules exist or `acl_allow_unrestricted_recursion` is
true.

**Persistence.** Changes made with `PUT /api/v1/acl` or
`PUT /api/v1/acl/recursion` are written (both lists together, mode 0600) to
`<storage.data_dir>/access_policy.json`. When that file exists it **replaces**
the `acl` and `allow_recursion` settings of the config file at start and on
reload. Delete the file to go back to the config file. Without
`storage.data_dir`, changes last until the next restart or reload
(`persistent` is `false`). If writing the file fails, the change is rolled back
and the API returns `500`.

### GET /api/v1/acl

Role: operator.

```bash
curl -s http://127.0.0.1:8080/api/v1/acl -H "Authorization: Bearer $TOKEN"
```

```json
{
  "rules": [
    {"name": "local", "networks": ["127.0.0.0/8", "::1/128"], "action": "allow"},
    {"name": "no-any", "networks": ["0.0.0.0/0"], "action": "deny", "types": ["ANY"]}
  ],
  "allow_recursion": {"allow_all": false, "networks": ["192.168.1.0/24", "203.0.113.10/32"]},
  "persistent": true,
  "policy_file": "/var/lib/nothingdns/access_policy.json"
}
```

| Field | Type | Meaning |
|---|---|---|
| `rules[]` | array | Current ACL rules (`types` and `redirect` omitted when empty) |
| `allow_recursion.allow_all` | boolean | `true` when every client admitted by the ACL may recurse; `networks` is then empty |
| `allow_recursion.networks` | string[] | Allowed networks in canonical CIDR form |
| `persistent` | boolean | `true` when changes are saved to `policy_file` |
| `policy_file` | string | Omitted when not persistent |

### PUT /api/v1/acl

Role: admin. Replaces the whole rule list.

| Field | Type | Required | Notes |
|---|---|---|---|
| `rules` | array | yes | `[]` removes all rules (everyone may query) |
| `rules[].name` | string | recommended | Used in error messages |
| `rules[].networks` | string[] | yes | CIDR notation only; a bare IP such as `10.0.0.1` is rejected, use `10.0.0.1/32` |
| `rules[].action` | string | yes | `allow`, `deny` or `redirect` (case-insensitive) |
| `rules[].types` | string[] | no | Query types such as `A`, `AAAA`, `TXT`. Omit to match every type. `ANY` matches only literal ANY (QTYPE 255) queries. |
| `rules[].redirect` | string | with `redirect` | Redirect target |

```bash
curl -s -X PUT http://127.0.0.1:8080/api/v1/acl \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"rules":[
        {"name":"local","networks":["127.0.0.0/8","::1/128"],"action":"allow"},
        {"name":"lan","networks":["192.168.1.0/24"],"action":"allow"},
        {"name":"no-any","networks":["0.0.0.0/0","::/0"],"action":"deny","types":["ANY"]}
      ]}'
```

```json
{"message":"ACL rules updated"}
```

| Status | Example body |
|---|---|
| 400 | `ACL rule "bad": invalid CIDR "10.0.0.1": invalid CIDR address: 10.0.0.1` |
| 400 | `ACL rule "bad": unknown action "block" (expected allow, deny, or redirect)` |
| 400 | `ACL rule "bad": action "redirect" requires a non-empty redirect target` |
| 400 | `ACL rule "x": unknown query type "FOO"` |
| 500 | `Failed to save access policy` (or the write error) |
| 503 | `ACL not available` |

The response does not echo the rules; call `GET /api/v1/acl` to confirm.

### GET /api/v1/acl/recursion

Role: operator.

```bash
curl -s http://127.0.0.1:8080/api/v1/acl/recursion -H "Authorization: Bearer $TOKEN"
```

```json
{"allow_all":false,"networks":["127.0.0.0/8","::1/128","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"]}
```

### PUT /api/v1/acl/recursion

Role: admin. Replaces the recursion allow list and turns `allow_all` off.

| Field | Type | Required | Notes |
|---|---|---|---|
| `networks` | string[] | yes | CIDRs or single IPv4/IPv6 addresses. Bare IPs become `/32` or `/128`, host bits are cleared (`192.168.1.7/24` becomes `192.168.1.0/24`), blanks and duplicates are dropped. `[]` denies recursion to every client. To allow everyone, send `["0.0.0.0/0","::/0"]`. |

```bash
curl -s -X PUT http://127.0.0.1:8080/api/v1/acl/recursion \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"networks":["192.168.1.0/24","203.0.113.10","2001:db8::1"]}'
```

Response `200` with the resulting policy:

```json
{"allow_all":false,"networks":["192.168.1.0/24","203.0.113.10/32","2001:db8::1/128"]}
```

| Status | Body |
|---|---|
| 400 | `networks is required (use [] to deny recursion to every client)` (body `{}` or `"networks": null`) |
| 400 | `allow_recursion: invalid IP or CIDR "nope"` |
| 500 | `Failed to save access policy` (or the write error); the previous list is restored |
| 503 | `Recursion policy not available` |

Effect on DNS, for a client outside the list:

```text
$ dig @dns.example.net www.example.com A      # name in a local zone
;; status: NOERROR   -> answered from the zone
$ dig @dns.example.net example.org A          # anything else
;; status: REFUSED   -> EDE 18 "recursion not allowed for this client"
```

---

## 10. Blocklists

The blocklist must be enabled in the config (`blocklist.enabled: true`). When
it is disabled, `GET /api/v1/blocklists` returns zero stats and the other
blocklist endpoints return `503 {"error":"Blocklist not available"}`.

Changes made here are runtime only: they are not written to the config file
and are discarded by a config reload or restart.

### GET /api/v1/blocklists

Role: operator.

```bash
curl -s http://127.0.0.1:8080/api/v1/blocklists -H "Authorization: Bearer $TOKEN"
```

```json
{"enabled":true,"total_rules":2,"files_count":1,"urls_count":0}
```

### GET /api/v1/blocklists/sources

Role: operator. `id` is the file path or URL and is the identifier used by the
toggle and delete endpoints.

```json
[{"id":"/etc/nothingdns/blocklists/ads.txt","type":"file","enabled":true,"domains":2}]
```

Returns `null` when no source is configured.

### POST /api/v1/blocklists

Role: admin. Adds and immediately loads one source.

| Field | Type | Notes |
|---|---|---|
| `file` | string | A file under `blocklist.base_dir`. Checked first if both fields are set. |
| `url` | string | HTTPS URL; fetched right away |

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/blocklists \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/hosts.txt"}'
```

Response `201`:

```json
{"message":"Blocklist URL added: https://example.com/hosts.txt"}
```

For a file: `{"message":"Blocklist file added"}`.

| Status | Body |
|---|---|
| 400 | `file or url is required` |
| 400 | `adding blocklist files at runtime requires blocklist.base_dir to be configured` |
| 400 | `invalid blocklist URL: only HTTPS URLs are allowed, got scheme "http"` or another load error |
| 503 | `Blocklist not available` |

File paths must be absolute and resolve (after following symlinks) inside
`blocklist.base_dir`; without `base_dir` in the config, file sources cannot be
added at runtime.

### POST /api/v1/blocklists/toggle

Role: admin. Switches blocklist filtering off or back on. No body.

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/blocklists/toggle -H "Authorization: Bearer $TOKEN"
```

```json
{"message":"Blocklist disabled"}
```

### POST /api/v1/blocklists/{source}/toggle

Role: admin. Enables or disables one source. URL-encode the id (`/` becomes
`%2F`).

```bash
curl -s -X POST "http://127.0.0.1:8080/api/v1/blocklists/%2Fetc%2Fnothingdns%2Fblocklists%2Fads.txt/toggle" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{"message":"Source disabled"}
```

`404 {"error":"Source not found"}` for an unknown id.

### DELETE /api/v1/blocklists/{source}

Role: admin. Removes a source by its URL-encoded id.

```bash
curl -s -X DELETE "http://127.0.0.1:8080/api/v1/blocklists/https%3A%2F%2Fexample.com%2Fhosts.txt" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{"message":"Blocklist source removed"}
```

An unknown id returns `400` (`source not found: <id>`, or
`Failed to remove blocklist source` when the id contains `/`). `GET` on any
other `/api/v1/blocklists/...` path returns `404`; `DELETE /api/v1/blocklists`
returns 405.

---

## 11. RPZ

The RPZ engine always exists. With `rpz.enabled: false` it starts disabled
and matches nothing; `POST /api/v1/rpz/toggle` enables it at runtime and rules
can be added before or after that. `rpz.enabled`, `rpz.files` and `rpz.zones`
in the config decide the state and the file-backed rules at startup.

### GET /api/v1/rpz

Role: operator.

```bash
curl -s http://127.0.0.1:8080/api/v1/rpz -H "Authorization: Bearer $TOKEN"
```

```json
{
  "enabled": true,
  "total_rules": 2,
  "qname_rules": 2,
  "client_ip_rules": 0,
  "resp_ip_rules": 0,
  "files_count": 1,
  "total_matches": 0,
  "total_lookups": 0,
  "last_reload": "2026-09-16T20:07:59+03:00"
}
```

### GET /api/v1/rpz/rules

Role: operator. Lists QNAME-trigger rules only, at most 5000 (`truncated: true`
when capped; `total` is the full count).

```json
{
  "rules": [
    {"pattern": "bad.example.com", "action": "NXDOMAIN", "trigger": "QNAME",
     "policy_name": "/etc/nothingdns/rpz/blacklist.zone", "priority": 100},
    {"pattern": "portal.example", "action": "CNAME", "trigger": "QNAME",
     "override_data": "walled.example.com.", "policy_name": "dynamic", "priority": 0}
  ],
  "total": 2
}
```

`action` is one of `NXDOMAIN`, `NODATA`, `CNAME`, `Override`, `Drop`,
`PassThrough`, `TCPOnly`. Rules added through the API have
`policy_name: "dynamic"` and priority 0.

### POST /api/v1/rpz/rules

Role: admin. Adds a QNAME rule in memory. It is lost on config reload and
restart.

| Field | Type | Required | Notes |
|---|---|---|---|
| `pattern` | string | yes | Domain; lowercased and stored without the trailing dot (`bad.example.` and `bad.example` are the same rule). Wildcards such as `*.example.com` follow RPZ file syntax. |
| `action` | string | no | `NXDOMAIN`, `NODATA`, `CNAME`, `OVERRIDE`, `DROP`, `PASSTHROUGH`, `TCPONLY` (case-insensitive). **Missing or unknown values become `NXDOMAIN`.** |
| `override_data` | string | no | Target for `CNAME`/`OVERRIDE` |

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/rpz/rules \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"pattern":"ads.example.net","action":"NODATA"}'
```

Response `201`:

```json
{"message":"Rule added"}
```

`400 {"error":"pattern is required"}`.

### DELETE /api/v1/rpz/rules?pattern=

Role: admin.

```bash
curl -s -X DELETE "http://127.0.0.1:8080/api/v1/rpz/rules?pattern=ads.example.net" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{"message":"Rule removed"}
```

The response is `200` even when no rule had that pattern.
`400 {"error":"pattern query parameter required"}` without the parameter.

### POST /api/v1/rpz/toggle

Role: admin. Switches RPZ filtering off or on. Statistics and rules are kept.

```json
{"message":"RPZ disabled"}
```

Other paths under `/api/v1/rpz/` return `404`.

---

## 12. DNSSEC

### GET /api/v1/dnssec/status

Role: operator. Validation settings.

```bash
curl -s http://127.0.0.1:8080/api/v1/dnssec/status -H "Authorization: Bearer $TOKEN"
```

```json
{"enabled":true,"require_dnssec":false}
```

When validation is off: `{"enabled":false,"require_dnssec":false}`.

### GET /api/v1/dnssec/keys

Role: admin. Public metadata of the signing keys of signed zones. Private key
material is never returned.

```json
{
  "zones": [
    {"keyTag": 12345, "algorithm": 13, "flags": 257, "isKSK": true, "isZSK": false, "zone": "example.com."},
    {"keyTag": 54321, "algorithm": 13, "flags": 256, "isKSK": false, "isZSK": true, "zone": "example.com."}
  ]
}
```

`zones` is `null` when no zone is signed.

---

## 13. Upstreams

### GET /api/v1/upstreams

Role: operator. Aggregate counters in `upstreams` and each configured server
in `servers`.

```bash
curl -s http://127.0.0.1:8080/api/v1/upstreams -H "Authorization: Bearer $TOKEN"
```

```json
{"upstreams":[{"address":"direct-upstream","healthy":true,"queries":30,"failed":0,"failovers":0}],
 "servers":[{"address":"1.1.1.1:53","healthy":true,"latency_ms":21.4},
            {"address":"8.8.8.8:53","healthy":true,"latency_ms":38.9}]}
```

`upstreams` has an entry with `address: "load-balancer"` when a load balancer is
configured and an entry `"direct-upstream"` with the upstream client's totals.
With neither, `upstreams` is `null`. `servers` lists the upstream client's
servers (empty without one); `latency_ms` is the last successful query's round
trip, 0 before the first one.

### PUT /api/v1/upstreams

Role: admin. Adds or removes one server of the upstream client. Runtime only.

| Field | Type | Required | Notes |
|---|---|---|---|
| `action` | string | yes | `add` or `remove` |
| `server` | string | yes | `host:port`. On `add`, private and internal addresses are rejected; a host name must resolve only to public IPs and is replaced by the first resolved IP. |

```bash
curl -s -X PUT http://127.0.0.1:8080/api/v1/upstreams \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"action":"add","server":"9.9.9.9:53"}'
```

```json
{"message":"Server added: 9.9.9.9:53 (resolved from 9.9.9.9:53)"}
```

Remove with the same address that was added (the pinned IP form):

```json
{"message":"Server removed: 9.9.9.9:53"}
```

| Status | Body |
|---|---|
| 400 | `Server address required`, `Invalid action: must be 'add' or 'remove'` |
| 400 | `Invalid upstream address` (private IP) or a resolution error |
| 404 | `server 9.9.9.9:53 not found` |
| 409 | `server 9.9.9.9:53 already exists` |
| 503 | `Upstream client not configured` |

---

## 14. GeoIP

### GET /api/v1/geoip/stats

Role: operator.

```json
{"enabled":false,"rules":0,"mmdb_loaded":false,"lookups":0,"hits":0,"misses":0}
```

---

## 15. Cluster

All cluster routes are always registered. When clustering is disabled the read
endpoints return zero values and the write endpoints return
`503 {"error":"Cluster not available"}`.

### GET /api/v1/cluster/status

Role: operator.

```bash
curl -s http://127.0.0.1:8080/api/v1/cluster/status -H "Authorization: Bearer $TOKEN"
```

```json
{
  "node_id": "node-1",
  "consensus": "raft",
  "node_count": 3,
  "alive_count": 3,
  "healthy": true,
  "gossip": {"messages_sent": 1200, "messages_received": 1180, "ping_sent": 300, "ping_received": 298},
  "raft": {"state": "Leader", "term": 4, "commit_index": 88, "applied_index": 88, "is_leader": true, "leader_id": "node-1"},
  "metrics": {"queries_total": 25000, "queries_per_sec": 15.2, "cache_hits": 20000, "cache_misses": 5000,
              "cache_hit_rate": 0.8, "latency_avg_ms": 3.1, "latency_p99_ms": 12.4}
}
```

`consensus` is `raft` or `swim`; `raft` is present only in Raft mode. With
clustering disabled every field is empty or zero and `consensus` is `""`.

### GET /api/v1/cluster/nodes

Role: operator.

```json
{
  "nodes": [
    {"id": "node-1", "addr": "10.0.0.10", "port": 7946, "state": "alive", "role": "leader", "region": "eu-west", "zone": "a",
     "weight": 100, "http_addr": "10.0.0.10:8080", "version": 12, "health_score": 98,
     "queries_per_second": 120.5, "latency_ms": 2.1, "cpu_percent": 12.0, "memory_percent": 35.5,
     "active_connections": 14},
    {"id": "node-2", "addr": "10.0.0.11", "port": 7946, "state": "alive", "role": "follower", "region": "eu-west", "zone": "a",
     "weight": 100, "http_addr": "10.0.0.11:8080", "version": 12, "health_score": 50,
     "queries_per_second": 0, "latency_ms": 0, "cpu_percent": 0, "memory_percent": 0,
     "active_connections": 0}
  ]
}
```

In Raft mode the list is self plus `cluster.peers` (gossip is not started).
`role` is `leader`, `follower`, or `candidate`. In SWIM mode `role` is omitted.
### POST /api/v1/cluster/join

Role: admin. Joins through a seed node. Gossip (SWIM) mode only; Raft
membership is static.

| Field | Type | Required | Notes |
|---|---|---|---|
| `seed_address` | string | yes | `host:port`, port 1-65535 |

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/cluster/join \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"seed_address":"10.0.0.11:7946"}'
```

```json
{"message":"Joined cluster via 10.0.0.11:7946"}
```

`400` for a missing or malformed address or a failed join.

### DELETE /api/v1/cluster/leave

Role: admin. Drains in-flight work, then leaves the cluster. No body.

```bash
curl -s -X DELETE http://127.0.0.1:8080/api/v1/cluster/leave -H "Authorization: Bearer $TOKEN"
```

```json
{"message":"Node left cluster gracefully"}
```

`500` when draining or leaving fails. Only `DELETE` is accepted.

---

## 16. Zone transfers

### GET /api/v1/zones/transfers

Role: operator. Lists secondary zones configured under `slave_zones` and their
transfer state. Transfers themselves (AXFR/IXFR/NOTIFY) run over DNS, not HTTP.

```bash
curl -s http://127.0.0.1:8080/api/v1/zones/transfers -H "Authorization: Bearer $TOKEN"
```

```json
{
  "slave_zones": [
    {"zone": "example.com.", "masters": "192.0.2.53:53", "serial": 2024050101,
     "last_transfer": "2026-05-24T12:00:00Z", "status": "synced", "records": 42}
  ]
}
```

`status` is `synced` once a transfer has produced zone data, otherwise
`pending`. `masters` is a comma-separated string. `last_transfer` is omitted
before the first transfer. `slave_zones` is `[]` when none are configured.

---

## 17. Dashboard data, query log, metrics and WebSocket

The query log, top domains and the live stream come from an in-memory buffer
of recent query events kept by the dashboard component.

### GET /api/dashboard/stats

Role: operator.

```json
{"uptime":129,"queriesTotal":3,"queriesPerSec":0,"cacheHitRate":33.33,"blockedQueries":0,
 "activeClients":1,"zoneCount":1,"upstreamLatency":0}
```

`uptime` is seconds, `cacheHitRate` a percentage (0-100), `activeClients` the
number of distinct DNS clients seen recently, `upstreamLatency` milliseconds.

### GET /api/dashboard/queries

Role: operator. The last 100 query events, oldest first. For non-admins the
last octet (IPv4) or group (IPv6) of `clientIp` is masked, as in
`/api/v1/queries`.

```json
[
  {"timestamp":"2026-09-16T20:07:19.26535+03:00","clientIp":"192.168.1.20","countryCode":"",
   "domain":"www.example.com.","queryType":"A","responseCode":"NOERROR","duration":0,
   "cached":false,"blocked":false,"protocol":"udp"}
]
```

### GET /api/dashboard/zones

Role: operator. A light zone summary. `records` here is the number of distinct
owner names, not the number of records (use `GET /api/v1/zones` for that).

```json
[{"name":"example.com.","records":6,"serial":2024010101}]
```

### GET /api/v1/queries

Role: operator. Paginated query log, newest first (the server keeps the last
100 events).

| Query parameter | Default | Notes |
|---|---|---|
| `offset` | 0 | Negative or invalid values are ignored |
| `limit` | 100 | 1-500; values outside the range are ignored |
| `q` | | Case-insensitive substring match on the domain, applied before paging (max 253 characters) |

```bash
curl -s "http://127.0.0.1:8080/api/v1/queries?limit=2&q=example" -H "Authorization: Bearer $TOKEN"
```

```json
{
  "queries": [
    {"timestamp":"2026-09-16T17:07:19Z","client_ip":"192.168.1.xxx","domain":"www.example.com.",
     "query_type":"A","response_code":"NOERROR","duration_ms":0,"cached":false,"blocked":false,"protocol":"udp"}
  ],
  "total": 7,
  "offset": 0,
  "limit": 2
}
```

For callers that are not admins, the last IPv4 octet is replaced with `xxx`
(the last IPv6 group with `xxxx`). `total` is the number of matching events.

### GET /api/v1/topdomains

Role: operator.

| Query parameter | Default | Notes |
|---|---|---|
| `limit` | 10 | 1-100 |

```json
{"domains":[{"domain":"example.org.","count":3},{"domain":"www.example.com.","count":2}],"limit":3}
```

### GET /api/v1/metrics/history

Role: operator. Samples from the metrics ring buffer as parallel arrays, newest
first. `timestamps` are Unix seconds.

```json
{"timestamps":[1789578000,1789577940],"queries":[120,98],"cache_hits":[80,70],
 "cache_misses":[40,28],"latency_ms":[12,15],"count":2}
```

`503 {"error":"Metrics not available"}` when there is no metrics collector.
Right after start the arrays are empty and `count` is 0.

### WebSocket /ws

Role: any authenticated user (including `viewer`). Streams every DNS query
event as it happens. Non-admins receive `clientIp` with the last octet or group
masked (`192.0.2.xxx`). Authenticate with `Authorization: Bearer` or the
`ndns_token` cookie (browsers send the cookie automatically); query-string
tokens are not accepted. The `Origin` header, when present, must be the same
origin as the request or be listed in `server.http.allowed_origins`.

Each text message is:

```json
{"type":"query","event":{"timestamp":"2026-09-16T20:08:34.847842+03:00","clientIp":"127.0.0.1",
 "countryCode":"","domain":"www.example.com.","queryType":"A","responseCode":"NOERROR",
 "duration":0,"cached":false,"blocked":false,"protocol":"udp"}}
```

The server closes connections that stay silent for 2 minutes, so clients
should send a message (for example a ping) periodically. A plain `GET` without
upgrade headers returns `400`.

```bash
# Example with websocat
websocat -H "Authorization: Bearer $TOKEN" ws://127.0.0.1:8080/ws
```

---

## 18. OpenAPI and API explorer

| Path | Role | Content |
|---|---|---|
| `GET /api/openapi.json` | any | OpenAPI 3.0.3 document. Each operation has an `x-required-role` extension. |
| `GET /api/docs` | any | API explorer page that renders `/api/openapi.json` (script: `/api/docs/app.js`) |

Both require a token (the dashboard cookie is enough in a browser, as these are
`GET` requests).

```bash
curl -s http://127.0.0.1:8080/api/openapi.json -H "Authorization: Bearer $TOKEN" | jq '.paths | keys'
```

`/api/docs` is a self-contained API explorer served from the server itself
(`/api/docs/app.js`, no CDN), so it works under the server's
`Content-Security-Policy` (`script-src 'self'`). Open it in a browser after
signing in to the dashboard: operations are grouped by tag, filterable, and
show the required role, parameters and request/response schemas. For "try it
out" requests, load `/api/openapi.json` into another OpenAPI tool.

---

## 19. DNS privacy transports (DoH, DoWS, ODoH)

These endpoints answer DNS queries over HTTP. They share the API listener but
need no token and are not subject to the API rate limit. Queries go through the
normal DNS pipeline with the HTTP client's IP, so the ACL, recursion allow list
and DNS rate limiting apply.

### DNS over HTTPS (RFC 8484)

Enable with `server.http.doh_enabled: true`; the path is
`server.http.doh_path` (default `/dns-query`). The config validator requires
`tls_cert_file` and `tls_key_file` when DoH is enabled.

| Request | Response |
|---|---|
| `GET /dns-query?dns=<base64url DNS message>` | `application/dns-message` |
| `POST /dns-query` with `Content-Type: application/dns-message` | `application/dns-message` |
| `GET /dns-query?name=www.example.com&type=A`, or any request with `Accept: application/dns-json` | `application/dns-json` (JSON API) |
| `POST` with `Content-Type: application/dns-json` | `application/dns-json` |

```bash
# Wire format
curl -s -H 'Content-Type: application/dns-message' --data-binary @query.bin \
  https://dns.example.net/dns-query -o answer.bin

# JSON
curl -s "https://dns.example.net/dns-query?name=www.example.com&type=A"
```

```json
{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,
 "Question":[{"name":"www.example.com.","type":1}],
 "Answer":[{"name":"www.example.com.","type":1,"TTL":3600,"data":"192.0.2.10"}]}
```

Errors are plain text: `400` (invalid request or DNS message, no question),
`405` for other methods (`Allow: GET, POST`), `413` for an oversized body.

### DNS over WebSocket

Enable with `server.http.dows_enabled: true`; path `server.http.dows_path`
(default `/dns-ws`). After the WebSocket upgrade, send each DNS query as a
binary frame containing a wire-format DNS message; answers come back as binary
frames. Text frames are ignored. Each connection may send at most 100 queries
per second. The `Origin` check is the same as for `/ws`.

### Oblivious DoH (RFC 9230)

Enable with `server.http.odoh_enabled: true`; path `server.http.odoh_path`
(default `/odoh`); enabling the top-level `odoh` section also turns it on.
When `odoh.enabled` is true and `odoh.target_url` is set, the server acts as a
proxy that forwards to that target; otherwise it acts as a target that decrypts
and resolves queries itself.

| Request | Notes |
|---|---|
| `POST /odoh` with an encrypted ODoH message | Response `application/oblivious-dns-message`. Other methods: 405. |
| `GET /.well-known/odoh-config` | Target public key as JSON: `{"public_key":"base64url:...","kem":..,"kdf":..,"aead":..}` with `Content-Type: application/odoh-config+json`. `503 {"error":"ODoH target not available"}` when the server runs as proxy or has no key. |

The config document is JSON, not the binary `ObliviousDoHConfigs` structure
from RFC 9230.

---

## 20. Errors, limits and cross-cutting behaviour

### Error format and common status codes

```json
{"error":"Operator role required"}
```

| Status | Typical meaning |
|---|---|
| 400 | Validation error, malformed JSON, body over 64 KiB |
| 401 | `Unauthorized`: no token, unknown or expired token, or a cookie on a state-changing request |
| 403 | Role too low, bootstrap from a non-loopback address, or CORS preflight from a disallowed origin (`origin not allowed`) |
| 404 | Unknown resource, or an unknown sub-path under a prefix route |
| 405 | Method not supported (usually with an `Allow` header) |
| 409 | Conflict (zone or user exists, duplicate upstream) |
| 421 | Zone write sent to a Raft follower; the message names the leader when known |
| 429 | Rate limited; see `Retry-After` |
| 500 | Server-side failure (reload failed, file write failed) |
| 503 | The subsystem is disabled or not wired (cache, blocklist, RPZ, cluster, metrics, recursion policy) |

Error messages that contain a `/` or the word `panic` are replaced by a generic
message (for example `Not found`) so file paths do not leak. As a result a few
validation errors surface with a generic text and an unexpected status.

A request to a non-API path without a valid token serves the dashboard's HTML
page (the web app handles login) instead of `401`.

### Rate limits

| Limit | Scope | Behaviour |
|---|---|---|
| API | every path starting with `/api/`, including login, bootstrap, CSP reports and OpenAPI | server.http.api_rate_limit requests per server.http.api_rate_window_secs (defaults: 600 per 60s) sliding window per client IP, counted before authentication. `429 {"error":"rate limit exceeded"}` with `Retry-After` (seconds). |
| Login, per IP | `POST /api/v1/auth/login` | 30-second wait after each failure; 5 failures lock the IP for 5 minutes |
| Login, per IP and username | `POST /api/v1/auth/login` | 5 failures lock the pair for 5 minutes |
| DoWS | per connection | 100 queries per second |

`/health`, `/readyz`, `/livez`, `/ws` and the DoH/DoWS/ODoH paths are not
counted by the API limiter.

### Client IP and reverse proxies

The client IP used for rate limiting, login lockout and the bootstrap
loopback check is the TCP peer address. `X-Forwarded-For` (rightmost address
that is not itself a trusted proxy) and `X-Real-IP` are honoured only when the
peer is listed in `server.http.trusted_proxies` (CIDRs or IPs). The same rule
applies to `X-Forwarded-Proto: https`, which sets the cookie's `Secure` flag.

Behind a reverse proxy without `trusted_proxies`, every request appears to
come from the proxy. All clients then share one API rate-limit budget, and the
bootstrap endpoint accepts requests relayed by a proxy on the same host.

### CORS

- `server.http.allowed_origins` empty: no `Access-Control-Allow-Origin` header
  is sent, so browsers allow same-origin use only.
- A list of origins: a matching `Origin` is echoed back with `Vary: Origin`.
- `"*"`: any origin is echoed (the literal `*` is used when no `Origin` header
  was sent).
- Allowed methods: `GET, POST, PUT, DELETE, OPTIONS`; allowed headers:
  `Content-Type, Authorization, X-Requested-With`.
- A preflight `OPTIONS` from an origin that is not allowed gets
  `403 {"error":"origin not allowed"}`; other `OPTIONS` requests get `200`.

### Security headers

Every response carries `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`,
`Referrer-Policy: strict-origin-when-cross-origin`,
`Cross-Origin-Opener-Policy: same-origin`,
`Cache-Control: no-store, no-cache, must-revalidate, private`, a restrictive
`Permissions-Policy`, and a `Content-Security-Policy` whose `report-uri` is
`/api/v1/csp-report`. `Strict-Transport-Security` is added on TLS connections.

### POST /api/v1/csp-report

Public. Browsers post CSP violation reports here
(`{"csp-report": {"document-uri": ..., "violated-directive": ..., "blocked-uri": ...}}`).
The server logs recognisable reports and always answers `204 No Content`,
including for malformed bodies. Only `POST` is accepted.

### TLS

Set `server.http.tls_cert_file` and `server.http.tls_key_file` to serve the
API over HTTPS. Without TLS the server logs a warning, because tokens and the
session cookie then travel in clear text.
