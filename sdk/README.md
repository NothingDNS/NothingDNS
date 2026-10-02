# NothingDNS SDKs

Official client libraries for the [NothingDNS](https://github.com/nothingdns/nothingdns)
DNS server management API.

Each SDK wraps the same HTTP management API and exposes the same operations with
idiomatic naming for its language, so switching languages does not mean relearning
the server.

| Language | Directory | Package | Runtime dependencies |
| --- | --- | --- | --- |
| [Python](python/) | `sdk/python` | `nothingdns` (PyPI) | `requests` |
| [TypeScript](typescript/) | `sdk/typescript` | `@nothingdns/sdk` (npm) | none (platform `fetch`) |
| [Go](go/) | `sdk/go` | `github.com/nothingdns/nothingdns/sdk/go` | none (stdlib) |
| [C#](csharp/) | `sdk/csharp` | `NothingDns.Sdk` (NuGet) | none (BCL) |
| [Java](java/) | `sdk/java` | `io.nothingdns:nothingdns-sdk` (Maven) | Gson |

**API version covered:** NothingDNS 1.2.17 — all 71 operations in the server's
OpenAPI document (`GET /api/openapi.json` on any running node).

---

## What these SDKs cover

Every REST operation the server exposes:

| Group | Operations |
| --- | --- |
| Health | `/health`, `/readyz`, `/livez` |
| Status | `/api/v1/status`, `/api/v1/server/config`, `/api/openapi.json` |
| Auth & users | login, bootstrap, session, logout, roles, list/create/delete users |
| Zones | list, create, get, delete, reload, transfers, records (add/replace/delete/list), export, bulk PTR, IPv6 PTR lookup |
| Cache | statistics, flush |
| Config | effective config, reload, runtime logging/RRL/cache/resolution/DNS64/cookie |
| ACL | rules, recursion allow list |
| Blocklists | stats, sources, add/remove/toggle |
| RPZ | stats, QNAME rules, toggle |
| DNSSEC | validation status, signing keys |
| Upstreams | health, add/remove |
| GeoDNS | statistics |
| Cluster | status, nodes, join, leave |
| Dashboard & metrics | counters, query events, zone summary, query log, top domains, metrics history |

The browser-facing endpoints (`/api/docs`, `/api/docs/app.js`,
`POST /api/v1/csp-report`) serve the web dashboard. Go, C# and Java wrap them
anyway (plus the `DELETE /api/v1/auth/users?username=` query form) so their
coverage tables match the OpenAPI document one-to-one; Python and TypeScript
omit them as non-management operations.

**These are management SDKs, not DNS resolvers.** They speak HTTP to the
server's API. To actually resolve a name, use a DNS library in your language
(`dnspython`, `dns-packet`, `miekg/dns`, …) against a NothingDNS listener.

---

## Shared design

All five SDKs deliberately share one architecture, so the mental model transfers
between languages:

- **A client object** holding the base URL, the bearer token and the timeout.
- **Resource namespaces** mirroring the server's API groups: `auth`, `zones`,
  `cache`, `config`, `acl`, `blocklists`, `rpz`, `dnssec`, `upstreams`, `geoip`,
  `cluster`, `dashboard`, `metrics`.
- **Matching method names** across languages — Python `zones.add_record(...)`,
  TypeScript `zones.addRecord(...)`, Go `zones.AddRecord(...)`, C#
  `Zones.AddRecord(...)`, Java `zones.addRecord(...)`.
- **A typed error for every non-2xx response**, carrying the status code, the
  server's message and the decoded body, plus a predicate per interesting status
  (`isNotFound`, `isUnauthorized`, `isForbidden`, `isRateLimited`).
- **Reads return typed models; writes return the server's acknowledgement
  message.**
- **Partial updates omit `None`/`undefined` fields**, so setting one runtime
  config key never clobbers the others.

### Naming across languages

The wire format is `snake_case`, and each SDK maps it to its own conventions:

| | Python | TypeScript | Go | C# | Java |
| --- | --- | --- | --- | --- | --- |
| Wire `hit_ratio` | `hit_ratio` | `hitRatio` | `HitRatio` (json tag) | `HitRatio` (`JsonPropertyName`) | `hitRatio` (`@SerializedName`) |
| A DNS record | `Record` | `DNSRecord` | `Record` | `Record` | `Record` |
| Method style | `snake_case` | `camelCase` | `PascalCase` | `PascalCase` | `camelCase` |

TypeScript exports `DNSRecord` rather than `Record` because a type named
`Record` would shadow TypeScript's built-in `Record<K, V>` utility for consumers.

---

## Authentication

Two ways to authenticate, identical in every SDK:

1. **Log in with a user account.** The returned bearer token is stored on the
   client, so later calls are authenticated automatically.
2. **Use the static service token** configured as `server.http.auth_token`.

```python
client.auth.login(os.environ["NDNS_USER"], os.environ["NDNS_PASSWORD"])
client.set_token(os.environ["NOTHINGDNS_TOKEN"])      # or the static token
```

```ts
await client.auth.login(process.env.NDNS_USER!, process.env.NDNS_PASSWORD!);
client.setToken(process.env.NDNS_TOKEN!);
```

```go
session, err := client.Auth.Login(ctx, os.Getenv("NDNS_USER"), os.Getenv("NDNS_PASSWORD"))
err = client.SetToken(os.Getenv("NOTHINGDNS_TOKEN"))
```

Roles are `viewer < operator < admin`, enforced **per operation** on the server —
see each SDK's README for the table. A `403` means the token's role is too low,
not that the request was malformed.

---

## Choosing an SDK

- **Python** — provisioning, automation, ops scripts, anything already in a venv.
- **TypeScript** — Node.js services, serverless functions, CLIs, and anything in
  a browser bundle. Zero dependencies, works on Node 18+, Deno, Bun and Workers.
- **Go** — Go programs, controllers, CLI tools. Stdlib only, so no dependency
  conflicts with the server's own strict dependency policy.
- **C#** — .NET 8 services, Windows-integrated admin tooling.
- **Java** — Spring Boot apps and JVM-based infrastructure.

---

## Adding a new operation

The server is the source of truth, and a drift test
(`internal/api/openapi_route_drift_test.go`) fails the build when a registered
route is missing from the spec. To add an endpoint:

1. Implement the handler in `internal/api/` and register it in
   `internal/api/server.go`.
2. Document it in the `OpenAPISpec` constant in `internal/api/openapi.go` —
   including `x-required-role`, params, body and responses.
3. Add the matching method to all five SDKs, keeping the shared naming.

```bash
go test ./internal/api/ -run TestOpenAPISpecDocumentsEveryRegisteredRoute
```

---

## Documentation

Each SDK's README is the authoritative reference for that language
(install, quick start, authentication, per-namespace examples, error handling,
role requirements and a method → endpoint coverage table):

- [Python](python/README.md) · [TypeScript](typescript/README.md) ·
  [Go](go/README.md) · [C#](csharp/NothingDns.Sdk/README.md) ·
  [Java](java/README.md)

The server-side references remain the source of truth for the API itself:

- [API reference](../docs/API_REFERENCE.md)
- [OpenAPI spec](https://github.com/nothingdns/nothingdns/blob/main/internal/api/openapi.go)
  (served live at `GET /api/openapi.json`)

## License

MIT
