# NothingDNS Architecture Map — Security Recon

## 1. Technology Stack Detection

### Languages
- **Go** (~95%) — All DNS server code, API, cluster, zone transfers
- **TypeScript/React 19** (~5%) — Web dashboard SPA at `web/src/`

### Frameworks (Go — stdlib only)
- `net/http` — HTTP API, DoH, DoWS handlers
- `net` — UDP/TCP DNS transports
- `crypto/tls` — TLS/DoT, QUIC
- Custom DNS protocol parser in `internal/protocol/` (no miekg/dns)

### Application Type
- **DNS Server** (authoritative + recursive) with 7 transports
- **REST API** — 40+ endpoints for management
- **React 19 SPA** — Web dashboard with WebSocket live updates
- **CLI tool** — `dnsctl` for client-side operations

---

## 2. Entry Points

### DNS Transports
| Protocol | Port | Handler |
|----------|------|---------|
| UDP | 53 (or config) | `server.Handler` |
| TCP | 53 (or config) | `server.Handler` |
| TLS (DoT) | 853 | `server.Handler` |
| QUIC (DoQ) | 784 | `doqHandlerAdapter` |
| DoH | HTTP port + `/dns-query` | `doh.Handler` |
| DoWS | HTTP port + `/ws` | `doh.WSHandler` |
| ODoH | HTTP port + `/odoh` | `odoh.ObliviousProxy` |

### HTTP API Routes
**Public:** `/health`, `/readyz`, `/livez`, `/api/v1/auth/login`

**Authenticated (JWT or shared token):**
- Zones: `GET/POST /api/v1/zones`, `DELETE /api/v1/zones/{name}`, record operations
- Cache: `GET /api/v1/cache/stats`, `POST /api/v1/cache/flush`
- ACL: `GET/PUT /api/v1/acl`
- RPZ: `GET/POST/DELETE /api/v1/rpz/rules`
- Upstreams: `GET/PUT /api/v1/upstreams`
- Config: `GET /api/v1/config`, `POST /api/v1/config/reload`
- DNSSEC: `GET /api/v1/dnssec/status`
- Metrics: `GET /api/v1/metrics/history`
- Users: `GET/POST/DELETE /api/v1/auth/users`
- WebSocket: `WS /ws`

### CLI Commands (`dnsctl`)
`dig`, `zone`, `record`, `cluster`, `cache`, `import`, `dnssec`

---

## 3. Trust Boundaries

```
Internet DNS queries
        |
        v
[ACL filter] --> Allow/Drop/Redirect
        |
        v
[Blocklist/RPZ check] --> Block/Allow
        |
        v
[Cache lookup] --> Hit/Miss
        |
        v
[Authoritative zone] OR [Recursive resolver]
        |
        v
[DNSSEC validation/signing]
        |
        v
[Audit logging]
```

### Authentication
- **JWT tokens** — HMAC-SHA256, 24h expiry, role claims (admin/operator/viewer)
- **Shared secret** — constant-time comparison via `subtle.ConstantTimeCompare`
- **Login rate limiting** — 5 attempts, 5min lockout, progressive delays up to 30s
- **API rate limiting** — 100 req/min per IP for authenticated requests

### Authorization (RBAC)
| Role | Permissions |
|------|-------------|
| admin | Full access + user management |
| operator | Zone/record/cache/config mutations |
| viewer | Read-only |

---

## 4. Data Flow

### DNS Query Path
```
Client → Transport (UDP/TCP/TLS/QUIC/DoH/DoWS/ODoH)
  → server.Handler.ServeDNS()
  → integratedHandler.handleDNS()
    → ACL check
    → Blocklist/RPZ check
    → Split-horizon view selection
    → Cache lookup
      → Hit: return cached
      → Miss: Authoritative zone lookup OR recursive resolution
    → DNSSEC signing/validation
    → Audit logging
    → Response
```

### API Request Path
```
HTTP Request
  → CORS middleware (origin validation)
  → Auth middleware (skip for public endpoints)
    → Login rate limiting
    → JWT/shared token validation
    → API rate limiting
  → RBAC check (for mutating operations)
  → Handler
```

---

## 5. Security Controls Implemented

| Control | Location | Status |
|---------|----------|--------|
| Authentication | `internal/auth/auth.go` | ✅ JWT + shared token |
| Authorization | `internal/auth/auth.go` | ✅ RBAC |
| Rate Limiting | `internal/api/server.go` | ✅ Login + API |
| ACL | `internal/filter/acl.go` | ✅ CIDR-based |
| Blocklist | `internal/blocklist/blocklist.go` | ✅ Domain/prefix |
| RPZ | `internal/rpz/rpz.go` | ✅ QNAME/clientIP/respIP |
| DNSSEC | `internal/dnssec/` | ✅ Signing + validation |
| DNS Cookies | `internal/dnscookie/` | ✅ RFC 7873 |
| Query Logging | `internal/audit/` | ✅ Configurable |
| Goroutine Leak | `internal/api/server.go` | ✅ Liveness probe |
| Input Validation | All handlers | ✅ Body limits (64KB) |
| CORS | `internal/api/server.go` | ✅ Origin allowlist |

---

## 6. External Integrations

- **Upstream DNS** — `internal/upstream/` — HTTP client, load balancer
- **Cluster** — `internal/cluster/raft/` — Raft consensus, gossip protocol
- **Zone Transfers** — `internal/transfer/` — AXFR, IXFR, DDNS, NOTIFY
- **TSIG** — HMAC-SHA256/384/512 for zone transfer authentication

---

## 7. Key Security Constants

| Constant | Value | Location |
|----------|-------|----------|
| MaxLabelLength | 63 | `internal/protocol/labels.go` |
| MaxNameLength | 255 | `internal/protocol/labels.go` |
| MaxPointerDepth | 5 | `internal/protocol/labels.go` (compression loop prevention) |
| TCPMaxMessageSize | 65535 | `internal/server/tcp.go` |
| MaxGenerateRecords | 65536 | `internal/zone/zone.go` |
| MaxIncludeDepth | 10 | `internal/zone/zone.go` |
| LoginRateLimit | 5 attempts, 5min | `internal/api/server.go` |
| APIRateLimit | 100 req/min | `internal/api/server.go` |
| WSFrameMaxSize | 1MB | `internal/websocket/websocket.go` |
| DoHMaxBodySize | 65535 | `internal/doh/handler.go` |

---

## 8. Language Detection

- **Go** (95%) → activates `sc-lang-go`
- **TypeScript** (5%) → activates `sc-lang-typescript`

---

*Generated by security-check sc-recon skill — Phase 1*
