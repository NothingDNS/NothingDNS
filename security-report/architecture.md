# NothingDNS Architecture Map

## System Boundary

```
┌─────────────────────────────────────────────────────────────────────┐
│                        NothingDNS Server                             │
│                                                                      │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐      │
│  │  UDP:53 │ │ TCP:53  │ │TLS:853  │ │HTTPS:443│ │QUIC:853 │      │
│  │  ★      │ │         │ │         │ │         │ │  ✗     │       │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘      │
│       └───────────┴───────────┴───────────┴───────────┘            │
│                              │                                      │
│                    ┌─────────▼─────────┐                           │
│                    │ integratedHandler  │                           │
│                    │  (21-stage pipeline)│                          │
│                    └─────────┬─────────┘                           │
│       ┌──────────────────────┼──────────────────────┐             │
│       │         │            │            │         │             │
│  ┌────▼───┐ ┌───▼────┐ ┌────▼────┐ ┌────▼────┐ ┌──▼───────┐    │
│  │ Cache  │ │ Zones  │ │Resolver │ │Upstream │ │ DNSSEC  │    │
│  │ (LRU)  │ │(radix) │ │(iterat.)│ │(pool)   │ │(sign/  │    │
│  │        │ │        │ │         │ │         │ │ verify) │    │
│  └────────┘ └────────┘ └─────────┘ └─────────┘ └─────────┘    │
│                                                                      │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐        │
│  │ Blocklist   │  │ RPZ          │  │ Filter (ACL/rate)   │        │
│  │             │  │              │  │                     │        │
│  └─────────────┘  └──────────────┘  └─────────────────────┘        │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────┐     │
│  │              API Server :8080                              │     │
│  │  REST + WebSocket + MCP + Dashboard + DoH + ODoH          │     │
│  │  Auth: JWT + RBAC (admin/operator/viewer)                 │     │
│  └───────────────────────────────────────────────────────────┘     │
│                                                                      │
│  ┌─────────────────────┐  ┌──────────────────────┐                 │
│  │ Cluster (Gossip+    │  │ Storage (KV+WAL)     │                 │
│  │  Raft, AES-256-GCM) │  │ TLV, ACID txns       │                 │
│  └─────────────────────┘  └──────────────────────┘                 │
│                                                                      │
│  ┌─────────────────────┐  ┌──────────────────────┐                 │
│  │ Transfer (AXFR/IXFR │  │ DNS64, GeoDNS,       │                 │
│  │  NOTIFY, DDNS, XoT) │  │ IDNA, DNS Cookies    │                 │
│  └─────────────────────┘  └──────────────────────┘                 │
└─────────────────────────────────────────────────────────────────────┘
```

## Trust Boundaries

| Boundary | Authentication | Encryption | Notes |
|----------|---------------|------------|-------|
| UDP:53 → Internet | None | None | Open resolver |
| TCP:53 → Internet | None | None | Open resolver |
| TLS:853 → Internet | None | TLS 1.2+ | Opportunistic or strict |
| HTTPS:443 → Internet | None | TLS 1.2+ | DoH public endpoint |
| QUIC:853 → Internet | None | QUIC TLS | **Non-functional (TODO)** |
| API:8080 → Internal | JWT + RBAC | Optional TLS | Admin interface |
| WebSocket → Internal | Token in header/URL | Inherited from TLS | Live query stream |
| MCP (SSE) → Internal | **None** | Inherited | Destructive tools exposed |
| Gossip → Cluster | AES-256-GCM key | Encrypted | Cluster-only |
| Raft → Cluster | Network isolation | Optional TLS | Cluster-only |
| AXFR/IXFR → Peers | TSIG (optional) | TLS (XoT) | **Weak without TSIG** |
| NOTIFY → Peers | **None** | TLS (XoT) | **Unauthenticated** |
| DDNS → Clients | TSIG (required) | TLS (XoT) | Authenticated |

## Security Symbols

- ✓ = Well-secured
- ★ = Missing controls
- ✗ = Non-functional
- △ = Partially secured
