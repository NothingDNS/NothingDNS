# NothingDNS — Branding Guide

---

## 1. Identity

### 1.1 Name
**NothingDNS**

### 1.2 Taglines
- **Primary:** "Nothing but DNS. Nothing else needed."
- **Technical:** "Zero dependencies. Full resolution."
- **Marketing:** "The DNS server that needs nothing — and does everything."
- **Developer:** "One binary. Zero deps. All protocols."
- **Cluster:** "From single node to sovereign DNS infrastructure."

### 1.3 Elevator Pitch
NothingDNS is a production-grade DNS server written in pure Go with zero external dependencies. A single binary delivers authoritative + recursive DNS, supports all modern protocols (UDP, TCP, DoT, DoH, DoQ), includes DNSSEC, ad-blocking, GeoDNS, split-horizon views, and Raft-based clustering — with a built-in web dashboard, REST API, CLI tool, and MCP server for AI-native management.

### 1.4 One-Liner Descriptions
- **GitHub:** Pure Go DNS server — authoritative, recursive, DoT/DoH/DoQ, DNSSEC, clustering. Zero dependencies.
- **Twitter/X:** DNS server that needs literally nothing. One Go binary. All protocols. Zero deps. 🚀
- **Hacker News:** Show HN: NothingDNS — Full-featured DNS server in pure Go, zero dependencies
- **Reddit:** Built a complete DNS server from scratch in Go with zero external dependencies — authoritative + recursive + DoT/DoH/DoQ + DNSSEC + Raft clustering

---

## 2. Visual Identity

### 2.1 Color Palette

| Name | Hex | Usage |
|------|-----|-------|
| Void Black | `#0A0A0B` | Primary background, text |
| Nothing White | `#F5F5F7` | Light background, reverse text |
| Signal Green | `#00E676` | Primary accent, success, healthy |
| Query Blue | `#448AFF` | Links, active states, info |
| Warn Amber | `#FFD740` | Warnings, rate limiting |
| Error Red | `#FF5252` | Errors, blocked, unhealthy |
| Muted Gray | `#9E9E9E` | Secondary text, disabled |
| Deep Navy | `#1A1A2E` | Dark mode cards, panels |
| Terminal Green | `#39FF14` | CLI/terminal aesthetic, code |

### 2.2 Typography
- **Headings:** JetBrains Mono (or system monospace)
- **Body:** Inter (or system sans-serif)
- **Code:** JetBrains Mono / Fira Code / SF Mono

### 2.3 Logo Concept
The NothingDNS logo plays on the concept of "nothing" — minimalism taken to its logical conclusion.

**Concept A — The Empty Set:**
A stylized ∅ (empty set symbol) where the diagonal slash is replaced by a DNS query path (root → TLD → domain). The circle represents "nothing" and the path represents DNS resolution.

**Concept B — The Zero:**
A bold "0" (zero) with subtle DNS packet binary pattern (0s and 1s) embedded in the outline. Represents zero dependencies.

**Concept C — Negative Space:**
The letters "DNS" where the letterforms are created entirely from negative space within a solid rectangle. The absence IS the design — "nothing" creates the identity.

### 2.4 ASCII Art Logo (for CLI/README)
```
    _   _       _   _     _             ____  _   _ ____
   | \ | | ___ | |_| |__ (_)_ __   __ _|  _ \| \ | / ___|
   |  \| |/ _ \| __| '_ \| | '_ \ / _` | | | |  \| \___ \
   | |\  | (_) | |_| | | | | | | | (_| | |_| | |\  |___) |
   |_| \_|\___/ \__|_| |_|_|_| |_|\__, |____/|_| \_|____/
                                    |___/
   Nothing but DNS. Nothing else needed.
```

---

## 3. Messaging Framework

### 3.1 Key Messages

**For DevOps/SRE:**
"Replace your fragmented DNS stack with a single binary. NothingDNS handles authoritative serving, recursive resolution, encrypted transports, ad-blocking, and clustering — with zero dependencies to manage."

**For Homelabbers:**
"Your Pi-hole, your authoritative DNS, and your recursive resolver — all in one 30MB binary. No Docker compose gymnastics. No dependency hell. Just run it."

**For Enterprise:**
"Production-grade DNS with Raft clustering for high availability, DNSSEC for security, split-horizon for network segmentation, and a REST API for automation. All from a single Go binary with no supply chain risk."

**For Open Source Community:**
"Every line is Go standard library. Read the code. Understand the code. No dependency maze. No hidden complexity. Pure, auditable DNS."

**For AI/LLM Users:**
"The first DNS server with a built-in MCP server. Manage your DNS infrastructure through natural language with Claude Code."

### 3.2 Feature Highlights (for README/Landing Page)

**🏗️ Complete DNS Server**
- Authoritative + Recursive in one binary
- BIND zone file compatible
- All standard record types (A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA, and more)

**🔒 Modern & Secure**
- DNS over TLS (DoT)
- DNS over HTTPS (DoH)
- DNS over QUIC (DoQ)
- Full DNSSEC signing & validation
- Response Rate Limiting (RRL)

**🚫 Built-in Ad Blocking**
- Domain blocklists (Pi-hole compatible)
- Wildcard blocking
- Allowlist overrides
- Multiple response modes

**🌍 Smart Routing**
- GeoDNS (location-based responses)
- Split-horizon DNS (views)
- EDNS Client Subnet awareness

**🔗 Raft Clustering**
- Automatic leader election
- Zone replication across nodes
- Zero-downtime failover
- Snapshot & recovery

**🎛️ Full Management Suite**
- REST API with Swagger UI
- Web Dashboard (real-time)
- CLI tool (dnsctl)
- MCP Server (AI-native)
- Prometheus metrics

**📦 Zero Dependencies**
- Pure Go standard library
- Single binary (~30MB)
- `FROM scratch` Docker image
- No supply chain risk
- Cross-platform (Linux, macOS, Windows, FreeBSD)

### 3.3 Comparison Narrative

"**BIND** is the grandfather of DNS — battle-tested but complex, C-based, and dependency-heavy. **CoreDNS** brought Go and plugins but still depends on external libraries and lacks built-in clustering. **PowerDNS** offers features but requires multiple components and databases. **Unbound** excels at recursive resolution but can't do authoritative serving.

**NothingDNS** combines all of these capabilities in a single, dependency-free Go binary. It's the DNS server for people who are tired of stitching together multiple tools."

---

## 4. Content Strategy

### 4.1 Launch Content

**Blog Post (Technical Deep Dive):**
"Building a DNS Server from Scratch in Go — With Zero Dependencies"
- Wire protocol implementation details
- QUIC from scratch challenges
- Raft consensus for DNS
- Performance benchmarks vs BIND/CoreDNS

**Twitter/X Thread:**
"I built a complete DNS server in pure Go. Zero external dependencies. Here's what I learned about DNS wire protocol, QUIC, Raft consensus, and why you should care about your DNS infrastructure. 🧵"

**Hacker News:**
"Show HN: NothingDNS — Full DNS server (auth + recursive + DoT/DoH/DoQ + DNSSEC + clustering) in pure Go, zero deps"

**Reddit Posts:**
- r/golang: Technical deep dive on zero-dependency approach
- r/selfhosted: Replacement for Pi-hole + authoritative DNS
- r/homelab: Single binary DNS infrastructure
- r/netsec: DNSSEC + security features
- r/devops: Clustering + automation + MCP

### 4.2 Infographic Prompt (for Nano Banana 2)

```
STYLE: Modern dark tech infographic, isometric 3D elements, #0A0A0B background, neon green (#00E676) and blue (#448AFF) accents, clean grid layout

TITLE: "NothingDNS" in bold monospace, subtitle "Nothing but DNS. Nothing else needed."

SECTIONS:
1. CENTER: Isometric server cube with DNS symbols flowing through it
2. TOP LEFT: Protocol icons (UDP, TCP, DoT shield, DoH cloud, DoQ lightning)
3. TOP RIGHT: Zero dependencies badge with "0" prominently displayed
4. MIDDLE: Architecture flow (Query → Filter → Route → Resolve → Sign → Respond)
5. BOTTOM LEFT: Cluster visualization (3 nodes with Raft arrows)
6. BOTTOM RIGHT: Management icons (API, Dashboard, CLI, MCP robot, Prometheus graph)

FOOTER: "Pure Go • Single Binary • Zero Dependencies • github.com/ecostack/nothingdns"
```

### 4.3 X/Twitter Post Templates

**Launch:**
```
🚀 Introducing NothingDNS

A complete DNS server written in pure Go.
Zero external dependencies.

✅ Authoritative + Recursive
✅ DoT / DoH / DoQ
✅ DNSSEC signing & validation
✅ Raft clustering
✅ Built-in ad blocking
✅ Web dashboard + REST API + MCP

One binary. That's it.

github.com/ecostack/nothingdns
```

**Technical:**
```
TIL: The entire DNS wire protocol fits in ~500 lines of Go.

12-byte header → label compression → record types → EDNS

No library needed. Just encoding/binary and net.UDPConn.

Building NothingDNS taught me DNS is simpler than most people think. The hard part is DNSSEC. 😅
```

**Culture:**
```
DNS server dependency tree:

BIND: libxml2, libuv, openssl, json-c, lmdb...
CoreDNS: 847 Go modules
PowerDNS: boost, lua, openssl, sqlite, mysql...

NothingDNS: go.sum is literally empty 💀

Zero. Dependencies.
```

---

## 5. Repository Structure (Public-Facing)

### 5.1 README.md Outline
1. ASCII logo + tagline
2. Feature highlights (badges)
3. Quick Start (3 commands)
4. Architecture diagram
5. Installation (binary, Docker, package managers)
6. Configuration (minimal example)
7. Usage examples (authoritative, recursive, cluster)
8. CLI tool (dnsctl)
9. API documentation link
10. Performance benchmarks
11. Comparison table (vs BIND, CoreDNS, PowerDNS, Unbound)
12. Roadmap
13. Contributing
14. License

### 5.2 Badges
```
[Go Version: 1.22+]
[Dependencies: 0]
[License: Apache 2.0]
[Build: passing]
[Coverage: 85%]
[Release: v1.0.0]
[Docker: ghcr.io/ecostack/nothingdns]
```

---

## 6. Community & Growth

### 6.1 Target Audiences (Priority Order)
1. **DevOps/SRE engineers** — Need reliable, automatable DNS
2. **Homelabbers/self-hosters** — Want Pi-hole + authoritative in one tool
3. **Go developers** — Interested in the zero-dependency approach
4. **Security-conscious orgs** — Want minimal supply chain + DNSSEC
5. **AI/LLM users** — Interested in MCP-native infrastructure

### 6.2 Community Channels
- GitHub Discussions (primary)
- Discord server (optional, later)
- Twitter/X: @nothingdns or @ecostack
- Blog: Technical articles on DNS internals

### 6.3 Growth Metrics
- GitHub stars
- Docker pulls
- Blog post shares/views
- Conference talks/mentions
- Production deployment reports

---

*Document Version: 1.0*
*Created: 2026-03-25*
*Author: Ersin / ECOSTACK TECHNOLOGY OÜ*
*Status: DRAFT — Pending Review*
