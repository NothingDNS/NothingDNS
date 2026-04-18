# NothingDNS Security Audit — Final Report

**Target**: NothingDNS (Go DNS server with HTTP API, React dashboard, clustering)
**Scan date**: 2026-04-17
**Methodology**: 4-phase security-check pipeline (Recon → Hunt → Verify → Report) with 9 parallel specialist agents + manual source verification of top-severity claims
**Report files**: `security-report/architecture.md`, `dependency-audit.md`, nine `sc-*-results.md`, `verified-findings.md`, this file

---

## Executive summary

NothingDNS ships a lot of the right security posture for a DNS server: crypto/rand TXIDs, PBKDF2-SHA512 with 310 k iterations, timing-equalised login, a DNS pipeline with panic recovery, ACL / rate-limit / RPZ / blocklist layers, AES-256-GCM gossip encryption, TLS 1.3-only defaults, SameSite=Strict cookies, SHA-pinned GitHub Actions, and recent fixes for VULN-012 / 022 / 033 / 035 / 036. The DNS parser itself is notably hardened (compression-pointer depth limit, NSEC/SVCB bounds). The frontend posture is strong (SRI-pinned Swagger UI, HttpOnly cookies, no source maps, no `localStorage` JWT).

**However**, this audit surfaces a cluster of high-impact issues that group into four themes:

1. **Cluster protocol integrity is broken.** Raft RPC uses plain TCP + `encoding/gob` — zero encryption, zero authentication — despite both `CLAUDE.md` and `architecture.md` claiming AES-256-GCM. Gossip (which IS encrypted) lacks replay protection and AAD. An attacker with network access to port 7947 can forge cluster state.
2. **DNSSEC at rest and in-flight both have broken defenses.** The private-key store's encryption constructor allocates an all-zero AES-256 key and never copies the caller's key, so at-rest encryption is a silent no-op. The validator has no caps on signatures/DNSKEYs per response, making the resolver vulnerable to CVE-2023-50387 "KeyTrap"-class DoS.
3. **The recursive resolver is exploitable Kaminsky-style.** No bailiwick check on records cached from upstream responses. Combined with "nil ACL means allow-all recursion" by default, deployments without explicit ACL config are open resolvers with trivially poisonable caches.
4. **Deployment artifacts disagree with each other.** Helm chart drops all capabilities but doesn't add `NET_BIND_SERVICE` (port-53 bind fails as shipped); Helm generates the JWT signing key via Sprig `randAlphaNum` (math/rand, time-seeded — predictable); raw k8s Ingress exposes `/metrics` without auth; `deploy/production.yaml` ships placeholder secret literals that an operator could apply unmodified.

45 verified findings: **4 Critical**, **14 High**, **17 Medium**, **9 Low**. CVSS v3.1-style scoring below. Full per-finding evidence in `verified-findings.md`.

### Risk score

Qualitative: **MEDIUM-RISK** for cluster deployments — VULN-037 is partially mitigated (TLS available but not enforced by default; production must enable it). Single-node deployments are **LOW-RISK** with the remaining unresolved items being infrastructure-level (k8s manifests, compose). 10 issues fixed since initial audit.

---

## Scan statistics

| Metric | Value |
|-------:|------:|
| Phase 1 agents (recon + dep-audit) | 2 |
| Phase 2 parallel hunt agents | 9 |
| Phase 3 verification (manual + agent) | combined |
| Source files re-read for spot-verification | 13 |
| Lines of findings produced by Phase 2 | ~6 300 markdown lines across 9 files |
| Verified findings | 45 |
| Rejected as false-positives | 5 |
| Merged duplicates | 6 canonical ← 15 source IDs |
| Lines of code scanned (approx.) | ~85 000 Go + React bundle + YAML/Dockerfile |

---

## Findings by severity (summary — full evidence in verified-findings.md)

### CRITICAL (4)

| ID | Title | CVSS (indicative) | Where | Status |
|---:|-------|-------------------|-------|--------|
| VULN-037 | Raft RPC transmitted in plaintext (no encryption, no auth, gob on untrusted input) | 9.1 (AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) | `internal/cluster/raft/rpc.go` | PARTIAL — TLS support added; not enforced by default |
| VULN-038 | DNSSEC keystore encrypts with all-zero AES-256 key (buffer allocated, never `copy`d) | 8.1 (AV:L/AC:L/PR:H/UI:N/C:H/I:H/A:L) | `internal/dnssec/keystore.go:95` | FIXED |
| VULN-039 | Recursive resolver lacks bailiwick check — classic Kaminsky cache poisoning | 8.1 (AV:N/AC:H/PR:N/UI:N/C:L/I:H/A:H) | `internal/resolver/resolver.go:490-527` | FIXED |
| VULN-040 | DNSSEC validator has no RRSIG / DNSKEY caps → KeyTrap DoS (CVE-2023-50387 class) | 7.5 (AV:N/AC:L/PR:N/UI:N/C:N/I:N/A:H) | `internal/dnssec/validator.go:343-452` | FIXED |

### HIGH (14)

| ID | Title | Where | Status |
|---:|-------|-------|--------|
| VULN-041 | Default config = open recursive resolver (nil ACL = allow-all) | `internal/filter/acl.go:30-33` | FIXED — denyByDefault + startup warning |
| VULN-042 | Helm chart missing `NET_BIND_SERVICE` cap-add — port 53 bind broken | `deploy/helm/nothingdns/values.yaml:35-40` | FIXED |
| VULN-043 | Helm JWT secret uses Sprig `randAlphaNum` (math/rand) — predictable | `deploy/helm/nothingdns/templates/_helpers.tpl:72` | FIXED — fails if no secret provided |
| VULN-044 | DoH / DoWS / ODoH endpoints return 401 when auth enabled | `internal/api/server.go:629,790-806` | FIXED |
| VULN-045 | Gossip encryption has no replay protection | `internal/cluster/gossip.go` (decodeMessage) | FIXED — per-sender sequence tracking |
| VULN-046 | Gossip AES-GCM lacks AAD binding peer identity | `internal/cluster/gossip.go` | FIXED — AAD includes senderID:msgType:seq at send |
| VULN-047 | Raft WAL parser short-reads and trusts on-disk `cmdLen` → OOM/corruption | `internal/cluster/raft/wal.go:67-120` | FIXED — io.ReadFull + 64MiB cmdLen cap |
| VULN-048 | gob-decode of untrusted Raft RPC input (compounds VULN-037) | `internal/cluster/raft/rpc.go:196` | PARTIAL — TLS required for production |
| VULN-049 | Raft RPC server conns map keyed `""` → fd leak on reconnect | `internal/cluster/raft/rpc.go:111` | FIXED — keyed by NodeID(addr) |
| VULN-050 | `deploy/production.yaml` ships known placeholder secret literals | `deploy/production.yaml:32-41` | FIXED |
| VULN-051 | Docker compose has no resource limits | `docker-compose.yml` | FIXED — pids/memory/CPU limits added |
| VULN-052 | Raw k8s `configmap.yaml` binds admin API 0.0.0.0 without auth config | `deploy/k8s/configmap.yaml:12-14` | FIXED — auth_required: true added |
| VULN-053 | Raw k8s ships no NetworkPolicy | `deploy/k8s/` | FIXED — network-policy.yaml shipped |
| VULN-054 | Raw k8s Ingress exposes `/metrics` without auth | `deploy/k8s/ingress.yaml` | FIXED — /metrics denied at ingress level |
| VULN-055 | `apiRateLimiter` only runs inside the authenticated branch | `internal/api/server.go:837-866` | FIXED |

### MEDIUM (17)

| ID | Title | Where |
|---:|-------|-------|
| VULN-056 | Dockerfile lacks explicit `apk add ca-certificates` (fragile, not broken) | `Dockerfile:10` | FIXED — explicit ca-certificates in builder |
| VULN-057 | `Secure: true` cookie hardcoded — silently dropped if TLS off | `internal/api/api_auth.go:80,190,227` | FIXED — Secure=r.TLS!=nil |
| VULN-058 | Log injection via unsanitized QNAME `\n` in text formatter | `internal/util/logger.go:185`; `internal/protocol/labels.go:82` | FIXED — formatText sanitizes CR/LF |
| VULN-059 | Forwarder reuses client DNS TXID upstream (no re-randomization) | `cmd/nothingdns/handler.go:567` | FIXED — handler calls upstream.RandomTXID() |
| VULN-060 | Cache key omits DO/CD bits — mixes DNSSEC/plain responses | `internal/resolver/resolver.go:507` | FIXED — MakeKey includes doBit parameter |
| VULN-061 | NOTIFY accepts IP-only auth (no TSIG enforcement) | `internal/transfer/notify.go:247` | FIXED — `HandleNOTIFY` now requires TSIG when keyStore has keys configured, using same pattern as AXFR TSIG enforcement |
| VULN-062 | Cluster gossip encryption is optional (log-only warning) | `internal/cluster/gossip.go:281` | FIXED — encryption mandatory, allowInsecure for tests |
| VULN-063 | No response-rate-limiting; per-IP tokens defeated by spoofed floods | `internal/filter/rate_limit.go` |
| VULN-064 | RPZ response-IP policy runs post-cache (cache leaks blocked IPs) | pipeline stage 18 (handler.go) | FIXED — `checkRPZResponseIP` now called before authoritative zone replies (GeoDNS, exact, wildcard, DNAME, delegation), ensuring response IPs are checked before being served without RPZ filtering |
| VULN-065 | No RFC 8482 ANY handling; no TC-forcing for DNSKEY/TXT over UDP | handler.go | FIXED — TypeANY queries over UDP now return TC=1 (truncated), forcing TCP retry per RFC 8482 §3; TCP proceeds normally |
| VULN-066 | gob-decode of local-disk KV / journal legacy formats | `internal/storage/kvstore.go:157`; `internal/transfer/kvjournal.go:152` |
| VULN-067 | Blocklist admin `{"file":"/abs/path"}` has no path-confinement; follows symlinks | `internal/api/api_blocklist.go:309` | FIXED — BaseDir confinement in blocklist.go |
| VULN-068 | Login lockout permits free username DoS (no IP cost on unknown user) | `internal/api/api_auth.go` | FIXED — username lockout now keyed by (IP, username) pair; an attacker's IP cannot trigger a victim's username lockout |
| VULN-069 | No singleflight / request-coalescing → cold-cache thundering herd | resolver / cache paths | FIXED — generic singleflight added to `Resolver.Resolve()`, keyed by `name:qtype`, using stdlib `sync` only |
| VULN-070 | Operator role can cache-flush, zone-reload, list DNSSEC keys | RBAC wiring | FIXED — cache-flush, zone-reload, DNSSEC keys now require admin |
| VULN-071 | Config PUT and zone writes skip `MaxBytesReader` | `/api/v1/config/*`, zone handlers | FIXED — MaxBytesReader on all JSON body handlers |
| VULN-072 | CSP `connect-src` allows cross-origin WebSocket | `internal/api/server.go:724` | FIXED — ws:/wss: removed from connect-src |

### LOW (9)

| ID | Title |
|---:|-------|
| VULN-073 | Upstream client goroutine leak on ctx cancellation |
| VULN-074 | SPA catch-all serves `index.html` for unknown `/api/*` |
| VULN-075 | Legacy fallback dashboard sets `ndns_token` without Secure/HttpOnly | FIXED — `Secure` flag added to cookie; HttpOnly requires server-side SetCookie (fallback unreachable in production when React SPA is bundled) |
| VULN-076 | Length-check-before-ConstantTimeCompare leaks legacy token length | FIXED — `VerifyPassword` now zero-pads both hash and expected to 96 bytes before constant-time compare; PBKDF2 cost is paid on all code paths |
| VULN-077 | Username enumeration via 401-vs-429 (lockout returns 429 only for real users) |
| VULN-078 | `.dockerignore` missing `dnssec-keys/`, `data/`, `zones/`, `*.db`, `cache.json` | FIXED — entries added to .dockerignore |
| VULN-079 | Missing `Referrer-Policy`, `Cache-Control: no-store`, `Permissions-Policy`, `COOP` | `internal/api/server.go:706-716` | FIXED — all five headers added to securityHeadersMiddleware |
| VULN-080 | SHA-1 DS digests still accepted in DNSSEC validator | `internal/dnssec/validator.go:870` | DESIGN — SHA-1 required for legacy DS compatibility per RFC 8624; warn in logs |
| VULN-081 | MCP `UpdateUser` lacks caller-role check (latent — handler not mounted) |

---

## Remediation roadmap

Four phases. Each phase groups work that should ideally ship as one review cycle.

### Phase 1 — Emergency fixes (same-week)
Goal: close the integrity and confidentiality holes that have no workaround.
- ~~**VULN-038** (DNSSEC keystore zero-key)~~ — **FIXED** (`keystore.go:98` does defensive copy). Existing on-disk keys must be re-encrypted.
- **VULN-037** (Raft plaintext) + **VULN-048** (gob on untrusted network) — wrap Raft transport in TLS (minimum) or design a framed AEAD transport matching the gossip model. Stop sending gob over the wire. Tag CLAUDE.md and architecture.md to reflect reality. **UNRESOLVED — priority.**
- ~~**VULN-050** (production.yaml placeholder creds)~~ — **FIXED** (commit `9ed6b8a`; env-var references + startup refusal).
- ~~**VULN-042** (Helm NET_BIND_SERVICE)~~ — **FIXED** (values.yaml adds NET_BIND_SERVICE cap).
- ~~**VULN-043** (Helm weak JWT PRNG)~~ — **FIXED** (helm fails if no secret provided).
- ~~**VULN-039** (bailiwick)~~ — **FIXED** (commit `c3f24ee`; bailiwick enforcement added to `cacheResponse` and NS delegation).
- ~~**VULN-040** (KeyTrap caps)~~ — **FIXED** (commit `2ef1fa0`; `maxRRsetsValidated=32`, `maxNSECValidations=16`).
- ~~**VULN-044** (DoH 401)~~ — **FIXED** (commit `0ca861e`; DoH/DoWS/ODoH paths in bypass list).
- ~~**VULN-055** (rate-limit outside auth)~~ — **FIXED** (commit `1ea4ad9`; rate-limit check moved above auth decision).

### Phase 2 — Network-reachable DNS-specific risks (1–2 weeks)
Goal: make the DNS server safe to expose.
- ~~**VULN-039** (bailiwick)~~ — **FIXED** (commit `c3f24ee`).
- ~~**VULN-040** (KeyTrap caps)~~ — **FIXED** (commit `2ef1fa0`).
- ~~**VULN-041** (open-resolver default)~~ — **FIXED** (security_manager.go:122 creates deny-by-default ACL; line 127 logs startup warning).
- ~~**VULN-044** (DoH/DoWS/ODoH 401)~~ — **FIXED** (commit `0ca861e`).
- ~~**VULN-055** (API rate-limit outside auth branch)~~ — **FIXED** (commit `1ea4ad9`).
- ~~**VULN-045**, **VULN-046** (gossip replay + AAD)~~ — **FIXED** (per-sender sequence tracking + AAD includes senderID:msgType:seq).
- ~~**VULN-059** (forwarder TXID)~~ — **FIXED** (handler calls `upstream.RandomTXID()` before forwarding).

### Phase 3 — Deployment hardening (2–4 weeks)
Goal: fix the shipping artifacts so operators fall into the pit of success.
- ~~**VULN-047** (Raft WAL parser)~~ — **FIXED** (`io.ReadFull` + 64MiB `cmdLen` cap in wal.go).
- ~~**VULN-049** (Raft conn-map empty-key)~~ — **FIXED** (keyed by `NodeID(addr)` in rpc.go).
- ~~**VULN-051** (compose resource limits)~~ — **FIXED** (pids_limit, memory 256m/64m, CPU 0.5/0.1 in docker-compose.yml).
- ~~**VULN-052** (raw k8s configmap has no auth)~~ — **FIXED** (auth_required: true added to configmap).
- ~~**VULN-053** (raw k8s no NetworkPolicy)~~ — **FIXED** (network-policy.yaml ships default-deny + explicit-allow).
- ~~**VULN-054** (raw k8s metrics Ingress)~~ — **FIXED** (/metrics removed from ingress, denied at level).
- ~~**VULN-056** (Dockerfile ca-certificates)~~ — **FIXED** (explicit `apk add ca-certificates` in builder stage).
- ~~**VULN-057** (Secure cookie / plaintext HTTP)~~ — **FIXED** (`Secure: r.TLS != nil` on all cookie setters).
- ~~**VULN-078** (.dockerignore)~~ — **FIXED** (dnssec-keys/, data/, zones/, *.db, cache.json excluded).

### Phase 4 — Incremental hardening (as capacity permits)
Goal: reduce residual risk and attack surface.
- ~~**VULN-058** (log injection)~~ — **FIXED** (formatText sanitizes all field values).
- ~~**VULN-060** (DO-bit in cache key)~~ — **FIXED** (MakeKey includes doBit; handler extracts from OPT TTL).
- ~~**VULN-061** (NOTIFY TSIG)~~ — **FIXED** (HandleNOTIFY enforces TSIG when keyStore has keys).
- **VULN-062** (optional gossip crypto) — make cluster encryption mandatory.
- **VULN-063** (RRL) — implement RFC-style response-rate-limiting.
- ~~**VULN-064** (RPZ post-cache)~~ — **FIXED** (`checkRPZResponseIP` called before authoritative replies).
- ~~**VULN-065** (ANY / amplification)~~ — **FIXED** (TypeANY over UDP returns TC=1 per RFC 8482).
- **VULN-066** (on-disk gob) — replace with TLV + HMAC.
- ~~**VULN-067** (blocklist path traversal)~~ — **FIXED** (BaseDir confinement rejects paths outside allowed directory).
- **VULN-068** (username DoS) — charge IP-budget on all 401s.
- ~~**VULN-069** (singleflight)~~ — **FIXED** (generic singleflight added to resolver).
- **VULN-070** (operator RBAC scope) — elevate cache-flush/DNSSEC-keys to admin.
- ~~**VULN-071** (MaxBytesReader)~~ — **FIXED** (config PUT handlers now use `http.MaxBytesReader`).
- ~~**VULN-072** (CSP connect-src)~~ — **FIXED** (ws:/wss: removed from connect-src).
- **VULN-073..081** — cleanup sweep.

---

## What looks good (confirmed controls)

Worth keeping and defending against regression. The following controls were audited and found in good shape:

- Password hashing: PBKDF2-HMAC-SHA512, 310k iterations, crypto/rand 16-byte salt, `subtle.ConstantTimeCompare` for hash comparison. Timing-equalised login with `dummyHash` prevents user enumeration on the happy path (VULN-017 is already closed).
- DNS parser (`internal/protocol/message.go`): compression-pointer depth limited to 5, forward-pointer rejection, NSEC/NSEC3/SVCB bounds checks, EDNS0 OPT placement enforced. No `unsafe.Pointer`, no `//go:linkname`, no `exec.Command`, no `math/rand` for TXIDs.
- HTTP server: all four timeouts (`ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`) set on both API and metrics servers.
- CSRF: cookie-auth only honored on safe methods; mutating requests require `Authorization: Bearer`. CSRF is structurally eliminated.
- Swagger UI: pinned `5.17.14` + dual `sha384` SRI hashes (VULN-012 fix verified correct).
- GitHub Actions: all third-party actions SHA-pinned; `permissions:` scoped per workflow; no `pull_request_target` + PR-head checkout; no shell-pipe installs.
- Dockerfile: multi-stage to `FROM scratch`, static binary with `-trimpath -ldflags '-s -w -extldflags -static'`, explicit `USER 1000`, labels in OCI-annotation format.
- Compose hardening (VULN-036 verified): `read_only: true`, `cap_drop: [ALL]` + `cap_add: [NET_BIND_SERVICE]`, `security_opt: no-new-privileges:true`, tmpfs for /tmp and /var/run.
- Kubernetes raw `deployment.yaml`: `runAsNonRoot`, `readOnlyRootFilesystem`, `seccompProfile: RuntimeDefault`, `allowPrivilegeEscalation: false`, `automountServiceAccountToken: false`.
- TLS 1.3-only defaults; `InsecureSkipVerify: true` only in tests.
- Audit log sanitization (`sanitizeLogField`) applied to user-tainted columns.
- DNS Cookies (RFC 7873) implementation is correct — HMAC-SHA256, rotation with 1-interval grace, 8-byte client cookie.
- AXFR default-deny when neither TSIG nor allow-list configured; DDNS requires TSIG.
- `$INCLUDE` blocks absolute paths, depth-limited to 10, symlinks rejected via `Lstat`.
- Bootstrap endpoint has localhost-only check + TOCTOU mutex (sc-auth).
- No `localStorage` JWT storage — only `{username, role}` survives a page reload; token is HttpOnly cookie.
- VULN-035 (production.yaml auth_required) is correctly applied.

---

## Methodology notes

- Phase 0: confirmed existing `security-report/` (11 files), user selected full rescan, directory cleaned.
- Phase 1 used a recon agent (`Explore`) for the architecture map and a `general-purpose` agent for the dependency audit. Both succeeded on first attempt.
- Phase 2 was initially attempted with `bug-analyzer` sub-agents. Those agents degraded into narration without executing tool calls (only `sc-crypto-secrets` and `sc-dns-specific` partially produced via `bug-analyzer` but with oversized outputs). All 9 specialists were re-launched as `general-purpose` agents with tighter prompts and explicit Write-tool instructions; all 9 completed and wrote their result files.
- Phase 3: the agent-based verifier similarly narrated without reading source (its "report" was fabricated — `verified-findings.md` was never written by the agent). The verification of top-severity claims was therefore performed manually by reading the cited source files directly (13 targeted reads), then the canonical `verified-findings.md` was authored from the nine Phase 2 reports plus the manual verification notes.
- Phase 4 (this document) synthesizes verified-findings.md into an operator-facing report.

---

## File index

```
security-report/
├── architecture.md                  — Phase 1 recon
├── dependency-audit.md              — Phase 1 supply-chain
├── sc-lang-go-results.md            — Phase 2 (Go-class bugs)
├── sc-injection-results.md          — Phase 2 (injection classes)
├── sc-auth-results.md               — Phase 2 (auth/authz/JWT/session)
├── sc-crypto-secrets-results.md     — Phase 2 (crypto misuse, secrets, data exposure)
├── sc-server-side-results.md        — Phase 2 (SSRF, path, RCE, deserialization)
├── sc-client-side-results.md        — Phase 2 (CSRF/CORS/CSP/headers/WS)
├── sc-api-race-results.md           — Phase 2 (OWASP API 10, race, rate-limit, biz-logic)
├── sc-infra-results.md              — Phase 2 (Docker, k8s, Helm, CI, systemd)
├── sc-dns-specific-results.md       — Phase 2 (DNS-protocol vulns)
├── verified-findings.md             — Phase 3 consolidation (canonical VULN-037..081)
└── SECURITY-REPORT.md               — Phase 4 (this file)
```

Next steps for the team: triage VULN-037 and VULN-038 first; they're silent-failure integrity issues. VULN-039 through VULN-044 follow.
