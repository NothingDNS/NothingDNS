# Security Report — NothingDNS

**Date:** 2026-04-13
**Scanner:** security-check skill (4-phase pipeline: Recon → Hunt → Verify → Report)
**Scope:** All Go source files in `internal/` and `cmd/`
**Verdict:** 6 Critical, 10 High, 14 Medium, 12 Low, 3 Informational

---

## Executive Summary

NothingDNS is a zero-dependency DNS server written in pure Go. The codebase is well-structured with good security fundamentals: AES-256-GCM for cluster gossip, TLS profiles for encrypted transports, RBAC for API access, and TSIG for zone transfers.

However, several **production-readiness gaps** exist in protocol parsers (unbounded allocations enabling remote DoS), transport handlers (missing rate limiting enabling amplification), and zone transfer logic (insufficient authentication on AXFR/NOTIFY). Two features are partially implemented (DoQ, ODoH) which creates a false sense of security if enabled in production.

---

## Critical Findings

### C1: Unbounded Record Count Iteration — Remote Memory Exhaustion DoS

| File | Lines | Severity | CVSS |
|------|-------|----------|------|
| `internal/protocol/message.go` | 232-271 | CRITICAL | 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) |

**Issue:** `UnpackMessage()` loops over `h.ANCount`, `h.NSCount`, and `h.ARCount` (each up to 65535) without any aggregate limit. A single crafted DNS response with max record counts triggers hundreds of megabytes of allocation.

**Attack Vector:** Spoofed DNS response with ANCount=65535 → each RR allocates a new `ResourceRecord` struct → per-packet memory exhaustion.

**Fix:** Add a cap on total records parsed per message (e.g., 512). Return `TRUNC` or error when exceeded.

---

### C2: No Recursion Depth Limit in YAML Parser — Stack Overflow DoS

| File | Lines | Severity | CVSS |
|------|-------|----------|------|
| `internal/config/parser.go` | 159, 291, 617, 679 | CRITICAL | 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) |

**Issue:** `parseMapping`, `parseBlockSequence`, `parseFlowMapping`, and `parseFlowSequence` call each other recursively with no depth limit. A deeply nested YAML config (e.g., 10,000 levels) causes a Go runtime stack overflow, crashing the server.

**Attack Vector:** If an attacker can write to the config file (via API or file access), or supply config via any unvalidated input, the parser panics on stack overflow.

**Fix:** Add a `depth` counter to the parser; reject inputs exceeding ~100 levels of nesting.

---

### C3: QUIC DoQ 1-RTT Packet Handling Unimplemented (TODO)

| File | Lines | Severity | CVSS |
|------|-------|----------|------|
| `internal/quic/doq.go` | 443-463 | CRITICAL | 5.0 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L) |

**Issue:** `handleShortHeaderPacket()` contains `_ = dc` (TODO comment). Normal 1-RTT encrypted QUIC packets are silently discarded. The DoQ server cannot process standard DNS queries over QUIC.

**Impact:** Functional bug — DoQ does not work. Enabling it in production creates a false sense of security.

**Fix:** Implement QUIC stream data routing to complete DoQ support.

---

### C4: ODoH Target `processDNSQuery` Is a No-Op

| File | Lines | Severity | CVSS |
|------|-------|----------|------|
| `internal/odoh/odoh.go` | 469-474 | CRITICAL | 5.0 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L) |

**Issue:** `ObliviousTarget.processDNSQuery()` returns the query as the response: `return query`. The ODoH target does not resolve DNS queries.

**Impact:** Functional dead code. Enabling ODoH returns nonsense responses.

---

### C5: DNSSEC NSEC3 Iterations Not Validated During Wire Unpacking

| File | Lines | Severity | CVSS |
|------|-------|----------|------|
| `internal/protocol/dnssec_nsec3.go` | 164-251 | CRITICAL | 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) |

**Issue:** NSEC3 `Iterations` field is read directly from wire format with no validation. `MaxIterations = 150` exists in `dnssec_nsec3param.go` but is only checked in `VerifyParams()`, not during unpacking.

**Attack Vector:** Send an NSEC3 record with Iterations=65535 → DNSSEC validator computes 65,535 SHA-1 iterations per name → severe CPU exhaustion.

**Fix:** Validate iterations against `MaxIterations` during `Unpack()`.

---

### C6: Zone Radix Tree Panics on Empty Domain String

| File | Lines | Severity | CVSS |
|------|-------|----------|------|
| `internal/zone/radix.go` | 65 | CRITICAL | 6.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) |

**Issue:** `splitDomainReversed()` does `name = name[:len(name)-1]` which panics when `name` is empty.

**Attack Vector:** A query or zone operation that triggers an empty domain string crashes the goroutine handling the DNS query.

**Fix:** Add bounds check: `if len(name) == 0 { return nil }`.

---

## High Findings

### H1: No UDP Rate Limiting or Amplification Mitigation

| File | Severity |
|------|----------|
| `internal/server/udp.go`, `internal/server/handler.go` | HIGH |

**Issue:** UDP reader dispatches every packet to workers with no per-IP rate limiting, no query throttling, no response-size-to-query-size ratio enforcement. 60-byte query → 4096-byte response (68x amplification).

**Fix:** Implement per-IP query rate limiting at the UDP layer; cap response amplification ratio.

---

### H2: AXFR Zone Transfers Without TSIG When Only IP Allowlist Configured

| File | Severity |
|------|----------|
| `internal/transfer/axfr.go` | HIGH |

**Issue:** If an IP allowlist is configured but no TSIG keys, zone transfers are allowed to any IP in the allowlist without additional authentication. Combined with broad CIDR ranges (e.g., `0.0.0.0/0`), any client can exfiltrate zone data.

**Fix:** Require TSIG for zone transfers regardless of IP allowlist.

---

### H3: NOTIFY Handler Accepts from Any IP Without Authentication

| File | Severity |
|------|----------|
| `internal/transfer/notify.go` | HIGH |

**Issue:** `HandleNOTIFY()` has no TSIG verification, no IP allowlist check, no master-server validation.

**Attack Vector:** Forged NOTIFY triggers unnecessary zone transfers, wasting resources.

**Fix:** Add IP allowlist and/or TSIG verification for NOTIFY.

---

### H4: QUIC Stream Deadlines Are No-Ops

| File | Severity |
|------|----------|
| `internal/quic/conn.go` | HIGH |

**Issue:** `SetDeadline`, `SetReadDeadline`, `SetWriteDeadline` all return `nil` without doing anything. Streams cannot be timed out.

**Attack Vector:** Open a QUIC stream and hold it indefinitely → resource exhaustion.

**Fix:** Implement stream-level deadline enforcement.

---

### H5: Unbounded EDNS0 Option Parsing

| File | Severity |
|------|----------|
| `internal/protocol/opt.go` | HIGH |

**Issue:** OPT record parser allocates a new byte slice and struct for every EDNS0 option with no count limit.

**Fix:** Cap options per OPT record (e.g., 64).

---

### H6: `advance()` and `peek()` Skip Comments — Parser Trust Model

| File | Severity |
|------|----------|
| `internal/protocol/` (documented in CLAUDE.md) | HIGH |

**Issue:** The parser's `advance()` and `peek()` automatically skip `TokenComment` tokens. This is a design decision documented in CLAUDE.md, but means comments in zone files or wire data are silently consumed. If comment handling changes, all parse logic that relies on this implicit skip will break.

**Fix:** Document this behavior clearly in each parse function; consider explicit comment handling.

---

### H7: WebSocket Handler Has No Per-Connection Rate Limiting

| File | Severity |
|------|----------|
| `internal/doh/wshandler.go` | HIGH |

**Issue:** WebSocket loop reads messages with only a 30-second read timeout. No limit on total messages per connection.

**Fix:** Add per-connection message rate limit.

---

### H8: QUIC Stream Limiting Not Enforced

| File | Severity |
|------|----------|
| `internal/quic/doq.go` | HIGH |

**Issue:** `DoQMaxStreamsPerConnection = 100` is defined but never enforced. A single QUIC connection can spawn unlimited stream handler goroutines.

**Fix:** Enforce the constant in stream acceptance.

---

### H9: Opportunistic TLS Allows Plaintext Fallback

| File | Severity |
|------|----------|
| `internal/server/tls.go` | HIGH |

**Issue:** `TLSProfileOpportunistic` allows `ShouldFallback()` to return `true`. An active MITM can force downgrade to plaintext DNS (STRIP-DNS attack).

**Fix:** Default to `TLSProfileStrict` which disallows fallback.

---

### H10: `splitDomainReversed` Panics on Single-Label Domain

| File | Severity |
|------|----------|
| `internal/zone/radix.go` | HIGH |

**Issue:** If called with a single-label domain (e.g., `"example"` without trailing dot), the slice operation after removing the trailing dot may panic or produce incorrect results depending on input.

**Fix:** Validate input has at least one dot before processing.

---

## Medium Findings

### M1: Auth Secret Not Persisted Between Restarts

| File | Severity |
|------|----------|
| `internal/auth/auth.go` | MEDIUM |

**Issue:** Auto-generated `auth_secret` is ephemeral. All valid tokens are invalidated on restart → DoS for authenticated users.

---

### M2: Error Message Leakage in API Responses

| File | Severity |
|------|----------|
| `internal/api/server.go` | MEDIUM |

**Issue:** Internal Go error strings (file paths, internal state) are reflected in HTTP error responses.

---

### M3: No RBAC on Legacy Token Mode

| File | Severity |
|------|----------|
| `internal/api/server.go` | MEDIUM |

**Issue:** Legacy `auth_token` mode bypasses all RBAC — single token has full admin access.

---

### M4: MCP Server Has No Authentication on SSE Transport

| File | Severity |
|------|----------|
| `internal/api/mcp/server.go` | MEDIUM |

**Issue:** SSE transport exposes destructive tools (`zone_delete`, `cache_flush`) without auth.

---

### M5: WebSocket Token Accepted via Query Parameter

| File | Severity |
|------|----------|
| `internal/dashboard/server.go` | MEDIUM |

**Issue:** Tokens in URL are logged in access logs, proxy logs, browser history.

---

### M6: WebSocket Origin Check Skipped When `allowedOrigins` Empty

| File | Severity |
|------|----------|
| `internal/websocket/websocket.go` | MEDIUM |

**Issue:** Empty `allowedOrigins` disables origin validation → cross-site WebSocket hijacking.

---

### M7: Unbounded String Reading in YAML Tokenizer

| File | Severity |
|------|----------|
| `internal/config/tokenizer.go` | MEDIUM |

**Issue:** `readQuotedString()` uses `strings.Builder` with no size limit.

---

### M8: Silent Empty-String Substitution for Missing Environment Variables

| File | Severity |
|------|----------|
| `internal/config/config.go` | MEDIUM |

**Issue:** Missing env vars silently become empty strings → could disable auth, encryption, or TLS.

---

### M9: Zone File Loading Follows Symlinks

| File | Severity |
|------|----------|
| `internal/zone/manager.go` | MEDIUM |

**Issue:** `os.Open()` follows symlinks without validation → path disclosure if symlink is attacker-controlled.

---

### M10: XoT Server Has No Read Timeout

| File | Severity |
|------|----------|
| `internal/transfer/xot.go` | MEDIUM |

**Issue:** `conn.Read()` never sets a read deadline → slow-loris on XoT connections.

---

### M11: DDNS RData Stored as Raw String Without Validation

| File | Severity |
|------|----------|
| `internal/transfer/ddns.go` | MEDIUM |

**Issue:** Malformed RData from DDNS updates passes directly to zone operations.

---

### M12: No ALPN Enforcement on TLS Servers

| File | Severity |
|------|----------|
| `internal/server/tls.go` | MEDIUM |

**Issue:** `BuildTLSConfigForProfile()` never sets `NextProtos` → non-DNS clients can connect to TLS ports.

---

### M13: ODoH Proxy Does Not Validate Target Identity

| File | Severity |
|------|----------|
| `internal/odoh/odoh.go` | MEDIUM |

**Issue:** No certificate pinning or target identity verification beyond standard HTTPS.

---

### M14: `maxRecords = 65535` Is a No-Op Validation

| File | Severity |
|------|----------|
| `internal/protocol/wire.go` | MEDIUM |

**Issue:** Validation check against `maxRecords` is effectively useless (max uint16 can never exceed it).

---

## Low Findings

### L1: `rand.Read` Error Ignored in Secret Generation

| File | Severity |
|------|----------|
| `internal/auth/auth.go` | LOW |

If `crypto/rand` fails, secret becomes all zero bytes.

---

### L2: Bootstrap Endpoint Relies on `X-Real-IP` Header

| File | Severity |
|------|----------|
| `internal/api/server.go` | LOW |

`getClientIP()` checks `X-Real-IP` before `RemoteAddr` → spoofable behind a proxy.

---

### L3: Blocklist File Path Traversal Check Is String-Based

| File | Severity |
|------|----------|
| `internal/blocklist/blocklist.go` | LOW |

`strings.Contains(path, "..")` does not protect against symlink-based traversal.

---

### L4: Audit Log Fields Not Fully Sanitized

| File | Severity |
|------|----------|
| `internal/audit/audit.go` | LOW |

`ClientIP` and `QueryType` bypass `sanitizeLogField()` → log injection.

---

### L5: Metrics Endpoint Exposed Without Authentication

| File | Severity |
|------|----------|
| `internal/metrics/metrics.go` | LOW |

Prometheus `/metrics` exposes internal server state with no auth.

---

### L6: Metrics Cardinality via Unbounded Label Values

| File | Severity |
|------|----------|
| `internal/metrics/metrics.go` | LOW |

Dynamically created label values can cause unbounded memory growth.

---

### L7: Rate Limiter Map Memory Growth

| File | Severity |
|------|----------|
| `internal/filter/ratelimit.go` | LOW |

`buckets` map grows for every unique IP; IP spoofing can cause memory growth between prune cycles.

---

### L8: `math/rand` Fallback for DNS Transaction IDs

| File | Severity |
|------|----------|
| `internal/resolver/resolver.go` | LOW |

If `crypto/rand` is unavailable, transaction IDs become predictable → cache poisoning.

---

### L9: DoH GET Base64 Parameter Has No Size Limit

| File | Severity |
|------|----------|
| `internal/doh/handler.go` | LOW |

No length check on base64 parameter before decode → memory allocation.

---

### L10: DoH Error Messages Leak Internal State

| File | Severity |
|------|----------|
| `internal/doh/handler.go` | LOW |

Raw Go error strings in HTTP responses.

---

### L11: Legacy Login Cookie Missing `Secure` Flag in JS

| File | Severity |
|------|----------|
| `internal/dashboard/static.go` | LOW |

JavaScript-set cookie lacks `Secure` flag → sent over plaintext HTTP.

---

### L12: Integer Overflow in Config `GetInt`

| File | Severity |
|------|----------|
| `internal/config/node.go` | LOW |

No overflow check in manual integer parsing → silent wrap-around.

---

### L13: TXT Record Truncation in ZONEMD

| File | Severity |
|------|----------|
| `internal/zone/zonemd.go` | LOW |

TXT records > 255 bytes silently truncated in ZONEMD hash computation.

---

### L14: WAL Replay Loads All Entries Into Memory

| File | Severity |
|------|----------|
| `internal/zone/wal_journal.go` | LOW |

No limit on WAL replay → potential OOM on large journals.

---

## Informational

### I1: SHA-1 in WebSocket Handshake — RFC-Mandated

| File | Severity |
|------|----------|
| `internal/websocket/websocket.go` | INFO |

SHA-1 is required by RFC 6455 Section 4.2.2. Not a vulnerability.

---

### I2: HMAC-MD5 for TSIG — Protocol Required

| File | Severity |
|------|----------|
| `internal/transfer/tsig.go` | INFO |

HMAC-MD5 is required by RFC 2845 for TSIG interoperability. Not a vulnerability.

---

### I3: TLS Cipher Suites Broader Than Needed

| File | Severity |
|------|----------|
| `internal/server/tls.go` | INFO |

Cipher suite list includes TLS 1.2 suites, but `MinVersion: tls.VersionTLS13` in default profile makes them irrelevant. Cleanup only.

---

## Remediation Priority

### Immediate (Fix Before Production)

| # | Finding | Effort |
|---|---------|--------|
| C1 | Cap total records per DNS message | Low |
| C2 | Add YAML parser recursion depth limit | Low |
| C5 | Validate NSEC3 iterations during unpack | Low |
| C6 | Add empty string check in `splitDomainReversed` | Low |
| H1 | Add UDP per-IP rate limiting | Medium |
| H2 | Require TSIG for zone transfers | Low |
| H3 | Add NOTIFY authentication | Low |
| H4 | Implement QUIC stream deadlines | Medium |
| H5 | Cap EDNS0 options per OPT record | Low |

### Short-Term (Next Sprint)

| # | Finding | Effort |
|---|---------|--------|
| H9 | Default to strict TLS profile | Low |
| H6 | Document parser comment-skip behavior | Low |
| H7 | Add WebSocket rate limiting | Low |
| H8 | Enforce QUIC stream limits | Low |
| M2 | Sanitize API error responses | Low |
| M4 | Add MCP SSE transport auth | Medium |
| M5 | Remove WebSocket URL token auth | Low |
| M6 | Fail closed on empty `allowedOrigins` | Low |
| M8 | Log warnings for missing env vars | Low |
| M12 | Set ALPN `NextProtos` in TLS config | Low |

### Medium-Term (Backlog)

| # | Finding | Effort |
|---|---------|--------|
| C3/C4 | Complete DoQ and ODoH implementations | High |
| M1 | Persist auth secret or fail to start | Low |
| M3 | Deprecate legacy token mode or add RBAC | Medium |
| M7 | Add YAML tokenizer string size limit | Low |
| M9 | Validate symlinks in zone loading | Low |
| M10 | Add XoT read timeout | Low |
| M11 | Validate DDNS RData | Medium |
| M13 | Add ODoH target identity validation | Medium |
| M14 | Replace `maxRecords` with meaningful limit | Low |

---

## Architecture Map

```
Attack Surface Map:

Internet
  ├── UDP:53 ────────→ [No rate limiting] → Amplification risk
  ├── TCP:53 ────────→ [Pipeline semaphore] → Slow-loris
  ├── TLS:853 ───────→ [Opportunistic fallback] → STRIP attack
  ├── HTTPS:443 ─────→ [No auth on DoH] → Public resolver
  ├── QUIC:853 ──────→ [TODO: unimplemented] → Non-functional
  └── API:8080 ──────→ [RBAC + JWT] → Well-secured

Internal:
  ├── Gossip ────────→ [AES-256-GCM] → Well-secured
  ├── Raft ──────────→ [WAL + snapshot] → Well-secured
  ├── Zone Transfer ──→ [TSIG + allowlist] → Partially secured
  └── MCP ───────────→ [No auth on SSE] → Risk if exposed
```

---

## Dependency Audit

NothingDNS uses **zero external dependencies** beyond `golang.org/x/sys` (for `SO_REUSEPORT`). This eliminates:

- Supply chain attacks via third-party packages
- Vulnerable dependency CVEs
- Typosquatting risks
- License compliance issues

All cryptographic operations use Go stdlib: `crypto/tls`, `crypto/rand`, `crypto/hmac`, `crypto/sha1`, `crypto/sha256`, `crypto/aes`, `crypto/cipher`, `encoding/base64`, `crypto/x509`.

**Verdict:** Supply chain risk is minimal. All security-relevant code is in-house and should be audited accordingly.

---

*Report generated by security-check skill on 2026-04-13*
