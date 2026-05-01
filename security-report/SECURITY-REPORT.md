## Patched (committed)

| ID | Severity | CWE | Title | Commit |
|----|----------|-----|-------|--------|
| P1 | CRITICAL | CWE-639 | Privilege escalation in user creation API | `00a736b` |
| P2 | HIGH | CWE-285 | ACL default-allow when rules configured | `00a736b` |
| P3 | MEDIUM | CWE-400 | NSEC3 iteration bounds (max=150) | `00a736b` |
| P4 | MEDIUM | CWE-306 | Dashboard HTTP endpoints wired to auth | `735b3c3` |
| P6 | MEDIUM | CWE-319 | Warn when allow_insecure cluster used with non-loopback seeds | `1b53b60` |

# NothingDNS Security Audit Report

**Date:** 2026-05-01
**Branch:** main
**Tool:** security-check (Phase 1–2: Recon + Hunt)
**Scope:** Full codebase audit — 4 agent threads, 48 skill categories

---

## Executive Summary

| Severity | Original | Patched | Remaining |
|----------|----------|---------|-----------|
| CRITICAL | 1 | 1 | 0 |
| HIGH | 2 | 1 | 1 |
| MEDIUM | 8 | 4 | 4 |
| LOW | 4 | 0 | 4 |
| INFO / Protected | 11 | 0 | 11 |

**Patched count:** 5 of 15 findings (1 CRITICAL, 1 HIGH, 3 MEDIUM).

The codebase uses strong crypto (AES-256-GCM, ECDSA P-256/P-384, Ed25519, HMAC-SHA512, PBKDF2 310k), stdlib-only deps, and TLS 1.3 by default.

---

## CRITICAL

### CWE-639 — Privilege Escalation: Any Authenticated User Can Create Admin Accounts

**File:** `internal/api/api_auth.go:269–290`

The create-user endpoint (`POST /api/v1/users`) requires the `admin` role to call. However, the role requested in the request body (`req.Role`) is **not validated against the caller's role**. An Operator or Viewer token can create an account with `RoleAdmin`, escalating privileges without authorization.

**Remediation:** Validate `req.Role <= caller's.Role` or restrict role field to only allow roles ≤ the caller's own role.

---

## HIGH

### CWE-306 — DoH/ODoH Endpoints Skip Auth Entirely

**File:** `internal/api/server.go:824–846`

Browsers and stub resolvers don't send Bearer tokens for DoH queries, so these endpoints intentionally skip auth. However, when `auth_token` or `authStore` is configured, there is no mechanism to restrict DoH/ODoH to authenticated users. Any client can use the encrypted DNS path without credentials.

**Remediation:** Add optional DoH/ODoH authentication via client certificates or configure IP allowlisting for the encrypted DNS path.

---

### CWE-319 — AllowInsecureCluster Permits Plaintext Gossip

**File:** `internal/cluster/cluster.go:75–79`, `internal/cluster/gossip.go:287–296`

When `allow_insecure=true`, cluster gossip traffic is sent in plaintext with no node authentication. Any node on the network can join, receive zone updates, cache invalidations, and config sync payloads. This is dangerous in multi-tenant environments.

**Remediation:** Require `encryption_key` whenever `seed_nodes` are configured. Warn loudly if `allow_insecure=true` is set with non-loopback seed nodes.

---

## MEDIUM

### CWE-285 — ACL Default-Allow Without Rules

**File:** `internal/filter/acl.go:79–92`

If `denyByDefault=false` (the default) and no ACL rules are configured, all traffic is allowed. Accidentally clearing ACL rules exposes the resolver to unauthorized use.

**Remediation:** Change the default to `denyByDefault=true`.

---

### CWE-306 — Dashboard HTTP Endpoints Unauthenticated

**File:** `internal/dashboard/server.go:207–218`

`/api/dashboard/stats`, `/api/dashboard/queries`, and `/api/dashboard/zones` serve without checking credentials. The dashboard server has `SetAuthStore`/`SetAuthToken` but only the WebSocket handler uses them.

**Remediation:** Wire auth middleware to all dashboard HTTP endpoints.

---

### CWE-306 — Metrics & Health Endpoints Open Without Auth Token

**File:** `internal/metrics/metrics.go:144–148`

```go
if m.config.AuthToken != "" {
    metricsHandler = m.requireMetricsAuth(m.handleMetrics)
    healthHandler = m.requireMetricsAuth(m.handleHealth)
}
```

If `AuthToken` is not configured, metrics (cache hits, upstream latency, query counts) and health probes are fully open.

**Remediation:** Fail-fast if `AuthToken` is not set when metrics are enabled, or bind to localhost only.

---

### CWE-307 — No Failed Login Tracking or Account Lockout

**File:** `internal/auth/auth.go:505–518`

Failed login attempts are not logged or tracked. No progressive delay, no attempt counter, no lockout. Brute-force attacks against credentials go undetected.

**Remediation:** Add failed login tracking with exponential backoff per account after N failed attempts.

---

### CWE-307 — Unlimited Concurrent Sessions

**File:** `internal/auth/auth.go:256–259`

No per-user concurrent session limit. A compromised token can be used alongside the legitimate token indefinitely.

**Remediation:** Add optional per-user session limit with configurable max tokens.

---

### CWE-312 — TSIG Secret Stored in Plaintext YAML

**File:** `internal/config/config.go:295`

`TSIGSecret` is stored in plaintext in the YAML config file with no minimum length or entropy check. Placeholder detection is the only validation.

**Remediation:** Require TSIG secrets to be at least 32 bytes and warn if they appear to be low-entropy.

---

### CWE-312 — Cluster Encryption Key in Plaintext YAML

**File:** `internal/config/config.go:431`

Cluster encryption key is stored in plaintext in config. `validateSecrets` only checks for placeholder patterns, not cryptographic strength of the actual key value.

**Remediation:** Same as TSIG — enforce minimum entropy/length for cluster encryption key in config validation.

---

### CWE-400 — NSEC3 Iterations Not Bounds-Checked (CPU DoS)

**File:** `internal/dnssec/crypto.go:494–519`

`NSEC3Hash(iterations uint16)` accepts any value 0–65535 without validation. RFC 9276 recommends ≤150 for SHA-1. An attacker could craft an NSEC3 record with max iterations to cause CPU exhaustion during validation.

KeyTrap mitigation (`maxDelegationOps = 32`) limits DS x DNSKEY comparisons, but not NSEC3 hash iterations per record. `maxNSECValidations = 16` limits the number of NSEC3 records evaluated, but each still runs its full iteration count.

**Remediation:** Validate NSEC3 iterations against a maximum (e.g., 150) during validation. Reject zones with excessive NSEC3 iterations.

---

### CWE-613 — Tokens In-Memory Only, No Persistence Across Restarts

**File:** `internal/auth/auth.go:710–716`

`cmd/nothingdns` never calls `SetTokenFilePath`, so all tokens are invalidated on server restart. While documented, this means session continuity is broken for all users on any restart or crash.

**Remediation:** Wire `SaveTokensSigned`/`LoadTokensSigned` in the server lifecycle or warn prominently in the config if token persistence is not configured.

---

### CWE-345 — No Node Identity Verification in Gossip Protocol

**File:** `internal/cluster/gossip.go:506–543`

The `handleMessage` function processes messages from any UDP source without cryptographically verifying that a message originated from the claimed node. Sequence numbers protect against replay, but an attacker in plaintext mode can send fake gossip messages.

**Remediation:** In encrypted mode, bind messages to sender identity via AEAD AAD (already partially done). Consider adding a MAC over the sender identity field.

---

## LOW

### CWE-327 — HMAC-SHA1 Accepted for TSIG with Warning

**File:** `internal/transfer/tsig.go:474–479`

HMAC-SHA1 for TSIG produces a deprecation warning but is not rejected. SHA-1 is weakened but not broken for HMAC.

**Remediation:** Log at WARN level and consider requiring a config flag to reject SHA-1 in production.

---

### CWE-672 — Auto-Generated Auth Secret Invalidated on Restart

**File:** `internal/auth/auth.go:100–108`

When no `auth_secret` is configured, a random 32-byte secret is generated in-memory. All outstanding tokens are invalidated on every restart.

**Remediation:** Warn more prominently. Consider generating a persistent secret file on first boot.

---

### CWE-290 — TSIG Not Bound to Source IP

**File:** `internal/transfer/axfr.go:149–217`

TSIG key validation does not verify the client's source IP matches any IP associated with the TSIG key. Keys are not bound to client addresses.

**Remediation:** Bind TSIG keys to source IP CIDRs in the config and validate on each AXFR/IXFR request.

---

### CWE-200 — DoH Audit Logging May Contain PII

**File:** `internal/audit/audit.go:22–32`

`QueryAuditEntry` captures `ClientIP` and `QueryName`. When audit logging is enabled and DNS queries touch privacy-sensitive domains, this may constitute PII under GDPR and similar frameworks.

**Remediation:** Add a privacy mode that redacts query names or client IPs from audit logs. Provide GDPR-compliant data minimization guidance in docs.

---

## INFO / Protected

| Area | Status |
|------|--------|
| RNG (crypto/rand only) | GOOD |
| AES-256-GCM (fresh nonce per msg) | GOOD |
| TLS 1.3 default, RFC 7525 suites | GOOD |
| Password hashing (PBKDF2 310k) | GOOD |
| Auth token format (opaque, HMAC-SHA512) | GOOD |
| DNSSEC algorithm strength (RSA 2048/4096, ECDSA, Ed25519) | GOOD |
| Cache poisoning mitigation (DO bit in key, maphash shards) | GOOD |
| Response Rate Limiting with superlative detection | GOOD |
| AXFR deny-by-default + TSIG enforcement | GOOD |
| UDP record-boundary-aware truncation | GOOD |
| DNS Cookie HMAC-SHA256 with rotation | GOOD |
| ODoH independent keys per RFC 9230 | GOOD |
| DNSSEC KeyTrap mitigation (maxRRsets, maxNSEC) | GOOD |

---

## Remediation Priority

| Priority | Finding | Effort |
|----------|---------|--------|
| P1 | Privilege escalation in user creation API | Low |
| P2 | ACL default-allow → deny-by-default | Low |
| P3 | NSEC3 iteration bounds validation | Medium |
| P4 | Dashboard + metrics auth wiring | Medium |
| P5 | Cluster encryption key enforcement | Medium |
| P6 | Failed login tracking | Medium |
| P7 | Token persistence across restarts | Medium |
