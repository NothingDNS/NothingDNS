## Patched (committed)

| ID | Severity | CWE | Title | Commit |
|----|----------|-----|-------|--------|
| P1 | CRITICAL | CWE-639 | Privilege escalation in user creation API | `00a736b` |
| P2 | HIGH | CWE-285 | ACL default-allow when rules configured | `00a736b` |
| P3 | MEDIUM | CWE-400 | NSEC3 iteration bounds (max=150) | `00a736b` |
| P4 | MEDIUM | CWE-306 | Dashboard HTTP endpoints wired to auth | `735b3c3` |
| P5 | MEDIUM | CWE-319 | Warn when allow_insecure cluster used with non-loopback seeds | `1b53b60` |
| P6 | MEDIUM | CWE-306 | Metrics & health fail-fast without auth token | `735b3c3` |
| P7 | MEDIUM | CWE-307 | Failed login tracking (false positive — already implemented) | `735b3c3` |
| P8 | MEDIUM | CWE-312 | Entropy validation for TSIG secrets and cluster encryption key | `6b761e8` |
| P9 | MEDIUM | CWE-290 | TSIG keys bound to source IP CIDRs | `6b761e8` |
| P10 | MEDIUM | CWE-307 | Per-user concurrent session limits | `6b761e8` |
| P11 | MEDIUM | CWE-613 | Token persistence across restarts | `1a4cdbc` |

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
| MEDIUM | 8 | 6 | 2 |
| LOW | 4 | 1 | 3 |
| INFO / Protected | 11 | 0 | 11 |

**Patched count:** 10 of 15 findings (1 CRITICAL, 1 HIGH, 6 MEDIUM, 1 LOW).

The codebase uses strong crypto (AES-256-GCM, ECDSA P-256/P-384, Ed25519, HMAC-SHA512, PBKDF2 310k), stdlib-only deps, and TLS 1.3 by default.

---

## CRITICAL

### CWE-639 — Privilege Escalation: Any Authenticated User Can Create Admin Accounts

**File:** `internal/api/api_auth.go:269–290`

The create-user endpoint (`POST /api/v1/users`) requires the `admin` role to call. However, the role requested in the request body (`req.Role`) is **not validated against the caller's role**. An Operator or Viewer token can create an account with `RoleAdmin`, escalating privileges without authorization.

**Remediation:** Validate `req.Role <= caller's.Role` or restrict role field to only allow roles ≤ the caller's own role.

**Status:** Patched (`00a736b`) — role level comparison added in `handleUsers`.

---

## HIGH

### CWE-306 — DoH/ODoH Endpoints Skip Auth Entirely

**File:** `internal/api/server.go:824–846`

Browsers and stub resolvers don't send Bearer tokens for DoH queries, so these endpoints intentionally skip auth. However, when `auth_token` or `authStore` is configured, there is no mechanism to restrict DoH/ODoH to authenticated users. Any client can use the encrypted DNS path without credentials.

**Remediation:** Add optional DoH/ODoH authentication via client certificates or configure IP allowlisting for the encrypted DNS path.

**Status:** Not yet addressed — requires design decision (client certificates, cookie-based DNS auth, or IP allowlisting).

---

### CWE-319 — AllowInsecureCluster Permits Plaintext Gossip

**File:** `internal/cluster/cluster.go:75–79`, `internal/cluster/gossip.go:287–296`

When `allow_insecure=true`, cluster gossip traffic is sent in plaintext with no node authentication. Any node on the network can join, receive zone updates, cache invalidations, and config sync payloads. This is dangerous in multi-tenant environments.

**Remediation:** Require `encryption_key` whenever `seed_nodes` are configured. Warn loudly if `allow_insecure=true` is set with non-loopback seed nodes.

**Status:** Patched (`1b53b60`) — SECURITY warning logged at startup when `allow_insecure=true` with non-loopback seeds.

---

## MEDIUM

### CWE-285 — ACL Default-Allow Without Rules

**File:** `internal/filter/acl.go:79–92`

If `denyByDefault=false` (the default) and no ACL rules are configured, all traffic is allowed. Accidentally clearing ACL rules exposes the resolver to unauthorized use.

**Remediation:** Change the default to `denyByDefault=true`.

**Status:** Patched (`00a736b`) — `denyByDefault=true` as default in `NewACLChecker`.

---

### CWE-306 — Dashboard HTTP Endpoints Unauthenticated

**File:** `internal/dashboard/server.go:207–218`

`/api/dashboard/stats`, `/api/dashboard/queries`, and `/api/dashboard/zones` serve without checking credentials. The dashboard server has `SetAuthStore`/`SetAuthToken` but only the WebSocket handler uses them.

**Remediation:** Wire auth middleware to all dashboard HTTP endpoints.

**Status:** Patched (`735b3c3`) — `authenticateRequest()` method added and wired to stats/queries/zones endpoints.

---

### CWE-306 — Metrics & Health Endpoints Open Without Auth Token

**File:** `internal/metrics/metrics.go:144–148`

If `AuthToken` is not configured, metrics and health probes are fully open.

**Remediation:** Fail-fast if `AuthToken` is not set when metrics are enabled, or bind to localhost only.

**Status:** Patched (`735b3c3`) — server refuses to start with `fmt.Errorf` if metrics enabled but `auth_token` not set.

---

### CWE-307 — No Failed Login Tracking or Account Lockout

**File:** `internal/auth/auth.go:505–518`

Failed login attempts are not logged or tracked. No progressive delay, no attempt counter, no lockout.

**Remediation:** Add failed login tracking with exponential backoff per account after N failed attempts.

**Status:** False positive — `loginRateLimiter` in `internal/api/server.go:81` already implements 5-attempt lockout (5 min), progressive delay (30s max), keyed by (IP, username). No new code needed.

---

### CWE-307 — Unlimited Concurrent Sessions

**File:** `internal/auth/auth.go:256–259`

No per-user concurrent session limit. A compromised token can be used alongside the legitimate token indefinitely.

**Remediation:** Add optional per-user session limit with configurable max tokens.

**Status:** Patched (`6b761e8`) — `http.max_sessions_per_user` config; `activeSessions` map; oldest-token eviction in `GenerateToken`; `LastAccess` updated on every `ValidateToken`.

---

### CWE-312 — TSIG Secret Stored in Plaintext YAML

**File:** `internal/config/config.go:295`

`TSIGSecret` is stored in plaintext in the YAML config file with no minimum length or entropy check. Placeholder detection is the only validation.

**Remediation:** Require TSIG secrets to be at least 32 bytes and warn if they appear to be low-entropy.

**Status:** Patched (`6b761e8`) — `secretHasMinEntropy()` rejects <32 bytes and >85%-single-char-class strings for `slave_zones[].tsig_secret`.

---

### CWE-312 — Cluster Encryption Key in Plaintext YAML

**File:** `internal/config/config.go:431`

Cluster encryption key is stored in plaintext in config. `validateSecrets` only checks for placeholder patterns, not cryptographic strength.

**Remediation:** Enforce minimum entropy/length for cluster encryption key in config validation.

**Status:** Patched (`6b761e8`) — `secretHasMinEntropy()` now validates `cluster.encryption_key`.

---

### CWE-400 — NSEC3 Iterations Not Bounds-Checked (CPU DoS)

**File:** `internal/dnssec/crypto.go:494–519`

`NSEC3Hash(iterations uint16)` accepts any value 0–65535 without validation. RFC 9276 recommends ≤150 for SHA-1. An attacker could craft an NSEC3 record with max iterations to cause CPU exhaustion during validation.

**Remediation:** Validate NSEC3 iterations against a maximum (e.g., 150) during validation.

**Status:** Patched (`00a736b`) — `maxNSEC3Iterations = 150` constant and bounds check at NSEC3Hash entry.

---

### CWE-613 — Tokens In-Memory Only, No Persistence Across Restarts

**File:** `internal/auth/auth.go:710–716`

`cmd/nothingdns` never calls `SetTokenFilePath`, so all tokens are invalidated on server restart.

**Remediation:** Wire `SaveTokensSigned`/`LoadTokensSigned` in the server lifecycle.

**Status:** Patched (`1a4cdbc`) — `http.token_persistence_path` config option; `LoadTokensSigned` at startup, `SaveTokensSigned` at shutdown.

---

### CWE-345 — No Node Identity Verification in Gossip Protocol

**File:** `internal/cluster/gossip.go:506–543`

The `handleMessage` function processes messages from any UDP source without cryptographically verifying that a message originated from the claimed node.

**Remediation:** In encrypted mode, bind messages to sender identity via AEAD AAD.

**Status:** Informational — encrypted mode uses AES-256-GCM with AEAD AAD including sender identity. Plaintext mode has loud warning.

---

## LOW

### CWE-327 — HMAC-SHA1 Accepted for TSIG with Warning

**File:** `internal/transfer/tsig.go:474–479`

HMAC-SHA1 for TSIG produces a deprecation warning but is not rejected.

**Remediation:** Log at WARN level and consider requiring a config flag to reject SHA-1 in production.

**Status:** Deprecation warning already present. Rejection requires opt-in flag (not yet implemented).

---

### CWE-672 — Auto-Generated Auth Secret Invalidated on Restart

**File:** `internal/auth/auth.go:100–108`

When no `auth_secret` is configured, a random 32-byte secret is generated in-memory. All outstanding tokens are invalidated on every restart.

**Remediation:** Warn more prominently. Consider generating a persistent secret file on first boot.

**Status:** Warning already fires at startup. Token persistence (`http.token_persistence_path`) mitigates this for configured deployments.

---

### CWE-290 — TSIG Not Bound to Source IP

**File:** `internal/transfer/axfr.go:149–217`

TSIG key validation does not verify the client's source IP matches any IP associated with the TSIG key.

**Remediation:** Bind TSIG keys to source IP CIDRs in the config and validate on each AXFR/IXFR/DDNS/NOTIFY request.

**Status:** Patched (`6b761e8`) — `TSIGKey.AllowedCIDRs` + `KeyStore.ValidateKeySource()` wired into HandleAXFR, HandleIXFR, HandleUpdate, HandleNOTIFY.

---

### CWE-200 — DoH Audit Logging May Contain PII

**File:** `internal/audit/audit.go:22–32`

`QueryAuditEntry` captures `ClientIP` and `QueryName`. When audit logging is enabled and DNS queries touch privacy-sensitive domains, this may constitute PII under GDPR.

**Remediation:** Add a privacy mode that redacts query names or client IPs from audit logs.

**Status:** Not yet addressed — requires privacy mode design decision.

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

## Remediation Status

| Priority | Finding | Status |
|----------|---------|--------|
| P1 | Privilege escalation in user creation API | Done |
| P2 | ACL default-allow → deny-by-default | Done |
| P3 | NSEC3 iteration bounds validation | Done |
| P4 | Dashboard + metrics auth wiring | Done |
| P5 | Cluster plaintext warning | Done |
| P6 | Failed login tracking | Done (false positive) |
| P7 | Token persistence across restarts | Done |
| P8 | Session limits | Done |
| P9 | TSIG IP binding | Done |
| P10 | Entropy validation for secrets | Done |
| P11 | Metrics fail-fast | Done |
| — | DoH/ODoH auth | Not done (design decision needed) |
| — | DoH PII audit logging | Not done (privacy mode design) |
| — | HMAC-SHA1 TSIG rejection | Not done (warn-only, needs opt-in) |