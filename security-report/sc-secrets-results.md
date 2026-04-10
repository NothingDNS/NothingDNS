# Security Scan: Hardcoded Secrets & Crypto Misuse
**Target:** NothingDNS (D:\Codebox\PROJECTS\NothingDNS)
**Date:** 2026-04-09
**Scanner:** Manual Code Review + Grep Pattern Analysis

---

## [CRYPTO] crypto/rand Correctly Used for Security-Sensitive Operations

**Severity:** PASS (No Issue)
**Files:**
- `internal/auth/auth.go:200` — Token generation uses `crypto/rand`
- `internal/auth/auth.go:163` — Password generation uses `crypto/rand`
- `internal/dnssec/crypto.go:366,390,403` — Key pair generation uses `crypto/rand`
- `internal/dnssec/crypto.go:561` — Salt generation uses `rand.Reader`
- `internal/dnscookie/cookie.go:82,180` — Cookie secret generation uses `rand.Reader`
- `internal/transfer/tsig.go` — HMAC operations use proper crypto

**Description:** All security-sensitive random number generation correctly uses `crypto/rand`. No use of `math/rand` for cryptographic purposes.

**Recommendation:** Maintain current approach.

---

## [CRYPTO] SHA-1 Usage in NSEC3 (DNSSEC)

**Severity:** Medium
**File:** `internal/dnssec/crypto.go:506,513`
**Lines:** 506, 513

```go
h := sha1.New() // #nosec G505 - NSEC3 requires SHA-1 per RFC 5155
```

**Description:** SHA-1 is used for NSEC3 hash computation. The code has `#nosec G505` annotation citing RFC 5155 requirement. However, NSEC3 is used for denial of existence, not integrity of data in transit.

**Impact:** Low — SHA-1 for NSEC3 is mandated by RFC 5155. The weakness in SHA-1 would only affect an attacker trying to precompute NSEC3 hashes, which is not a practical attack vector.

**Recommendation:** Accept — SHA-1 for NSEC3 is per RFC standard. The `#nosec` annotation appropriately documents the intentional use.

---

## [CRYPTO] HMAC-MD5 Allowed in TSIG (Legacy Compatibility)

**Severity:** Low
**File:** `internal/transfer/tsig.go:19-26`
**Lines:** 19-20

```go
const (
    // HMAC-MD5 is deprecated but included for compatibility
    HmacMD5    = "hmac-md5.sig-alg.reg.int"
```

**Description:** HMAC-MD5 is defined as a constant but is not actually used — the `calculateMAC` function rejects it:

```go
case HmacSHA1:
    return nil, fmt.Errorf("SHA-1 is deprecated, use SHA-256 or SHA-512")
default:
    return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
```

**Impact:** None — HMAC-MD5 is defined but rejected at runtime.

**Recommendation:** Remove `HmacMD5` constant to prevent confusion and enforce SHA-256/SHA-512 only.

---

## [CRYPTO] TLS Configuration Hardening

**Severity:** High
**Files:** `cmd/nothingdns/main.go:502-504`, `internal/transfer/xot.go:117-119`, `internal/server/tls.go:124-147`

**Description:** TLS configurations found:

1. **DoT/DoQ in main.go (line 502):**
```go
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
}
```
No `MinVersion` set — relies on Go defaults (TLS 1.0 minimum).

2. **XoT in xot.go (line 117):**
```go
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
    MaxVersion: tls.VersionTLS13,
}
```
Correctly sets TLS 1.2 minimum.

3. **Server TLS profile (line 124):**
```go
config := &tls.Config{
    MinVersion: profile.MinimumTLSVersion,
    MaxVersion: tls.VersionTLS13,
}
```
Uses configurable minimum.

**Impact:** DoT/DoQ without explicit `MinVersion` may allow TLS 1.0/1.1 connections. While Go's defaults have improved, explicit configuration is safer.

**Recommendation:** Add `MinVersion: tls.VersionTLS12` to DoT/DoQ TLS config in main.go.

---

## [CRYPTO] Weak Hash in WebSocket Handshake

**Severity:** Low
**File:** `internal/websocket/websocket.go:55`
**Line:** 55

```go
h := sha1.New()
h.Write([]byte(key))
h.Write([]byte(wsGUID))
accept := base64.StdEncoding.EncodeToString(h.Sum(nil))
```

**Description:** SHA-1 is used for WebSocket accept key computation per RFC 6455. This is not a security issue — the WebSocket handshake uses SHA-1 for domain separation, not for security-critical operations. The "security" of WebSocket is provided by TLS.

**Impact:** None — Per RFC 6455 standard, SHA-1 is required for the accept hash.

**Recommendation:** Accept — RFC 6455 compliant.

---

## [SECRETS] No Hardcoded Passwords/Keys Found

**Severity:** PASS (No Issue)
**Files Checked:**
- `internal/auth/auth.go` — Uses `crypto/rand` for password generation, no hardcoded defaults
- `internal/config/config.go` — No default passwords in config
- `cmd/nothingdns/main.go` — Auth store initialized from config only

**Description:** No hardcoded passwords, API keys, or tokens found. Auth store correctly uses cryptographically generated passwords when no users configured.

---

## [SECRETS] Auto-Generated Auth Secret Warning Logged

**Severity:** Medium
**File:** `internal/auth/auth.go:77-83`
**Lines:** 77-83

```go
if cfg.Secret == "" {
    generated := generateSecret(32)
    secret = []byte(generated)
    util.Warnf("AUTH: No auth_secret configured. Generated temporary secret for this run: %s. " +
        "Set auth_secret in config for production deployments.", generated)
}
```

**Description:** When no auth secret is configured, a temporary secret is generated and logged. This is intentional for first-run/dev scenarios but could be problematic if logs are persisted.

**Impact:** If logs are stored long-term and accessible to attackers, they could recover the temporary auth secret. However, the warning message explicitly advises setting a proper secret.

**Recommendation:** Remove the generated secret from the log message. The warning should only indicate that a temporary secret was generated without exposing it:
```go
util.Warnf("AUTH: No auth_secret configured. Generated temporary secret for this run. " +
    "Set auth_secret in config for production deployments.")
```

---

## [AUTH] Password Hashing — Custom PBKDF2-like Scheme

**Severity:** High (Informational)
**File:** `internal/auth/auth.go:124-151`
**Lines:** 124-151

```go
func HashPassword(password string, salt []byte) []byte {
    // PBKDF2-like key derivation using SHA256
    key := make([]byte, 32)
    h := sha256.New()

    // First iteration: password + salt
    h.Write([]byte(password))
    h.Write(salt)
    copy(key, h.Sum(nil))

    // Multiple iterations for computational cost
    for i := 1; i < 10000; i++ {
        h.Reset()
        h.Write(key)
        h.Write(salt)
        copy(key, h.Sum(nil))
    }
    // Prepend salt to hash
    result := make([]byte, len(salt)+len(key))
    copy(result, salt)
    copy(result[len(salt):], key)
    return result
}
```

**Description:** Custom password hashing scheme uses 10,000 iterations of SHA-256 with salt. While not using a standard PBKDF2 function, the design follows PBKDF2 principles (key stretching with salt).

**Impact:** The scheme is not provably resistant to GPU/ASIC attacks like bcrypt or argon2. However, 10,000 iterations with SHA-256 provides reasonable protection against brute force.

**Recommendation:** Consider migrating to `golang.org/x/crypto/argon2` or `crypto/pbkdf2` for industry-standard hashing. Current implementation is acceptable but not best-in-class.

---

## [AUTH] HMAC Signing Key Handling

**Severity:** Low
**File:** `internal/auth/auth.go:51`
**Line:** 51

```go
secret  []byte // HMAC signing key
```

**Description:** HMAC signing key is stored in memory as `[]byte`. The key is used for `SignToken` and `VerifyTokenSignature` operations.

**Impact:** Key resides in memory. With proper file permissions (0600 on auth store), this is acceptable.

**Recommendation:** Ensure auth store file permissions are restrictive.

---

## [COOKIE] DNS Cookie Security

**Severity:** PASS (No Issue)
**File:** `internal/dnscookie/cookie.go`
**Lines:** 82-84, 180-182

**Description:** DNS cookies correctly use `crypto/rand` for secret generation and `HMAC-SHA256` for cookie computation. Secret rotation is implemented with previous-secret grace period.

**Recommendation:** Maintain current implementation.

---

## [SESSION] Cookie Security Configuration

**Severity:** PASS (No Issue)
**File:** `internal/api/server.go:2411-2418`
**Lines:** 2411-2418

```go
http.SetCookie(w, &http.Cookie{
    Name:     "ndns_token",
    Value:    token.Token,
    Path:     "/",
    HttpOnly: true,
    Secure:   r.TLS != nil,
    SameSite: http.SameSiteStrictMode,
    MaxAge:   86400,
})
```

**Description:** Cookie security is properly configured:
- `HttpOnly: true` — Prevents JavaScript access
- `Secure: r.TLS != nil` — Only sent over HTTPS
- `SameSite: http.SameSiteStrictMode` — CSRF protection

**Recommendation:** Consider adding `SameSite: http.SameSiteStrictMode` when TLS is not available (development mode) to avoid breakage, but current approach is correct.

---

## [CRYPTO] math/rand in Raft Consensus (Non-Critical)

**Severity:** Low
**File:** `internal/cluster/raft/rng.go:17`
**Line:** 17

```go
rng: rand.New(rand.NewSource(rand.Int63())),
```

**Description:** Raft consensus module uses `math/rand` with seed from `rand.Int63()`. This is not a cryptographic use — Raft's random delays for elections are not security-critical.

**Impact:** Low — Consensus operations using predictable randomness for non-security purposes (election timeout randomization).

**Recommendation:** Accept for consensus operations. If future-proofing desired, could use `crypto/rand` for seed, but unnecessary.

---

## [CONFIG] TSIG Secret in Config

**Severity:** Informational
**File:** `internal/config/config.go:1001-1002`
**Lines:** 1001-1002

```go
slave.TSIGKeyName = slaveNode.GetString("tsig_key_name")
slave.TSIGSecret = slaveNode.GetString("tsig_secret")
```

**Description:** TSIG secrets are stored in configuration files. No hardcoded defaults found.

**Recommendation:** Ensure config file permissions are restrictive (0600) and TSIG secrets are properly managed. Use environment variable expansion for secrets in production.

---

## Summary Table

| Category | Finding | Severity | Status |
|----------|---------|----------|--------|
| crypto/rand usage | All security-sensitive operations use crypto/rand | PASS | PASS |
| Hardcoded secrets | No hardcoded passwords/keys/tokens found | PASS | PASS |
| TLS hardening | DoT/DoQ missing explicit MinVersion | High | FINDING |
| Password hashing | Custom PBKDF2-like scheme (10k iterations) | Medium | ACCEPTABLE |
| SHA-1 usage | NSEC3 (RFC required), WebSocket (RFC required) | Low | ACCEPTABLE |
| HMAC-MD5 | Defined but rejected at runtime | Low | CLEANUP |
| Auth secret logging | Generated secret logged on startup | Medium | FINDING |
| Cookie security | DNS cookies use crypto/rand + HMAC-SHA256 | PASS | PASS |
| Session cookies | HttpOnly, Secure, SameSite properly set | PASS | PASS |
| math/rand | Raft consensus only (non-security-critical) | Low | ACCEPTABLE |

---

## Priority Findings

### 1. DoT/DoQ TLS Configuration (High)
**File:** `cmd/nothingdns/main.go:502-504`
**Action:** Add `MinVersion: tls.VersionTLS12` to TLS config

### 2. Auth Secret in Logs (Medium)
**File:** `internal/auth/auth.go:82-83`
**Action:** Remove generated secret from log message

### 3. Remove Unused HMAC-MD5 Constant (Low)
**File:** `internal/transfer/tsig.go:20`
**Action:** Remove `HmacMD5` constant to prevent confusion

---

*Generated by security scan. For questions, consult the NothingDNS security team.*