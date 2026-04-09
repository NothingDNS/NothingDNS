# Authentication & Authorization Security Audit Report

**Project:** NothingDNS
**Date:** 2026-04-09
**Auditor:** Security Audit (Phase 2)
**Scope:** Authentication, Authorization, Session Management, Token Security

---

## Executive Summary

The NothingDNS codebase implements a custom authentication and RBAC system with three roles (admin, operator, viewer). While the implementation shows security awareness in some areas (constant-time comparison, HMAC-SHA256 signatures), several significant vulnerabilities were identified that require immediate attention.

**Critical Findings:** 1
**High Findings:** 2
**Medium Findings:** 5
**Low Findings:** 3

---

## Findings

### F1: Default Admin Password Logged to stdout/stderr

**CWE:** CWE-532 (Credentials in Logs), CWE-200 (Exposure of Sensitive Information)

**File:** `internal/auth/auth.go:103-104`

```go
// Log the generated password - operator must change this
util.Warnf("No users configured. Default admin password generated: %s", defaultPassword)
util.Warnf("Change this password immediately via the dashboard or API.")
```

**Description:**
When no users are configured in `auth.yaml`, the system auto-generates a default admin account with a cryptographically secure random password. However, this password is written to stdout via `util.Warnf()` (which defaults to `os.Stdout` per `internal/util/logger.go:68-69`).

Any process with access to stdout (container logs, system logs, log aggregation systems) can retrieve the admin password.

**Severity:** HIGH

**Confidence:** HIGH

**Evidence:**
- `internal/util/logger.go:66-69`: Default output is `os.Stdout`
- `internal/util/logger.go:184`: `fmt.Fprintln(l.output, output)` writes to configured output

**Remediation:**
1. Log only a warning that a default admin was created, without the password
2. Require interactive first-run setup to set admin password
3. If auto-generation is necessary, output password ONLY to a secured file with restrictive permissions
4. Consider requiring password change on first login

---

### F2: Missing RBAC Enforcement on Multiple API Endpoints

**CWE:** CWE-284 (Improper Access Control), CWE-269 ( Improper Privilege Management)

**File:** `internal/api/server.go:175-196, 605-617, 643-651, 765-830, 832-842, 869-922, 1627-1673, 1717-1787, 1789-1847, 1849-1938`

**Description:**
The `authMiddleware` validates that a valid token is present but does NOT enforce role-based access control. Most endpoints that modify system state (zones, cache, blocklists, upstreams, ACL, RPZ) do not check if the user has the required role.

**Affected Endpoints Without Role Checks:**

| Endpoint | Methods | Operations | Expected Role | Actual Check |
|----------|---------|------------|---------------|--------------|
| `/api/v1/zones` | POST | Create zone | Operator+ | Token only |
| `/api/v1/zones/{name}` | DELETE | Delete zone | Operator+ | Token only |
| `/api/v1/zones/{name}/records` | POST/PUT/DELETE | Modify records | Operator+ | Token only |
| `/api/v1/cache/flush` | POST | Flush cache | Operator+ | Token only |
| `/api/v1/blocklists` | POST | Add blocklist | Operator+ | Token only |
| `/api/v1/blocklists/{path}` | DELETE | Remove blocklist | Operator+ | Token only |
| `/api/v1/upstreams` | PUT | Update upstreams | Operator+ | Token only |
| `/api/v1/acl` | PUT | Update ACL rules | Operator+ | Token only |
| `/api/v1/rpz/rules` | POST/DELETE | Modify RPZ | Operator+ | Token only |

**Impact:**
Any authenticated user (including `viewer` role) can:
- Create and delete DNS zones
- Modify DNS records
- Flush the cache
- Add/remove blocklists
- Modify upstreams
- Update ACL rules
- Modify RPZ policies

**Severity:** HIGH

**Confidence:** HIGH

**Evidence:**
- `internal/api/server.go:201-207`: Only `/api/v1/auth/*` endpoints have role checks
- `internal/api/server.go:2162-2203`: `handleUsers` is the only handler with explicit `hasRole()` checks

**Remediation:**
Add role checks to all state-modifying endpoints:
```go
// Example for handleCreateZone
func (s *Server) handleCreateZone(w http.ResponseWriter, r *http.Request) {
    if !hasRole(r.Context(), s.authStore, auth.RoleOperator) {
        s.writeError(w, http.StatusForbidden, "Operator role required")
        return
    }
    // ... rest of handler
}
```

---

### F3: No Rate Limiting on Authentication Endpoint

**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)

**File:** `internal/api/server.go:2058-2113`

**Description:**
The `/api/v1/auth/login` endpoint has no rate limiting, brute-force protection, or account lockout mechanism. An attacker can attempt unlimited password guesses against user accounts.

**Severity:** MEDIUM

**Confidence:** HIGH

**Evidence:**
- `internal/api/server.go:2059-2068`: No rate limiting before credential verification
- `internal/api/server.go:2077-2086`: Direct password verification without throttling

**Remediation:**
1. Implement per-IP rate limiting (e.g., 5 attempts per minute)
2. Implement per-username progressive delay
3. Add CAPTCHA after failed attempts
4. Consider implementing account lockout after 10 failed attempts

---

### F4: Token Permitted in URL Query Parameter

**CWE:** CWE-598 (Sensitive Data in URL), CWE-532 (Credentials in Logs)

**File:** `internal/api/server.go:312-315`

```go
// Fallback: query parameter
if token == "" {
    token = r.URL.Query().Get("token")
}
```

**Description:**
Authentication tokens can be passed via URL query parameter (`?token=xxx`). This exposes the token in:
- Browser history
- Server access logs
- Proxy logs
- Referer headers
- Web server logs (typically written to disk)

**Severity:** MEDIUM

**Confidence:** HIGH

**Evidence:**
- `internal/api/server.go:314`: Token extracted from query parameters
- Tokens in URLs are frequently logged by default in web servers

**Remediation:**
1. Remove query parameter token fallback
2. Require tokens only in `Authorization: Bearer` header
3. If backward compatibility required, document the risk and recommend header usage

---

### F5: In-Memory Token Store - No Persistence or Revocation Across Restarts

**CWE:** CWE-613 (Insufficient Session Expiration)

**File:** `internal/auth/auth.go:47-52, 195-196`

```go
type Store struct {
    mu      sync.RWMutex
    users   map[string]*User
    tokens  map[string]*Token  // In-memory only
    secret  []byte
}
```

**Description:**
Tokens are stored only in memory in a `map[string]*Token`. If the server restarts:
1. All active sessions are invalidated
2. Users must re-authenticate
3. Revoked tokens list is lost

Additionally, if a user is deleted, their active tokens are only revoked on the current node (not propagated in cluster mode).

**Severity:** LOW

**Confidence:** HIGH

**Note:** This may be by design for simplicity. If high availability is required, consider distributed session store.

---

### F6: Custom Password Hashing Instead of Standard Library

**CWE:** CWE-916 (Use of Password Hash With Insufficient Computational Effort)

**File:** `internal/auth/auth.go:112-140`

```go
func HashPassword(password string, salt []byte) []byte {
    if salt == nil {
        salt = make([]byte, 16)
        rand.Read(salt)
    }
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
    // ...
}
```

**Description:**
The implementation uses a custom PBKDF2-like construction with SHA256 and 10000 iterations. While this provides some protection, it:
1. Is not a standard algorithm (no third-party audit)
2. Uses SHA256 instead of bcrypt/argon2 which have GPU-resistant properties
3. May have implementation-specific weaknesses

Industry standard is `bcrypt` or `argon2id` which are specifically designed for password hashing and have been extensively cryptanalyzed.

**Severity:** MEDIUM

**Confidence:** HIGH

**Remediation:**
Replace with `golang.org/x/crypto/bcrypt` or `github.com/alexedwards/argon2id`:
```go
import "golang.org/x/crypto/bcrypt"

func HashPassword(password string) []byte {
    hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return hash
}
```

---

### F7: Permissive CORS Policy

**CWE:** CWE-942 (Permissive Cross-Domain Whitelist)

**File:** `internal/api/server.go:269-283`

```go
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
        // ...
    })
}
```

**Description:**
CORS policy allows `Access-Control-Allow-Origin: *` meaning any website can make requests to the API on behalf of authenticated users. While the API requires authentication, this:
1. Allows any origin to attempt XSS attacks against the API
2. Enables CSRF attacks (though SameSite cookies help)
3. Violates least-privilege principle for CORS

**Severity:** MEDIUM

**Confidence:** HIGH

**Remediation:**
1. Configure specific allowed origins based on deployment
2. Use environment-based configuration for CORS origins
3. Consider whether CORS is needed at all for a DNS management API

---

### F8: No Session Fixation Protection

**CWE:** CWE-384 (Session Fixation)

**File:** `internal/api/server.go:169-197, 2058-2113`

**Description:**
When a user logs in, a new random token is generated (`GenerateToken`). However, the token does not change after privilege escalation or role changes. If an attacker can establish a session before privilege escalation, they retain access after the user upgrades their privileges.

**Severity:** LOW

**Confidence:** MEDIUM

**Note:** The code does revoke tokens on password change (`internal/auth/auth.go:284-289`), but not on role changes.

---

### F9: Timing Attack on AuthToken Comparison

**CWE:** CWE-208 (Observable Timing Discrepancy)

**File:** `internal/api/server.go:327`

```go
if s.config.AuthToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.config.AuthToken)) == 1 {
```

**Description:**
`subtle.ConstantTimeCompare` is used correctly, BUT the comparison happens on byte slices of potentially different lengths. When `len(token) != len(s.config.AuthToken)`, the function returns 0 immediately without constant-time behavior (this is documented in Go's crypto/subtle).

An attacker could potentially determine the length of the auth token by measuring response times.

**Severity:** LOW

**Confidence:** MEDIUM

**Remediation:**
Compare lengths before constant-time comparison:
```go
if s.config.AuthToken != "" && len(token) == len(s.config.AuthToken) && subtle.ConstantTimeCompare([]byte(token), []byte(s.config.AuthToken)) == 1 {
```

---

### F10: Weak HMAC Secret Generation on First Start

**CWE:** CWE-798 (Use of Hard-coded Credentials)

**File:** `internal/auth/auth.go:66-71, 408-413`

```go
func DefaultConfig() *Config {
    return &Config{
        Secret:      generateSecret(32),  // Called on first start if not configured
        TokenExpiry: Duration{24 * time.Hour},
    }
}

func generateSecret(n int) string {
    b := make([]byte, n)
    rand.Read(b)
    return base64.URLEncoding.EncodeToString(b)
}
```

**Description:**
When no `auth_secret` is configured, a random 32-byte secret is auto-generated. However:
1. The secret is generated in memory and not persisted
2. If the server restarts before saving config, a new secret is generated
3. This invalidates all existing tokens

This can cause production outages if the secret is not properly saved to config.

**Severity:** LOW

**Confidence:** MEDIUM

**Remediation:**
1. Warn loudly if auto-generated secret is used in production
2. Require secret to be explicitly configured for production deployments
3. Provide tooling to validate secret is persisted before accepting connections

---

### F11: Viewer Can Access Sensitive Configuration Data

**CWE:** CWE-200 (Exposure of Sensitive Information)

**File:** `internal/api/server.go:1541-1555`

```go
func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
    cfg := s.configGetter()
    s.writeJSON(w, http.StatusOK, cfg)
}
```

**Description:**
`GET /api/v1/server/config` returns the full server configuration including potentially sensitive data like `auth_token` (if configured). This endpoint only requires a valid token (any role), not admin access.

**Severity:** MEDIUM

**Confidence:** HIGH

**Remediation:**
1. Sanitize sensitive fields before returning config
2. Require admin role for full config access
3. Create separate endpoints for public vs. sensitive config

---

## Summary Table

| ID | CWE | File | Line | Severity | Confidence |
|----|-----|------|------|----------|------------|
| F1 | CWE-532, CWE-200 | internal/auth/auth.go | 103-104 | HIGH | HIGH |
| F2 | CWE-284, CWE-269 | internal/api/server.go | 175-196 | HIGH | HIGH |
| F3 | CWE-307 | internal/api/server.go | 2058-2113 | MEDIUM | HIGH |
| F4 | CWE-598, CWE-532 | internal/api/server.go | 312-315 | MEDIUM | HIGH |
| F5 | CWE-613 | internal/auth/auth.go | 47-52 | LOW | HIGH |
| F6 | CWE-916 | internal/auth/auth.go | 112-140 | MEDIUM | HIGH |
| F7 | CWE-942 | internal/api/server.go | 269-283 | MEDIUM | HIGH |
| F8 | CWE-384 | internal/api/server.go | 169-197 | LOW | MEDIUM |
| F9 | CWE-208 | internal/api/server.go | 327 | LOW | MEDIUM |
| F10 | CWE-798 | internal/auth/auth.go | 66-71 | LOW | MEDIUM |
| F11 | CWE-200 | internal/api/server.go | 1541-1555 | MEDIUM | HIGH |

---

## Positive Security Findings

1. **Constant-time password comparison** (`internal/auth/auth.go:166`): Uses `subtle.ConstantTimeCompare` correctly for password verification

2. **HMAC-SHA256 for token signatures** (`internal/auth/auth.go:417-420`): Uses cryptographically secure HMAC

3. **Secure cookie attributes** (`internal/api/server.go:2097-2105`): HttpOnly, Secure (when TLS), SameSiteStrictMode

4. **Token revocation on password change** (`internal/auth/auth.go:284-289`): Revokes all user tokens when password is changed

5. **Role hierarchy correctly implemented** (`internal/auth/auth.go:389-406`): Admin > Operator > Viewer with proper comparison

---

## Recommendations (Priority Order)

1. **[CRITICAL]** Remove default admin password from logs (F1)
2. **[HIGH]** Add RBAC enforcement to all state-modifying endpoints (F2)
3. **[HIGH]** Add rate limiting to login endpoint (F3)
4. **[MEDIUM]** Remove token from URL query parameter fallback (F4)
5. **[MEDIUM]** Replace custom password hashing with bcrypt/argon2 (F6)
6. **[MEDIUM]** Restrict CORS policy to specific origins (F7)
7. **[MEDIUM]** Sanitize sensitive config data before returning (F11)
8. **[LOW]** Add session fixation protection on role changes (F8)
9. **[LOW]** Fix timing attack on token length comparison (F9)
10. **[LOW]** Document and warn about auto-generated secret requirements (F10)
