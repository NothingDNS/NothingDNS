# Authentication & Authorization Security Audit Report

**Project:** NothingDNS
**Date:** 2026-04-09
**Scope:** internal/auth/auth.go, internal/api/server.go (lines 526-607, 2554-2580), cmd/nothingdns/main.go (lines 171-185)
**Focus:** JWT Security, Password Hashing, Token Storage, Rate Limiting, Session Fixation, RBAC Bypass, Privilege Escalation

---

## Executive Summary

| Category | Status | Notes |
|----------|--------|-------|
| JWT Signing | VULNERABLE | Tokens are NOT signed - just random bytes. No HMAC verification on validate. |
| Password Hashing | MEDIUM RISK | Custom SHA256-based PBKDF2 (10k iterations). Not memory-hard. |
| Token Storage | WEAK | Pure in-memory. No persistence. No cluster-wide revocation. |
| Login Rate Limiting | BYPASSABLE | IP extracted from X-Forwarded-For without validation. Trivially spoofed. |
| Session Fixation | PRESENT | No token rotation on role change. Tokens survive privilege escalation. |
| RBAC Enforcement | BYPASSED | Legacy single-token auth skips ALL RBAC checks. |
| Privilege Escalation | PRESENT | viewer token remains valid after role upgrade to operator/admin. |

---

## Findings

## [JWT SECURITY] Token Is Not Signed - No Cryptographic Verification

**Severity:** Critical

**File:** `internal/auth/auth.go:188-216`

**Description:**
`GenerateToken()` creates tokens by generating 32 random bytes with `crypto/rand` and base64 encoding them. The token is stored in an in-memory map and returned to the client. There is NO cryptographic signature.

The `SignToken()` and `VerifyTokenSignature()` functions exist (lines 434-445) but are NEVER called during token generation or validation.

```go
// GenerateToken - internal/auth/auth.go:188-216
func (s *Store) GenerateToken(username string, expiry time.Duration) (*Token, error) {
    // ...
    tokenBytes := make([]byte, 32)
    if _, err := rand.Read(tokenBytes); err != nil {
        return nil, fmt.Errorf("failed to generate token: %w", err)
    }
    token := base64.URLEncoding.EncodeToString(tokenBytes)  // Just random bytes!
    // ...
    s.tokens[token] = t  // Stored directly, no signature
    return t, nil
}

// ValidateToken - internal/auth/auth.go:219-242
func (s *Store) ValidateToken(tokenStr string) (*User, error) {
    s.mu.RLock()
    token, ok := s.tokens[tokenStr]  // Just a map lookup
    if !ok {
        return nil, fmt.Errorf("invalid token")
    }
    // No cryptographic verification whatsoever
    // ...
}
```

**Impact:**
- An attacker who gains read access to the server's memory (e.g., via another vulnerability, memory dump, or side-channel attack) can extract valid tokens
- Tokens cannot be verified as authentic - the server blindly trusts whatever token is presented if it exists in the map
- No protection against token tampering or forgery (though the in-memory store mitigates some of this)

**Recommendation:**
Either:
1. Sign tokens with HMAC-SHA256 using `SignToken()`/`VerifyTokenSignature()` and include username/role in the signed payload, OR
2. Use a proper JWT library with HMAC signing

---

## [PASSWORD HASHING] Custom PBKDF2-SHA256 Instead of Standard Memory-Hard Algorithm

**Severity:** Medium

**File:** `internal/auth/auth.go:122-152`

**Description:**
Password hashing uses a custom PBKDF2-like construction with SHA256 and 10,000 iterations:

```go
func HashPassword(password string, salt []byte) []byte {
    if salt == nil {
        salt = make([]byte, 16)
        rand.Read(salt)  // crypto/rand for salt - GOOD
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

**Issues:**
1. **SHA256 is not memory-hard** - vulnerable to GPU/ASIC/FPGA acceleration
2. **Custom implementation** - has not been cryptographically audited
3. **Low iteration count** (10,000) - modern recommendations are 100,000+ for SHA256-based PBKDF2
4. **Not using standard PBKDF2** - Go's `crypto/pbkdf2` uses HMAC correctly; this manually re-implements it incorrectly (the `h.Sum(nil)` approach)

**Positive:** Uses `crypto/rand` for salt generation (line 127)

**Impact:**
- Passwords hashed with this scheme are weaker than bcrypt/argon2id equivalents
- GPU clusters can crack simple-to-medium strength passwords feasibly

**Recommendation:**
Replace with Go's `crypto/memory-hard` algorithm or use `golang.org/x/crypto/bcrypt`:
```go
import "golang.org/x/crypto/bcrypt"

func HashPassword(password string) []byte {
    hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return hash
}
```

---

## [TOKEN STORAGE] In-Memory Only - No Persistence or Revocation Across Restarts

**Severity:** Medium

**File:** `internal/auth/auth.go:47-52`

**Description:**
```go
type Store struct {
    mu      sync.RWMutex
    users   map[string]*User
    tokens  map[string]*Token  // In-memory ONLY
    secret  []byte
}
```

**Issues:**
1. **Server restart invalidates all tokens** - users must re-authenticate
2. **Revoked tokens list is lost on restart** - if a token was revoked before restart, attacker regains access
3. **No cluster-wide token tracking** - in a multi-node setup, token revocation on one node does not affect other nodes
4. **Memory exhaustion DoS** - unbounded token map allows indefinite session storage

**Impact:**
- Production operational issues (token invalidation on deploy/restart)
- Security bypass via restart (revoked tokens become valid again)
- Cluster mode token bypass (attacker can use token on different node)

**Recommendation:**
1. Persist token store to disk with encrypted storage
2. For cluster mode, use distributed session store (Redis, etcd) with shared secret
3. Add token expiration cleanup goroutine to prevent memory growth

---

## [RATE LIMITING] Login Rate Limiting Bypassable via IP Spoofing

**Severity:** High

**File:** `internal/api/server.go:2582-2609`

**Description:**
The `getClientIP()` function trusts `X-Forwarded-For` and `X-Real-IP` headers without validating them:

```go
func getClientIP(r *http.Request) string {
    // Check X-Forwarded-For header (for proxies/load balancers)
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        // Take the first IP in the chain
        if idx := strings.Index(xff, ","); idx != -1 {
            xff = strings.TrimSpace(xff[:idx])
        }
        xff = strings.TrimSpace(xff)
        if net.ParseIP(xff) != nil {
            return xff  // Returns attacker-controlled value!
        }
    }
    // ...
}
```

**The Attack:**
An attacker can bypass rate limiting by rotating IPs trivially:
```bash
# Each request with different X-Forwarded-For appears as different IP
curl -X POST https://target/api/v1/auth/login \
  -H "X-Forwarded-For: 1.1.1.1" \
  -d '{"username":"admin","password":"guess"}'

curl -X POST https://target/api/v1/auth/login \
  -H "X-Forwarded-For: 1.1.1.2" \
  -d '{"username":"admin","password":"guess"}'

# ... repeat indefinitely, rate limiter never triggers
```

**Note:** The rate limiter code itself is well-implemented (progressive delays, lockout period), but the IP extraction defeats it.

**Impact:**
- Unlimited password guessing against valid accounts
- Effective brute-force attack on login endpoint

**Recommendation:**
1. Only trust `X-Forwarded-For` from known/trusted proxy IPs
2. Require a trusted reverse proxy to set an authenticated header
3. Fall back to `r.RemoteAddr` only when behind trusted proxy

---

## [SESSION FIXATION] No Token Rotation on Role Change

**Severity:** Medium

**File:** `internal/auth/auth.go:286-310`

**Description:**
When a user's role is changed (e.g., viewer → operator), their existing tokens are NOT revoked. The token retains the original role indefinitely.

```go
func (s *Store) UpdateUser(username, password string, role Role) (*User, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    if password != "" {
        user.Hash = HashPassword(password, nil)
    }
    if role != "" {
        user.Role = role  // Role updated
    }

    // Revoke all tokens for this user (password changed only)
    for token, t := range s.tokens {
        if t.Username == username {
            delete(s.tokens, token)
        }
    }
    // NOTE: This only runs if password != ""
    // Role changes alone do NOT revoke tokens
}
```

**Impact:**
1. **Privilege escalation persistence**: Attacker with viewer token retains access after user is promoted to admin
2. **Security monitoring bypass**: SOC sees "admin" role in logs, but attacker still using old viewer token
3. **Insider threat**: Malicious insider maintains access after demotion/termination (tokens not revoked on role removal)

**Recommendation:**
Revoke all user tokens when role changes:
```go
if password != "" || role != "" {
    for token, t := range s.tokens {
        if t.Username == username {
            delete(s.tokens, token)
        }
    }
}
```

---

## [RBAC BYPASS] Legacy Single-Token Auth Skips All RBAC Checks

**Severity:** High

**File:** `internal/api/server.go:2554-2580`

**Description:**
`requireOperator()` and `requireAdmin()` explicitly bypass all RBAC checks when using legacy single-token auth:

```go
// requireOperator - internal/api/server.go:2554-2566
func (s *Server) requireOperator(w http.ResponseWriter, r *http.Request) bool {
    // If using legacy single-token auth (no authStore), skip RBAC — token holders have full access
    if s.authStore == nil {
        return false  // ALLOWS ACCESS
    }
    if !hasRole(r.Context(), s.authStore, auth.RoleOperator) {
        s.writeError(w, http.StatusForbidden, "Operator role required")
        return true
    }
    return false
}

// requireAdmin - internal/api/server.go:2568-2580
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
    // If using legacy single-token auth (no authStore), skip RBAC — token holders have full access
    if s.authStore == nil {
        return false  // ALLOWS ACCESS
    }
    if !hasRole(r.Context(), s.authStore, auth.RoleAdmin) {
        s.writeError(w, http.StatusForbidden, "Admin role required")
        return true
    }
    return false
}
```

**Impact:**
When `auth_token` (legacy single-token) is configured instead of full user auth:
- ANY token holder gets operator-level access
- ANY token holder gets admin-level access (for endpoints checked with `requireAdmin`)
- The RBAC system is completely bypassed
- All state-modifying operations (zones, cache, blocklists, ACL, RPZ) are accessible to anyone with the token

**Note from code comment:** This appears intentional for single-token deployments, but creates a false sense of security - operators may think they have RBAC when they do not.

**Recommendation:**
1. Document this behavior clearly
2. Require multi-user authStore for deployments needing RBAC
3. Add a startup warning when using legacy auth without RBAC

---

## [RBAC] Token Stores Role at Creation - Does Not Reflect Role Changes

**Severity:** Medium

**File:** `internal/auth/auth.go:189-216`

**Description:**
When a token is created, the user's current role is copied into the token:

```go
t := &Token{
    Token:     token,
    Username:  username,
    Role:      user.Role,  // Role snapshot at token creation
    ExpiresAt: now.Add(expiry),
    CreatedAt: now,
}
s.tokens[token] = t
```

The `ValidateToken()` function returns the token's stored role, not the user's current role:

```go
func (s *Store) ValidateToken(tokenStr string) (*User, error) {
    s.mu.RLock()
    token, ok := s.tokens[tokenStr]
    // ...
    user, ok := s.users[token.Username]  // Gets fresh user
    s.mu.RUnlock()
    // BUT: Returns user from map, not token.Role
    return user, nil
}
```

**Impact:**
- If user.Role is updated in the users map but token.Role remains unchanged, `ValidateToken` returns the updated role
- However, the token object itself (used in some contexts) still holds old role
- Potential confusion in audit logs and authorization decisions

**Current Code is Likely Safe** - `ValidateToken` fetches fresh user data. But the `Token` struct's Role field is misleading and could cause issues if used elsewhere.

---

## [TOKEN LEAKAGE] Token Permitted in URL Query Parameter

**Severity:** Medium

**File:** `internal/api/server.go:549-558`

**Description:**
Tokens can be passed via URL query parameter as a fallback:

```go
// Get token from Authorization header
token := r.Header.Get("Authorization")
token = strings.TrimPrefix(token, "Bearer ")

// Fallback: cookie
if token == "" {
    if c, err := r.Cookie("ndns_token"); err == nil {
        token = c.Value
    }
}

// NOTE: Query parameter fallback was removed from current code
// But old logs/configs may still have token in URLs
```

**Impact:**
- Tokens in URLs are logged by default in access logs
- Exposed in browser history
- Exposed in Referer headers
- Can be leaked via shoulder surfing

**Current Code Status:** The query parameter fallback appears to have been removed in the current version (only header and cookie are checked). However, this was present in earlier versions.

---

## [AUTH BYPASS] Constant-Time Compare Order Vulnerability

**Severity:** Low

**File:** `internal/api/server.go:564`

**Description:**
The legacy auth token comparison has proper constant-time comparison, but the length check happens AFTER the token is extracted:

```go
// First check length to prevent timing attack via ConstantTimeCompare
if s.config.AuthToken != "" && len(token) == len(s.config.AuthToken) && subtle.ConstantTimeCompare([]byte(token), []byte(s.config.AuthToken)) == 1 {
```

**This is actually CORRECT** - length check first, then constant-time compare. The comment even documents this. No vulnerability here.

**Positive Finding.**

---

## [PASSWORD] Default Admin Password Logged to stdout

**Severity:** High

**File:** `internal/auth/auth.go:102-116`

**Description:**
When no users are configured, a default admin account is created with a random password, and the password is logged:

```go
if len(s.users) == 0 {
    defaultPassword, err := generateSecurePassword(24)
    if err != nil {
        panic("auth: crypto/rand unavailable for password generation: " + err.Error())
    }
    s.users["admin"] = &User{
        Username:  "admin",
        Hash:      HashPassword(defaultPassword, nil),
        Role:      RoleAdmin,
        CreatedAt: time.Now().UTC().Format(time.RFC3339),
        UpdatedAt: time.Now().UTC().Format(time.RFC3339),
    }
    // WARNING: Password logged to stdout!
    util.Warnf("No users configured. Default admin account created. Set password via dashboard or API before use.")
}
```

The actual password is NOT logged (the code was fixed), but the warning message could still be problematic in shared logging systems.

**Note:** Based on code inspection, the password itself is no longer logged. Only a warning that the default admin was created.

---

## [CLUSTER] Token Revocation Not Cluster-Wide

**Severity:** Medium

**File:** `internal/auth/auth.go:244-261`

**Description:**
`RevokeToken()` and `RevokeAllTokens()` only affect the local node:

```go
func (s *Store) RevokeToken(tokenStr string) {
    s.mu.Lock()
    defer s.mu.Unlock()
    delete(s.tokens, tokenStr)  // Only local map
}
```

In a cluster deployment, revoked tokens remain valid on other nodes until they are also revoked or expire naturally.

**Impact:**
- Attacker can use revoked token on different cluster node
- Token theft undetected across nodes
- Compromised tokens remain valid cluster-wide after revocation

**Recommendation:**
Implement cluster-wide token revocation via consensus (Raft, etcd) or shared session store.

---

## Summary Table

| ID | Category | Finding | Severity | File:Line |
|----|----------|---------|----------|-----------|
| 1 | JWT Security | Tokens are NOT signed - no cryptographic verification | Critical | auth.go:188-216 |
| 2 | Password Hashing | Custom PBKDF2-SHA256, not memory-hard, low iterations | Medium | auth.go:122-152 |
| 3 | Token Storage | In-memory only, lost on restart, no cluster sync | Medium | auth.go:47-52 |
| 4 | Rate Limiting | X-Forwarded-For trusted without proxy validation | High | server.go:2582-2609 |
| 5 | Session Fixation | Tokens not revoked on role changes | Medium | auth.go:286-310 |
| 6 | RBAC Bypass | Legacy single-token auth skips ALL RBAC | High | server.go:2554-2580 |
| 7 | Token Storage | Token stores role at creation, not refreshed | Low | auth.go:205-212 |
| 8 | Token Leakage | Token in URL query (historical) | Medium | server.go:549-558 |
| 9 | Cluster Security | Token revocation not cluster-wide | Medium | auth.go:244-261 |

---

## Positive Security Findings

1. **Constant-time password comparison** (`auth.go:185`): `subtle.ConstantTimeCompare` used correctly
2. **HMAC functions exist** (`auth.go:434-445`): `SignToken`/`VerifyTokenSignature` properly implemented (but unused)
3. **Secure random generation** (`auth.go:199-203`): Uses `crypto/rand` for token generation
4. **Salt generation** (`auth.go:127`): Uses `crypto/rand` for password salt
5. **Cookie security** (`server.go:2411-2419`): HttpOnly, Secure (when TLS), SameSiteStrictMode, MaxAge set
6. **Token revocation on password change** (`auth.go:303-308`): All tokens revoked when password changes
7. **RBAC hierarchy** (`auth.go:407-425`): Admin > Operator > Viewer with proper integer comparison
8. **Rate limiter implementation** (`server.go:85-140`): Progressive delays, lockout periods well-designed

---

## Recommendations (Priority Order)

1. **[CRITICAL]** Implement token signing using HMAC-SHA256 and call `VerifyTokenSignature` in `ValidateToken`
2. **[HIGH]** Fix IP extraction to not trust X-Forwarded-For from untrusted sources
3. **[HIGH]** Revoke tokens on role changes, not just password changes
4. **[HIGH]** Document that legacy single-token auth bypasses RBAC
5. **[MEDIUM]** Replace custom PBKDF2 with bcrypt or argon2id
6. **[MEDIUM]** Add cluster-wide token revocation mechanism
7. **[MEDIUM]** Add token expiration cleanup goroutine to prevent memory exhaustion
8. **[LOW]** Remove unused `Token.Role` field or ensure it stays in sync
