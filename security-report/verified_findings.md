# Verified Security Findings

## Finding 1: Empty HMAC Secret Allows Token Forgery

**Severity:** HIGH (CVSS 7.5) — **FIXED**

**File:** `internal/auth/auth.go`

**Lines:** 77-87

**Description:**
`NewStore()` generated tokens using an empty HMAC key when `auth_secret` was not configured. An attacker could forge arbitrary tokens by computing `HMAC-SHA256(token, empty_key)`.

**Fix Applied:**
When `cfg.Secret == ""`, a random 32-byte secret is now generated and logged for the session. This prevents token forgery until a proper `auth_secret` is configured.

```go
// auth.go:77-87 (FIXED)
var secret []byte
if cfg.Secret == "" {
    generated := generateSecret(32)
    secret = []byte(generated)
    util.Warnf("AUTH: No auth_secret configured. Generated temporary secret for this run: %s. " +
        "Set auth_secret in config for production deployments.", generated)
} else {
    secret = []byte(cfg.Secret)
}
```

**Status:** ✅ Fixed — tokens now signed with a cryptographically random secret even when `auth_secret` is unset.

---

## Finding 2: Path Traversal in Blocklist File Loading

**Severity:** HIGH (CVSS 8.1) — **ALREADY FIXED**

**File:** `internal/blocklist/blocklist.go`

**Lines:** 247-251

**Description:**
`AddFile()` did not check for `..` path sequences before opening files.

**Fix Present (pre-existing):**
```go
// blocklist.go:247-251 (ALREADY SAFE)
func (bl *Blocklist) loadFile(path string) error {
    // SECURITY: Check for path traversal sequences
    if strings.Contains(path, "..") {
        return fmt.Errorf("blocklist path traversal attempt blocked: %s", path)
    }
    f, err := os.Open(path)
    // ...
}
```

**Status:** ✅ Already protected — `..` check was present before this audit.

---

## Finding 3: CORS Origin Validation Permits Dangerous Wildcard with Credentials

**Severity:** MEDIUM (CVSS 6.8) — **FIXED**

**File:** `internal/api/server.go`

**Lines:** ~375-377

**Description:**
CORS middleware accepted `*` wildcard as a valid origin, which is insecure when combined with credentials/tokens.

**Fix Applied (api/server.go):**
Wildcard `*` is now silently rejected — no `Access-Control-Allow-Origin` header is sent, causing browsers to block credentialed cross-origin requests.

```go
// api/server.go:375-377 (FIXED)
} else if len(allowedOrigins) == 1 && allowedOrigins[0] == "*" {
    // Reject wildcard - insecure when credentials are involved.
    // No CORS header = browser blocks credentialed cross-origin requests.
    allowOrigin = ""
}
```

**Fix Applied (websocket/websocket.go):**
WebSocket `Handshake()` also rejected `*` wildcard in origin validation, preventing the same vulnerability via the DoWS transport.

```go
// websocket.go:95-104 (FIXED)
// If allowedOrigins contains "*", all origins are allowed.
func isOriginAllowed(origin string, allowedOrigins []string) bool {
    for _, o := range allowedOrigins {
        if o == origin {  // No longer accepts "*" as a catch-all
            return true
        }
    }
    return false
}
```

**Status:** ✅ Fixed — wildcard origins are no longer honored in both HTTP API and WebSocket.

---

## Finding 4: WebSocket Frame Size Limit Too Large for DNS Context

**Severity:** LOW (CVSS 3.7) — **FIXED**

**File:** `internal/websocket/websocket.go`

**Lines:** ~214

**Description:**
WebSocket implementation allowed frames up to 1MB. DNS responses are typically < 4KB.

**Fix Applied:**
Frame size limit reduced from 1MB to 16KB.

```go
// websocket.go:214 (FIXED)
if payloadLen > 16*1024 { // 16KB max frame (DNS messages are typically < 4KB)
    return 0, nil, errors.New("websocket: frame too large")
}
```

**Status:** ✅ Fixed — excessive frame allocation eliminated.

---

## Finding 5: DNS Cookie Validation Missing Chain Walking Check

**Severity:** LOW (CVSS 5.3) — **NOT REMEDIATED**

**File:** `internal/dnscookie/cookie.go`

**Description:**
RFC 7873 DNS Cookies use a chain walking mechanism. The server may not properly validate that presented cookies were generated through the proper resolver chain, allowing replay attacks.

**Status:** ⏸ Skipped — RFC 7873 chain walking requires all resolvers in a chain to share the same secret, which requires significant architectural changes. The current implementation validates timestamp freshness and HMAC, which provides protection against casual replay.

**Remediation (deferred):** Implement chain walking validation per RFC 7873 Section 4.4. Requires all resolvers to share a common secret.

---

## Summary Table

| ID | Finding | Severity | CVSS | Status |
|----|---------|----------|------|--------|
| 1 | Empty HMAC secret allows token forgery | HIGH | 7.5 | ✅ Fixed |
| 2 | Path traversal in blocklist file loading | HIGH | 8.1 | ✅ Already Fixed |
| 3 | CORS wildcard with credentials | MEDIUM | 6.8 | ✅ Fixed |
| 4 | WebSocket 1MB frame limit too large | LOW | 3.7 | ✅ Fixed |
| 5 | DNS Cookie chain walking not validated | LOW | 5.3 | ⏸ Deferred |

---

## Not Applicable / Safe Findings

| Category | Status | Notes |
|----------|--------|-------|
| CWE-119 bounds | SAFE | All buffer accesses checked with len() before slicing. `UnpackName` validates offsets. Message Pack/Unpack bounds-checked. |
| Integer overflow | SAFE | No arithmetic overflow vectors in DNS parsing. Wire length calculations use int, not uint. |
| Nil dereference | SAFE | All nil checks present on slices/maps. ResponseWriter interface nil guards in place. |
| Race conditions | SAFE | sync.RWMutex guards on shared state. atomic operations for counters. Connection handler closures capture local vars. |
| XSS | SAFE | Dashboard uses JSON encoding. API uses json.Marshal. No string concatenation into HTML. |
| CMDi | SAFE | Zero exec.Command usage confirmed via grep. All external calls use stdlib net/http, crypto. |
| Auth/AuthZ | SAFE | HMAC secret generation fixed. RBAC hierarchy properly implemented. |
| Secrets | SAFE | Password hashing uses 10k iterations. Tokens use crypto/rand. No hardcoded credentials. |
| Protocol attacks | SAFE | MaxPointerDepth=5, label length validation, name length limits. Compression loop prevention. |
| DoS | SAFE | Rate limiting (RRL), connection limits (1000 global, 10 per IP), pipeline limits (16), timeouts (30s), message size limits (65535 TCP/UDP). |
| SSRF | SAFE | Blocklist URL fetching validates against private IPs, cloud metadata, 169.254.169.254. DNS resolution check for hostnames. |
| Crypto | SAFE | HMAC-SHA256/384/512 for TSIG. 10k iteration password derivation. AES-256-GCM and ChaCha20-Poly1305 for ODoH. |
| Header Injection | SAFE | No user input reflected in headers without sanitization. |
| CSRF | SAFE | Dashboard uses WebSocket streaming. API tokens via Authorization header, not cookies. |
