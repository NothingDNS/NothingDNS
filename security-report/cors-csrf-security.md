# CORS and CSRF Security Assessment - NothingDNS

**Repository:** D:\Codebox\PROJECTS\NothingDNS
**Date:** 2026-04-09
**Assessor:** Security Code Review
**Confidence:** High

---

## Executive Summary

The NothingDNS API server contains **critical CORS misconfiguration vulnerabilities** that expose the entire administrative API to cross-origin attacks. The combination of wildcard CORS origin, lack of CSRF protection, and token authentication via URL parameters creates a severe attack surface.

---

## Findings Summary

| Severity | Count | CWEs |
|----------|-------|------|
| Critical | 2 | CWE-942, CWE-346 |
| High | 2 | CWE-352, CWE-598 |
| Medium | 1 | CWE-346 |

---

## Finding 1: CORS Wildcard Origin Permits All Cross-Origin Access

**CWE ID:** [CWE-942](https://cwe.mitre.org/data/definitions/942.html) - Permissive Cross-Domain Whitelist

**File:** `internal/api/server.go:272`

**Description:**
The CORS middleware sets `Access-Control-Allow-Origin: *` which permits any website to make cross-origin requests to the API server. This allows attackers to:
- Exfiltrate sensitive DNS configuration data
- Trigger zone management operations (create/delete zones, add/delete records)
- Flush cache and reload configuration
- Access authentication tokens stored in cookies

```go
// Line 269-283
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*")  // <-- VULNERABLE
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
        // ...
    })
}
```

**Affected Endpoints (partial list):**
- `GET/POST/PUT/DELETE /api/v1/zones/*` - Zone management
- `POST /api/v1/cache/flush` - Cache flush
- `POST /api/v1/config/reload` - Configuration reload
- `POST /api/v1/blocklists/toggle` - Blocklist toggle
- `POST /api/v1/rpz/toggle` - RPZ toggle
- `GET/POST/PUT/DELETE /api/v1/acl` - ACL management
- `POST /api/v1/auth/login` - Authentication
- `GET /api/v1/server/config` - Server configuration exposure

**Impact:**
An attacker can host a malicious webpage that, when visited by an authenticated administrator, will silently perform administrative actions against the NothingDNS API.

**Remediation:**
Replace wildcard origin with explicit whitelist validation:

```go
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        origin := r.Header.Get("Origin")
        allowedOrigins := s.config.AllowedOrigins  // Configure explicit origins

        if origin != "" && isOriginAllowed(origin, allowedOrigins) {
            w.Header().Set("Access-Control-Allow-Origin", origin)
            w.Header().Set("Vary", "Origin")
        }

        // Only set methods/headers if origin is allowed
        if isOriginAllowed(origin, allowedOrigins) {
            w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
        }

        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusOK)
            return
        }

        next.ServeHTTP(w, r)
    })
}

func isOriginAllowed(origin string, allowed []string) bool {
    for _, o := range allowed {
        if o == origin {
            return true
        }
    }
    return false
}
```

**Severity:** Critical
**Confidence:** High
**CVSS 3.1 Vector:** AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H (8.3 High)

---

## Finding 2: No CSRF Protection on State-Changing Operations

**CWE ID:** [CWE-352](https://cwe.mitre.org/data/definitions/352.html) - Cross-Site Request Forgery

**File:** `internal/api/server.go:286-354` (authMiddleware)

**Description:**
The API provides no CSRF protection mechanisms. The `authMiddleware` validates tokens but does not verify:
- CSRF tokens in request headers or bodies
- Custom request headers that cannot be set by cross-origin HTML forms
- `Origin` or `Sec-Fetch-Site` headers for same-site request verification

This allows cross-origin attacks even if CORS were properly configured.

**Vulnerable Handlers (all state-changing operations):**
- `POST /api/v1/auth/login` - Authentication
- `POST /api/v1/auth/logout` - Logout
- `POST /api/v1/zones` - Create zone
- `DELETE /api/v1/zones/{name}` - Delete zone
- `POST /api/v1/zones/{name}/records` - Add record
- `PUT /api/v1/zones/{name}/records` - Update record
- `DELETE /api/v1/zones/{name}/records` - Delete record
- `POST /api/v1/zones/reload?zone=` - Reload zone
- `POST /api/v1/cache/flush` - Flush cache
- `POST /api/v1/config/reload` - Reload config
- `POST /api/v1/blocklists/toggle` - Toggle blocklist
- `DELETE /api/v1/blocklists/{filepath}` - Remove blocklist
- `POST /api/v1/rpz/toggle` - Toggle RPZ
- `POST /api/v1/rpz/rules` - Add RPZ rule
- `DELETE /api/v1/rpz/rules?pattern=` - Delete RPZ rule
- `PUT /api/v1/acl` - Update ACL rules
- `PUT /api/v1/upstreams` - Update upstreams
- `POST /api/v1/auth/users` - Create user
- `DELETE /api/v1/auth/users?username=` - Delete user

**Impact:**
An authenticated administrator visiting a malicious website may unknowingly trigger state-changing operations. The attack is silent and does not require the attacker to know the authentication token.

**Remediation:**
Implement CSRF protection using one or more of the following:

1. **Double-Submit Cookie Pattern:**
```go
func csrfMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
            cookie, err := r.Cookie("csrf_token")
            if err != nil {
                http.Error(w, "CSRF token missing", http.StatusForbidden)
                return
            }
            header := r.Header.Get("X-CSRF-Token")
            if header == "" || header != cookie.Value {
                http.Error(w, "CSRF token mismatch", http.StatusForbidden)
                return
            }
        }
        next.ServeHTTP(w, r)
    })
}
```

2. **SameSite Cookies:**
Ensure authentication cookies use `SameSite=Strict` or `SameSite=Lax` (already set to `SameSiteStrictMode` in `handleLogin` at line 2103, but token can still be sent via Authorization header).

3. **Custom Header Verification:**
Require a custom header like `X-Requested-With` or `X-CSRF-Token` that cannot be sent by cross-origin HTML forms.

**Severity:** High
**Confidence:** High
**CVSS 3.1 Vector:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N (7.5 High)

---

## Finding 3: Authentication Token Leakage via URL Query Parameter

**CWE ID:** [CWE-598](https://cwe.mitre.org/data/definitions/598.html) - Information Exposure Through Query Strings

**File:** `internal/api/server.go:312-315`

**Description:**
The authentication middleware accepts tokens via URL query parameter (`?token=<token>`):

```go
// Fallback: query parameter
if token == "" {
    token = r.URL.Query().Get("token")
}
```

This exposes tokens in:
- Browser history
- Server access logs
- Referer headers sent to third-party sites
- Browser bookmarks (if shared)
- WebCache (if not disabled)

**Impact:**
An attacker who tricks a user into visiting a page with a token in the URL (e.g., `https://dns.example.com/api/v1/config/reload?token=secret`) can capture the token from the Referer header or log files.

**Remediation:**
Remove token-from-query support entirely. Tokens should only be accepted via:
- `Authorization: Bearer <token>` header
- `ndns_token` HttpOnly cookie (already implemented)

**Severity:** High
**Confidence:** High

---

## Finding 4: Missing Origin Validation in Preflight Requests

**CWE ID:** [CWE-346](https://cwe.mitre.org/data/definitions/346.html) - Origin Confusion

**File:** `internal/api/server.go:276-279`

**Description:**
The CORS middleware handles preflight (OPTIONS) requests without validating the Origin header:

```go
if r.Method == "OPTIONS" {
    w.WriteHeader(http.StatusOK)  // Always returns OK
    return
}
```

This allows any origin to send a preflight request and receive the CORS headers, even if the actual request would not be allowed. This can leak information about the API structure.

**Impact:**
An attacker can probe the API structure by sending preflight requests with different origins to determine:
- Which endpoints exist
- Which HTTP methods are supported
- The presence of authentication requirements

**Remediation:**
Validate Origin in OPTIONS handler:

```go
if r.Method == "OPTIONS" {
    origin := r.Header.Get("Origin")
    if !isOriginAllowed(origin, s.config.AllowedOrigins) {
        http.Error(w, "Origin not allowed", http.StatusForbidden)
        return
    }
    w.WriteHeader(http.StatusOK)
    return
}
```

**Severity:** Medium
**Confidence:** High

---

## Finding 5: WebSocket Endpoint Lacks Origin Validation

**CWE ID:** [CWE-346](https://cwe.mitre.org/data/definitions/346.html) - Origin Confusion

**File:** `internal/api/server.go:231` (maps to dashboard server)

**Description:**
The WebSocket endpoint (`/ws`) is registered without additional origin checking:

```go
mux.HandleFunc("/ws", s.dashboardServer.ServeHTTP)
```

The dashboard server's `handleWebSocket` at `internal/dashboard/server.go:222-237` performs a WebSocket handshake without validating the Origin header against an allowlist.

**Impact:**
An attacker can establish WebSocket connections to the dashboard server, potentially:
- Receiving live DNS query streaming data (including client IPs, queried domains)
- Connection-based information disclosure

**Remediation:**
Validate Origin in WebSocket handshake:

```go
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
    origin := r.Header.Get("Origin")
    if !isOriginAllowed(origin, allowedOrigins) {
        http.Error(w, "Origin not allowed", http.StatusForbidden)
        return
    }
    conn, err := websocket.Handshake(w, r)
    // ...
}
```

**Severity:** Medium
**Confidence:** High

---

## Additional Observations

### Positive Security Practices Found

1. **SameSite Cookie Flag:** The authentication cookie correctly uses `SameSite: http.SameSiteStrictMode` (line 2103).

2. **HttpOnly Cookie Flag:** The authentication cookie is marked `HttpOnly: true`, preventing JavaScript access.

3. **Secure Cookie Flag:** The cookie correctly sets `Secure: true` when served over TLS.

4. **Constant-Time Token Comparison:** Uses `subtle.ConstantTimeCompare` for token validation (line 327).

5. **POST-Only for Sensitive Operations:** Most state-changing handlers properly enforce POST-only (zone reload, cache flush, config reload, toggles).

### Security Concerns in Authentication Flow

The combination of:
- Wildcard CORS
- No CSRF tokens
- Token-in-URL support

Creates a situation where even properly protected cookies can be bypassed via cross-origin requests.

---

## Remediation Priority

| Priority | Finding | Effort |
|----------|---------|--------|
| P0 - Critical | CORS Wildcard Origin (Finding 1) | Medium |
| P0 - Critical | CSRF Protection (Finding 2) | Medium |
| P1 - High | Token in URL Query (Finding 3) | Low |
| P2 - Medium | Preflight Origin Validation (Finding 4) | Low |
| P2 - Medium | WebSocket Origin Validation (Finding 5) | Low |

---

## References

- [OWASP CORS Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [MDN CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [CWE-942: Permissive Cross-Domain Whitelist](https://cwe.mitre.org/data/definitions/942.html)
- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [CWE-346: Origin Confusion](https://cwe.mitre.org/data/definitions/346.html)
- [CWE-598: Information Exposure Through Query Strings](https://cwe.mitre.org/data/definitions/598.html)

---

*Report generated by security code review. All findings should be verified in context of deployment environment.*
