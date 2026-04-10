# NothingDNS Security Scan Report
## CORS, CSRF, and WebSocket Vulnerability Assessment

**Scan Date:** 2026-04-09
**Files Analyzed:**
- `internal/api/server.go` — CORS middleware (lines 472-514), Auth middleware (lines 526-607)
- `internal/dashboard/server.go` — WebSocket server
- `internal/websocket/websocket.go` — WebSocket handshake and frame handling
- `internal/doh/handler.go` — DoH/DoWS handlers

---

## [CORS] Wildcard Origin Default When No Origins Configured

**Severity:** Medium

**File:** `internal/api/server.go:482-495`

**Description:**
When `allowed_origins` is empty (the backward-compatible default), the CORS middleware sets `allowOrigin = "*"` without any check for credentials. The code explicitly handles the case where `allowed_origins` contains "*" by rejecting it (lines 486-489), but when the config is empty, it falls through to wildcard.

```go
if len(allowedOrigins) == 0 {
    // Default: allow all when no explicit origins configured
    allowOrigin = "*"
} else if len(allowedOrigins) == 1 && allowedOrigins[0] == "*" {
    // Reject wildcard - insecure when credentials are involved.
    allowOrigin = ""
}
```

**Impact:**
If cookies or Authorization headers are later added as a fallback authentication mechanism, the wildcard CORS policy would allow any origin to make credentialed requests. Currently, the API uses Bearer token auth via headers, so the practical risk is mitigated but the CORS configuration is misleading.

**Recommendation:**
When `allowed_origins` is empty and the server has authentication enabled, consider setting `allowOrigin = ""` to reject cross-origin requests rather than allowing all. Document clearly that empty `allowed_origins` means "no CORS" rather than "allow all."

---

## [CORS] Missing Vary:Origin Header for Dynamic Origin Selection

**Severity:** Low

**File:** `internal/api/server.go:494-497`

**Description:**
The CORS middleware sets `Vary: Origin` only when `allowOrigin != ""` (line 496). When the origin list is empty and `allowOrigin` is set to "*", the Vary header is still set correctly. However, when origin validation fails silently (origin present but not in allowlist), no Vary header is sent.

**Impact:**
Caching proxies may incorrectly cache responses that vary based on origin, potentially leaking content to other origins.

**Recommendation:**
Move `Vary: Origin` outside the conditional so it is always set when Origin header is present.

---

## [CORS] No Access-Control-Allow-Credentials Header

**Severity:** Info

**File:** `internal/api/server.go:472-514`

**Description:**
The CORS middleware never sets `Access-Control-Allow-Credentials: true`. This is actually correct behavior given the current authentication design (Bearer tokens in Authorization header, not cookies), but it means cookie-based auth cannot work with cross-origin requests.

**Impact:**
None for current design. Cookies are only used as fallback (line 555) when Authorization header is missing, and SameSiteStrictMode is set on login cookies (line 2417).

**Recommendation:**
None required for current design. Document that cross-origin API access requires the Authorization header.

---

## [CSRF] No CSRF Protection on Logout Endpoint

**Severity:** High

**File:** `internal/api/server.go:2429-2453`

**Description:**
The `/api/v1/auth/logout` handler processes POST requests without any CSRF token validation. While the cookie has `SameSite: StrictMode` which mitigates CSRF for same-site attackers, a CSRF vulnerability on logout could be exploited in conjunction with sub-domain compromises.

```go
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
        return
    }
    // ... proceeds without CSRF token check
}
```

**Impact:**
An attacker could force authenticated users to logout by tricking them into visiting a malicious page that submits a POST to the logout endpoint.

**Recommendation:**
Add CSRF token validation to state-changing endpoints (POST/PUT/DELETE). Use the `Double Submit Cookie` pattern: generate a random CSRF token on login, set it as an `HttpOnly` cookie and require it in a custom header (e.g., `X-CSRF-Token`).

---

## [CSRF] No CSRF Tokens on API State-Changing Endpoints

**Severity:** Medium

**File:** `internal/api/server.go` (general)

**Description:**
All API endpoints that modify state (POST/PUT/DELETE) lack CSRF token validation. While `SameSite: StrictMode` cookies provide protection against cross-site CSRF attacks, this protection is bypassed when:
1. The attacker can issue a GET request that reads the CSRF token
2. Sub-domain takeover allows setting cookies on the parent domain
3. HTTP(S) mixed content issues

**Impact:**
If cookies are used for authentication (they are, as fallback per line 555), CSRF attacks could force users to perform unintended actions like configuration changes or zone updates.

**Recommendation:**
Implement CSRF tokens for all state-changing operations. Consider using the `SameSite: StrictMode` cookie attribute as a defense-in-depth measure (already in place) and add explicit CSRF tokens for high-privilege operations.

---

## [WEBSOCKET] No Authentication During WebSocket Handshake

**Severity:** Critical

**File:** `internal/dashboard/server.go:233-249`

**Description:**
The `/ws` WebSocket endpoint performs origin validation but does NOT validate authentication. The `authMiddleware` in `internal/api/server.go` is not applied to WebSocket handlers because WebSocket upgrades are handled separately via `websocket.Handshake()`.

```go
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
    conn, err := websocket.Handshake(w, r, s.allowedOrigins...)  // No auth check!
    if err != nil {
        util.Warnf("dashboard: websocket handshake failed: %v", err)
        return
    }
    // ... proceeds to accept connection without authentication
}
```

**Impact:**
Any user visiting the dashboard SPA will have their browser automatically include the `ndns_token` cookie (since SameSite is not set to None, cross-site cookies won't be sent, but same-site requests will). An attacker who can trick a victim into visiting a same-origin page (or if the attacker has XSS) could establish an authenticated WebSocket connection and stream DNS query data.

**Recommendation:**
1. Pass the authentication token via WebSocket URL query parameter or header during handshake
2. Validate the token in `handleWebSocket()` before accepting the connection
3. Alternatively, implement WebSocket-specific authentication (e.g., token in the Sec-WebSocket-Protocol header)

---

## [WEBSOCKET] No Read Deadline Prevents DoS Detection

**Severity:** High

**File:** `internal/dashboard/server.go:374-380`

**Description:**
The `ClientLoop` function sets a write deadline before writing messages (line 362) but never sets a read deadline. If a client connects and stops reading or sends data very slowly, the connection will never time out.

```go
// Read loop - no deadline set!
for {
    _, _, err := client.conn.ReadMessage()
    if err != nil {
        return
    }
}
```

**Impact:**
A malicious client could establish many WebSocket connections and hold them open indefinitely without sending data, consuming server resources and exhausting the `MaxWebSocketClients` limit (1000). This enables a slow-layer DoS attack.

**Recommendation:**
Set a read deadline when accepting the connection:
```go
if err := client.conn.SetReadDeadline(time.Now().Add(60*time.Second)); err != nil {
    return
}
```

---

## [WEBSOCKET] No Maximum Message Size Limit on Read

**Severity:** Medium

**File:** `internal/websocket/websocket.go:214`

**Description:**
While the frame parsing code checks if `payloadLen > 16*1024` (line 214), this check occurs AFTER allocating the payload buffer. A client could send a frame with `payloadLen = 16*1024` continuously and flood the server's memory through the send channel (256 deep).

```go
if payloadLen > 16*1024 { // 16KB max frame
    return 0, nil, errors.New("websocket: frame too large")
}
payload = make([]byte, payloadLen)
```

**Impact:**
The send channel is bounded to 256 messages (line 243). With 16KB per message, each client could buffer up to 4MB. With 1000 concurrent clients, this could be 4GB.

**Recommendation:**
1. Add a total connection memory limit per client
2. Add idle timeout that closes connections not sending messages for N seconds
3. Monitor the send channel buffer fullness as an early DoS indicator

---

## [WEBSOCKET] No Origin Validation for Empty AllowedOrigins

**Severity:** Medium

**File:** `internal/websocket/websocket.go:39-46`

**Description:**
When `allowedOrigins` is empty (passed from dashboard server), the WebSocket handshake skips origin validation entirely:

```go
// Validate Origin if allowedOrigins is specified
if len(allowedOrigins) > 0 {
    origin := r.Header.Get("Origin")
    if origin != "" && !isOriginAllowed(origin, allowedOrigins) {
        http.Error(w, "origin not allowed", http.StatusForbidden)
        return nil, errors.New("websocket: origin not allowed")
    }
}
```

**Impact:**
Any website can establish a WebSocket connection to the dashboard if `allowedOrigins` is not configured. Combined with the lack of authentication during handshake, this allows unrestricted WebSocket access.

**Recommendation:**
Treat empty `allowedOrigins` as "no origins allowed" rather than "all origins allowed." Require explicit origin configuration for WebSocket connections.

---

## [API] Token Exposure in URL Query Parameter

**Severity:** Medium

**File:** `internal/api/server.go:554-558`

**Description:**
The auth middleware falls back to reading the token from a cookie (`ndns_token`), but if the token is ever passed via URL query parameter (e.g., `/api/v1/config?token=xxx`), it will be logged in server access logs, browser history, and potentially referrer headers.

```go
// Fallback: cookie
if token == "" {
    if c, err := r.Cookie("ndns_token"); err == nil {
        token = c.Value
    }
}
```

**Impact:**
Token leakage through logs or browser history could allow unauthorized access.

**Recommendation:**
1. Never accept tokens via URL query parameters
2. Ensure all API endpoints require `Authorization: Bearer <token>` header
3. If URL tokens are needed for specific use cases, use short-lived, scoped tokens

---

## [API] Rate Limiting Applied After Authentication Check

**Severity:** Low

**File:** `internal/api/server.go:564-572`

**Description:**
The rate limiting check occurs AFTER successful authentication validation. An attacker could send many slow authentication attempts to exhaust server resources before the rate limit kicks in.

```go
if s.config.AuthToken != "" && len(token) == len(s.config.AuthToken) && subtle.ConstantTimeCompare([]byte(token), []byte(s.config.AuthToken)) == 1 {
    // Check API rate limit for authenticated requests
    ip := getClientIP(r)
    if s.apiRateLimiter.checkRateLimit(ip) {
```

**Impact:**
Slow authentication attempts (using long tokens that don't match) could consume CPU resources without triggering rate limits.

**Recommendation:**
Apply rate limiting before expensive operations like constant-time comparisons. Consider rate limiting based on IP before token validation.

---

## [DOH] No CORS Headers on DoH Endpoints

**Severity:** Low

**File:** `internal/doh/handler.go:34-80`

**Description:**
The DoH handler does not set any CORS headers. While browsers enforce same-origin policy for DoH requests (since the origin is the server itself), this means legitimate cross-origin use cases (e.g., browser extensions) cannot work.

**Impact:**
No security impact for standard browser-based DoH usage. Browser extensions and cross-platform DoH clients may be blocked.

**Recommendation:**
If cross-origin DoH access is needed, add appropriate CORS headers with restrictive origin validation.

---

## [DOH] MaxBytesReader on POST Body Correctly Configured

**Severity:** Info

**File:** `internal/doh/handler.go:230-233`

**Description:**
The DoH handler correctly uses `http.MaxBytesReader` to limit request body size to `MaxDNSMessageSize` (65535 bytes), preventing oversized DNS messages.

**Impact:**
None — this is correct security behavior.

---

## Summary

| Category | Finding | Severity |
|----------|---------|----------|
| WebSocket | No authentication during handshake | **Critical** |
| WebSocket | No read deadline for DoS prevention | **High** |
| CSRF | No CSRF protection on logout endpoint | **High** |
| WebSocket | No origin validation when allowedOrigins empty | **Medium** |
| WebSocket | Message size could cause memory exhaustion | **Medium** |
| CSRF | No CSRF tokens on state-changing endpoints | **Medium** |
| API | Token fallback to cookie without CSRF | **Medium** |
| API | Rate limiting after auth check | **Low** |
| CORS | Wildcard origin when config empty | **Medium** |
| CORS | Missing Vary:Origin on some paths | **Low** |
| DoH | No CORS headers (info only) | **Low** |

## Key Recommendations (Priority Order)

1. **Add authentication to WebSocket handshake** — This is the most critical issue
2. **Add read deadline to WebSocket connections** — Prevents slow-client DoS
3. **Add CSRF tokens to logout and other POST/PUT/DELETE endpoints**
4. **Treat empty allowedOrigins as "reject all" for WebSocket** — Not "allow all"
5. **Consider requiring explicit CORS configuration** for API server when auth is enabled
