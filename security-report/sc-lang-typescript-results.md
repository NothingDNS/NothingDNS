# Security Scan Report: NothingDNS React Dashboard (sc-lang-typescript)

**Scan Date:** 2026-04-09  
**Scope:** `web/src/` - React 19 SPA with TypeScript  
**Files Analyzed:**
- `App.tsx`
- `pages/login.tsx`
- `pages/dashboard.tsx`
- `components/layout/sidebar.tsx`
- `hooks/useTheme.tsx`
- `hooks/useWebSocket.ts`
- `lib/api.ts`
- `pages/zone-detail.tsx`

---

## [XSS] No Dangerous innerHTML/dangerouslySetInnerHTML Found

**Severity:** Low  
**File:** N/A  
**Description:** No usage of `innerHTML`, `dangerouslySetInnerHTML`, or equivalent dangerous patterns was found across the scanned codebase. All text content is rendered via React's standard JSX expressions, which automatically escapes values.

**Impact:** XSS via DOM manipulation is not present in the scanned files.  
**Recommendation:** Continue to avoid these patterns. Ensure any future third-party component additions are reviewed.

---

## [AUTH] Token Passed as URL Query Parameter for WebSocket Authentication

**Severity:** Critical  
**File:** `web/src/hooks/useWebSocket.ts:24-26`  
**Description:** The authentication token is appended to the WebSocket URL as a query parameter:

```typescript
const token = document.cookie.match(/ndns_token=([^;]+)/)?.[1];
let url = `${proto}//${location.host}${path}`;
if (token) url += `?token=${encodeURIComponent(token)}`;
```

This transmits the session token in plaintext via the URL, which exposes it to:
- Server-side access logs (referer headers, URL logging)
- Browser history
- Network proxies
- Browser extensions
- Shared hosting environments

**Impact:** Token leakage via URL logging. An attacker with access to server logs, browser history, or network traffic captures can impersonate the authenticated user.

**Recommendation:** Use WebSocket subprotocol authentication or the Sec-WebSocket-Protocol header. Send the token in the WebSocket handshake via a cookie (which is already HTTP-only and SameSite=Strict), or use a secure token exchange mechanism where the server validates credentials and issues a short-lived WS-specific token.

---

## [AUTH] No Token Expiry or Refresh Mechanism

**Severity:** High  
**File:** `web/src/App.tsx:23-26`, `web/src/pages/login.tsx:18`  
**Description:** The token is stored in a cookie with `max-age=86400` (24-hour lifetime) and there is no refresh or renewal mechanism:

```typescript
document.cookie = `ndns_token=${encodeURIComponent(token.trim())}; path=/; max-age=86400; SameSite=Strict`;
```

There is no sliding session expiration. The `/api/v1/status` check only validates existing tokens, but does not refresh or issue new tokens.

**Impact:** Long-lived tokens increase the window of compromise. If a token is stolen, attackers have up to 24 hours of access without detection.

**Recommendation:** Implement token refresh with shorter-lived access tokens (e.g., 15 minutes) and sliding refresh tokens. On each successful API call, the server should return a new token or indicate expiration.

---

## [AUTH] Token Accessible to JavaScript via Document Cookie

**Severity:** High  
**File:** `web/src/App.tsx:24-25`  
**Description:** Although the cookie has `SameSite=Strict`, it does not have the `HttpOnly` flag set. This means JavaScript can read the cookie via `document.cookie`, enabling XSS attacks to exfiltrate the token:

```typescript
const match = document.cookie.match(/ndns_token=([^;]+)/);
```

**Impact:** Any successful XSS injection can steal the session token. The `SameSite=Strict` flag helps mitigate CSRF but does not protect against XSS-based token theft.

**Recommendation:** Set `HttpOnly` on the cookie so it cannot be accessed via JavaScript. For WebSocket authentication, use a separate mechanism such as a WebSocket-specific token returned from the login endpoint that is not marked HttpOnly but has shorter expiry.

---

## [WEBSOCKET] No Authentication Handshake Validation

**Severity:** High  
**File:** `web/src/hooks/useWebSocket.ts:21-28`  
**Description:** The WebSocket connection sends the token as a URL query parameter and the server does not validate it until after the connection is established. If the server rejects the token, the client still connects and only then receives an error, leading to repeated connection attempts with invalid credentials.

```typescript
const ws = new WebSocket(url);
// Server only validates token after connection - no pre-auth check
```

**Impact:** Unauthenticated connection attempts create a potential denial-of-service vector. The client will repeatedly attempt reconnection with invalid credentials.

**Recommendation:** Implement a WebSocket authentication handshake where the server validates the token before the `Connection: Upgrade` is complete. The server should return an HTTP 401 during the WebSocket handshake if the token is invalid, preventing the socket from ever being fully opened with bad credentials.

---

## [WEBSOCKET] Token Query Parameter Persists in Browser History

**Severity:** Medium  
**File:** `web/src/hooks/useWebSocket.ts:24-26`  
**Description:** Because the token is in the URL (`?token=...`), it is stored in browser history, bookmarks, and can be shared accidentally:

```typescript
if (token) url += `?token=${encodeURIComponent(token)}`;
```

**Impact:** Any user who bookmarks the page, shares URLs, or has browser history compromised exposes their session token.

**Recommendation:** Never put authentication tokens in URLs. Use cookie-based or header-based authentication for WebSocket connections.

---

## [INPUT] Unvalidated Zone Name in Route Parameter

**Severity:** Medium  
**File:** `web/src/pages/zone-detail.tsx:13`  
**Description:** The zone name from URL parameters is decoded and used directly in API calls without validation:

```typescript
const zn = decodeURIComponent(name || '');
// ... then used in API call:
api<ZoneDetail>('GET', `/api/v1/zones/${encodeURIComponent(zn)}`),
```

**Impact:** While the value is re-encoded before being sent to the API, the initial decode of potentially malicious input could be a concern if there is any downstream processing that interprets the decoded value differently than expected.

**Recommendation:** Validate the zone name format before processing. Use a strict allowlist pattern (e.g., `/^[a-zA-Z0-9.-]+$/`) to ensure the decoded value matches expected DNS zone name syntax.

---

## [URL] External Link Download via window.location.href

**Severity:** Medium  
**File:** `web/src/pages/zone-detail.tsx:100`  
**Description:** A download action sets `window.location.href` to an API endpoint:

```typescript
window.location.href = `/api/v1/zones/${encodeURIComponent(zn)}/export`;
```

**Impact:** This navigates away from the SPA and exposes the URL in browser history. If the export endpoint requires the same token (via cookie), this is a minor issue. However, if the URL is constructed with user-controlled data without proper encoding, it could be leveraged in open redirect scenarios.

**Recommendation:** Use a fetch-based download with a blob URL or use the `<a download>` pattern with a properly constructed blob. This keeps the user in the SPA and avoids URL exposure in history.

---

## [AUTH] Login Token Input Not Rate Limited Client-Side

**Severity:** Low  
**File:** `web/src/pages/login.tsx:12-21`  
**Description:** The login form submission does not implement client-side rate limiting or captcha. The `handleSubmit` function:

```typescript
const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token.trim()) return;
    setLoading(true); setError('');
    try {
      const r = await fetch('/api/v1/status', { headers: { Authorization: `Bearer ${token.trim()}` } });
```

**Impact:** The server should implement rate limiting on `/api/v1/status`, but if it does not, the application is vulnerable to brute-force token guessing.

**Recommendation:** Implement exponential backoff with a maximum retry count on the client side. Display a countdown timer before allowing retry attempts after failed logins.

---

## [REACT19] Hydration Compatibility Review

**Severity:** Low  
**File:** `web/src/hooks/useTheme.tsx`  
**Description:** The `useTheme` hook uses `localStorage` for theme persistence with a `'system'` fallback. This is compatible with React 19's improved hydration, but the initial render may flash with the wrong theme if localStorage is slow:

```typescript
const [theme, setThemeRaw] = useState<Theme>(() => (localStorage.getItem('ndns-theme') as Theme) || 'system');
```

**Impact:** Theme flash on initial load is a UX issue, not a security issue. React 19 handles this better than previous versions.

**Recommendation:** No changes needed for security. Consider adding a blocking script in `index.html` to set the theme before React hydrates to prevent flash.

---

## [CONFIG] No CSP Header Configuration Found

**Severity:** Medium  
**File:** `web/src/` (infrastructure-level)  
**Description:** No Content Security Policy (CSP) header configuration was found in the scanned source files. React 19 applications should be served with a strict CSP to mitigate XSS risks.

**Impact:** Without a CSP, inline scripts and event handlers could be exploited if XSS is introduced via any future vulnerability.

**Recommendation:** Configure a strict CSP header on the server serving the React SPA. Example:
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; frame-ancestors 'none';
```

---

## Summary

| Severity | Count | Findings |
|----------|-------|----------|
| Critical | 1 | Token exposed in WebSocket URL query parameter |
| High | 4 | No HttpOnly on cookie, no token refresh, no WS auth handshake, no WS auth validation |
| Medium | 3 | URL history exposure, unvalidated zone name, missing CSP |
| Low | 3 | No XSS found, login rate limiting, React 19 compatibility |

**Most Critical Fix:** The token should never be transmitted via URL query parameters. Move WebSocket authentication to use cookies exclusively, and ensure the cookie has `HttpOnly` set. Implement proper WebSocket handshake authentication so invalid tokens are rejected before the connection is established.
