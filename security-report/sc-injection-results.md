# NothingDNS Injection Vulnerability Security Report

**Date:** 2026-04-09
**Scanner:** Claude Code Security Scan
**Files Scanned:**
- `internal/api/server.go`
- `internal/config/parser.go`
- `internal/zone/zone.go`
- `internal/blocklist/blocklist.go`
- `cmd/dnsctl/import.go`

---

## [HEADER INJECTION] Content-Disposition Filename Not Sanitized

**Severity:** Medium
**File:** `internal/api/server.go:1276`
**Description:** The `Content-Disposition` header at line 1276 uses `zoneName` directly in a format string without sanitization. A malicious zone name containing CRLF (`\r\n`) characters could inject headers.

**Impact:** An attacker with ability to create zone names could inject arbitrary HTTP headers via `Content-Disposition: attachment; filename=malicious.zone\r\nX-Injected: header`.

**Recommendation:**
```go
// Sanitize filename to prevent header injection
safeName := strings.Map(func(r rune) rune {
    if r == '\r' || r == '\n' || r == '"' {
        return -1
    }
    return r
}, strings.TrimSuffix(zoneName, "."))
w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.zone", safeName))
```

**Status:** Finding

---

## [HEADER INJECTION] X-Forwarded-For Spoofing in API Rate Limiting

**Severity:** Medium
**File:** `internal/api/server.go:2584-2592`
**Description:** The `getClientIP()` function trusts `X-Forwarded-For` and `X-Real-IP` headers without validation. While it attempts to parse the IP, an attacker behind a trusted proxy could spoof their apparent IP by setting these headers. The rate limiter uses this IP, potentially allowing attackers to exhaust other users' rate limit budgets.

**Impact:** IP-based rate limiting bypass. An attacker behind a trusted proxy (or if the proxy does not properly sanitize these headers) could appear as any IP, poisoning rate limit tracking for other users.

**Recommendation:** If the server is not behind a trusted proxy that sanitizes these headers, only use `r.RemoteAddr` for rate limiting. Consider adding a configuration option to control this behavior.

**Status:** Finding

---

## [HEADER INJECTION] Blocklist URL Reflected in Comment Storage

**Severity:** Low
**File:** `internal/blocklist/blocklist.go:218`
**Description:** When loading blocklists from URLs, the URL is stored as part of the entry comment without sanitization: `Comment: "url:" + url`. If the URL contains special characters, they are stored as-is.

**Impact:** Low - Comment field is not rendered in a way that enables header injection. Stored URLs could potentially be displayed in admin dashboards without proper HTML escaping.

**Recommendation:** Validate/sanitize URLs when stored in comments. Consider URL-escaping or encoding special characters.

**Status:** Finding

---

## [YAML PARSING] Parser Uses Custom Implementation - No Known Code Execution

**Severity:** Low (by design)
**File:** `internal/config/parser.go`
**Description:** The custom YAML parser does not use `os/exec` or any code execution mechanisms. It is a pure tokenizer-to-AST parser that builds an AST tree without evaluating arbitrary code.

**Impact:** By design, the custom parser cannot execute code. However, it is not as robust as a standard library parser and may have edge cases.

**Recommendation:** Document the parser's limitations and ensure it is not used for untrusted input that could contain YAML anchors/aliases (which the parser does not support).

**Status:** Not a vulnerability - by design

---

## [ZONE FILE INJECTION] $INCLUDE Path Traversal Protection Present

**Severity:** Low (protected)
**File:** `internal/zone/zone.go:367-386`
**Description:** The `handleInclude` function implements path traversal protection:
- Checks for `..` in include paths (line 369)
- Validates resolved paths stay within zone directory (line 382-386)
- Uses `maxIncludeDepth = 10` to prevent infinite recursion (line 361-362)

**Impact:** Path traversal attempts are blocked with errors. The protection appears adequate.

**Recommendation:** No changes needed. Protection is in place.

**Status:** Not a vulnerability - protected

---

## [ZONE FILE INJECTION] $GENERATE Range Limit Protection

**Severity:** Low (protected)
**File:** `internal/zone/zone.go:441-447`
**Description:** The `handleGenerate` function limits generated records to `maxGenerateRecords = 65536` to prevent memory exhaustion from maliciously large ranges.

**Impact:** Large range values are rejected. DoS via excessive memory allocation is prevented.

**Recommendation:** No changes needed. Protection is in place.

**Status:** Not a vulnerability - protected

---

## [COMMAND INJECTION] No External Process Spawning Found

**Severity:** Low (no issues found)
**File:** All scanned files
**Description:** `go vet ./...` completed with no output (no issues). Grep for `os/exec` found no matches in `internal/` directories. The codebase does not spawn external processes.

**Impact:** No command injection attack surface.

**Recommendation:** No changes needed.

**Status:** Not a vulnerability

---

## [URL INJECTION] Blocklist URL Validation Strong

**Severity:** Low (protected)
**File:** `internal/blocklist/blocklist.go:82-123`
**Description:** The `validateBlocklistURL` function:
- Requires HTTPS only (line 91-93)
- Blocks cloud metadata endpoints (line 99-102)
- Resolves hostname and validates no private/reserved IPs (line 105-120)
- Implements `isPrivateOrReservedIP` for comprehensive checks (line 126-160)

**Impact:** SSRF attacks via blocklist URLs are prevented. The validation is thorough.

**Recommendation:** No changes needed. Protection is in place.

**Status:** Not a vulnerability - protected

---

## [URL INJECTION] Path Traversal Check in Blocklist File Loading

**Severity:** Low (protected)
**File:** `internal/blocklist/blocklist.go:248-251`
**Description:** The `loadFile` function checks for `..` path traversal sequences before opening files:
```go
if strings.Contains(path, "..") {
    return fmt.Errorf("blocklist path traversal attempt blocked: %s", path)
}
```

**Impact:** Path traversal attacks via blocklist file paths are blocked.

**Recommendation:** No changes needed. Protection is in place.

**Status:** Not a vulnerability - protected

---

## [LOG INJECTION] Audit Logs Use Structured Logging - Safe

**Severity:** Low (no issues found)
**File:** `internal/api/server.go:1509`
**Description:** The `util.Infof` at line 1509 is used for audit logging with structured parameters:
```go
util.Infof("bulk-ptr: zone=%s cidr=%s pattern=%s override=%v addA=%v added=%d addedA=%d skipped=%d exists=%d",
    zoneName, req.CIDR, req.Pattern, req.Override, req.AddA, added, addedA, skipped, exists)
```
This uses format strings with explicit parameter passing, not direct string interpolation.

**Impact:** Query logs pass domain names via structured logging which prevents log injection attacks.

**Recommendation:** Ensure all audit/logging uses structured formatting rather than direct string interpolation of user input.

**Status:** Not a vulnerability - protected

---

## [LOG INJECTION] Default Admin Password Logged via util.Warnf

**Severity:** High
**File:** `internal/auth/auth.go:116`
**Description:** When no users are configured, the system generates a default admin password and logs it via `util.Warnf`:
```go
util.Warnf("No users configured. Default admin password generated: %s", defaultPassword)
util.Warnf("Change this password immediately via the dashboard or API.")
```

**Impact:** The default admin password is written to stdout (or configured log output). If logs are persisted to files or log aggregation systems, this exposes the admin password in plaintext.

**Recommendation:** Change to `util.Errorf` which writes to stderr (not stdout). Consider not logging the password at all, or only logging a hash/fingerprint for verification purposes.

**Status:** Finding

---

## Summary

| Category | Findings | Protected | Not Applicable |
|----------|----------|-----------|----------------|
| Header Injection | 2 | 0 | 0 |
| YAML Parsing | 0 | 0 | 1 |
| Zone File Injection | 0 | 2 | 0 |
| Command Injection | 0 | 0 | 1 |
| URL Injection | 0 | 2 | 0 |
| Log Injection | 1 | 1 | 0 |

### Action Items

1. **High Priority:** Fix log injection in `internal/auth/auth.go:116` - admin password is logged
2. **Medium Priority:** Sanitize `Content-Disposition` header value in `internal/api/server.go:1276`
3. **Low Priority:** Review `X-Forwarded-For` trust in `internal/api/server.go:2584-2592` for rate limiting bypass potential

### Go Vet Results

```
go vet ./...
(Bash completed with no output)
```

No issues found by `go vet`. All scanned files are syntactically correct and pass static analysis.