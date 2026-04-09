# NothingDNS Secrets Exposure Security Report

**Audit Date:** 2026-04-09
**Audit Scope:** Secrets/Credentials Exposure
**Severity Scale:** Critical > High > Medium > Low > Info

---

## Executive Summary

This report details findings from a security audit focused on secrets and credentials exposure in the NothingDNS codebase. The audit identified **1 Critical**, **1 High**, **2 Medium**, and **3 Info** severity issues related to secret management, token handling, and cryptographic operations.

**Most Critical Finding:** Auto-generated admin passwords are logged to stdout, creating a severe risk of credential exposure in production environments.

---

## Findings

### F1: Auto-Generated Admin Password Logged to stdout

**Severity:** Critical
**CWE ID:** CWE-532, CWE-200
**Confidence:** High
**File:** `internal/auth/auth.go:103-104`

**Description:**
When no users are configured in the auth store, the `NewStore` function generates a cryptographically secure random password for the default admin account and immediately logs it via `util.Warnf`:

```go
// Log the generated password - operator must change this
util.Warnf("No users configured. Default admin password generated: %s", defaultPassword)
util.Warnf("Change this password immediately via the dashboard or API.")
```

The `util.Warnf` function writes to the configured logger output (default: stdout). In production deployments where logs are persisted to files or log aggregation systems, this exposes the admin password in plaintext.

**Impact:**
- Production log files contain valid admin credentials
- Shared logging infrastructure (ELK, Splunk, CloudWatch) exposes credentials to unauthorized parties
- Compliance violations (PCI-DSS, SOC2) for credential exposure
- Full administrative access to the DNS server and dashboard

**Remediation:**
1. **Never log generated credentials.** Change the log level to DEBUG or remove the logging entirely.
2. Alternative: Write the password to a secure file with restricted permissions (0600), or output only to stderr with a prompt to change.
3. Consider requiring user configuration before the server starts (fail if no users configured in production mode).

**Example Fix:**
```go
// Write to a secure file instead of logging
if err := os.WriteFile("/var/run/nothingdns/admin.pass", []byte(defaultPassword), 0600); err != nil {
    util.Errorf("Failed to write admin password file: %v", err)
}
```

---

### F2: Authentication Token Passed Via URL Query Parameter

**Severity:** High
**CWE ID:** CWE-597
**Confidence:** High
**File:** `internal/api/server.go:313-314`

**Description:**
The API authentication accepts tokens via URL query parameter (`?token=`), which is explicitly designed to leak credentials:

```go
// Fallback: query parameter
if token == "" {
    token = r.URL.Query().Get("token")
}
```

Tokens in URLs are exposed through:
- Browser history (bookmarked URLs)
- Server access logs (Apache, Nginx, CloudFront)
- Referer headers (when navigating away)
- Web proxies and caches
- Browser autofill suggestions

**Impact:**
- Credential theft via log analysis
- Session hijacking if token is intercepted
- Compliance violations for sensitive data in URLs

**Remediation:**
1. **Remove token query parameter support entirely.** RFC 6750 specifies Bearer tokens should only be sent in:
   - `Authorization: Bearer <token>` header
   - `Cookie` header
2. If backwards compatibility is required, deprecate with a warning and require secure transport (HTTPS).

---

### F3: Modulo Bias in Secure Password Generation

**Severity:** Medium
**CWE ID:** CWE-331
**Confidence:** Medium
**File:** `internal/auth/auth.go:152-153`

**Description:**
The `generateSecurePassword` function uses a biased modulo operation to map random bytes to charset characters:

```go
const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
// charsetLen = 74

for i := range bytes {
    bytes[i] = charset[int(bytes[i])%charsetLen]
}
```

Since 256 (byte range) does not divide evenly by 74 (charset length), characters early in the charset have a slightly higher probability of being selected, creating a modulo bias.

**Impact:**
- Slightly reduced entropy (approximately 0.1 bits for 24-character passwords)
- Theoretical attack vector for offline password guessing if attacker has sufficient password samples

**Remediation:**
Use rejection sampling to ensure uniform distribution:

```go
func generateSecurePassword(length int) (string, error) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    charsetLen := len(charset)

    bytes := make([]byte, length)
    for i := range bytes {
        for {
            var b [1]byte
            if _, err := rand.Read(b[:]); err != nil {
                return "", err
            }
            if int(b[0]) < (256 / charsetLen * charsetLen) {
                bytes[i] = charset[int(b[0])%charsetLen]
                break
            }
        }
    }
    return string(bytes), nil
}
```

---

### F4: DNS Cookie Secret Rotation Error Uses fmt.Printf

**Severity:** Medium
**CWE ID:** CWE-547
**Confidence:** Medium
**File:** `internal/dnscookie/cookie.go:194-196`

**Description:**
When DNS cookie secret rotation fails, the error is printed to stdout via `fmt.Printf` instead of proper error logging:

```go
if err := j.RotateSecret(); err != nil {
    fmt.Printf("WARNING: %v\n", err)
}
```

While the error message itself doesn't contain secrets, this pattern:
1. Bypasses structured logging (no log level, no context)
2. May write to stdout when logger is configured for file output
3. Inconsistent error handling approach

**Impact:**
- Inconsistent logging behavior
- Potential information disclosure if rotation failure reveals implementation details
- Security events may be missed in log monitoring

**Remediation:**
Use the structured logger like other parts of the codebase:
```go
if err := j.RotateSecret(); err != nil {
    util.Errorf("dnscookie: secret rotation failed: %v", err)
}
```

---

### F5: Test Credentials Hardcoded in Test Files

**Severity:** Low
**CWE ID:** CWE-547
**Confidence:** High
**File:** `internal/auth/auth_test.go` (multiple locations)

**Description:**
Test files contain hardcoded credentials that are checked into version control:
- Lines 71, 115: `Password: "adminpass"`
- Lines 162, 187, 218, 301, 330, 356, 385: `Password: "pass"`
- Lines 259, 277, 468: `Password: "adminpass"`

Additionally, `test-config.yaml:16` contains `auth_token: "testtoken123"`.

**Impact:**
- Low risk as these are in test code
- Could be accidentally used as defaults
- Static code analysis tools may flag these

**Remediation:**
Use environment variables or test-specific configuration files for test credentials:
```go
password := os.Getenv("TEST_ADMIN_PASSWORD")
if password == "" {
    password = "testpassword" // only for local dev
}
```

---

### F6: Environment Variable Expansion Without Validation

**Severity:** Info
**CWE ID:** CWE-20
**Confidence:** Medium
**File:** `internal/config/config.go:809-848`

**Description:**
The `expandEnvVars` function silently expands environment variables to empty strings when they are unset:

```go
func expandEnvVars(input string) string {
    // ...
    varValue := os.Getenv(varName)
    result.WriteString(varValue)  // silently expands to "" if unset
    // ...
}
```

This affects secrets loaded from environment variables like `auth_secret`, `encryption_key`, and TSIG secrets. If a required secret is accidentally unset, the server may:
1. Use an empty/weak secret
2. Fail silently with unpredictable behavior
3. Generate weak auto-generated secrets

**Impact:**
- Silent failure if required secrets are not set
- Potential use of empty secrets in production

**Remediation:**
1. Validate required secrets after environment variable expansion
2. Fail fast with a clear error message if required secrets are missing
3. Log which environment variables were used for secrets (without values)

---

### F7: Fallback Weak Password in Error Path

**Severity:** Info
**CWE ID:** CWE-672
**Confidence:** Low
**File:** `internal/auth/auth.go:91-93`

**Description:**
If `crypto/rand` fails during password generation (extremely unlikely), the code falls back to "admin":

```go
defaultPassword, err := generateSecurePassword(24)
if err != nil {
    // Fallback - this should never happen with crypto/rand
    defaultPassword = "admin"
}
```

While the comment acknowledges this should never happen, the fallback creates a predictable credential.

**Impact:**
- Near-zero risk (crypto/rand failure indicates system-level issues)
- Predictable credential in extremely rare failure mode

**Remediation:**
If crypto/rand fails, either:
1. Refuse to start (fail fast)
2. Use a panic/restart loop rather than falling back to weak credentials

---

## Recommendations Summary

| Priority | Finding | Action |
|----------|---------|--------|
| **P0** | F1 | Remove password logging immediately |
| **P1** | F2 | Remove token query parameter support |
| **P2** | F3 | Implement rejection sampling in password generation |
| **P2** | F4 | Use structured logger for rotation errors |
| **P3** | F5 | Move test credentials to environment variables |
| **P3** | F6 | Add validation for required secrets |
| **P4** | F7 | Consider failing instead of weak fallback |

---

## References

- [CWE-532: Information Exposure Through Log Files](https://cwe.mitre.org/data/definitions/532.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-597: Use of PUT/POST instead of GET for Sensitive Operations](https://cwe.mitre.org/data/definitions/597.html)
- [CWE-331: Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)
- [CWE-547: Use of Hard-coded, Security-Relevant Constants](https://cwe.mitre.org/data/definitions/547.html)
- [RFC 6750: OAuth 2.0 Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
- [RFC 7873: DNS Cookies](https://tools.ietf.org/html/rfc7873)
