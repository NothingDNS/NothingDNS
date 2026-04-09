# Input Validation Security Audit Report

**Project:** NothingDNS
**Date:** 2026-04-09
**Auditor:** Security Code Review
**Focus Areas:** Path Traversal, YAML Parsing, DNS Name Validation, Integer Overflow, Buffer Overflow, Nil Pointer Dereference, Unicode/UTF-8, Null Byte Injection

---

## Executive Summary

This audit examined the NothingDNS codebase for input validation vulnerabilities across YAML parsing, DNS wire format handling, zone file parsing, and HTTP API endpoints. Several issues were identified ranging from informational to medium severity. The codebase demonstrates good security practices in several areas, particularly in DNS wire format parsing with proper bounds checking and pointer loop detection.

---

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 1 |
| Medium | 2 |
| Low | 4 |
| Informational | 5 |

---

## Detailed Findings

### HIGH Severity

#### 1. Unbounded $GENERATE Range in Zone File Parsing

**CWE ID:** CWE-400 (Uncontrolled Resource Consumption)
**File:** `internal/zone/zone.go:440`
**Description:**

The `$GENERATE` directive parser does not limit the number of records it can generate. A malicious zone file could specify a range like `1-2147483647` with step 1, potentially generating nearly 2 billion records and causing memory exhaustion or denial of service.

```go
// Line 440: No bounds check on stop value
for i := start; i <= stop; i += step {
    expanded := expandGenerate(template, i)
    if err := p.parseRecord(expanded); err != nil {
        return fmt.Errorf("$GENERATE at iteration %d: %w", i, err)
    }
}
```

**Severity:** High
**Confidence:** High
**Evidence:**
- `parseGenerateRange()` (line 451-489) validates start <= stop but does not cap the range
- `$GENERATE` is directly processed from zone files without user input validation

**Remediation:**

Add a maximum iteration limit for `$GENERATE`:

```go
const maxGenerateRecords = 65536  // Same limit used in CIDR handling

// In parseGenerateRange or handleGenerate
if (stop - start) / step > maxGenerateRecords {
    return fmt.Errorf("$GENERATE range too large (max %d records)", maxGenerateRecords)
}
```

---

### MEDIUM Severity

#### 2. Missing Path Traversal Protection in Blocklist File Loading

**CWE ID:** CWE-22 (Path Traversal)
**File:** `internal/blocklist/blocklist.go:145-187`
**Description:**

The blocklist file loading mechanism does not validate for path traversal sequences (`..`) before opening files. While `os.Open` is used (not `os.OpenFile` with `O_CREAT`), a maliciously configured blocklist path could access files outside the intended directory.

Unlike the zone file parser which has explicit `..` checks and directory boundary validation, the blocklist `loadFile` function directly passes the path to `os.Open`:

```go
// Line 145-149: No traversal check before os.Open
func (bl *Blocklist) loadFile(path string) error {
    f, err := os.Open(path)
    if err != nil {
        return err
    }
    defer f.Close()
```

**Severity:** Medium
**Confidence:** Medium
**Remediation:**

Add path traversal validation similar to zone file handling:

```go
func (bl *Blocklist) loadFile(path string) error {
    // Check for path traversal
    if strings.Contains(path, "..") {
        return fmt.Errorf("blocklist path traversal attempt blocked: %s", path)
    }

    // Resolve and validate path stays within allowed directory
    absPath, err := filepath.Abs(path)
    if err != nil {
        return err
    }

    // Optionally: validate against allowed base directories
    f, err := os.Open(absPath)
    // ...
}
```

---

#### 3. Wildcard Character Allowed in DNS Labels Without Special Handling

**CWE ID:** CWE--79 (Cross-Site Scripting) - DNS Wildcard Abuse
**File:** `internal/protocol/labels.go:176-181`
**Description:**

The `isValidLabelChar` function allows the `*` character in DNS labels, which creates wildcard records. While this is a valid DNS feature, wildcard records can be problematic for security:

1. A wildcard `*.example.com` matching all subdomains could inadvertently override more specific secure subdomains
2. The validation does not distinguish between regular labels and wildcard labels

```go
// Line 176-181: * is allowed without special security considerations
func isValidLabelChar(c rune) bool {
    return (c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') ||
        c == '-' || c == '_' || c == '*'
}
```

**Severity:** Medium (for DNSSEC/certificate validation scenarios)
**Confidence:** High
**Remediation:**

Consider adding a separate validation for wildcard-only records or documenting the security implications. The `IsWildcard()` method at line 92-94 correctly identifies wildcard names:

```go
func (n *Name) IsWildcard() bool {
    return len(n.Labels) > 0 && n.Labels[0] == "*"
}
```

Ensure wildcard matching logic in zone lookups is clearly documented and that certificate validation workflows account for wildcard behavior.

---

### LOW Severity

#### 4. DNS Label Underscore Validation

**CWE ID:** CWE-939 (Improper Authorization in Resource Called) - Label Character Validation
**File:** `internal/protocol/labels.go:176-181`
**Description:**

The underscore character (`_`) is allowed in DNS labels. While this is a common convention for service discovery records (e.g., `_http._tcp`), RFC 1035 specifies that labels should only contain letters, digits, and hyphens. The underscore is not a valid DNS character per the original specification.

```go
// Line 180: Underscore allowed but not RFC 1035 compliant
c == '-' || c == '_' || c == '*'
```

**Severity:** Low
**Confidence:** High
**Remediation:**

If strict RFC compliance is required, remove underscore from valid characters. If service discovery records are needed, document that underscore is intentionally allowed as an extension:

```go
// Option 1: Strict RFC 1035
c == '-' || c == '*'

// Option 2: Documented extension for SRV records
// Note: _ is allowed per common convention for _service._proto records
c == '-' || c == '_' || c == '*'
```

---

#### 5. CORS Policy Allows All Origins

**CWE ID:** CWE-942 (Permissive Cross-Domain Whitelist)
**File:** `internal/api/server.go:270-283`
**Description:**

The CORS middleware is configured to allow all origins (`*`):

```go
// Line 272: Wildcard CORS origin
w.Header().Set("Access-Control-Allow-Origin", "*")
```

**Severity:** Low
**Confidence:** High
**Remediation:**

If the API is intended for dashboard access only, consider restricting CORS to the dashboard origin. If the API is public, this is acceptable but should be documented.

---

#### 6. Token-Based Auth via URL Query Parameter

**CWE ID:** CWE-598 (Information Exposure Through Query Strings)
**File:** `internal/api/server.go:313-315`
**Description:**

The authentication token can be passed via URL query parameter (`?token=xxx`), which can leak tokens in server logs, browser history, and referrer headers:

```go
// Lines 313-315: Token fallback to query parameter
if token == "" {
    token = r.URL.Query().Get("token")
}
```

**Severity:** Low
**Confidence:** High
**Remediation:**

Remove the query parameter token fallback, requiring tokens to be sent only via:
1. `Authorization: Bearer <token>` header
2. `HttpOnly` cookie (already implemented at line 2097-2105)

---

### INFORMATIONAL Severity

#### 7. No Billion Laughs / YAML Entity Expansion Protection Needed

**File:** `internal/config/tokenizer.go`
**Description:**

The custom YAML tokenizer does not implement anchors (`&`), aliases (`*`), or tags (`!`), so it is not vulnerable to the "Billion Laughs" exponential entity expansion attack. This is a positive security finding.

**Confidence:** High
**Remediation:** None required. The tokenizer's lack of anchor/alias support prevents this attack class.

---

#### 8. Good DNS Wire Format Bounds Checking

**File:** `internal/protocol/labels.go`, `internal/protocol/record.go`
**Description:**

The DNS wire format parsing implements comprehensive bounds checking:

- `MaxLabelLength` (63 bytes) enforced at lines 315-317
- `MaxNameLength` (255 bytes) enforced at lines 325-328
- `MaxPointerDepth` (10) enforced at lines 286-288 to prevent pointer loops
- `rdlength` validation against buffer bounds at line 165-167

**Confidence:** High
**Remediation:** None required. The parsing is well-protected against buffer overruns.

---

#### 9. Zone File $INCLUDE Depth Limit

**File:** `internal/zone/zone.go:17`, `internal/zone/zone.go:357-359`
**Description:**

The zone file parser implements `maxIncludeDepth = 10` to prevent infinite recursion through circular `$INCLUDE` directives:

```go
const maxIncludeDepth = 10  // Line 17

// Lines 357-359: Depth check
if p.includeDepth >= maxIncludeDepth {
    return fmt.Errorf("$INCLUDE depth limit exceeded (max %d)", maxIncludeDepth)
}
```

**Confidence:** High
**Remediation:** None required.

---

#### 10. Good Path Traversal Protection in Zone File $INCLUDE

**File:** `internal/zone/zone.go:363-383`
**Description:**

The zone file `$INCLUDE` directive properly validates paths:

```go
// Line 365-367: Explicit traversal check
if strings.Contains(includeFile, "..") {
    return fmt.Errorf("$INCLUDE path traversal attempt blocked: %s", includeFile)
}

// Lines 377-382: Validate cleaned path stays within zone directory
cleanPath := filepath.Clean(includeFile)
if p.filename != "" && !filepath.IsAbs(args[0]) {
    zoneDir := filepath.Dir(p.filename)
    if !strings.HasPrefix(cleanPath, zoneDir+string(filepath.Separator)) && cleanPath != zoneDir {
        return fmt.Errorf("$INCLUDE path traversal attempt blocked: %s", includeFile)
    }
}
```

**Confidence:** High
**Remediation:** None required. This is a good example of path traversal prevention.

---

#### 11. API Input Validation on Pagination Parameters

**File:** `internal/api/server.go:471-479`
**Description:**

The API properly validates pagination parameters with upper bounds:

```go
// Line 472: offset must be >= 0
if v, err := strconv.Atoi(o); err == nil && v >= 0 {
    offset = v
}
// Line 477: limit must be 1-500
if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 500 {
    limit = v
}
```

**Confidence:** High
**Remediation:** None required.

---

## Additional Observations

### No Null Byte Injection Found

The codebase properly handles null bytes by:
1. Using `strings.Builder` which handles embedded nulls gracefully
2. Checking `ch == 0` in tokenizer as terminator condition (line 319)
3. Using Go's `byte` type which preserves null bytes but no C-style string handling exists

### No Integer Overflow in DNS Count Fields

The `ValidateMessage` function at `wire.go:338-359` validates that record counts do not exceed `maxRecords = 65535`, which prevents integer overflow in loops that parse records based on header counts.

### ASCII-Only Lowercase Conversion

The `toLower` function at `labels.go:339-344` uses ASCII-only conversion (`b + 32` for uppercase A-Z), which is correct for DNS names per RFC. Non-ASCII internationalized domain names are not supported, which is acceptable given the zero-dependency design constraint.

### Blocklist HTTP Client Has Timeout

The blocklist HTTP client is properly configured with a 30-second timeout:

```go
httpClient: &http.Client{
    Timeout: 30 * time.Second,
}
```

---

## Recommendations

### Immediate (High Priority)

1. **Add `$GENERATE` range limit** - Implement a maximum iteration count (suggest 65536) to prevent memory exhaustion from malicious zone files.

### Medium Priority

2. **Add path traversal check to blocklist** - Align blocklist file loading with zone file `$INCLUDE` security.

3. **Document wildcard DNS security implications** - Ensure operators understand wildcard record behavior and potential impact on certificate validation.

### Low Priority / Future Considerations

4. **Remove underscore from strict RFC 1035 mode** or document as intentional extension.

5. **Consider restricting CORS** if API is not meant to be publicly accessed.

6. **Remove token fallback to URL query parameter** to prevent token leakage in logs.

---

## Conclusion

The NothingDNS codebase demonstrates solid security fundamentals in critical areas:
- DNS wire format parsing has comprehensive bounds checking
- Zone file includes are protected against path traversal
- Input validation on API parameters with proper limits
- No entity expansion vulnerabilities in YAML parsing

The primary security concern is the unbounded `$GENERATE` directive range, which could be exploited to cause resource exhaustion. This should be addressed before deployment in untrusted environments.
