# Security Scan Report: SSRF and Path Traversal

**Target:** NothingDNS (D:\Codebox\PROJECTS\NothingDNS)
**Date:** 2026-04-09
**Scanner:** Manual security review
**Files Analyzed:**
- internal/blocklist/blocklist.go
- internal/zone/zone.go
- internal/config/parser.go
- internal/config/config.go
- internal/zone/manager.go

---

## SSRF (Server-Side Request Forgery)

### [SSRF] Incomplete IPv6 Private Address Validation

**Severity:** Medium
**File:** internal/blocklist/blocklist.go:126-160
**Description:** The `isPrivateOrReservedIP` function attempts to validate IPv6 unique local addresses (ULA) using an incorrect bitmask. At line 156, the check `ip[0]&0xfe == 0xfc` does not correctly identify the fc00::/7 range. This is a vestigial check since the IPv6 address methods (`IsLoopback()`, `IsLinkLocalUnicast()`, `IsUnspecified()`) at lines 152-154 handle common IPv6 special addresses. However, ULA addresses (fd00::/8) would pass through this check if they don't match the other conditions.

**Impact:** An attacker could potentially specify a ULA address (fd00::/8) as a hostname in a blocklist URL. If resolved, these addresses would not be blocked by the current implementation, as `IsLoopback()`, `IsLinkLocalUnicast()`, and `IsUnspecified()` return false for ULA addresses.

**Recommendation:** Fix the IPv6 ULA check to properly validate fc00::/7 addresses. For fd00::/8 addresses (the locally assigned ULA range), add explicit validation:

```go
// RFC 4193 unique local (fc00::/7)
// Check for fd00::/8 (locally assigned) and fc00::/8 (reserved)
if ip[0] == 0xfd || ip[0] == 0xfc {
    return true
}
```

Alternatively, rely solely on the stdlib methods and remove the bitmask check.

---

### [SSRF] Incomplete Cloud Metadata Hostname Blocking

**Severity:** Medium
**File:** internal/blocklist/blocklist.go:97-103
**Description:** The metadata hostname blocklist only covers four specific endpoints:
- 169.254.169.254 (AWS)
- metadata.google.internal (GCP)
- metadata.azure.com (Azure)
- metadata.googleusercontent.com (GCP alternative)

Other cloud providers' metadata endpoints are not explicitly blocked. However, these would be caught by the IP-based validation if DNS resolution returns RFC 1918 addresses (10/8, 172.16/12, 192.168/16).

**Impact:** An attacker could target metadata endpoints of cloud providers not in the blocklist (e.g., DigitalOcean: 10.10.0.1, OpenStack: 10.0.0.2, Oracle Cloud: 10.0.0.2). The IP-based validation provides defense-in-depth since these resolve to RFC 1918 addresses.

**Recommendation:** Consider either expanding the hostname blocklist or implementing a warning when a hostname resolves to known cloud provider metadata ranges. The current IP-based validation is sufficient for blocking actual SSRF attacks.

---

### [SSRF] Verification: URL Scheme Enforcement

**Severity:** Pass (No Issue)
**File:** internal/blocklist/blocklist.go:90-93
**Description:** The validation correctly enforces HTTPS-only fetching:

```go
if u.Scheme != "https" {
    return fmt.Errorf("only HTTPS URLs are allowed, got scheme %q", u.Scheme)
}
```

`file://`, `http://`, `gopher://`, and other schemes are blocked. The HTTP client's `Get()` call at line 184 will only receive URLs that passed the HTTPS check.

**Impact:** N/A - This is the intended behavior.

**Recommendation:** None required.

---

### [SSRF] Verification: Direct IP Address Blocking

**Severity:** Pass (No Issue)
**File:** internal/blocklist/blocklist.go:106-120
**Description:** When a URL contains a direct IP address (e.g., `https://10.0.0.1/blocklist`), the validation:
1. Parses the IP directly via `net.ParseIP()` at line 106
2. If successful, checks it against `isPrivateOrReservedIP()` at line 118-119
3. Blocks the request if the IP is private/reserved

This correctly blocks scenarios like `https://169.254.169.254/latest/meta-data/`.

**Impact:** N/A - Direct IP SSRF is properly mitigated.

**Recommendation:** None required.

---

### [SSRF] Verification: DNS Resolution with Multi-IP Handling

**Severity:** Pass (No Issue)
**File:** internal/blocklist/blocklist.go:107-117
**Description:** When a hostname is provided, all resolved IP addresses are checked:

```go
addrs, err := net.LookupHost(host)
if err != nil {
    return fmt.Errorf("cannot resolve host %q: %w", host, err)
}
for _, addr := range addrs {
    if ip = net.ParseIP(addr); ip != nil && isPrivateOrReservedIP(ip) {
        return fmt.Errorf("private/reserved IP not allowed: %s", addr)
    }
}
```

If a hostname resolves to multiple IPs (e.g., round-robin DNS), ALL addresses are validated. This prevents DNS rebinding-style attacks where different queries return different IPs.

**Impact:** N/A - Multi-IP resolution is properly validated.

**Recommendation:** None required.

---

## Path Traversal

### [PATH_TRAVERSAL] Zone File $INCLUDE - Directory Boundary Check Bypass

**Severity:** Medium
**File:** internal/zone/zone.go:380-387
**Description:** The directory boundary check in `handleInclude` has a logic flaw that may allow path traversal in certain scenarios:

```go
cleanPath := filepath.Clean(includeFile)
if p.filename != "" && !filepath.IsAbs(args[0]) {
    zoneDir := filepath.Dir(p.filename)
    if !strings.HasPrefix(cleanPath, zoneDir+string(filepath.Separator)) && cleanPath != zoneDir {
        return fmt.Errorf("$INCLUDE path traversal attempt blocked: %s", includeFile)
    }
}
```

The check only applies when `args[0]` is NOT absolute AND `p.filename` is not empty. If the zone file path is absolute, or if `p.filename` is empty, the directory check is skipped. Additionally, when `p.filename` is empty, relative includes may resolve unexpectedly.

**Impact:** If an attacker can control zone file paths (e.g., through configuration), they could potentially craft zone files that include files outside the intended zone directory. However, the `..` check at line 369 provides some protection:

```go
if strings.Contains(includeFile, "..") {
    return fmt.Errorf("$INCLUDE path traversal attempt blocked: %s", includeFile)
}
```

**Recommendation:** Consider making the path traversal validation unconditional for relative paths and ensuring all includes are validated against a configurable zone directory root.

---

### [PATH_TRAVERSAL] Blocklist File Loading - No Path Sanitization

**Severity:** Medium
**File:** internal/blocklist/blocklist.go:246-251
**Description:** The `loadFile` function only checks for `..` sequences:

```go
if strings.Contains(path, "..") {
    return fmt.Errorf("blocklist path traversal attempt blocked: %s", path)
}
```

Unlike the zone file `$INCLUDE` handler, there is no `filepath.Clean()` normalization or directory boundary validation. While `..` is correctly blocked, there could be other path manipulation techniques depending on the filesystem.

**Impact:** The `..` check prevents basic path traversal attacks. However, symlinks or other filesystem features could potentially be exploited.

**Recommendation:** Add filepath.Clean() and directory boundary validation similar to the zone file $INCLUDE protection:

```go
cleanPath := filepath.Clean(path)
// Optionally validate against allowed base directory
```

---

### [PATH_TRAVERSAL] Verification: Zone File $INCLUDE `..` Check

**Severity:** Pass (No Issue)
**File:** internal/zone/zone.go:369-371
**Description:** The `..` sequence is correctly blocked in $INCLUDE paths:

```go
if strings.Contains(includeFile, "..") {
    return fmt.Errorf("$INCLUDE path traversal attempt blocked: %s", includeFile)
}
```

**Impact:** N/A - Basic path traversal is blocked.

**Recommendation:** None required.

---

### [PATH_TRAVERSAL] Verification: Zone File $INCLUDE Depth Limit

**Severity:** Pass (No Issue)
**File:** internal/zone/zone.go:361-363
**Description:** The include depth is limited to 10 levels to prevent infinite recursion:

```go
if p.includeDepth >= maxIncludeDepth {
    return fmt.Errorf("$INCLUDE depth limit exceeded (max %d)", maxIncludeDepth)
}
```

`maxIncludeDepth` is set to 10 at line 17.

**Impact:** N/A - Circular include attacks are prevented.

**Recommendation:** None required.

---

### [PATH_TRAVERSAL] Verification: $GENERATE Record Limit

**Severity:** Pass (No Issue)
**File:** internal/zone/zone.go:441-447
**Description:** The $GENERATE directive is protected against memory exhaustion:

```go
if step > 0 {
    count := (stop-start)/step + 1
    if count < 0 || count > maxGenerateRecords {
        return fmt.Errorf("$GENERATE range too large: %d records (max %d)", count, maxGenerateRecords)
    }
}
```

`maxGenerateRecords` is set to 65536.

**Impact:** N/A - Maliciously large $GENERATE ranges are blocked.

**Recommendation:** None required.

---

## SSRF Protection Verification Summary

The blocklist.go `validateBlocklistURL` function provides the following SSRF protections:

| Protection | Status | Notes |
|------------|--------|-------|
| Only HTTPS allowed | PASS | Line 91-93 |
| Blocks 169.254.169.254 (AWS) | PASS | Line 100-103 |
| Blocks metadata.google.internal (GCP) | PASS | Line 100-103 |
| Blocks metadata.azure.com (Azure) | PASS | Line 100-103 |
| Blocks metadata.googleusercontent.com | PASS | Line 100-103 |
| Blocks 10/8 (RFC 1918) | PASS | Line 129-132 |
| Blocks 172.16/12 (RFC 1918) | PASS | Line 133-136 |
| Blocks 192.168/16 (RFC 1918) | PASS | Line 137-140 |
| Blocks 127/8 (loopback) | PASS | Line 141-144 |
| Blocks 169.254/16 (link-local) | PASS | Line 145-148 |
| Blocks IPv6 loopback | PASS | Line 152 |
| Blocks IPv6 link-local | PASS | Line 152 |
| Blocks IPv6 unspecified | PASS | Line 152 |
| Blocks ULA (fc00::/7) | PARTIAL | Line 156 - incorrect mask |
| Direct IP blocking | PASS | Line 106-120 |
| Multi-IP DNS resolution | PASS | Line 113-116 |
| file:// scheme | PASS | Only HTTPS allowed |

---

## Overall Assessment

**SSRF Posture:** The SSRF protection in blocklist.go is well-designed with defense-in-depth:
1. Scheme restriction (HTTPS only)
2. Hardcoded metadata hostname blocks
3. IP-based validation for all resolved addresses
4. Blocking of RFC 1918, loopback, and link-local addresses

The main gaps are:
- Incomplete IPv6 ULA validation (medium severity, defense-in-depth exists)
- No explicit blocking of some non-AWS/GCP/Azure metadata endpoints (low severity, IP-based protection exists)

**Path Traversal Posture:** The zone file parser has proper protections for `$INCLUDE`:
- `..` sequence blocking
- Directory boundary validation (with minor logic issues)
- Include depth limiting
- Record generation limits

The blocklist file loading only has `..` checking, lacking directory boundary validation.

**Risk Level:** LOW to MEDIUM - The codebase demonstrates security awareness with SSRF and path traversal protections in place. The identified issues are primarily defense-in-depth gaps rather than critical vulnerabilities.