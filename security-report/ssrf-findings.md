# SSRF Security Audit Report - NothingDNS

**Audit Date:** 2026-04-09
**Auditor:** Security Code Review (AI-assisted)
**Scope:** Server-Side Request Forgery (SSRF) Attack Surface Analysis
**Target:** NothingDNS Codebase

---

## Executive Summary

This report documents findings from an SSRF (Server-Side Request Forgery) security audit of the NothingDNS codebase. Multiple critical vulnerabilities were identified where user-controlled or config-controlled URLs are fetched via HTTP without proper validation, potentially allowing attackers to access internal services, cloud metadata endpoints, and internal network resources.

---

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 1 |
| Medium | 0 |
| Low | 1 |
| Info | 1 |

---

## Detailed Findings

### Finding 1: Unvalidated URL Fetching in Blocklist Loader

**CWE ID:** CWE-918 (Server-Side Request Forgery)
**File:** `internal/blocklist/blocklist.go`
**Lines:** 82, 272-276
**Severity:** Critical
**Confidence:** High
**CVSS 3.1 Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

#### Description

The blocklist loader fetches blocklist data from URLs using an HTTP client with **no URL validation whatsoever**. An attacker who can influence the blocklist URLs configuration (via config file, API, or other means) can cause the server to make HTTP requests to arbitrary URLs, including:

- Cloud metadata endpoints (AWS `169.254.169.254`, GCP `metadata.google.internal`, Azure `169.254.169.254`)
- Internal services (database ports, admin panels, internal APIs)
- Local file access via `file://` protocol
- Any arbitrary host:port combination

#### Vulnerable Code

```go
// internal/blocklist/blocklist.go:82
func (bl *Blocklist) loadURL(url string) error {
    resp, err := bl.httpClient.Get(url)  // NO VALIDATION - SSRF VULNERABILITY
    if err != nil {
        return fmt.Errorf("fetching %s: %w", url, err)
    }
    defer resp.Body.Close()
    // ...
}
```

The same vulnerability exists in the `AddURL` method at lines 272-276:

```go
// internal/blocklist/blocklist.go:272-276
func (bl *Blocklist) AddURL(url string) error {
    bl.mu.Lock()
    defer bl.mu.Unlock()

    if err := bl.loadURL(url); err != nil {  // Calls loadURL without validation
        return err
    }
    bl.urls = append(bl.urls, url)
    return nil
}
```

#### HTTP Client Configuration

The HTTP client is created with only a timeout (30 seconds) but no restrictions:

```go
// internal/blocklist/blocklist.go:45-47
httpClient: &http.Client{
    Timeout: 30 * time.Second,
},
```

**No `CheckRedirect` function is set**, meaning the client will follow redirects, potentially amplifying the attack surface.

#### Attack Scenarios

1. **Cloud Metadata Exfiltration:**
   ```
   URLs: ["http://169.254.169.254/latest/meta-data/iam/security-credentials/"]
   ```
   Could retrieve AWS IAM credentials from metadata service.

2. **Internal Port Scanning:**
   ```
   URLs: ["http://192.168.1.1:8080/", "http://192.168.1.1:3306/"]
   ```
   Could detect internal services and their versions.

3. **Local File Access:**
   ```
   URLs: ["file:///etc/passwd"]
   ```
   Could read local files if the HTTP client supports `file://` scheme.

4. **Internal Service Access:**
   ```
   URLs: ["http://10.0.0.5:5432/", "http://internal-admin:8080/config"]
   ```
   Could access internal databases, admin panels, or configuration interfaces.

#### Proof of Concept

```yaml
# Attacker-controlled blocklist configuration
blocklist:
  enabled: true
  urls:
    - "http://169.254.169.254/latest/meta-data/"
    - "http://localhost:6379/"
    - "file:///etc/passwd"
```

When this config is loaded, the server will attempt to fetch from these URLs, potentially exposing:
- Cloud provider credentials
- Internal service detection
- Local file contents

#### Remediation

Implement strict URL validation before making HTTP requests:

```go
func validateBlocklistURL(rawURL string) error {
    u, err := url.Parse(rawURL)
    if err != nil {
        return fmt.Errorf("invalid URL: %w", err)
    }

    // Only allow HTTPS
    if u.Scheme != "https" {
        return fmt.Errorf("only HTTPS URLs are allowed, got: %s", u.Scheme)
    }

    // Block private and reserved IPs
    host := u.Hostname()
    if ip := net.ParseIP(host); ip != nil {
        if isPrivateOrReserved(ip) {
            return fmt.Errorf("private/reserved IPs not allowed: %s", host)
        }
    }

    // Optionally: Whitelist specific domains
    allowedDomains := map[string]bool{
        "blocklist.project-dns.com": true,
        "raw.githubusercontent.com": true,
    }
    if !allowedDomains[host] {
        return fmt.Errorf("domain not in allowlist: %s", host)
    }

    return nil
}
```

---

### Finding 2: User-Controlled Server URL in Health Check

**CWE ID:** CWE-918 (Server-Side Request Forgery)
**File:** `cmd/dnsctl/server.go`
**Lines:** 105-111
**Severity:** High
**Confidence:** Medium
**CVSS 3.1 Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L

#### Description

The `dnsctl` CLI tool constructs health check URLs from the user-provided `-server` flag without validation. While this is a client-side tool typically used by administrators, the lack of URL validation could be exploited in scenarios where:

- The server flag is populated from untrusted sources (scripts, automation)
- The tool is used in contexts where server URLs are derived from user input

#### Vulnerable Code

```go
// cmd/dnsctl/server.go:105-111
case "health":
    url := strings.TrimRight(globalFlags.Server, "/") + "/health"
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        fmt.Printf("Server unhealthy: %v\n", err)
        os.Exit(1)
    }
    resp, err := httpClient.Do(req)
```

The `globalFlags.Server` defaults to `http://localhost:8080` but accepts any URL:

```go
// cmd/dnsctl/main.go:51
flag.StringVar(&globalFlags.Server, "server", "http://localhost:8080", "NothingDNS API server URL")
```

#### Attack Scenario

If an attacker can influence the server flag value:

```bash
dnsctl -server "http://169.254.169.254/latest/meta-data/" server health
```

This would cause the CLI to make an HTTP request to the cloud metadata endpoint.

#### Remediation

Add URL validation to ensure only intended targets are accessed:

```go
func validateServerURL(rawURL string) error {
    u, err := url.Parse(rawURL)
    if err != nil {
        return fmt.Errorf("invalid URL: %w", err)
    }

    // Only allow HTTP/HTTPS
    if u.Scheme != "http" && u.Scheme != "https" {
        return fmt.Errorf("invalid scheme: %s", u.Scheme)
    }

    // Block known internal/metadata hosts
    host := strings.ToLower(u.Hostname())
    blockedHosts := map[string]bool{
        "169.254.169.254": true,
        "metadata.google.internal": true,
        "metadata.azure.com": true,
        "localhost": true,
    }
    if blockedHosts[host] {
        return fmt.Errorf("access to %s not allowed", host)
    }

    return nil
}
```

---

### Finding 3: ODoH Target/Proxy URL Construction from Config

**CWE ID:** CWE-918 (Server-Side Request Forgery)
**File:** `internal/odoh/odoh.go`
**Lines:** 92-101, 202
**Severity:** Info
**Confidence:** Low
**CVSS 3.1 Vector:** CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N

#### Description

The ODoH (Oblivious DNS over HTTPS) implementation constructs target and proxy URLs from configuration without explicit validation. While the URLs are hardcoded with `https://` prefix, if an attacker can modify the ODoH configuration, they could point to arbitrary HTTPS endpoints.

#### Vulnerable Code

```go
// internal/odoh/odoh.go:92-101
func NewODoHConfig(targetName, proxyName string) *ODoHConfig {
    return &ODoHConfig{
        TargetName: targetName,
        ProxyName:  proxyName,
        TargetURL:  "https://" + targetName + "/dns-query",  // No validation
        ProxyURL:   "https://" + proxyName + "/dns-query",   // No validation
        // ...
    }
}

// internal/odoh/odoh.go:202
req, err := http.NewRequest("POST", c.config.ProxyURL, bytes.NewReader(reqBody))
```

#### Risk Assessment

**Lower risk** because:
1. Requires attacker to modify server configuration (high privilege)
2. Uses HTTPS scheme by default
3. Attack surface is limited to HTTPS endpoints

**However**, an attacker with config modification access could:
- Probe internal HTTPS services
- Attempt to exploit vulnerabilities in internal HTTPS endpoints

#### Remediation

Add validation in `NewODoHConfig` or at config loading time:

```go
func validateODoHURLs(cfg *ODoHConfig) error {
    validate := func(name, url string) error {
        if !strings.HasPrefix(url, "https://") {
            return fmt.Errorf("%s must use HTTPS", name)
        }
        // Add host validation similar to Finding 1
        return nil
    }

    if err := validate("TargetURL", cfg.TargetURL); err != nil {
        return err
    }
    return validate("ProxyURL", cfg.ProxyURL)
}
```

---

### Finding 4: Missing URL Validation in Config Parser

**CWE ID:** CWE-20 (Improper Input Validation)
**File:** `internal/config/config.go`
**Lines:** 1259-1268
**Severity:** Low
**Confidence:** High

#### Description

The `unmarshalBlocklist` function does **not** parse the `URLs` field from YAML configuration, despite the `BlocklistConfig` struct defining a `URLs []string` field. This creates a discrepancy between the config struct and the parser that could lead to security misconfigurations.

#### Vulnerable Code

```go
// internal/config/config.go:109-113
type BlocklistConfig struct {
    Enabled bool     `yaml:"enabled"`
    Files   []string `yaml:"files"`
    URLs    []string `yaml:"urls"` // Defined but NOT PARSED!
}

// internal/config/config.go:1259-1268
func unmarshalBlocklist(node *Node, cfg *BlocklistConfig) error {
    if node.Type != NodeMapping {
        return fmt.Errorf("expected mapping")
    }

    cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
    cfg.Files = getStringSlice(node, "files", cfg.Files)
    // NOTE: cfg.URLs is never parsed from YAML!
    return nil
}
```

#### Impact

This is technically a **validation gap** rather than an active SSRF, because URLs defined in config will not be loaded. However, URLs can still be added programmatically via:
- `Blocklist.AddURL()` method
- Direct struct manipulation

If the `URLs` field parsing is added later without proper validation, existing deployments could become vulnerable.

#### Remediation

Either:
1. **Remove** the `URLs` field from `BlocklistConfig` if URL-based blocklists are not intended
2. **Add proper URL validation** when implementing URL parsing (see Finding 1)

---

## Recommendations

### Immediate Actions

1. **Implement URL validation** in `internal/blocklist/blocklist.go` before any HTTP requests
2. **Remove or disable** the `AddURL` method until proper validation is in place
3. **Audit all HTTP client usage** to ensure no unvalidated URLs are fetched

### Short-Term Fixes

1. Add URL allowlist for blocklist sources (e.g., only predefined blocklist providers)
2. Implement RFC 3986 URL validation for all user-controlled URLs
3. Block access to private/reserved IP ranges:
   - `10.0.0.0/8`
   - `172.16.0.0/12`
   - `192.168.0.0/16`
   - `127.0.0.0/8`
   - `169.254.0.0/16` (link-local)
   - `::1` (IPv6 loopback)
   - `fc00::/7` (IPv6 unique local)

### Long-Term Security Architecture

1. **Network Segmentation:** Run blocklist fetch operations in isolated network segments
2. **Egress Filtering:** Implement firewall rules to block unexpected outbound connections
3. **Monitoring:** Log all blocklist fetch attempts with full URL details
4. **Content Security Policy:** If serving blocklists via API, implement strict CSP headers

---

## Testing Checklist

- [ ] Verify blocking of `http://169.254.169.254/` requests
- [ ] Verify blocking of `file://` scheme URLs
- [ ] Verify blocking of private IP ranges (10.x, 172.16.x, 192.168.x)
- [ ] Verify blocking of `localhost` and `127.0.0.1`
- [ ] Verify blocking of IPv6 private addresses
- [ ] Verify only HTTPS URLs are allowed (if implementing strict scheme)
- [ ] Verify allowlist works correctly for trusted domains
- [ ] Verify HTTP redirect following does not bypass validation

---

## References

- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP: Server-Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [RFC 3986: Uniform Resource Identifier (URI): Generic Syntax](https://datatracker.ietf.org/doc/html/rfc3986)
- [AWS IMDSv2 Security](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- [GCP Metadata Server](https://cloud.google.com/compute/docs/metadata/default-metadata-values)

---

## Conclusion

The NothingDNS codebase contains **critical SSRF vulnerabilities** in the blocklist loading mechanism. Immediate remediation is required before production deployment. The absence of URL validation on HTTP requests that fetch external resources represents a severe security risk that could lead to:

- Credential exfiltration from cloud metadata services
- Internal network reconnaissance
- Access to internal management interfaces
- Potential RCE via internal service exploitation

All HTTP client requests to user or config-controlled URLs must implement strict validation before deployment.
