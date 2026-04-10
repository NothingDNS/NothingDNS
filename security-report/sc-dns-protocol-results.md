# NothingDNS Security Assessment Report

**Target:** NothingDNS - Custom DNS Server Implementation
**Location:** D:\Codebox\PROJECTS\NothingDNS
**Date:** 2026-04-09
**Files Analyzed:**
- internal/protocol/message.go
- internal/protocol/labels.go
- internal/protocol/header.go
- internal/transfer/axfr.go
- internal/transfer/ixfr.go
- internal/resolver/resolver.go
- internal/transfer/ddns.go
- internal/transfer/tsig.go
- internal/protocol/dnssec_dnskey.go
- internal/protocol/dnssec_nsec3.go
- internal/protocol/record.go
- internal/protocol/wire.go

---

## [CRITICAL] AXFR/IXFR Allows Unrestricted Transfers When No Allowlist Configured

**Severity:** Critical
**File:** internal/transfer/axfr.go:111-121
**Description:** The AXFR server's `IsAllowed` method returns `true` (allow all) when `allowList` is `nil` or empty. This means if no ACL is explicitly configured, any client can perform full zone transfers.

```go
func (s *AXFRServer) IsAllowed(clientIP net.IP) bool {
    if s.allowList == nil || len(s.allowList) == 0 {
        return true // Allow all if no list configured
    }
    // ...
}
```

**Impact:** Complete zone disclosure to any attacker. Zone transfers expose the entire DNS namespace including internal hostnames, IP addresses, and service records. This is one of the most dangerous DNS misconfigurations.

**Recommendation:** Change default behavior to deny when no allowList is configured. Explicit ACL configuration should be required for AXFR/IXFR to operate.

---

## [HIGH] DNSSEC Validation Not Implemented

**Severity:** High
**File:** internal/protocol/dnssec_*.go (definitions only)
**Description:** DNSSEC files contain only data structures (RDataDNSKEY, RDataDS, RDataNSEC3, etc.) but no validation logic. There is no signature verification, chain of trust validation, or DNSSEC record checking anywhere in the codebase.

**Impact:** Without DNSSEC validation, the resolver accepts any DNS response as authoritative. This enables DNS cache poisoning attacks where attackers inject forged DNS records. Responses claiming to be DNSSEC-signed are accepted without verification.

**Recommendation:** Implement DNSSEC validation:
1. Build DNSSEC chain of trust from root to leaf
2. Verify RRSIG records against DNSKEY records
3. Validate DS records against parent zone
4. Check NSEC/NSEC3 proofs for negative responses
5. Implement RFC 5011 key trust anchor management

---

## [HIGH] QNAME Minimization Disabled By Default

**Severity:** High
**File:** internal/resolver/resolver.go:57
**Description:** QNAME minimization (RFC 7816) is defined in the config but disabled by default (`QnameMinimization bool // default false`). The resolver sends full query names to all upstream servers during iterative resolution.

```go
type Config struct {
    QnameMinimization bool          // RFC 7816 QNAME minimization (default false)
    // ...
}
```

**Impact:** Full query names leak to all authoritative servers in the resolution chain. This violates RFC 7816 and reveals the complete domain being looked up to every NS server along the path, enabling surveillance and targeted attacks.

**Recommendation:** Enable QNAME minimization by default. The privacy benefit outweighs any compatibility concerns with legacy servers.

---

## [HIGH] 0x20 Encoding Disabled By Default

**Severity:** High
**File:** internal/resolver/resolver.go:58
**Description:** DNS 0x20 encoding (randomized case in query names for spoof resistance) is implemented but disabled by default.

```go
type Config struct {
    Use0x20           bool          // DNS 0x20 encoding for spoofing resistance (default false)
    // ...
}
```

**Impact:** Without 0x20 encoding, DNS responses are not validated for query case sensitivity. Attackers can potentially forge DNS responses with matching transaction IDs. This reduces defense-in-depth against DNS spoofing attacks.

**Recommendation:** Enable 0x20 encoding by default to provide additional spoofing resistance.

---

## [MEDIUM] TSIG Not Required When No Keys Configured

**Severity:** Medium
**File:** internal/transfer/axfr.go:152-175, internal/transfer/ixfr.go:142-163
**Description:** TSIG authentication is only required if `keyStore.HasKeys()` returns true. If no TSIG keys are configured, AXFR and IXFR transfers proceed without any authentication.

```go
// Verify TSIG — if keyStore has keys, TSIG is required
if s.keyStore != nil && s.keyStore.HasKeys() {
    if !hasTSIG(req) {
        return nil, nil, fmt.Errorf("TSIG authentication required for AXFR")
    }
    // ... verify TSIG
}
```

**Impact:** In deployments where TSIG keys are not configured (even accidentally), zone transfers are completely unauthenticated. Combined with the unrestricted AXFR when no allowlist is set, this creates a severe exposure.

**Recommendation:** Require explicit configuration to allow unauthenticated transfers, or require TSIG for all transfers and reject non-TSIG requests with a clear error message.

---

## [MEDIUM] DDNS Updates Lack Rate Limiting

**Severity:** Medium
**File:** internal/transfer/ddns.go:226-230
**Description:** Dynamic DNS updates are sent to a channel with buffer size 100, but there is no rate limiting on update requests per client.

```go
select {
case h.updateChan <- updateReq:
default:
    return h.createUpdateResponse(req, protocol.RcodeRefused), nil
}
```

**Impact:** An authenticated (via TSIG) client could flood the update channel or overwhelm the zone update processing. This could lead to denial of service.

**Recommendation:** Implement per-client rate limiting for DDNS updates, tracking request counts over time windows.

---

## [MEDIUM] NSEC3 Iteration Count Not Validated

**Severity:** Medium
**File:** internal/protocol/dnssec_nsec3.go:186
**Description:** When parsing NSEC3 records, the iteration count is read but not validated against reasonable limits. High iteration counts (e.g., > 100) can cause computational DoS during DNSSEC validation.

```go
r.Iterations = Uint16(buf[offset:])
offset += 2
// No validation of iteration count
```

RFC 9276 recommends strict limits (e.g., max 50 for SHA-1 NSEC3).

**Impact:** If DNSSEC validation were implemented, an attacker could craft NSEC3 records with high iteration counts to cause CPU exhaustion during validation.

**Recommendation:** Add iteration count validation per RFC 9276 guidelines before any DNSSEC validation logic.

---

## [LOW] No Maximum Record Count During Unpacking

**Severity:** Low
**File:** internal/protocol/message.go:219-268
**Description:** While `ValidateMessage` in wire.go enforces a maximum of 65535 records per section, `UnpackMessage` does not enforce limits during parsing. Theoretically, a malformed message could cause excessive memory allocation before limits are checked.

```go
// In ValidateMessage:
const maxRecords = 65535
if qdcount > maxRecords || ancount > maxRecords || ...

// But UnpackMessage iterates without per-iteration limits
for i := 0; i < int(msg.Header.QDCount); i++ {
    // ... unpacks each record
}
```

**Impact:** Resource exhaustion through large record counts in DNS messages. CPU/memory exhaustion before the 65535 limit is hit.

**Recommendation:** Add per-section record limits during unpacking (e.g., max 1000 records per section as a reasonable operational limit).

---

## [LOW] IXFR Journal In-Memory Only By Default

**Severity:** Low
**File:** internal/transfer/ixfr.go:51-54, 222-233
**Description:** IXFR journal entries are stored in-memory by default. If `journalStore` is not configured (nil), only recent entries are kept in memory with a limit of 100 entries.

```go
journals       map[string][]*IXFRJournalEntry // zone name -> journal entries (in-memory cache)
maxJournalSize int                            // Maximum entries per zone

// Default:
maxJournalSize: 100, // Default: keep last 100 changes
```

**Impact:** If the server restarts, IXFR journal is lost. Clients must fall back to full AXFR, causing increased transfer volume and potential exposure.

**Recommendation:** Warn operators that persistent journal storage is recommended for production IXFR deployments.

---

## [INFO] Positive Security Findings

### Label Compression Pointer Loop Protection
**File:** internal/protocol/labels.go:21, 287-289
- `MaxPointerDepth = 5` is properly enforced
- `UnpackName` checks `ptrDepth >= MaxPointerDepth` before following pointers
- `WireNameLength` also enforces the limit

### Transaction ID Uses Crypto Rand
**File:** internal/resolver/resolver.go:22-29
- `nextSecureID()` uses `crypto/rand` for DNS transaction IDs
- Falls back to panic (not predictable values) if crypto/rand fails

### Message Truncation Is Record-Boundary Aware
**File:** internal/protocol/message.go:343-380
- `Truncate()` removes entire records from sections (Additional -> Authority -> Answers)
- Sets TC bit when truncation still necessary
- Does not cut at arbitrary byte boundaries

### TSIG Uses Constant-Time Comparison
**File:** internal/transfer/tsig.go:446
```go
if !hmac.Equal(tsigs.MAC, expectedMAC) {
```
- Uses `hmac.Equal` for MAC comparison to prevent timing attacks

### SHA-1 TSIG Algorithm Rejected
**File:** internal/transfer/tsig.go:470-472
- SHA-1 is explicitly rejected with error message directing to SHA-256/SHA-512

### Strong DNSSEC Algorithms Supported
**File:** internal/protocol/dnssec_dnskey.go:97-106
- Only RSA/SHA-256, RSA/SHA-512, ECDSA P-256/SHA-256, and ED25519 are marked as supported
- Weak algorithms (MD5, DH, DSA, SHA-1) are marked as NOT RECOMMENDED

### No External Process Spawning
- No `os/exec`, `syscall.Exec`, or similar patterns found in the codebase
- No eval-like string parsing that could lead to code injection

### No Serialization of Untrusted Data
- Uses Go's native types with no custom serialization of untrusted input
- No `encoding/gob`, `gob.Encode`, or similar deserialization of attacker-controlled data

---

## Summary

| Category | Finding | Severity |
|----------|---------|----------|
| Zone Transfer | Unrestricted AXFR when no allowlist | Critical |
| DNSSEC | No validation implemented | High |
| Privacy | QNAME minimization disabled by default | High |
| Spoof Resistance | 0x20 encoding disabled by default | High |
| Zone Transfer | TSIG optional when no keys configured | Medium |
| DDOS | No rate limiting on DDNS updates | Medium |
| DNSSEC | NSEC3 iterations not validated | Medium |
| Resource Limits | No per-section record limits during unpack | Low |
| Availability | IXFR journal in-memory only | Low |

**Build Status:** `go build ./...` completed successfully with no errors.

**Overall Assessment:** The implementation shows good security practices in some areas (pointer depth limits, crypto rand for TXIDs, constant-time MAC comparison), but has significant gaps in default-secure configuration (AXFR allowlist, QNAME minimization, 0x20 encoding) and critical missing security features (DNSSEC validation). The zone transfer access control defaults are particularly concerning for production deployments.
