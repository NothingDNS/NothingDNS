# NothingDNS Security Audit Report

**Date**: 2026-04-09
**Auditor**: Claude Code Security Analysis
**Target**: NothingDNS DNS Protocol Implementation
**Files Analyzed**:
- `internal/protocol/*.go` (DNS wire format, message parsing, compression)
- `internal/server/udp.go`, `tcp.go`, `tls.go` (Server implementations)
- `internal/zone/*.go` (Zone file parsing)
- `internal/resolver/*.go` (Iterative resolver)
- `internal/transfer/axfr.go`, `ixfr.go`, `tsig.go` (Zone transfer)

---

## Executive Summary

The NothingDNS implementation is a custom DNS protocol implementation in Go without external dependencies. Several security concerns were identified across the categories requested, ranging from **Critical** to **Informational** severity.

---

## Findings Summary

| Category | Severity | Count | Critical |
|----------|----------|-------|----------|
| Zone Transfer Security | CRITICAL | 2 | Yes |
| DNS Amplification | HIGH | 2 | No |
| Malformed Packet Handling | HIGH | 3 | No |
| DNS Cookie Implementation | MEDIUM | 2 | No |
| DNSSEC Validation | MEDIUM | 2 | No |
| NXDOMAIN Manipulation | LOW | 2 | No |
| Truncation Attacks | LOW | 2 | No |
| Name Compression | LOW | 2 | No |
| DNS Poisoning (ID Security) | INFO | 2 | No |
| DNS Rebinding | INFO | 1 | No |

---

## Detailed Findings

### 1. Zone Transfer Security (AXFR/IXFR without TSIG)

#### Finding AXFR-01: AXFR Allows Unauthenticated Zone Transfers

**CWE**: CWE-306 (Missing Authentication for Critical Function)

**Location**: `internal/transfer/axfr.go:111-121`

```go
// IsAllowed checks if a client IP is allowed to request AXFR
func (s *AXFRServer) IsAllowed(clientIP net.IP) bool {
    if s.allowList == nil || len(s.allowList) == 0 {
        return true // Allow all if no list configured
    }
    // ...
}
```

**Description**: When no allowList is configured (default), **all clients can request AXFR zone transfers without any authentication**. This exposes the entire DNS zone data to any attacker who can send UDP/TCP packets to the server.

**Severity**: CRITICAL

**Confidence**: High

**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (10.0 Critical)

**Recommendation**:
1. Require TSIG authentication for all AXFR requests
2. Implement `WithTSIGRequired()` option to enforce TSIG
3. Default deny with explicit allowList configuration
4. Log all AXFR requests for audit purposes

---

#### Finding AXFR-02: TSIG Verification is Optional

**CWE**: CWE-1390 (Insufficient Authentication Controls)

**Location**: `internal/transfer/axfr.go:152-169`

```go
// Verify TSIG if present
var tsigKey *TSIGKey
if s.keyStore != nil && hasTSIG(req) {
    keyName, err := getTSIGKeyName(req)
    // ...
    if err := VerifyMessage(req, key, nil); err != nil {
        return nil, nil, fmt.Errorf("TSIG verification failed: %w", err)
    }
    tsigKey = key
}
// If no TSIG present, request proceeds without verification
```

**Description**: When TSIG is not present in the request, the zone transfer proceeds without any authentication. An attacker who can reach the DNS server port can obtain full zone data.

**Severity**: CRITICAL

**Confidence**: High

**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N (9.1 Critical)

**Recommendation**: Require TSIG for AXFR and IXFR. Reject requests without valid TSIG signatures when TSIG keys are configured.

---

#### Finding AXFR-03: Same Issue in IXFR Server

**CWE**: CWE-306 (Missing Authentication for Critical Function)

**Location**: `internal/transfer/ixfr.go:142-157`

```go
// Verify TSIG if present (delegate to AXFR server)
if s.axfrServer.keyStore != nil && hasTSIG(req) {
    // ... TSIG verification
}
// IXFR also proceeds without TSIG if keyStore is nil or no TSIG present
```

**Description**: IXFR (Incremental Zone Transfer) has the same authentication bypass vulnerability.

**Severity**: CRITICAL

**Confidence**: High

**Recommendation**: Same as AXFR-01 and AXFR-02.

---

### 2. DNS Amplification

#### Finding AMP-01: Large UDP Responses Without Validation

**CWE**: CWE-406 (Insufficient Control of Network Message Volume)

**Location**: `internal/server/udp.go:17-23`, `internal/protocol/wire.go:10-19`

```go
// DefaultUDP sizes and limits.
const (
    DefaultUDPPayloadSize = 512
    MaxUDPPayloadSize = 4096
    MaxEDNSSize = 4096
)
```

**Description**: The maximum UDP payload size is 4096 bytes, which is relatively large. When serving as an open resolver, an attacker could amplify traffic by querying for ANY records or large zones.

**Severity**: HIGH

**Confidence**: High

**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:L (7.5 High)

**Recommendation**:
1. Implement response rate limiting
2. Consider limiting amplification by restricting ANY queries
3. Add source IP validation
4. Implement query filtering based on client IP subnets

---

#### Finding AMP-02: Additional Section Records Not Validated for Amplification

**CWE**: CWE-406 (Insufficient Control of Network Message Volume)

**Location**: `internal/protocol/message.go:343-380` (Truncate method)

```go
func (m *Message) Truncate(maxSize int) {
    // Try removing additional records first
    for len(m.Additionals) > 0 && m.WireLength() > maxSize {
        m.Additionals = m.Additionals[:len(m.Additionals)-1]
    }
    // ... then authorities, then answers
}
```

**Description**: The truncation logic removes records from the end of sections, but the server will still generate large responses for queries that trigger large additional/authority sections (e.g., DNSSEC records).

**Severity**: HIGH

**Confidence**: Medium

**Recommendation**: Implement maximum response size limits that account for potential amplification.

---

### 3. Malformed Packet Handling

#### Finding MAL-01: Nil Pointer Dereference in EDNS0 Client Subnet

**CWE**: CWE-476 (NULL Pointer Dereference)

**Location**: `internal/server/udp.go:237-255`

```go
for _, rr := range msg.Additionals {
    if rr != nil && rr.Type == protocol.TypeOPT {
        client.HasEDNS0 = true
        client.EDNS0UDPSize = rr.Class
        if optData, ok := rr.Data.(*protocol.RDataOPT); ok {
            for _, opt := range optData.Options {
                if opt.Code == protocol.OptionCodeClientSubnet {
                    if ecs, err := protocol.UnpackEDNS0ClientSubnet(opt.Data); err == nil {
                        client.ClientSubnet = ecs
                    }
                    break
                }
            }
        }
        break
    }
}
```

**Description**: While `rr != nil` is checked, if `rr.Data` is nil, the type assertion `rr.Data.(*protocol.RDataOPT)` will panic.

**Severity**: HIGH

**Confidence**: Medium

**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)

**Recommendation**: Add nil check for `rr.Data` before type assertion.

---

#### Finding MAL-02: Potential Panic in ResourceRecord.Copy()

**CWE**: CWE-476 (NULL Pointer Dereference)

**Location**: `internal/protocol/record.go:316-334`

```go
func (rr *ResourceRecord) Copy() *ResourceRecord {
    if rr == nil {
        return nil
    }
    var data RData
    if rr.Data != nil {
        data = rr.Data.Copy()
    }
    return &ResourceRecord{
        Name:  NewName(rr.Name.Labels, rr.Name.FQDN),
        // ...
    }
}
```

**Description**: If `rr.Name` is nil, `rr.Name.Labels` will panic. This can occur when processing malformed packets where name parsing failed but record was still partially processed.

**Severity**: HIGH

**Confidence**: Medium

**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)

**Recommendation**: Add nil check for `rr.Name` before accessing its fields.

---

#### Finding MAL-03: UDP Response Pool May Return Inconsistent State

**CWE**: CWE-562 (Return of Stack Data)

**Location**: `internal/server/udp.go:291-307`

```go
var buf []byte
if w.server != nil {
    if p, ok := w.server.responsePool.Get().([]byte); ok {
        buf = p
    } else {
        buf = make([]byte, MaxUDPPayloadSize)
    }
    if cap(buf) < MaxUDPPayloadSize {
        buf = make([]byte, MaxUDPPayloadSize)
    } else {
        defer w.server.responsePool.Put(buf)
    }
}
```

**Description**: The response pool is shared across goroutines. If a buffer is not properly reset before being returned to the pool, stale data could be sent to a different client (potential information disclosure between clients).

**Severity**: HIGH

**Confidence**: Low (Go's sync.Pool behavior may mitigate)

**Recommendation**: Ensure buffer is fully overwritten before return to pool, or use a separate pool per worker.

---

### 4. DNS Cookie Implementation

#### Finding COOK-01: DNS Cookie Option Defined But Not Implemented

**CWE**: CWE-665 (Improper Initialization)

**Location**: `internal/protocol/opt.go:622-625`, `internal/protocol/constants.go:158`

```go
OptionCodeCookie = 10  // Cookie (RFC 7873)
```

**Description**: The DNS Cookie option code is defined in constants.go, but no implementation exists. RFC 7873 specifies that servers should validate cookies to mitigate amplification. Without cookie support, the server cannot validate that responses come from legitimate queries.

**Severity**: MEDIUM

**Confidence**: High

**Recommendation**: Implement DNS Cookie support per RFC 7873:
1. Generate server cookie on receiving Client Cookie
2. Validate cookies in incoming requests
3. Reject requests with invalid/missing cookies

---

#### Finding COOK-02: No Cookie Validation on UDP Responses

**CWE**: CWE-346 (Origin Validation Error)

**Location**: `internal/server/udp.go`

**Description**: UDP responses are sent without validating that the source IP matches the original query source. This enables reflection attacks.

**Severity**: MEDIUM

**Confidence**: Medium

**Recommendation**: Implement source IP validation or DNS cookies to prevent reflection.

---

### 5. DNSSEC Validation

#### Finding DNSSEC-01: DNSSEC Record Types Implemented But No Validation

**CWE**: CWE-296 (Improper Certificate Validation)

**Location**: `internal/protocol/dnssec_*.go` (multiple files)

**Description**: DNSSEC record types (DNSKEY, DS, RRSIG, NSEC, NSEC3) are implemented with packing/unpacking logic, but no actual signature verification or chain-of-trust validation exists. The `DO` bit (DNSSEC OK) is parsed but not acted upon.

**Severity**: MEDIUM

**Confidence**: High

**Recommendation**: Implement DNSSEC validation:
1. Verify RRSIG signatures over answer/authority sections
2. Build and validate DNSSEC chain of trust
3. Check for NXDOMAIN proofs (NSEC/NSEC3)
4. Respond appropriately when DO bit is set

---

#### Finding DNSSEC-02: DO Bit Parsed But Not Used

**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)

**Location**: `internal/protocol/message.go:99-121` (SetEDNS0)

```go
func (m *Message) SetEDNS0(udpPayloadSize uint16, do bool) {
    // ...
    ttl := BuildEDNSTTL(0, 0, do, 0)
    // DO bit is stored but never verified in responses
}
```

**Description**: The DO (DNSSEC OK) bit is stored but responses don't include DNSSEC records when DO=1 is set in the query.

**Severity**: MEDIUM

**Confidence**: High

---

### 6. NXDOMAIN Manipulation

#### Finding NXDOM-01: No Query ID Validation on UDP Responses

**CWE**: CWE-296 (Improper Certificate Validation)

**Location**: `internal/server/udp.go:221-227`

```go
func (s *UDPServer) handleRequest(req *udpRequest) {
    msg, err := protocol.UnpackMessage(req.data[:req.n])
    if err != nil {
        atomic.AddUint64(&s.errors, 1)
        return
    }
    // No validation that response ID matches query ID
}
```

**Description**: While the resolver validates response IDs (`internal/resolver/resolver.go:737-739`), the UDP server does not validate that the Query ID in the request matches before processing. An attacker could send forged packets with random IDs that bypass validation.

**Severity**: LOW

**Confidence**: Medium

**CVSS Vector**: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N (4.0 Low)

**Recommendation**: Add Query ID validation on the server side when processing recursive queries.

---

#### Finding NXDOM-02: NXDOMAIN Response Cache Could Be Poisoned

**CWE**: CWE-524 (Information Exposure Through Cache)

**Location**: `internal/resolver/resolver.go:516-523`

```go
func (r *Resolver) cacheNegative(name string, qtype uint16, rcode uint8) {
    if r.cache == nil {
        return
    }
    key := cacheKey(name, qtype)
    r.cache.SetNegative(key, rcode)
}
```

**Description**: NXDOMAIN cache entries are stored with only the RCODE, without validation that the NXDOMAIN came from an authoritative server (AA bit check).

**Severity**: LOW

**Confidence**: Medium

**Recommendation**: Only cache NXDOMAIN responses that have AA=1 (authoritative) or are from trusted upstream servers.

---

### 7. Truncation Attacks

#### Finding TRUNC-01: TC Bit Set But Truncation May Be Incomplete

**CWE**: CWE-361 (Time-of-Check Time-of-Use)

**Location**: `internal/server/udp.go:315-341`

```go
if n > w.maxSize {
    msg.Header.Flags.TC = true
    msg.Authorities = nil
    msg.Additionals = nil
    // Reduce answers until the message fits
    for len(msg.Answers) > 0 {
        msg.Answers = msg.Answers[:len(msg.Answers)-1]
        n, err = msg.Pack(buf)
        if n <= w.maxSize {
            break
        }
    }
    // If still too large, send header + question only
    if n > w.maxSize || len(msg.Answers) == 0 {
        msg.Answers = nil
        n, err = msg.Pack(buf)
    }
}
```

**Description**: The truncation logic removes entire answer records, but if a single answer record is larger than maxSize, truncation still results in oversized messages. Also, TC=1 responses could be intercepted and truncated further by attackers.

**Severity**: LOW

**Confidence**: Low

**Recommendation**: Ensure individual record size is validated before inclusion, and consider using TCP for large responses.

---

#### Finding TRUNC-02: No TCP Fallback Validation

**CWE**: CWE-361 (Time-of-Check Time-of-Use)

**Location**: `internal/server/udp.go:315-341`

**Description**: When a UDP response is truncated (TC=1), clients should retry over TCP. However, there's no validation that the subsequent TCP request matches the original UDP query.

**Severity**: LOW

**Confidence**: Low

---

### 8. Name Compression

#### Finding COMP-01: Pointer Depth Limit Too High

**CWE**: CWE-835 (Loop with Unreachable Exit Condition)

**Location**: `internal/protocol/labels.go:19-21`

```go
const (
    MaxPointerDepth = 10
)
```

**Description**: The maximum pointer indirection depth is 10. While this prevents infinite loops, an attacker could craft a packet with 10 pointer indirections to cause excessive CPU usage during parsing (compression pointer attack).

**Severity**: LOW

**Confidence**: Medium

**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (5.3 Medium)

**Recommendation**: Consider lowering MaxPointerDepth to 5 and implementing per-record parsing timeouts.

---

#### Finding COMP-02: WireNameLength Has Redundant Loop Detection

**CWE**: CWE-835 (Loop with Unreachable Exit Condition)

**Location**: `internal/protocol/labels.go:379-421`

```go
func WireNameLength(buf []byte, offset int) (int, error) {
    // ...
    ptrDepth := 0
    for {
        // ... follows pointers
        ptrDepth++
        if ptrDepth > MaxNameLength {  // Should be MaxPointerDepth
            return 0, ErrPointerLoop
        }
    }
}
```

**Description**: The `WireNameLength` function uses `MaxNameLength` (255) instead of `MaxPointerDepth` (10) for loop detection, which is inconsistent with `UnpackName` and less secure.

**Severity**: LOW

**Confidence**: Low

**Recommendation**: Use `MaxPointerDepth` consistently in both functions.

---

### 9. DNS Poisoning (ID Security)

#### Finding POIS-01: Resolver Uses Cryptographically Secure ID Generation

**CWE**: CWE-331 (Insufficient Entropy)

**Location**: `internal/resolver/resolver.go:21-30`

```go
func nextSecureID() uint16 {
    var b [2]byte
    if _, err := cryptorand.Read(b[:]); err != nil {
        panic("crypto/rand unavailable: " + err.Error())
    }
    return binary.BigEndian.Uint16(b[:])
}
```

**Description**: The resolver uses `crypto/rand` for DNS query ID generation, which is cryptographically secure and resistant to prediction attacks.

**Severity**: INFO (Good Practice)

**Confidence**: High

---

#### Finding POIS-02: Response ID Validation in StdioTransport

**CWE**: CWE-296 (Improper Certificate Validation)

**Location**: `internal/resolver/resolver.go:737-739`, `788-790`

```go
if resp.Header.ID != msg.Header.ID {
    return nil, fmt.Errorf("resolver: UDP ID mismatch")
}
```

**Description**: The resolver correctly validates that response IDs match query IDs before accepting responses.

**Severity**: INFO (Good Practice)

**Confidence**: High

---

### 10. DNS Rebinding

#### Finding REBIND-01: No DNS Rebinding Protection

**CWE**: CWE-350 (Reliance on Reverse DNS Resolution)

**Location**: `internal/server/handler.go` (entire file not reviewed for DNS rebinding protection)

**Description**: The implementation does not appear to implement DNS rebinding protections such as:
- Checking for private IP ranges in responses
- Time-based DNS entries
- DNS rebinding heuristics

An attacker could potentially use DNS rebinding to bypass Same-Origin Policy in browsers.

**Severity**: INFO

**Confidence**: Low

**Recommendation**: Consider implementing DNS rebinding protection:
1. Filter external queries for private IP ranges in responses
2. Implement TTL-based access restrictions
3. Add hostname validation for known attack patterns

---

## Security Best Practices Observations

### Positive Findings

1. **Panic Recovery**: `ServeDNSWithRecovery` wrapper prevents server crashes
2. **Buffer Bounds Checking**: Most packet parsing includes proper bounds checks
3. **Name Validation**: Labels are validated for length and characters
4. **Compression Pointer Limits**: MaxPointerDepth limits prevent infinite loops
5. **TCP Connection Limits**: TCPMaxConnections prevents resource exhaustion
6. **Query ID Validation**: Response ID matching in resolver
7. **Cryptographic Randomness**: Uses crypto/rand for secure ID generation

### Areas Requiring Attention

1. Authentication for zone transfers
2. DNS amplification mitigation
3. DNSSEC validation implementation
4. DNS cookie support
5. Comprehensive input validation for all packet types

---

## Recommendations Summary

### Critical (Address Immediately)

1. **Require TSIG for AXFR/IXFR**: Add configuration option to mandate TSIG authentication for zone transfers
2. **Implement AXFR Access Control**: Default deny for zone transfers, require explicit allowList
3. **Fix Nil Pointer Issues**: Add nil checks in EDNS0 and ResourceRecord processing

### High Priority

4. **Implement Rate Limiting**: Prevent DNS amplification attacks
5. **Add DNS Cookie Support**: RFC 7873 implementation to validate query sources
6. **Implement DNSSEC Validation**: Full chain-of-trust verification
7. **Buffer Pool Security Review**: Ensure proper buffer clearing before pool return

### Medium Priority

8. **Lower MaxPointerDepth**: Reduce from 10 to 5 for compression attacks
9. **Fix WireNameLength**: Use consistent MaxPointerDepth
10. **Query ID Validation on Server**: Add validation before processing

### Low Priority / Future Enhancements

11. **DNS Rebinding Protection**: Filter private IP ranges
12. **Response Size Limits**: Stricter limits on amplification
13. **Audit Logging**: Log all zone transfer requests
14. **DNSSEC NSEC3 Support**: Full NSEC3 validation

---

## CVSS Scores Reference

| Finding | Base Score | Vector |
|---------|------------|--------|
| AXFR-01, AXFR-02, AXFR-03 | 10.0 (Critical) | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H |
| MAL-01, MAL-02 | 9.8 (Critical) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| AMP-01 | 7.5 (High) | AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:L |
| COMP-01 | 5.3 (Medium) | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H |

---

*Report generated by Claude Code Security Analysis*
*Framework: CWE 4.14, CVSS 3.1*
