# NothingDNS Go Security Audit Report

**Date:** 2026-04-09
**Auditor:** Claude Code Security Analysis
**Language:** Go
**Coverage:** DNS wire protocol parsing, YAML configuration, zone file parsing, caching, upstream resolution, cluster communication

---

## Executive Summary

The NothingDNS codebase demonstrates strong security awareness with proper use of cryptographic functions for DNS transaction security, comprehensive bounds checking in wire format parsing, and defensive programming patterns including panic recovery in handlers. No critical or high-severity vulnerabilities were identified. A few minor observations are documented below for completeness.

---

## Findings

### 1. math/rand Usage in Raft Module (Non-Critical)

**CWE ID:** CWE-338 (Use of Predictable Algorithm in a Security Context)

**File:** `internal/cluster/raft/rng.go:4-17`

**Description:**
The Raft consensus implementation uses `math/rand` for random number generation in `LockedRand`. The seed is initialized from `rand.Int63()` which itself is not cryptographically random.

```go
func NewLockedRand() *LockedRand {
    return &LockedRand{
        rng: rand.New(rand.NewSource(rand.Int63())),
    }
}
```

**Analysis:**
- **Confidence:** False Positive (for security context)
- **Severity:** Low
- **Justification:** Raft uses this for non-deterministic leader election tie-breaking (leader candidate selection). This is not a security-sensitive operation - it does not affect cryptographic keys, session tokens, or authentication. Raft's safety guarantee does not depend on unpredictability of these random values.
- **Recommendation:** Acceptable for Raft consensus operations. If future-proofing is desired, could use `crypto/rand` but it is not necessary.

---

### 2. NAPTR Regexp Field Not Validated for ReDoS

**CWE ID:** CWE-1333 (Regular Expression Denial of Service)

**File:** `internal/protocol/types.go:993, 1044-1054, 1109-1118`

**Description:**
The NAPTR record's Regexp field is stored as a raw string and could contain complex regular expressions that may cause ReDoS when processed by downstream consumers.

```go
type RDataNAPTR struct {
    Order       uint16
    Preference  uint16
    Flags       string
    Service     string
    Regexp      string   // <-- Not validated
    Replacement *Name
}
```

**Analysis:**
- **Confidence:** Possible
- **Severity:** Low
- **Justification:** The Regexp field is stored but not compiled or executed within the NothingDNS codebase itself. It is only transmitted as part of DNS zone transfers. However, if downstream systems process this regexp without validation, it could pose a risk.
- **Recommendation:** Consider adding a note in documentation that NAPTR regexps should be validated before compilation by consuming applications.

---

### 3. sync.Pool Buffer Management (Correct Pattern)

**CWE ID:** N/A

**Files:**
- `internal/protocol/wire.go:216-246`
- `internal/upstream/client.go:351-450`

**Description:**
The codebase uses `sync.Pool` for efficient buffer reuse across goroutines. The implementation correctly follows the documented pattern of zeroing buffers before returning them to the pool.

**Analysis:**
- **Confidence:** N/A (Correct Implementation)
- **Severity:** None
- **Observation:** The code properly handles sync.Pool by:
  1. Resetting buffers before returning to pool (`for i := range buf { buf[i] = 0 }`)
  2. Using `PutBufferSized` to discard oversized buffers
  3. Using `sync.Pool` only for byte slices, not complex structs

---

### 4. Panic Recovery in DNS Handlers (Correct Pattern)

**CWE ID:** N/A

**Files:**
- `internal/server/handler.go:91-98`
- `cmd/nothingdns/handler.go:77-84`
- `internal/quic/doq.go:351`
- `internal/transfer/slave.go:198-370`
- `internal/cluster/raft/raft.go:735-984`

**Description:**
The codebase properly uses `defer/recover` patterns in goroutines and DNS handlers to prevent panics from crashing the server. All panic recovery handlers return SERVFAIL or log the error appropriately.

**Analysis:**
- **Confidence:** N/A (Correct Implementation)
- **Severity:** None
- **Observation:** The code correctly:
  1. Uses deferred recover() in all goroutines
  2. Returns SERVFAIL responses on panic in DNS handlers
  3. Logs recovered panics for debugging

---

### 5. SHA-1 Usage in DNSSEC (Required by RFC)

**CWE ID:** N/A

**Files:**
- `internal/dnssec/crypto.go:506,513`
- `internal/dnssec/validator.go:815`
- `internal/dnssec/trustanchor.go:425`

**Description:**
The codebase uses SHA-1 in DNSSEC operations (NSEC3 and DS digest).

**Analysis:**
- **Confidence:** N/A (Not a Vulnerability)
- **Severity:** None
- **Justification:** SHA-1 is REQUIRED by RFC 5155 for NSEC3 and by RFC 4034 for DS digest calculation. These are not uses of SHA-1 for collision resistance but for DNSSEC protocol compliance. The `#nosec G505` comments indicate intentional acceptance of this.
- **Recommendation:** No change needed. This is correct per DNS protocol specifications.

---

### 6. crypto/rand Correctly Used for Security-Sensitive Operations

**CWE ID:** N/A

**Files:**
- `internal/resolver/resolver.go:22-30` (DNS transaction IDs)
- `internal/auth/auth.go:92` (JWT signing)
- `internal/dnscookie/cookie.go:14` (Cookie generation)
- `internal/cluster/node.go:205` (Node ID generation)
- `internal/odoh/odoh.go:11` (HPKE nonce generation)

**Description:**
The codebase correctly uses `crypto/rand` for all security-sensitive random number generation including DNS transaction IDs, authentication tokens, and cryptographic nonces.

```go
func nextSecureID() uint16 {
    var b [2]byte
    if _, err := cryptorand.Read(b[:]); err != nil {
        panic("crypto/rand unavailable: " + err.Error())
    }
    return binary.BigEndian.Uint16(b[:])
}
```

**Analysis:**
- **Confidence:** N/A (Correct Implementation)
- **Severity:** None
- **Observation:** Proper use of `crypto/rand` with panic on failure for transaction ID generation.

---

### 7. Path Traversal Prevention in Zone File $INCLUDE

**CWE ID:** CWE-22 (Path Traversal)

**File:** `internal/zone/zone.go:352-383`

**Description:**
The zone file parser implements explicit path traversal checks for `$INCLUDE` directives:

```go
func (p *parser) handleInclude(args []string) error {
    // SECURITY: Check for path traversal in the include path itself
    if strings.Contains(includeFile, "..") {
        return fmt.Errorf("$INCLUDE path traversal attempt blocked: %s", includeFile)
    }
    // ... additional validation
}
```

**Analysis:**
- **Confidence:** Confirmed
- **Severity:** None
- **Observation:** Proper path traversal prevention with explicit checks and zone directory boundary validation.

---

### 8. No Command Injection Vulnerabilities Found

**CWE ID:** CWE-78 (OS Command Injection)

**Analysis:**
- **Confidence:** Confirmed
- **Severity:** None
- **Observation:** Comprehensive grep search found no usage of `os/exec` or `exec.Command` in the codebase. The project correctly avoids shell execution.

---

### 9. Buffer Bounds Checking in Wire Protocol Parsing

**CWE ID:** CWE-120 (Buffer Over-read), CWE-125 (Buffer Over-read)

**Files:**
- `internal/protocol/wire.go:338-359`
- `internal/protocol/labels.go:254-336`
- `internal/protocol/message.go:204-271`

**Description:**
The DNS wire format parser implements comprehensive bounds checking before every memory access:

```go
func UnpackMessage(buf []byte) (*Message, error) {
    if len(buf) < HeaderLen {
        return nil, ErrBufferTooSmall
    }
    // ... each read operation checks bounds first
}
```

**Analysis:**
- **Confidence:** Confirmed
- **Severity:** None
- **Observation:** Excellent bounds checking throughout the protocol parsing code. All buffer accesses are preceded by length validation.

---

### 10. DNS Compression Pointer Loop Detection

**CWE ID:** CWE-835 (Loop with Unreachable Exit Condition)

**File:** `internal/protocol/labels.go:286-288, 416-419`

**Description:**
The name unpacking code implements protection against DNS compression pointer loops:

```go
if ptrDepth >= MaxPointerDepth {
    return nil, 0, ErrPointerTooDeep
}
```

**Analysis:**
- **Confidence:** Confirmed
- **Severity:** None
- **Observation:** Proper detection of compression pointer loops with configurable maximum depth (10) prevents infinite loops.

---

## Summary

| Category | Status | Notes |
|----------|--------|-------|
| Error Handling | Pass | Panic recovery properly implemented |
| Concurrency | Pass | sync.Pool, mutex patterns correct |
| Memory Safety | Pass | Comprehensive bounds checking |
| Command Injection | Pass | No os/exec usage found |
| Path Traversal | Pass | Explicit checks in $INCLUDE |
| Crypto (IDs/nonces) | Pass | crypto/rand correctly used |
| Crypto (DNSSEC) | Pass | SHA-1 usage per RFC requirements |
| Regular Expression | Pass | Regexp field not auto-compiled |
| TOC/TOU | Pass | No file operations with user input |

## Recommendations

1. **Accept** the `math/rand` usage in Raft - it is appropriate for non-security-critical consensus operations.

2. **Consider** adding validation note in documentation for NAPTR regexps if consumed by external applications.

3. **No security fixes required** based on this audit.

---

*Report generated by Claude Code security analysis. For questions, contact the security team.*
