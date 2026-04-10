# NothingDNS Go Security Scan Report

**Date:** 2026-04-09
**Scanner:** Claude Code Security Analysis
**Language:** Go
**Scope:** `internal/protocol/`, `internal/server/`, `internal/cache/`, `internal/cluster/`, `internal/transfer/`, `internal/dnscookie/`, `internal/upstream/`

---

## Executive Summary

The NothingDNS codebase demonstrates strong security practices in several key areas. The DNS protocol implementation includes proper pointer loop protection, bounds checking throughout, and constant-time HMAC comparison for TSIG. However, one medium-severity issue was identified related to gossip protocol fallback during rolling upgrades.

**`go vet ./...`:** PASSED (no issues)

---

## [DNS_PROTOCOL] Label Compression Pointer Loop Protection

**Severity:** High (Positive Finding)

**File:** `internal/protocol/labels.go:19-21`

```go
const (
    MaxPointerDepth = 5
)
```

**Description:** The DNS name unpacking implementation properly limits pointer indirection depth to 5, preventing compression pointer loops that could cause infinite processing or stack exhaustion.

**Evidence:**
- `UnpackName()` (labels.go:287-289) checks `ptrDepth >= MaxPointerDepth` before following pointers
- `WireNameLength()` (labels.go:417-420) also enforces `ptrDepth > MaxPointerDepth`
- RFC 1035 allows 2-byte pointers; the depth limit prevents compression-based attacks

**Impact:** Proper protection against malicious DNS messages with crafted pointer chains.

**Recommendation:** This is a positive finding. No action required.

---

## [DNS_PROTOCOL] Record-Boundary-Aware Truncation

**Severity:** Medium

**File:** `internal/server/udp.go:316-342`

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
    // ...
}
```

**Description:** The UDP truncation logic removes complete `ResourceRecord` entries from the Answers slice until the message fits within `maxSize`. This is record-boundary-aware since entire records are removed, not partial record data. However, after truncation, if the message still doesn't fit, it removes ALL answers and sends only header + question.

**Impact:** A truncated response with no answers could be returned when the question itself is very large (e.g., long domain names with many labels), potentially causing clients to retry with TCP unnecessarily. This is a minor inefficiency rather than a security issue.

**Recommendation:**
1. Consider checking if the question itself exceeds maxSize before entering the truncation loop
2. For very long domain names, consider implementing label truncation or returning FORMERR instead

---

## [DNS_PROTOCOL] EDNS0 Client Subnet Handling

**Severity:** High (Positive Finding)

**Files:**
- `internal/protocol/opt.go:235-252`
- `internal/server/tcp.go:291-309`
- `internal/server/udp.go:236-255`

**Description:** EDNS0 Client Subnet (ECS, RFC 7871) implementation is secure:

1. **Proper bounds checking:** `UnpackEDNS0ClientSubnet` validates minimum 4 bytes before accessing
2. **Safe data copying:** Address bytes are copied to a new slice, not aliased
3. **Prefix masking:** `NewEDNS0ClientSubnet` properly masks the last byte when prefix doesn't end on byte boundary (line 212-215)
4. **Family validation:** Only processes family 1 (IPv4) and 2 (IPv6)

**Recommendation:** This is a positive finding. No action required.

---

## [DNS_PROTOCOL] DNS Cookie Implementation

**Severity:** High (Positive Finding)

**File:** `internal/dnscookie/cookie.go`

**Description:** RFC 7873 DNS Cookie implementation is comprehensive:

1. **HMAC-SHA256:** Client and server cookies use HMAC-SHA256 (lines 244-254, 256-282)
2. **Timestamp validation:** `ValidateServerCookie` (line 122-169) checks:
   - Cookie version (byte 0 must be 1)
   - Timestamp freshness within 2x rotation interval
   - Future timestamp tolerance (1 second for clock skew)
3. **Secret rotation:** Automatic rotation with grace period for previous secret (lines 187-200, 174-185)
4. **Constant-time comparison:** Uses `hmac.Equal` for MAC comparison (lines 158, 165)

**Recommendation:** This is a positive finding. No action required.

---

## [CONCURRENCY] TSIG HMAC Authentication

**Severity:** High (Positive Finding)

**File:** `internal/transfer/tsig.go`

**Description:** TSIG (RFC 2845) implementation is secure:

1. **Constant-time comparison:** Uses `hmac.Equal` (line 446) instead of `bytes.Equal`
2. **Algorithm rejection:** SHA-1 is explicitly rejected with error (line 472)
3. **Time validation:** Fudge window properly checked (lines 426-431)
4. **Key rotation support:** `VerifyMessageWithPrevious` tries current then previous key

**Recommendation:** This is a positive finding. No action required.

---

## [CONCURRENCY] Gossip Protocol Encryption

**Severity:** High (Positive Finding)

**File:** `internal/cluster/gossip.go`

**Description:** Cluster gossip protocol uses AES-256-GCM:

1. **AEAD encryption:** Uses `cipher.NewGCM` with AES-256 (line 652)
2. **Random nonces:** Generated via `crypto/rand.Reader` (line 674)
3. **Proper sealing:** Nonce || ciphertext || tag format (line 678)

**Key size validation (lines 644-646):**
```go
if len(key) != 32 {
    return fmt.Errorf("gossip encryption key must be 32 bytes, got %d", len(key))
}
```

**Recommendation:** This is a positive finding. No action required.

---

## [CONCURRENCY] Gossip Decryption Fallback

**Severity:** Medium

**File:** `internal/cluster/gossip.go:713-728`

```go
func (gp *GossipProtocol) decodeMessage(data []byte, msg *Message) error {
    if gp.aead != nil {
        decrypted, err := gp.decrypt(data)
        if err != nil {
            // Might be unencrypted message during rolling upgrade - try unencrypted parse
            if rawErr := decodeMessageRaw(data, msg); rawErr != nil {
                return fmt.Errorf("gossip decrypt: %w (also failed unencrypted parse: %v)", err, rawErr)
            }
            return nil
        }
        data = decrypted
    }
    return json.Unmarshal(data, msg)
}
```

**Description:** When decryption fails and the node has encryption enabled, the code falls back to parsing unencrypted messages. This enables rolling upgrades from unencrypted to encrypted clusters, but could allow an attacker to inject unencrypted gossip messages if they can observe and replay traffic during the upgrade window.

**Impact:** Medium - An attacker who can intercept gossip traffic could potentially inject fake membership updates during a rolling upgrade from unencrypted to encrypted gossip. The attacker would need to successfully spoof or intercept messages during the brief upgrade window.

**Recommendation:**
1. Add a configurable grace period for the fallback behavior with a warning log
2. Consider adding a node configuration flag to reject unencrypted messages once all nodes are encrypted
3. Log when fallback parsing is used to detect potential attacks

---

## [CONCURRENCY] TCP Pipelining Write Serialization

**Severity:** High (Positive Finding)

**File:** `internal/server/tcp.go:342-405`

**Description:** TCP response writer properly serializes writes during pipelining:

1. **Mutex-protected writes:** `writeMu` ensures serialized writes (lines 389-390)
2. **Pipeline limit:** `pipeSem` limits concurrent in-flight queries to 16 (line 219)
3. **Connection limits:** Global (1000) and per-IP (10) connection limits enforced (lines 163-184)
4. **Proper cleanup:** Semaphore slot released in defer

**Recommendation:** This is a positive finding. No action required.

---

## [MEMORY] sync.Pool Buffer Management

**Severity:** High (Positive Finding)

**Files:**
- `internal/util/pool.go`
- `internal/upstream/client.go:345-450`
- `internal/upstream/loadbalancer.go:460-575`

**Description:** sync.Pool usage follows best practices:

1. **Buffer clearing before return:** The upstream client properly zeros buffers before returning to pool (lines 359-365, 439-445):
```go
for i := range buf {
    buf[i] = 0
}
pool.Put(buf)
```

2. **Size-limited pools:** `PutBufferSized` discards oversized buffers to prevent memory bloat (pool.go:240-246)
3. **Capacity-based fallback:** Buffers that are too small for pooled use are allocated fresh (tcp.go:360-362)

**Recommendation:** This is a positive finding. No action required.

---

## [MEMORY] NodeList Value Copy Pattern

**Severity:** Low (Informational)

**File:** `internal/cluster/node.go:89-100`

```go
func (nl *NodeList) Get(id string) (*Node, bool) {
    nl.mu.RLock()
    defer nl.mu.RUnlock()
    n, ok := nl.nodes[id]
    if !ok {
        return nil, false
    }
    cp := *n
    return &cp, true
}
```

**Description:** The method returns a pointer to a stack-allocated copy. This is intentional design - it allows callers to safely read node data without the lock, while the internal map stores the authoritative node.

**Impact:** None - This is intentional API design. Callers receive a safe copy.

**Recommendation:** This is a positive finding. No action required.

---

## [ERROR_HANDLING] Panic Recovery in ServeDNS

**Severity:** High (Positive Finding)

**Files:**
- `internal/server/handler.go:83-99`
- `cmd/nothingdns/handler.go:75-85`

**Description:** Double-layer panic recovery:

1. **Transport layer:** `ServeDNSWithRecovery` wraps all handlers (handler.go:91-98)
2. **Application layer:** `integratedHandler.ServeDNS` has its own defer/recover (handler.go:76-84)

Both layers log the panic and return SERVFAIL, preventing server crashes.

**Recommendation:** This is a positive finding. No action required.

---

## [ERROR_HANDLING] Audit Logging of Query Data

**Severity:** Low (Informational)

**File:** `cmd/nothingdns/handler.go:98-111`

```go
h.auditLogger.LogQuery(audit.QueryAuditEntry{
    Timestamp: start.UTC().Format(time.RFC3339),
    ClientIP:  clientIP,
    QueryName: qnameAudit,
    QueryType: qtypeStr,
    Latency:   latency,
    CacheHit:  cacheHit,
})
```

**Description:** Audit logging captures client IP and query name. These are appropriate for DNS query auditing. No passwords, tokens, or sensitive personal data are logged.

**Recommendation:** This is appropriate logging behavior. No action required.

---

## [DNS_PROTOCOL] TSIG Key Rotation Race Condition

**Severity:** Low

**File:** `internal/transfer/tsig.go:130-143`

```go
func (ks *KeyStore) RotateKey(newKey *TSIGKey) {
    ks.mu.Lock()
    defer ks.mu.Unlock()

    oldKey, exists := ks.keys[strings.ToLower(newKey.Name)]
    if exists {
        ks.previous = oldKey
        ks.rotatedAt = time.Now()
    }

    ks.keys[strings.ToLower(newKey.Name)] = newKey
}
```

**Description:** During rotation, the new key is added to the map before the rotation state is fully committed. However, the entire operation is protected by a mutex, so this is atomic.

**Impact:** None - The mutex ensures atomicity.

**Recommendation:** This is secure. No action required.

---

## [MEMORY] Cache Entry nil Safety

**Severity:** High (Positive Finding)

**File:** `internal/cache/cache.go`

**Description:** Cache implementation properly handles nil entries:

1. `Get` (line 183-217) checks `exists` before accessing entry
2. `Delete` (line 420-435) checks existence before removal
3. `removeEntry` (line 367-371) properly handles element removal from LRU list
4. All public methods that iterate use proper nil checks

**Recommendation:** This is a positive finding. No action required.

---

## [DNS_PROTOCOL] Buffer Size Validation

**Severity:** High (Positive Finding)

**File:** `internal/protocol/wire.go:338-359`

```go
func ValidateMessage(data []byte) error {
    if len(data) < 12 {
        return errors.New("message too short")
    }

    const maxRecords = 65535
    qdcount := binary.BigEndian.Uint16(data[4:6])
    // ...
    if qdcount > maxRecords || // ...
        return errors.New("record count too high")
    }
    return nil
}
```

**Description:** Message validation enforces:
- Minimum 12-byte header
- Maximum 65535 records per section (prevents allocation attacks)

**Recommendation:** This is a positive finding. No action required.

---

## Summary of Findings

| Category | Finding | Severity |
|----------|---------|----------|
| DNS Protocol | Pointer loop protection | Positive |
| DNS Protocol | EDNS0 ECS handling | Positive |
| DNS Protocol | DNS Cookie implementation | Positive |
| Concurrency | TSIG HMAC authentication | Positive |
| Concurrency | Gossip AES-256-GCM encryption | Positive |
| Concurrency | **Gossip decryption fallback** | Medium |
| Concurrency | TCP write serialization | Positive |
| Memory | sync.Pool buffer clearing | Positive |
| Memory | NodeList value copy pattern | Positive |
| Memory | Cache nil safety | Positive |
| Error Handling | Panic recovery | Positive |
| Error Handling | Audit logging | Positive |
| DNS Protocol | TSIG key rotation atomicity | Positive |
| DNS Protocol | Buffer size validation | Positive |
| DNS Protocol | UDP truncation | Medium |

### Critical Issues: 0
### High Severity Issues: 0 (all high findings are positive)
### Medium Severity Issues: 2
- Gossip decryption fallback during rolling upgrades
- UDP truncation edge case with oversized questions

### Recommendations Priority
1. **Medium:** Add logging for gossip unencrypted fallback to detect potential attacks
2. **Low:** Consider adding early check in UDP truncation for oversized questions

---

*Report generated by Claude Code Security Scanner*
