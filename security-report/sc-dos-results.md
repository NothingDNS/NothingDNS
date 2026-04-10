# NothingDNS Security Scan: DoS and Rate Limiting Analysis

**Target:** D:\Codebox\PROJECTS\NothingDNS
**Date:** 2026-04-09
**Test Suite:** `go test ./... -short` - All tests pass

---

## 1. DNS Amplification

### [HIGH] EDNS0 Buffer Size Lower Bound Not Validated Before Use

**Severity:** High
**File:** `internal/server/handler.go:162-167`
**Location:** `ResponseSizeLimit()` function

**Description:**
The `ResponseSizeLimit()` function uses the client's advertised EDNS0 UDP buffer size without validating a minimum threshold. The check `client.EDNS0UDPSize > 512` only validates the lower bound, but does not sanitize the value before use.

```go
if client.HasEDNS0 && client.EDNS0UDPSize > 512 {
    if client.EDNS0UDPSize > 4096 {
        return 4096
    }
    return int(client.EDNS0UDPSize)
}
```

**Impact:**
A malicious client could advertise an EDNS0 buffer size of 513-4096 bytes, causing the server to send larger responses than necessary. While the cap at 4096 limits damage, the server still honors the client's requested size without additional validation. This could aid in DNS amplification attacks.

**Recommendation:**
Validate that the client's advertised EDNS0 size is within a reasonable range before using it:
- Minimum: 512 (RFC 1035 default)
- Maximum: 4096 (practical limit to avoid fragmentation)
- Consider adding validation that rejects malformed OPT records with unrealistic buffer sizes

---

## 2. Connection Exhaustion

### [LOW] TCP Connection Limits Properly Implemented

**Severity:** Low (Good Security)
**File:** `internal/server/tcp.go:32-36`, `tcp.go:162-184`

The TCP server correctly implements:
- Global connection limit: 1000 (`TCPMaxConnections`)
- Per-IP connection limit: 10 (`TCPMaxConnectionsPerIP`)

Both limits are properly enforced via semaphore and map tracking.

### [LOW] QUIC Connection Limits Properly Implemented

**Severity:** Low (Good Security)
**File:** `internal/quic/doq.go:29-33`, `doq.go:120`, `doq.go:248-254`

The DoQ server correctly implements:
- Global connection limit: 500 (`DoQMaxConnections`)
- Per-connection stream limit: 100 (`DoQMaxStreamsPerConnection`)
- Stream message size limit: 65535 bytes via `io.LimitReader`

---

## 3. Rate Limiting Bypass

### [CRITICAL] API Rate Limiter Memory Leak - cleanup() Never Called

**Severity:** Critical
**File:** `internal/api/server.go:229-250`, `server.go:252-259`

**Description:**
The `apiRateLimiter` struct has a `cleanup()` function (line 230) that removes stale entries to prevent memory growth, but this function is **never called** anywhere in the codebase.

```go
func newAPIRateLimiter() *apiRateLimiter {
    return &apiRateLimiter{
        requests:    make(map[string][]time.Time),
        maxReqs:     apiRateLimitMaxRequests,
        windowSecs:  apiRateLimitWindowSecs,
    }
}
```

**Impact:**
- Memory exhaustion: The `requests` map grows indefinitely as new IPs make requests
- Over time, this could consume significant memory, leading to OOM conditions
- The rate limiter itself becomes ineffective as memory grows, slowing lookups

**Recommendation:**
Call `cleanup()` periodically via a background goroutine or on each N requests:

```go
func (s *Server) periodicRateLimiterCleanup() {
    ticker := time.NewTicker(1 * time.Minute)
    for {
        select {
        case <-s.ctx.Done():
            return
        case <-ticker.C:
            s.apiRateLimiter.cleanup()
        }
    }
}
```

### [CRITICAL] Login Rate Limiter Memory Leak - cleanup() Never Called

**Severity:** Critical
**File:** `internal/api/server.go:65-150`

**Description:**
The `loginRateLimiter` tracks failed login attempts per IP in an unbounded `attempts` map. There is no cleanup mechanism for expired entries.

```go
type loginRateLimiter struct {
    mu       sync.Mutex
    attempts map[string]*loginAttempt
}
```

**Impact:**
- Memory exhaustion: Failed login attempts are recorded forever
- After lockout period expires, the IP entry remains in the map
- An attacker could deliberately trigger lockouts for many IPs to inflate memory

**Recommendation:**
Add cleanup for expired lockout entries:

```go
func (l *loginRateLimiter) cleanup() {
    l.mu.Lock()
    defer l.mu.Unlock()
    now := time.Now()
    for ip, attempt := range l.attempts {
        if now.After(attempt.lockedUntil) && attempt.count < loginMaxAttempts {
            delete(l.attempts, ip)
        }
    }
}
```

### [HIGH] X-Forwarded-For Header Spoofing Bypasses Rate Limiting

**Severity:** High
**File:** `internal/api/server.go:2582-2610`

**Description:**
The `getClientIP()` function trusts the `X-Forwarded-For` header without validation:

```go
func getClientIP(r *http.Request) string {
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        if idx := strings.Index(xff, ","); idx != -1 {
            xff = strings.TrimSpace(xff[:idx])
        }
        xff = strings.TrimSpace(xff)
        if net.ParseIP(xff) != nil {
            return xff
        }
    }
    // ...
}
```

This function is used by both `loginRateLimiter.checkRateLimit()` and `apiRateLimiter.checkRateLimit()`.

**Impact:**
- If the API server is behind a reverse proxy that doesn't sanitize X-Forwarded-For, attackers can spoof their IP address
- Rate limiting based on IP becomes ineffective
- Attackers can bypass per-IP login attempt limits and API rate limits
- Automated attacks can appear to come from different IPs by rotating the X-Forwarded-For header

**Recommendation:**
Only trust X-Forwarded-For when the request comes from a known proxy IP range:

```go
func (s *Server) getClientIP(r *http.Request) string {
    // Only use X-Forwarded-For if request is from trusted proxy
    if s.config.TrustedProxies.Contains(r.RemoteAddr) {
        if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
            // Extract first IP and validate
            // ...
        }
    }
    // Fall back to RemoteAddr
    // ...
}
```

### [HIGH] No Per-IP QUIC Connection Limiting

**Severity:** High
**File:** `internal/quic/doq.go:59-87`, `doq.go:248-254`

**Description:**
The DoQ server implements a global connection limit (500) but does not track or limit connections per IP. TCP has `TCPMaxConnectionsPerIP = 10`, but QUIC has no equivalent.

**Impact:**
A single attacker IP could establish all 500 QUIC connections, preventing legitimate clients from connecting.

**Recommendation:**
Add per-IP connection tracking similar to TCP:

```go
type DoQServer struct {
    // ... existing fields ...
    ipConnCount map[string]int
    ipConnMu    sync.Mutex
    // ...
}

const DoQMaxConnectionsPerIP = 10
```

### [MEDIUM] Login Rate Limiter Trivially Bypassed with IP Rotation

**Severity:** Medium
**File:** `internal/api/server.go:79-83`

**Description:**
The login rate limiter allows 5 attempts (`loginMaxAttempts = 5`) before lockout. An attacker with even a small botnet (10 IPs) can make 50 login attempts before any IP gets locked out.

**Impact:**
Brute force attacks on login endpoints become feasible with even modest IP rotation.

**Recommendation:**
Consider:
- Lowering the lockout threshold but shortening the lockout period
- Implementing progressive delays instead of hard lockouts
- Adding CAPTCHA after 2-3 failed attempts
- Implementing account-based lockout (username) in addition to IP-based

---

## 4. Resource Exhaustion

### [LOW] $GENERATE Limits Properly Implemented

**Severity:** Low (Good Security)
**File:** `internal/zone/zone.go:19-21`, `zone.go:443-448`

The zone parser correctly limits `$GENERATE` to 65536 records maximum (`maxGenerateRecords = 65536`), preventing memory exhaustion from maliciously large ranges.

### [LOW] $INCLUDE Depth Limits Properly Implemented

**Severity:** Low (Good Security)
**File:** `internal/zone/zone.go:15-17`, `zone.go:361-363`

The zone parser correctly limits `$INCLUDE` nesting to 10 levels (`maxIncludeDepth = 10`), preventing infinite recursion attacks.

### [LOW] Path Traversal Protection in $INCLUDE

**Severity:** Low (Good Security)
**File:** `internal/zone/zone.go:367-387`

The `$INCLUDE` handler properly validates paths:
- Blocks `..` traversal attempts
- Validates resolved paths stay within zone directory

### [LOW] Compression Pointer Loop Protection

**Severity:** Low (Good Security)
**File:** `internal/protocol/labels.go:19-21`, `labels.go:287-289`

The protocol package properly protects against compression pointer loops:
- `MaxPointerDepth = 5` limits pointer indirection
- Returns `ErrPointerTooDeep` when exceeded
- Also implemented in `WireNameLength()` for non-pointer paths

### [MEDIUM] TCP Message Length Validated After Reading Prefix

**Severity:** Medium
**File:** `internal/server/tcp.go:244-250`

**Description:**
TCP message length is validated after reading the 2-byte length prefix:

```go
msgLen := binary.BigEndian.Uint16(lengthBuf[:])
if msgLen == 0 || msgLen > TCPMaxMessageSize {
    atomic.AddUint64(&s.errors, 1)
    return
}
```

**Impact:**
An attacker could send a length prefix of 1-65534, causing the server to allocate that exact amount of memory before validation. However, this is limited by `TCPMaxMessageSize = 65535`.

**Recommendation:**
Consider adding a minimum message size check or validating the length prefix is reasonable for a DNS query.

---

## 5. Goroutine Leaks

### [LOW] Liveness Probe Properly Implemented

**Severity:** Low (Good Security)
**File:** `internal/api/server.go:657-679`

The liveness probe correctly detects goroutine leaks:
- Baseline captured at startup via `atomic.StoreInt64(&s.goroutineBaseline, int64(runtime.NumGoroutine()))`
- Threshold: 2x baseline (`if current > baseline*2`)
- Returns 503 Service Unavailable when threshold exceeded

---

## Summary of Findings

| Category | Finding | Severity | Status |
|----------|---------|----------|--------|
| DNS Amplification | EDNS0 lower bound not validated before use | High | Needs Fix |
| Connection Exhaustion | TCP limits properly implemented | Low | Good |
| Connection Exhaustion | QUIC limits properly implemented | Low | Good |
| Rate Limiting | API rate limiter cleanup() never called | Critical | Needs Fix |
| Rate Limiting | Login rate limiter cleanup() never called | Critical | Needs Fix |
| Rate Limiting | X-Forwarded-For spoofing bypasses rate limits | High | Needs Fix |
| Rate Limiting | No per-IP QUIC connection limiting | High | Needs Fix |
| Rate Limiting | Login limiter bypassed with IP rotation | Medium | Needs Fix |
| Resource Exhaustion | $GENERATE limits properly implemented | Low | Good |
| Resource Exhaustion | $INCLUDE depth limits properly implemented | Low | Good |
| Resource Exhaustion | Path traversal protection in $INCLUDE | Low | Good |
| Resource Exhaustion | Compression pointer loop protection | Low | Good |
| Resource Exhaustion | TCP message length validated | Medium | Acceptable |
| Goroutine Leaks | Liveness probe properly implemented | Low | Good |

## Test Results

```
go test ./... -short
ok  github.com/nothingdns/nothingdns/cmd/dnsctl        7.934s
ok  github.com/nothingdns/nothingdns/cmd/nothingdns   2.997s
ok  github.com/nothingdns/nothingdns/internal/api     5.533s
ok  github.com/nothingdns/nothingdns/internal/cache   19.446s
ok  github.com/nothingdns/nothingdns/internal/server   9.889s
ok  github.com/nothingdns/nothingdns/internal/quic    3.746s
ok  github.com/nothingdns/nothingdns/internal/zone     0.579s
... (all packages pass)
```

All tests pass. No regressions detected.
