# Security Audit: WebSocket and DoS Vulnerabilities

**Target:** NothingDNS codebase
**Date:** 2026-04-09
**Auditor:** Security Code Review
**Confidence:** High (code analysis of reviewed files)

---

## Executive Summary

This audit focuses on WebSocket security and Denial of Service vulnerabilities in NothingDNS. Multiple issues were identified ranging from missing origin validation to unbounded resource allocation.

---

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 3 |
| Medium | 4 |
| Low | 2 |

---

## Detailed Findings

### 1. WebSocket Origin Header Not Validated

**CWE ID:** CWE-346 (Origin Validation Error)

**File:** `internal/websocket/websocket.go:31-82`

**Description:**
The WebSocket handshake implementation does not validate the `Origin` HTTP header. Per RFC 6454 and RFC 6455 Section 4.2.1.10, servers should validate the Origin header to prevent Cross-Site WebSocket Hijacking attacks. Without origin validation, malicious websites can establish WebSocket connections to the NothingDNS dashboard on behalf of users.

**Vulnerable Code:**
```go
// Handshake performs the WebSocket upgrade handshake. On success the response
// writer has been hijacked and the caller can use ReadMessage/WriteMessage.
func Handshake(w http.ResponseWriter, r *http.Request) (*Conn, error) {
    if !IsWebSocketRequest(r) {
        http.Error(w, "not a websocket request", http.StatusBadRequest)
        return nil, ErrNotWebSocket
    }
    // ... no Origin check ...
    key := r.Header.Get("Sec-WebSocket-Key")
    if key == "" {
        http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
        return nil, ErrNotWebSocket
    }
```

**Impact:**
An attacker could host a malicious page that forces a victim's browser to connect to the NothingDNS WebSocket endpoint, potentially reading query statistics or performing actions if the user is authenticated.

**Severity:** High

**Confidence:** High

**CVSS:** 7.5 (AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H) - Estimated

**Recommendation:**
Add origin validation to the `Handshake` function:
```go
func Handshake(w http.ResponseWriter, r *http.Request) (*Conn, error) {
    // Validate Origin header
    origin := r.Header.Get("Origin")
    if origin != "" && !isAllowedOrigin(origin) {
        http.Error(w, "forbidden", http.StatusForbidden)
        return nil, errors.New("websocket: origin not allowed")
    }
    // ... rest of handshake
}
```

---

### 2. No WebSocket Connection Limit

**CWE ID:** CWE-770 (Allocation of Resources Without Limits or Throttling)

**File:** `internal/dashboard/server.go:15-22, 139-154, 221-237`

**Description:**
The dashboard server has no maximum limit on the number of concurrent WebSocket clients. The `clients` map grows unbounded and no connection admission control exists. An attacker can open many WebSocket connections to exhaust server resources.

**Vulnerable Code:**
```go
type Server struct {
    mu            sync.RWMutex
    clients       map[*Client]struct{}  // No max size
    broadcastChan chan *QueryEvent
    stats         *DashboardStats
    enabled       bool
    wg            sync.WaitGroup
}

func NewServer() *Server {
    s := &Server{
        clients:       make(map[*Client]struct{}),
        // ... no connection limit
    }
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
    conn, err := websocket.Handshake(w, r)
    if err != nil {
        return
    }
    client := &Client{
        conn:   conn,
        send:   make(chan []byte, 256),
        closed: make(chan struct{}),
    }
    s.AddClient(client)  // No limit check
    s.ClientLoop(client)
}
```

**Impact:**
An attacker can exhaust file descriptors and memory by opening thousands of WebSocket connections.

**Severity:** High

**Confidence:** High

**CVSS:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H) - Estimated

**Recommendation:**
Add a connection limit:
```go
const MaxWebSocketClients = 1000

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
    s.mu.Lock()
    if len(s.clients) >= MaxWebSocketClients {
        s.mu.Unlock()
        http.Error(w, "too many connections", http.StatusServiceUnavailable)
        return
    }
    s.mu.Unlock()
    // ... rest of connection handling
}
```

---

### 3. WebSocket Read Timeout Too Long (5 Minutes)

**CWE ID:** CWE-400 (Uncontrolled Resource Consumption)

**File:** `internal/doh/wshandler.go:15-18`

**Description:**
The WebSocket read timeout is set to 5 minutes (`wsReadTimeout = 5 * time.Minute`). This is excessively long and allows slow-read attacks where a malicious client reads messages very slowly to hold connections open indefinitely.

**Vulnerable Code:**
```go
const (
    // wsReadTimeout is the maximum time to wait for a WebSocket message
    // before closing the connection.
    wsReadTimeout = 5 * time.Minute
)
```

**Impact:**
An attacker can hold thousands of connections open with minimal resources by sending bytes very slowly. This blocks legitimate clients from connecting.

**Severity:** Medium

**Confidence:** High

**CVSS:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L) - Estimated

**Recommendation:**
Reduce the read timeout to a more reasonable value:
```go
const wsReadTimeout = 30 * time.Second  // Or use TCPReadTimeout at 30s
```

---

### 4. No Write Deadline on WebSocket Connections

**CWE ID:** CWE-400 (Uncontrolled Resource Consumption)

**File:** `internal/doh/wshandler.go:50-88`

**Description:**
The WebSocket handler sets a read deadline but never sets a write deadline. If a client stops reading responses, the server can block indefinitely on writes, leading to resource exhaustion.

**Vulnerable Code:**
```go
for {
    // Set a read deadline to prevent hanging connections.
    if err := conn.SetReadDeadline(time.Now().Add(wsReadTimeout)); err != nil {
        return
    }
    // ... read and process message ...
    // No write deadline set!
    h.dnsHandler.ServeDNS(rw, query)
}
```

**Impact:**
A malicious client that stops reading can cause the server to block on writes, eventually exhausting goroutines.

**Severity:** Medium

**Confidence:** High

**CVSS:** 6.5 (AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H) - Estimated

**Recommendation:**
Set write deadlines before each write operation:
```go
if err := conn.SetWriteDeadline(time.Now().Add(TCPWriteTimeout)); err != nil {
    return
}
```

---

### 5. Dashboard WebSocket Has No Ping/Pong Heartbeat

**CWE ID:** CWE-833 (Deadlock)

**File:** `internal/dashboard/server.go:331-361`

**Description:**
The dashboard WebSocket client loop only reads messages but does not send ping frames to detect dead connections. Dead connections are only detected when attempting to write fails.

**Vulnerable Code:**
```go
func (s *Server) ClientLoop(client *Client) {
    defer func() {
        close(client.closed)
        client.closeSend.Do(func() { close(client.send) })
        s.RemoveClient(client)
        client.conn.Close()
    }()

    // Write loop
    go func() {
        for {
            select {
            case data := <-client.send:
                if err := client.conn.WriteMessage(1, data); err != nil {
                    return
                }
            case <-client.closed:
                return
            }
        }
    }()

    // Read loop - no heartbeat
    for {
        _, _, err := client.conn.ReadMessage()
        if err != nil {
            return
        }
    }
}
```

**Impact:**
Dead connections accumulate until write attempts detect them. This delays cleanup of dead connections and wastes server resources.

**Severity:** Low

**Confidence:** Medium

**CVSS:** 4.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L) - Estimated

**Recommendation:**
Implement a ping/pong heartbeat mechanism:
```go
const pingInterval = 30 * time.Second

// In ClientLoop read goroutine:
for {
    client.conn.SetReadDeadline(time.Now().Add(pingInterval * 2))
    _, _, err := client.conn.ReadMessage()
    if err != nil {
        return
    }
}
```

---

### 6. Unbounded RecentQueries List

**CWE ID:** CWE-770 (Allocation of Resources Without Limits or Throttling)

**File:** `internal/dashboard/server.go:53-64, 138-154`

**Description:**
The `RecentQueries` slice has a capacity limit of 100 entries but the `DashboardStats` struct initialization shows this is a fixed ring buffer. However, appends to this slice are unbounded in the `RecordQuery` function as it only trims from the front after reaching capacity.

**Vulnerable Code:**
```go
type DashboardStats struct {
    mu              sync.RWMutex
    Uptime          time.Time
    QueriesTotal    int64
    // ...
    RecentQueries   []*QueryEvent  // 100 entry ring buffer
}

// In RecordQuery:
s.stats.RecentQueries = append(s.stats.RecentQueries, event)
if len(s.stats.RecentQueries) > 100 {
    s.stats.RecentQueries = s.stats.RecentQueries[1:]
}
```

**Impact:**
The current implementation actually has a 100-entry limit which is reasonable. However, each `QueryEvent` contains strings that could be large (domain names up to 253 bytes). Under high query volume, string allocation could be significant.

**Severity:** Low

**Confidence:** High

**CVSS:** 3.7 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L) - Estimated (with 100 limit, this is acceptable)

**Recommendation:**
No immediate action needed. The 100-entry limit is reasonable.

---

### 7. Rate Limiter Does Not Account for Transport Protocol

**CWE ID:** CWE-799 (Improper Control of Interaction Frequency)

**File:** `internal/filter/ratelimit.go:11-88`, `cmd/nothingdns/handler.go:168-178`

**Description:**
The rate limiter operates at the DNS query level without distinguishing transport protocols. A client can send many queries over DoH/DoWS that are counted together with UDP/TCP queries, or a single WebSocket connection can multiplex unlimited queries through the same rate-limited bucket.

**Vulnerable Code:**
```go
// RateLimiter.Allow only checks client IP:
func (rl *RateLimiter) Allow(clientIP net.IP) bool {
    key := clientIP.String()  // Only uses IP, not protocol
    // ...
}

// In handler.go, all protocols use the same rate limiter:
if h.rateLimiter != nil && clientIP != nil {
    if !h.rateLimiter.Allow(clientIP) {
        // Rate limited
    }
}
```

**Impact:**
A client can bypass per-IP rate limits by using DoH/DoWS if the rate limiter is configured per-UDP/TCP transport only. Additionally, a single WebSocket connection can send unlimited queries that all count against the same IP's rate limit bucket.

**Severity:** Medium

**Confidence:** High

**CVSS:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L) - Estimated

**Recommendation:**
Consider implementing protocol-aware rate limiting or per-connection limits:
```go
func (rl *RateLimiter) Allow(clientIP net.IP, protocol string) bool {
    key := fmt.Sprintf("%s:%s", clientIP.String(), protocol)
    // ...
}
```

---

### 8. DoH/DoWS Protocol Field Always "https" or "wss"

**CWE ID:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

**File:** `internal/doh/handler.go:289-308`, `internal/doh/wshandler.go:122-141`

**Description:**
The `ClientInfo()` method for DoH and DoWS response writers always returns `"https"` or `"wss"` as the protocol, regardless of the actual transport used. This makes it impossible to apply different ACL/rate limit rules based on the actual protocol.

**Vulnerable Code:**
```go
// In dohResponseWriter.ClientInfo():
return &server.ClientInfo{
    Addr: &net.TCPAddr{
        IP:   ip,
        Port: parsePort(port),
    },
    Protocol: "https",  // Always "https" even if over HTTP/2
}

// In wsResponseWriter.ClientInfo():
return &server.ClientInfo{
    Addr: &net.TCPAddr{
        IP:   ip,
        Port: parsePort(port),
    },
    Protocol: "wss",  // Always "wss"
}
```

**Impact:**
Cannot distinguish between DoH/DoWS and plain DNS over TLS when applying security policies. ACL rules cannot specifically allow/deny DoH while allowing DNS-over-TLS.

**Severity:** Medium

**Confidence:** High

**CVSS:** 5.0 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N) - Estimated

**Recommendation:**
Use more specific protocol identifiers or pass the actual protocol through the response writer:
```go
Protocol: "doh"    // vs "https"
Protocol: "dows"   // vs "wss"
```

---

### 9. WebSocket Frame Size Limit May Be Bypassed

**CWE ID:** CWE-400 (Uncontrolled Resource Consumption)

**File:** `internal/websocket/websocket.go:183-185`

**Description:**
The frame size limit is 1MB (`1<<20`), but this is applied after reading the extended length prefix. If a client sends a frame with `payloadLen > 1<<20`, the `readFrame` function will first read 8 bytes for the extended length, then reject the frame. However, if masked frames are used, the mask key (4 bytes) is read before checking payload length, which is acceptable.

**Vulnerable Code:**
```go
if payloadLen > 1<<20 { // 1MB max frame
    return 0, nil, errors.New("websocket: frame too large")
}
```

**Impact:**
A malicious client could send frames with extended length prefixes indicating very large payloads, causing the server to allocate resources before rejecting. However, the check happens before the payload buffer allocation.

**Severity:** Low

**Confidence:** High

**CVSS:** 3.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L) - Estimated

**Recommendation:**
No changes needed. The implementation correctly checks before buffer allocation.

---

### 10. TCP Server Has Connection Limit But No Per-IP Limit

**CWE ID:** CWE-770 (Allocation of Resources Without Limits or Throttling)

**File:** `internal/server/tcp.go:32-33, 56-57, 93, 155-165`

**Description:**
The TCP server has a global connection limit (`TCPMaxConnections = 1000`) but no per-IP limit. A single attacker can open 1000 connections from one IP, blocking legitimate clients from other IPs.

**Vulnerable Code:**
```go
const (
    TCPMaxConnections = 1000
    // No TCPMaxConnectionsPerIP
)

type TCPServer struct {
    connSem chan struct{}  // Global only
}

// At connection acceptance:
select {
case s.connSem <- struct{}{}:
    atomic.AddUint64(&s.connectionsAccepted, 1)
default:
    // Too many connections globally - but no per-IP limit
    conn.Close()
}
```

**Impact:**
A single malicious IP can exhaust all TCP connection slots, preventing other clients from connecting.

**Severity:** High

**Confidence:** High

**CVSS:** 6.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H) - Estimated

**Recommendation:**
Implement per-IP connection tracking:
```go
type TCPServer struct {
    // ...
    perIPConns    map[string]int
    perIPConnMu   sync.Mutex
    maxConnsPerIP int  // e.g., 10
}

func (s *TCPServer) allowConnection(ip string) bool {
    s.perIPConnMu.Lock()
    defer s.perIPConnMu.Unlock()
    if s.perIPConns[ip] >= s.maxConnsPerIP {
        return false
    }
    s.perIPConns[ip]++
    return true
}
```

---

## Phase 1 Note: DoH/DoWS ACL/RateLimit Bypass

**Status:** NOT A VULNERABILITY

After thorough code analysis, the DoH and DoWS handlers do NOT bypass ACL or rate limiting. The handler chain is:

1. API server receives DoH/DoWS request
2. `doh.Handler.ServeHTTP()` or `doh.WSHandler.ServeHTTP()` is called
3. Handler calls `h.dnsHandler.ServeDNS(rw, query)`
4. `h.dnsHandler` is `&server.ServeDNSWithRecovery{Handler: dnsHandler}`
5. `dnsHandler` is the `integratedHandler` from `cmd/nothingdns/handler.go`
6. `integratedHandler.ServeDNS()` applies ACL check (line 144-158) and rate limit check (line 168-178)

Both DoH and DoWS use the same `integratedHandler` that includes ACL and rate limiting checks.

---

## Conclusion

The NothingDNS codebase has several security issues related to WebSocket and DoS resilience:

1. **Critical:** No WebSocket origin validation allows Cross-Site WebSocket Hijacking
2. **High:** No WebSocket connection limits enable connection exhaustion
3. **High:** No per-IP TCP connection limits enable single-IP DoS
4. **Medium:** 5-minute WebSocket read timeout enables slow-read attacks
5. **Medium:** No WebSocket write deadlines enable write blocking attacks
6. **Medium:** Rate limiter doesn't account for transport protocol differences

The DoH/DoWS bypass concern was determined to be unfounded after code review - both protocols correctly pass through the integrated handler with ACL and rate limiting.

---

## References

- RFC 6455 (WebSocket Protocol)
- RFC 6454 (The Web Origin Concept)
- CWE-346: Origin Validation Error
- CWE-400: Uncontrolled Resource Consumption
- CWE-770: Allocation of Resources Without Limits or Throttling
- CWE-799: Improper Control of Interaction Frequency
