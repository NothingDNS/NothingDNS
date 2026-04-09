# NothingDNS Architecture Map

## Entry Points

### cmd/nothingdns/main.go
The single binary entry point. Initializes all subsystems on startup:
- Cache manager (in-memory DNS cache with negative caching)
- Upstream resolver (recursive resolver with health checking)
- Zone manager (authoritative zone loading from BIND-format files)
- DNSSEC validator/signer
- Cluster manager (raft-based distributed consensus)
- Transfer manager (AXFR, IXFR, DDNS with TSIG)
- Auth store (RBAC: admin/operator/viewer, HMAC-SHA256 tokens)
- API server (REST + WebSocket dashboard)
- DoH server (DNS over HTTPS, RFC 8484)
- DoQ server (DNS over QUIC, RFC 9250)
- DoWS/ODoH servers (DNS over WebSocket / Oblivious DoH, RFC 9230)

SIGHUP triggers config reload and zone reloading.

---

## Trust Boundaries

```
Internet DNS queries
        |
        v
[ACL filter] --> Allow/Drop/Redirect
        |
        v
[Blocklist check] --> Block/Allow
        |
        v
[Rate Limiter (RRL)] --> Truncate/Allow
        |
        v
[Auth check (if configured)] --> Token validation for API/dashboard
        |
        v
[DNS Handler]
        |
        +-->[Recursive Resolution]--> Upstream DNS servers
        |
        +-->[Zone Lookup]--> Authoritative answers from loaded zones
        |
        +-->[Cache Lookup]--> Cached responses
        |
        v
[Response with EDNS0, DNSSEC]
```

---

## DNS Protocol Parsing Stack

### internal/protocol/header.go
DNS message header (12 bytes). Flags bitfield: QR, Opcode, AA, TC, RD, RA, Z, AD, CD, RCODE. Pack/Unpack via binary.BigEndian.

### internal/protocol/labels.go
Domain name encoding. Label compression with 2-byte pointers (0xC0 prefix). MaxPointerDepth=5 prevents compression loops. MaxLabelLength=63, MaxNameLength=255. Wire format: length-byte prefixed labels + terminating 0.

### internal/protocol/message.go
Full DNS message Pack/Unpack. Sections: Question, Answer, Authority, Additional. Compression map for packing. Truncate() removes whole records from end (record-boundary-aware, not byte-level cut).

### internal/zone/zone.go
BIND-format zone file parser. $INCLUDE (max depth 10), $GENERATE (max 65536 records), $ORIGIN, $TTL. Multi-line records via parenthesis. Quoted string handling.

---

## Transport Layer

### internal/server/udp.go
UDP DNS server. Worker pool (NumCPU * multiplier). EDNS0 truncation record-boundary-aware. Buffer pools for zero-alloc hot path.

### internal/server/tcp.go
TCP DNS server. Pipelining (16 concurrent in-flight queries). Connection limits (1000 global, 10 per IP). 65535 max message size. 30s read/write timeouts. EDNS0 Client Subnet extraction.

### internal/doh/handler.go (DNS over HTTPS, RFC 8484)
Wire format POST with application/dns-message content-type. JSON API via application/dns-json. GET uses base64.RawURLEncoding. 65535 body limit.

### internal/doh/wshandler.go (DNS over WebSocket)
Binary frames only (rejects text/continuation frames). 30s timeouts. Client info from HTTP RemoteAddr.

### internal/websocket/websocket.go
Custom RFC 6455 implementation. Origin validation. Sec-WebSocket-Key SHA1+base64 accept. 1MB max frame. Mask validation for client frames. Ping/pong.

---

## Security-Critical Components

### internal/auth/auth.go
HMAC-SHA256 token signing. Password hashing: 10000-iteration SHA256 key derivation with random 16-byte salt. VerifyPassword uses subtle.ConstantTimeCompare. Empty HMAC secret warning on startup (tokens forgeable if secret empty). Auto-generates secure random default admin password.

### internal/transfer/tsig.go
TSIG authentication (HMAC-SHA256/384/512). Time fudge window for replay prevention. Sign/Verify message integrity.

### internal/blocklist/blocklist.go
Hosts file format parsing. URL fetching with SSRF protection: HTTPS only, blocks 169.254.169.254 (AWS), metadata.google.internal (GCP), azure metadata, googleusercontent, private IPs (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16), loopback, link-local, RFC 4193. DNS resolution check for hostnames. Path traversal check for `..` in file paths.

### internal/filter/acl.go
CIDR-based ACL matching. IsAllowed() returns (bool, redirectTarget). Default allow when no rules.

### internal/resolver/resolver.go
Iterative resolver. QNAME minimization (RFC 7816). 0x20 encoding for response validation. MaxDepth=30, MaxCNAMEDepth=16. crypto/rand for secure ID selection (panics on failure).

---

## API Layer

### internal/api/server.go
40+ REST endpoints. CORS middleware validates Origin against AllowedOrigins (supports *). Auth via auth_token query param or Authorization Bearer header. RBAC: requireOperator(), requireAdmin(). Rate limiting: 5 login attempts, 5min lockout. JSON body limited to 65536 bytes. getClientIP() checks X-Forwarded-For, X-Real-IP, RemoteAddr.

### internal/dashboard/server.go
WebSocket streaming dashboard. MaxWebSocketClients=1000. Broadcast to all clients (non-blocking, drops if channel full). ClientLoop read/write split with 1-minute write deadline.

---

## Configuration

### internal/config/config.go
30+ subsystems. expandEnvVars() for ${VAR} and $VAR. Validate() runs 10+ validation functions. isValidIP, isValidHostname, isValidCIDR helpers. DefaultConfig().

### internal/config/parser.go
Custom YAML parser (recursive descent, zero external deps). advance() skips TokenComment automatically. ParseMapping, parseBlockSequence, parseFlowMapping.

---

## Key Constants

| Constant | Value | Location |
|----------|-------|----------|
| MaxLabelLength | 63 | labels.go |
| MaxNameLength | 255 | labels.go |
| MaxPointerDepth | 5 | labels.go |
| PointerMask | 0xC0 | labels.go |
| TCPMaxMessageSize | 65535 | tcp.go |
| TCPReadTimeout | 30s | tcp.go |
| TCPWriteTimeout | 30s | tcp.go |
| MaxGenerateRecords | 65536 | zone.go |
| MaxIncludeDepth | 10 | zone.go |
| TSIGFudgeWindow | 5min | tsig.go |
| MaxWebSocketClients | 1000 | dashboard.go |
| WSFrameMaxSize | 1MB | websocket.go |
| DoHMaxBodySize | 65535 | doh/handler.go |
| ODoHMaxBodySize | 4MB | odoh/odoh.go |
| LoginRateLimit | 5 attempts, 5min lockout | api/server.go |
