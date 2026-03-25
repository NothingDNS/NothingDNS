# NothingDNS — Implementation Guide

> Technical implementation details for every module. This document serves as the engineering blueprint for Claude Code single-shot prompt generation.

---

## Table of Contents

1. [Project Bootstrap](#1-project-bootstrap)
2. [DNS Wire Protocol](#2-dns-wire-protocol)
3. [Protocol Listeners (Server Layer)](#3-protocol-listeners)
4. [Authoritative Engine](#4-authoritative-engine)
5. [Recursive Resolver](#5-recursive-resolver)
6. [DNSSEC Implementation](#6-dnssec-implementation)
7. [Zone Transfer](#7-zone-transfer)
8. [Dynamic DNS](#8-dynamic-dns)
9. [Filter Layer](#9-filter-layer)
10. [QUIC Implementation](#10-quic-implementation)
11. [Cluster Layer (Raft)](#11-cluster-layer-raft)
12. [Storage Layer](#12-storage-layer)
13. [Configuration System](#13-configuration-system)
14. [REST API](#14-rest-api)
15. [gRPC Inter-Node](#15-grpc-inter-node)
16. [MCP Server](#16-mcp-server)
17. [Web Dashboard](#17-web-dashboard)
18. [CLI Tool (dnsctl)](#18-cli-tool-dnsctl)
19. [Metrics & Observability](#19-metrics--observability)
20. [Shared Utilities](#20-shared-utilities)
21. [Testing Strategy](#21-testing-strategy)
22. [Build & Release Pipeline](#22-build--release-pipeline)
23. [Implementation Order & Dependencies](#23-implementation-order--dependencies)

---

## 1. Project Bootstrap

### 1.1 Go Module Initialization

```
go mod init github.com/ecostack/nothingdns
```

`go.mod` will contain ONLY the module declaration and Go version. No `require` block. No `go.sum` entries.

```go
module github.com/ecostack/nothingdns

go 1.22
```

### 1.2 Binary Entry Points

#### cmd/nothingdns/main.go
```go
// Main server binary. Responsibilities:
// 1. Parse CLI flags (--config, --version, --help)
// 2. Load & validate configuration
// 3. Initialize all subsystems based on config
// 4. Start protocol listeners
// 5. Start management APIs
// 6. Handle graceful shutdown (SIGINT, SIGTERM)
// 7. Handle config reload (SIGHUP)

// Initialization order:
// Logger → Config → Storage → ZoneStore → Cache → Filter →
// AuthEngine → Resolver → DNSSEC → Cluster → Listeners →
// API → Dashboard → MCP → Metrics

// Shutdown order (reverse):
// Metrics → MCP → Dashboard → API → Listeners →
// Cluster → DNSSEC → Resolver → AuthEngine → Filter →
// Cache → ZoneStore → Storage → Logger
```

#### cmd/dnsctl/main.go
```go
// CLI management tool. Responsibilities:
// 1. Parse subcommands (zone, record, cache, cluster, blocklist, dnssec, dig, config, server)
// 2. Connect to NothingDNS REST API
// 3. Execute commands and format output
// 4. Built-in dig functionality (direct DNS queries)

// No dependency on server internals — communicates only via REST API.
// Exception: `dnsctl dig` uses internal/protocol directly for DNS queries.
```

### 1.3 Global Constants & Types

```go
// internal/protocol/constants.go

// DNS opcodes
const (
    OpcodeQuery  = 0
    OpcodeIQuery = 1  // Inverse query (obsolete)
    OpcodeStatus = 2
    OpcodeNotify = 4  // RFC 1996
    OpcodeUpdate = 5  // RFC 2136
)

// DNS response codes
const (
    RcodeSuccess        = 0  // NOERROR
    RcodeFormatError    = 1  // FORMERR
    RcodeServerFailure  = 2  // SERVFAIL
    RcodeNameError      = 3  // NXDOMAIN
    RcodeNotImplemented = 4  // NOTIMP
    RcodeRefused        = 5  // REFUSED
    RcodeYXDomain       = 6  // Name exists when it should not
    RcodeYXRRSet        = 7  // RR set exists when it should not
    RcodeNXRRSet        = 8  // RR set that should exist does not
    RcodeNotAuth        = 9  // Not authorized
    RcodeNotZone        = 10 // Name not contained in zone
    RcodeBadSig         = 16 // TSIG signature failure
    RcodeBadKey         = 17 // Key not recognized
    RcodeBadTime        = 18 // Signature out of time window
)

// DNS record types (uint16)
const (
    TypeA          = 1
    TypeNS         = 2
    TypeCNAME      = 5
    TypeSOA        = 6
    TypePTR        = 12
    TypeMX         = 15
    TypeTXT        = 16
    TypeAAAA       = 28
    TypeSRV        = 33
    TypeNAPTR      = 35
    TypeOPT        = 41
    TypeDS         = 43
    TypeSSHFP      = 44
    TypeRRSIG      = 46
    TypeNSEC       = 47
    TypeDNSKEY     = 48
    TypeNSEC3      = 50
    TypeNSEC3PARAM = 51
    TypeTLSA       = 52
    TypeCAA        = 257
    TypeTSIG       = 250
    TypeAXFR       = 252
    TypeIXFR       = 251
    TypeANY        = 255
)

// DNS classes
const (
    ClassIN  = 1   // Internet
    ClassCH  = 3   // Chaos (version.bind)
    ClassANY = 255
)
```

---

## 2. DNS Wire Protocol

### 2.1 Message Structure

```go
// internal/protocol/message.go

type Message struct {
    Header     Header
    Questions  []Question
    Answers    []ResourceRecord
    Authority  []ResourceRecord
    Additional []ResourceRecord
}

// Marshal serializes Message to wire format.
// Uses a pooled byte buffer (sync.Pool) to avoid allocations.
// Implements DNS label compression during serialization.
func (m *Message) Marshal() ([]byte, error)

// Unmarshal deserializes wire format to Message.
// Handles label compression (pointer following with loop detection).
// Validates message structure (counts match actual sections).
func (m *Message) Unmarshal(data []byte) error

// Response creates a response message from a query.
// Copies ID, Question section, sets QR=1.
func (m *Message) Response() *Message
```

### 2.2 Header Parsing

```go
// internal/protocol/header.go

type Header struct {
    ID      uint16
    Flags   Flags
    QDCount uint16
    ANCount uint16
    NSCount uint16
    ARCount uint16
}

type Flags struct {
    QR     bool   // Query (0) or Response (1)
    Opcode uint8  // 4 bits
    AA     bool   // Authoritative Answer
    TC     bool   // Truncated
    RD     bool   // Recursion Desired
    RA     bool   // Recursion Available
    Z      bool   // Reserved (must be 0)
    AD     bool   // Authentic Data (DNSSEC)
    CD     bool   // Checking Disabled (DNSSEC)
    RCODE  uint8  // 4 bits
}

// Marshal: 12 bytes, big-endian
// Byte 0-1: ID
// Byte 2-3: Flags (bit-packed)
//   Bit 0:     QR
//   Bit 1-4:   Opcode
//   Bit 5:     AA
//   Bit 6:     TC
//   Bit 7:     RD
//   Bit 8:     RA
//   Bit 9:     Z
//   Bit 10:    AD
//   Bit 11:    CD
//   Bit 12-15: RCODE
// Byte 4-5: QDCount
// Byte 6-7: ANCount
// Byte 8-9: NSCount
// Byte 10-11: ARCount

// Implementation: Use encoding/binary.BigEndian for uint16 reads/writes.
// Flags: Manual bit manipulation with shifts and masks.
```

### 2.3 Question Section

```go
// internal/protocol/question.go

type Question struct {
    Name  Name    // Domain name (label sequence)
    Type  uint16  // QTYPE
    Class uint16  // QCLASS
}

// Wire format:
// - Name: sequence of labels (length-prefixed) ending with 0x00
// - Type: 2 bytes big-endian
// - Class: 2 bytes big-endian
```

### 2.4 Resource Records

```go
// internal/protocol/record.go

type ResourceRecord struct {
    Name  Name
    Type  uint16
    Class uint16
    TTL   uint32
    RData RData   // Interface for type-specific data
}

// RData is the interface all record type data implements.
type RData interface {
    Type() uint16
    Marshal() ([]byte, error)
    Unmarshal(data []byte, offset int, msg []byte) (int, error)
    String() string
}
```

### 2.5 Record Type Implementations

```go
// internal/protocol/types.go

// Each record type implements the RData interface.

type RDataA struct {
    Address [4]byte  // IPv4
}

type RDataAAAA struct {
    Address [16]byte // IPv6
}

type RDataCNAME struct {
    Target Name
}

type RDataMX struct {
    Preference uint16
    Exchange   Name
}

type RDataNS struct {
    NameServer Name
}

type RDataSOA struct {
    MName   Name    // Primary nameserver
    RName   Name    // Admin email (dot-encoded)
    Serial  uint32
    Refresh uint32
    Retry   uint32
    Expire  uint32
    Minimum uint32  // Negative TTL
}

type RDataTXT struct {
    Text []string  // Multiple <character-string>s
}
// Wire format: each string is length-prefixed (1 byte, max 255)
// Multiple strings concatenated within RDATA

type RDataSRV struct {
    Priority uint16
    Weight   uint16
    Port     uint16
    Target   Name
}

type RDataPTR struct {
    DomainName Name
}

type RDataCAA struct {
    Flags uint8
    Tag   string
    Value string
}

type RDataNAPTR struct {
    Order       uint16
    Preference  uint16
    Flags       string
    Service     string
    Regexp      string
    Replacement Name
}

type RDataSSHFP struct {
    Algorithm   uint8
    FPType      uint8
    Fingerprint []byte
}

type RDataTLSA struct {
    Usage        uint8
    Selector     uint8
    MatchingType uint8
    CertAssoc    []byte
}
```

### 2.6 DNS Label System

```go
// internal/protocol/labels.go

type Name struct {
    Labels []string // ["www", "example", "com"]
}

// Compression: During marshal, maintain a map[string]uint16 of
// previously written domain names → their byte offsets.
// When writing a name, check if suffix already exists.
// If so, write pointer (2 bytes: 0xC0 | offset_high, offset_low).

// Decompression: During unmarshal, when encountering 0xC0 prefix,
// follow pointer to offset. Track visited offsets to detect loops.
// Maximum pointer depth: 10 (prevent infinite loops).

type LabelCompressor struct {
    offsets map[string]uint16  // domain suffix → wire offset
}

func (c *LabelCompressor) WriteName(buf []byte, offset int, name Name) int
func DecompressName(data []byte, offset int) (Name, int, error)

// Name normalization:
// - Lowercase all labels (DNS is case-insensitive)
// - Remove trailing dot (root label implied)
// - Validate: each label max 63 bytes, total name max 253 bytes
// - No empty labels (except root)
```

### 2.7 EDNS(0)

```go
// internal/protocol/edns.go

type OPTRecord struct {
    UDPSize     uint16      // Requestor's UDP payload size
    ExtRcode    uint8       // Extended RCODE (upper 8 bits)
    Version     uint8       // EDNS version (must be 0)
    DO          bool        // DNSSEC OK flag
    Options     []EDNSOption
}

type EDNSOption struct {
    Code uint16
    Data []byte
}

// EDNS Client Subnet (RFC 7871)
type EDNSClientSubnet struct {
    Family        uint16  // 1=IPv4, 2=IPv6
    SourcePrefix  uint8
    ScopePrefix   uint8
    Address       []byte
}

// OPT is encoded as a pseudo-RR in Additional section:
// Name: root (0x00)
// Type: OPT (41)
// Class: UDP payload size
// TTL: Extended RCODE (8) | Version (8) | DO (1) | Z (15)
// RDATA: sequence of (Code:2, Length:2, Data:N) options

// Implementation notes:
// - Parse OPT from Additional section during Message.Unmarshal
// - Store as separate field in Message (not in Additional slice)
// - Generate OPT record for responses with appropriate values
// - Strip ECS option in privacy mode before forwarding
```

### 2.8 Wire Serialization Helpers

```go
// internal/protocol/wire.go

// Buffer pool to avoid allocations on hot path
var bufferPool = sync.Pool{
    New: func() interface{} {
        buf := make([]byte, 0, 4096)
        return &buf
    },
}

func GetBuffer() *[]byte   // Get from pool
func PutBuffer(buf *[]byte) // Return to pool

// Big-endian helpers wrapping encoding/binary
func PutUint16(b []byte, v uint16)
func PutUint32(b []byte, v uint32)
func Uint16(b []byte) uint16
func Uint32(b []byte) uint32

// Wire format validation
func ValidateMessage(data []byte) error  // Quick validation before full parse
```

---

## 3. Protocol Listeners

### 3.1 Common Handler Interface

```go
// internal/server/handler.go

// Handler processes DNS queries and returns responses.
type Handler interface {
    ServeDNS(ctx context.Context, req *protocol.Message, client ClientInfo) (*protocol.Message, error)
}

// ClientInfo carries per-query metadata.
type ClientInfo struct {
    RemoteAddr net.Addr
    Protocol   string    // "udp", "tcp", "dot", "doh", "doq"
    LocalAddr  net.Addr
    ReceivedAt time.Time
}

// QueryPipeline orchestrates the full query processing chain.
type QueryPipeline struct {
    acl          *filter.ACL
    ratelimiter  *filter.RateLimiter
    blocklist    *filter.Blocklist
    splithorizon *filter.SplitHorizon
    geodns       *filter.GeoDNS
    authEngine   *auth.Engine
    resolver     *resolver.Engine
    dnssec       *dnssec.Manager
    metrics      *metrics.Collector
}

// Process executes the full pipeline:
// 1. ACL check → REFUSED if denied
// 2. Rate limit check → drop or TC if exceeded
// 3. Blocklist check → NXDOMAIN/0.0.0.0 if blocked
// 4. Determine view (split-horizon) based on client IP
// 5. Route: authoritative (zone match) vs recursive
// 6. GeoDNS post-processing (if authoritative)
// 7. DNSSEC signing (if zone is signed)
// 8. EDNS processing (add OPT to response)
// 9. Metrics recording
func (p *QueryPipeline) Process(ctx context.Context, req *protocol.Message, client ClientInfo) (*protocol.Message, error)
```

### 3.2 UDP Listener

```go
// internal/server/udp.go

type UDPServer struct {
    conn       *net.UDPConn
    handler    Handler
    bufferSize int          // Default: 4096 (EDNS max)
    workers    int          // Goroutine count for processing
}

// Implementation strategy:
// 1. Single goroutine reads from UDPConn in a loop
// 2. For each packet, dispatch to worker goroutine pool
// 3. Worker: Unmarshal → Handler.ServeDNS → Marshal → WriteTo
//
// Optimization:
// - Use sync.Pool for receive/send buffers
// - Pre-allocate worker pool (bounded goroutines via semaphore channel)
// - If response > client's UDP size, set TC bit and truncate
//
// Error handling:
// - Malformed packet → log + drop (no response)
// - Handler error → SERVFAIL response
// - Write error → log + continue

func (s *UDPServer) Start(ctx context.Context) error
func (s *UDPServer) Shutdown(ctx context.Context) error
```

### 3.3 TCP Listener

```go
// internal/server/tcp.go

type TCPServer struct {
    listener    net.Listener
    handler     Handler
    idleTimeout time.Duration  // Default: 30s
    maxConns    int            // Default: 10000
}

// Implementation strategy:
// 1. Accept loop spawns goroutine per connection
// 2. Each connection: read loop (2-byte length prefix + DNS message)
// 3. Support pipelining (multiple queries on same connection)
// 4. Idle timeout per connection
// 5. Connection limit with semaphore
//
// Wire format:
// [2 bytes: message length (big-endian)] [N bytes: DNS message]
//
// The 2-byte prefix allows messages > 512 bytes (no EDNS needed for TCP).

func (s *TCPServer) Start(ctx context.Context) error
func (s *TCPServer) Shutdown(ctx context.Context) error
```

### 3.4 DoT Listener

```go
// internal/server/dot.go

type DoTServer struct {
    listener    net.Listener   // tls.Listen wrapping TCP
    handler     Handler
    tlsConfig   *tls.Config
    idleTimeout time.Duration
}

// Implementation:
// - Identical to TCP but wrapped in tls.Listen()
// - TLS 1.2 minimum, prefer TLS 1.3
// - Certificate from config (file or ACME)
// - Same 2-byte length prefix wire format as TCP
//
// TLS Config:
// - MinVersion: tls.VersionTLS12
// - PreferServerCipherSuites: true
// - CipherSuites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
// - NextProtos: not set (no ALPN for DoT)

func (s *DoTServer) Start(ctx context.Context) error
func (s *DoTServer) Shutdown(ctx context.Context) error
```

### 3.5 DoH Listener

```go
// internal/server/doh.go

type DoHServer struct {
    httpServer *http.Server
    handler    Handler
    path       string        // Default: "/dns-query"
}

// Implementation:
// - net/http server with TLS (HTTP/2 automatic with TLS)
// - Two content types:
//   a) application/dns-message (wire format) — RFC 8484
//      GET: ?dns=<base64url-encoded-query>
//      POST: body is raw DNS wire format
//   b) application/dns-json (JSON API, Google/Cloudflare compatible)
//      GET: ?name=example.com&type=A
//
// Processing:
// 1. Parse Content-Type / Accept header
// 2. Decode DNS query (base64url for GET, raw for POST, or JSON)
// 3. Handler.ServeDNS()
// 4. Encode response in requested format
// 5. Set Cache-Control based on min TTL in response
//
// HTTP/2 Server Push: Not used (not beneficial for DNS).
// Keep-alive: Default HTTP/2 behavior (multiplexed streams).

// JSON API format (Cloudflare-compatible):
type DoHJSONRequest struct {
    Name string `json:"name"`
    Type string `json:"type"`
    // Optional: cd, do, edns_client_subnet
}

type DoHJSONResponse struct {
    Status   int              `json:"Status"`
    TC       bool             `json:"TC"`
    RD       bool             `json:"RD"`
    RA       bool             `json:"RA"`
    AD       bool             `json:"AD"`
    CD       bool             `json:"CD"`
    Question []DoHJSONQuestion `json:"Question"`
    Answer   []DoHJSONAnswer   `json:"Answer,omitempty"`
}

func (s *DoHServer) Start(ctx context.Context) error
func (s *DoHServer) Shutdown(ctx context.Context) error
```

### 3.6 DoQ Listener

```go
// internal/server/doq.go

type DoQServer struct {
    listener *quic.Listener   // Our hand-written QUIC listener
    handler  Handler
}

// Implementation:
// - Uses internal/quic package (hand-written QUIC stack)
// - ALPN: "doq" (RFC 9250)
// - One DNS message per QUIC stream (unidirectional)
// - No 2-byte length prefix (QUIC provides framing)
// - 0-RTT for repeat clients
//
// Processing per stream:
// 1. Accept stream → read full stream content
// 2. Unmarshal DNS message
// 3. Handler.ServeDNS()
// 4. Marshal response → write to stream → close stream
//
// Error handling:
// - Connection-level errors → close connection with error code
// - Stream-level errors → reset stream

func (s *DoQServer) Start(ctx context.Context) error
func (s *DoQServer) Shutdown(ctx context.Context) error
```

---

## 4. Authoritative Engine

### 4.1 Zone Data Structure

```go
// internal/auth/zone.go

type Zone struct {
    Name       protocol.Name
    SOA        *protocol.ResourceRecord  // SOA record (always present)
    Serial     uint32                     // Current SOA serial
    Records    *RadixTree                 // Domain name → RRSet
    Delegations *RadixTree               // NS delegation points
    Wildcards   map[string]*RRSet        // Wildcard entries
    DNSSEC      *ZoneDNSSEC              // Signing config & keys (nil if unsigned)
    Primary     bool                      // true=primary, false=secondary
    mu          sync.RWMutex
}

// RadixTree: Trie indexed by reversed domain labels.
// Example: "www.example.com" → ["com", "example", "www"]
// This allows efficient longest-match for delegation and zone finding.
//
// Implementation: Hand-written radix tree with:
// - Node: children map[string]*Node, data *RRSet, isWildcard bool
// - Thread-safe: Zone-level RWMutex (read lock for queries, write lock for updates)

type RRSet struct {
    Records []protocol.ResourceRecord  // Same name+type+class
    // Sorted by type for efficient lookup
}

// Zone lookup algorithm:
// 1. Exact match: name exists in Records → return matching type
// 2. Delegation check: walk up from name, check Delegations → return referral
// 3. Wildcard match: closest encloser + *.encloser → synthesize
// 4. NXDOMAIN: no match found
```

### 4.2 BIND Zone File Parser

```go
// internal/auth/zonefile.go

type ZoneFileParser struct {
    origin Name           // Current $ORIGIN
    ttl    uint32         // Current $TTL
    prev   Name           // Previous owner name (for blank owner shorthand)
    lineno int
}

// Parse reads a BIND-format zone file and returns a Zone.
// Handles:
// - $ORIGIN directive: sets default domain suffix
// - $TTL directive: sets default TTL
// - $INCLUDE directive: recursive file inclusion
// - $GENERATE directive: range-based record generation
//   Example: $GENERATE 1-100 host-$ A 10.0.0.$
// - Parenthesized multi-line records (SOA commonly spans multiple lines)
// - Semicolon comments
// - Relative names (appended with $ORIGIN)
// - Absolute names (trailing dot)
// - Blank owner name (inherit from previous record)
// - @ shorthand (zone apex)
// - Class field (optional, defaults to IN)
// - TTL field (optional, defaults to $TTL)
//
// State machine approach:
// 1. Tokenize line (respecting parentheses and quotes)
// 2. Identify directive ($ORIGIN, $TTL, etc.) vs. record
// 3. For records: parse owner → [TTL] → [CLASS] → TYPE → RDATA
//    TTL and CLASS can appear in either order
// 4. Validate parsed record
// 5. Add to Zone

func ParseZoneFile(path string, origin Name) (*Zone, error)
func ParseZoneData(data []byte, origin Name) (*Zone, error)

// Export writes zone data back to BIND zone file format.
func ExportZoneFile(zone *Zone) []byte
```

### 4.3 Zone Store

```go
// internal/auth/zonestore.go

type ZoneStore struct {
    zones map[string]*Zone  // Zone name → Zone (normalized, lowercase)
    tree  *RadixTree        // For finding best matching zone
    mu    sync.RWMutex
}

// FindZone: Given a query name, find the most specific zone.
// Walk up labels: "www.sub.example.com" → try "sub.example.com" → "example.com"
// Returns: zone, remainingLabels, found
func (s *ZoneStore) FindZone(name protocol.Name) (*Zone, bool)

func (s *ZoneStore) AddZone(zone *Zone) error
func (s *ZoneStore) RemoveZone(name string) error
func (s *ZoneStore) GetZone(name string) (*Zone, bool)
func (s *ZoneStore) ListZones() []*Zone
```

### 4.4 Authoritative Query Engine

```go
// internal/auth/engine.go

type Engine struct {
    store *ZoneStore
}

// Resolve handles authoritative queries.
// Returns: response message, isAuthoritative bool
//
// Algorithm:
// 1. FindZone for query name
// 2. If no zone → return nil, false (not authoritative)
// 3. Walk zone tree for exact match
// 4. If CNAME found and query type != CNAME → follow chain (max 10)
// 5. If delegation NS found → return referral (AA=0, NS in authority, glue in additional)
// 6. If wildcard match → synthesize answer
// 7. If no match → NXDOMAIN with SOA in authority
// 8. If match but no type → NODATA with SOA in authority
// 9. Add additional section (A/AAAA for NS targets, MX targets)
// 10. Set AA=1
func (e *Engine) Resolve(ctx context.Context, req *protocol.Message, view string) (*protocol.Message, bool)
```

### 4.5 Wildcard Processing

```go
// internal/auth/wildcard.go

// Wildcard matching per RFC 4592:
// 1. Find closest encloser (longest existing ancestor)
// 2. Check if wildcard exists at *.closest_encloser
// 3. If yes, synthesize records with query name replacing *
// 4. For DNSSEC: include NSEC/NSEC3 proving no exact match + wildcard match
//
// Rules:
// - Wildcards only match when no exact match AND no delegation exists
// - Wildcard label (*) only valid as leftmost label
// - Wildcard does not match names at delegation points
// - Multiple wildcard levels: *.*.example.com NOT supported (only one level)

func FindWildcard(zone *Zone, name protocol.Name) (*RRSet, protocol.Name, bool)
```

---

## 5. Recursive Resolver

### 5.1 Resolver Engine

```go
// internal/resolver/engine.go

type Engine struct {
    cache     *Cache
    forwarders []Forwarder
    mode       ResolverMode    // Recursive | Forwarder | Hybrid
    authEngine *auth.Engine    // For hybrid mode
    rootHints  []net.UDPAddr   // Embedded root server addresses
    pool       *ConnPool       // Connection pool to upstream servers
}

type ResolverMode int
const (
    ModeRecursive ResolverMode = iota
    ModeForwarder
    ModeHybrid
)

// Resolve processes a recursive query.
//
// Hybrid mode flow:
// 1. Try authoritative engine first
// 2. If authoritative → return (already handled)
// 3. Check cache → return if fresh hit
// 4. If forwarder mode → forward to upstream
// 5. If recursive mode → iterate from root
func (e *Engine) Resolve(ctx context.Context, req *protocol.Message, client server.ClientInfo) (*protocol.Message, error)
```

### 5.2 Iterative Resolver

```go
// internal/resolver/iterator.go

type Iterator struct {
    cache     *Cache
    maxDepth  int           // Default: 20
    timeout   time.Duration // Per-query: 5s, total: 30s
}

// Iterate performs full recursive resolution from root hints.
//
// Algorithm:
// 1. Start with root hints as nameservers
// 2. Send query to best NS for the zone
// 3. If answer → done
// 4. If referral (NS delegation) → update NS list, repeat
// 5. If CNAME → follow (add to answer, re-query for target)
// 6. QNAME minimization: send only necessary labels at each hop
//    Root: query for "com." type NS
//    TLD: query for "example.com." type NS
//    Auth: query for "www.example.com." type A
//
// Security:
// - Bailiwick check: ignore records outside delegated zone
// - Source port randomization (crypto/rand)
// - Transaction ID randomization
// - 0x20 encoding: randomize case of QNAME, verify in response
// - Validate response matches query (ID, QNAME, QTYPE)

func (i *Iterator) Resolve(ctx context.Context, name protocol.Name, qtype uint16) (*protocol.Message, error)
```

### 5.3 Forwarder

```go
// internal/resolver/forwarder.go

type Forwarder struct {
    address   string
    protocol  string         // "udp", "tcp", "dot", "doh"
    pool      *ConnPool
    healthy   atomic.Bool
    latency   atomic.Int64   // Smoothed RTT in microseconds
}

// Forward sends query to upstream and returns response.
// Protocol handling:
// - UDP: single packet, retry with TCP on TC=1
// - TCP: 2-byte length prefix
// - DoT: TCP with TLS, 2-byte length prefix
// - DoH: HTTP POST with application/dns-message body
//
// Health checking:
// - Periodic SOA query to "." (root) every 30s
// - Mark unhealthy after 3 consecutive failures
// - Weighted selection based on latency

type ForwarderGroup struct {
    forwarders []*Forwarder
    zoneRules  map[string][]*Forwarder  // Per-zone forwarding rules
}

func (g *ForwarderGroup) Forward(ctx context.Context, req *protocol.Message, zone string) (*protocol.Message, error)
```

### 5.4 Cache

```go
// internal/resolver/cache.go

type Cache struct {
    entries   map[CacheKey]*CacheEntry
    lru       *LRUList                  // Doubly-linked list for eviction
    maxSize   int
    minTTL    uint32
    maxTTL    uint32
    negTTL    uint32
    serveStale bool
    staleTTL   uint32
    mu         sync.RWMutex
}

type CacheKey struct {
    Name  string   // Normalized, lowercase
    Type  uint16
    Class uint16
    DO    bool     // DNSSEC OK (separate entries for DNSSEC-validated)
}

type CacheEntry struct {
    Message    *protocol.Message
    InsertTime time.Time
    TTL        uint32          // Original TTL
    ExpiresAt  time.Time
    Stale      bool            // Expired but servable if serve-stale enabled
    lruElement *LRUElement
}

// Get returns cached response with adjusted TTLs.
// TTL adjustment: remaining = original - (now - insertTime)
// If TTL expired:
//   - serveStale && within staleTTL → return with TTL=30, trigger background refresh
//   - else → return nil (cache miss)
func (c *Cache) Get(key CacheKey) (*protocol.Message, bool)

// Set stores response in cache.
// TTL clamped to [minTTL, maxTTL].
// If cache full → evict LRU entry.
func (c *Cache) Set(key CacheKey, msg *protocol.Message)

// Prefetch checks entries nearing expiration and refreshes them.
// Runs as background goroutine.
// Threshold: if remaining TTL < 10% of original → prefetch.
func (c *Cache) StartPrefetcher(ctx context.Context, resolver func(CacheKey) (*protocol.Message, error))
```

### 5.5 Negative Cache

```go
// internal/resolver/negative.go

// Negative caching (RFC 2308):
// - NXDOMAIN: entire name does not exist → cache keyed by (QNAME, QTYPE)
// - NODATA: name exists but type doesn't → cache keyed by (QNAME, QTYPE)
// - TTL: minimum of SOA.Minimum and SOA.TTL from authority section
// - Capped by config negative-ttl
//
// Stored in same Cache as positive entries, with special CacheEntry flags.
// NXDOMAIN cached responses include SOA from authority section.
```

### 5.6 Root Hints

```go
// internal/resolver/hints.go

// Embedded root hints — hardcoded root server addresses.
// Updated periodically in source code.
// Can be overridden via config file.
//
// Format:
// var rootHints = []RootServer{
//     {Name: "a.root-servers.net", IPv4: "198.41.0.4", IPv6: "2001:503:ba3e::2:30"},
//     {Name: "b.root-servers.net", IPv4: "170.247.170.2", IPv6: "2801:1b8:10::b"},
//     ...all 13 root servers...
// }
//
// On startup: shuffle order for load distribution.
// Periodically (every 24h): re-query for NS of "." to update cache.
```

### 5.7 QNAME Minimization

```go
// internal/resolver/qname.go

// RFC 7816 QNAME Minimization:
// Instead of sending full QNAME to each nameserver in the chain,
// send only the labels needed for the current zone.
//
// Example: Resolving "www.sub.example.com" type A
// To root: query "com." type NS (only TLD label)
// To .com NS: query "example.com." type NS (add one label)
// To example.com NS: query "www.sub.example.com." type A (full query)
//
// Benefits: Privacy (intermediate servers see less of the full name)
// Fallback: If NS responds with NXDOMAIN when we sent partial name,
//           retry with full QNAME (some broken servers need it).

func MinimizeQName(fullName protocol.Name, currentZone protocol.Name) protocol.Name
```

---

## 6. DNSSEC Implementation

### 6.1 Signer (Authoritative)

```go
// internal/dnssec/signer.go

type Signer struct {
    keyStore *KeyStore
}

// SignZone signs all RRsets in a zone.
// For each unique (name, type, class) tuple:
// 1. Canonical sort records (RFC 4034 §6.3)
// 2. Create RRSIG covering the RRset
// 3. Sign with ZSK (for non-DNSKEY RRsets) or KSK (for DNSKEY RRset)
//
// NSEC chain generation:
// 1. Sort all names in zone (canonical order)
// 2. Create NSEC record for each name → next name
// 3. Last name's NSEC points back to zone apex (circular)
// 4. NSEC bitmap: list of types present at each name
//
// NSEC3 (if configured):
// 1. Hash each name with SHA-1 + salt + iterations
// 2. Sort hashed names
// 3. Create NSEC3 for each hash → next hash
// 4. Opt-out: skip unsigned delegations
//
// Online signing: Instead of pre-signing entire zone, sign RRsets on query.
// Trade-off: CPU cost per query vs. memory for pre-signed zone.
// Default: Online signing with RRSIG cache.

func (s *Signer) SignRRSet(rrset []protocol.ResourceRecord, key *SigningKey) (*protocol.ResourceRecord, error)
func (s *Signer) GenerateNSEC(zone *auth.Zone) []protocol.ResourceRecord
func (s *Signer) GenerateNSEC3(zone *auth.Zone, params NSEC3Params) []protocol.ResourceRecord
```

### 6.2 Validator (Recursive)

```go
// internal/dnssec/validator.go

type Validator struct {
    trustAnchors []*TrustAnchor  // Root DNSKEY (IANA root KSK)
}

// Validate verifies DNSSEC chain of trust for a response.
//
// Chain: root KSK → root DNSKEY → .com DS → .com DNSKEY → example.com DS → example.com DNSKEY → RRSIG
//
// Algorithm:
// 1. Start with root trust anchor (hardcoded IANA root KSK)
// 2. For each zone in delegation chain:
//    a. Fetch DNSKEY RRset for zone
//    b. Verify DNSKEY RRSIG using parent's DS record
//    c. Verify answer RRSIG using zone's DNSKEY (ZSK)
// 3. Result: Secure | Insecure | Bogus | Indeterminate
//
// Cached validation: Store validation result with cache entry.
// Set AD bit in response if validation succeeded.

type ValidationResult int
const (
    Secure        ValidationResult = iota  // Fully validated
    Insecure                               // Provably unsigned (DS absent)
    Bogus                                  // Validation failed
    Indeterminate                          // Cannot determine
)

func (v *Validator) ValidateResponse(ctx context.Context, msg *protocol.Message) (ValidationResult, error)
```

### 6.3 Key Management

```go
// internal/dnssec/keys.go

type SigningKey struct {
    Algorithm  uint8
    Flags      uint16       // 256=ZSK, 257=KSK
    PrivateKey crypto.Signer
    PublicKey  crypto.PublicKey
    KeyTag     uint16        // Calculated from DNSKEY RDATA
    Inception  time.Time
    Expiration time.Time
}

// internal/dnssec/keystore.go

type KeyStore struct {
    keysDir string
    keys    map[string][]*SigningKey  // Zone → keys
    mu      sync.RWMutex
}

// Key generation:
// - ECDSAP256SHA256: crypto/ecdsa with elliptic.P256()
// - ECDSAP384SHA384: crypto/ecdsa with elliptic.P384()
// - ED25519: crypto/ed25519
// - RSASHA256: crypto/rsa (2048 or 4096 bits)
//
// Key storage format:
// Private key: PEM-encoded PKCS#8
// Public key: DNSKEY RDATA format (flags + protocol + algorithm + public key bytes)
//
// Key rollover (prepublish method for ZSK):
// 1. Generate new ZSK
// 2. Publish new DNSKEY (both old and new active)
// 3. Wait: propagation time (2x zone TTL)
// 4. Sign with new ZSK
// 5. Wait: propagation time
// 6. Remove old DNSKEY
//
// KSK rollover requires parent DS update (manual or CDS/CDNSKEY).

func (ks *KeyStore) GenerateKey(zone string, algorithm uint8, flags uint16) (*SigningKey, error)
func (ks *KeyStore) GetActiveKeys(zone string) ([]*SigningKey, error)
func (ks *KeyStore) RotateZSK(zone string) error
```

### 6.4 Algorithms

```go
// internal/dnssec/algorithms.go

// All implemented using Go standard library crypto packages.
// No external dependencies.

// Sign creates a digital signature over data.
func Sign(key *SigningKey, data []byte) ([]byte, error) {
    switch key.Algorithm {
    case AlgRSASHA256:
        // crypto/rsa.SignPKCS1v15 with crypto.SHA256
    case AlgRSASHA512:
        // crypto/rsa.SignPKCS1v15 with crypto.SHA512
    case AlgECDSAP256SHA256:
        // crypto/ecdsa.Sign with crypto/sha256
        // Wire format: R || S (32 bytes each, zero-padded)
    case AlgECDSAP384SHA384:
        // crypto/ecdsa.Sign with crypto/sha512.New384
        // Wire format: R || S (48 bytes each, zero-padded)
    case AlgED25519:
        // crypto/ed25519.Sign (64-byte signature)
    }
}

// Verify validates a digital signature.
func Verify(key *SigningKey, data []byte, signature []byte) bool
```

---

## 7. Zone Transfer

### 7.1 AXFR

```go
// internal/transfer/axfr.go

// AXFR Server (primary side):
// 1. Receive AXFR query on TCP
// 2. Check ACL (allow-transfer)
// 3. Check TSIG if configured
// 4. Send: SOA → all records → SOA (bookend)
// 5. Multiple DNS messages (each within TCP length-prefix framing)
//
// AXFR Client (secondary side):
// 1. Send AXFR query to primary
// 2. Receive stream of records between two SOA bookends
// 3. Build new Zone object
// 4. Atomic swap with old zone data

type AXFRServer struct {
    zoneStore *auth.ZoneStore
    acl       *filter.ACL
    tsig      *TSIGManager
}

type AXFRClient struct {
    primary string        // Primary server address
    zone    string        // Zone name
    tsig    *TSIGManager
}

func (s *AXFRServer) HandleAXFR(conn net.Conn, req *protocol.Message) error
func (c *AXFRClient) Transfer(ctx context.Context) (*auth.Zone, error)
```

### 7.2 IXFR

```go
// internal/transfer/ixfr.go

// IXFR transfers only changes since a given serial.
// Wire format: SOA(new) → [SOA(old) → deletions → SOA(new) → additions]* → SOA(new)
//
// Relies on journal (Dynamic DNS update journal) to generate diffs.
// If journal doesn't cover the requested serial → fallback to AXFR.

type IXFRServer struct {
    zoneStore *auth.ZoneStore
    journal   *dynamic.Journal
}

type IXFRClient struct {
    primary string
    zone    string
    serial  uint32  // Current serial on secondary
}

func (s *IXFRServer) HandleIXFR(conn net.Conn, req *protocol.Message) error
func (c *IXFRClient) Transfer(ctx context.Context) ([]ZoneChange, error)
```

### 7.3 TSIG

```go
// internal/transfer/tsig.go

type TSIGManager struct {
    keys map[string]*TSIGKey  // Key name → key
}

type TSIGKey struct {
    Name      string
    Algorithm string  // "hmac-sha256", "hmac-sha512", "hmac-md5"
    Secret    []byte  // Base64-decoded shared secret
}

// TSIG record format (appended as additional record):
// Name: key name
// Type: TSIG (250)
// Class: ANY
// TTL: 0
// RDATA: algorithm, time signed, fudge, MAC size, MAC, original ID, error, other data
//
// Signing: HMAC over (request + TSIG variables)
// Verification: Recompute HMAC and compare

func (m *TSIGManager) Sign(msg *protocol.Message, keyName string) error
func (m *TSIGManager) Verify(msg *protocol.Message) (string, error)
```

---

## 8. Dynamic DNS

### 8.1 UPDATE Processing

```go
// internal/dynamic/update.go

type UpdateProcessor struct {
    zoneStore *auth.ZoneStore
    journal   *Journal
    tsig      *transfer.TSIGManager
    cluster   *cluster.Manager  // For replicating updates in cluster mode
}

// Process handles RFC 2136 DNS UPDATE messages.
//
// UPDATE message sections:
// - Zone section: specifies which zone to update
// - Prerequisite section: conditions that must be true
// - Update section: changes to apply
// - Additional section: TSIG for authentication
//
// Algorithm:
// 1. Find zone from Zone section
// 2. Authenticate (TSIG or ACL check)
// 3. Check prerequisites:
//    - RRset exists (value dependent)
//    - RRset exists (value independent)
//    - Name is in use
//    - RRset does not exist
//    - Name is not in use
// 4. If any prerequisite fails → NXRRSET/YXRRSET/NXDOMAIN/YXDOMAIN
// 5. Apply updates atomically:
//    - Add to an RRset
//    - Delete an RRset
//    - Delete all RRsets at a name
//    - Delete individual RR from RRset
// 6. Update SOA serial (serial = max(serial+1, unixtime))
// 7. Write to journal
// 8. If cluster mode → replicate via Raft
// 9. Send NOTIFY to secondaries

func (p *UpdateProcessor) Process(ctx context.Context, req *protocol.Message, client server.ClientInfo) (*protocol.Message, error)
```

### 8.2 Journal

```go
// internal/dynamic/journal.go

type Journal struct {
    dir     string
    entries map[string]*JournalFile  // Zone → journal file
    mu      sync.Mutex
}

type JournalEntry struct {
    Timestamp time.Time
    OldSerial uint32
    NewSerial uint32
    Deletions []protocol.ResourceRecord
    Additions []protocol.ResourceRecord
}

// Journal file format (binary):
// [4 bytes: magic "JRNL"]
// [4 bytes: version]
// Repeated:
//   [4 bytes: entry length]
//   [8 bytes: timestamp (unix nanos)]
//   [4 bytes: old serial]
//   [4 bytes: new serial]
//   [2 bytes: deletion count]
//   [N * RR: deletions]
//   [2 bytes: addition count]
//   [N * RR: additions]
//
// Used by IXFR to generate incremental transfers.
// Periodically compacted by merging into zone file.

func (j *Journal) Append(zone string, entry JournalEntry) error
func (j *Journal) GetChangesSince(zone string, serial uint32) ([]JournalEntry, error)
func (j *Journal) Compact(zone string, currentZone *auth.Zone) error
```

---

## 9. Filter Layer

### 9.1 Blocklist

```go
// internal/filter/blocklist.go

type Blocklist struct {
    domains   map[string]bool   // Exact domain matches (normalized)
    wildcards []string          // Wildcard patterns (*.ads.example.com)
    response  BlockResponse     // NXDOMAIN | Zero | Custom
    customIP  net.IP
    mu        sync.RWMutex
}

type BlockResponse int
const (
    BlockNXDOMAIN BlockResponse = iota
    BlockZeroIP
    BlockCustomIP
)

// Supported blocklist formats:
// 1. Domain list: one domain per line
// 2. Hosts file: "0.0.0.0 domain" or "127.0.0.1 domain"
// 3. Adblock format: "||domain^" (basic support)
//
// Loading:
// - Parse file(s) on startup
// - Periodic reload (configurable interval)
// - De-duplicate entries
// - Normalize domains (lowercase, remove trailing dot)
// - Comment lines (# or !) ignored
//
// Lookup: O(1) map lookup for exact match, O(N) for wildcards.
// Optimization: Wildcard domains stored in radix tree for suffix matching.

func (b *Blocklist) IsBlocked(name protocol.Name) bool
func (b *Blocklist) Load(paths []BlocklistSource) error
func (b *Blocklist) Reload() error
func (b *Blocklist) Add(domain string) error
func (b *Blocklist) Remove(domain string) error
func (b *Blocklist) Stats() BlocklistStats
```

### 9.2 ACL

```go
// internal/filter/acl.go

type ACL struct {
    rules   []ACLRule
    default_ ACLAction  // allow | deny
}

type ACLRule struct {
    Action  ACLAction
    Source  []*net.IPNet   // CIDR ranges
    Zones   []string       // Optional: restrict to specific zones
}

type ACLAction int
const (
    ACLAllow ACLAction = iota
    ACLDeny
)

// Evaluation: First matching rule wins.
// If no rule matches → apply default action.
func (a *ACL) Check(clientIP net.IP, zone string) ACLAction
```

### 9.3 Rate Limiter (RRL)

```go
// internal/filter/ratelimit.go

type RateLimiter struct {
    buckets  map[RRLKey]*TokenBucket
    config   RRLConfig
    mu       sync.Mutex
    // Cleanup: periodic goroutine removes stale buckets
}

type RRLKey struct {
    SourcePrefix string  // Client IP masked to /24 (IPv4) or /56 (IPv6)
    ResponseType uint8   // Answer, NXDOMAIN, Referral, Nodata, Error
}

type TokenBucket struct {
    Tokens    float64
    LastTime  time.Time
    AllowNext bool  // For slip: alternate between drop and TC
}

// Token bucket algorithm:
// - Each bucket refills at `responses-per-second` rate
// - If tokens < 1: drop response (or send TC if slip counter matches)
// - Slip: every Nth dropped response, send truncated (TC=1) instead
//   This hints client to retry over TCP (which is rate-limited differently)
//
// Window: buckets older than `window` seconds are cleaned up.

func (r *RateLimiter) Allow(client net.IP, responseType uint8) RRLDecision

type RRLDecision int
const (
    RRLAllow    RRLDecision = iota
    RRLDrop
    RRLTruncate  // Send TC=1
)
```

### 9.4 GeoDNS

```go
// internal/filter/geodns.go

type GeoDNS struct {
    db     *GeoIPDB
    rules  map[string][]GeoRule  // Zone:Name → rules
}

type GeoRule struct {
    Region  string                    // "US", "EU", "AS", "default"
    Records []protocol.ResourceRecord
}

// Processing:
// 1. Get client IP (from direct connection or EDNS Client Subnet)
// 2. Lookup GeoIP → country code → continent
// 3. Match against rules: country → continent → default
// 4. Return matched records

func (g *GeoDNS) Apply(records []protocol.ResourceRecord, clientIP net.IP, ecs *protocol.EDNSClientSubnet) []protocol.ResourceRecord
```

### 9.5 GeoIP Reader

```go
// internal/filter/geoip.go

type GeoIPDB struct {
    data     []byte  // Memory-mapped MMDB file
    metadata MMDBMetadata
}

// MaxMind MMDB binary format parser (hand-written).
// Format: binary search tree + data section.
//
// Structure:
// [Binary Search Tree] [Data Section] [Metadata]
//
// Lookup algorithm:
// 1. Start at root node (node 0)
// 2. For each bit in IP address (MSB first):
//    - bit=0 → follow left pointer
//    - bit=1 → follow right pointer
// 3. When reaching data pointer → read record from data section
// 4. Parse data section (map/array/string/uint/bytes types)
//
// We only need: country code, continent code, ASN
// Minimal parser — skip fields we don't need.

func OpenGeoIPDB(path string) (*GeoIPDB, error)
func (db *GeoIPDB) Lookup(ip net.IP) (*GeoResult, error)

type GeoResult struct {
    CountryCode   string  // "US", "DE", "TR", etc.
    ContinentCode string  // "NA", "EU", "AS", etc.
    ASN           uint32
}
```

### 9.6 Split-Horizon

```go
// internal/filter/splithorizon.go

type SplitHorizon struct {
    views []View
}

type View struct {
    Name         string
    MatchClients []*net.IPNet
    ZoneStore    *auth.ZoneStore  // Each view has its own zone store
}

// View selection:
// 1. For each view (in order), check if client IP matches any CIDR
// 2. First matching view wins
// 3. If no match → use default view (last in list, matches "any")
//
// Each view has its own set of zones.
// The authoritative engine receives the selected view's zone store.

func (sh *SplitHorizon) SelectView(clientIP net.IP) *View
```

---

## 10. QUIC Implementation

### 10.1 Overview

Hand-written minimal QUIC implementation focused on DNS over QUIC (DoQ). This is the most complex single module due to QUIC's inherent complexity. We implement the minimum required subset.

**Scope**: QUIC v1 (RFC 9000) + TLS 1.3 integration + minimal congestion control.

**NOT in scope**: HTTP/3, WebTransport, DATAGRAM frames, connection migration (server-initiated).

### 10.2 Packet Format

```go
// internal/quic/packet.go

// QUIC packet types:
// 1. Initial (long header, unencrypted→encrypted with initial keys)
// 2. Handshake (long header, handshake keys)
// 3. 1-RTT (short header, application keys)
// 4. 0-RTT (long header, early data keys)
// 5. Retry (long header, server→client for address validation)

type LongHeader struct {
    Type        PacketType
    Version     uint32      // 0x00000001 for QUIC v1
    DCID        []byte      // Destination Connection ID
    SCID        []byte      // Source Connection ID
    Token       []byte      // Only in Initial packets
    Length      uint64      // Remaining packet length (varint)
    PacketNum   uint32      // Packet number (variable length)
}

type ShortHeader struct {
    DCID      []byte
    PacketNum uint32
}

// QUIC frames within packets:
type Frame interface {
    Type() FrameType
    Marshal() []byte
    Unmarshal([]byte) error
}

// Implemented frame types:
// PADDING, PING, ACK, CRYPTO, NEW_TOKEN,
// STREAM, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS,
// DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED,
// NEW_CONNECTION_ID, RETIRE_CONNECTION_ID,
// CONNECTION_CLOSE, HANDSHAKE_DONE
```

### 10.3 Connection & Crypto

```go
// internal/quic/connection.go

type Connection struct {
    localCID    []byte
    remoteCID   []byte
    state       ConnState
    tls         *QUICTLSState
    streams     map[uint64]*Stream
    sendBuf     []Frame
    recvBuf     map[uint64][]byte
    congestion  *CongestionController
    maxData     uint64
    nextStreamID uint64
    mu           sync.Mutex
}

// internal/quic/crypto.go

type QUICTLSState struct {
    config     *tls.Config
    // We use crypto/tls for the TLS 1.3 handshake, but need to
    // feed QUIC CRYPTO frames into it manually.
    //
    // Go 1.21+ provides crypto/tls support for QUIC via:
    // tls.QUICClient / tls.QUICServer (introduced in Go 1.21)
    //
    // This allows us to:
    // 1. Create tls.QUICServer with our TLS config
    // 2. Feed incoming CRYPTO frame data via HandleData()
    // 3. Get outgoing CRYPTO frame data via NextEvent()
    // 4. Derive QUIC packet protection keys from TLS keying material
    //
    // Key derivation (HKDF-based):
    // - Initial keys: derived from DCID + salt (well-known)
    // - Handshake keys: from TLS handshake
    // - 1-RTT keys: from TLS application traffic secret
    // - 0-RTT keys: from TLS early traffic secret
    quicConn *tls.QUICConn
}

// Packet protection:
// - Header protection: AES-ECB or ChaCha20 mask
// - Payload encryption: AEAD (AES-128-GCM or ChaCha20-Poly1305)
// - Nonce: packet number XOR with IV derived from secret
```

### 10.4 Stream Management

```go
// internal/quic/stream.go

type Stream struct {
    id        uint64
    conn      *Connection
    readBuf   []byte
    writeBuf  []byte
    readDone  bool
    writeDone bool
    mu        sync.Mutex
}

// For DoQ: each DNS query/response uses one bidirectional stream.
// Client opens stream → sends DNS query → server reads → sends response → closes stream.
// No 2-byte length prefix (QUIC framing handles message boundaries).

func (s *Stream) Read(p []byte) (int, error)
func (s *Stream) Write(p []byte) (int, error)
func (s *Stream) Close() error
```

### 10.5 Congestion Control

```go
// internal/quic/congestion.go

type CongestionController struct {
    cwnd          uint64  // Congestion window
    ssthresh      uint64  // Slow start threshold
    bytesInFlight uint64
    mode          CongestionMode
}

// New Reno implementation:
// - Slow start: cwnd doubles each RTT
// - Congestion avoidance: cwnd += MSS/cwnd per ACK
// - On loss: ssthresh = cwnd/2, cwnd = ssthresh (fast recovery)
//
// Minimal but sufficient for DNS traffic (small packets, short connections).
```

### 10.6 Listener

```go
// internal/quic/listener.go

type Listener struct {
    conn       *net.UDPConn
    tlsConfig  *tls.Config
    conns      map[string]*Connection  // CID → connection
    acceptChan chan *Connection
    mu         sync.RWMutex
}

// Listen reads UDP packets, demuxes by Connection ID,
// dispatches to existing connections or creates new ones.
//
// Accept returns new connections (after TLS handshake completes).

func Listen(addr string, tlsConfig *tls.Config) (*Listener, error)
func (l *Listener) Accept() (*Connection, error)
func (l *Listener) Close() error
```

---

## 11. Cluster Layer (Raft)

### 11.1 Raft Implementation

```go
// internal/cluster/raft.go

type Raft struct {
    nodeID     string
    state      RaftState        // Leader | Follower | Candidate
    currentTerm uint64
    votedFor    string
    log        *RaftLog
    commitIndex uint64
    lastApplied uint64
    fsm         FSM              // State machine to apply commands
    transport   *Transport
    peers       map[string]*Peer
    electionTimer  *time.Timer
    heartbeatTimer *time.Timer
    mu          sync.Mutex
}

type RaftState int
const (
    Follower  RaftState = iota
    Candidate
    Leader
)

// RequestVote RPC:
// Candidate → all peers, requesting votes for election.
// Voter grants vote if:
// 1. Candidate's term >= voter's term
// 2. Voter hasn't voted in this term (or voted for this candidate)
// 3. Candidate's log is at least as up-to-date

type RequestVoteReq struct {
    Term         uint64
    CandidateID  string
    LastLogIndex uint64
    LastLogTerm  uint64
}

type RequestVoteResp struct {
    Term        uint64
    VoteGranted bool
}

// AppendEntries RPC:
// Leader → followers, for log replication and heartbeats.
type AppendEntriesReq struct {
    Term         uint64
    LeaderID     string
    PrevLogIndex uint64
    PrevLogTerm  uint64
    Entries      []LogEntry
    LeaderCommit uint64
}

type AppendEntriesResp struct {
    Term    uint64
    Success bool
    // ConflictIndex/Term for fast log backtracking
    ConflictIndex uint64
    ConflictTerm  uint64
}

// Election process:
// 1. Election timeout expires (randomized 150-300ms within config range)
// 2. Increment term, vote for self, become Candidate
// 3. Send RequestVote to all peers
// 4. If majority votes received → become Leader
// 5. If AppendEntries from valid leader received → revert to Follower
// 6. If election timeout again → start new election

// Leader responsibilities:
// 1. Send heartbeats (empty AppendEntries) at heartbeat interval
// 2. Replicate new log entries to followers
// 3. Advance commitIndex when majority has entry
// 4. Apply committed entries to FSM
```

### 11.2 Raft Log

```go
// internal/cluster/log.go

type RaftLog struct {
    entries []LogEntry
    storage *storage.WAL  // Persistent storage
    mu      sync.RWMutex
}

type LogEntry struct {
    Index uint64
    Term  uint64
    Type  LogEntryType
    Data  []byte
}

type LogEntryType uint8
const (
    LogCommand     LogEntryType = iota  // Zone/record mutation
    LogConfig                           // Configuration change
    LogMembership                       // Cluster membership change
)

// Persistent: Entries are written to WAL before responding to leader.
// In-memory: Also kept in slice for fast access.
// Compaction: After snapshot, entries before snapshot index can be truncated.
```

### 11.3 State Machine (FSM)

```go
// internal/cluster/fsm.go

type FSM struct {
    zoneStore *auth.ZoneStore
    config    *config.Config
    blocklist *filter.Blocklist
}

// Apply processes committed Raft log entries.
// Commands are serialized as:
// [1 byte: command type] [N bytes: command-specific data]
//
// Command types:
// - ZoneCreate: create new zone
// - ZoneDelete: delete zone
// - RecordAdd: add record to zone
// - RecordUpdate: update record in zone
// - RecordDelete: delete record from zone
// - DynamicUpdate: full RFC 2136 update
// - BlocklistAdd: add domain to blocklist
// - BlocklistRemove: remove domain from blocklist
// - ConfigUpdate: runtime config change
//
// All mutations go through Raft → only leader accepts writes.
// Followers reject writes with redirect to leader.

func (f *FSM) Apply(entry LogEntry) error
func (f *FSM) Snapshot() (*FSMSnapshot, error)
func (f *FSM) Restore(snapshot *FSMSnapshot) error
```

### 11.4 Snapshot

```go
// internal/cluster/snapshot.go

type Snapshot struct {
    dir string
}

// Snapshot captures full state for:
// - All zone data (serialized)
// - Configuration
// - Blocklist
// - DNSSEC keys
//
// Format: Binary-encoded state (using internal/storage/serializer.go)
//
// Triggered:
// - After N log entries since last snapshot (configurable threshold)
// - Periodic interval (configurable)
// - Manual trigger via API
//
// Used for:
// - Log compaction (truncate entries before snapshot)
// - New node bootstrap (send snapshot instead of full log replay)

func (s *Snapshot) Create(fsm *FSM) error
func (s *Snapshot) Restore() (*FSMSnapshot, error)
func (s *Snapshot) List() []SnapshotMeta
```

### 11.5 Transport

```go
// internal/cluster/transport.go

type Transport struct {
    bindAddr string
    conns    map[string]net.Conn  // Peer ID → persistent connection
    mu       sync.RWMutex
}

// Binary RPC protocol over TCP:
// [1 byte: message type] [4 bytes: payload length] [N bytes: payload]
//
// Message types:
// 0x01: RequestVote
// 0x02: RequestVoteResp
// 0x03: AppendEntries
// 0x04: AppendEntriesResp
// 0x05: InstallSnapshot
// 0x06: InstallSnapshotResp
//
// Connection management:
// - Persistent TCP connections between peers
// - Reconnect with exponential backoff on failure
// - Heartbeat doubles as connection keep-alive
// - TLS optional for inter-node communication

func (t *Transport) SendRequestVote(peer string, req *RequestVoteReq) (*RequestVoteResp, error)
func (t *Transport) SendAppendEntries(peer string, req *AppendEntriesReq) (*AppendEntriesResp, error)
func (t *Transport) SendSnapshot(peer string, snapshot io.Reader) error
```

---

## 12. Storage Layer

### 12.1 Write-Ahead Log

```go
// internal/storage/wal.go

type WAL struct {
    dir       string
    current   *os.File
    segment   uint64
    offset    int64
    syncMode  SyncMode  // SyncEvery | SyncPeriodic | SyncNone
    mu        sync.Mutex
}

type SyncMode int
const (
    SyncEvery    SyncMode = iota  // fsync after every write
    SyncPeriodic                   // fsync every 100ms
    SyncNone                       // OS handles flushing
)

// WAL segment format:
// Filename: {segment_number:06d}.wal (e.g., 000001.wal)
// Max segment size: 64MB (configurable)
//
// Entry format:
// [4 bytes: CRC32] [4 bytes: data length] [N bytes: data]
//
// On recovery:
// 1. Find all .wal files, sort by segment number
// 2. Read entries from each, verify CRC
// 3. Replay into state machine

func (w *WAL) Append(data []byte) (uint64, error)  // Returns offset
func (w *WAL) ReadAll() ([][]byte, error)
func (w *WAL) Truncate(beforeOffset uint64) error
func (w *WAL) Sync() error
```

### 12.2 Embedded Key-Value Store

```go
// internal/storage/boltlike.go

type DB struct {
    file     *os.File
    pageSize int           // Default: 4096
    meta     *Meta
    freelist *FreeList
    mu       sync.RWMutex
}

// B+tree based embedded KV store.
// Inspired by BoltDB but simplified for our use case.
//
// Features:
// - ACID transactions (single writer, multiple readers)
// - Copy-on-write pages (no write locks block readers)
// - Single file database
// - Bucket-based namespacing (like BoltDB)
//
// Page types:
// - Meta page (x2, alternating for crash safety)
// - Freelist page
// - Branch page (internal B+tree nodes)
// - Leaf page (key-value data)
//
// Buckets:
// - "zones": zone metadata
// - "records:{zone}": records for zone
// - "config": configuration
// - "raft": Raft persistent state (term, votedFor)
// - "dnssec": DNSSEC key metadata

type Tx struct {
    db       *DB
    writable bool
    root     *Bucket
}

func (db *DB) Begin(writable bool) (*Tx, error)
func (tx *Tx) Bucket(name []byte) *Bucket
func (tx *Tx) CreateBucket(name []byte) (*Bucket, error)
func (tx *Tx) Commit() error
func (tx *Tx) Rollback() error

type Bucket struct {
    name string
    root pageID
}

func (b *Bucket) Get(key []byte) []byte
func (b *Bucket) Put(key, value []byte) error
func (b *Bucket) Delete(key []byte) error
func (b *Bucket) ForEach(fn func(key, value []byte) error) error
```

### 12.3 Binary Serializer

```go
// internal/storage/serializer.go

// Efficient binary serialization for storage.
// Used for: zone data, Raft log entries, snapshots, config.
//
// Format: TLV (Type-Length-Value) encoding
// [1 byte: type tag] [varint: length] [N bytes: value]
//
// Type tags:
// 0x01: string
// 0x02: uint32
// 0x03: uint64
// 0x04: bytes
// 0x05: list (repeated TLV)
// 0x06: map (key-value TLV pairs)
// 0x07: bool
// 0x08: nil

type Encoder struct {
    buf *bytes.Buffer
}

type Decoder struct {
    data []byte
    pos  int
}

func (e *Encoder) WriteString(s string) error
func (e *Encoder) WriteUint32(v uint32) error
func (e *Encoder) WriteBytes(b []byte) error
func (d *Decoder) ReadString() (string, error)
func (d *Decoder) ReadUint32() (uint32, error)
func (d *Decoder) ReadBytes() ([]byte, error)
```

---

## 13. Configuration System

### 13.1 YAML Parser

```go
// internal/config/config.go

// Hand-written YAML parser (subset of YAML 1.2).
// Supports:
// - Scalar values: strings, integers, booleans, null
// - Maps: key: value (indentation-based nesting)
// - Sequences: - item (indentation-based)
// - Comments: # to end of line
// - Quoted strings: "double" and 'single'
// - Multi-line strings: | (literal) and > (folded) — basic support
// - Environment variable expansion: ${ENV_VAR} and ${ENV_VAR:-default}
//
// NOT supported (not needed):
// - Anchors & aliases (&anchor, *alias)
// - Complex keys
// - Tags (!!str, !!int)
// - Multiple documents (---)
// - Flow style ({}, [])
//
// Parser approach:
// 1. Tokenize: line-by-line, track indentation level
// 2. Build tree: nested maps/sequences based on indentation
// 3. Unmarshal into Go structs via reflection-free approach:
//    Each config section has a typed Parse method.

type Config struct {
    Server    ServerConfig
    TLS       TLSConfig
    Resolver  ResolverConfig
    Cache     CacheConfig
    Zones     []ZoneConfig
    Blocking  BlockingConfig
    GeoDNS    GeoDNSConfig
    Views     []ViewConfig
    RateLimit RateLimitConfig
    ACL       ACLConfig
    Cluster   ClusterConfig
    API       APIConfig
    Dashboard DashboardConfig
    Metrics   MetricsConfig
    MCP       MCPConfig
    Logging   LoggingConfig
}

func LoadConfig(path string) (*Config, error)
func (c *Config) Validate() error
```

### 13.2 Defaults

```go
// internal/config/defaults.go

// All config values have sensible defaults.
// The server runs with ZERO configuration — defaults produce a
// recursive resolver listening on :53 (UDP/TCP) with caching.
//
// DefaultConfig returns a fully populated config with defaults.
func DefaultConfig() *Config
```

### 13.3 Hot Reload

```go
// internal/config/reload.go

type Reloader struct {
    configPath string
    current    *Config
    callbacks  []ReloadCallback
    mu         sync.RWMutex
}

type ReloadCallback func(old, new *Config) error

// SIGHUP handler:
// 1. Re-read config file
// 2. Validate new config
// 3. Diff with current config
// 4. Call registered callbacks for changed sections
// 5. Atomic swap
//
// Reloadable without restart:
// - Zone files (re-parse and swap)
// - Blocklists (re-load)
// - TLS certificates (swap in tls.Config.GetCertificate)
// - ACL rules
// - Rate limit config
// - Log level
//
// NOT reloadable (require restart):
// - Listen addresses
// - Cluster config
// - Storage paths

func (r *Reloader) RegisterCallback(section string, cb ReloadCallback)
func (r *Reloader) Reload() error
```

---

## 14. REST API

```go
// internal/api/rest/router.go

// Hand-written HTTP router (no gorilla/mux, no chi).
// Trie-based path matching with parameter extraction.
//
// Features:
// - Path parameters: /zones/{name}/records/{id}
// - Method routing: GET, POST, PUT, PATCH, DELETE
// - Middleware chain: auth → CORS → logging → handler
// - JSON request/response (encoding/json from stdlib)

type Router struct {
    tree    *routeNode
    middlewares []Middleware
}

type Middleware func(http.Handler) http.Handler

type routeNode struct {
    children  map[string]*routeNode
    paramName string              // Non-empty if this is a {param} segment
    handlers  map[string]http.HandlerFunc  // Method → handler
}

func (r *Router) Handle(method, path string, handler http.HandlerFunc)
func (r *Router) Use(mw Middleware)
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request)

// Path parameter extraction from context:
func PathParam(r *http.Request, name string) string

// internal/api/rest/middleware.go

// Auth middleware: Bearer token or Basic auth
// Reads from Authorization header, validates against config.
func AuthMiddleware(token string) Middleware

// CORS middleware: Allow configurable origins.
func CORSMiddleware(origins []string) Middleware

// Logging middleware: Log method, path, status, duration.
func LoggingMiddleware(logger *util.Logger) Middleware

// internal/api/rest/swagger.go

// Embedded Swagger UI (go:embed).
// OpenAPI 3.0 spec generated as Go string constant.
// Serves at /api/v1/swagger (UI) and /api/v1/swagger/spec.json (spec).
```

---

## 15. gRPC Inter-Node

```go
// internal/api/grpc/proto.go

// Hand-written protobuf-compatible binary encoding.
// NOT using protobuf compiler or library — just the wire format.
//
// Protobuf wire format is simple:
// Field: [varint: field_number << 3 | wire_type] [value]
// Wire types: 0=varint, 1=64-bit, 2=length-delimited, 5=32-bit
//
// We define message schemas in Go structs and manually encode/decode.

// internal/api/grpc/server.go

type GRPCServer struct {
    listener net.Listener
}

// Hand-written HTTP/2 + gRPC framing.
// gRPC over HTTP/2:
// - Request: POST /<service>/<method>
// - Content-Type: application/grpc
// - Body: [1 byte: compressed?] [4 bytes: msg length] [N bytes: protobuf msg]
//
// For inter-node communication, we can simplify:
// Use plain TCP with our own binary RPC instead of full HTTP/2.
// This is simpler and sufficient for internal cluster communication.
//
// Alternative: Use the same binary RPC as Raft transport (port 4223).

// Services:
// - ZoneSync: replicate zone data to new nodes
// - Health: cluster health checks
// - Forward: forward write requests from follower to leader
// - Metrics: aggregate metrics across cluster
```

---

## 16. MCP Server

```go
// internal/api/mcp/server.go

type MCPServer struct {
    zoneStore   *auth.ZoneStore
    resolver    *resolver.Engine
    cache       *resolver.Cache
    cluster     *cluster.Raft
    blocklist   *filter.Blocklist
    config      *config.Config
    metrics     *metrics.Collector
}

// MCP Protocol: JSON-RPC 2.0
// Transport: stdio (for Claude Code CLI) or SSE (for web clients)
//
// Initialization handshake:
// Client → {"jsonrpc":"2.0","method":"initialize","params":{...}}
// Server → {"jsonrpc":"2.0","result":{"capabilities":{...},"serverInfo":{...}}}
//
// stdio mode: Read JSON-RPC from stdin, write to stdout.
// SSE mode: HTTP endpoint, server-sent events for responses.

// internal/api/mcp/tools.go

// MCP tools are functions the LLM can call.
// Each tool: name, description, inputSchema (JSON Schema), handler func.
//
// Tool implementations delegate to existing subsystems:
// dns_zone_list → zoneStore.ListZones()
// dns_record_add → POST /api/v1/zones/{name}/records (via internal func)
// dns_query → create DNS query message, run through pipeline
// etc.
//
// Input validation using JSON Schema defined per tool.

// internal/api/mcp/resources.go

// MCP resources are data the LLM can read.
// URI scheme: dns://
// Each resource: URI template, description, handler func.

// internal/api/mcp/prompts.go

// MCP prompts are pre-built prompt templates.
// Help LLMs perform complex DNS operations:
// - troubleshoot_dns: "Query failed for {domain}. Check cache, zone, upstream."
// - migrate_from_bind: "I'll help import your BIND zones. Upload named.conf."
// - optimize_config: "Analyzing current config for performance improvements."
```

---

## 17. Web Dashboard

```go
// internal/dashboard/server.go

// Static file server using go:embed.
// All frontend assets are embedded in the binary.

//go:embed static/*
var staticFS embed.FS

type DashboardServer struct {
    apiBase string  // Base URL for API calls (e.g., "/api/v1")
}

// Serves at configurable path (default: /dashboard).
// SPA routing: all non-API, non-static paths → index.html.

// internal/dashboard/websocket.go

// WebSocket for real-time updates.
// Hand-written WebSocket upgrade (RFC 6455):
// 1. Check Upgrade: websocket header
// 2. Compute Sec-WebSocket-Accept from Sec-WebSocket-Key
// 3. Send 101 Switching Protocols
// 4. Frame-based communication
//
// Channels:
// - /ws/queries: real-time query stream
// - /ws/stats: periodic stats updates (every 1s)
// - /ws/cluster: cluster state changes

// internal/dashboard/static/app.js

// Vanilla JavaScript dashboard (no framework).
// Features:
// - Fetch wrapper for API calls
// - WebSocket client for real-time data
// - Simple chart rendering (Canvas 2D API)
// - Table components with sorting/filtering
// - Form components for zone/record CRUD
// - Dark/light theme toggle
//
// Libraries: NONE. Pure DOM manipulation + Canvas API.
// CSS: Single style.css with CSS variables for theming.
```

---

## 18. CLI Tool (dnsctl)

```go
// cmd/dnsctl/main.go

// Subcommand-based CLI using hand-written argument parser.
// No flag/cobra/urfave dependency.
//
// Parser:
// 1. First arg = subcommand (zone, record, cache, cluster, blocklist, dnssec, dig, config, server)
// 2. Second arg = action (list, create, delete, add, etc.)
// 3. Remaining args = positional params + flags (--key value)
//
// API client:
// - Base URL from config file, env var, or --server flag
// - Default: http://localhost:8080/api/v1
// - Auth: --token flag or NOTHINGDNS_API_TOKEN env var
// - JSON parsing with encoding/json
//
// Output formatting:
// - Table format (default for TTY)
// - JSON format (--json flag, for scripting)
// - YAML format (--yaml flag)

// Built-in dig:
// dnsctl dig is a standalone DNS query tool that uses internal/protocol
// directly — no API dependency. Creates DNS messages, sends over
// UDP/TCP/DoT/DoH, parses responses.
//
// dig flags:
// @server    - target DNS server
// +tcp       - force TCP
// +dnssec    - request DNSSEC (DO bit)
// +short     - short output
// +trace     - trace resolution path
// +json      - JSON output
```

---

## 19. Metrics & Observability

```go
// internal/metrics/collector.go

type Collector struct {
    queries     map[string]*Counter    // Labeled counters
    histograms  map[string]*Histogram  // Labeled histograms
    gauges      map[string]*Gauge      // Labeled gauges
    mu          sync.RWMutex
}

// Hand-written metric types (no prometheus client library).

type Counter struct {
    value uint64  // atomic increment
}

type Gauge struct {
    value int64  // atomic set/add
}

type Histogram struct {
    buckets []float64   // Bucket boundaries
    counts  []uint64    // Count per bucket (atomic)
    sum     float64
    count   uint64
    mu      sync.Mutex
}

// internal/metrics/prometheus.go

// Prometheus exposition format renderer.
// Writes text to /metrics endpoint in the format:
// # HELP metric_name description
// # TYPE metric_name counter|gauge|histogram
// metric_name{label="value"} 123.0
//
// For histograms:
// metric_name_bucket{le="0.001"} 10
// metric_name_bucket{le="0.01"} 50
// metric_name_bucket{le="+Inf"} 100
// metric_name_sum 1.234
// metric_name_count 100

func (c *Collector) RenderPrometheus(w io.Writer) error

// internal/metrics/health.go

// Health check endpoint: GET /health
// Returns 200 OK with JSON body:
// {
//   "status": "healthy|degraded|unhealthy",
//   "uptime": "...",
//   "version": "...",
//   "cluster": { "role": "leader|follower", "peers": 2 },
//   "zones": 5,
//   "cache_size": 50000,
//   "queries_per_second": 1234.5
// }
```

---

## 20. Shared Utilities

### 20.1 Logger

```go
// internal/util/logger.go

type Logger struct {
    level   LogLevel
    format  LogFormat  // JSON | Text
    output  io.Writer
    mu      sync.Mutex
}

type LogLevel int
const (
    LevelDebug LogLevel = iota
    LevelInfo
    LevelWarn
    LevelError
)

// JSON format: {"time":"2024-01-01T00:00:00Z","level":"info","msg":"...","key":"value"}
// Text format: 2024-01-01T00:00:00Z INFO message key=value
//
// No structured logging library — simple fmt.Fprintf with level check.
// Query logging: separate logger for query log with fields:
// timestamp, client_ip, protocol, qname, qtype, rcode, latency, flags

func (l *Logger) Debug(msg string, fields ...interface{})
func (l *Logger) Info(msg string, fields ...interface{})
func (l *Logger) Warn(msg string, fields ...interface{})
func (l *Logger) Error(msg string, fields ...interface{})
```

### 20.2 Other Utilities

```go
// internal/util/pool.go
// sync.Pool wrappers for byte buffers, Message objects, etc.

// internal/util/ip.go
// IP address parsing, CIDR matching, IPv4/IPv6 detection.
// net.IP and net.IPNet wrappers.

// internal/util/domain.go
// Domain name validation (RFC 1123), normalization (lowercase),
// label splitting, wildcard detection, parent domain extraction.

// internal/util/signal.go
// Graceful shutdown: listen for SIGINT, SIGTERM → cancel context.
// Config reload: listen for SIGHUP → trigger reload.
```

---

## 21. Testing Strategy

### 21.1 Unit Tests
- Every package has `*_test.go` files
- DNS wire protocol: round-trip marshal/unmarshal tests for every record type
- Zone file parser: test with sample BIND zone files (valid + invalid)
- Cache: TTL expiration, LRU eviction, serve-stale behavior
- Raft: election, log replication, snapshot (using in-memory transport)
- DNSSEC: sign + verify round-trips for each algorithm

### 21.2 Integration Tests
- Full query pipeline: UDP query → response (using net.UDPConn loopback)
- Authoritative: load zone, query, verify response sections
- Recursive: mock upstream, verify iterative resolution
- Zone transfer: AXFR/IXFR between two instances
- Cluster: 3-node in-process cluster, verify leader election + replication

### 21.3 Conformance Tests
- RFC compliance: test against known-good DNS query/response pairs
- DNSSEC validation: test against known signed zones
- Zone file parser: test against BIND test suite zone files

### 21.4 Benchmark Tests
- `go test -bench=.` for hot paths:
  - Message marshal/unmarshal
  - Cache lookup
  - Zone lookup
  - Label compression/decompression
  - DNSSEC signing/verification

---

## 22. Build & Release Pipeline

### 22.1 Makefile Targets
```
make build        # Build both binaries
make test         # Run all tests
make bench        # Run benchmarks
make lint         # go vet + staticcheck
make release      # Cross-compile all platforms
make docker       # Build Docker image
make clean        # Remove build artifacts
```

### 22.2 CI/CD (GitHub Actions)
```
on push/PR:
  - go vet
  - go test -race -cover
  - go build (all platforms)
  - Benchmark comparison with main branch

on tag:
  - Cross-compile release binaries
  - Build + push Docker images (ghcr.io)
  - Generate changelog
  - Create GitHub Release with binaries
```

---

## 23. Implementation Order & Dependencies

### Phase 1: Foundation (Week 1-2)
```
1. Project bootstrap (go.mod, directory structure)
2. internal/protocol — DNS wire protocol (message, header, question, records, labels, edns, wire)
3. internal/util — Logger, pools, IP utils, domain utils, signal handling
4. internal/config — YAML parser, config structs, defaults, validation
5. internal/server/udp.go — UDP listener (basic, no pipeline)
6. internal/server/tcp.go — TCP listener
7. internal/server/handler.go — Basic handler (echo/REFUSED)
```
**Milestone: Binary that listens on :53 and responds to basic queries.**

### Phase 2: Authoritative (Week 3-4)
```
8. internal/auth/zone.go — Zone data structure, radix tree
9. internal/auth/zonefile.go — BIND zone file parser
10. internal/auth/zonestore.go — Zone store
11. internal/auth/engine.go — Authoritative query engine
12. internal/auth/wildcard.go — Wildcard processing
13. internal/auth/delegation.go — NS delegation handling
14. Update handler to route through authoritative engine
```
**Milestone: Serve authoritative DNS for loaded zone files.**

### Phase 3: Recursive Resolver (Week 5-6)
```
15. internal/resolver/cache.go — LRU cache with TTL
16. internal/resolver/negative.go — Negative caching
17. internal/resolver/hints.go — Root hints
18. internal/resolver/forwarder.go — Upstream forwarding
19. internal/resolver/iterator.go — Iterative resolution
20. internal/resolver/qname.go — QNAME minimization
21. internal/resolver/engine.go — Resolver engine (hybrid mode)
22. internal/resolver/prefetch.go — Cache prefetching
```
**Milestone: Full recursive resolution + forwarder mode + caching.**

### Phase 4: Security & Filters (Week 7-8)
```
23. internal/filter/acl.go — Access control lists
24. internal/filter/ratelimit.go — Response Rate Limiting
25. internal/filter/blocklist.go — Domain blocking
26. internal/filter/geoip.go — MMDB reader
27. internal/filter/geodns.go — Geo-based response routing
28. internal/filter/splithorizon.go — Split-horizon views
29. internal/server/handler.go — Full query pipeline with all filters
```
**Milestone: Production-grade filtering, rate limiting, GeoDNS.**

### Phase 5: Encrypted Transports (Week 9-10)
```
30. internal/server/dot.go — DNS over TLS
31. internal/server/doh.go — DNS over HTTPS (wire + JSON)
32. internal/quic/* — QUIC implementation (minimal DoQ-focused)
33. internal/server/doq.go — DNS over QUIC
```
**Milestone: All four DNS transports operational.**

### Phase 6: DNSSEC (Week 11-12)
```
34. internal/dnssec/algorithms.go — Crypto operations
35. internal/dnssec/keys.go — Key types and structures
36. internal/dnssec/keystore.go — Key storage and management
37. internal/dnssec/signer.go — Zone signing (online)
38. internal/dnssec/validator.go — Response validation
```
**Milestone: DNSSEC signing + validation working.**

### Phase 7: Zone Transfer & Dynamic DNS (Week 13-14)
```
39. internal/transfer/tsig.go — TSIG authentication
40. internal/transfer/axfr.go — Full zone transfer
41. internal/transfer/ixfr.go — Incremental zone transfer
42. internal/auth/notify.go — NOTIFY
43. internal/dynamic/update.go — DNS UPDATE
44. internal/dynamic/journal.go — Update journal
```
**Milestone: Primary/secondary zone replication + dynamic updates.**

### Phase 8: Storage & Persistence (Week 15-16)
```
45. internal/storage/serializer.go — Binary serialization
46. internal/storage/wal.go — Write-ahead log
47. internal/storage/boltlike.go — Embedded KV store
48. Integrate storage with zone store, config, DNSSEC keys
```
**Milestone: Crash-safe persistence for all state.**

### Phase 9: Clustering (Week 17-19)
```
49. internal/cluster/transport.go — Raft RPC transport
50. internal/cluster/log.go — Raft log
51. internal/cluster/raft.go — Raft consensus
52. internal/cluster/fsm.go — State machine
53. internal/cluster/snapshot.go — Snapshots
54. internal/cluster/peer.go — Peer management
55. internal/cluster/health.go — Health checks
56. internal/api/grpc/* — Inter-node gRPC
```
**Milestone: 3-node cluster with zone replication and failover.**

### Phase 10: Management (Week 20-22)
```
57. internal/api/rest/* — REST API (router, all endpoints, swagger)
58. internal/api/mcp/* — MCP server (tools, resources, prompts)
59. internal/dashboard/* — Web dashboard (embed, websocket, static assets)
60. internal/metrics/* — Prometheus metrics, health endpoint
61. cmd/dnsctl/* — CLI management tool
```
**Milestone: Full management suite operational.**

### Phase 11: Polish & Release (Week 23-24)
```
62. Comprehensive test suite
63. Benchmark optimization
64. Documentation (README, man pages)
65. Docker image + compose files
66. CI/CD pipeline
67. Performance tuning
68. Security audit
```
**Milestone: v1.0.0 release-ready.**

---

*Document Version: 1.0*
*Created: 2026-03-25*
*Author: Ersin / ECOSTACK TECHNOLOGY OÜ*
*Status: DRAFT — Pending Review*
