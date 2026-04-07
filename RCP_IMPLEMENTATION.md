# RFC Implementation Plan — NothingDNS

> **Amaç:** Tüm eksik RFC'lerin implementasyonu için detaylı yol haritası
> **Tarih:** 2026-04-06
> **Toplam:** ~20 RFC implementasyonu
> **Öncelik:** High → Medium → Low

---

## PHASE 1 — YÜKSEK ÖNCELİKLİ (Production Zorunlu)

### 1.1 XoT — DNS Zone Transfer over TLS (RFC 9103)

**Dosyalar:**
```
internal/transfer/xot.go          [NEW]
internal/transfer/xot_test.go     [NEW]
cmd/nothingdns/transfer.go       [MODIFY]
internal/server/tls.go            [MODIFY]
```

**Neden:** RFC 5936 AXFR'i TLS üzerinden çalıştırmak zorunlu güvenlik gereksinimi. Bugün plaintext TCP üzerinden AXFR/IXFR var ama TLS yok.

**Implementation:**

```go
// XoT: DNS Zone Transfer over TLS (RFC 9103)
// 1. TLS listener port 853 -> AXFR/IXFR over TLS
// 2. TLS connection must validate peer via IP address + TLSA record (RFC 7671)
// 3. Use tcp://host:853 or tls://host:853 in config
// 4. Support both XFR over TLS and XFR over TCP (fallback)
// 5. TLS 1.3 minimum, 1.2 allowed for compatibility

type XoTServer struct {
    tlsConfig *tls.Config
    zoneManager *zone.Manager
}

func (s *XoTServer) HandleXoT(conn net.Conn, req *transfer.Request) error {
    // RFC 9103 Section 4: XoT uses RFC 5936 AXFR semantics over TLS
    // RFC 9103 Section 5: Connection must use TLS
    // RFC 9103 Section 6: TLSA verification required
}
```

**Bağımlılıklar:** `internal/transfer/tsig.go` (mevcut), `internal/protocol/types.go` (mevcut)

---

### 1.2 mDNS — Multicast DNS (RFC 6762)

**Dosyalar:**
```
internal/mdns/querier.go          [NEW]
internal/mdns/responder.go        [NEW]
internal/mdns/browser.go          [NEW]
internal/mdns/constants.go        [NEW]
internal/mdns/message.go          [NEW]
internal/mdns/mdns_test.go        [NEW]
cmd/nothingdns/main.go            [MODIFY]
internal/server/udp.go           [MODIFY]
```

**Neden:** `.local` domain resolution için zorunlu. Apple, Google Home, smart home cihazları mDNS kullanıyor.

**Implementation:**

```go
// RFC 6762: Multicast DNS
// - IPv4: 224.0.0.251:5353
// - IPv6: ff02::fb:5353
// - UDP only, no TCP
// - Probing, announcing, query phases
// - Conflict resolution
// - Goodbye packets (TTL=0)

const (
    mDNSIPv4Addr = "224.0.0.251"
    mDNSIPv6Addr = "ff02::fb"
    mDNSPort    = 5353
)

type Responder struct {
    services   map[string]*ServiceInstance
    hostName   string
    multicast  *net.UDPConn
}
```

**Önemli:** mDNS service browsing (RFC 6763) ile birlikte implement edilmeli.

---

### 1.3 DNS-SD — DNS-Based Service Discovery (RFC 6763)

**Dosyalar:**
```
internal/mdns/browser.go         [NEW] — RFC 6763
internal/mdns/service.go         [NEW]
```

**Neden:** `_printer._tcp.local`, `_airplay._tcp.local` gibi service browsing için.

**Implementation:**

```go
// RFC 6763: DNS-Based Service Discovery
// 1. Service Instance Enumeration (browse)
//    - PTR queries: _service._proto.dns-sd.local
// 2. Service Instance Resolution
//    - SRV + TXT queries for service instance
// 3. Service Domain Enumeration
//    - PTR for domains

func (b *Browser) Browse(service, proto string) ([]*ServiceInstance, error) {
    // Send PTR query: _service._proto._dns-sd.local
    // Parse answers to get service instance names
}
```

---

### 1.4 IDNA — Internationalized Domain Names (RFC 5890-5895)

**Dosyalar:**
```
internal/idna/idna.go             [NEW]
internal/idna/idna_test.go        [NEW]
internal/idna/punycode.go         [NEW]
internal/protocol/labels.go       [MODIFY]
internal/config/parser.go         [MODIFY]
```

**Neden:** Non-ASCII domain names (Türkçe domainler, Arapça, Çince vs.) için gerekli.

**Implementation:**

```go
// RFC 5891: IDNA Protocol
// RFC 5892: Unicode code point restrictions
// RFC 5893: Right-to-left scripts
// RFC 5895: Character mapping
// RFC 3492: Punycode

// ToUnicode(domain) -> punycode to unicode
// ToASCII(domain) -> unicode to punycode

type IDNAConverter struct {
    mappingTable map[rune]string
}

func (c *IDNAConverter) ToASCII(label string) (string, error) {
    // 1. Normalize (RFC 5891 Section 3.1)
    // 2. Check NCM (Non-Starting-Mixed-Case characters)
    // 3. Map characters (RFC 5895)
    // 4. Check BID (Base Invalid) characters
    // 5. Check TLD-specific rules
    // 6. Encode as punycode
}

func (c *IDNAConverter) ToUnicode(input string) (string, error) {
    // 1. Detect ACE prefix "xn--"
    // 2. Decode punycode
    // 3. Validate result
}
```

**Dikkat:** RFC 5892 Section 2.3 "StringPREP" yerine "Unicode Normalization Form C (NFC)" kullanılmalı.

---

### 1.5 ZONEMD — Message Digest for DNS Zones (RFC 8976)

**Dosyalar:**
```
internal/zone/zonemd.go           [NEW]
internal/zone/zonemd_test.go      [NEW]
internal/zone/manager.go          [MODIFY]
internal/zone/zone.go             [MODIFY]
```

**Neden:** Zone transfer'de message integrity için SHA-256/384 hash.

**Implementation:**

```go
// RFC 8976: Message Digest for DNS Zones
// - Added to SOA rdata: ZONEMD record type (60)
// - Hash zone contents: SOA + all RRsets sorted
// - Multiple hash algorithms supported (SHA-256/384)
// - Published at zone apex

type ZoneMessageDigest struct {
    ZoneName    string
    Checksum    string
    Algorithm   uint8   // 1=SHA-256, 2=SHA-384
    Minimizers  [2]uint64  // optional zone minimizers
}

func ComputeZoneMD(zone *Zone) (*ZoneMessageDigest, error) {
    // RFC 8976 Section 4: Compute hash over sorted RRsets
    // Include SOA rdata as first element
    // Digest = Hash(sorted RRsets concatenated)
}
```

---

### 1.6 ODoH — Oblivious DNS over HTTPS (RFC 9230)

**Dosyalar:**
```
internal/odoh/oblivious.go        [NEW]
internal/odoh/proxy.go            [NEW]
internal/odoh/target.go           [NEW]
internal/odoh/odoh_test.go       [NEW]
internal/doh/handler.go          [MODIFY]
```

**Neden:** DNS query privacy - recursive ile authoritative arasında third-party gizleme.

**Implementation:**

```go
// RFC 9230: Oblivious DNS over HTTPS (ODoH)
// 1. Client -> Proxy: encrypted DNS query
// 2. Proxy -> Target: forward encrypted query
// 3. Target -> Proxy: encrypted response
// 4. Proxy -> Client: encrypted response

// ODoH Oblivious DNS Privacy (ODoHP) protocol
// - Uses HPKE (Hybrid Public Key Encryption)
// - target_name: resolvable DNS name
// - oblivious_name: proxy's DNS name

type ObliviousClient struct {
    targetName string  // e.g., "dns.example.com"
    resolverIP  net.IP
}

func (c *ObliviousClient) Query(query []byte) ([]byte, error) {
    // 1. Generate HPKE key pair
    // 2. Encapsulate query to target
    // 3. Send to proxy via DoH
    // 4. Decapsulate response
}
```

**Bağımlılık:** HPKE implementation gerekiyor (Go stdlib crypto olabilir veya hand-rolled)

---

## PHASE 2 — ORTA ÖNCELİKLİ (Production Değerli)

### 2.1 DNS Stateful Operations (DSO) — RFC 8490

**Dosyalar:**
```
internal/dso/session.go          [NEW]
internal/dso/dso.go               [NEW]
internal/dso/dso_test.go          [NEW]
internal/server/tcp.go           [MODIFY]
```

**Neden:** TCP üzerinde persistent sessions, keepalive, redirect.

**Implementation:**

```go
// RFC 8490: DNS Stateful Operations
// - DSO session establishment via SIGHUP mechanism
// - Keepalive messages
// - Session redirect
// - Data reuse

const (
    DSONonTerminal = 0
    DsoTerminal    = 1
    DSOTypeKeepalive = 0
    DSOTypeRedirect   = 1
    DSOTypeReuse      = 2
)

type Session struct {
    ID        uint16
    Lifetime  uint32
    State     SessionState
    Messages  map[uint16]*DNSMessage
}
```

---

### 2.2 Compact DNSSEC Denial (RFC 9824)

**Dosyalar:**
```
internal/protocol/dnssec_compact.go  [NEW]
internal/dnssec/compact_test.go       [NEW]
internal/protocol/constants.go       [MODIFY]
```

**Neden:** NSEC/NSEC3 yerine daha compact denial-of-existence kanıtı.

**Implementation:**

```go
// RFC 9824: Compact Denial of Existence in DNSSEC
// - New record type: NSEC4 (type 57?)
// - Shorter proof of non-existence
// - Compatible with NSEC3 parameters

type NSEC4Record struct {
    NextDomain   *Name
    TypeBitMaps  []uint16
    Salt         []byte
    HashAlgorithm uint8
}
```

---

### 2.3 Multi-Signer DNSSEC (RFC 8901)

**Dosyalar:**
```
internal/dnssec/multi_signer.go   [NEW]
internal/dnssec/ksk_ceremony.go   [NEW]
```

**Neden:** Birden fazla provider'ın aynı zone'u imzaladığı ortamda DNSSEC.

**Implementation:**

```go
// RFC 8901: Multi-Signer DNSSEC Models
// Model A: All providers share same ZSK
// Model B: Each provider has own ZSK, parent sees all CSYNC
// Model C: Loose coordination via CDS/CDNSKEY

type MultiSignerConfig struct {
    Providers []ProviderConfig
    Model     ModelType  // A, B, or C
}

func SyncDSFromProviders(zone *Zone) error {
    // Collect DNSKEYs from all providers
    // Generate combined DS for parent
    // Handle algorithm rollovers across providers
}
```

---

### 2.4 DNS64 — RFC 6147 Compliant

**Dosyalar:**
```
internal/dns64/dns64.go           [MODIFY]
internal/dns64/synthesizer.go     [NEW]
internal/dns64/nat64_test.go      [NEW]
```

**Neden:** Mevcut dns64.go var ama tam RFC 6147 uyumlu değil.

**Implementation:**

```go
// RFC 6147: DNS64 from AAAA synthesis
// 1. Check if AAAA exists
// 2. If not, check A exists
// 3. If A exists, synthesize AAAA:
//    - Well-known prefix: 64:ff9b::/96 (or custom)
//    - IPv4 address: 96-bit prefix + 32-bit A address
// 4. Set EDNS0 PAD option in response

func (s *Synthesizer) SynthesizeAAAA(name *Name, aRecord *RDataA, req *Message) (*Message, error) {
    // RFC 6147 Section 3: AAAA synthesis
    // RFC 7050: Discovery
}
```

---

### 2.5 DoT Usage Profiles — RFC 8310

**Dosyalar:**
```
internal/server/tls.go            [MODIFY]
internal/config/config.go        [MODIFY]
internal/config/validator.go      [MODIFY]
```

**Implementation:**

```go
// RFC 8310: Usage Profiles for DNS-over-TLS
// Strict Mode: Require valid certificate, no fallback
// Opportunistic Mode: Try TLS, fallback to plaintext

type TLSProfile int

const (
    TLSProfileStrict       TLSProfile = iota
    TLSProfileOpportunistic
    TLSProfilePrivacy      // Like strict but prefer privacy
)

type TLSConfig struct {
    Profile TLSProfile
    // For Strict: validate via TFO, IP address in certificate
    // Verify hostname matches certificate CN/SAN
}

// Use RFC 7525 for TLS recommendations
```

---

### 2.6 Catalog Zones — RFC 9432

**Dosyalar:**
```
internal/zone/catalog.go          [NEW]
internal/zone/catalog_test.go    [NEW]
internal/transfer/notify.go      [MODIFY]
```

**Implementation:**

```go
// RFC 9432: DNS Catalog Zones
// - Special zone with catalog zones extension
// - Serial: increment on any change
// - Multiple changes in one serial allowed

type CatalogZone struct {
    Version     string
    Groups      []CatalogGroup  // "primary", "secondary", etc.
}

type CatalogGroup struct {
    Name     string
    Zones    []CatalogZoneInfo
}

type CatalogZoneInfo struct {
    Name           string  // zone name
    Serial         uint32
    CustomFields   map[string]string
}

const (
    TypeCatalogZones  = 42  // Actually TYPE without assignment yet
    // Use CHAOS class for catalog
)
```

**Not:** Catalog zones draft'ta, tam RFC değil. Implementasyon dikkatli olmalı.

---

### 2.7 SIG(0) — Transaction Signatures (RFC 2931)

**Dosyalar:**
```
internal/transfer/sig0.go         [NEW]
internal/transfer/sig0_test.go   [NEW]
internal/transfer/tsig.go        [MODIFY]
```

**Implementation:**

```go
// RFC 2931: DNS Request and Transaction Signatures (SIG(0))
// - Uses public key cryptography instead of shared secret
// - SIG(0) record attached to message
// - Key selection via KEY tag in packet

type SIG0Signer struct {
    privateKey *crypto.PrivateKey
    algorithm  uint8
}

func (s *SIG0Signer) Sign(msg *Message, key *DNSKEY) ([]byte, error) {
    // 1. Build canonical wire format of message
    // 2. Sign with private key
    // 3. Create SIG(0) record
    // 4. Append to message additional section
}

func (s *SIG0Signer) Verify(msg *Message, sig []byte, key *DNSKEY) error {
    // 1. Extract SIG(0) from additional section
    // 2. Verify signature using key
}
```

---

## PHASE 3 — DÜŞÜK ÖNCELİKLİ (Nice-to-Have)

### 3.1 TKEY — Secret Key Establishment (RFC 2930)

**Dosyalar:**
```
internal/transfer/tkey.go         [NEW]
internal/transfer/tkey_test.go   [NEW]
```

**Implementation:**

```go
// RFC 2930: Secret Key Establishment for DNS (TKEY RR)
// - GSS-API based key exchange
// - Diffie-Hellman key agreement
// - Resolver can propose algorithm

type TKEYRecord struct {
    Algorithm *Name
    Inception uint32
    Expire    uint32
    Mode      uint16  // 1=keyagreement, 2=serverassign, etc.
    Key       []byte
    OtherLen  uint16
    OtherData []byte
}
```

---

### 3.2 NSID — DNS Server Identifier (RFC 5001)

**Dosyalar:**
```
internal/server/handler.go      [MODIFY]
internal/protocol/opt.go        [MODIFY]
internal/protocol/constants.go  [MODIFY]
```

**Implementation:**

```go
// RFC 5001: DNS NSID Option
// - EDNS0 option code 12
// - Server sends its identifier in response
// - Request must include NSID option in OPT

const OptionCodeNSID = 12

type NSIDOption struct {
    NSID []byte  // Server's identifier
}

func HandleNSIDRequest(req *Message, resp *Message) error {
    // If request has NSID option, include server identifier
    // Typically hostname or operator-defined string
}
```

---

### 3.3 CHAIN Queries — RFC 7901

**Dosyalar:**
```
internal/resolver/resolver.go    [MODIFY]
internal/protocol/opt.go        [MODIFY]
```

**Implementation:**

```go
// RFC 7901: CHAIN Query Requests in DNS
// - Client asks resolver to return all keys up to trust anchor
// - EDNS0 option code 13 (CHAIN)

// Query for A record with CHAIN option:
// -> A.example.com + CHAIN=root
// <- A record + DNSKEY chain from example.com to root
```

---

### 3.4 DNS Error Reporting — RFC 9567

**Dosyalar:**
```
internal/protocol/ede.go         [NEW]
internal/server/handler.go      [MODIFY]
```

**Implementation:**

```go
// RFC 9567: DNS Error Reporting
// - New EDNS0 option for client-initiated error reporting
// - Report information about resolution failures

const OptionCodeErrorReport = 19

type ErrorReportOption struct {
    ReportType   uint16  // 1=BrokenTrustChain, etc.
    ReportBody    []byte
}
```

---

### 3.5 DNS Resolver Information — RFC 9606

**Dosyalar:**
```
internal/resolver/info.go        [NEW]
internal/server/handler.go      [MODIFY]
```

**Implementation:**

```go
// RFC 9606: DNS Resolver Information
// - New TXT record subtype for resolver metadata
// - _dns.resolver TXT for discovery

type ResolverInfo struct {
    Hostname   string
    Version    string
    Features   []string
    Contacts   []string
}
```

---

### 3.6 RDNSS/DNSSL — IPv6 DNS Configuration (RFC 8106)

**Dosyalar:**
```
internal/resolver/rdnss.go       [NEW]
internal/upstream/config.go     [MODIFY]
```

**Implementation:**

```go
// RFC 8106: IPv6 RA Options for DNS Configuration
// - Parse Router Advertisement for RDNSS/DNSSL options
// - Use to configure upstream resolvers

type RDNSSOption struct {
    Lifetime uint32
    Addrs    []net.IP  // Up to 3 IPv6 addresses
}

type DNSSLOption struct {
    Lifetime  uint32
    Domains   []string  // Search domains
}
```

---

### 3.7 YANG Types — RFC 9108

**Dosyalar:**
```
internal/yang/yang.go            [NEW]
cmd/dnsctl/yang.go              [NEW]
```

**Implementation:**

```go
// RFC 9108: YANG Types for DNS Classes and RR Types
// - Define YANG models for DNS protocol
// - Use for NETCONF/YANG-based management

type YANGDNSModule struct {
    Name    string
    Prefixes []string
}
```

---

### 3.8 C-DNS — Compacted DNS (RFC 8618)

**Dosyalar:**
```
internal/protocol/cdns.go       [NEW]
internal/protocol/cdns_test.go  [NEW]
```

**Implementation:**

```go
// RFC 8618: Compacted-DNS (C-DNS) Packet Capture Format
// - Binary format for DNS packet capture
// - Significant size reduction for pcap files

type CDNSWriter struct {
    buffer *bytes.Buffer
}

func (w *CDNSWriter) WriteQuery(q *Message) error {
    // RFC 8618 Section 5: CDNS block format
    // Use CBOR encoding for fields
}
```

---

## PHASE 4 — KOD BASED ON EXISTING ARCHITECTURE

### 4.1 File Structure

```
internal/
├── doh/                    [EXISTING - do not modify]
├── quic/                   [EXISTING - do not modify]
├── dnssec/                 [EXISTING - extend as needed]
├── transfer/              [EXISTING - add xot.go, sig0.go]
├── zone/                  [EXISTING - add zonemd.go, catalog.go]
├── resolver/             [EXISTING - extend for DNS64, CHAIN, NSID]
├── protocol/             [EXISTING - add new record types]
├── mdns/                  [NEW - RFC 6762/6763]
├── idna/                  [NEW - RFC 5890-5895]
├── odoh/                  [NEW - RFC 9230]
├── dso/                   [NEW - RFC 8490]
├── yang/                  [NEW - RFC 9108]
```

### 4.2 Implementation Order (Dependency Graph)

```
RFC 5890-5895 (IDNA)
    └── RFC 6762/6763 (mDNS/DNS-SD)

RFC 9103 (XoT)
    └── RFC 9432 (Catalog Zones)

RFC 8976 (ZONEMD)
    └── Depends on zone signing

RFC 9230 (ODoH)
    └── Depends on DoH infrastructure

RFC 8490 (DSO)
    └── Depends on TCP server

RFC 2931 (SIG(0))
    └── Depends on DNSSEC infrastructure

RFC 9824 (Compact NSEC)
    └── Depends on DNSSEC infrastructure
```

---

## PHASE 5 — TEST STRATEGY

### 5.1 Test File Naming Convention

```
{x}_test.go              - Unit tests
{x}_coverage_test.go     - Coverage tests
{x}_integration_test.go  - Integration tests
```

### 5.2 RFC Compliance Matrix

| RFC | Test Coverage | Interop Tests |
|-----|---------------|---------------|
| 9103 XoT | AXFR/IXFR over TLS | Bind, Knot, NSD |
| 6762 mDNS | Querier, Responder | Apple devices |
| 6763 DNS-SD | Browser, Service | Avahi, Bonjour |
| 5890-5895 IDNA | ToASCII/ToUnicode | Valid domain tests |
| 8976 ZONEMD | Zone hash | Zone transfer |
| 9230 ODoH | HPKE encrypt/decrypt | ODoH proxy |
| 8490 DSO | Session, Keepalive | Unbound |

---

## PHASE 6 — ROLLBACK & DEPLOYMENT

### 6.1 Feature Flags

```yaml
# config.yaml
features:
  xot: true           # RFC 9103
  mdns: false         # RFC 6762/6763
  dns_sd: false       # RFC 6763
  idna: true          # RFC 5890-5895
  zonemd: false       # RFC 8976
  odoh: false         # RFC 9230
  dso: false          # RFC 8490
```

### 6.2 Configuration

```yaml
# config.yaml for XoT example
zones:
  - name: example.com
    transfer:
      mode: [axfr, ixfr, xot]  # Enable XoT
      tls_profile: strict      # RFC 8310
      tls_port: 853
```

---

## PHASE 7 — IMPLEMENTATION SCHEDULE

### Sprint 1 (1-2 hafta)
- [ ] RFC 5890-5895 IDNA (foundation)
- [ ] RFC 9103 XoT (high value)

### Sprint 2 (2-3 hafta)
- [ ] RFC 6762/6763 mDNS/DNS-SD
- [ ] RFC 8976 ZONEMD

### Sprint 3 (2-3 hafta)
- [ ] RFC 9230 ODoH
- [ ] RFC 8490 DSO

### Sprint 4 (1-2 hafta)
- [ ] RFC 2931 SIG(0)
- [ ] RFC 9824 Compact NSEC

### Sprint 5+ (Remaining)
- [ ] All remaining RFCs from Phase 3

---

## OPEN ISSUES & RISKS

1. **HPKE implementation** - ODoH (RFC 9230) için HPKE kütüphanesi gerekiyor. Go stdlib'de yok, ya hand-rolled ya da minimal dependency gerekecek.

2. **Catalog Zones** - Draft aşamasında, RFC 9432 olarak yayınlandı ama değişebilir.

3. **IDNA** - Full IDNA2008 implementation karmaşık, özellikle bidirectional scripts (RTL) için.

4. **mDNS** - UDP multicast, network interface handling gerektirir. Test zorluğu yüksek.

5. **Zero dependencies policy** - Bazı RFC'ler için cryptographic primitive'ler stdlib'de mevcut (HMAC, AES-GCM, ChaCha20), ancak HPKE tam desteklenmiyor.

---

## APPENDIX A: RFC References

| RFC | Title | Category |
|-----|-------|----------|
| 9103 | DNS Zone Transfer over TLS | Transfer |
| 6762 | Multicast DNS | Discovery |
| 6763 | DNS-Based Service Discovery | Discovery |
| 5890 | IDNA: Definitions | Internationalization |
| 5891 | IDNA: Protocol | Internationalization |
| 5892 | Unicode Code Points and IDNA | Internationalization |
| 5893 | Right-to-Left Scripts for IDNA | Internationalization |
| 5895 | Mapping Characters for IDNA 2008 | Internationalization |
| 3492 | Punycode | Internationalization |
| 8976 | Message Digest for DNS Zones | Zone Integrity |
| 9230 | Oblivious DNS over HTTPS | Privacy |
| 8490 | DNS Stateful Operations | Transport |
| 9824 | Compact DNSSEC Denial | DNSSEC |
| 8901 | Multi-Signer DNSSEC | DNSSEC |
| 2931 | SIG(0) | Transaction Security |
| 2930 | TKEY | Key Exchange |
| 5001 | NSID | Resolver |
| 7901 | CHAIN Queries | Resolver |
| 9567 | DNS Error Reporting | Resolver |
| 9606 | DNS Resolver Information | Resolver |
| 8106 | RDNSS/DNSSL | IPv6 |
| 9108 | YANG Types | Management |
| 8618 | Compacted-DNS | Format |
| 9432 | Catalog Zones | Zone Management |

---

## APPENDIX B: Implementation Checklist Template

```markdown
### [RFC Number] — [Title]

- [ ] Read RFC thoroughly
- [ ] Identify all wire format changes
- [ ] Add constants to internal/protocol/constants.go
- [ ] Add record types to internal/protocol/types.go
- [ ] Implement core logic
- [ ] Add tests
- [ ] Update documentation
- [ ] Add feature flag to config
- [ ] Verify with RFC compliance test
- [ ] Interoperability testing
```

---

*Last updated: 2026-04-06*
*Prepared for: NothingDNS RFC Implementation Project*