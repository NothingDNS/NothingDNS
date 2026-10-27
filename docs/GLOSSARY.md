# NothingDNS Glossary

DNS terminology, acronyms, and RFC reference guide.

## A

### ACL (Access Control List)
A list of rules that defines which IP addresses are allowed or denied access to DNS queries. Configured in the top-level `acl` section and managed at runtime via `/api/v1/acl`.

**RFC**: None (operational concept)

### AD (Authentic Data) Flag
A DNS header flag indicating that the response has been cryptographically verified using DNSSEC. Set when a zone is signed and validation succeeds.

**RFC**: RFC 4035 §3.1.6

### Additional Section
The fourth section of a DNS message, containing RRs that provide extra information about nameservers or other records.

**RFC**: RFC 1035 §4.3

### Answer Section
The second section of a DNS response containing RRs that directly answer the query.

**RFC**: RFC 1035 §4.3

### ANY
A pseudo record type that requests all known information about a domain name. Returns TC=1 (truncated) for UDP to encourage TCP retry. Deprecated for amplification attack prevention.

**RFC**: RFC 8482

### API (Application Programming Interface)
REST API provided by NothingDNS for management via HTTP. Available at port 8080 (configurable).

### Authority Section
The third section of a DNS response, containing RRs that point to authoritative nameservers.

**RFC**: RFC 1035 §4.3

### AXFR (Authoritative Zone Transfer)
Full zone transfer protocol for copying entire zone databases between nameservers.

**RFC**: RFC 5936

---

## B

### BADCOOKIE
A DNS response code indicating an invalid DNS server cookie. Client should retry with the cookie from the response. NothingDNS sends it over UDP only; over TCP, DoT, DoH and DoQ the connection authenticates the client, so the query is answered with a fresh cookie (RFC 7873 §5.2.3).

**RFC**: RFC 7873

### BIND (Berkeley Internet Name Domain)
The most widely used DNS software implementation. NothingDNS zone file format is BIND-compatible.

**Website**: https://www.isc.org/bind/

### Bogus
A DNSSEC validation state indicating the signature failed cryptographic validation. Returns SERVFAIL to client.

**RFC**: RFC 4035 §5.3

### Bruteforce
See: Dictionary Attack

---

## C

### CAA (Certification Authority Authorization)
DNS record type that specifies which certificate authorities (CAs) are allowed to issue certificates for a domain.

**RFC**: RFC 8659

### Cache
In-memory store of previously queried DNS responses. NothingDNS cache supports TTL, negative caching, and NSEC aggressive caching.

**RFC**: RFC 2308 (negative caching), RFC 8198 (aggressive)

### Canonical Name
See: CNAME

### CB (Certification Authority)
Organization that issues digital certificates. Referenced in CAA records.

**RFC**: RFC 8659

### CD (Checking Disabled) Flag
A DNS header flag sent by the resolver to indicate DNSSEC validation should not be performed. Used for debugging.

**RFC**: RFC 4035 §3.1.4

### Certificate
Digital document that binds a public key to an identity, used for TLS/DoT and DNSSEC.

### Chain of Trust
Hierarchical validation of DNSSEC signatures from trust anchor (typically root DNSKEY) through DNSKEY → DS → DNSKEY chain.

**RFC**: RFC 4035 §5

### Challenge
See: ACME Challenge

### Class
The second field of a DNS question, almost always IN (Internet). Other classes exist (CH, HS, NONE, ANY) but rarely used.

**RFC**: RFC 1035 §3.2.3

### CNAME (Canonical Name)
DNS record type that creates an alias from one domain name to another. Only one CNAME allowed per name.

**RFC**: RFC 1035 §3.3.1

### Cookie
A DNS extension for anti-spoofing that allows servers to verify client IP address without requiring TSIG.

**RFC**: RFC 7873

### CR
Canonical Resolution. The process of following DNS delegations from root to authoritative nameservers.

### CSR (Certificate Signing Request)
A file containing certificate request information, sent to a CA to request a certificate.

### CT (Certificate Transparency)
Public log of issued TLS certificates. Referenced by CAA records.

**RFC**: RFC 6962

### Current Stamp
See: SOA Serial

---

## D

### DANE (DNS-Based Authentication of Named Entities)
A protocol that uses TLSA records to specify how to verify TLS certificates using DNS.

**RFC**: RFC 6698

### DDoS (Distributed Denial of Service)
Attack that overwhelms DNS server with traffic. NothingDNS mitigates with RRL and rate limiting.

### Delegation
The process by which a parent zone directs DNS queries for a subdomain to child nameservers.

**RFC**: RFC 1035 §4.2

### DKIM (DomainKeys Identified Mail)
Email authentication using DNS TXT records to store public keys for verifying email signatures.

**RFC**: RFC 6376

### DMARC (Domain-based Message Authentication, Reporting & Conformance)
Email authentication policy that combines SPF and DKIM with reporting.

**RFC**: RFC 7489

### DNSSEC (DNS Security Extensions)
A set of extensions that add cryptographic signatures to DNS records, enabling verification of authenticity and integrity.

**RFC**: RFCs 4033, 4034, 4035, 5011, 6840, 7583

### DNSKEY
A DNSSEC record containing a public key used to verify RRSIG records.

**RFC**: RFC 4034 §2

### DO (DNSSEC OK) Flag
An EDNS0 option flag indicating client can handle DNSSEC responses. Included in cache key to fix VULN-060.

**RFC**: RFC 3225

### DNS64
A mechanism for synthesizing AAAA records from A records, enabling IPv6 clients to communicate with IPv4-only servers.

**RFC**: RFC 6147

### DOC (Delegation of Signing)
See: ZONEMD

### Domain
A namespaced entity in DNS, identified by one or more labels separated by dots.

### DNAME (Delegation Name)
A record that redirects an entire subtree of DNS names to another domain. Unlike CNAME, applies to all subdomains.

**RFC**: RFC 6672

### DoH (DNS over HTTPS)
DNS transport protocol that encapsulates DNS queries in HTTP(S) requests.

**RFC**: RFC 8484

### DoQ (DNS over QUIC)
DNS transport protocol using QUIC (UDP-based multiplexed transport).

**RFC**: RFC 9250

### DoT (DNS over TLS)
DNS transport protocol using TLS encryption over TCP.

**RFC**: RFC 8310

### DSC (DNSSEC Look-Aside Validation)
See: DS

### DS (Delegation Signer)
A DNSSEC record that references a child zone's DNSKEY, establishing chain of trust from parent to child.

**RFC**: RFC 4034 §5

### DSO (DNS Stateful Operations)
A protocol extension for managing long-lived DNS sessions.

**RFC**: RFC 8490

### Dynamic Update
RFC 2136 protocol for adding, modifying, or deleting DNS records dynamically.

**RFC**: RFC 2136

---

## E

### ECDSA (Elliptic Curve Digital Signature Algorithm)
A public key cryptographic algorithm used in DNSSEC. Preferred over RSA for better performance.

**RFC**: RFC 6605

### EDE (Extended DNS Errors)
Additional error information beyond standard RCODEs for debugging DNS failures.

**RFC**: RFC 8914

### EDNS0 (Extension Mechanisms for DNS)
A mechanism for extending DNS protocol functionality without changing the base protocol. Adds OPT records.

**RFC**: RFC 6891

### Expire
In SOA records, the time after which a secondary nameserver should stop answering queries if it can't contact the primary.

**RFC**: RFC 1035 §3.3.13

---

## F

### FQDN (Fully Qualified Domain Name)
A domain name that includes all labels to the root, ending with a dot (e.g., `www.example.com.`).

### Forwarder
A DNS server that forwards queries to other DNS servers instead of performing recursive resolution.

---

## G

### GeoDNS
Geographic DNS routing that returns different answers based on the client's IP address location.

### Gossip Protocol
A SWIM-like failure detection and dissemination protocol used in NothingDNS cluster for node membership.

---

## H

### Header
The first 12 bytes of a DNS message, containing transaction ID, flags, and record counts.

**RFC**: RFC 1035 §4.1.1

### HMAC (Hash-based Message Authentication Code)
A cryptographic MAC using hash functions. Used in TSIG for authenticating DNS messages.

**RFC**: RFC 4635

### HINFO (Host Information)
A record type containing CPU and operating system information about a host.

**RFC**: RFC 1035 §3.3.2

---

## I

### IDNA (Internationalized Domain Names in Applications)
A protocol for handling non-ASCII characters in domain names. NothingDNS validates IDNA per RFC 5891.

**RFC**: RFC 5891, RFC 5892, RFC 5893

### In-addr.arpa
The reverse DNS namespace for IPv4 addresses (Class A, B, C networks).

**RFC**: RFC 1035 §3.5

### Indy
See: DNSSEC

### IP6.arpa
The reverse DNS namespace for IPv6 addresses.

**RFC**: RFC 3596 §2.5

### IPv6
Internet Protocol version 6, using 128-bit addresses. AAAA records store IPv6 addresses.

**RFC**: RFC 3596

### IXFR (Incremental Zone Transfer)
An efficient zone transfer mechanism that only transfers changed records instead of the entire zone.

**RFC**: RFC 1995

---

## K

### KSK (Key Signing Key)
A DNSSEC key used only to sign the DNSKEY RRset. Its corresponding DS record is published in the parent zone.

**RFC**: RFC 7583 §3.2

---

## L

### Label
A single component of a domain name (e.g., "www" in "www.example.com"). Maximum 63 characters.

**RFC**: RFC 1035 §2.3.1

### LDH
Letters, digits, hyphen. The allowed characters in domain name labels per RFC 952.

### LDNS
Local DNS. The recursive resolver on the client network, typically provided by ISP or network.

### LRU (Least Recently Used)
A cache eviction algorithm that removes the least recently accessed items first.

### LUA (Longest Used Alternative)
Not related to Lua. A proposed DNS record type for alternative resolution.

---

## M

### mDNS (Multicast DNS)
A DNS-like protocol for service discovery on local networks without a unicast DNS server.

**RFC**: RFC 6762

### MX (Mail Exchange)
A record type specifying the mail servers responsible for accepting email for a domain.

**RFC**: RFC 1035 §3.3.9

---

## N

### Name Compression
A technique in DNS wire format that replaces repeated domain names with pointers to previous occurrences, reducing message size.

**RFC**: RFC 1035 §4.1.4

### NAPTR (Naming Authority Pointer)
A record type used in ENUM and SIP to rewrite URIs into DNS names.

**RFC**: RFC 2915

### Natively Compiled
See: AOT (Ahead-of-Time)

### NODATA
A DNS response where the answer section is empty but the query was valid. Indicates the name exists but has no records of the requested type.

### NS (Name Server)
A record type identifying the authoritative nameservers for a zone.

**RFC**: RFC 1035 §3.3.11

### NSEC (Next Secure)
A DNSSEC record that proves a name does not exist by listing the next existing name in sorted order.

**RFC**: RFC 4034 §4

### NSEC3
A variant of NSEC that uses hashed names to prevent enumeration of zone contents.

**RFC**: RFC 5155

### NSEC3PARAM
A record published by DNSSEC-signed zones to indicate NSEC3 parameters for validators.

**RFC**: RFC 5155 §4

### NSecCache
NothingDNS component that caches NSEC records for RFC 8198 aggressive negative caching.

### NSID (Name Server Identifier)
An EDNS0 option that allows nameservers to identify themselves in responses.

**RFC**: RFC 5001

### NXDOMAIN
A DNS response code indicating the queried domain name does not exist. Used in negative caching.

**RFC**: RFC 1035 §4.1.1

---

## O

### ODoH (Oblivious DNS over HTTPS)
A protocol that separates DNS resolver from the entity that sees the DNS query, providing improved privacy.

**RFC**: RFC 9230

### OPT
A pseudo-record type used in EDNS0 to extend DNS functionality. Appended as the last record in the additional section.

**RFC**: RFC 6891 §6

---

## P

### Packet
See: DNS Message

### Parent Zone
A zone that delegates authority for a subdomain to a child zone. The zone one level higher in the DNS hierarchy.

### PD (Privacy Enhancements for DNS)
See: TLS, DoT, DoQ, DoH

### PDNS
PowerDNS. Another DNS server implementation.

### Poisoning
See: DNS Poisoning

### PTR (Pointer)
A record type used for reverse DNS lookups, mapping IP addresses to hostnames.

**RFC**: RFC 1035 §3.3.12

### QNAME
The domain name being queried in a DNS request.

### QTYPE
The type of DNS record being queried (A, AAAA, MX, etc.).

### Question Section
The first section of a DNS message, containing the query details.

**RFC**: RFC 1035 §4.3.1

---

## R

### RA (Recursion Available) Flag
A DNS header flag indicating whether the nameserver supports recursive queries.

**RFC**: RFC 1035 §4.1.1

### RCODE (Response Code)
A 4-bit field in DNS header indicating the status of the response (0=OK, 2=SERVFAIL, 3=NXDOMAIN, etc.).

**RFC**: RFC 1035 §4.1.1

### RD (Recursion Desired) Flag
A DNS header flag sent by client indicating it wants recursive resolution.

**RFC**: RFC 1035 §4.1.1

### RDATA
The data portion of a DNS resource record, format varies by record type.

**RFC**: RFC 1035 §3.2.1

### RDS
See: Reverse DNS

### Refresh
In SOA records, the interval (in seconds) a secondary nameserver should wait before checking for zone changes.

**RFC**: RFC 1035 §3.3.13

### Resolver
A DNS client that performs recursive queries on behalf of end clients. NothingDNS includes an iterative resolver.

**RFC**: RFC 1035 §2.4

### Response Rate Limiting (RRL)
A technique for detecting and limiting DNS amplification attacks by rate-limiting responses based on response patterns.

### Retry
In SOA records, the interval (in seconds) a secondary nameserver should wait before retrying a failed zone transfer.

**RFC**: RFC 1035 §3.3.13

### RFC (Request for Comments)
The document series that defines Internet standards, including DNS protocols.

**Website**: https://www.rfc-editor.org/

### RNAME
The administrative contact email in SOA records (with @ replaced by .).

**RFC**: RFC 1035 §3.3.13

### Root Hints
A set of NS and A records pointing to root nameservers, used by resolvers to begin iterative resolution.

### Root Zone
The apex of the DNS namespace (.), delegated to 13 logical root nameservers (a-m.root-servers.net).

### RRL
See: Response Rate Limiting

### RRSIG (Resource Record Signature)
A DNSSEC record containing a cryptographic signature over an RRset.

**RFC**: RFC 4034 §3

### RRset (Resource Record Set)
A set of DNS records with the same name, type, and class. The atomic unit of DNSSEC signatures.

**RFC**: RFC 4034 §5

### RSA
A public-key cryptosystem used in DNSSEC for digital signatures.

**RFC**: RFC 5702

---

## S

### Secondary
See: Slave Nameserver

### SERVFAIL
A DNS response code indicating the server encountered an error while processing the query.

**RFC**: RFC 1035 §4.1.1

### SFD (See Full Delegate)
Not a standard acronym.

### SHA
Secure Hash Algorithm. Family of cryptographic hash functions (SHA-1, SHA-256, SHA-512) used in DNSSEC.

### SLAAC
Stateless Address Autoconfiguration. IPv6 address assignment method.

### Slave Nameserver
A nameserver that receives zone transfers from a master nameserver. Also called secondary.

**RFC**: RFC 5936

### SM
See: Secondary

### SOA (Start of Authority)
A record containing authoritative information about a zone, including serial number and timing values.

**RFC**: RFC 1035 §3.3.13

### SPF (Sender Policy Framework)
An email authentication method using DNS TXT records to specify which mail servers can send email for a domain.

**RFC**: RFC 7208

### SPOF
Single Point of Failure. A component whose failure causes entire system failure.

### SRV (Service)
A record type for specifying the location of services (hostname and port).

**RFC**: RFC 2782

### SSHFingerprints
SSH key fingerprints published in DNS (RFC 4255).

### Static
A DNS record that is permanently configured and not dynamically updated.

### Stale Cache
Cache entries that have exceeded their TTL but are still served when upstream is unavailable (RFC 8767).

### Strip
In DNS response minimization, removing unnecessary sections from responses.

**RFC**: RFC 6604

### Subdomain
A domain that is a child of another domain. E.g., "www" is a subdomain of "example.com".

### Superlative
A type of amplification attack where the response is much larger than the query.

### SWIM
Scalable Weakly-consistent Infection-style Membership protocol. The gossip protocol used by NothingDNS cluster.

---

## T

### TC (Truncated) Flag
A DNS header flag indicating the response was truncated and should be retried over TCP.

**RFC**: RFC 1035 §4.1.1

### TCP
Transmission Control Protocol. Used for DNS when responses are too large for UDP, zone transfers, and DoT.

### TTL (Time To Live)
A value indicating how long a DNS record may be cached, in seconds.

**RFC**: RFC 1035 §3.2.2

### TKEY
A record type for exchanging TSIG keys between DNS servers.

**RFC**: RFC 2930

### TLSA
A record type used by DANE to associate TLS certificates with domain names.

**RFC**: RFC 6698

### TSIG (Transaction Signature)
A protocol for authenticating DNS messages using HMAC-MD5, HMAC-SHA1, HMAC-SHA256, etc.

**RFC**: RFC 2845

### TXT (Text)
A record type for storing arbitrary text data. Used for SPF, DKIM, DMARC, and verification records.

**RFC**: RFC 1035 §3.3.14

### TXID
Transaction ID. A 16-bit identifier in DNS header used to match queries with responses.

**RFC**: RFC 1035 §4.1.1

---

## U

### UD (Update Destination)
Not a standard acronym.

### UDP
User Datagram Protocol. The primary transport for DNS queries and responses. Limited to 512 bytes (without EDNS0).

### Upstream
An external DNS server that NothingDNS forwards queries to when not serving authoritative answers.

### URL
Uniform Resource Locator. Not directly related to DNS, but DNS A/AAAA records provide the IP addresses for URLs.

---

## V

### Validation
The process of verifying DNSSEC signatures in a DNS response.

**RFC**: RFC 4035 §5

### VE
Version. Not commonly used in DNS context.

### VPN
Virtual Private Network. May use DNS for internal hostname resolution.

---

## W

### Waive
Not a DNS term.

### WAL (Write-Ahead Log)
A log of database operations that is written before applying changes, used for crash recovery.

### WebUI
The embedded React dashboard in NothingDNS, served at the HTTP port.

### WHOIS
A protocol for querying databases of registered domain names.

### Wildcard
A DNS record starting with `*` that matches any subdomain (e.g., `*.example.com`).

**RFC**: RFC 4592

### WKS (Well-Known Services)
A record type listing services and protocols supported by a host. Obsolete.

**RFC**: RFC 1035 §3.3.2

### WS (WebSocket)
A bidirectional communication protocol used for live query streaming in NothingDNS dashboard.

---

## X

### XFR
See: AXFR, IXFR

---

## Z

### Zone
A contiguous portion of the DNS namespace administered by a single authority.

**RFC**: RFC 1035 §2.4

### Zone Apex
The root of a zone, e.g., "example.com" is the apex of the "example.com" zone.

### Zone File
A text file containing DNS records in BIND format.

### Zone Transfer
The process of copying zone data between nameservers. See: AXFR, IXFR, XoT.

### ZONEMD (Zone Message Digest)
A mechanism for verifying zone content integrity, providing an alternative to DNSSEC for zone validation.

**RFC**: RFC 8976

### ZSK (Zone Signing Key)
A DNSSEC key used to sign all records in a zone except the DNSKEY RRset.

**RFC**: RFC 7583 §3.1

---

## RFC Index

| RFC | Title | Area |
|-----|-------|------|
| 1035 | Domain Names - Implementation and Specification | Core DNS |
| 1996 | A Mechanism for Prompt Notification of Zone Changes (NOTIFY) | Zone Transfer |
| 2136 | Dynamic Updates in the Domain Name System (UPDATE) | Dynamic DNS |
| 2308 | Negative Caching of DNS Queries (NXDOMAIN) | Cache |
| 2782 | A DNS RR for Specifying Service Location (SRV) | Records |
| 2845 | Secret Key Transaction Authentication for DNS (TSIG) | Security |
| 2915 | The Naming Authority Pointer (NAPTR) DNS Resource Record | Records |
| 2930 | Secret Key Exchange for DNS (TKEY) | Security |
| 3007 | Secure Domain Name System (DNSSEC) Dynamic Updates | DNSSEC |
| 3596 | Extension Mechanisms for DNS (IPv6 Support) | Extensions |
| 4033 | DNS Security Introduction and Requirements | DNSSEC |
| 4034 | Resource Records for DNS Security Extensions | DNSSEC |
| 4035 | Protocol Modifications for DNS Security Extensions | DNSSEC |
| 4255 | Using DNS to Securely Publish SSH Key Fingerprints | DNS Usage |
| 4255 | See SSHFingerprints | DNS Usage |
| 5011 | Automated Testing of DNSSEC Delegation Trust | DNSSEC |
| 5155 | DNS Security (DNSSEC) NSEC3 | DNSSEC |
| 5452 | Measures for Making DNS More Resilient | Security |
| 5891 | Internationalized Domain Names in Applications (IDNA) | Internationalization |
| 5936 | DNS Zone Transfer Protocol (AXFR) | Zone Transfer |
| 6147 | DNS64 (NAT64) | IPv6 |
| 6604 | Edns Subnet Option (ECS) | Extensions |
| 6761 | Special-Use Domain Names | DNS Usage |
| 6762 | Multicast DNS (mDNS) | Discovery |
| 6891 | Extension Mechanisms for DNS (EDNS0) | Extensions |
| 6895 | Reserved DNS Header Bits | Core DNS |
| 6975 | Signaling Cryptographic Algorithm Understanding | DNSSEC |
| 7208 | Sender Policy Framework (SPF) | Email |
| 7583 | DNSSEC Key Rollover Timing Considerations | DNSSEC |
| 7766 | DNS over TCP | Transport |
| 7816 | DNS Query Name Minimization | Privacy |
| 7849 | Email Processing by DNS | Email |
| 7858 | Specification for DNS over TLS | Transport |
| 7910 | Single Point of Failure | Architecture |
| 8027 | DNSSEC Provably False | DNSSEC |
| 8085 | UDP Usage Guidelines | Transport |
| 8162 | Using DNSSEC with SMTP | Email |
| 8198 | Aggressive Use of DNSSEC-Validated Cache | Cache |
| 8310 | Usage Profiles for DNS over TLS and DNS over HTTPS | Transport |
| 8324 | DNS over HTTPS | Transport |
| 8482 | Fetching DNS Resources (ANY/0x00 query) | Queries |
| 8484 | DNS over HTTPS (DoH) | Transport |
| 8490 | DNS Stateful Operations (DSO) | Extensions |
| 8624 | DNSSEC Algorithm Requirements | DNSSEC |
| 8767 | Serving Stale DNS Data | Cache |
| 8914 | Extended DNS Errors | Extensions |
| 8932 | Private DNS | Privacy |
| 8976 | Zone Metadata (ZONEMD) | Zone |
| 9076 | DNS Privacy | Privacy |
| 9103 | DNS Zone Transfer over TLS (XoT) | Transport |
| 9218 | Extensible Provisioning Protocol (EPP) | Provisioning |
| 9230 | Oblivious DNS over HTTPS (ODoH) | Privacy |
| 9250 | DNS over QUIC (DoQ) | Transport |

---

## Quick Reference

### Common Record Types

| Type | Purpose | RFC |
|------|---------|-----|
| A | IPv4 address | 1035 |
| AAAA | IPv6 address | 3596 |
| CNAME | Canonical name (alias) | 1035 |
| MX | Mail exchange | 1035 |
| NS | Nameserver | 1035 |
| SOA | Start of authority | 1035 |
| TXT | Text record | 1035 |
| DNSKEY | DNSSEC public key | 4034 |
| DS | Delegation signer | 4034 |
| RRSIG | DNSSEC signature | 4034 |
| NSEC | Proof of none-existence | 4034 |
| NSEC3 | Hashed proof of none-existence | 5155 |
| SRV | Service locator | 2782 |
| CAA | Certification authority authorization | 8659 |
| TLSA | TLS certificate association | 6698 |

### Response Codes (RCODEs)

| Code | Name | Meaning |
|------|------|---------|
| 0 | NOERROR | Success |
| 1 | FORMERR | Format error |
| 2 | SERVFAIL | Server failure |
| 3 | NXDOMAIN | Name does not exist |
| 4 | NOTIMP | Not implemented |
| 5 | REFUSED | Query refused |
| 6 | YXDOMAIN | Name exists (for UPDATE) |
| 7 | YXRRSET | RRset exists |
| 8 | NOTAUTH | Not authoritative |
| 9 | NOTZONE | Not in zone |

### EDNS0 Option Codes

| Code | Name | RFC |
|------|------|-----|
| 1 | LLQ | 6891 |
| 2 | UL | 6891 |
| 3 | NSID | 5001 |
| 5 | DAU | 6895 |
| 6 | DHU | 6895 |
| 7 | N3U | 6895 |
| 8 | Client Subnet | 7871 |
| 9 | TCP Keepalive | 7828 |
| 10 | Cookie | 7873 |
| 12 | Padding | 7830 |
| 13 | Chain | 7901 |

### Transport Comparison

| Protocol | Port | Encryption | RFC |
|----------|------|------------|-----|
| DNS | 53/UDP, 53/TCP | None | 1035 |
| DoT | 853/TCP | TLS 1.3 | 8310 |
| DoH | 443/HTTPS | TLS | 8484 |
| DoQ | 853/UDP | QUIC/TLS | 9250 |
| XoT | 853/TCP | TLS | 9103 |
| ODoH | 443/HTTPS | TLS + proxy | 9230 |
