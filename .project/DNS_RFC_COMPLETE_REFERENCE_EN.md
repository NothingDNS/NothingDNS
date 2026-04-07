# Complete DNS RFC Reference Guide

> **Purpose:** Every RFC needed to build a full-stack DNS Server from scratch  
> **Last Updated:** April 2026  
> **Sources:** IETF Datatracker, StatDNS, ICANN RFC Annotations  
> **Total:** 200+ RFCs across 17 categories

---

## TIER 1 — MANDATORY CORE (No DNS Server Without These)

### 1.1 Core Protocol

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [1034](https://datatracker.ietf.org/doc/html/rfc1034) | Domain Names — Concepts and Facilities | 1987-11 | **THE BIBLE** — All fundamental concepts |
| [1035](https://datatracker.ietf.org/doc/html/rfc1035) | Domain Names — Implementation and Specification | 1987-11 | **THE BIBLE PT.2** — Wire format, message structure, RR types |
| [2181](https://datatracker.ietf.org/doc/html/rfc2181) | Clarifications to the DNS Specification | 1997-07 | Critical fixes to 1034/1035 |
| [3597](https://datatracker.ietf.org/doc/html/rfc3597) | Handling of Unknown DNS RR Types | 2003-09 | How to process unknown RR types |
| [4343](https://datatracker.ietf.org/doc/html/rfc4343) | DNS Case Insensitivity Clarification | 2006-01 | Case-insensitive comparison rules |
| [6895](https://datatracker.ietf.org/doc/html/rfc6895) | DNS IANA Considerations | 2013-04 | RR type, class, opcode registry |
| [9499](https://datatracker.ietf.org/doc/html/rfc9499) | DNS Terminology | 2024-03 | Current terminology reference (obsoletes RFC 8499) |
| [9267](https://datatracker.ietf.org/doc/html/rfc9267) | Common Implementation Anti-Patterns Related to DNS RR Processing | 2022-07 | Common implementation mistakes to avoid |

### 1.2 Transport Layer

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [7766](https://datatracker.ietf.org/doc/html/rfc7766) | DNS Transport over TCP — Implementation Requirements | 2016-03 | TCP is now MANDATORY |
| [9210](https://datatracker.ietf.org/doc/html/rfc9210) | DNS Transport over TCP — Operational Requirements | 2022-03 | TCP operational requirements (updates 7766) |
| [9715](https://datatracker.ietf.org/doc/html/rfc9715) | IP Fragmentation Avoidance in DNS over UDP | 2025-01 | Avoiding UDP fragmentation |
| [1982](https://datatracker.ietf.org/doc/html/rfc1982) | Serial Number Arithmetic | 1996-08 | SOA serial comparison math |
| [8490](https://datatracker.ietf.org/doc/html/rfc8490) | DNS Stateful Operations | 2019-03 | DSO — Stateful operations over TCP |

### 1.3 EDNS — Extension Mechanisms

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [6891](https://datatracker.ietf.org/doc/html/rfc6891) | Extension Mechanisms for DNS (EDNS(0)) | 2013-04 | **CRITICAL** — OPT pseudo-RR, large messages (obsoletes RFC 2671) |
| [7830](https://datatracker.ietf.org/doc/html/rfc7830) | The EDNS(0) Padding Option | 2016-05 | Privacy padding |
| [7828](https://datatracker.ietf.org/doc/html/rfc7828) | The edns-tcp-keepalive EDNS0 Option | 2016-04 | TCP keepalive |
| [7871](https://datatracker.ietf.org/doc/html/rfc7871) | Client Subnet in DNS Queries | 2016-05 | ECS — Critical for GeoDNS |
| [8467](https://datatracker.ietf.org/doc/html/rfc8467) | Padding Policies for EDNS(0) | 2018-10 | Padding strategies |
| [7314](https://datatracker.ietf.org/doc/html/rfc7314) | EDNS EXPIRE Option | 2014-07 | Zone expiration info |
| [9660](https://datatracker.ietf.org/doc/html/rfc9660) | The DNS Zone Version (ZONEVERSION) Option | 2024-10 | Zone version info |
| [9619](https://datatracker.ietf.org/doc/html/rfc9619) | In the DNS, QDCOUNT Is (Usually) One | 2024-07 | QDCOUNT constraint |

### 1.4 Core Resource Record Types

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [1183](https://datatracker.ietf.org/doc/html/rfc1183) | New DNS RR Definitions (AFSDB, RT, X25, ISDN, RP) | 1990-10 | Additional RR types |
| [2782](https://datatracker.ietf.org/doc/html/rfc2782) | DNS SRV RR | 2000-02 | Service location record |
| [3596](https://datatracker.ietf.org/doc/html/rfc3596) | DNS Extensions to Support IPv6 | 2003-10 | **AAAA record** |
| [6672](https://datatracker.ietf.org/doc/html/rfc6672) | DNAME Redirection in the DNS | 2012-06 | DNAME record |
| [4408](https://datatracker.ietf.org/doc/html/rfc4408) | Sender Policy Framework (SPF) | 2006-04 | SPF/TXT record (email security) |
| [7553](https://datatracker.ietf.org/doc/html/rfc7553) | The URI DNS Resource Record | 2015-06 | URI record |
| [8659](https://datatracker.ietf.org/doc/html/rfc8659) | DNS CAA Resource Record | 2019-11 | Certification Authority Authorization |
| [1876](https://datatracker.ietf.org/doc/html/rfc1876) | LOC — Location Information in DNS | 1996-01 | Geographic location record |
| [7043](https://datatracker.ietf.org/doc/html/rfc7043) | EUI-48 and EUI-64 RRs | 2013-10 | MAC address records |
| [1464](https://datatracker.ietf.org/doc/html/rfc1464) | Using DNS To Store Arbitrary String Attributes | 1993-05 | TXT record usage |
| [4255](https://datatracker.ietf.org/doc/html/rfc4255) | Using DNS to Publish SSH Key Fingerprints (SSHFP) | 2006-01 | SSH key verification |
| [6594](https://datatracker.ietf.org/doc/html/rfc6594) | SHA-256 in SSHFP Resource Records | 2012-04 | SSHFP update |
| [7479](https://datatracker.ietf.org/doc/html/rfc7479) | Ed25519 in SSHFP Resource Records | 2015-03 | Modern SSHFP |
| [4398](https://datatracker.ietf.org/doc/html/rfc4398) | Storing Certificates in DNS (CERT) | 2006-03 | Certificate record |
| [4025](https://datatracker.ietf.org/doc/html/rfc4025) | Storing IPsec Keying Material in DNS (IPSECKEY) | 2005-03 | IPsec keying |
| [2317](https://datatracker.ietf.org/doc/html/rfc2317) | Classless IN-ADDR.ARPA Delegation | 1998-03 | CIDR reverse DNS |
| [3403](https://datatracker.ietf.org/doc/html/rfc3403) | DDDS Part Three: DNS Database (NAPTR) | 2002-10 | NAPTR record |
| [6742](https://datatracker.ietf.org/doc/html/rfc6742) | DNS RRs for ILNP | 2012-11 | NID, L32, L64, LP records |

---

## TIER 2 — ZONE MANAGEMENT & TRANSFER

### 2.1 Zone Transfer

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [5936](https://datatracker.ietf.org/doc/html/rfc5936) | DNS Zone Transfer Protocol (AXFR) | 2010-06 | Full zone transfer |
| [1995](https://datatracker.ietf.org/doc/html/rfc1995) | Incremental Zone Transfer (IXFR) | 1996-08 | Delta zone transfer |
| [1996](https://datatracker.ietf.org/doc/html/rfc1996) | DNS NOTIFY | 1996-08 | Zone change notification |
| [9103](https://datatracker.ietf.org/doc/html/rfc9103) | DNS Zone Transfer over TLS (XoT) | 2021-08 | Encrypted zone transfer |
| [9432](https://datatracker.ietf.org/doc/html/rfc9432) | DNS Catalog Zones | 2023-07 | Automatic zone provisioning |
| [9859](https://datatracker.ietf.org/doc/html/rfc9859) | Generalized DNS Notifications | 2025-09 | Modern notification mechanism |

### 2.2 Dynamic DNS (DDNS)

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [2136](https://datatracker.ietf.org/doc/html/rfc2136) | Dynamic Updates in DNS (DNS UPDATE) | 1997-04 | Dynamic record updates |
| [3007](https://datatracker.ietf.org/doc/html/rfc3007) | Secure DNS Dynamic Update | 2000-11 | Secured DDNS |
| [9664](https://datatracker.ietf.org/doc/html/rfc9664) | EDNS(0) Option to Negotiate Leases on DNS Updates | 2025-06 | Update lease negotiation |

### 2.3 Caching & Negative Caching

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [2308](https://datatracker.ietf.org/doc/html/rfc2308) | Negative Caching of DNS Queries (NCACHE) | 1998-03 | Negative caching rules |
| [8767](https://datatracker.ietf.org/doc/html/rfc8767) | Serving Stale Data to Improve DNS Resiliency | 2020-03 | Stale cache serving |
| [8020](https://datatracker.ietf.org/doc/html/rfc8020) | NXDOMAIN: There Really Is Nothing Underneath | 2016-11 | NXDOMAIN cut |
| [9520](https://datatracker.ietf.org/doc/html/rfc9520) | Negative Caching of DNS Resolution Failures | 2023-12 | Resolution failure caching |
| [8198](https://datatracker.ietf.org/doc/html/rfc8198) | Aggressive Use of DNSSEC-Validated Cache | 2017-07 | DNSSEC cache optimization |

---

## TIER 3 — DNSSEC (DNS Security Extensions)

### 3.1 DNSSEC Core

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [4033](https://datatracker.ietf.org/doc/html/rfc4033) | DNS Security Introduction and Requirements | 2005-03 | DNSSEC introduction |
| [4034](https://datatracker.ietf.org/doc/html/rfc4034) | Resource Records for DNSSEC | 2005-03 | DNSKEY, RRSIG, DS, NSEC |
| [4035](https://datatracker.ietf.org/doc/html/rfc4035) | Protocol Modifications for DNSSEC | 2005-03 | Protocol changes |
| [9364](https://datatracker.ietf.org/doc/html/rfc9364) | DNS Security Extensions (DNSSEC) | 2023-02 | **CURRENT DNSSEC overview** |
| [6840](https://datatracker.ietf.org/doc/html/rfc6840) | Clarifications and Implementation Notes for DNSSEC | 2013-02 | Implementation notes |

### 3.2 NSEC / NSEC3 (Authenticated Denial of Existence)

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [5155](https://datatracker.ietf.org/doc/html/rfc5155) | DNSSEC Hashed Authenticated Denial (NSEC3) | 2008-03 | Zone enumeration protection |
| [9077](https://datatracker.ietf.org/doc/html/rfc9077) | NSEC and NSEC3: TTLs and Aggressive Use | 2021-07 | TTL corrections |
| [9276](https://datatracker.ietf.org/doc/html/rfc9276) | Guidance for NSEC3 Parameter Settings | 2022-08 | NSEC3 parameter guidance |
| [7129](https://datatracker.ietf.org/doc/html/rfc7129) | Authenticated Denial of Existence in DNS | 2014-02 | Conceptual explanation |
| [9824](https://datatracker.ietf.org/doc/html/rfc9824) | Compact Denial of Existence in DNSSEC | 2025-09 | **NEW** — Compact denial |

### 3.3 DNSSEC Algorithms & Cryptography

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [8624](https://datatracker.ietf.org/doc/html/rfc8624) | Algorithm Implementation Requirements for DNSSEC | 2019-06 | Which algorithms are mandatory/recommended |
| [5702](https://datatracker.ietf.org/doc/html/rfc5702) | SHA-2 Algorithms with RSA in DNSSEC | 2009-10 | RSA/SHA-256, RSA/SHA-512 |
| [6605](https://datatracker.ietf.org/doc/html/rfc6605) | ECDSA for DNSSEC | 2012-04 | Elliptic Curve |
| [8080](https://datatracker.ietf.org/doc/html/rfc8080) | EdDSA for DNSSEC | 2017-02 | Ed25519 / Ed448 |
| [3110](https://datatracker.ietf.org/doc/html/rfc3110) | RSA/SHA-1 SIGs and RSA KEYs in DNS | 2001-05 | Legacy but still widespread |
| [4509](https://datatracker.ietf.org/doc/html/rfc4509) | SHA-256 in DS Resource Records | 2006-05 | DS record hashing |
| [6014](https://datatracker.ietf.org/doc/html/rfc6014) | Cryptographic Algorithm Identifier Allocation for DNSSEC | 2010-11 | Algorithm allocation |
| [6725](https://datatracker.ietf.org/doc/html/rfc6725) | DNSKEY Algorithm IANA Registry Updates | 2012-08 | Registry update |
| [6975](https://datatracker.ietf.org/doc/html/rfc6975) | Signaling Crypto Algorithm Understanding in DNSSEC | 2013-07 | Algorithm signaling |
| [9904](https://datatracker.ietf.org/doc/html/rfc9904) | DNSSEC Crypto Algorithm Recommendation Update Process | 2025-11 | **NEW** — Update process |
| [9905](https://datatracker.ietf.org/doc/html/rfc9905) | Deprecating SHA-1 in DNSSEC Signature Algorithms | 2025-11 | **NEW** — SHA-1 deprecated |
| [9906](https://datatracker.ietf.org/doc/html/rfc9906) | Deprecate ECC-GOST within DNSSEC | 2025-11 | **NEW** — GOST deprecated |

### 3.4 DNSSEC Operations & Trust Anchors

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [5011](https://datatracker.ietf.org/doc/html/rfc5011) | Automated Updates of DNSSEC Trust Anchors | 2007-09 | RFC 5011 rollover |
| [7344](https://datatracker.ietf.org/doc/html/rfc7344) | Automating DNSSEC Delegation Trust Maintenance | 2014-09 | CDS/CDNSKEY |
| [8078](https://datatracker.ietf.org/doc/html/rfc8078) | Managing DS Records via CDS/CDNSKEY | 2017-03 | Parent DS management |
| [7583](https://datatracker.ietf.org/doc/html/rfc7583) | DNSSEC Key Rollover Timing | 2015-10 | Rollover timing considerations |
| [6781](https://datatracker.ietf.org/doc/html/rfc6781) | DNSSEC Operational Practices v2 | 2012-12 | Operational guide |
| [6841](https://datatracker.ietf.org/doc/html/rfc6841) | Framework for DNSSEC Policies & Practice Statements | 2013-01 | DPS framework |
| [7646](https://datatracker.ietf.org/doc/html/rfc7646) | DNSSEC Negative Trust Anchors | 2015-09 | NTA definition and usage |
| [8027](https://datatracker.ietf.org/doc/html/rfc8027) | DNSSEC Roadblock Avoidance | 2016-11 | Troubleshooting guide |
| [8145](https://datatracker.ietf.org/doc/html/rfc8145) | Signaling Trust Anchor Knowledge in DNSSEC | 2017-04 | Trust anchor signaling |
| [8509](https://datatracker.ietf.org/doc/html/rfc8509) | Root Key Trust Anchor Sentinel for DNSSEC | 2018-12 | Sentinel mechanism |
| [9157](https://datatracker.ietf.org/doc/html/rfc9157) | Revised IANA Considerations for DNSSEC | 2021-12 | Registry updates |
| [9615](https://datatracker.ietf.org/doc/html/rfc9615) | Automatic DNSSEC Bootstrapping | 2024-07 | Automated DNSSEC setup |
| [9718](https://datatracker.ietf.org/doc/html/rfc9718) | DNSSEC Trust Anchor Publication for Root Zone | 2025-01 | Root trust anchor publication |
| [7958](https://datatracker.ietf.org/doc/html/rfc7958) | DNSSEC Trust Anchor Publication for Root Zone (legacy) | 2016-08 | Updated by 9718 |
| [8901](https://datatracker.ietf.org/doc/html/rfc8901) | Multi-Signer DNSSEC Models | 2020-09 | Multi-signer models |

### 3.5 TSIG & SIG(0) — Transaction Security

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [8945](https://datatracker.ietf.org/doc/html/rfc8945) | Secret Key Transaction Authentication (TSIG) | 2020-11 | **CURRENT TSIG** (obsoletes RFC 2845) |
| [2930](https://datatracker.ietf.org/doc/html/rfc2930) | Secret Key Establishment for DNS (TKEY RR) | 2000-09 | Key exchange |
| [3645](https://datatracker.ietf.org/doc/html/rfc3645) | GSS-TSIG | 2003-10 | Kerberos/GSS-API based TSIG |
| [2931](https://datatracker.ietf.org/doc/html/rfc2931) | DNS Request and Transaction Signatures (SIG(0)) | 2000-09 | Public key based |

---

## TIER 4 — ENCRYPTED DNS (DoT / DoH / DoQ)

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [7858](https://datatracker.ietf.org/doc/html/rfc7858) | DNS over Transport Layer Security (DoT) | 2016-05 | Port 853 |
| [8310](https://datatracker.ietf.org/doc/html/rfc8310) | Usage Profiles for DoT and DoD TLS | 2018-03 | Strict vs Opportunistic modes |
| [8484](https://datatracker.ietf.org/doc/html/rfc8484) | DNS Queries over HTTPS (DoH) | 2018-10 | Port 443, application/dns-message |
| [9250](https://datatracker.ietf.org/doc/html/rfc9250) | DNS over Dedicated QUIC Connections (DoQ) | 2022-05 | QUIC-based DNS |
| [8094](https://datatracker.ietf.org/doc/html/rfc8094) | DNS over DTLS | 2017-02 | Experimental |
| [9230](https://datatracker.ietf.org/doc/html/rfc9230) | Oblivious DNS over HTTPS (ODoH) | 2022-06 | Proxy-based privacy |
| [9539](https://datatracker.ietf.org/doc/html/rfc9539) | Unilateral Opportunistic Encrypted Recursive-to-Authoritative DNS | 2024-02 | Recursive→Auth encryption |
| [9102](https://datatracker.ietf.org/doc/html/rfc9102) | TLS DNSSEC Chain Extension | 2021-08 | DNSSEC chain in TLS |

---

## TIER 5 — DNS PRIVACY

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [9076](https://datatracker.ietf.org/doc/html/rfc9076) | DNS Privacy Considerations | 2021-07 | General privacy analysis |
| [9156](https://datatracker.ietf.org/doc/html/rfc9156) | DNS Query Name Minimisation (QNAME Minimisation) | 2021-11 | Updates RFC 7816 |
| [7816](https://datatracker.ietf.org/doc/html/rfc7816) | DNS Query Name Minimisation to Improve Privacy | 2016-03 | Original QMIN definition |
| [8932](https://datatracker.ietf.org/doc/html/rfc8932) | Recommendations for DNS Privacy Service Operators | 2020-10 | Operator guidance |

---

## TIER 6 — RESOLVER & RECURSIVE

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [8109](https://datatracker.ietf.org/doc/html/rfc8109) | Initializing a DNS Resolver with Priming Queries | 2017-03 | Root priming |
| [5452](https://datatracker.ietf.org/doc/html/rfc5452) | Measures for Making DNS More Resilient against Forged Answers | 2009-01 | Anti-spoofing measures |
| [5358](https://datatracker.ietf.org/doc/html/rfc5358) | Preventing Use of Recursive Nameservers in Reflector Attacks | 2008-10 | Amplification protection |
| [7873](https://datatracker.ietf.org/doc/html/rfc7873) | DNS Cookies | 2016-05 | Anti-spoofing cookies |
| [9018](https://datatracker.ietf.org/doc/html/rfc9018) | Interoperable DNS Server Cookies | 2021-04 | Standard cookie format |
| [7901](https://datatracker.ietf.org/doc/html/rfc7901) | CHAIN Query Requests in DNS | 2016-06 | Full DNSSEC chain in one query |
| [8914](https://datatracker.ietf.org/doc/html/rfc8914) | Extended DNS Errors | 2020-10 | Detailed error information (EDE) |
| [9567](https://datatracker.ietf.org/doc/html/rfc9567) | DNS Error Reporting | 2024-04 | Error reporting mechanism |
| [9606](https://datatracker.ietf.org/doc/html/rfc9606) | DNS Resolver Information | 2024-06 | Resolver info discovery |
| [5001](https://datatracker.ietf.org/doc/html/rfc5001) | DNS NSID Option | 2007-08 | Server identification |
| [8482](https://datatracker.ietf.org/doc/html/rfc8482) | Minimal-Sized Responses to QTYPE=ANY | 2019-01 | ANY query restriction |
| [8806](https://datatracker.ietf.org/doc/html/rfc8806) | Running a Root Server Local to a Resolver | 2020-06 | Local root mirror |

---

## TIER 7 — AUTHORITATIVE SERVER OPERATIONS

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [4592](https://datatracker.ietf.org/doc/html/rfc4592) | The Role of Wildcards in DNS | 2006-07 | Wildcard behavior |
| [6604](https://datatracker.ietf.org/doc/html/rfc6604) | xNAME RCODE and Status Bits Clarification | 2012-04 | CNAME/DNAME RCODE rules |
| [7477](https://datatracker.ietf.org/doc/html/rfc7477) | Child-to-Parent Synchronization (CSYNC) | 2015-03 | NS/glue synchronization |
| [9471](https://datatracker.ietf.org/doc/html/rfc9471) | DNS Glue Requirements in Referral Responses | 2023-09 | Glue record rules |
| [9199](https://datatracker.ietf.org/doc/html/rfc9199) | Considerations for Large Authoritative DNS Server Operators | 2022-03 | Large-scale operations |
| [7720](https://datatracker.ietf.org/doc/html/rfc7720) | DNS Root Name Service Protocol and Deployment Requirements | 2015-12 | Root server requirements |
| [2182](https://datatracker.ietf.org/doc/html/rfc2182) | Selection and Operation of Secondary DNS Servers | 1997-07 | Secondary server operations |
| [3258](https://datatracker.ietf.org/doc/html/rfc3258) | Distributing Authoritative Nameservers via Shared Unicast | 2002-04 | Anycast infrastructure |
| [8976](https://datatracker.ietf.org/doc/html/rfc8976) | Message Digest for DNS Zones | 2021-02 | ZONEMD — Zone integrity hash |
| [1912](https://datatracker.ietf.org/doc/html/rfc1912) | Common DNS Operational and Configuration Errors | 1996-02 | Common mistakes guide |

---

## TIER 8 — DANE (DNS-Based Authentication of Named Entities)

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [6698](https://datatracker.ietf.org/doc/html/rfc6698) | DANE TLSA Protocol | 2012-08 | TLSA record definition |
| [7671](https://datatracker.ietf.org/doc/html/rfc7671) | DANE Protocol: Updates and Operational Guidance | 2015-10 | DANE updates |
| [7673](https://datatracker.ietf.org/doc/html/rfc7673) | Using DANE TLSA with SRV Records | 2015-10 | SRV + DANE |
| [6394](https://datatracker.ietf.org/doc/html/rfc6394) | Use Cases and Requirements for DANE | 2011-10 | Requirements |
| [7218](https://datatracker.ietf.org/doc/html/rfc7218) | Adding Acronyms to Simplify DANE | 2014-04 | DANE terminology |
| [7929](https://datatracker.ietf.org/doc/html/rfc7929) | DANE Bindings for OpenPGP (OPENPGPKEY) | 2016-08 | PGP keys in DNS |
| [8162](https://datatracker.ietf.org/doc/html/rfc8162) | Using Secure DNS for S/MIME Certificates (SMIMEA) | 2017-05 | S/MIME in DNS |

---

## TIER 9 — DNS-SD & mDNS (Service Discovery)

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [6762](https://datatracker.ietf.org/doc/html/rfc6762) | Multicast DNS (mDNS) | 2013-02 | .local domain |
| [6763](https://datatracker.ietf.org/doc/html/rfc6763) | DNS-Based Service Discovery (DNS-SD) | 2013-02 | Service browsing |
| [8882](https://datatracker.ietf.org/doc/html/rfc8882) | DNS-SD Privacy and Security Requirements | 2020-09 | Privacy requirements |
| [9665](https://datatracker.ietf.org/doc/html/rfc9665) | Service Registration Protocol for DNS-SD | 2025-06 | **NEW** — SRP |
| [7558](https://datatracker.ietf.org/doc/html/rfc7558) | Requirements for Scalable DNS-SD/mDNS Extensions | 2015-07 | Scalability requirements |

---

## TIER 10 — IDN (Internationalized Domain Names)

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [5890](https://datatracker.ietf.org/doc/html/rfc5890) | IDNA: Definitions and Document Framework | 2010-08 | IDNA 2008 framework |
| [5891](https://datatracker.ietf.org/doc/html/rfc5891) | IDNA: Protocol | 2010-08 | IDNA 2008 protocol |
| [5892](https://datatracker.ietf.org/doc/html/rfc5892) | The Unicode Code Points and IDNA | 2010-08 | Character rules |
| [5893](https://datatracker.ietf.org/doc/html/rfc5893) | Right-to-Left Scripts for IDNA | 2010-08 | Arabic/Hebrew support |
| [5894](https://datatracker.ietf.org/doc/html/rfc5894) | IDNA: Background, Explanation, and Rationale | 2010-08 | Explanatory document |
| [5895](https://datatracker.ietf.org/doc/html/rfc5895) | Mapping Characters for IDNA 2008 | 2010-09 | Character mapping |
| [3492](https://datatracker.ietf.org/doc/html/rfc3492) | Punycode | 2003-03 | xn-- encoding |

---

## TIER 11 — ENUM (Telephone Number Mapping)

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [6116](https://datatracker.ietf.org/doc/html/rfc6116) | The E.164 to URI DDDS Application (ENUM) | 2011-03 | Phone→URI mapping |
| [6117](https://datatracker.ietf.org/doc/html/rfc6117) | IANA Registration of Enumservices | 2011-03 | Service registration |
| [6118](https://datatracker.ietf.org/doc/html/rfc6118) | Update of Legacy IANA Registrations of Enumservices | 2011-03 | Registry update |

---

## TIER 12 — SPECIAL USE & INFRASTRUCTURE

### 12.1 Special-Use Domains

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [2606](https://datatracker.ietf.org/doc/html/rfc2606) | Reserved Top Level DNS Names | 1999-06 | .test, .example, .invalid, .localhost |
| [6303](https://datatracker.ietf.org/doc/html/rfc6303) | Locally Served DNS Zones | 2011-07 | Zones to serve locally |
| [6761](https://datatracker.ietf.org/doc/html/rfc6761) | Special-Use Domain Names | 2013-02 | Special-use registry |
| [8375](https://datatracker.ietf.org/doc/html/rfc8375) | Special-Use Domain 'home.arpa.' | 2018-05 | Home networks |
| [8880](https://datatracker.ietf.org/doc/html/rfc8880) | Special Use Domain Name 'ipv4only.arpa' | 2020-08 | NAT64 discovery |
| [7793](https://datatracker.ietf.org/doc/html/rfc7793) | Adding 100.64.0.0/10 to Locally-Served DNS Zones | 2016-05 | CGNAT reverse DNS |
| [9120](https://datatracker.ietf.org/doc/html/rfc9120) | Nameservers for the 'arpa' Domain | 2021-10 | .arpa management |
| [3172](https://datatracker.ietf.org/doc/html/rfc3172) | Management of the 'arpa' Domain | 2001-09 | .arpa operations |

### 12.2 IPv6 DNS

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [3596](https://datatracker.ietf.org/doc/html/rfc3596) | DNS Extensions to Support IPv6 | 2003-10 | AAAA record |
| [3364](https://datatracker.ietf.org/doc/html/rfc3364) | Tradeoffs in DNS Support for IPv6 | 2002-08 | IPv6 DNS analysis |
| [4472](https://datatracker.ietf.org/doc/html/rfc4472) | Operational Considerations with IPv6 DNS | 2006-04 | IPv6 operations |
| [8501](https://datatracker.ietf.org/doc/html/rfc8501) | Reverse DNS in IPv6 for ISPs | 2018-11 | ISP reverse DNS |
| [6147](https://datatracker.ietf.org/doc/html/rfc6147) | DNS64 | 2011-04 | NAT64 DNS translation |
| [8106](https://datatracker.ietf.org/doc/html/rfc8106) | IPv6 RA Options for DNS Configuration | 2017-03 | RDNSS/DNSSL |

### 12.3 AS112 & Infrastructure

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [7534](https://datatracker.ietf.org/doc/html/rfc7534) | AS112 Nameserver Operations | 2015-05 | Sink-hole DNS |
| [7535](https://datatracker.ietf.org/doc/html/rfc7535) | AS112 Redirection Using DNAME | 2015-05 | DNAME redirection |

---

## TIER 13 — THREAT ANALYSIS & SECURITY

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [3833](https://datatracker.ietf.org/doc/html/rfc3833) | Threat Analysis of the DNS | 2004-08 | Threat model |
| [5625](https://datatracker.ietf.org/doc/html/rfc5625) | DNS Proxy Implementation Guidelines | 2009-08 | Proxy security |
| [8906](https://datatracker.ietf.org/doc/html/rfc8906) | Failure to Communicate — Common Operational Problem | 2020-09 | Communication failures |
| [5782](https://datatracker.ietf.org/doc/html/rfc5782) | DNS Blacklists and Whitelists (DNSBL) | 2010-02 | Blocklist mechanism |
| [6471](https://datatracker.ietf.org/doc/html/rfc6471) | Best Email DNSBL Operational Practices | 2012-01 | DNSBL operations |
| [9704](https://datatracker.ietf.org/doc/html/rfc9704) | Establishing Local DNS Authority in Split-Horizon | 2025-01 | Split-horizon security |

---

## TIER 14 — JSON, YANG & DATA FORMATS

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [8427](https://datatracker.ietf.org/doc/html/rfc8427) | Representing DNS Messages in JSON | 2018-07 | DNS→JSON format |
| [9108](https://datatracker.ietf.org/doc/html/rfc9108) | YANG Types for DNS Classes and RR Types | 2021-09 | NETCONF/YANG model |
| [4027](https://datatracker.ietf.org/doc/html/rfc4027) | DNS Media Types | 2005-04 | MIME types |
| [8618](https://datatracker.ietf.org/doc/html/rfc8618) | Compacted-DNS (C-DNS) Packet Capture Format | 2019-09 | DNS packet capture format |

---

## TIER 15 — DDDS / NAPTR / SRV

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [3401](https://datatracker.ietf.org/doc/html/rfc3401) | DDDS Part One: The Comprehensive DDDS | 2002-10 | Framework |
| [3402](https://datatracker.ietf.org/doc/html/rfc3402) | DDDS Part Two: The Algorithm | 2002-10 | Algorithm |
| [3403](https://datatracker.ietf.org/doc/html/rfc3403) | DDDS Part Three: DNS Database | 2002-10 | NAPTR record |
| [3404](https://datatracker.ietf.org/doc/html/rfc3404) | DDDS Part Four: URI Resolution | 2002-10 | URI resolution |
| [3405](https://datatracker.ietf.org/doc/html/rfc3405) | DDDS Part Five: URI.ARPA Assignment | 2002-10 | ARPA assignment |
| [2915](https://datatracker.ietf.org/doc/html/rfc2915) | The NAPTR DNS RR | 2000-09 | Original NAPTR |
| [3958](https://datatracker.ietf.org/doc/html/rfc3958) | Domain-Based Application Service Location Using SRV + DDDS | 2005-01 | SRV+DDDS integration |

---

## TIER 16 — IoT, PROVISIONING & MISCELLANEOUS

| RFC | Title | Date | Notes |
|-----|-------|------|-------|
| [9726](https://datatracker.ietf.org/doc/html/rfc9726) | Operational Considerations for DNS in IoT Devices | 2025-03 | IoT DNS guidance |
| [9526](https://datatracker.ietf.org/doc/html/rfc9526) | Simple Provisioning of Public Names for Residential Networks | 2024-01 | Home network DNS provisioning |
| [9803](https://datatracker.ietf.org/doc/html/rfc9803) | EPP Mapping for DNS TTL Values | 2025-06 | EPP TTL mapping |
| [4701](https://datatracker.ietf.org/doc/html/rfc4701) | DHCID RR | 2006-10 | DHCP↔DNS linkage |
| [8553](https://datatracker.ietf.org/doc/html/rfc8553) | DNS Attrleaf Changes | 2019-03 | Underscore naming |
| [8552](https://datatracker.ietf.org/doc/html/rfc8552) | Scoped Interpretation via Underscored Naming | 2019-03 | _dmarc, _acme-challenge etc. |
| [3646](https://datatracker.ietf.org/doc/html/rfc3646) | DNS Configuration Options for DHCPv6 | 2003-12 | DHCPv6 DNS options |

---

## TIER 17 — OBSOLETE BUT STILL REFERENCED

> These RFCs have been officially obsoleted but parts remain in active use or serve as important historical context.

| RFC | Title | Date | Replaced By |
|-----|-------|------|-------------|
| [2671](https://datatracker.ietf.org/doc/html/rfc2671) | EDNS0 (original) | 2001 | → RFC 6891 |
| [2845](https://datatracker.ietf.org/doc/html/rfc2845) | TSIG (original) | 2000 | → RFC 8945 |
| [2535](https://datatracker.ietf.org/doc/html/rfc2535) | DNSSEC (original) | 1999 | → RFC 4033-4035 |
| [3008](https://datatracker.ietf.org/doc/html/rfc3008) | DNSSEC Signing Authority | 2000 | → RFC 4033-4035 |
| [3755](https://datatracker.ietf.org/doc/html/rfc3755) | Legacy Resolver Compatibility for DNSSEC | 2004 | → RFC 4033-4035 |
| [7719](https://datatracker.ietf.org/doc/html/rfc7719) | DNS Terminology (v1) | 2015 | → RFC 9499 |
| [8499](https://datatracker.ietf.org/doc/html/rfc8499) | DNS Terminology (v2) | 2019 | → RFC 9499 |
| [1123](https://datatracker.ietf.org/doc/html/rfc1123) | Requirements for Internet Hosts | 1989 | DNS section still valid |
| [5074](https://datatracker.ietf.org/doc/html/rfc5074) | DLV (DNSSEC Lookaside Validation) | 2007 | → RFC 8749 (Historic) |
| [5933](https://datatracker.ietf.org/doc/html/rfc5933) | GOST in DNSSEC | 2010 | → RFC 9558 / 9906 |

---

## IMPLEMENTATION PRIORITY ROADMAP

```
PHASE 1 — MVP DNS Server (Authoritative Only)
├── RFC 1034, 1035          ← Core protocol
├── RFC 6891               ← EDNS(0)
├── RFC 3596               ← IPv6/AAAA
├── RFC 2782               ← SRV
├── RFC 4343               ← Case insensitivity
├── RFC 2181               ← Clarifications
├── RFC 7766, 9210         ← TCP transport
└── RFC 1982               ← Serial arithmetic

PHASE 2 — Zone Management
├── RFC 5936               ← AXFR
├── RFC 1995               ← IXFR
├── RFC 1996               ← NOTIFY
├── RFC 2136               ← Dynamic Update
└── RFC 2308               ← Negative caching

PHASE 3 — Recursive Resolver
├── RFC 8109               ← Root priming
├── RFC 5452               ← Anti-spoofing
├── RFC 7873, 9018         ← DNS Cookies
├── RFC 8914               ← Extended DNS Errors
├── RFC 8020               ← NXDOMAIN cut
├── RFC 8767               ← Stale serving
└── RFC 9156               ← QNAME minimisation

PHASE 4 — DNSSEC
├── RFC 4033, 4034, 4035   ← Core DNSSEC
├── RFC 5155               ← NSEC3
├── RFC 8945               ← TSIG
├── RFC 8624               ← Algorithm requirements
├── RFC 5702               ← SHA-2 algorithms
├── RFC 6605               ← ECDSA
├── RFC 8080               ← EdDSA
└── RFC 9364               ← DNSSEC overview

PHASE 5 — Encrypted DNS
├── RFC 7858               ← DoT
├── RFC 8484               ← DoH
├── RFC 9250               ← DoQ
└── RFC 9103               ← Zone transfer over TLS

PHASE 6 — Advanced Features
├── RFC 7871               ← Client Subnet (GeoDNS)
├── RFC 6698, 7671         ← DANE/TLSA
├── RFC 6762, 6763         ← mDNS / DNS-SD
├── RFC 5890-5895          ← IDN/IDNA
├── RFC 8976               ← ZONEMD
├── RFC 9432               ← Catalog Zones
└── RFC 8427               ← DNS-over-JSON
```

---

## USEFUL RESOURCES

- **IETF Datatracker:** https://datatracker.ietf.org/
- **ICANN RFC Annotations:** https://rfc-annotations.research.icann.org/
- **StatDNS RFC List:** https://www.statdns.com/rfc/
- **DNS RFC Descent Diagram:** https://emaillab.jp/dns/dns-rfc/
- **Zytrax DNS RFCs:** https://www.zytrax.com/books/dns/apd/
- **IANA DNS Parameters:** https://www.iana.org/assignments/dns-parameters/

---

*Prepared for full-stack DNS server implementation. Last updated: April 2026*
