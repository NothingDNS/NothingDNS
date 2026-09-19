# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in NothingDNS, please report it responsibly.

**Do NOT open a public GitHub issue** for security vulnerabilities.

### How to Report

1. **Email**: Send a description of the vulnerability to the maintainers
2. **Private Security Forum**: Use [GitHub's Private Vulnerability Reporting](https://github.com/NothingDNS/NothingDNS/security/advisories/new)
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### What to Expect

- Acknowledgment within 48 hours
- Regular updates on remediation progress
- Public disclosure after a fix is released

## Supported Versions

Security fixes are released for the latest minor release line only.

| Version | Supported          |
|---------|-------------------|
| 1.2.x   | :white_check_mark: |
| < 1.2   | :x:                |

## Security Design Principles

### Minimal External Dependencies

NothingDNS keeps a **minimal external dependency** set: the core DNS logic is hand-rolled, `quic-go` provides DNS over QUIC, and Go-maintained `golang.org/x/*` packages cover platform, crypto, and network support.

All cryptographic operations use Go's standard library `crypto/*` packages.

### DNSSEC

- Signing uses RSA/SHA-256/SHA-512 with key rollover support (RFC 7583)
- Validation follows RFC 4035 with chain-of-trust from trust anchors
- NSEC3 opt-out support for large delegations
- RFC 5011 trust anchor maintenance

### TSIG

- RFC 2845 HMAC-MD5/SHA-1/SHA-256/SHA-512 for AXFR/IXFR/DDNS
- TSIG errors cause transfer failure, not silent fallback

### Network Security

- TLS 1.3 minimum for DoT/DoH/DoQ
- Configurable cipher suites per RFC 7525
- SO_REUSEPORT for multi-core scalability
- DNS Cookie (RFC 7873) for anti-spoofing

### Access Control

- IP-based ACL for queries and management
- Rate limiting (RRL) for amplification prevention
- Response Policy Zones (RPZ) for DNS filtering

## Known Limitations

- DNSSEC signing is performed on-the-fly. High-QPS DNSSEC-signed zones may experience elevated CPU usage.
- TSIG uses HMAC-MD5 for backwards compatibility. Prefer SHA-256 or SHA-512 where supported.
- All authenticated operators have global access to all zones. There is no per-zone isolation. For strict separation, run separate NothingDNS instances.

## Cryptography

- **Hashing**: SHA-256, SHA-512 for DNSSEC and TSIG
- **Signatures**: RSA (2048, 4096), ECDSA (P-256, P-384), Ed25519
- **Encryption**: AES-256-GCM for cluster gossip
- **Key Derivation**: HKDF for DNS Cookies

## Vulnerability Mitigations

| ID | Description | Mitigation |
|----|-------------|------------|
| VULN-005 | Multi-node without encryption | Cluster refuses to start without encryption key |
| VULN-020 | WAL length overflow | Rejects entries > MaxSegmentSize (64MB) |
| VULN-044 | DoH/DoWS/ODoH auth bypass | No auth required (privacy feature, intentional) |
| VULN-059 | TXID prediction | Re-randomizes TXID before forwarding |
| VULN-060 | Cache side-channel | DO bit included in cache key |
| VULN-063 | Amplification attack | Response Rate Limiting (RRL) mitigates abusive reflection/amplification patterns |
| VULN-068 | Username enumeration | Per-(IP, username) lockout pair |