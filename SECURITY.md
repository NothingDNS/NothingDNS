# Security Policy

## Supported Versions

| Version | Supported          |
|---------|-------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in NothingDNS, please report it responsibly.

**Do NOT open a public GitHub issue** for security vulnerabilities.

### How to Report

1. **Email**: Send a description of the vulnerability to the maintainers
2. **Private Security Forum**: Use [GitHub's Private Vulnerability Reporting](https://github.com/NothingDNS/NothingDNS/security/advisories/new) if available
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### What to Expect

- Acknowledgment within 48 hours
- Regular updates on remediation progress
- Public disclosure after a fix is released

## Security Design Principles

### Zero External Dependencies
NothingDNS has **zero external dependencies**. This minimizes the attack surface from third-party code. All cryptographic operations use Go's standard library `crypto/*` packages.

### DNSSEC
- Signing uses RSA/SHA-256/SHA-512 with key rollover support
- Validation follows RFC 4035 with chain-of-trust from trust anchors
- NSEC3 opt-out support for large delegations

### TSIG
- RFC 2845 HMAC-MD5/SHA-1/SHA-256/SHA-512 for AXFR/IXFR/DDNS
- TSIG errors cause transfer failure, not silent fallback

### Network
- TLS/DoT/DoH/DoQ support with configurable cipher suites
- SO_REUSEPORT for multi-core scalability
- No arbitrary code execution in zone files

### ACL
- IP-based access control for queries and management
- Rate limiting (RRL) for query amplification prevention

## Known Limitations

- DNSSEC signing is performed on-the-fly (not pre-signed). High-QPS DNSSEC-signed zones may experience elevated CPU usage.
- TSIG uses HMAC-MD5 for backwards compatibility. Prefer SHA-256 or SHA-512 where supported.
