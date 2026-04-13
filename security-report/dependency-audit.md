# Dependency Audit — NothingDNS

## Summary

NothingDNS has **zero external dependencies**. The entire codebase uses only Go standard library plus one platform-specific package.

## Direct Dependencies

| Module | Version | Purpose | Risk |
|--------|---------|---------|------|
| `golang.org/x/sys` | v0.43.0 | Platform-specific socket ops (`SO_REUSEPORT`, syscall) | Minimal — official Go sub-repo |

## Go Standard Library Usage

All functionality is implemented using Go stdlib. Key packages used:

| Category | Stdlib Packages |
|----------|----------------|
| Crypto | `crypto/tls`, `crypto/rand`, `crypto/hmac`, `crypto/sha1`, `crypto/sha256`, `crypto/sha512`, `crypto/aes`, `crypto/cipher`, `crypto/x509`, `crypto/ecdsa`, `crypto/ed25519`, `crypto/rsa` |
| Network | `net`, `net/http`, `net/url`, `net/netip` |
| Encoding | `encoding/json`, `encoding/base64`, `encoding/binary`, `encoding/hex` |
| Serialization | `bytes`, `strings` (custom TLV, custom DNS wire format) |
| Concurrency | `sync`, `sync/atomic`, `context` |
| I/O | `io`, `os`, `bufio` |
| Time | `time` |
| Logging | `log`, `fmt` |
| Reflection | `reflect` |
| Debug | `runtime`, `runtime/debug` |
| Other | `math`, `math/big`, `math/bits`, `sort`, `regexp`, `path/filepath` |

## Supply Chain Assessment

**Risk Level: Minimal**

- No third-party packages → no supply chain attack surface
- No `go.sum` entries beyond `golang.org/x/sys`
- No indirect dependencies
- No vendored code
- No CGO dependencies (builds with `CGO_ENABLED=0`)

**Vulnerable:**
- `golang.org/x/sys` v0.43.0 — check for known CVEs. As of 2026-04, no critical CVEs reported for this version.

**Recommendations:**
1. Pin `golang.org/x/sys` to a specific version in `go.mod` (already done)
2. Periodically check for CVEs against `golang.org/x/sys`
3. Consider adding a `go.sum` hash verification step in CI

## Hand-Rolled Implementations (Review These Carefully)

Since NothingDNS reimplements common functionality from scratch, each of these should receive focused security review:

| Implementation | Risk | Notes |
|---------------|------|-------|
| DNS wire protocol parser | High | Untrusted input from network |
| YAML config parser | High | Untrusted input from file |
| TLS certificate validation | High | X.509 chain validation |
| AES-256-GCM cluster encryption | High | Key management, nonce reuse |
| Raft consensus protocol | Medium | State machine correctness |
| Gossip membership protocol | Medium | Message authentication |
| DNSSEC validation/signing | High | Cryptographic correctness |
| HPKE implementation (ODoH) | High | Custom crypto — high risk |
| JWT implementation | Medium | Token signing, validation |
| Base64 URL encoding | Low | Stdlib used |
| Rate limiter (token bucket) | Low | Algorithm simplicity |
