# Verified Findings

After false positive elimination during Phase 3 (VERIFY), the following findings are confirmed.

## Confirmed Critical (4 actionable)

| ID | Finding | Confidence | Notes |
|----|---------|-----------|-------|
| C1 | Unbounded record count in DNS message unpacking | 95% | No aggregate cap; max uint16 iteration |
| C2 | YAML parser stack overflow via deep nesting | 90% | No depth limit in recursive parse functions |
| C5 | NSEC3 iterations not validated on unpack | 95% | `MaxIterations` constant exists but not checked in `Unpack()` |
| C6 | Radix tree panic on empty domain | 95% | `name[:len(name)-1]` panics on empty string |

## Dismissed as Non-Critical

| ID | Finding | Reason |
|----|---------|--------|
| C3 | QUIC DoQ 1-RTT unimplemented | Functional bug, not exploitable — feature doesn't work, so no attack surface |
| C4 | ODoH `processDNSQuery` no-op | Functional dead code — returns query as response, not a security vulnerability per se |

## Confirmed High (8)

| ID | Finding | Confidence |
|----|---------|-----------|
| H1 | No UDP rate limiting | 100% |
| H2 | AXFR without TSIG on IP allowlist | 95% |
| H3 | NOTIFY from any IP without auth | 100% |
| H4 | QUIC stream deadlines are no-ops | 100% |
| H5 | Unbounded EDNS0 options | 90% |
| H7 | WebSocket no rate limiting | 100% |
| H8 | QUIC stream limit not enforced | 100% |
| H9 | Opportunistic TLS fallback | 90% |

## Confirmed Medium (11)

All M1-M13 findings confirmed after verification. M12 (ALPN not enforced) confirmed as medium — non-DNS clients can connect to TLS ports.

## Confirmed Low (13)

All L1-L14 findings confirmed. Most are defense-in-depth or operational concerns.

## Dismissed During Verification

| Finding | Reason |
|---------|--------|
| `sync.Pool` reference leak in UDP | Verified correct pattern — worker returns `&req.data` to the same pool |
| TCP pipelining deadlock | Semaphore design is correct; slow-loris only fills the pipeline, not a true deadlock |
| Buffer allocation on TCP read path | Performance concern, not security |
| HPKE nonce reuse risk | Random nonces with AES-256-GCM have negligible collision probability |
| SO_REUSEPORT fallback | Operational concern, not security |
| TSIG MD5 support | RFC 2845 mandated — not a vulnerability in TSIG context |
| SHA-1 in WebSocket | RFC 6455 mandated — not a vulnerability |
| TLS 1.2 cipher suites | Irrelevant when `MinVersion: tls.VersionTLS13` — cleanup only |
