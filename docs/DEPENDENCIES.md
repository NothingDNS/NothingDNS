# NothingDNS Dependencies

## Philosophy

NothingDNS follows a **minimal external dependencies** philosophy for the core server. The runtime dependency set is intentionally small: `quic-go` for DNS over QUIC plus Go-maintained `golang.org/x/*` support packages for platform, crypto, and network functionality that cannot be implemented using only the standard library.

## Go Version Requirements

| Go Version | Support Status |
|------------|----------------|
| 1.26.5+ | **Required** (primary development) |
| 1.25.x | May work, not tested |
| < 1.25 | Not supported |

The `go` directive in the root `go.mod` and `web/go.mod` specifies `1.26.5`.

## Direct Dependencies

These are the packages imported and used directly by NothingDNS:

### github.com/quic-go/quic-go

**Purpose**: DNS over QUIC (DoQ) transport

**Version**: `v0.60.0`

**Why Required**: QUIC is a complex protocol with intricate state machine handling, connection management, and flow control. Implementing a standards-compliant QUIC stack from scratch would be a massive undertaking and would require ongoing maintenance as the RFC evolves.

**Usage**: `internal/quic/` package for DoQ server and client

**License**: MIT (quic-go/quic-go)

**Alternatives Considered**:
- Implementing QUIC from scratch — Not feasible for a DNS server project
- Using another QUIC library — `quic-go` is the most mature and widely-used Go QUIC implementation

### golang.org/x/sys

**Purpose**: Platform-specific socket operations

**Version**: `v0.46.0`

**Why Required**: Certain DNS server features require OS-level access:
- `SO_REUSEPORT` for multi-core UDP scalability on Linux
- `IP_TRANSPARENT` for transparent proxying
- Platform-specific socket options

**Usage**: Various `internal/server/` packages for network socket configuration

**License**: BSD 3-Clause (Go Authors)

**Alternatives Considered**:
- Standard library `net` package — Does not expose `SO_REUSEPORT` or other advanced socket options
- This is a Go team's official package, not third-party

## Indirect Dependencies

These packages are dependencies of `quic-go`:

### golang.org/x/crypto

**Purpose**: Cryptographic operations for QUIC

**Version**: `v0.53.0`

**Used For**:
- TLS 1.3 connection encryption
- QUIC handshake (via quic-go)

### golang.org/x/net

**Purpose**: Network primitives for QUIC

**Version**: `v0.56.0`

**Used For**:
- HTTP/2 framing (used by QUIC internally)
- WebSocket support in quic-go
- Various network utilities

## Standard-library-only core subsystems

The following categories use only the Go standard library:

| Category | Implementation |
|----------|----------------|
| DNS Protocol | `internal/protocol/` — Go stdlib only |
| DNS Cache | `internal/cache/` — sync.Map + in-memory |
| DNSSEC | `internal/dnssec/` — crypto/* standard library |
| Zone Storage | `internal/storage/` — File I/O only |
| HTTP API | `internal/api/` — net/http standard library |
| Clustering | `internal/cluster/` — Custom SWIM/Raft |
| WebSocket | `internal/websocket/` — net/http only |
| mDNS | `internal/mdns/` — net/http only |
| Metrics | `internal/metrics/` — Prometheus format (string building) |
| Logging | `internal/util/` — fmt + io Writer |
| Configuration | `internal/config/` — Custom YAML parser |
| Blocklist | `internal/blocklist/` — File parsing only |

## Cryptographic Operations

All cryptographic operations use Go's standard library:

```go
// DNSSEC signing and validation
crypto/ecdsa
crypto/rsa
crypto/ed25519
crypto/hmac
crypto/sha256
crypto/sha512

// Cluster encryption
crypto/aes          // AES-256-GCM for gossip
crypto/cipher
crypto/subtle

// Key derivation
crypto/hkdf
```

## Dependency Policy

### Adding Dependencies

New dependencies must be approved by meeting ALL criteria:

1. **Necessity**: Cannot be implemented using Go stdlib
2. **Maintenance**: Actively maintained (commits within 6 months)
3. **Security**: No known vulnerabilities (run `govulncheck`)
4. **License**: Compatible with MIT
5. **Size**: Less than 1MB added to binary size
6. **Approach**: Verify with project maintainers first

### Prohibited Dependencies

The following are explicitly NOT allowed:

- DNS protocol implementations (we use our own `internal/protocol/`)
- YAML parsers (we use our own `internal/config/`)
- Logging frameworks (we use structured logging with Go stdlib)
- Database drivers (we use our own KVStore)
- Web frameworks (we use stdlib `net/http`)
- External DNS libraries (we implement RFC 1035 ourselves)

## Version Management

### Updating Dependencies

```bash
# Check for vulnerabilities
make security-check

# Update specific package
go get github.com/quic-go/quic-go@latest

# Update all
go get -u ./...

# Tidy dependencies
go mod tidy

# Verify integrity
go mod verify
```

### Updating Go Version

When updating Go version:

1. Test with the new Go version: `make test-full`
2. Update the `go` directive in `go.mod` and `web/go.mod`
3. Run `go mod tidy` in the affected module(s)
4. Update CI workflows if needed
5. Update this document

## Vulnerability Management

### Running Security Checks

```bash
# Check for vulnerabilities
make security-check

# Or manually
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

### Responding to CVEs

When a CVE affects a dependency:

1. Check if affected version is used: `govulncheck ./...`
2. Update to patched version if available
3. If no patch available:
   - Consider removing the dependency if possible
   - Implement workaround
   - Monitor for official fix
4. Document in security report

## Build Reproducibility

To ensure reproducible builds:

```bash
# Build with exact versions
go build -trimpath -ldflags "-s -w" ./cmd/nothingdns

# Verify module checksums
go mod verify
```

## Module Graph

```
github.com/nothingdns/nothingdns
├── github.com/quic-go/quic-go v0.60.0
├── golang.org/x/sys v0.46.0
├── golang.org/x/crypto v0.53.0 (indirect)
├── golang.org/x/net v0.56.0 (indirect)
└── go.uber.org/mock v0.6.0 (indirect, tests/tooling)
```

## Compatibility Matrix

| Feature | Go Version | Notes |
|---------|------------|-------|
| QUIC/DoQ | 1.26.5+ | Requires quic-go |
| AES-GCM (cluster) | 1.26.5+ | stdlib crypto |
| Ed25519 | 1.26.5+ | stdlib crypto |
| RFC 8439 (chacha20) | 1.26.5+ | stdlib crypto |
| SO_REUSEPORT | 1.26.5+ | x/sys Linux only |
| Link-local IPv6 | 1.26.5+ | stdlib net |

## License Compatibility

| Package | License | Compatible with MIT |
|---------|---------|---------------------|
| quic-go | MIT | Yes |
| x/sys | BSD 3-Clause | Yes |
| x/crypto | BSD 3-Clause | Yes |
| x/net | BSD 3-Clause | Yes |
| go.uber.org/mock | Apache 2.0 | Yes |
| NothingDNS | MIT | Yes (self) |

## Frequently Asked Questions

### Why not use external DNS libraries?

We implement DNS ourselves for:
- Full control over security (VULN-059, VULN-060, etc.)
- Optimizations specific to our use case
- No dependency on third-party DNS implementations
- Learning and transparency

### Why not use a YAML library?

Our custom parser handles 95% of YAML use cases and is:
- Zero dependency
- Faster for our specific schema
- Easier to debug
- No security CVEs in YAML parsers

### Can I remove quic-go for a smaller binary?

Yes, if you don't need DoQ:

```bash
go build -tags nodefaults ./cmd/nothingdns
```

This removes QUIC support and reduces binary size by ~2MB.

### What about Windows support?

Windows support is limited:
- `SO_REUSEPORT` not available on Windows
- Some features may not work
- CI/CD tests run on Linux

For Windows deployments, use Docker.

## Security Considerations

1. **Minimize Attack Surface**: Only use dependencies that are essential
2. **Keep Updated**: Regularly update dependencies for security patches
3. **Verify Sources**: All dependencies from trusted sources (Go team or established projects)
4. **No Native Code**: No CGO dependencies that could introduce vulnerabilities
5. **Reproducible Builds**: Use `-trimpath` and `-ldflags "-s -w"` for consistent builds