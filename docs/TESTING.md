# NothingDNS Testing Guide

## Overview

NothingDNS uses comprehensive testing across multiple levels to ensure reliability and correctness.

## Testing Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                        Pyramid                                 │
│                                                              │
│                        ┌─────────┐                           │
│                       │   E2E   │                          │
│                      ┌───────────────┐                     │
│                     │ Integration   │                      │
│                    ┌─────────────────────┐                 │
│                   │      Unit Tests      │                │
│                  └───────────────────────────┘              │
└─────────────────────────────────────────────────────────────┘
```

- **Unit tests**: Fast, isolated, many
- **Integration tests**: Component interaction
- **E2E tests**: Full system validation

## Running Tests

### Quick Test (Short Mode)

```bash
# All packages
make test

# Single package
make test-pkg PKG=./internal/cache

# Single test
make test-run TEST=TestCacheGet
```

### Full Test Suite

```bash
# Includes long-running tests
make test-full

# With verbose output
make test-verbose

# Race detector (detects data races)
make test-race
```

### Coverage

```bash
# Generate HTML coverage report
make test-coverage

# View in browser
open coverage.html
```

### E2E Tests

```bash
# Requires running NothingDNS server
make test-e2e
```

## Unit Testing

### Structure

```go
// internal/cache/cache_test.go
package cache

import (
    "testing"
    "time"
)

func TestCacheSetGet(t *testing.T) {
    c := NewCache(Config{Size: 100})

    // Setup
    msg := &Message{...}
    c.Set("example.com", TypeA, ClassIN, 0, msg, time.Hour)

    // Assert
    got, ok := c.Get("example.com", TypeA, ClassIN, 0)
    if !ok {
        t.Fatal("expected cache hit")
    }
    if got != msg {
        t.Error("message mismatch")
    }
}
```

### Testing Best Practices

1. **Use table-driven tests**:
```go
func TestRCODEString(t *testing.T) {
    tests := []struct {
        rcode  int
        expect string
    }{
        {0, "NOERROR"},
        {3, "NXDOMAIN"},
        {2, "SERVFAIL"},
    }

    for _, tt := range tests {
        t.Run(tt.expect, func(t *testing.T) {
            if got := RCODE(tt.rcode).String(); got != tt.expect {
                t.Errorf("RCODE(%d).String() = %q, want %q", tt.rcode, got, tt.expect)
            }
        })
    }
}
```

2. **Use subtests for related cases**:
```go
func TestDNSSECValidation(t *testing.T) {
    t.Run("Secure", func(t *testing.T) { ... })
    t.Run("Bogus", func(t *testing.T) { ... })
    t.Run("Insecure", func(t *testing.T) { ... })
}
```

3. **Test edge cases**:
```go
// Empty name
{"", TypeA, false},

// Single label
{"a", TypeA, true},

// Max length label
{strings.Repeat("a", 63), TypeA, true},

// Over-length label
{strings.Repeat("a", 64), TypeA, false},
```

4. **Keep assertions dependency-free**:
```go
if got != want {
    t.Errorf("got %d, want %d", got, want)
}
```

Prefer the standard `testing` package and small local helpers over external assertion libraries.

## Integration Testing

### Database/Storage Tests

```go
func TestKVStoreUpdate(t *testing.T) {
    // Setup
    tmpDir := t.TempDir()
    kv, err := NewKVStore(tmpDir, nil)
    require.NoError(t, err)
    defer kv.Close()

    // Test
    err = kv.Update(func(tx *Tx) error {
        return tx.PutBucket("test").Put("key", []byte("value"))
    })
    require.NoError(t, err)

    // Verify
    var got []byte
    err = kv.View(func(tx *Tx) error {
        got = tx.GetBucket("test").Get("key")
        return nil
    })
    require.NoError(t, err)
    require.Equal(t, []byte("value"), got)
}
```

### Network Tests

```go
func TestUDPMessageRoundTrip(t *testing.T) {
    // Create message
    msg := &Message{
        Header: Header{ID: 1234},
        Questions: []*Question{
            {Name: MustNewName("example.com"), QType: TypeA, Class: ClassIN},
        },
    }

    // Pack to wire format
    buf := make([]byte, 512)
    n, err := msg.Pack(buf)
    require.NoError(t, err)

    // Unpack
    got := &Message{}
    err = got.UnpackMessage(buf[:n])
    require.NoError(t, err)

    // Verify
    require.Equal(t, msg.Header.ID, got.Header.ID)
    require.Len(t, got.Questions, 1)
    require.Equal(t, "example.com.", got.Questions[0].Name.String())
}
```

### DNS Protocol Tests

```go
func TestZoneTransfer(t *testing.T) {
    // Start test server with zone
    srv := startTestServer(t, "testdata/zones/example.com.zone")
    defer srv.Close()

    // AXFR request
    msg := &Message{
        Header: Header{Flags: HeaderFlags(FlagRD)},
        Questions: []*Question{
            {Name: MustNewName("example.com"), QType: TypeAXFR, Class: ClassIN},
        },
    }

    // Send and verify response
    resp, err := srv.QueryAXFR(msg)
    require.NoError(t, err)
    require.Greater(t, len(resp.Answers), 10) // Multiple records
}
```

## End-to-End Testing

### E2E Test Structure

```go
// internal/e2e/dns_test.go
func TestDNSQuery(t *testing.T) {
    // Start full server
    srv := servertest.RunServer(t, config.Default())
    defer srv.Close()

    // Create client
    client := dnstest.NewClient(srv.Addr())

    // Test queries
    tests := []dnstest.Case{
        {
            Name: "A record",
            Q:    dnstest.Question{Name: "example.com", Type: TypeA},
            Expect: dnstest.Answer{
                RCode: RcodeSuccess,
                Answer: []RR{
                    &A{Name: "example.com", A: net.ParseIP("93.184.216.34")},
                },
            },
        },
    }

    dnstest.Run(t, client, tests)
}
```

### Test Fixtures

```bash
internal/e2e/testdata/
├── zones/
│   ├── example.com.zone
│   └── internal.zone
├── configs/
│   ├── default.yaml
│   ├── cluster.yaml
│   └── dnssec.yaml
└── expected/
    ├── signed_zone.txt
    └── blocklist_response.txt
```

### Writing E2E Tests

1. **Start server**:
```go
func TestWithServer(t *testing.T) {
    cfg := config.Default()
    cfg.Upstream.Servers = []string{"1.1.1.1:53"}

    srv := servertest.RunServer(t, cfg)
    defer srv.Close()

    // Tests here
}
```

2. **Query DNS**:
```go
msg := &Message{
    Header: Header{ID: 1234},
    Questions: []*Question{
        {Name: MustNewName("example.com"), QType: TypeA, Class: ClassIN},
    },
}

resp, err := client.Query(msg, "udp")
require.NoError(t, err)
require.Equal(t, RcodeSuccess, resp.Header.RCODE)
```

3. **Verify response**:
```go
require.Len(t, resp.Answers, 1)
a, ok := resp.Answers[0].(*A)
require.True(t, ok)
require.Equal(t, "93.184.216.34", a.A.String())
```

## Property-Based Testing

Using `github.com/leanovate/gopter`:

```go
import "github.com/leanovate/gopter"

func TestNamePacking(t *testing.T) {
    properties := gopter.NewProperties(nil)

    properties.Property("pack-unpack roundtrip", prop.ForAll(
        func(name string) bool {
            if len(name) > 255 {
                return true // Skip invalid
            }
            // Create name
            n, err := NewName(name)
            if err != nil {
                return false
            }
            // Pack
            buf := make([]byte, 256)
            n2, err := n.Pack(buf)
            if err != nil {
                return false
            }
            // Unpack
            n3, _, err := UnpackName(buf, 0)
            if err != nil {
                return false
            }
            return n3.String() == n.String()
        },
        genName(), // Generator
    ))

    properties.TestingRun(t)
}

// Custom generator
func genName() gopter.Gen {
    return func(*gopter.GenContext) *gopter.GenResult {
        labels := []string{"a", "bc", "example", "test"}
        name := strings.Join(labels, ".")
        return gopter.NewGenResult(name, gopter.NoShrink)
    }
}
```

## Fuzz Testing

### Fuzz Targets

```go
// internal/protocol/fuzz_test.go
func FuzzMessageUnpack(f *testing.F) {
    // Seed corpus
    f.Add([]byte{
        0x00, 0x00, // ID
        0x01, 0x20, // Flags: RD
        0x00, 0x01, // QDCount: 1
        0x00, 0x00, // ANCount
        0x00, 0x00, // NSCount
        0x00, 0x00, // ARCount
    })

    f.Fuzz(func(t *testing.T, data []byte) {
        msg := &Message{}
        err := msg.UnpackMessage(data)
        if err != nil {
            return // Expected for invalid input
        }
        // Verify invariants
        if msg.Header.QDCount > 100 {
            t.Error("QDCount too large")
        }
    })
}
```

### Run Fuzz Tests

```bash
# Install go-fuzz
go install github.com/dvyukov/go-fuzz/go-fuzz@latest
go install github.com/dvyukov/go-fuzz/go-fuzz-build@latest

# Build fuzz targets
go-fuzz-build

# Run fuzz test
go-fuzz -bin=./fuzz.zip -procs=4
```

### Corpus Example

```bash
fuzz/corpus/
├── valid_query.bin
├── nxdomain_response.bin
├── signed_response.bin
└── truncated_response.bin
```

## Benchmarking

### Writing Benchmarks

```go
func BenchmarkCacheGet(b *testing.B) {
    c := NewCache(Config{Size: 10000})
    msg := &Message{...}
    c.Set("example.com", TypeA, ClassIN, 0, msg, time.Hour)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, ok := c.Get("example.com", TypeA, ClassIN, 0)
        if !ok {
            b.Fatal("cache miss")
        }
    }
}
```

### Run Benchmarks

```bash
# Specific package
go test ./internal/cache -bench=. -benchmem

# All benchmarks
go test ./... -bench=. -benchmem -count=3

# With CPU profiling
go test -bench=. -cpuprofile=cpu.out ./internal/cache
go tool pprof cpu.out
```

### Benchmark Output

```
BenchmarkCacheGet-8    1000000    245 ns/op    48 B/op    1 allocs/op
BenchmarkCacheSet-8     500000    312 ns/op    64 B/op    2 allocs/op
```

## Test Data

### Test Zones

```bash
testdata/
└── zones/
    ├── example.com.zone      # Standard zone
    ├── signed-example.com.zone  # DNSSEC signed
    ├── internal.zone         # Split-horizon
    └── dynamic.zone          # For UPDATE tests
```

### Mock Objects

```go
// Mock upstream for testing
type mockUpstream struct {
    responses map[string]*Message
    err       error
}

func (m *mockUpstream) Query(ctx context.Context, q *Question) (*Message, error) {
    if m.err != nil {
        return nil, m.err
    }
    return m.responses[q.Name.String()], nil
}
```

## Test Utilities

### dnstest Package

```go
import "github.com/nothingdns/nothingdns/internal/e2e/dnstest"

// Create test case
case := dnstest.Case{
    Name: "A record lookup",
    Q: dnstest.Question{
        Name: "example.com",
        Type: TypeA,
    },
    Expect: dnstest.Answer{
        RCode: RcodeSuccess,
        HasAnswer: func(m *Message) bool {
            return len(m.Answers) > 0
        },
    },
}

// Run
dnstest.RunOne(t, client, case)
```

### servertest Package

```go
import "github.com/nothingdns/nothingdns/internal/e2e/servertest"

// Start test server
srv := servertest.RunServer(t, cfg)
defer srv.Close()

// Query
resp, err := srv.Query(msg, "udp")
```

## Coverage

### Viewing Coverage

```bash
# Generate coverage report
go test ./... -coverprofile=coverage.out

# View HTML
go tool cover -html=coverage.out -o coverage.html
open coverage.html

# Summary
go tool cover -func=coverage.out
```

### Coverage by Package

```bash
# Per-package coverage
for pkg in $(go list ./...); do
    cover=$(go test -coverprofile=/dev/null "$pkg" 2>/dev/null | grep coverage || echo "0%")
    echo "$pkg: $cover"
done
```

### Increasing Coverage

1. Find uncovered lines:
```bash
go tool cover -html=coverage.out -o coverage.html
# Open in browser, look for red
```

2. Add tests for edge cases:
```bash
// Uncovered: error path
if err != nil {
    t.Errorf("unexpected error: %v", err)
}
```

3. Use coverage-guided fuzzing:
```bash
go-fuzz -bin=./fuzz.zip -cover
```

## CI Testing

### GitHub Actions

The workflows do **not** run on every push or pull request. Run the local
checks below before pushing; CI runs only when it is asked for:

| Workflow | Triggers |
|---|---|
| `go.yml` (build, vet, tests, race, static analysis, govulncheck) | manual (`workflow_dispatch`), push of a `v*` tag |
| `web.yml` (dashboard type check, lint, tests, build; npm audit, Retire.js, CodeQL) | manual, push of a `v*` tag |
| `sdk.yml` (Go, C#, Java, Python and TypeScript SDKs) | manual, push of a `v*` tag |
| `container.yml` (multi-arch image, SBOM, provenance, cosign signature) | manual, push of a `v*` tag |
| `release.yml` (release binaries and assets) | GitHub release published, manual re-run for an existing tag |
| `advisory-monitor.yml` | weekly schedule (Monday 06:00 UTC), manual |

Run a workflow manually from the repository's **Actions** tab (select the
workflow → **Run workflow** → branch), or with the GitHub CLI:

```bash
gh workflow run go.yml --ref main
gh workflow run web.yml --ref main
gh workflow run sdk.yml --ref main
gh run watch                     # follow the run
```

Cutting a release: run the CI workflows on `main` manually and wait for them
to pass, then push the tag (`git tag vX.Y.Z && git push origin vX.Y.Z`),
which runs CI and builds the container image again for the tagged commit,
and publish the GitHub release for that tag to build the release assets.

### Local CI

```bash
# Run full CI locally
make ci

# Or manually
make vet
make test
make build
```

## Test Maintenance

### When to Add Tests

- New features → Test before merge
- Bug fixes → Add regression test
- Performance changes → Benchmark before/after
- Security changes → Manual verification + test

### Test Naming

| Pattern | Example | Use Case |
|---------|---------|----------|
| `TestPackageName` | `TestCache` | Package tests |
| `TestPackageName_SubTest` | `TestCache_Eviction` | Subtests |
| `TestPackageName_Feature` | `TestDNSSEC_Validate` | Feature tests |
| `BenchmarkPackage_Function` | `BenchmarkCache_Get` | Benchmarks |
| `FuzzPackage_Target` | `FuzzMessage_Unpack` | Fuzz tests |

### Common Patterns

```go
// Test table
func TestX(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {"valid", "input", "output", false},
        {"invalid", "bad", "", true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := doSomething(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("doSomething() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if got != tt.want {
                t.Errorf("doSomething() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

## Troubleshooting

### Flaky Tests

1. **Race conditions**:
```bash
make test-race
```

2. **Timing issues**:
```go
// Use eventually instead of sleep
require.Eventually(t, func() bool {
    return cache.Size() > 0
}, 5*time.Second, 100*time.Millisecond)
```

3. **Network dependency**:
```go
// Skip if network unavailable
if !testenv.HasNetwork() {
    t.Skip("requires network")
}
```

### Test Failures in CI

1. Check if tests pass locally: `make test`
2. Check race detector: `make test-race`
3. Run with verbose: `make test-verbose`
4. Check for resource exhaustion: increase timeout

## References

- [Go Testing Package](https://pkg.go.dev/testing)
- [Go fuzzing](https://go.dev/doc/security/fuzz/)
- [Go coverage tooling](https://go.dev/blog/cover)
- [High Performance Go](https://dave.cheney.net/high-performance-go.html)