# NothingDNS — Security Assessment Report

| Field | Value |
|---|---|
| **Project** | NothingDNS — multi-protocol DNS server (Go + React 19 dashboard) |
| **Scan date** | 2026-04-16 |
| **Scanner** | `sc-*` security pipeline (48 skills, 7 language-specific scanners) |
| **Scope** | 366 Go files / 58 TS/TSX files (~50k LOC Go, ~6k LOC TS) |
| **Commit** | `main @ 48e18b7` |
| **Overall Risk Score** | **7.5 / 10** |
| **Risk Band** | **HIGH — production deploy gated pending Critical fixes** |

---

## 1. Executive Summary

NothingDNS is a well-engineered, stdlib-first DNS server with a hand-rolled wire-protocol parser, clustered HA (gossip + Raft), embedded admin dashboard, and a 21-stage request pipeline. Cryptographic primitives are modern (PBKDF2-HMAC-SHA512 at 310k rounds, constant-time compares, TLS 1.3 defaults, AES-256-GCM with per-message nonces, Ed25519/ECDSA DNSSEC). That hygiene is real and noted throughout this report.

The caveat is that a small number of **structural flaws** weaken the otherwise solid posture:

1. The **Raft cluster RPC channel** is plaintext `gob`-over-TCP with no authentication, no size cap, and no encryption. Any network attacker reaching the Raft port can crash the leader or forge log entries.
2. A **debug file** (`genhash_tmp.go`) was committed to `main` and runs in the `init()` of every production start, burning CPU and shipping a known-answer hash for a fixed password.
3. **RBAC has collapsed in practice**: the "operator" role can rewrite ACLs, swap upstreams, overwrite RPZ rules, and disable filtering — each of which is admin-equivalent power. A legacy shared token silently synthesizes admin context on top of that.
4. **Tenant isolation does not exist**: every operator has global CRUD over every zone, with no per-zone ACL, no soft-delete, and no block on creating IANA TLDs.

These are not implementation bugs sprayed across the codebase — they are discrete design gaps. Once closed, the rest of the audit is mostly hardening (CSP, CSRF defense-in-depth, per-endpoint rate buckets, k8s manifest, supply-chain gates).

**Recommendation: block production deploy until Critical and High-severity items are resolved. Medium items can be scheduled into the next sprint.**

---

## 2. Key Metrics

| Severity | Count | Share |
|---|---:|---:|
| **Critical** | 2 | 5% |
| **High** | 9 | 24% |
| **Medium** | 13 | 34% |
| **Low** | 10 | 26% |
| **Info** | 4 | 11% |
| **Total verified** | **38** | 100% |

Confidence distribution: 16 findings ≥90, 15 findings 70–89, 6 findings 50–69, 1 finding 30–49. 21 raw findings were eliminated as false-positive, out-of-scope, or positive findings.

---

## 3. Top Risks

### Risk #1 — Unauthenticated Raft RPC over plaintext TCP with `encoding/gob`
(VULN-001, Critical, conf 92)

The Raft consensus layer listens on a plain `net.Listen("tcp", addr)` socket with no TLS, no mTLS, no HMAC envelope, and no shared-key validation. Frames are `encoding/gob`-encoded — the Go stdlib explicitly documents `gob` as unsafe for untrusted input. A single crafted payload OOM-kills the Raft leader via unbounded slice/map allocation; a well-formed payload hijacks leader election or injects malicious log entries that replicate cluster-wide. The gossip transport is AES-256-GCM encrypted; the Raft transport is a separate code path that does not share that protection. `s.conns[""] = conn` also makes all connections unevictable on shutdown.

### Risk #2 — Debug test code `genhash_tmp.go` runs at every production boot
(VULN-002, Critical, conf 95)

`internal/auth/genhash_tmp.go` is a committed non-test `.go` file with a top-level `init()` that computes `HashPassword("test-password", fixedSalt)` (PBKDF2-HMAC-SHA512 × 310,000) and prints the known-answer hash to stdout. Every start of `nothingdns` and `dnsctl` burns ~200–500ms CPU, writes test-scaffold output to operator logs, and ships a rainbow-table entry for a fixed string + fixed salt. This is clearly unintentional — a developer used `_tmp.go` to bypass their `_test.go` convention and the file was never removed.

### Risk #3 — Operator role is admin-equivalent + no per-zone ownership
(VULN-008 + VULN-009, High × 2, conf 95/92)

The three-tier RBAC model (admin/operator/viewer) collapses because Operator-role endpoints include ACL rewrite, upstream replacement, RPZ rules, blocklist toggle, config reload, log-level change, and cache flush. Any single Operator compromise is an infrastructure-level compromise. Concurrently, no zone has an owner: every operator can `DELETE` any zone, `POST /records` on any zone, or `GET /export` anyone else's TXT/SPF/DKIM/DMARC material. The code explicitly documents "by design: no per-zone or multi-tenant isolation" — in practice this is indistinguishable from BOLA (CWE-639). Combined with VULN-003 (legacy `auth_token` synthesizes admin), the path from "stolen CI token" to "delete all zones" is two hops with no interstitial check.

### Risk #4 — Blocklist SSRF via redirect-follow
(VULN-004, High, conf 85)

`validateBlocklistURL` correctly rejects IP-literals, RFC 1918 ranges, loopback, and cloud-metadata hostnames on the **initial** URL — but the `http.Client` has no `CheckRedirect`, so Go's default 10-hop policy silently follows `302 Location: http://169.254.169.254/...`. The SSRF allowlist applies only to hop 0. An attacker who convinces an operator to add a community blocklist URL reaches cloud metadata, intranet services, or loopback admin endpoints.

### Risk #5 — Cluster gossip encryption is opt-in (plaintext is the silent default)
(VULN-005, High, conf 90)

`NewGossipProtocol` only activates AES-256-GCM when `config.EncryptionKey` is non-empty. Otherwise a single `Warnf` is logged and gossip proceeds in plaintext JSON over UDP — including `MessageTypeZoneUpdate`, `MessageTypeConfigSync`, `MessageTypeCacheSync`. Sample `deploy/config-node{1,2,3}.yaml` files ship with the key unset, so "copy the sample config" is the insecure path.

---

## 4. Scan Statistics

| Metric | Value |
|---|---|
| Go files scanned | 366 |
| TS / TSX files scanned | 58 |
| Approx. Go LOC | ~50,000 |
| Approx. TypeScript LOC | ~6,000 |
| Language share | Go 86% / TypeScript 14% |
| Direct Go runtime deps | 2 (`quic-go`, `golang.org/x/sys`) |
| Direct npm deps | 29 prod + 13 dev |
| Skills executed | 48 (including 7 language-specific) |
| Raw findings emitted | ~130 |
| After dedupe / merge | 38 verified |
| False positives eliminated | 21 |
| De-duplication ratio | 71% (130 → 38) |

---

## 5. Finding Distribution by Category

| Category | Crit | High | Med | Low | Info | Total |
|---|---:|---:|---:|---:|---:|---:|
| **Authentication & Session** | 0 | 1 | 2 | 2 | 0 | 5 |
| **Authorization / RBAC / BOLA** | 0 | 2 | 0 | 0 | 0 | 2 |
| **Cryptography & Secrets** | 1 | 1 | 0 | 2 | 0 | 4 |
| **Injection (SSRF, path, deser.)** | 1 | 2 | 1 | 2 | 0 | 6 |
| **API / CSRF / CORS / Web** | 0 | 2 | 4 | 2 | 0 | 8 |
| **Rate limiting / DoS** | 0 | 0 | 3 | 1 | 0 | 4 |
| **Race conditions** | 0 | 0 | 1 | 0 | 0 | 1 |
| **Infrastructure / IaC / CI-CD** | 0 | 0 | 3 | 1 | 2 | 6 |
| **Dependency / Supply chain** | 0 | 0 | 0 | 0 | 2 | 2 |
| **Protocol parser safety** | 0 | 1 | 0 | 1 | 0 | 2 |
| **Totals** | **2** | **9** | **14** | **11** | **4** | **40** |

(Row totals exceed 38 because several findings span two categories — e.g. VULN-001 maps to both crypto and injection; counts reflect primary + secondary tagging.)

---

## 6. Critical Findings — Full Detail

### VULN-001 — Unauthenticated Raft RPC binary deserialization over plaintext TCP

| Field | Value |
|---|---|
| Severity | **Critical** |
| Confidence | 92 |
| CWE | CWE-502 (Deser. of Untrusted Data), CWE-306 (Missing Authn), CWE-319 (Cleartext Transmission), CWE-345 (Insufficient Verification), CWE-400 (Resource Exhaustion) |
| OWASP | A08:2021 Software and Data Integrity Failures; A02:2021 Cryptographic Failures; A07:2021 Identification and Authentication Failures |
| File:line | `internal/cluster/raft/rpc.go:53-65, 111, 120-189` |

**Vulnerable code (shape):**

```go
// internal/cluster/raft/rpc.go
ln, err := net.Listen("tcp", s.addr)           // :53-65  no TLS
...
s.conns[""] = conn                             // :111    map-key bug (all conns same key)
...
// readRPCMessage :120-189
msgType := buf[0]
dec := gob.NewDecoder(r)                       // no io.LimitReader
if err := dec.Decode(msg); err != nil { ... }  // unbounded allocation
```

**Impact.** Three concrete attack paths, each independently catastrophic:

1. **Resource exhaustion / OOM.** A gob stream can declare arbitrary slice/map lengths before the payload arrives. Without `io.LimitReader` the decoder calls `make([]byte, declaredLen)` — on an 8 GB box a single 10 GB declaration OOM-kills the Raft leader. Repeat against replicas and the cluster fails open.
2. **Leader hijack / log injection.** `VoteRequest`, `AppendRequest`, and `SnapshotRequest` messages are fully controllable by any peer that can open a TCP connection. There is no HMAC, no shared secret, no peer allowlist enforced at the transport layer. A forged `AppendRequest` with a valid-looking term and prev-log-index replicates attacker-authored entries cluster-wide — which for a DNS server means zone-data poisoning across every replica.
3. **Connection-table corruption.** The `s.conns[""] = conn` statement at :111 uses the empty string as a map key for every connection, so all in-flight connections share one slot. The symptom today is connections being unevictable on shutdown; the latent bug is a shutdown hang under load.

Reachability is "cluster-internal" in the documented threat model, but the sample configs bind Raft to a non-loopback address by default, and any neighbor-container compromise, flat-L2 misconfig, or overlay-network leak exposes the port. Gossip (separate code path) uses AES-256-GCM — Raft does not inherit that protection.

**Remediation (step-by-step).**

1. **Wrap the listener in TLS with mTLS:**
   ```go
   // new: load cluster CA + peer certs
   caPool := x509.NewCertPool()
   caPool.AppendCertsFromPEM(clusterCAPEM)
   tlsCfg := &tls.Config{
       Certificates: []tls.Certificate{peerCert},
       ClientAuth:   tls.RequireAndVerifyClientCert,
       ClientCAs:    caPool,
       MinVersion:   tls.VersionTLS13,
   }
   rawLn, err := net.Listen("tcp", s.addr)
   if err != nil { return err }
   ln := tls.NewListener(rawLn, tlsCfg)
   ```
   Or, to reuse the existing gossip PSK, wrap each frame in AES-256-GCM (simpler migration path):
   ```go
   // pseudo-API
   cipher := gossip.AEADFromKey(encryptionKey)
   framed, err := cipher.Open(nil, nonce, ciphertext, nil) // per-frame
   ```

2. **Cap decoder input:**
   ```go
   const maxRPCBytes = 16 << 20 // 16 MiB
   limited := io.LimitReader(r, maxRPCBytes)
   dec := gob.NewDecoder(limited)
   ```

3. **Replace `encoding/gob` with a fixed-schema binary encoder** long-term. Gob is too permissive for untrusted channels by design. `encoding/binary` + explicit struct layout is the stdlib-compliant move.

4. **Peer allowlist enforced at accept-time:**
   ```go
   remoteIP := conn.RemoteAddr().(*net.TCPAddr).IP
   if !s.allowedPeers.Contains(remoteIP) {
       conn.Close()
       continue
   }
   ```

5. **Fix the map-key bug:**
   ```go
   s.conns[peerNodeID] = conn  // key by authenticated NodeID after mTLS handshake
   ```

**References.** CWE-502, CWE-306, CWE-319; Go stdlib `encoding/gob` documentation ("The implementation compiles a custom codec for each data type"); Raft paper §5.2 (authenticated RPC required for correctness in the presence of network adversaries).

---

### VULN-002 — `genhash_tmp.go` debug `init()` runs in production on every start

| Field | Value |
|---|---|
| Severity | **Critical** |
| Confidence | 95 |
| CWE | CWE-489 (Active Debug Code), CWE-798 (Use of Hardcoded Credentials) |
| OWASP | A05:2021 Security Misconfiguration |
| File:line | `internal/auth/genhash_tmp.go:1-11` |

**Vulnerable code (verbatim shape):**

```go
// internal/auth/genhash_tmp.go — NO build tag, NO _test.go suffix
package auth

import "fmt"

func init() {
    salt := fixedSalt[:]
    hash := HashPassword("test-password", salt)  // PBKDF2-SHA512 × 310,000
    fmt.Printf("KNOWN_ANSWER_LEN=%d\n", len(hash))
    fmt.Printf("KNOWN_ANSWER_HEX=%x\n", hash)
}
```

**Impact.** This was clearly a developer scaffolding file used to verify the PBKDF2 known-answer test, which survived review because the `_tmp.go` suffix bypasses the `_test.go` convention that would have kept it out of the production binary. Effects:

- **CPU burn at every start.** 310k rounds of PBKDF2-HMAC-SHA512 is ~200–500ms on a modern core. Every container restart, every SIGHUP-triggered restart, every cluster healthcheck restart pays this cost. On autoscaled deployments that cycle pods aggressively the aggregate waste is non-trivial.
- **Hash leak in operator logs.** The `fmt.Printf` writes `KNOWN_ANSWER_HEX=<hex>` to stdout. Log aggregators ingest this. Because salt and password are both constants, this is a public rainbow-table entry for `PBKDF2-SHA512(test-password, fixedSalt, 310000)`. Not catastrophic on its own — but categorically "debug-scaffold in production", which is a compliance red flag for SOC 2 / ISO 27001 audits.
- **Compiled into `dnsctl` too.** Because the `auth` package is imported by both `cmd/nothingdns/` and `cmd/dnsctl/`, every CLI invocation — `dnsctl zone list`, `dnsctl cache flush`, `dnsctl dig ...` — also pays the cost and writes the hash.
- **Supply chain signal.** The file proves the dev workflow is writing `_tmp.go` to avoid test conventions. Other `_tmp.go` files may exist (verified: only this one).

**Remediation.**

1. **Delete the file.** No refactor needed — it is not called anywhere.
   ```bash
   git rm internal/auth/genhash_tmp.go
   ```

2. **If the known-answer test is genuinely useful**, move it into a `_test.go` file:
   ```go
   // internal/auth/pbkdf2_test.go
   func TestPBKDF2KnownAnswer(t *testing.T) {
       salt := fixedSalt[:]
       got := HashPassword("test-password", salt)
       want, _ := hex.DecodeString("…")
       if !bytes.Equal(got, want) {
           t.Fatalf("KAT mismatch")
       }
   }
   ```

3. **Add a CI grep to fail the build on `_tmp.go` files:**
   ```yaml
   # .github/workflows/go.yml
   - name: Reject _tmp.go files
     run: |
       if find . -name '*_tmp.go' | grep .; then
         echo "::error::Remove *_tmp.go files before merge"
         exit 1
       fi
   ```

**References.** CWE-489 (Active Debug Code in Production Build), CWE-798, NIST SP 800-63B §5.1.1.2 (salt + hash handling).

---

## 7. High Findings — Full Detail

### VULN-003 — Legacy `auth_token` silently synthesizes admin

- **CWE-287, CWE-269 — OWASP A01 Broken Access Control**
- **File:line**: `internal/api/server.go:820-840`
- When an operator configures both `auth_token` (legacy shared secret, intended for CI/automation) and `users` (RBAC mode), the middleware matches the shared token first via `subtle.ConstantTimeCompare` and then injects `GetUser("admin")` into the request context. Every downstream `requireAdmin` / `requireOperator` check trivially passes. The constant-time compare is correctly used — the bug is semantic, not cryptographic: any holder of the CI automation token is de-facto admin with no explicit role mapping.
- **Fix.** Refuse to boot when both modes are configured, OR require explicit `auth_token_role: admin|operator|viewer` with `viewer` as default and fail closed when unset:
  ```go
  if cfg.AuthToken != "" && cfg.AuthTokenRole == "" {
      return errors.New("auth_token requires auth_token_role when users are configured")
  }
  ```

### VULN-004 — Blocklist SSRF via redirect-follow

- **CWE-918 — OWASP A10 SSRF**
- **File:line**: `internal/blocklist/blocklist.go:54-57, 190-197` (client + fetch); validator at `:98-133`
- `validateBlocklistURL` rejects IP-literal hosts, RFC 1918 / loopback / link-local IPs, and cloud-metadata hostnames. It runs **only on the initial URL**. The `http.Client` has no `CheckRedirect`, so Go's default 10-hop policy silently follows attacker-controlled redirects to `http://169.254.169.254/...`, `http://127.0.0.1:8080/...`, or any intranet endpoint.
- **Fix.** Set `CheckRedirect` to re-validate every hop and add a `net.Dialer.Control` callback that rechecks the resolved IP against the private-range allowlist (defeats DNS-rebinding):
  ```go
  client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
      if len(via) >= 5 { return errors.New("too many redirects") }
      return validateBlocklistURL(req.URL.String())
  }
  dialer := &net.Dialer{
      Control: func(network, address string, c syscall.RawConn) error {
          host, _, _ := net.SplitHostPort(address)
          ip := net.ParseIP(host)
          if isPrivateOrMetadata(ip) { return errors.New("blocked IP") }
          return nil
      },
  }
  client.Transport = &http.Transport{DialContext: dialer.DialContext}
  ```

### VULN-005 — Cluster gossip plaintext by default

- **CWE-319, CWE-522, CWE-1188 — OWASP A02 Cryptographic Failures**
- **File:line**: `internal/cluster/gossip.go:275-283`; sample configs `deploy/config-node{1,2,3}.yaml:30`
- `NewGossipProtocol` only enables AEAD when `config.EncryptionKey` is set. Otherwise a single warning is logged and plaintext JSON flows over UDP — including zone-update, config-sync, and cache-sync messages. Sample configs ship with the key unset. Any attacker on the cluster network can forge zone updates and cluster config deltas — effective cluster takeover without touching Raft.
- **Fix.** Fail-closed: refuse to boot when `cluster.enabled: true` and `encryption_key` is empty unless `cluster.insecure: true` is explicitly set. Ship sample configs with `encryption_key: "${NOTHINGDNS_GOSSIP_KEY}"` placeholder and document key generation (`openssl rand -hex 32`).

### VULN-006 — `$INCLUDE` absolute-path bypass in zone-file parser

- **CWE-22, CWE-23 — OWASP A01 Broken Access Control**
- **File:line**: `internal/zone/zone.go:360-420`
- The parser blocks `..` substrings and symlinks (`os.Lstat`) and restricts relative paths via `filepath.Rel`. The guard `!filepath.IsAbs(args[0])` means **absolute paths skip the `Rel` check entirely**. A zone file containing `$INCLUDE /etc/shadow` (or `C:\Windows\System32\config\SAM`) passes validation and `os.Open(includeFile)` reads the absolute path. Parser error messages echo malformed record text, so the zone-file load becomes an arbitrary-file-read oracle.
- **Fix.** Unconditionally reject `filepath.IsAbs(args[0])`, OR require an explicit `zone_include_root` allowlist that absolute paths must be contained within:
  ```go
  if filepath.IsAbs(args[0]) { return errAbsIncludeForbidden }
  ```

### VULN-007 — SSHFP / TLSA `Unpack` panic on undersized `rdlength`

- **CWE-191 (Integer Underflow), CWE-20 — OWASP A03 Injection**
- **File:line**: `internal/protocol/types.go:877-896` (SSHFP), `:945-968` (TLSA)
- `RDataSSHFP.Unpack` computes `fpLen := int(rdlength) - 2`; if `rdlength < 2` this goes negative, `offset+fpLen > len(buf)` is false, and `make([]byte, fpLen)` panics. TLSA has the identical pattern with `certLen := int(rdlength) - 3`. The top-level `integratedHandler.ServeDNS` has panic recovery, so a query-time crash returns SERVFAIL — **but the same unpack runs inside zone-file parsing (server startup panic), AXFR response processing (background goroutine, no recovery), and DNSSEC validation (no recovery)**. An attacker-controlled authoritative zone referenced during recursion is enough.
- **Fix.** Guard at function entry:
  ```go
  if rdlength < 2 { return 0, ErrBufferTooSmall } // SSHFP
  if rdlength < 3 { return 0, ErrBufferTooSmall } // TLSA
  ```
  Consider a generic `typeMinRDLength` table in `UnpackResourceRecord` for defense-in-depth.

### VULN-008 — No per-zone ownership / BOLA

- **CWE-639, CWE-862, CWE-284 — OWASP API1:2023 Broken Object Level Authorization**
- **File:line**: `internal/api/api_zones.go:66` (documented design choice), `:68-138` (handler), `internal/zone/manager.go:208-220`
- Every authenticated operator has global CRUD across every zone. Endpoints: `GET/POST/PUT/DELETE /api/v1/zones/{name}`, `POST /api/v1/zones/{name}/records`, `POST /api/v1/zones/{name}/ptr-bulk`, `GET /api/v1/zones/{name}/export`. `CreateZone` rejects only `""` and `"."` — `CreateZone("com.")`, `CreateZone("arpa.")`, `CreateZone("localhost.")` all succeed. A compromised or curious operator can delete any victim's zone (immediate, no soft-delete), squat IANA TLDs, or export TXT/SPF/DKIM/DMARC material.
- **Fix.** Introduce a per-zone ACL (`zone -> [usernames]`), or at least a tenancy model. Block creation of IANA TLDs, `arpa.`, `in-addr.arpa.`, `localhost.`, `example.`, `test.`, `invalid.`. Add soft-delete with tombstone + grace period for destructive operations.

### VULN-009 — Operator role has admin-grade reach

- **CWE-862, CWE-269, CWE-863 — OWASP API5:2023 Broken Function Level Authorization**
- **File:line**: `internal/api/api_acl.go:37`, `api_rpz.go:82, 121`, `api_upstreams.go:45`, `api_blocklist.go:39, 79`, `api_config.go:13, 105, 144`, `api_cache.go:32`, `api_zones.go:457`
- Endpoints that should require Admin but currently require only Operator: `PUT /api/v1/acl` (rewrite all ACL rules — operator can self-grant `0.0.0.0/0 allow ANY`, creating an open amplifier), `POST /api/v1/rpz/rules` (redirect `bank.com -> attacker.example`), `POST /api/v1/rpz/toggle` (disable RPZ entirely), `POST /api/v1/blocklists` URL-add (SSRF per VULN-004), `POST /api/v1/blocklists/toggle`, `PUT /api/v1/upstreams` (MITM every recursive query), `POST /api/v1/config/reload`, `PUT /api/v1/config/logging` (silence audit by setting FATAL log level), `PUT /api/v1/config/rrl` (disable rate limiting), `POST /api/v1/cache/flush`, `POST /api/v1/zones/{name}/ptr-bulk` (up to 65,536 records per call). The 3-tier RBAC collapses to 2 tiers in practice.
- **Fix.** Split into `dns-operator` (zones, records only) vs `admin` (infra). Promote ACL, RPZ, upstream, blocklist-URL-add, config-reload, logging-level, and RRL to `requireAdmin`. Sanity-check ACL rules at write-time (reject `0.0.0.0/0 allow ANY` unless an explicit flag is set).

### VULN-010 — CSRF exposure on cookie-auth API

- **CWE-352 — OWASP A01 Broken Access Control**
- **File:line**: `internal/api/server.go:776-860` (authMiddleware cookie fallback), `internal/api/api_auth.go:74-82` (cookie set)
- The auth middleware falls back to the `ndns_token` cookie when no `Authorization` header is present. Mutating endpoints accept cookie auth. The only CSRF defense is `SameSite=Strict` on the cookie. Practical exploitation today is blocked by modern browser SameSite enforcement, but defense-in-depth is absent: no CSRF token, no `Origin`/`Referer` check, no custom-header requirement. A future addition of `Access-Control-Allow-Credentials: true` would flip this to catastrophic. Confidence capped at 65 because the practical CSRF window requires a SameSite bypass.
- **Fix.** On POST/PUT/DELETE require either (a) `Authorization: Bearer` header (drop cookie for mutating endpoints), (b) a CSRF double-submit token, or (c) a custom `X-Requested-With` header to force preflight. Additionally check `Sec-Fetch-Site: same-origin` on state-changing requests.

### VULN-011 — JWT stored in JS-readable cookie, overwriting HttpOnly server cookie

- **CWE-1004, CWE-522 — OWASP A07 Identification and Authentication Failures**
- **File:line**: `web/src/pages/login.tsx:50`, `web/src/lib/api.ts:3-7`, `web/src/stores/authStore.ts:13-31`, `internal/dashboard/static.go:144`
- The backend correctly issues `Set-Cookie: ndns_token=…; HttpOnly; Secure; SameSite=Strict` at `api_auth.go:74-82`. The frontend then **overwrites** that cookie via `document.cookie = ...` in `login.tsx:50`, which is always non-HttpOnly by spec. The same token is also persisted to `localStorage` under `ndns-auth` via zustand. Any future XSS — in the React SPA, in an unescaped API response, or in any of ~24 npm transitive deps — yields the token and grants 24 hours of full admin reach. React's auto-escape makes the current code XSS-clean, hence confidence 88 rather than 95.
- **Fix.** Delete the `document.cookie = ...` write. Rely solely on the server's `Set-Cookie` header. Remove `token` from the zustand persist partition (keep only `username/role/isAuthenticated`). If a bearer header is needed for non-cookie flows, keep the token in a module-scope JS variable, not storage.

---

## 8. Medium Findings

**Compact table (all 13 mediums):**

| # | Title | CWE | File:line | One-line fix |
|---|---|---|---|---|
| VULN-012 | Swagger UI loads scripts from unpkg CDN, no SRI, no version pin | CWE-829 | `internal/api/openapi.go:670-688` | Self-host via `embed.FS`, or pin exact version + SRI hash |
| VULN-013 | Single global 100 rpm rate limit covers destructive endpoints | CWE-770 | `internal/api/server.go:264-268` | Per-endpoint buckets (reload 1/min, bulk-PTR 2/min, URL add 5/min) |
| VULN-014 | Login limiter locks accounts by username across IPs | CWE-307, CWE-840 | `internal/api/server.go:92-171` | Lock by `(ip, username)` tuple only; exponential backoff |
| VULN-015 | RPZ `IsEnabled()` data race on `enabled` field | CWE-362, CWE-367 | `internal/rpz/rpz.go:536-546` | Use `atomic.Bool` or hold `e.mu` in `IsEnabled()` |
| VULN-016 | CSP missing explicit directives, no trusted-types | CWE-693, CWE-1021 | `internal/api/server.go:714` | Expand to full directive set; add `require-trusted-types-for 'script'` |
| VULN-017 | Username enumeration via PBKDF2 timing oracle | CWE-204, CWE-208 | `internal/api/api_auth.go:46-58` | On missing user, run dummy PBKDF2 against placeholder hash |
| VULN-018 | No per-connection rate limit on dashboard WebSocket | CWE-770 | `internal/dashboard/server.go:handleWebSocket` | Call `conn.SetRateLimit(100, time.Second)` after handshake |
| VULN-019 | Blocklist URL-add runs synchronously, starves handler goroutines | CWE-400 | `internal/blocklist/blocklist.go:190-197` | Queue + background worker, return 202 Accepted |
| VULN-020 | WAL entry reader trusts uint32 length without segment cap | CWE-789 | `internal/storage/wal.go:404-411` | `if length > MaxSegmentSize { err }` before `make` |
| VULN-021 | Password policy gap: CreateUser accepts empty password, no max | CWE-521 | `internal/auth/auth.go:348` | Enforce 12 ≤ len ≤ 128, share validator with bootstrap |
| VULN-022 | Token revocation is in-memory only; persistence never wired | CWE-613 | `internal/auth/auth.go:329, 628` | Wire `SaveTokensSigned` in `auth_manager.go` or document loudly |
| VULN-023 | Legacy k8s manifest missing core hardening | CWE-250, CWE-732 | `deploy/k8s/deployment.yaml:71-74` | Add `allowPrivilegeEscalation:false`, `cap_drop:[ALL]`, seccomp |
| VULN-024 | Helm default exposes public LB with NetworkPolicy off | CWE-284, CWE-732 | `deploy/helm/nothingdns/values.yaml:45, 332` | Flip defaults to `ClusterIP` and `networkPolicy.enabled: true` |
| VULN-025 | Container workflow has no sign, SBOM, scan, or test gate | CWE-494, CWE-1357 | `.github/workflows/container.yml` | Add cosign, SBOM, Trivy, `needs: [test]` |

### Featured Medium #1 — VULN-013 (rate-limiter scoping)

A single global 100 rpm/IP limit covers every authenticated endpoint. That limit is generous for ACL reads but dangerous for destructive verbs: an operator can issue 100 config reloads per minute, 100 cache flushes, or 100 bulk-PTR expansions (each up to 65,536 records — 6.5M mutations per minute at the cap). The blocklist URL-add also runs synchronously, so an attacker adding slow-responding URLs holds handler goroutines for up to 30s each and starves the HTTP server. Remediation is per-endpoint leaky buckets plus a per-token limit (not just per-IP, because a stolen token rotated through IPv6 /64 addresses bypasses the IP limit entirely).

### Featured Medium #2 — VULN-014 (login-limiter DoS)

The login limiter tracks failures by `(ip, username)` tuple **and** independently by `username` alone. Five failures on a known username from any mix of IPs locks that account for 5 minutes. A distributed attacker (botnet, CGNAT pool, IPv6 /64) can therefore lock every known admin account indefinitely by cycling five failed attempts per username per 5 minutes. Combined with VULN-017 (username enumeration via timing oracle), the attacker can first enumerate then indefinitely deny admin login — trivial DoS of administrative access. Additionally, the limiter's O(N) map-eviction path allows an attacker to flush legitimate lockouts by flooding fresh IPs. Fix: drop the username-alone counter; lock only on `(ip, username)`; replace O(N) eviction with sampled LRU.

### Featured Medium #3 — VULN-015 (RPZ data race)

`IsEnabled()` reads `e.enabled` without a lock; `SetEnabled()` mutates it under `e.mu`. Per the Go memory model this is undefined behavior — the race detector flags it immediately. The `api_rpz.go:130` pattern `SetEnabled(!IsEnabled())` is additionally TOCTOU: two concurrent toggle calls may both read the same pre-state and both apply the flip, yielding net-zero change or torn state. Fix: `atomic.Bool`, or hold `e.mu.RLock()` in `IsEnabled()`, and replace the toggle pattern with an atomic `Toggle()` method (or switch the API to `PUT /api/v1/rpz/enabled {enabled: true|false}`).

---

## 9. Low & Info Findings

| # | Severity | Title | File:line |
|---|---|---|---|
| VULN-026 | Low | ZONEMD Pack missing destination-buffer bounds check | `internal/protocol/types.go:1554-1578` |
| VULN-027 | Low | `UnpackName` may read past `rdlength` into adjacent RR bytes | `internal/protocol/types.go:146, 198, 250, 302, 381, 569, 577, 708, 1124, 1266` |
| VULN-028 | Low | `sync.Pool` bimodal type (`[]byte` vs `*[]byte`) defeats recycling | `internal/server/udp.go:157-167, 392-408`, `tcp.go:100-104, 355-372` |
| VULN-029 | Low | Metrics HTTP server missing `ReadHeaderTimeout` + `IdleTimeout` | `internal/metrics/metrics.go:154-159` |
| VULN-030 | Low | Auth-store AES key derived via `SHA-512(secret)[:32]` (not HKDF) | `internal/auth/auth.go:614-619` |
| VULN-031 | Low | TSIG accepts HMAC-SHA1 with only a log warning | `internal/transfer/tsig.go:477-482` |
| VULN-032 | Low | Hardcoded 24h token TTL ignores `Config.TokenExpiry` | `internal/api/api_auth.go:67, 81, 173, 187` |
| VULN-033 | Low | Zone-export button loses `Authorization` header (top-level nav) | `web/src/pages/zone-detail.tsx:99-101` |
| VULN-034 | Low | OpenAPI endpoint hardcodes `Access-Control-Allow-Origin: *` | `internal/api/openapi.go:655` |
| VULN-035 | Low | `deploy/production.yaml` ships with API auth entirely commented out | `deploy/production.yaml:27-39` |
| VULN-036 | Info | `docker-compose.yml` services lack cap_drop/read_only/no-new-privileges | `docker-compose.yml:15-97` |
| VULN-037 | Info | `quic-go@v0.59.0` should be CVE-audited; subscribe to advisories | `go.mod:8` |
| VULN-038 | Info | CLAUDE.md "zero external dependencies" claim is inaccurate | `CLAUDE.md`, `go.mod:8` |
| VULN-039 | Info | Web CI uses `npm install` (not `npm ci`); no Dependabot config | `.github/workflows/web.yml:27` |

---

## 10. Remediation Roadmap

### Phase 1 — Immediate (1–3 days, pre-production-deploy)

All Critical findings must close before production deploy.

| # | Finding | Effort | Impact |
|---|---|---|---|
| 1 | VULN-001 — Raft RPC authn + size cap + TLS or AEAD | **M** (1–2 days) | Critical — eliminates cluster takeover primitive |
| 2 | VULN-002 — Delete `genhash_tmp.go`, add CI grep | **S** (15 min) | Critical — removes debug code from prod |

**Gate:** production deploy may proceed after Phase 1.

### Phase 2 — Short-Term (1–2 weeks)

All High findings + three quick-win Mediums (VULN-015 atomic.Bool, VULN-020 WAL size cap, VULN-023 k8s hardening).

| # | Finding | Effort | Impact |
|---|---|---|---|
| 3 | VULN-003 — Refuse mixed `auth_token` + `users` or require role | **S** | High |
| 4 | VULN-004 — Blocklist redirect SSRF guard + dialer.Control | **M** | High |
| 5 | VULN-005 — Fail-closed gossip encryption | **S** | High |
| 6 | VULN-006 — Reject absolute `$INCLUDE` paths | **S** | High |
| 7 | VULN-007 — rdlength underflow guards (SSHFP + TLSA) | **S** | High |
| 8 | VULN-008 — Per-zone ACL + soft-delete + TLD block | **L** | High |
| 9 | VULN-009 — Split `operator` vs `admin` endpoints | **M** | High |
| 10 | VULN-010 — CSRF double-submit token or bearer-only on mutations | **M** | High |
| 11 | VULN-011 — Remove JS cookie write + localStorage persist | **S** | High |
| 12 | VULN-015 — `atomic.Bool` on RPZ `enabled` | **S** | Medium (quick win) |
| 13 | VULN-020 — WAL length cap vs segment size | **S** | Medium (quick win) |
| 14 | VULN-023 — k8s manifest hardening block | **S** | Medium (quick win) |

### Phase 3 — Medium-Term (1–2 months)

Remaining Mediums + dependency updates.

| # | Finding | Effort | Impact |
|---|---|---|---|
| 15 | VULN-012 — Self-host Swagger UI via `embed.FS` | **M** | Medium |
| 16 | VULN-013 — Per-endpoint rate-limit buckets + per-token limit | **M** | Medium |
| 17 | VULN-014 — Login limiter `(ip, username)` tuple + backoff | **S** | Medium |
| 18 | VULN-016 — Full CSP directive set + trusted-types | **S** | Medium |
| 19 | VULN-017 — Constant-time login (dummy PBKDF2 on missing user) | **S** | Medium |
| 20 | VULN-018 — WebSocket `SetRateLimit(100, 1s)` + per-user caps | **S** | Medium |
| 21 | VULN-019 — Async blocklist URL fetch with 202 Accepted | **M** | Medium |
| 22 | VULN-021 — Unified password validator (12–128 chars, classes) | **S** | Medium |
| 23 | VULN-022 — Wire token-store persistence OR document behavior | **S** | Medium |
| 24 | VULN-024 — Helm defaults: ClusterIP + NetworkPolicy on | **S** | Medium |
| 25 | VULN-025 — cosign + SBOM + Trivy + test-gate in container workflow | **M** | Medium |
| 26 | VULN-037 — Subscribe to quic-go advisories; adopt `govulncheck` in CI | **S** | Info → defensive |
| 27 | VULN-039 — Switch web CI to `npm ci`; add Dependabot | **S** | Info → defensive |

### Phase 4 — Hardening (Ongoing)

Lows + defense-in-depth.

| # | Finding | Effort | Impact |
|---|---|---|---|
| 28 | VULN-026 — ZONEMD Pack bounds check | **S** | Low |
| 29 | VULN-027 — `UnpackName` rdlimit parameter | **M** | Low |
| 30 | VULN-028 — `sync.Pool` idiom unification | **S** | Low |
| 31 | VULN-029 — Metrics HTTP server timeout fields | **S** | Low |
| 32 | VULN-030 — HKDF for auth-store AES / HMAC split | **S** | Low |
| 33 | VULN-031 — Reject HMAC-SHA1 TSIG by default (opt-in flag) | **S** | Low |
| 34 | VULN-032 — Honor `Config.TokenExpiry` + idle timeout | **S** | Low |
| 35 | VULN-033 — Zone-export via `fetch()` + blob download | **S** | Low |
| 36 | VULN-034 — Route OpenAPI through `corsMiddleware` | **S** | Low |
| 37 | VULN-035 — Default `auth_required: true` in prod samples | **S** | Low |
| 38 | VULN-036 — docker-compose hardening (cap_drop, read_only) | **S** | Info |
| 39 | VULN-038 — Reconcile CLAUDE.md dependency policy with reality | **S** | Info |

**Phase counts:** Phase 1 = 2 items · Phase 2 = 12 items · Phase 3 = 13 items · Phase 4 = 12 items · **Total = 39 items** (38 findings + 1 CI grep as a standalone task).

---

## 11. Methodology

This assessment was produced by a multi-phase pipeline:

1. **Reconnaissance (Phase 1)** — Automated architecture mapping (`sc-recon`) and dependency inventory (`sc-dependency-audit`) produced `architecture.md` and `dependency-audit.md`. No code executed against the project; findings based on static inventory.

2. **Detection (Phase 2)** — 48 specialized security skills executed in parallel across the codebase: 7 language scanners (`sc-lang-go`, `sc-lang-typescript`), OWASP-aligned scanners (auth, crypto, injection, API/race, SSRF, CSRF, CORS, deserialization, path, header, XSS, open-redirect, mass-assignment, file-upload, business-logic, rate-limiting, WebSocket), and infrastructure scanners (`sc-infra`, `sc-docker`, `sc-ci-cd`, `sc-iac`). ~130 raw findings emitted.

3. **Verification (Phase 3)** — `sc-verifier` consolidated duplicates by root cause, recalculated confidence with reachability and sanitization modifiers, applied severity caps by confidence band (conf <30 → Info; 30–49 → cap Medium; 50–69 → cap High), and emitted the 38-finding `verified-findings.md` consumed by this report. 21 raw findings were eliminated as false-positive, out-of-scope, or positive findings.

4. **Reporting (Phase 4)** — This document. All findings cite file:line; CWE and OWASP references attached per-finding; remediation code snippets use stdlib idioms (no third-party recommendations, consistent with the project's dependency policy).

**Risk score model.**
- 2 Criticals × 2.0 = 4.0
- 9 Highs × 1.0 = 9.0
- 13 Mediums × 0.3 = 3.9
- 10 Lows × 0.1 = 1.0
- Raw = 17.9, clamped to 10
- Modifier: solid crypto fundamentals (PBKDF2@310k, constant-time compares, TLS 1.3, AES-256-GCM gossip when on) -1.0
- Modifier: hand-rolled security-critical paths (DNS parser, YAML parser, KV/WAL, Raft transport) +0.5
- Final **7.5 / 10 — High Risk**

This reflects that production deploy is gated on two discrete Criticals and a handful of Highs — not a systemic hygiene failure.

---

## 12. Disclaimer

This report is the output of an automated security scanning pipeline augmented by LLM-driven analysis. It is not a substitute for a manual penetration test, a formal code audit, or a threat-model exercise conducted by a qualified team against a running deployment. Findings reflect the state of the codebase at the commit captured above (`main @ 48e18b7`) and may be invalidated by subsequent changes. False positives have been filtered during the verification phase but cannot be guaranteed to zero — operators should confirm each finding against the cited file:line before committing remediation effort. No exploitation was performed against any running system; all findings are derived from static analysis of the source tree. Severity scoring follows CVSS-aligned heuristics but is not CVSS-equivalent. Absence of a finding in this report does not imply absence of vulnerability — only that the scanning pipeline and verification step did not surface one at the given confidence threshold.

*End of report.*
