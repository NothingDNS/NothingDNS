# NothingDNS Production Readiness Report

Last updated: 2026-07-20

## Verdict

**Repository status: ready for a release candidate; deployment status: READY WITH GAPS until target-environment proof is attached.**

The current tree passes the local build, vet, formatting, full Go test, focused race, frontend lint/unit/build/smoke, dependency, workflow, config-invariant, and backup/restore gates listed below. The 2026-07-20 audit also fixed a real DoQ shutdown race, a frontend production-build type failure, a DoT/XoT listener collision, staging metrics exposure, and non-functional backup/restore/Prometheus-monitoring paths.

Do not translate repository health into an unconditional production claim. A promotion still requires the environment-specific evidence in `PRODUCTION_PROOF_CHECKLIST.md`: rendered/applied manifests, real secrets/files, image scan, restore drill, deployed smoke, load budget, and (when HA is in scope) three-node failover/snapshot proof.

## Release Gates

Run these before tagging or promoting an image:

```bash
npm --prefix web run lint -- --max-warnings=0
npm --prefix web test
npm --prefix web run build
npm --prefix web run smoke
npm --prefix web audit --audit-level=moderate

git diff --check
go build ./...
go vet ./...
govulncheck ./...
actionlint .github/workflows/*.yml
make backup-restore-test

helm lint deploy/helm/nothingdns \
  --set-string auth.authSecret='AuthSecret-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
  --set-string auth.adminPassword='AdminPassword-1234567890-ABCDE' \
  --set-string auth.storageEncryptionKey='a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90'

go test ./... -count=1 -short
go test -race ./internal/quic ./cmd/nothingdns -count=1 -short
make test-race-critical
```

Validate rendered deployment configs:

```bash
# Raw Kubernetes ConfigMap config
awk '/^  config.yaml: \|/{flag=1; next} flag { if (substr($0,1,4)=="    ") print substr($0,5); else if ($0=="") print ""; else flag=0 }' \
  deploy/k8s/configmap.yaml > /tmp/nothingdns-k8s-config.yaml
sed -i \
  -e "s/\${NOTHINGDNS_AUTH_SECRET}/AuthSecret-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ/g" \
  -e "s/\${NOTHINGDNS_ADMIN_PASSWORD}/AdminPassword-1234567890-ABCDE/g" \
  -e "s/\${NOTHINGDNS_METRICS_AUTH_TOKEN}/MetricsToken-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ/g" \
  -e "s/\${NOTHINGDNS_STORAGE_ENCRYPTION_KEY}/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/g" \
  -e "s/\${NOTHINGDNS_CLUSTER_ENCRYPTION_KEY}/ClusterKey-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ/g" \
  -e "s/\${NOTHINGDNS_CLUSTER_SNAPSHOT_ENCRYPTION_KEY}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/g" \
  -e "s/\${POD_NAME}/nothingdns-0/g" \
  -e "s/\${POD_IP}/127.0.0.1/g" \
  /tmp/nothingdns-k8s-config.yaml
go run ./cmd/nothingdns -config /tmp/nothingdns-k8s-config.yaml -validate-config

# Production config, with all required secrets present
NOTHINGDNS_AUTH_SECRET='AuthSecret-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
NOTHINGDNS_ADMIN_PASSWORD='AdminPassword-1234567890-ABCDE' \
NOTHINGDNS_OPERATOR_PASSWORD='OperatorPassword-1234567890-ABCDE' \
NOTHINGDNS_VIEWER_PASSWORD='ViewerPassword-1234567890-ABCDE' \
NOTHINGDNS_METRICS_AUTH_TOKEN='MetricsToken-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
NOTHINGDNS_STORAGE_ENCRYPTION_KEY='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
NOTHINGDNS_CLUSTER_ENCRYPTION_KEY='ClusterKey-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
NOTHINGDNS_CLUSTER_SNAPSHOT_ENCRYPTION_KEY='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
go run ./cmd/nothingdns -config deploy/production.yaml -validate-production-config
```

The production validation should complete without missing-environment warnings or production gate failures.

Smoke-test a deployed target before promotion:

```bash
NOTHINGDNS_BASE_URL='https://dns.example.com' \
NOTHINGDNS_METRICS_URL='https://metrics.example.com/metrics' \
NOTHINGDNS_DNS_SERVER='203.0.113.53' \
NOTHINGDNS_DNS_PORT='53' \
NOTHINGDNS_DNS_NAME='example.com' \
NOTHINGDNS_DNS_TYPE='A' \
NOTHINGDNS_METRICS_AUTH_TOKEN="$NOTHINGDNS_METRICS_AUTH_TOKEN" \
scripts/production-smoke.sh
```

## Closed Production Gaps

### Configuration and Deployability

- The custom YAML parser now reads production-critical fields that were previously documented but ignored: top-level `rrl`, `blocklist.urls`, `cache.serve_stale`, `cache.stale_grace_secs`, `server.pid_file`, `zonemd`, `shutdown_timeout`, and transfer policy.
- Production, staging, raw Kubernetes, and Helm-rendered configs validate through the actual daemon parser.
- `-validate-production-config` adds stricter production gates for stable auth secrets/users, closed recursion, DNSSEC time validation, explicit encrypted persistent storage, encrypted cluster transport, Raft persistence, metrics auth, and TSIG-protected transfer allowlists.
- Helm chart defaults now render valid NothingDNS config by default, including secret/env wiring, transfer policy, metrics auth, ingress/service ports, and network policy behavior.
- `deploy/production.yaml` documents all auth secrets as environment inputs; `docs/DEPLOYMENT_CHECKLIST.md` includes the full required env set.

### Security Behavior

- Metrics endpoints support auth token wiring in deployment manifests.
- Zone transfer is deny-by-default through `transfer.allow_list`; the same list also authorizes RFC 1996 NOTIFY (a master permitted for AXFR/IXFR may send NOTIFY, others are refused). AXFR serving no longer depends on stale doc-only `allow-transfer` wording.
- Cluster startup no longer fails open. If `cluster.enabled=true` and cluster init/start fails, the daemon startup fails instead of silently running standalone.
- DSO session IDs now fail closed if `crypto/rand` is unavailable instead of falling back to predictable sequential IDs.
- DNSSEC `RRSIGForRRSet` now canonicalizes RRSet ordering and propagates RDATA packing errors.
- Graceful shutdown and test cleanup paths were hardened to reduce race and lifecycle ambiguity.

### CI and Supply Chain

- GitHub Actions workflows were tightened for Go, web, Helm, actionlint, container SBOM/provenance, and keyless signing.
- Codecov action usage is pinned.
- Helm lint and rendered-config validation are release gates.

### Dashboard

- The React dashboard passes lint and production build.
- Dashboard route smoke tests are part of the web CI gate and verify the production shell, deep links, and entrypoint asset.
- Route-level code splitting removed the large Vite chunk warning; the main dashboard JS chunk is now below the warning threshold and pages load as separate chunks.
- `web/go.mod` is intentionally present as a nested Go module sentinel so root `go test ./...` does not traverse Go packages inside `web/node_modules`.

### Repository Hygiene

- Debug-printing parser tests were converted into assertion-based tests and renamed.
- Security scan artifacts are ignored and retained only in the system that produced them.
- Stale documentation examples were updated to match the current config schema and CLI/API behavior.

## Required Operator Inputs

For `deploy/production.yaml`, provide these as secrets in the runtime environment:

```bash
NOTHINGDNS_AUTH_SECRET
NOTHINGDNS_ADMIN_PASSWORD
NOTHINGDNS_OPERATOR_PASSWORD
NOTHINGDNS_VIEWER_PASSWORD
NOTHINGDNS_METRICS_AUTH_TOKEN
NOTHINGDNS_STORAGE_ENCRYPTION_KEY
NOTHINGDNS_CLUSTER_ENCRYPTION_KEY
NOTHINGDNS_CLUSTER_SNAPSHOT_ENCRYPTION_KEY
```

Recommended generation:

```bash
openssl rand -base64 32  # auth/user/metrics secrets
openssl rand -hex 32     # persistent zone DB encryption key
openssl rand -base64 32  # cluster gossip encryption key
openssl rand -hex 32     # cluster snapshot encryption key
```

Do not commit literal secret values to any config file. The config validator rejects common placeholder secret strings and low-entropy secrets.

## Residual roadmap (ordered)

### P0 — Promotion blockers for a specific environment

- Render and validate Helm locally/in CI, then server-side dry-run the manifests against the target cluster CRDs and policies. The 2026-07-20 local environment did not have a Helm binary, so only template source review plus CI assertions were available locally.
- Build/scan the final image by digest and verify its signature, SBOM, provenance, non-root runtime, probes, persistence, and network policy in the target registry/cluster.
- Run an off-host backup plus destructive restore drill and record achieved RPO/RTO; the repository round-trip test proves the archive mechanism, not cloud retention or volume-snapshot orchestration.
- Run `production-smoke.sh` against the deployed target with real DNS/API/metrics/TLS inputs.
- If Raft HA is release scope, attach three-node election, replication, restart, partition/failover, and snapshot catch-up evidence.
- Capture a target-hardware load test with explicit QPS, P95/P99 latency, error-rate, CPU, memory, and saturation budgets.

### P1 — Near-term hardening

- Replace the custom tracing exporter with the official OpenTelemetry SDK/OTLP pipeline and W3C TraceContext propagation.
- ~~Ship a versioned Grafana dashboard and validate PrometheusRule queries against real emitted metric names.~~ **Shipped 2026-08-19**: `deploy/grafana/nothingdns-overview.json` (13 panels; every metric name validated against a live production `/metrics` scrape, including the `nothingdns_query_duration_seconds` histogram bucket series). PrometheusRule alert expressions were also validated against the same scrape the same day — three stale metric names corrected (`nothingdns_dns_requests_total{rcode="SERVFAIL"}` → `nothingdns_responses_total{rcode="2"}`, `nothingdns_dns_request_duration_seconds_bucket` → `nothingdns_query_duration_seconds_bucket`, `nothingdns_cluster_nodes` → `nothingdns_cluster_nodes_alive`).
- Add scheduled recovery drills, container vulnerability scans, and benchmark regression budgets to CI/release automation.
- Decide whether production environments require progressive delivery (canary/blue-green) and codify rollback criteria in the deployment platform rather than the application chart.

### P2 — Non-blocking maintenance

- Add visual browser regression tests if pixel-level dashboard stability is a release requirement.
- Tune dashboard chunk grouping only if measured request overhead justifies it.
- Continue simplifying legacy/dead paths such as the unused Raft `sendCommitted` helper; do not treat them as runtime data-loss paths without reproducing the active apply-loop behavior.

## Promotion Checklist

- All release gates above pass on a clean checkout.
- `npm --prefix web test` passes (89 unit tests in the 2026-07-20 baseline, 0 failures).
- `npm --prefix web run build` output is committed under `internal/dashboard/static/dist/`.
- `make backup-restore-test` passes, and a target-storage restore drill has separate evidence.
- Container image is built from the verified tree and includes SBOM/provenance plus a clean vulnerability scan.
- Deployment config validates with real secret values in the target environment; Helm monitor/XoT templates render and apply against installed CRDs.
- DNS, DoH, metrics, health, readiness, liveness, cluster, and dashboard endpoints are smoke-tested after rollout with `scripts/production-smoke.sh`.
- Binary version reports `NothingDNS version 1.0.0` (or the tagged release version).
