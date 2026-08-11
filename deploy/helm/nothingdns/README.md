# NothingDNS Helm Chart

A production-grade DNS server with support for all major DNS protocols.

## TL;DR

```bash
helm repo add nothingdns https://nothingdns.github.io/helm
helm install my-release nothingdns/nothingdns \
  --set auth.authSecret="$(openssl rand -base64 32)" \
  --set auth.adminPassword="$(openssl rand -base64 32)"
```

## Introduction

NothingDNS is a zero-dependency DNS server written in pure Go, implementing:
- **Authoritative DNS** with zone management and DNSSEC signing/validation
- **Recursive Resolution** with Qname minimization and 0x20 encoding
- **DNS Security** with DNSSEC, Cookies, ACLs, Rate Limiting, Blocklists, RPZ
- **All Standard Transports**: UDP, TCP, TLS (DoT), HTTPS (DoH), QUIC (DoQ), WebSocket, XoT

## Features

- **21-Stage Request Pipeline** for comprehensive DNS query processing
- **Hot Config Reload** without downtime (SIGHUP)
- **High Availability** with SWIM gossip or Raft consensus
- **Multi-Transport Support**: DoT, DoH, DoQ, XoT, WebSocket
- **Zero External Dependencies** (Go stdlib only)
- **Embedded Dashboard** with real-time stats

## Requirements

- Kubernetes 1.19+
- Helm 3.2.0+

## Installation

### Add Helm Repository

```bash
helm repo add nothingdns https://nothingdns.github.io/helm
helm repo update
```

### Install Chart

```bash
helm install my-release nothingdns/nothingdns \
  --set auth.authSecret="$(openssl rand -base64 32)" \
  --set auth.adminPassword="$(openssl rand -base64 32)"
```

### Configuration

See [NothingDNS Configuration Reference](https://github.com/nothingdns/NothingDNS/blob/main/docs/CONFIG_REFERENCE.md) for all available options.

#### Basic Configuration

```yaml
auth:
  authSecret: "<32+ byte random value>"
  adminPassword: "<admin password>"

config:
  server:
    port: 53
    bind:
      - 0.0.0.0
  http:
    enabled: true
    bind: "0.0.0.0:8080"
  upstream:
    servers:
      - 1.1.1.1:53
      - 8.8.8.8:53
  cache:
    size: 10000
    prefetch: true
```

For pre-created Kubernetes Secrets, set `auth.existingSecret` to a Secret
containing `auth-secret`, `admin-password`, and, when enabled,
`metrics-auth-token`, `storage-encryption-key`, and `cluster-encryption-key`.

### Secret material substitution

The rendered ConfigMap writes secret-backed values as literal
`${NOTHINGDNS_AUTH_SECRET}`, `${NOTHINGDNS_ADMIN_PASSWORD}`,
`${NOTHINGDNS_STORAGE_ENCRYPTION_KEY}`, `${NOTHINGDNS_CLUSTER_ENCRYPTION_KEY}`,
and `${NOTHINGDNS_METRICS_AUTH_TOKEN}` placeholders (depending on which
features are enabled). This is **intentional, not a missing
substitution**: those env vars are wired into the Pod via
`secretKeyRef` (see `templates/deployment.yaml`), and NothingDNS's
custom YAML parser resolves `${VAR}` references at server startup via
`os.LookupEnv` (`internal/config/config.go`). Operators inspecting the
rendered ConfigMap with `kubectl get cm -o yaml` will see the placeholder
strings — that is the source-of-truth design, not a Helm templating bug.
If the env var is unset, the parser logs a warning and substitutes the
empty string, so verify the Secret keys you declared actually map onto
the pod's env vars before treating the deployment as healthy.

#### Production Configuration with DNSSEC

```yaml
auth:
  authSecret: "<32+ byte random value>"
  adminPassword: "<admin password>"

config:
  server:
    port: 53
  http:
    enabled: true
    bind: "0.0.0.0:8080"
    tls_cert_file: /etc/nothingdns/tls/tls.crt
    tls_key_file: /etc/nothingdns/tls/tls.key
    doh_enabled: true
    doh_path: /dns-query
  upstream:
    servers:
      - 1.1.1.1:53
      - 8.8.8.8:53
  dnssec:
    enabled: true
    require_dnssec: false
```

#### High Availability Cluster

```yaml
auth:
  clusterEncryptionKey: "<32+ byte random value>"

config:
  cluster:
    enabled: true
    gossip_port: 7946
    consensus_mode: swim
    cache_sync: true
    seed_nodes:
      - 172.28.0.10:7946
      - 172.28.0.11:7946
```

## Parameters

### General Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `ghcr.io/nothingdns/nothingdns` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `image.tag` | Image tag | `latest` |

### Server Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.server.port` | DNS port | `53` |
| `config.http.enabled` | Enable HTTP API and dashboard | `true` |
| `config.http.bind` | HTTP API / dashboard / DoH bind address | `0.0.0.0:8080` |
| `config.http.doh_enabled` | Enable DoH on the HTTP bind | `false` |
| `service.dotPort` | DNS over TLS service port | `853` |
| `config.xot.enabled` | Enable XoT on a distinct TCP listener | `false` |
| `config.xot.bind` / `service.xotPort` | XoT bind/service port | `:8853` / `8853` |
| `auth.authSecret` | HTTP session signing secret | required when HTTP is enabled |
| `auth.adminPassword` | Default admin password when no explicit users are configured | required when HTTP is enabled |
| `auth.storageEncryptionKey` | Persistent zone DB encryption key | required |

### Upstream Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.upstream.servers` | Upstream DNS servers | `["1.1.1.1:53", "8.8.8.8:53"]` |
| `config.upstream.strategy` | Upstream selection strategy | `round_robin` |
| `config.upstream.health_check` | Upstream health check interval | `30s` |
| `config.upstream.failover_timeout` | Upstream failover timeout | `5s` |

### Cache Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.cache.size` | Maximum cache entries | `10000` |
| `config.cache.default_ttl` | Default TTL (seconds) | `300` |
| `config.cache.max_ttl` | Maximum TTL (seconds) | `86400` |
| `config.cache.min_ttl` | Minimum TTL (seconds) | `0` |
| `config.cache.negative_ttl` | Negative-cache TTL (seconds) | `60` |
| `config.cache.serve_stale` | Serve stale cache entries on upstream failure | `true` |
| `config.cache.stale_grace_secs` | Stale-cache grace period (seconds) | `86400` |
| `config.cache.prefetch` | Enable prefetch | `true` |

### Security Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `auth.existingSecret` | Existing Secret with chart auth keys | `""` |
| `networkPolicy.enabled` | Restrict pod ingress/egress with NetworkPolicy | `true` |
| `securityContext.readOnlyRootFilesystem` | Run container with read-only root filesystem | `true` |
| `securityContext.runAsNonRoot` | Require non-root runtime user | `true` |

### Cluster Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.cluster.enabled` | Enable clustering | `false` |
| `config.cluster.node_id` | Unique node ID; defaults to pod name when empty | `""` |
| `config.cluster.consensus_mode` | SWIM or Raft | `swim` |
| `config.cluster.gossip_port` | Gossip port | `7946` |
| `auth.clusterEncryptionKey` | Cluster encryption key when clustering is enabled | required for cluster |

## Persistence

The chart mounts a PersistentVolumeClaim at `/var/lib/nothingdns` for:
- Cache persistence
- Session storage
- Zone modifications
- WAL journals

| Parameter | Description | Default |
|-----------|-------------|---------|
| `persistence.enabled` | Enable persistence | `true` |
| `persistence.storageClass` | Storage class | `default` |
| `persistence.size` | Volume size | `1Gi` |

## Dashboard

The embedded React dashboard is served at the HTTP port (default: 8080). It provides:
- Real-time query statistics
- Cache hit/miss ratios
- Zone management
- Cluster status
- Log viewer

## Metrics

Prometheus metrics use the dedicated metrics listener configured by
`config.metrics.port` and `config.metrics.path`. When metrics are enabled,
set `auth.metricsAuthToken` or provide `metrics-auth-token` in
`auth.existingSecret`. Enabling `monitoring.serviceMonitor` or
`monitoring.podMonitor` renders Secret-backed scrape authorization; either
monitor fails rendering when `config.metrics.enabled=false`.

### Recommended Prometheus Rules

```yaml
prometheusRule:
  enabled: true
  groups:
    - name: nothingdns
      rules:
        - alert: NothingDNSErrors
          expr: rate(nothingdns_errors_total[5m]) > 0
          for: 5m
          labels:
            severity: warning
          annotations:
            description: NothingDNS error rate is elevated
```

## Security

### Network Policies

The chart includes network policies by default. Update `networkPolicy.enabled` to `false` to disable.

### Security Context

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
    add:
      - NET_BIND_SERVICE
```

## Troubleshooting

### DNS Queries Not Working

1. Check if the server is running:
   ```bash
   kubectl logs -l app.kubernetes.io/name=nothingdns
   ```

2. Verify the service is exposed:
   ```bash
   kubectl get svc -l app.kubernetes.io/name=nothingdns
   ```

3. Test DNS resolution:
   ```bash
   kubectl run -it --rm dns-test --image=busybox --restart=Never -- \
     nslookup kubernetes.default.svc.cluster.local
   ```

### Cluster Not Forming

1. Verify all nodes have unique `node_id` values
2. Check gossip port (default 7946) is accessible
3. Ensure `encryption_key` is set (required for multi-node)
4. Check cluster status via dashboard or API:
   ```bash
   curl http://<node>:8080/api/v1/cluster/status
   ```

### DNSSEC Validation Failing

1. Verify `dnssec.enabled: true` in configuration
2. Check trust anchors are configured correctly
3. Verify system time is correct
4. Check logs for specific validation errors

## Development

### Local Development with Helm

```bash
# Clone repository
git clone https://github.com/nothingdns/NothingDNS.git
cd NothingDNS

# Install dependencies
helm dependency update deploy/helm/nothingdns

# Dry run installation
helm install my-release deploy/helm/nothingdns \
  --dry-run \
  --debug \
  -f deploy/config-node1.yaml
```

### Building the Chart

```bash
helm package deploy/helm/nothingdns
```

## License

Copyright 2024 NothingDNS Authors. Apache License 2.0.
