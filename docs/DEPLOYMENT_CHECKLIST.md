# NothingDNS Deployment Checklist

## Pre-Deployment

### Infrastructure Requirements

- [ ] **CPU**: 2+ cores recommended (4+ for high QPS)
- [ ] **Memory**: 2GB minimum (4GB+ for caching)
- [ ] **Disk**: SSD for KVStore/WAL performance
- [ ] **Network**: Low-latency connectivity to upstream DNS servers

### Port Requirements

| Port | Protocol | Purpose | Required |
|------|----------|---------|----------|
| 53 | UDP/TCP | DNS queries | Yes |
| 53 | TCP | DNS TCP fallback; AXFR only when `transfer.allow_list` permits it | Yes |
| 853 | TCP | DNS over TLS (DoT) | Optional |
| 8080 | TCP | HTTP API + Dashboard + DoH by default | Yes |
| 443 | TCP | External HTTPS/DoH load balancer or ingress | Optional |
| 7946 | UDP/TCP | Cluster gossip | Cluster only |
| 9153 | TCP | Prometheus metrics | Optional |

### Firewall Configuration

```bash
# DNS (required)
sudo firewall-cmd --add-port=53/udp --add-port=53/tcp
sudo firewall-cmd --add-port=853/tcp  # DoT

# API (required for management)
sudo firewall-cmd --add-port=8080/tcp

# Cluster (if multi-node)
sudo firewall-cmd --add-port=7946/udp --add-port=7946/tcp

# Metrics (optional)
sudo firewall-cmd --add-port=9153/tcp
```

## Installation

### 1. Binary Installation

```bash
# Download latest Linux amd64 release artifacts
curl -LO https://github.com/NothingDNS/NothingDNS/releases/latest/download/nothingdns-linux-amd64
curl -LO https://github.com/NothingDNS/NothingDNS/releases/latest/download/dnsctl-linux-amd64
curl -LO https://github.com/NothingDNS/NothingDNS/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing

# Install
chmod +x nothingdns-linux-amd64 dnsctl-linux-amd64
sudo install -m 0755 nothingdns-linux-amd64 /usr/local/bin/nothingdns
sudo install -m 0755 dnsctl-linux-amd64 /usr/local/bin/dnsctl
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/nothingdns

# Verify
nothingdns -version
dnsctl -version
```

### 2. Docker Installation

> **Note:** The GHCR container image is currently published as a **private**
> package. To pull it, you need a GitHub Personal Access Token (PAT) with
> `read:packages` scope. If the package is later made public, the `docker
> login` step can be skipped.
>
> ```bash
> # Create a PAT at: GitHub Settings → Developer settings → Personal access
> # tokens → Fine-grained tokens (or classic) with read:packages scope.
> echo "$GITHUB_TOKEN" | docker login ghcr.io -u USERNAME --password-stdin
> ```

```bash
# Pull image
docker pull ghcr.io/nothingdns/nothingdns:latest

# Or use Docker Compose (see docker-compose.yml)
docker-compose up -d
```

### 3. Kubernetes Installation

```bash
# Add Helm repo
helm repo add nothingdns https://nothingdns.github.io/helm
helm repo update

# Install
helm install my-release nothingdns/nothingdns \
  --set auth.authSecret="$(openssl rand -base64 32)" \
  --set auth.adminPassword="$(openssl rand -base64 32)" \
  --set config.server.port=53 \
  --set config.upstream.servers[0]=1.1.1.1:53 \
  --set config.upstream.servers[1]=8.8.8.8:53
```

### 4. Configuration

- [ ] Copy `config.example.yaml` to `/etc/nothingdns/nothingdns.yaml`
- [ ] Configure bind addresses
- [ ] Set up upstream DNS servers
- [ ] Configure cache settings
- [ ] Enable security features (ACL, rate limiting)

### 5. Directory Setup

```bash
# Create directories
sudo mkdir -p /etc/nothingdns/zones
sudo mkdir -p /etc/nothingdns/tls
sudo mkdir -p /var/log/nothingdns
sudo mkdir -p /var/lib/nothingdns

# Set permissions
sudo chown -R 1000:1000 /etc/nothingdns
sudo chown -R 1000:1000 /var/log/nothingdns
sudo chown -R 1000:1000 /var/lib/nothingdns
```

### 6. Zone File Setup

```bash
# Copy example zones
cp examples/zones/example.com.zone /etc/nothingdns/zones/

# Update config
# zones:
#   - /etc/nothingdns/zones/example.com.zone
```

## Security Hardening

### 1. File Permissions

```bash
# Config file
chmod 600 /etc/nothingdns/nothingdns.yaml

# Zone files
chmod 644 /etc/nothingdns/zones/*.zone

# TLS certificates
chmod 600 /etc/nothingdns/tls/*.key
```

### 2. Enable TLS

```yaml
# /etc/nothingdns/nothingdns.yaml
server:
  http:
    tls_cert_file: /etc/nothingdns/tls/server.crt
    tls_key_file: /etc/nothingdns/tls/server.key
    doh_enabled: true
    doh_path: /dns-query
```

### 3. Configure ACL

```yaml
acl:
  - name: allow-private-networks
    action: allow
    networks:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
    # Omit types to allow all DNS query types. "ANY" only matches QTYPE 255.
```

### 4. Tune Runtime RRL

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/config/rrl \
  -d '{"enabled":true,"rate":100,"burst":200}'
```

### 5. Enable DNSSEC

```yaml
dnssec:
  enabled: true
  # Empty uses the built-in IANA root trust anchor.
  trust_anchor: ""
```

## Monitoring Setup

### 1. Prometheus Metrics

```yaml
metrics:
  enabled: true
  bind: ":9153"
  path: /metrics
  auth_token: "${NOTHINGDNS_METRICS_AUTH_TOKEN}"
```

### 2. Persistent Storage

```yaml
storage:
  data_dir: /var/lib/nothingdns
  encryption_key: "${NOTHINGDNS_STORAGE_ENCRYPTION_KEY}"
```

### 3. Health Checks

```bash
# Liveness probe
curl http://localhost:8080/health

# Readiness probe
curl http://localhost:8080/readyz
```

### 3. Log Rotation

```bash
# /etc/logrotate.d/nothingdns
# Match the rule written by install.sh / setup.sh verbatim. Pin the app's
# stdout/stderr to /var/log/nothingdns/server.log via the systemd unit's
# StandardOutput/StandardError directives so this glob catches real app logs
# and not just the query log.
#
# Note: deploy/nothingdns.service writes the log file with `nobody:nogroup`
# ownership (matching the user/group the systemd unit runs under); the rule
# below recreates rotated files with that same ownership.
/var/log/nothingdns/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    missingok
    create 0644 nobody nogroup
    sharedscripts
    postrotate
        systemctl reload nothingdns > /dev/null 2>&1 || true
    endscript
}
```

## Pre-Launch Validation

### 1. Configuration Validation

```bash
export NOTHINGDNS_AUTH_SECRET="$(openssl rand -base64 32)"
export NOTHINGDNS_ADMIN_PASSWORD="$(openssl rand -base64 32)"
export NOTHINGDNS_OPERATOR_PASSWORD="$(openssl rand -base64 32)"
export NOTHINGDNS_VIEWER_PASSWORD="$(openssl rand -base64 32)"
export NOTHINGDNS_METRICS_AUTH_TOKEN="$(openssl rand -base64 32)"
export NOTHINGDNS_STORAGE_ENCRYPTION_KEY="$(openssl rand -hex 32)"
export NOTHINGDNS_CLUSTER_ENCRYPTION_KEY="$(openssl rand -base64 32)"
export NOTHINGDNS_CLUSTER_SNAPSHOT_ENCRYPTION_KEY="$(openssl rand -hex 32)"

./nothingdns -validate-production-config -config /etc/nothingdns/nothingdns.yaml
```

### 2. Test DNS Resolution

```bash
# Test basic query
dig @localhost example.com

# Test with DNSSEC
dig @localhost example.com +dnssec

# Test TCP
dig @localhost example.com +tcp

# Test zone transfer only after transfer.allow_list permits this client
dig @localhost example.com AXFR +tcp
```

### 3. Check Logs

```bash
# Look for errors
journalctl -u nothingdns --no-pager -n 50

# Watch live logs
tail -f /var/log/nothingdns/*.log
```

### 4. Verify Ports

```bash
# Check listening ports
ss -tulpn | grep nothingdns
```

## Launch

### 1. Systemd Service

```bash
# Copy service file
sudo cp deploy/nothingdns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable nothingdns
sudo systemctl start nothingdns

# Check status
sudo systemctl status nothingdns
```

### 2. Docker Launch

```bash
docker run -d \
  --name nothingdns \
  --cap-add NET_BIND_SERVICE \
  -p 53:53/udp -p 53:53/tcp \
  -p 853:853/tcp \
  -p 8080:8080 \
  -p 9153:9153 \
  -v /etc/nothingdns:/etc/nothingdns:ro \
  -v /var/lib/nothingdns:/var/lib/nothingdns \
  ghcr.io/nothingdns/nothingdns:latest
```

## Post-Launch Verification

### 1. DNS Tests

```bash
# Query from localhost
dig @localhost example.com +short

# Query from external
dig @your-dns-server.com example.com +short

# Test DNSSEC validation
dig @localhost wikipedia.org A +dnssec

# Test DoH
curl -H 'accept: application/dns-json' 'https://localhost:8080/dns-query?name=example.com&type=A'
```

### 2. API Tests

```bash
# Health check
curl http://localhost:8080/health

# Get stats
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/cache/stats

# Check metrics
curl -H "Authorization: Bearer $NOTHINGDNS_METRICS_AUTH_TOKEN" \
  http://localhost:9153/metrics | grep nothingdns_
```

### 3. Supply Chain Verification

```bash
# Verify keyless signature on published image digest
cosign verify ghcr.io/nothingdns/nothingdns@sha256:<digest> \
  --certificate-identity-regexp 'https://github.com/.*/.github/workflows/container.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Inspect SBOM/provenance attestations
cosign verify-attestation ghcr.io/nothingdns/nothingdns@sha256:<digest> \
  --type slsaprovenance \
  --certificate-identity-regexp 'https://github.com/.*/.github/workflows/container.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### 3. Load Testing (Optional)

```bash
# Using dnsperf or similar
dnsperf -s localhost -d query.txt -c 100 -T 10
```

## Cluster Setup (Multi-Node)

### 1. First Node (Seed)

```yaml
cluster:
  enabled: true
  node_id: "node-1"
  bind_addr: "0.0.0.0"
  gossip_port: 7946
  consensus_mode: "swim"
  encryption_key: "${NOTHINGDNS_CLUSTER_ENCRYPTION_KEY}"
  cache_sync: true
  seed_nodes: []
```

### 2. Additional Nodes

```yaml
cluster:
  enabled: true
  node_id: "node-2"
  bind_addr: "0.0.0.0"
  gossip_port: 7946
  consensus_mode: "swim"
  encryption_key: "${NOTHINGDNS_CLUSTER_ENCRYPTION_KEY}"
  cache_sync: true
  seed_nodes:
    - 172.28.0.10:7946
```

### 3. Verify Cluster

```bash
curl http://localhost:8080/api/v1/cluster/status
curl http://localhost:8080/api/v1/cluster/nodes
```

## Rollback Plan

### 1. Keep Previous Binary

```bash
# Before upgrade, backup current binary
sudo cp /usr/local/bin/nothingdns /usr/local/bin/nothingdns.backup
```

### 2. Quick Rollback

```bash
# Stop service
sudo systemctl stop nothingdns

# Restore previous binary
sudo cp /usr/local/bin/nothingdns.backup /usr/local/bin/nothingdns

# Restart
sudo systemctl start nothingdns
```

### 3. Docker Rollback

```bash
# Stop and remove
docker stop nothingdns
docker rm nothingdns

# Pull previous version
docker pull ghcr.io/nothingdns/nothingdns:v0.x.x

# Start with previous version
docker run ...
```

## Documentation Handoff

- [ ] Update runbook with NothingDNS specifics
- [ ] Document custom RPZ rules
- [ ] Document cluster node IPs
- [ ] Document escalation contacts
- [ ] Test failover procedures
