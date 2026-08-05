# NothingDNS Operations Runbook

Day-to-day operational procedures for NothingDNS administrators.

## Table of Contents

1. [Daily Operations](#1-daily-operations)
2. [Monitoring](#2-monitoring)
3. [Log Analysis](#3-log-analysis)
4. [Configuration Changes](#4-configuration-changes)
5. [Zone Management](#5-zone-management)
6. [Cluster Operations](#6-cluster-operations)
7. [DNSSEC Operations](#7-dnssec-operations)
8. [Cache Management](#8-cache-management)
9. [Security Operations](#9-security-operations)
10. [Backup & Recovery](#10-backup--recovery)
11. [Troubleshooting](#11-troubleshooting)
12. [Emergency Procedures](#12-emergency-procedures)

---

## 1. Daily Operations

### Morning Checklist

```bash
# 1. Check server health
curl http://localhost:8080/health
# Expected: {"status":"ok"}

# 2. Check cluster status (if enabled)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/cluster/nodes | jq

# 3. Review cache hit ratio
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/cache/stats | jq '.hit_ratio'
# Expected: > 0.80 (80%)

# 4. Check error rates
curl http://localhost:9153/metrics | grep nothingdns_errors_total

# 5. Verify disk usage
df -h /data/nothingdns

# 6. Check dashboard/server metrics
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/dashboard/stats | jq
```

### Server Status Commands

```bash
# Via CLI
dnsctl server status

# Via API
curl http://localhost:8080/api/v1/status | jq

# Via systemd
systemctl status nothingdns

# Check logs
journalctl -u nothingdns --since "today" | tail -50
```

### Query Testing

```bash
# Basic query test
dig @localhost example.com +short

# Test DNSSEC
dig @localhost example.com +dnssec +ad

# Test TCP
dig @localhost example.com +tcp

# Test specific record type
dig @localhost example.com MX

# Test zone transfer
dig @localhost example.com AXFR +tcp
```

---

## 2. Monitoring

### Prometheus Metrics

Available at `http://localhost:9153/metrics` by default (or the configured `metrics.bind` + `metrics.path`).

**Key Metrics**:

```promql
# Query rate
rate(nothingdns_queries_total[5m])

# Cache performance
rate(nothingdns_cache_hits_total[5m]) / rate(nothingdns_cache_queries_total[5m])

# Latency
histogram_quantile(0.99, rate(nothingdns_latency_seconds_bucket[5m]))
histogram_quantile(0.999, rate(nothingdns_latency_seconds_bucket[5m]))

# Error rate
rate(nothingdns_errors_total[5m])

# Cluster sync
rate(nothingdns_cluster_cache_sync_total[5m])
```

### Grafana Dashboard

Use the Prometheus metrics endpoint (`metrics.path`, default `/metrics` on the configured metrics listener) to build or import your Grafana dashboard.

**Dashboard Panels**:
- Query Rate (QPS)
- Cache Hit Ratio
- Latency Percentiles (P50, P90, P99)
- Error Rate
- Upstream Latency
- Memory Usage
- Cluster Node Health

### Alert Configuration

```yaml
# prometheus/alerts/nothingdns.yaml
groups:
  - name: nothingdns
    rules:
      - alert: NothingDNSDown
        expr: up{job="nothingdns"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "NothingDNS instance down"
          description: "NothingDNS has been down for 2 minutes"

      - alert: NothingDNSHighLatency
        expr: histogram_quantile(0.99, rate(nothingdns_latency_seconds_bucket[5m])) > 0.5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "NothingDNS high latency"
          description: "P99 latency is {{ $value }}s"

      - alert: NothingDNSCacheHitRatioLow
        expr: rate(nothingdns_cache_hits_total[5m]) / rate(nothingdns_cache_queries_total[5m]) < 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Cache hit ratio below 50%"

      - alert: NothingDNSHighErrorRate
        expr: rate(nothingdns_errors_total[5m]) > 0.01
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Error rate above 1%"
```

---

## 3. Log Analysis

### Log Locations

```bash
# Systemd journal
journalctl -u nothingdns -f

# File-based logs (if configured)
/var/log/nothingdns/query.log
/var/log/nothingdns/reload.log

# Docker logs
docker logs -f nothingdns

# Kubernetes logs
kubectl logs -l app=nothingdns -f
```

### Log Format

JSON format example:

```json
{
  "level": "info",
  "ts": "2024-05-02T10:30:00Z",
  "msg": "query",
  "qname": "example.com",
  "qtype": "A",
  "client": "192.168.1.100",
  "rcode": "NOERROR",
  "cached": true,
  "latency_ms": 0.5
}
```

### Common Log Patterns

```bash
# Find errors
grep '"level":"error"' /var/log/nothingdns/*.log

# Find SERVFAIL responses
grep '"rcode":"SERVFAIL"' /var/log/nothingdns/*.log

# Find cache misses
grep '"cached":false' /var/log/nothingdns/*.log | head -20

# Find slow queries
grep '"latency_ms":' /var/log/nothingdns/*.log | jq 'select(.latency_ms > 100)' | head

# Find blocklist hits
grep '"blocked":true' /var/log/nothingdns/*.log

# Find cluster events
grep '"type":"cluster"' /var/log/nothingdns/*.log

# Find DNSSEC issues
grep '"dnssec":' /var/log/nothingdns/*.log | grep -v "validation=secure"
```

### Query Analysis

```bash
# Top queried domains
cat /var/log/nothingdns/query.log | jq -r '.qname' | sort | uniq -c | sort -rn | head -20

# Queries by type
cat /var/log/nothingdns/query.log | jq -r '.qtype' | sort | uniq -c | sort -rn

# Queries by client
cat /var/log/nothingdns/query.log | jq -r '.client' | sort | uniq -c | sort -rn | head -20

# Nxdomain rate
cat /var/log/nothingdns/query.log | jq -r '.rcode' | grep -c "NXDOMAIN"

# Cache hit rate from logs
HITS=$(grep -c '"cached":true' /var/log/nothingdns/query.log)
MISSES=$(grep -c '"cached":false' /var/log/nothingdns/query.log)
echo "Cache hits: $HITS, misses: $MISSES, ratio: $(echo "scale=2; $HITS/($HITS+$MISSES)" | bc)"
```

---

## 4. Configuration Changes

### Hot Reload (SIGHUP)

Most configuration changes take effect without restart:

```bash
# Send SIGHUP
kill -HUP $(pidof nothingdns)

# Or via API
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/config/reload

# Verify reload
curl http://localhost:8080/api/v1/config | jq '.logging.level'
```

**What reloads with SIGHUP**:
- Zone files
- Blocklist sources
- RPZ rules
- ACL rules
- Logging level
- Rate limits

**Requires restart**:
- Listen ports
- Cluster configuration
- TLS certificates (can use certificate rotation)
- Worker pool sizes
- Cache size changes

### Safe Config Change Process

```bash
# 1. Backup current config
cp /etc/nothingdns/nothingdns.yaml /etc/nothingdns/nothingdns.yaml.backup

# 2. Create new config
cp /etc/nothingdns/nothingdns.yaml /etc/nothingdns/nothingdns.yaml.new

# 3. Edit new config
vim /etc/nothingdns/nothingdns.yaml.new

# 4. Validate new config
./nothingdns -validate-config -config /etc/nothingdns/nothingdns.yaml.new

# 5. If valid, atomically replace
mv /etc/nothingdns/nothingdns.yaml.new /etc/nothingdns/nothingdns.yaml

# 6. Send SIGHUP to reload
kill -HUP $(pidof nothingdns)

# 7. Verify
curl http://localhost:8080/api/v1/status | jq '.config_hash'
```

---

## 5. Zone Management

### Adding a Zone

```bash
# Via CLI
dnsctl zone add example.com ns1.example.com.

# Via API
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/zones \
  -d '{"name":"example.com.","nameservers":["ns1.example.com."],"admin_email":"admin.example.com.","ttl":3600}'

# Then reload
dnsctl zone reload example.com.
```

### Reloading Zones

```bash
# Via CLI
dnsctl zone reload example.com.

# Via API
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/zones/reload?zone=example.com.

# Manual SIGHUP
kill -HUP $(pidof nothingdns)
```

### Zone Verification

```bash
# Check zone loads
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/zones | jq '.zones[] | select(.name == "example.com.")'

# Test zone resolution
dig @localhost example.com NS +short
dig @localhost example.com SOA +short
dig @localhost www.example.com +short

# Verify DNSSEC (if signed)
dig @localhost example.com DNSKEY +dnssec +ad
dig @localhost example.com DS +dnssec +ad
```

### Zone Transfers

```bash
# Check transfer status
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/zones/transfers | jq

# Slave zones fetch on startup/retry and when a valid NOTIFY arrives.
# Verify that the master serves AXFR:
dig @master-server example.com AXFR +tcp
```

### Dynamic Updates

```bash
# Add record
dnsctl record add example.com api A 192.168.1.50 --ttl=3600

# Update record
dnsctl record update example.com api A 192.168.1.51 --ttl=3600

# Remove record
dnsctl record remove example.com api A

# Via API
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/zones/example.com/records \
  -d '{"name":"api","type":"A","ttl":3600,"rdata":"192.168.1.50"}'
```

---

## 6. Cluster Operations

### Cluster Status

```bash
# Check cluster status
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/cluster/status | jq

# List nodes
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/cluster/nodes | jq

# Node health
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/cluster/nodes/node-1/metrics | jq
```

### Adding a Node

```bash
# On new node, configure seed nodes
cluster:
  enabled: true
  node_id: "node-4"
  seed_nodes:
    - 172.28.0.10:7946
    - 172.28.0.11:7946
  encryption_key: "YOUR_32_BYTE_KEY"

# Start new node
sudo systemctl start nothingdns

# Verify from seed node
sleep 5
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/cluster/nodes | jq '.nodes | length'
```

### Removing a Node

```bash
# Graceful leave (from the node itself)
dnsctl cluster leave

# Or force remove (from any node)
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/cluster/nodes/node-3

# Verify
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/cluster/nodes | jq '.nodes | length'
```

### Cache Invalidation

```bash
# Invalidate specific domain across cluster
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/cache/invalidate \
  -d '{"qname":"example.com","qtype":"A"}'

# Flush entire cache across cluster
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/cache/flush
```

### Network Partition Handling

```bash
# If split-brain detected:
# 1. Check node states
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/cluster/nodes | jq '.nodes[].state'

# 2. Identify partitioned nodes
# State will be "suspected" or "dead"

# 3. For suspected nodes, wait for recovery
# SWIM will automatically heal after 30s

# 4. For dead nodes, remove from cluster
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/cluster/nodes/failed-node

# 5. Add replacement node if needed
```

---

## 7. DNSSEC Operations

### Checking DNSSEC Status

```bash
# DNSSEC status
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/dnssec/status | jq

# Zone signing status
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/dnssec/keys | jq
```

### Signing a Zone

```bash
# Generate keys
dnsctl dnssec generate-key --zone=example.com --ksk --algorithm=ecdsap256sha256
dnsctl dnssec generate-key --zone=example.com --zsk --algorithm=ecdsap256sha256

# Sign zone
dnsctl dnssec sign-zone --zone=example.com --active-keys

# Verify signatures
dnsctl dnssec verify --zone=example.com
```

### DS Record Submission

```bash
# Get DS record
dnsctl dnssec ds-from-dnskey --zone=example.com --digest=sha256

# Output example:
# example.com.  3600  IN  DS  12345 13 2 ABCDEF...

# Submit DS to parent zone registrar
```

### Key Rollover

```bash
# Check key status
dnsctl dnssec key list --zone=example.com

# Pre-publish new ZSK
dnsctl dnssec key generate --zone=example.com --zsk --prepublish

# After 2x signature validity, activate new key
dnsctl dnssec key activate --zone=example.com --key-id=new-zsk-key

# Remove old key after TTL expires
dnsctl dnssec key deactivate --zone=example.com --key-id=old-zsk-key
```

### Troubleshooting DNSSEC

```bash
# Test validation
dig @localhost example.com DNSKEY +dnssec +ad
# If AD bit is set, validation succeeded
# If SERVFAIL, validation failed

# Check for BOGUS status
dig @localhost example.com DS +dnssec
# Look for validation errors in logs
grep -i dnssec /var/log/nothingdns/*.log | tail -20

# Common issues:
# 1. Trust anchor missing
# 2. System time incorrect
# 3. Signature expired
# 4. Algorithm mismatch
```

---

## 8. Cache Management

### Cache Statistics

```bash
# Get cache stats
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/cache/stats | jq

# Output:
# {
#   "hits": 15000,
#   "misses": 1500,
#   "size": 5432,
#   "capacity": 10000,
#   "hit_ratio": 0.91,
#   "evictions": 12,
#   "stale_hits": 45
# }
```

### Cache Flush

```bash
# Flush entire cache
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/cache/flush

# Or via CLI
dnsctl cache flush
```

### Cache Warming

There is no dedicated cache-warm API or `dnsctl` subcommand. To prefill cache entries, issue normal DNS queries for the domains you care about:

```bash
while read -r domain; do
  [ -n "$domain" ] && dig @localhost "$domain" A >/dev/null
done < /etc/nothingdns/popular-domains.txt
```

### Tune Cache TTLs

```yaml
# /etc/nothingdns/nothingdns.yaml
cache:
  min_ttl: 300          # 5 minutes minimum
  max_ttl: 86400         # 24 hours maximum
  default_ttl: 3600      # 1 hour default
  negative_ttl: 60       # 1 minute for NXDOMAIN

# After change, reload
kill -HUP $(pidof nothingdns)
```

---

## 9. Security Operations

### ACL Management

```bash
# Get current ACL
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/acl | jq

# Add rule
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/acl \
  -d '{
    "rules": [
      {"name": "allow-rfc1918-a", "action": "allow", "networks": ["10.0.0.0/8"], "types": ["ANY"]},
      {"name": "allow-rfc1918-b", "action": "allow", "networks": ["172.16.0.0/12"], "types": ["ANY"]},
      {"name": "deny-test-net", "action": "deny", "networks": ["192.0.2.0/24"], "types": ["ANY"]}
    ]
  }'
```

### Rate Limiting

```bash
# Check current limits
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/config | jq '.RRL'

# Update limits
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/config/rrl \
  -d '{"enabled":true,"rate":200,"burst":500}'

# Check RRL stats
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/config/rrl | jq
```

### Blocklist Management

```bash
# List blocklists
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/blocklists | jq

# Add blocklist source
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/blocklists \
  -d '{
    "name": "ads",
    "type": "hosts",
    "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
  }'

# Reload blocklists
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/blocklists/ads/reload

# Remove blocklist
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/blocklists/ads
```

### User Management

```bash
# List users
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/auth/users | jq

# Create user
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/auth/users \
  -d '{"username":"operator","password":"SecurePass123!","role":"operator"}'

# Change password
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/auth/users/operator/password \
  -d '{"password":"NewSecurePass456!"}'

# Delete user
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/auth/users/operator
```

---

## 10. Backup & Recovery

### Recovery objectives

Set these targets in the deployment change record and alert when they are missed:

- **RPO:** 24 hours by default (daily backup). Use hourly snapshots for zones with frequent dynamic updates.
- **RTO:** 60 minutes for a single-node restore; 120 minutes for a three-node cluster rebuild.
- Keep at least one encrypted, immutable copy outside the failure domain (another account/region or offline storage).
- Run `make backup-restore-test` in CI and perform a real restore drill at least quarterly.

### Create and verify a consistent backup

The archive contains the daemon config, the complete zone tree, and all files under `storage.data_dir`. The script fails when the required config is absent, writes atomically, and creates a SHA-256 sidecar. It does **not** make live WAL/KV writes transactionally consistent by itself.

```bash
# 1. Stop the daemon, or take a storage/volume snapshot first.
sudo systemctl stop nothingdns

# 2. Create the archive (defaults shown).
sudo env \
  NOTHINGDNS_CONFIG_FILE=/etc/nothingdns/nothingdns.yaml \
  NOTHINGDNS_ZONES_DIR=/etc/nothingdns/zones \
  NOTHINGDNS_DATA_DIR=/var/lib/nothingdns \
  ./scripts/backup.sh /var/backups/nothingdns

# 3. Verify immediately, then copy both files off-host.
cd /var/backups/nothingdns
sha256sum -c nothingdns-backup-YYYYmmdd_HHMMSS.tar.gz.sha256

# 4. Restart after the snapshot/archive is complete.
sudo systemctl start nothingdns
```

For Kubernetes, quiesce the pod before a `VolumeSnapshot`, snapshot the PVC, and retain the matching ConfigMap/Secret versions. Do not set `NOTHINGDNS_BACKUP_ALLOW_LIVE=1` unless the underlying volume snapshot already guarantees point-in-time consistency.

### Automated backup

```bash
# Daily local archive; the surrounding job must stop/snapshot and restart safely.
0 2 * * * /usr/local/sbin/nothingdns-consistent-backup
```

The wrapper should upload the `.tar.gz` and `.sha256` together to encrypted object storage, apply retention/immutability policy, and alert on any non-zero exit. Local retention defaults to seven archives and is configurable with `NOTHINGDNS_BACKUP_RETENTION`.

### Restore procedure

```bash
# 1. Isolate the node and stop the daemon.
sudo systemctl stop nothingdns

# 2. Verify and restore. Existing targets are never overwritten implicitly.
sudo env NOTHINGDNS_RESTORE_OVERWRITE=1 \
  NOTHINGDNS_CONFIG_FILE=/etc/nothingdns/nothingdns.yaml \
  NOTHINGDNS_ZONES_DIR=/etc/nothingdns/zones \
  NOTHINGDNS_DATA_DIR=/var/lib/nothingdns \
  ./scripts/restore.sh /var/backups/nothingdns/nothingdns-backup-YYYYmmdd_HHMMSS.tar.gz

# 3. Validate before opening traffic.
sudo -u nobody nothingdns \
  -config /etc/nothingdns/nothingdns.yaml \
  -validate-production-config

# 4. Start and run service checks.
sudo systemctl start nothingdns
dnsctl server health
./scripts/production-smoke.sh
```

`restore.sh` verifies SHA-256, rejects traversal/link/special-file archive entries, stages files before replacement, and rolls back a partial install. Keep the generated pre-restore copy until the smoke test is green.

### Cluster disaster recovery

1. Declare the incident, record the last known healthy commit/index, and stop writes/automation.
2. Select the newest backup whose SHA-256 and timestamp meet the RPO; never merge state from multiple backups.
3. Restore one isolated node with cluster joins disabled and validate authoritative zones, DNSSEC material, and API-created state.
4. Start that node as the recovery source, then create fresh peers and join them one at a time.
5. Confirm Raft term/leader/member state and compare zone digests before returning traffic.
6. Run `production-smoke.sh`, verify alerts and backup scheduling, then document actual RPO/RTO and corrective actions.

---

## 11. Troubleshooting

### High CPU Usage

```bash
# Check what's causing
top -p $(pgrep nothingdns)

# Profile CPU
curl http://localhost:8080/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof -http=:8081 cpu.prof

# Common causes:
# 1. DNSSEC signing on high QPS
# 2. Large zone with many records
# 3. Validation loops

# Quick fixes:
# - Disable DNSSEC signing if not needed
# - Reduce logging level
# - Increase cache size
```

### High Memory Usage

```bash
# Check dashboard/server metrics
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/dashboard/stats | jq

# Profile memory
curl http://localhost:8080/debug/pprof/heap > mem.prof
go tool pprof -http=:8081 mem.prof

# Quick fixes:
# - Reduce cache size
# - Disable prefetch
# - Increase memory limit in container
```

### High Latency

```bash
# Check upstream latency
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/upstreams | jq

# Check cache hit ratio
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/cache/stats | jq '.hit_ratio'

# Enable debug logging temporarily
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/config/logging \
  -d '{"level":"debug"}'

# Watch logs
journalctl -u nothingdns -f | grep -i latency
```

### DNS Query Failures

```bash
# Test basic resolution
dig @localhost example.com +tcp

# Check upstream connectivity
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/upstreams | jq '.upstreams[].status'

# Check ACL
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/acl | jq

# Check blocklist
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/blocklists | jq

# Check rate limiting
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/config | jq '.RRL'
```

---

## 12. Emergency Procedures

### Server Won't Start

```bash
# Check config
./nothingdns -validate-config -config /etc/nothingdns/nothingdns.yaml

# Check ports
ss -tulpn | grep :53

# Check permissions
ls -la /usr/local/bin/nothingdns
getcap /usr/local/bin/nothingdns

# Run in foreground
/usr/local/bin/nothingdns -config /etc/nothingdns/nothingdns.yaml
```

### Cluster Split-Brain

```bash
# 1. Identify issue
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/cluster/nodes | jq

# 2. Isolate affected nodes
# 3. Let SWIM heal (automatic after 30s timeout)
# 4. If persistent, manually remove dead nodes
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/cluster/nodes/dead-node

# 5. Restart cluster on affected nodes
sudo systemctl restart nothingdns
```

### Data Corruption

```bash
# If KVStore is corrupted:
# 1. Stop server
sudo systemctl stop nothingdns

# 2. Remove corrupted files
rm /data/nothingdns/*.kv
rm /data/nothingdns/*.wal

# 3. Restart (will rebuild from zones)
sudo systemctl start nothingdns

# 4. Reload any zone that was changed while the server was stopped
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/zones/reload?zone=example.com.

# 5. Verify
curl http://localhost:8080/api/v1/zones | jq
```

### Security Incident

```bash
# 1. Isolate affected node
sudo firewall-cmd --add-rich-rule='rule family="ipv4" source address="ATTACKER_IP" reject'

# 2. Check logs for scope
grep "ATTACKER_IP" /var/log/nothingdns/*.log | wc -l

# 3. Enable strict ACL temporarily
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/acl \
  -d '{"rules":[{"name":"allow-private","action":"allow","networks":["10.0.0.0/8"],"types":["ANY"]},{"name":"deny-ipv4","action":"deny","networks":["0.0.0.0/0"],"types":["ANY"]},{"name":"deny-ipv6","action":"deny","networks":["::/0"],"types":["ANY"]}]}'

# 4. Reset any compromised credentials
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/auth/users/compromised-user

# 5. Generate new API keys
# 6. Document incident
```

### Rollback Procedure

```bash
# Binaries
sudo cp /usr/local/bin/nothingdns.backup /usr/local/bin/nothingdns
sudo systemctl restart nothingdns

# Configuration
sudo cp /etc/nothingdns/nothingdns.yaml.backup /etc/nothingdns/nothingdns.yaml
kill -HUP $(pidof nothingdns)

# Zone files
# Copy backup zones from tar
tar -xzf /var/backups/nothingdns/zones-backup.tar.gz -C /
kill -HUP $(pidof nothingdns)
```

### Emergency Contacts

| Role | Contact |
|------|---------|
| Primary Admin | (configure) |
| On-call | (configure) |
| Security | (configure) |
| Network | (configure) |

### Runbooks

For specific incidents, follow these runbooks:

1. **High QPS Attack**: See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) → RRL section
2. **DNSSEC Validation Failures**: See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) → DNSSEC section
3. **Cluster Failures**: See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) → Cluster section
4. **Memory Exhaustion**: See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) → Memory section
