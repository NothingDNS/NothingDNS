# NothingDNS Troubleshooting Guide

## Table of Contents

1. [Installation Issues](#1-installation-issues)
2. [DNS Resolution Problems](#2-dns-resolution-problems)
3. [DNSSEC Issues](#3-dnssec-issues)
4. [Cluster Problems](#4-cluster-problems)
5. [Performance Issues](#5-performance-issues)
6. [Security Errors](#6-security-errors)
7. [Memory & Resource Issues](#7-memory--resource-issues)
8. [Common Error Messages](#8-common-error-messages)

---

## 1. Installation Issues

### Port 53 Requires Root

**Problem**: `bind: permission denied` when binding to port 53.

**Solution**:
```bash
# Linux: Use setcap
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/nothingdns

# Or run as root (not recommended for production)
sudo ./nothingdns

# Alternative: Use port 5354 for testing
```

### Docker Port Binding Fails

**Problem**: Docker container cannot bind to port 53.

**Solution**:
```yaml
# docker-compose.yml
services:
  nothingdns:
    cap_add:
      - NET_BIND_SERVICE
    # Or run as privileged (not recommended)
    privileged: true
```

### Configuration File Not Found

**Problem**: `open /etc/nothingdns/nothingdns.yaml: no such file or directory`

**Solution**:
```bash
# Use custom config path
./nothingdns -config /path/to/config.yaml

# Or create default location
sudo mkdir -p /etc/nothingdns
sudo cp config.example.yaml /etc/nothingdns/nothingdns.yaml
sudo chmod 644 /etc/nothingdns/nothingdns.yaml
```

### Invalid Configuration

**Problem**: `config validation failed` on startup.

**Solution**:
```bash
# Validate config before running
./nothingdns -validate-config -config /path/to/config.yaml

# Check specific validation errors in logs
./nothingdns -config /path/to/config.yaml 2>&1 | grep -i error
```

### Config Parse Error: "unexpected token COLON"

**Problem**: `parse error: unexpected token COLON at line N` when starting or
validating a config file.

**Diagnosis**: The custom YAML parser interprets `::` (consecutive colons) as a
mapping separator. This happens when an **unquoted IPv6 CIDR** appears in a
value, typically in an ACL `networks` list.

**Examples that fail**:
```yaml
# WRONG — :: interpreted as YAML syntax
networks:
  - ::1/128

# WRONG — unquoted IPv6
networks:
  - 2001:db8::/32
```

**Fix**: Quote IPv6 CIDR values:
```yaml
# RIGHT
networks:
  - "::1/128"
  - "2001:db8::/32"
  - 127.0.0.0/8        # IPv4 works without quotes
```

---

## 2. DNS Resolution Problems

### DNS Queries Timing Out

**Diagnosis**:
```bash
# Check if NothingDNS is running
curl http://localhost:8080/health

# Test DNS resolution directly
dig @localhost example.com

# Check upstream connectivity
curl http://localhost:8080/api/v1/upstreams/status
```

**Common Causes**:
1. **Upstream servers unreachable**: Verify upstream IPs in config
2. **Firewall blocking**: Allow UDP/TCP 53 and HTTP port
3. **Cache full**: Check `cache.size` in config
4. **Rate limiting triggered**: Check logs for RRL suppression

**Solutions**:
```yaml
# config.yaml - increase cache size
cache:
  size: 50000

# config.yaml - check upstream servers
upstream:
  servers:
    - 1.1.1.1:53
    - 8.8.8.8:53
    - 9.9.9.9:53
```

### NXDOMAIN for Valid Domains

**Diagnosis**:
```bash
# Check if zone exists
curl http://localhost:8080/api/v1/zones

# Check blocklist
curl http://localhost:8080/api/v1/blocklist/status

# Check RPZ policies
curl http://localhost:8080/api/v1/rpz/status
```

**Common Causes**:
1. **Zone not loaded**: Ensure zone file path is correct
2. **Blocklist blocking**: Check blocklist sources
3. **RPZ policy**: Verify RPZ zone content
4. **Wrong zone apex**: Ensure SOA/NS records match

### Cache Not Hit

**Diagnosis**:
```bash
# Check cache stats
curl http://localhost:8080/api/v1/cache/stats

# Response format:
# {"hits":100,"misses":50,"size":150,"capacity":10000}
```

**Solutions**:
```yaml
# Ensure cache is enabled
cache:
  size: 10000
  prefetch: true

# Check TTL settings (too low = cache expires fast)
cache:
  min_ttl: 300
  max_ttl: 86400
```

### DNS Amplification Attack Suspected (RRL)

**Problem**: `REFUSED` responses for legitimate queries.

**Diagnosis**:
```bash
# Check RRL logs
grep RRL /var/log/nothingdns/*.log

# Check RRL configuration
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/config | jq '.RRL'
```

**Solution**:
```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/config/rrl \
  -d '{"enabled":true,"rate":1000,"burst":500}'
```

---

## 3. DNSSEC Issues

### DNSSEC Validation Fails

**Diagnosis**:
```bash
# Check DNSSEC status
dig @localhost example.com DNSKEY +dnssec

# Look for AD (Authentic Data) flag
# AD flag present = validated successfully

# Check validator logs
curl http://localhost:8080/api/v1/dnssec/status
```

**Common Causes & Solutions**:

1. **Trust anchor missing**:
   ```yaml
   dnssec:
     # Empty uses the built-in IANA root trust anchor.
     trust_anchor: ""
   ```

2. **System time incorrect**: DNSSEC signatures have time validity
   ```bash
   timedatectl status
   sudo timedatectl set-ntp true
   ```

3. **Invalid signature**:
   ```bash
   # Check for BOGUS status
   dig @localhost example.com DS +dnssec

   # Look for validation errors in logs
   grep -i "dnssec\|bogus\|invalid" /var/log/nothingdns/*.log
   ```

### Zone Signing Errors

**Problem**: `failed to sign zone: key not found`

**Solution**:
```yaml
dnssec:
  signing:
    enabled: true
    # Ensure keys are generated
    keys:
      - private_key: /etc/nothingdns/dnssec/Kexample.com.+013+12345.private
        type: zsk
        algorithm: 13
```

**Generate keys manually**:
```bash
# Using dnsctl
./dnsctl dnssec key generate --zone example.com --ksk
./dnsctl dnssec key generate --zone example.com --zsk
```

### NSEC3 Opt-Out Issues

**Problem**: DNSSEC validation works for signed zones but fails for delegations.

**Solution**:
```yaml
dnssec:
  signing:
    nsec3:
      iterations: 10
      salt: ""
      opt_out: true    # Enable for large delegations
```

---

## 4. Cluster Problems

### Cluster Not Forming

**Diagnosis**:
```bash
# Check cluster status
curl http://localhost:8080/api/v1/cluster/status

# Check node list
curl http://localhost:8080/api/v1/cluster/nodes

# Verify gossip connectivity
grep -i gossip /var/log/nothingdns/*.log
```

**Common Causes**:

1. **Encryption key not set (VULN-005)**:
   ```
   ERROR: cluster: multi-node requires encryption_key
   ```
   **Solution**:
   ```yaml
   cluster:
     encryption_key: "YOUR_32_BYTE_BASE64_ENCODED_KEY"
   # Generate with: openssl rand -base64 32
   ```

2. **Gossip port blocked**:
   ```bash
   # Test connectivity
   nc -zv 172.28.0.10 7946

   # Firewall rules
   sudo firewall-cmd --add-port=7946/tcp --add-port=7946/udp
   ```

3. **Node IDs not unique**:
   ```yaml
   # node-1
   cluster:
     node_id: "node-1"

   # node-2
   cluster:
     node_id: "node-2"
   ```

4. **Seed nodes not reachable**:
   ```yaml
   cluster:
     seed_nodes:
       - 172.28.0.10:7946
       - 172.28.0.11:7946
   ```

### Split-Brain Detection

**Problem**: Cluster reports partition detected.

**Diagnosis**:
```bash
# Check node states
curl http://localhost:8080/api/v1/cluster/nodes | jq '.nodes[].state'

# Check logs for partition evidence
grep -i partition /var/log/nothingdns/*.log
```

**Solution**:
1. Identify network issue between nodes
2. Wait for SWIM to detect recovered nodes
3. If persistent, restart nodes one at a time
4. For Raft mode: check leader election

### Cache Not Syncing

**Diagnosis**:
```bash
# Check cache sync status
curl http://localhost:8080/api/v1/cluster/status | jq '.cache_sync'

# Verify cache invalidation
grep -i "cache.*invalid" /var/log/nothingdns/*.log
```

**Solution**:
```yaml
cluster:
  cache_sync: true
```

---

## 5. Performance Issues

### High Latency

**Diagnosis**:
```bash
# Check latency metrics
curl http://localhost:9153/metrics | grep nothingdns_latency

# Check Prometheus dashboard if enabled
# Look for p99 latency spikes
```

**Common Causes & Solutions**:

1. **Slow upstream**:
   ```yaml
   upstream:
     timeout: 10  # Increase from default 5
     strategy: round_robin  # or weighted/geo
   ```

2. **Cache disabled**:
   ```yaml
   cache:
     enabled: true
     size: 10000
   ```

3. **NSEC aggressive caching disabled**:
   ```yaml
   cache:
     negative_ttl: 60
   ```

4. **Too many zone lookups**:
   - Enable prefetch
   - Increase cache size

### High CPU Usage

**Diagnosis**:
```bash
# Check CPU usage
top -p $(pgrep nothingdns)

# Check if DNSSEC signing is causing load
grep -i "sign\|crypto" /var/log/nothingdns/*.log
```

**Solutions**:
1. **DNSSEC on-the-fly signing is CPU intensive**:
   ```yaml
   # Pre-sign zones instead
   dnssec:
     signing:
       enabled: true
       # Use ECDSA (faster than RSA)
       algorithm: ecdsap256sha256
   ```

2. **Small cache causing frequent lookups**:
   ```yaml
   cache:
     size: 50000  # Increase
     prefetch: true
   ```

3. **Too many worker threads**:
   ```yaml
   server:
     workers:
       udp: 16
       tcp: 8
   ```

### Memory Growing

**Diagnosis**:
```bash
# Check memory usage
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/dashboard/stats

# Check cache size
curl http://localhost:8080/api/v1/cache/stats
```

**Solutions**:
```yaml
cache:
  size: 5000    # Reduce if memory issue
  max_ttl: 3600 # Lower TTL

# Enable memory monitor
memory:
  monitor:
    enabled: true
    threshold: 0.8  # Evict at 80% memory usage
```

---

## 6. Security Errors

### Authentication Failures

**Problem**: `401 Unauthorized` on API calls.

**Solutions**:
```bash
# Check auth mode
curl http://localhost:8080/api/v1/config | jq '.auth.mode'

# For JWT auth, get token
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpassword"}'

# Use token in subsequent requests
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/v1/zones
```

### ACL Blocking Queries

**Problem**: DNS queries returning `REFUSED`.

**Diagnosis**:
```bash
# Check ACL config
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/acl | jq
```

**Solution**:
```yaml
acl:
  - name: allow-private-networks
    action: allow
    networks:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
    # Do NOT add `types: [ANY]` here. `types` narrows the rule to specific
    # QTYPEs, and "ANY" is QTYPE 255 — not a wildcard. A rule carrying it
    # matches no ordinary A/AAAA query, so every client stays refused and this
    # "solution" appears not to work. Omit `types` to match all query types.
```

### Rate Limiting Triggered

**Problem**: `429 Too Many Requests` on API or DNS REFUSED.

**Solution**:
```bash
# Check rate limit status
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/config | jq '.RRL'

# Increase limits
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/config/rrl \
  -d '{"enabled":true,"rate":500,"burst":1000}'
```

---

## 7. Memory & Resource Issues

### OOM (Out of Memory)

**Problem**: NothingDNS killed by OOM killer.

**Solutions**:

1. **Reduce cache size**:
   ```yaml
   cache:
     size: 1000
   ```

2. **Enable memory monitoring**:
   ```yaml
   memory:
     monitor:
       enabled: true
       threshold: 0.8
   ```

3. **Set resource limits in Docker/Kubernetes**:
   ```yaml
   # docker-compose.yml
   deploy:
     resources:
       limits:
         memory: 512M
   ```

### File Descriptor Exhaustion

**Problem**: `too many open files` errors.

**Diagnosis**:
```bash
# Check current limit
ulimit -n

# Check NothingDNS file descriptors
ls /proc/$(pgrep nothingdns)/fd | wc -l
```

**Solution**:
```bash
# Increase system limit
sudo sysctl -w fs.file-max=65536
sudo ulimit -n 65536

# Or in systemd service
[Service]
LimitNOFILE=65536
```

---

## 8. Common Error Messages

| Error Message | Cause | Solution |
|---------------|-------|----------|
| `bind: permission denied` | Port 53 requires root | Use `setcap` or run as root |
| `config validation failed` | Invalid YAML syntax | Run `-validate-config` |
| `multi-node requires encryption_key` | Cluster without encryption | Set `cluster.encryption_key` |
| `zone file not found` | Wrong path in `zones` | Verify zone file paths |
| `SERVFAIL` | Upstream resolution failed | Check upstream servers |
| `REFUSED` | ACL or RRL blocking | Check security settings |
| `BOGUS` | DNSSEC validation failed | Check trust anchors, system time |
| `NXDOMAIN` | Domain blocked by RPZ/blocklist | Check policy settings |
| `BADCOOKIE` | DNS Cookie invalid | Normal retry behavior |
| `架 ` | IDNA validation failed | Check domain name encoding |

---

## Debug Mode

Enable detailed logging:

```yaml
logging:
  level: debug
  format: json
  output: stdout

# Or for specific component debugging
logging:
  level: debug
  format: text
  output: /var/log/nothingdns/debug.log
```

**Key log patterns to search**:
```bash
# Cache operations
grep "cache" /var/log/nothingdns/*.log

# DNSSEC validation
grep "dnssec\|validat\|signature" /var/log/nothingdns/*.log

# Cluster operations
grep "cluster\|gossip\|swim\|raft" /var/log/nothingdns/*.log

# Security events
grep "acl\|rate\|block\|rpz" /var/log/nothingdns/*.log
```

## Getting Help

1. **Check existing issues**: https://github.com/nothingdns/NothingDNS/issues
2. **Check documentation**: https://github.com/nothingdns/NothingDNS/tree/main/docs
3. **Enable debug logging** and collect:
   - Config file (sanitized)
   - Relevant log excerpts
   - Output of `/api/v1/status` and the metrics endpoint (default `http://localhost:9153/metrics`)
4. **For security issues**: See [SECURITY.md](../SECURITY.md)
