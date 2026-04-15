# NothingDNS Helm Chart

A production-grade DNS server with comprehensive protocol support.

## Prerequisites

- Kubernetes 1.21+
- Helm 3.8.0+
- PV provisioner support in the underlying infrastructure (for persistence)

## Installing the Chart

```bash
# Add the repository (when published)
helm repo add nothingdns https://charts.nothingdns.io
helm repo update

# Install the chart
helm install my-dns nothingdns/nothingdns

# Or install from local source
helm install my-dns ./deploy/helm/nothingdns
```

## Uninstalling the Chart

```bash
helm uninstall my-dns
```

## Configuration

See [values.yaml](values.yaml) for the full list of configurable parameters.

### Key Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `nothingdns/nothingdns` |
| `image.tag` | Image tag | `""` (uses chart appVersion) |
| `service.type` | Service type | `LoadBalancer` |
| `persistence.enabled` | Enable persistent storage | `true` |
| `persistence.size` | Storage size | `10Gi` |
| `config.cache.enabled` | Enable DNS caching | `true` |
| `config.rate_limit.enabled` | Enable rate limiting | `true` |
| `config.dnssec.enabled` | Enable DNSSEC validation | `true` |

### Example: Basic Installation

```yaml
# values-basic.yaml
config:
  upstream:
    servers:
      - "1.1.1.1:53"
      - "8.8.8.8:53"
  
  rate_limit:
    enabled: true
    rate: 10
    burst: 50
```

```bash
helm install my-dns ./deploy/helm/nothingdns -f values-basic.yaml
```

### Example: High Availability

```yaml
# values-ha.yaml
replicaCount: 3

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10

pdb:
  enabled: true
  minAvailable: 2

config:
  cluster:
    enabled: true
    peers:
      - "nothingdns-0.nothingdns-headless:7946"
      - "nothingdns-1.nothingdns-headless:7946"
      - "nothingdns-2.nothingdns-headless:7946"
```

### Example: DoH with Ingress

```yaml
# values-doh.yaml
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: dns.example.com
      paths:
        - path: /dns-query
          pathType: Prefix
          servicePort: 443
        - path: /api
          pathType: Prefix
          servicePort: 8080
  tls:
    - secretName: nothingdns-tls
      hosts:
        - dns.example.com

config:
  server:
    tls:
      cert_file: /etc/nothingdns/tls/tls.crt
      key_file: /etc/nothingdns/tls/tls.key
```

### Example: Blocklist Configuration

```yaml
# values-blocklist.yaml
config:
  blocklist:
    enabled: true
    urls:
      - "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    files:
      - "/var/lib/nothingdns/custom-blocklist.txt"
```

### Example: Zone Transfer (AXFR/XoT)

```yaml
# values-xot.yaml
config:
  zone_transfer:
    enabled: true
    allow_list:
      - "192.168.1.0/24"
      - "10.0.0.0/8"
    require_tsig: true

  xot:
    enabled: true
    port: 853
    allowed_networks:
      - "192.168.1.0/24"
```

## Persistence

The chart mounts a Persistent Volume by default. To disable persistence:

```yaml
persistence:
  enabled: false
```

## Monitoring

### Prometheus ServiceMonitor

```yaml
monitoring:
  serviceMonitor:
    enabled: true
    namespace: monitoring
```

### Prometheus Rules (Alerts)

```yaml
monitoring:
  prometheusRule:
    enabled: true
    namespace: monitoring
```

## Upgrading

```bash
# Upgrade the release
helm upgrade my-dns ./deploy/helm/nothingdns

# Upgrade with new values
helm upgrade my-dns ./deploy/helm/nothingdns -f new-values.yaml
```

## Troubleshooting

### Check Pod Status

```bash
kubectl get pods -l app.kubernetes.io/name=nothingdns
```

### View Logs

```bash
kubectl logs -l app.kubernetes.io/name=nothingdns --tail=100
```

### Test DNS Resolution

```bash
# Get service IP
kubectl get svc my-dns-dns

# Test with dig
dig @<SERVICE_IP> example.com
```

### Configuration Reload

The server supports hot configuration reload via SIGHUP:

```bash
kubectl exec deployment/my-dns -- kill -HUP 1
```

## Development

### Lint the Chart

```bash
helm lint ./deploy/helm/nothingdns
```

### Template Rendering

```bash
helm template my-dns ./deploy/helm/nothingdns
```

### Dry Run

```bash
helm install --dry-run --debug my-dns ./deploy/helm/nothingdns
```

## License

Apache 2.0 - see [LICENSE](../../LICENSE)
