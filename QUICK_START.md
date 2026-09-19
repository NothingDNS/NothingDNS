# NothingDNS Quick Start

Get NothingDNS up and running in 5 minutes.

## Prerequisites

- Linux/macOS/Windows with Docker **or**
- Go 1.26.6+ (for building from source)

## Option 1: Docker (Fastest)

```bash
# Download docker-compose.yml (or use the one from this repo)
curl -O https://raw.githubusercontent.com/NothingDNS/NothingDNS/main/docker-compose.yml

# Start NothingDNS (the image ships a working default config)
docker compose up -d

# Test it
dig @127.0.0.1 example.com

# Create the dashboard admin. The bootstrap endpoint only accepts localhost,
# so run it inside the container; the password is read from stdin.
docker exec -i nothingdns dnsctl server bootstrap --username admin
```

That's it! DNS on port 53, dashboard on `http://<host>:8080`. Users, zones
and journals persist in the `nothingdns-data` volume. To use your own config,
mount it over `/etc/nothingdns/nothingdns.yaml` (see `docker-compose.yml`).

## Option 2: Install Script (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/NothingDNS/NothingDNS/main/install.sh | bash
```

The script verifies the release checksums, creates a `nothingdns` system
user, writes `/etc/nothingdns/nothingdns.yaml`, installs and starts a systemd
service, and creates the dashboard admin. The generated password is stored in
the root-only file `/etc/nothingdns/credentials`. If port 53 is taken by
another resolver it falls back to port 5353 (set `NOTHINGDNS_STOP_HOST_DNS=1`
to take over port 53 instead).

Windows: run `install.ps1` from an elevated PowerShell.

## Option 3: Manual Binary Installation

### Download Pre-built Binary

```bash
# Linux amd64
curl -LO https://github.com/NothingDNS/NothingDNS/releases/latest/download/nothingdns-linux-amd64
curl -LO https://github.com/NothingDNS/NothingDNS/releases/latest/download/dnsctl-linux-amd64
curl -LO https://github.com/NothingDNS/NothingDNS/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing

# macOS arm64
curl -LO https://github.com/NothingDNS/NothingDNS/releases/latest/download/nothingdns-darwin-arm64
curl -LO https://github.com/NothingDNS/NothingDNS/releases/latest/download/dnsctl-darwin-arm64

# Give permissions and install (adjust filenames for your OS/arch)
chmod +x nothingdns-linux-amd64 dnsctl-linux-amd64
sudo mv nothingdns-linux-amd64 /usr/local/bin/nothingdns
sudo mv dnsctl-linux-amd64 /usr/local/bin/dnsctl

# Verify
nothingdns -version
dnsctl -version
```

### From Source

```bash
git clone https://github.com/NothingDNS/NothingDNS.git
cd NothingDNS
make build
```

## Configuration

### Minimal Config

Create `/etc/nothingdns/nothingdns.yaml`:

```yaml
server:
  port: 53
  bind:
    - 0.0.0.0

upstream:
  servers:
    - 1.1.1.1:53
    - 8.8.8.8:53

cache:
  size: 10000
```

### Validate Config

```bash
nothingdns -validate-config -config /etc/nothingdns/nothingdns.yaml
```

## Running

### Root Required (Linux)

Port 53 requires root:

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/nothingdns
nothingdns -config /etc/nothingdns/nothingdns.yaml
```

### Or Run as Root (Not Recommended)

```bash
sudo nothingdns -config /etc/nothingdns/nothingdns.yaml
```

### Testing

```bash
# Basic query
dig @localhost example.com

# With DNSSEC
dig @localhost example.com +dnssec

# Check DNSSEC validation
dig @localhost example.com +dnssec +ad

# Query specific record type
dig @localhost mail.example.com MX
dig @localhost example.com AAAA
```

## Web Dashboard

Dashboard available at `http://localhost:8080`:

```yaml
# Add to config for dashboard
server:
  http:
    enabled: true
    bind: "127.0.0.1:8080"    # Use 127.0.0.1 behind a reverse proxy
    auth_secret: "replace-with-32-byte-random-secret"
```

> ⚠️ **Security**: Binding to `0.0.0.0:8080` exposes the dashboard and API to
> every network interface. For production, bind to `127.0.0.1` behind a reverse
> proxy or enable TLS. See [docs/SECURITY.md](docs/SECURITY.md).

Configure `server.http.users` for per-user dashboard login, or use the legacy
`server.http.auth_token` mode for a single shared bearer token.

With no users configured, the server creates a placeholder `admin` account with
a random password that is never shown. Create your admin account from the
server host itself (the endpoint only accepts localhost):

```bash
dnsctl server bootstrap --username admin      # prompts for the password on stdin
# or
curl -X POST http://127.0.0.1:8080/api/v1/auth/bootstrap \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"choose-a-strong-password"}'
```

Then sign in to the dashboard with those credentials. Signing in revokes that
user's earlier tokens, so each login ends the user's other sessions.

Users created this way (or from the dashboard) are stored in
`server.http.users_file`, which defaults to `<storage.data_dir>/users.json`.
Without either setting they live in memory only and are lost on restart.

## Using the CLI

```bash
# Check server status
dnsctl server status

# List zones
dnsctl zone list

# Flush cache
dnsctl cache flush

# Query cache stats
dnsctl cache stats

# Test DNSSEC
dnsctl dig +dnssec example.com A
```

## Docker with Custom Config

```yaml
# docker-compose.yml (Compose v2, no `version:` key needed)
services:
  nothingdns:
    image: ghcr.io/nothingdns/nothingdns:latest
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "8080:8080"
    volumes:
      - ./config.yaml:/etc/nothingdns/nothingdns.yaml:ro
    cap_add:
      - NET_BIND_SERVICE
```

```bash
docker-compose up -d
```

## Kubernetes with Helm

```bash
helm repo add nothingdns https://nothingdns.github.io/helm
helm repo update
helm install my-release nothingdns/nothingdns \
  --set server.port=53 \
  --set upstream.servers[0]=1.1.1.1:53
```

## Common Commands

### Query Types

```bash
dig @localhost example.com A       # IPv4 address
dig @localhost example.com AAAA    # IPv6 address
dig @localhost example.com MX      # Mail servers
dig @localhost example.com TXT     # Text records
dig @localhost example.com NS      # Nameservers
dig @localhost example.com CNAME    # Alias
dig @localhost example.com SOA     # Start of authority
dig @localhost example.com AXFR +tcp # Zone transfer; requires transfer.allow_list (the list also authorizes NOTIFY)
```

### Options

```bash
dig @localhost example.com +short           # Short output
dig @localhost example.com +tcp            # Use TCP
dig @localhost example.com +time=5          # Timeout
dig @localhost example.com +trace          # Trace delegation
dig @localhost -x 1.2.3.4                  # Reverse lookup
```

## API Examples

```bash
# Health check
curl http://localhost:8080/health

# Get stats (requires auth)
TOKEN="your-jwt-token"
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/cache/stats

# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

## Troubleshooting

### Port Already in Use

```bash
# Find what's using port 53
sudo lsof -i :53

# Or use a different port
server:
  port: 5353
```

### Permission Denied

```bash
# Set capabilities
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/nothingdns

# Or run as root
sudo nothingdns
```

### Docker Container Won't Start

```bash
# Check logs
docker-compose logs nothingdns

# The image is FROM scratch (no shell); validate a config with the binary
docker run --rm -v "$PWD/nothingdns.yaml:/etc/nothingdns/nothingdns.yaml:ro" \
  ghcr.io/nothingdns/nothingdns:latest -config /etc/nothingdns/nothingdns.yaml -validate-config
```

## Next Steps

- Read [docs/CONFIG_REFERENCE.md](docs/CONFIG_REFERENCE.md) for all configuration options
- Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) to understand how NothingDNS works
- Read [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for common issues
- Set up [DNSSEC](docs/CONFIG_REFERENCE.md#dnssec) for secure DNS
- Configure [clustering](docs/CONFIG_REFERENCE.md#cluster) for HA
- Enable [metrics](docs/CONFIG_REFERENCE.md#metrics) for monitoring

## Getting Help

```bash
# Built-in help
nothingdns -help
dnsctl -help

# Check logs
journalctl -u nothingdns

# Or in Docker
docker-compose logs -f nothingdns
```

## What's Next?

After getting started:

1. **Configure upstream servers** — Use your preferred DNS upstream
2. **Add your zones** — Point `zones:` to your zone files
3. **Enable DNSSEC** — Sign your zones for security
4. **Set up monitoring** — Enable Prometheus metrics
5. **Configure security** — ACLs, rate limiting, blocklists

Enjoy NothingDNS!
