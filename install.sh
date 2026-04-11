#!/bin/bash
#
# NothingDNS Install Script
# Downloads latest release, creates config, and sets up the server
#

set -e

REPO="NothingDNS/NothingDNS"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nothingdns"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
BINARY_NAME="nothingdns"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Detect OS and architecture
detect_os() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) error "Unsupported architecture: $ARCH" ;;
    esac

    case "$OS" in
        linux) PLATFORM="linux-${ARCH}" ;;
        darwin) PLATFORM="darwin-${ARCH}" ;;
        *) error "Unsupported OS: $OS (only Linux and macOS supported)" ;;
    esac
}

# Get latest release version
get_latest_version() {
    LATEST_VERSION=$(curl -s https://api.github.com/repos/${REPO}/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
    if [ -z "$LATEST_VERSION" ]; then
        error "Could not fetch latest release version"
    fi
    info "Latest version: ${LATEST_VERSION}"
}

# Download binary
download_binary() {
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/${BINARY_NAME}-${PLATFORM}"
    info "Downloading from ${DOWNLOAD_URL}..."

    TEMP_FILE=$(mktemp)
    trap "rm -f ${TEMP_FILE}" EXIT

    curl -fsSL -o "${TEMP_FILE}" "${DOWNLOAD_URL}" || error "Download failed"
    chmod +x "${TEMP_FILE}"

    if [ -d "${INSTALL_DIR}" ]; then
        mv "${TEMP_FILE}" "${INSTALL_DIR}/${BINARY_NAME}" || error "Failed to install to ${INSTALL_DIR}"
        info "Installed to ${INSTALL_DIR}/${BINARY_NAME}"
    else
        sudo mv "${TEMP_FILE}" "${INSTALL_DIR}/${BINARY_NAME}" || error "Failed to install to ${INSTALL_DIR}"
        info "Installed to ${INSTALL_DIR}/${BINARY_NAME}"
    fi
}

# Download dnsctl (CLI tool)
download_dnsctl() {
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/dnsctl-${PLATFORM}"
    info "Downloading dnsctl..."

    TEMP_FILE=$(mktemp)
    curl -fsSL -o "${TEMP_FILE}" "${DOWNLOAD_URL}" 2>/dev/null || {
        warn "dnsctl download failed, skipping..."
        return
    }
    chmod +x "${TEMP_FILE}"

    if [ -d "${INSTALL_DIR}" ]; then
        mv "${TEMP_FILE}" "${INSTALL_DIR}/dnsctl" 2>/dev/null || sudo mv "${TEMP_FILE}" "${INSTALL_DIR}/dnsctl"
        info "Installed dnsctl to ${INSTALL_DIR}/dnsctl"
    else
        sudo mv "${TEMP_FILE}" "${INSTALL_DIR}/dnsctl" 2>/dev/null || mv "${TEMP_FILE}" "${INSTALL_DIR}/dnsctl"
        info "Installed dnsctl to ${INSTALL_DIR}/dnsctl"
    fi
}

# Create default config
create_config() {
    if [ -f "${CONFIG_FILE}" ]; then
        warn "Config already exists at ${CONFIG_FILE}"
        read -p "Overwrite config? (y/N): " -n 1 -r; echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            info "Keeping existing config"
            return
        fi
    fi

    info "Creating default config at ${CONFIG_FILE}..."

    sudo mkdir -p "${CONFIG_DIR}"

    # Generate a random auth secret
    AUTH_SECRET=$(openssl rand -base64 32 2>/dev/null || head -c 32 /dev/urandom | base64)

    cat > "${CONFIG_FILE}" << EOF
# NothingDNS Configuration
# https://github.com/NothingDNS/NothingDNS
# Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

server:
  bind:
    - 0.0.0.0
    - "::"
  port: 53
  udp_workers: 0
  tcp_workers: 0

  tls:
    enabled: false
    cert_file: /etc/nothingdns/tls/server.crt
    key_file: /etc/nothingdns/tls/server.key
    bind: ":853"

  xot:
    enabled: false
    cert_file: /etc/nothingdns/tls/server.crt
    key_file: /etc/nothingdns/tls/server.key
    bind: ":853"

  http:
    enabled: true
    bind: ":8080"
    auth_secret: "${AUTH_SECRET}"
    doh_enabled: true
    doh_path: /dns-query
    dows_enabled: true
    dows_path: /dns-ws

resolution:
  recursive: true
  max_depth: 10
  timeout: 5s
  edns0_buffer_size: 4096

upstream:
  servers:
    - 8.8.8.8:53
    - 8.8.4.4:53
    - 1.1.1.1:53
    - 9.9.9.9:53
  strategy: random
  health_check: 30s
  failover_timeout: 5s

cache:
  enabled: true
  size: 10000
  default_ttl: 300
  max_ttl: 86400
  min_ttl: 5
  negative_ttl: 60
  prefetch: true
  prefetch_threshold: 60

logging:
  level: info
  format: text
  output: stdout
  query_log: true
  query_log_file: /var/log/nothingdns/query.log

metrics:
  enabled: true
  bind: ":9153"
  path: /metrics

dnssec:
  enabled: true

cluster:
  enabled: false
  gossip_port: 7946
  weight: 100
  cache_sync: true

blocklist:
  enabled: false
  files: []
  urls: []

zones: []
acl: []
slave_zones: []
EOF

    info "Config created at ${CONFIG_FILE}"
    info "Auth secret generated. Save this secret for API access:"
    info "  ${AUTH_SECRET}"
}

# Setup service (systemd)
setup_service() {
    # Create necessary directories
    sudo mkdir -p /etc/nothingdns/tls
    sudo mkdir -p /var/log/nothingdns
    sudo mkdir -p /var/lib/nothingdns/zones
    sudo mkdir -p /etc/nothingdns/zones

    if command -v systemctl &> /dev/null; then
        info "Setting up systemd service..."

        SERVICE_FILE="/etc/systemd/system/nothingdns.service"

        cat > /tmp/nothingdns.service << 'EOF'
[Unit]
Description=NothingDNS DNS Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/nothingdns --config /etc/nothingdns/config.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
TimeoutStopSec=30s

# Hardening
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/etc/nothingdns /var/lib/nothingdns /var/log/nothingdns

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nothingdns

[Install]
WantedBy=multi-user.target
EOF

        sudo mv /tmp/nothingdns.service "${SERVICE_FILE}"
        sudo systemctl daemon-reload
        sudo systemctl enable nothingdns
        info "Service installed. Run 'sudo systemctl start nothingdns' to start"
    else
        warn "systemd not found, skipping service setup"
    fi
}

# Check if stdin is a terminal
is_interactive() {
    [ -t 0 ]
}

# Main installation
main() {
    echo ""
    echo "======================================"
    echo "  NothingDNS Install Script v1.0"
    echo "======================================"
    echo ""

    local install_mode=""

    if is_interactive; then
        echo "Choose installation method:"
        echo "  1) Binary (recommended for servers)"
        echo "  2) Docker (GHCR: ghcr.io/nothingdns/nothingdns)"
        echo ""
        read -p "Select [1/2]: " -n 1 -r; echo
        install_mode="$REPLY"
    else
        # Non-interactive (curl | bash) - default to binary
        info "Running in non-interactive mode, selecting binary installation..."
        install_mode="1"
    fi

    if [[ "$install_mode" =~ ^[2]$ ]]; then
        echo ""
        echo "Docker installation selected."
        echo "Run: docker pull ghcr.io/nothingdns/nothingdns:latest"
        echo "Or use docker-compose.yml from the repository"
        exit 0
    fi

    # Check for required commands
    command -v curl &> /dev/null || error "curl is required but not installed"
    command -v gzip &> /dev/null || error "gzip is required but not installed"

    detect_os
    get_latest_version
    download_binary
    download_dnsctl
    create_config
    setup_service

    echo ""
    echo "======================================"
    echo -e "${GREEN}  Installation Complete!${NC}"
    echo "======================================"
    echo ""
    echo "Next steps:"
    echo "  1. Edit config: sudo nano ${CONFIG_FILE}"
    echo "  2. Create zone files in ${CONFIG_DIR}/zones/"
    echo "  3. Start server:"
    echo "       sudo systemctl start nothingdns"
    echo "     or run directly:"
    echo "       sudo ${INSTALL_DIR}/${BINARY_NAME} --config ${CONFIG_FILE}"
    echo ""
    echo "Dashboard: http://localhost:8080"
    echo ""
    echo "Docker alternative:"
    echo "  docker pull ghcr.io/nothingdns/nothingdns:latest"
    echo "======================================"
    echo ""
}

main "$@"
