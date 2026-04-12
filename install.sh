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
SKIP_DOWNLOAD=false
BOOTSTRAP_USER="admin"
BOOTSTRAP_PASS=""
USE_PORT_5353=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check if port 53 is in use and find what's using it
check_port_53() {
    if command -v ss &> /dev/null; then
        PORT_53_USERS=$(ss -tulpn | grep ':53' | grep -v nothingdns || true)
    elif command -v netstat &> /dev/null; then
        PORT_53_USERS=$(netstat -tulpn 2>/dev/null | grep ':53' | grep -v nothingdns || true)
    else
        PORT_53_USERS=""
    fi

    if [ -n "$PORT_53_USERS" ]; then
        echo ""
        warn "Port 53 is already in use!"
        echo "$PORT_53_USERS"
        echo ""
        return 1
    fi
    return 0
}

# Stop and remove existing NothingDNS installation
stop_existing_nothingdns() {
    info "Checking for existing NothingDNS installation..."

    # Stop systemd service if exists
    if systemctl is-active --quiet nothingdns 2>/dev/null; then
        info "Stopping existing NothingDNS service..."
        sudo systemctl stop nothingdns 2>/dev/null || true
    fi

    # Disable service
    if systemctl is-enabled --quiet nothingdns 2>/dev/null; then
        sudo systemctl disable nothingdns 2>/dev/null || true
    fi

    # Remove old binary
    if [ -f /usr/local/bin/nothingdns ]; then
        info "Removing old NothingDNS binary..."
        sudo rm -f /usr/local/bin/nothingdns
    fi

    # Remove old service file
    if [ -f /etc/systemd/system/nothingdns.service ]; then
        info "Removing old systemd service file..."
        sudo rm -f /etc/systemd/system/nothingdns.service
        sudo systemctl daemon-reload
    fi

    info "Existing NothingDNS installation removed"
}

# Try to stop common DNS services
stop_existing_dns() {
    local stopped=false

    # systemd-resolved
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        info "Stopping systemd-resolved..."
        sudo systemctl stop systemd-resolved || true
        sudo systemctl disable systemd-resolved 2>/dev/null || true
        stopped=true
    fi

    # unbound
    if systemctl is-active --quiet unbound 2>/dev/null; then
        info "Stopping unbound..."
        sudo systemctl stop unbound || true
        sudo systemctl disable unbound 2>/dev/null || true
        stopped=true
    fi

    # bind9 / named
    if systemctl is-active --quiet bind9 2>/dev/null; then
        info "Stopping bind9..."
        sudo systemctl stop bind9 || true
        sudo systemctl disable bind9 2>/dev/null || true
        stopped=true
    fi

    # dnsmasq
    if systemctl is-active --quiet dnsmasq 2>/dev/null; then
        info "Stopping dnsmasq..."
        sudo systemctl stop dnsmasq || true
        sudo systemctl disable dnsmasq 2>/dev/null || true
        stopped=true
    fi

    # NetworkManager
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        # Disable DNSSEC in NetworkManager if available
        sudo systemctl restart NetworkManager 2>/dev/null || true
    fi

    if [ "$stopped" = true ]; then
        info "Existing DNS services stopped"
    fi
}

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

# Check if NothingDNS is already installed
check_existing_install() {
    if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        # Extract version number from output like "NothingDNS version 0.1.0" or "v0.1.0"
        local current_version=$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null | grep -oP 'v?\d+\.\d+\.\d+' | head -1 || echo "unknown")
        info "NothingDNS already installed: ${current_version}"
        info "Latest release: ${LATEST_VERSION}"

        if [ "$current_version" = "v${LATEST_VERSION}" ] || [ "$current_version" = "${LATEST_VERSION}" ]; then
            info "NothingDNS is up to date!"
            if is_interactive; then
                echo ""
                echo "  1) Reinstall anyway"
                echo "  2) Skip download (use existing)"
                echo "  3) Exit"
                echo ""
                read -p "Select [2]: " -n 1 -r; echo
                case "$REPLY" in
                    1) info "Reinstalling..." ;;
                    3) info "Nothing to do. Exiting."; exit 0 ;;
                    *) info "Using existing installation."; SKIP_DOWNLOAD=true ;;
                esac
            else
                info "Non-interactive: using existing installation."
                SKIP_DOWNLOAD=true
            fi
        else
            echo ""
            echo "A newer version is available."
            echo "  1) Upgrade to ${LATEST_VERSION}"
            echo "  2) Keep current version"
            echo "  3) Exit"
            echo ""
            if is_interactive; then
                read -p "Select [1]: " -n 1 -r; echo
                case "$REPLY" in
                    2) info "Keeping current version."; SKIP_DOWNLOAD=true ;;
                    3) info "Exiting."; exit 0 ;;
                    *) info "Upgrading to ${LATEST_VERSION}..." ;;
                esac
            else
                info "Non-interactive: upgrading to ${LATEST_VERSION}..."
            fi
        fi
    fi
}

# Download binary
download_binary() {
    if [ "${SKIP_DOWNLOAD}" = true ]; then
        info "Skipping download (using existing installation)"
        return
    fi

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
    if [ "${SKIP_DOWNLOAD}" = true ]; then
        info "Skipping dnsctl download"
        return
    fi

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
    local port="${1:-53}"

    if [ -f "${CONFIG_FILE}" ]; then
        warn "Config already exists at ${CONFIG_FILE}"
        if is_interactive; then
            read -p "Overwrite config? (y/N): " -n 1 -r; echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                info "Keeping existing config"
                # Still apply port change if needed
                if [ "$port" != "53" ]; then
                    info "Applying port change to ${port}..."
                    sed -i "s/port: 53/port: ${port}/" "${CONFIG_FILE}" 2>/dev/null || true
                fi
                return
            fi
        else
            info "Non-interactive: keeping existing config"
            # Still apply port change if needed
            if [ "$port" != "53" ]; then
                info "Applying port change to ${port}..."
                sed -i "s/port: 53/port: ${port}/" "${CONFIG_FILE}" 2>/dev/null || true
            fi
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
  port: ${port}
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

# Create bootstrap user via API
create_bootstrap_user() {
    # Generate random password
    BOOTSTRAP_PASS=$(openssl rand -base64 12 2>/dev/null | tr -d '/+=' | head -c 12)

    # Wait for server to be ready
    local max_attempts=15
    local attempt=0

    info "Waiting for server to start..."
    while [ $attempt -lt $max_attempts ]; do
        if curl -s --max-time 2 http://localhost:8080/health > /dev/null 2>&1; then
            break
        fi
        attempt=$((attempt + 1))
        sleep 1
    done

    if [ $attempt -eq $max_attempts ]; then
        warn "Server did not start in time, skipping bootstrap user creation"
        warn "Generated password (save this): ${BOOTSTRAP_PASS}"
        warn "Start server manually and create user with:"
        warn "curl -X POST http://localhost:8080/api/v1/auth/bootstrap -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"${BOOTSTRAP_PASS}\"}'"
        return
    fi

    # Check if users already exist
    local bootstrap_needed=true
    local users_response
    users_response=$(curl -s -X GET http://localhost:8080/api/v1/auth/users \
        -H "Content-Type: application/json" 2>/dev/null)

    if echo "$users_response" | grep -q "username"; then
        info "Users already exist, skipping bootstrap"
        bootstrap_needed=false
    fi

    if [ "$bootstrap_needed" = true ]; then
        # Create bootstrap user
        local response
        response=$(curl -s -X POST http://localhost:8080/api/v1/auth/bootstrap \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"${BOOTSTRAP_USER}\",\"password\":\"${BOOTSTRAP_PASS}\"}" 2>&1)

        if echo "$response" | grep -q "token"; then
            info "Bootstrap user created successfully"
        else
            warn "Bootstrap response: $response"
            warn "Generated password (save this): ${BOOTSTRAP_PASS}"
            warn "If login fails, create user manually after server starts"
        fi
    fi
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

# Setup log rotation
setup_logrotate() {
    if [ ! -f /etc/logrotate.d/nothingdns ]; then
        info "Setting up log rotation..."
        cat > /tmp/nothingdns.logrotate << 'EOF'
/var/log/nothingdns/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 nobody nogroup
    sharedscripts
    postrotate
        systemctl reload nothingdns > /dev/null 2>&1 || true
    endscript
}
EOF
        sudo mv /tmp/nothingdns.logrotate /etc/logrotate.d/nothingdns
        sudo chown root:root /etc/logrotate.d/nothingdns
        info "Log rotation configured"
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

    # Detect OS and get version BEFORE stopping DNS services
    detect_os
    get_latest_version
    check_existing_install

    # Check if port 53 is available
    if ! check_port_53; then
        if is_interactive; then
            echo ""
            echo "Port 53 is in use by another service."
            echo "  1) Stop existing DNS services (recommended)"
            echo "  2) Use port 5353 instead"
            echo "  3) Exit"
            echo ""
            read -p "Select [1/2/3]: " -n 1 -r; echo
            case "$REPLY" in
                1) stop_existing_dns ;;
                2)
                    info "Using port 5353 instead of 53"
                    USE_PORT_5353=true
                    ;;
                *) error "Installation cancelled" ;;
            esac
        else
            # Non-interactive: auto-stop existing DNS services
            info "Auto-stopping existing DNS services..."
            stop_existing_dns
        fi
    fi

    # Stop and remove existing NothingDNS before installing
    stop_existing_nothingdns

    download_binary
    download_dnsctl

    # Determine port
    local port=53
    if [ "$USE_PORT_5353" = true ]; then
        port=5353
        info "Using port 5353 instead of 53"
    fi

    create_config $port
    setup_service
    setup_logrotate

    # Start the server
    info "Starting NothingDNS..."
    if command -v systemctl &> /dev/null; then
        sudo systemctl start nothingdns
        sleep 2
    else
        sudo ${INSTALL_DIR}/${BINARY_NAME} --config ${CONFIG_FILE} &
        sleep 3
    fi

    # Create bootstrap user
    create_bootstrap_user

    echo ""
    echo "======================================"
    echo -e "${GREEN}  Installation Complete!${NC}"
    echo "======================================"
    echo ""
    echo "Dashboard: http://localhost:8080"
    echo ""
    echo "Login credentials:"
    echo "  Username: ${BOOTSTRAP_USER}"
    echo "  Password: ${BOOTSTRAP_PASS}"
    echo ""
    echo "Edit config: sudo nano ${CONFIG_FILE}"
    echo ""
    echo "Docker alternative:"
    echo "  docker pull ghcr.io/nothingdns/nothingdns:latest"
    echo "======================================"
    echo ""
}

main "$@"
