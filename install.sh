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

    cat > "${CONFIG_FILE}" << 'EOF'
# NothingDNS Configuration
# https://github.com/NothingDNS/NothingDNS

# Server listen address (UDP/TCP DNS)
listen: "0.0.0.0:53"

# HTTP API/Dashboard address
http_addr: "0.0.0.0:8080"

# Data directory
data_dir: "./data"

# Authentication secret (change this!)
# Generate with: openssl rand -base64 32
auth_secret: "CHANGE_ME_generate_with_openssl_rand_base64_32"

# Zones (authoritative)
zones:
  - name: "example.com"
    type: "primary"
    file: "./zones/example.com.zone"

# Upstream resolvers (for recursion)
upstream:
  - "8.8.8.8:53"
  - "8.8.4.4:53"
  - "1.1.1.1:53"

# DNSSEC validation
dnssec:
  enabled: true
  validation: "strict"

# Log level (debug, info, warn, error)
log_level: "info"

# Cache settings
cache:
  size: 10000
  ttl: 300

# DNSSEC signing (for primary zones)
# signing:
#   enabled: true
#   key_dir: "./keys"
EOF

    info "Config created at ${CONFIG_FILE}"
    info "Please edit ${CONFIG_FILE} and set auth_secret!"
}

# Setup service (systemd)
setup_service() {
    if command -v systemctl &> /dev/null; then
        info "Setting up systemd service..."

        SERVICE_FILE="/etc/systemd/system/nothingdns.service"

        cat > /tmp/nothingdns.service << 'EOF'
[Unit]
Description=NothingDNS Authoritative DNS Server
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/nothingdns --config /etc/nothingdns/config.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/nothingdns /var/lib/nothingdns

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
