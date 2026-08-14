#!/bin/bash
#
# NothingDNS Master Setup Script v1.1
# Complete installation, configuration, and management
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nothingdns"
# Canonical config name; legacy installs (pre-v1.0.0) used config.yaml.
CONFIG_FILE="${CONFIG_DIR}/nothingdns.yaml"
if [ ! -f "${CONFIG_FILE}" ] && [ -f "${CONFIG_DIR}/config.yaml" ]; then
    CONFIG_FILE="${CONFIG_DIR}/config.yaml"
fi
DATA_DIR="/var/lib/nothingdns"
BINARY_NAME="nothingdns"
DNSCTL_NAME="dnsctl"
REPO="NothingDNS/NothingDNS"
# Release assets are verified against the published SHA256SUMS by default to stop
# a hijacked/MITM'd release from achieving root code execution. Override only in
# trusted/offline environments: NOTHINGDNS_SKIP_CHECKSUM=1.
SKIP_CHECKSUM="${NOTHINGDNS_SKIP_CHECKSUM:-0}"
CHECKSUMS_FILE=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
section() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

# Check if stdin is a terminal
is_interactive() {
    [ -t 0 ]
}

# Compute the SHA-256 of a file using whichever tool is available.
sha256_of() {
    if command -v sha256sum &> /dev/null; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum &> /dev/null; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo ""
    fi
}

# fatal prints an error and exits — used for integrity failures where continuing
# (chmod +x and run as root) is unsafe. setup.sh's error() does not exit.
fatal() { error "$1"; exit 1; }

# Download the release SHA256SUMS into CHECKSUMS_FILE (fail-closed).
fetch_checksums() {
    if [ "${SKIP_CHECKSUM}" = "1" ]; then
        warn "NOTHINGDNS_SKIP_CHECKSUM=1 — release integrity verification DISABLED"
        return
    fi
    if [ -z "$(sha256_of /dev/null)" ]; then
        fatal "No sha256sum/shasum tool available to verify the release. Install coreutils, or set NOTHINGDNS_SKIP_CHECKSUM=1 to bypass (NOT recommended)."
    fi
    CHECKSUMS_FILE=$(mktemp)
    local url="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/SHA256SUMS"
    curl -fsSL -o "${CHECKSUMS_FILE}" "${url}" || \
        fatal "Could not download release checksums (${url}). Refusing to install unverified binaries; set NOTHINGDNS_SKIP_CHECKSUM=1 to bypass (NOT recommended)."
}

# Verify a downloaded file against the published checksum for the given asset
# name. Fatal on mismatch or missing entry.
verify_checksum() {
    local file="$1" asset="$2"
    if [ "${SKIP_CHECKSUM}" = "1" ]; then
        return
    fi
    local expected
    expected=$(grep -E "[[:space:]][*]?${asset}\$" "${CHECKSUMS_FILE}" | awk '{print $1}' | head -n1)
    [ -n "${expected}" ] || fatal "No checksum entry for ${asset} in SHA256SUMS — refusing to install."
    local actual
    actual=$(sha256_of "${file}")
    if [ "${expected}" != "${actual}" ]; then
        fatal "Checksum mismatch for ${asset}: expected ${expected}, got ${actual}. Aborting — the download may be corrupt or tampered with."
    fi
    info "Verified ${asset} (sha256 ${actual})"
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

    info "Platform: $PLATFORM"
    info "User: $(whoami)"
}

# Check prerequisites
check_prereqs() {
    section "Checking Prerequisites"

    local missing=()

    command -v curl &> /dev/null || missing+=("curl")
    command -v gzip &> /dev/null || missing+=("gzip")

    if [ ${#missing[@} -gt 0 ]; then
        error "Missing required commands: ${missing[*]}"
        info "Install with: sudo apt install ${missing[*]} # Debian/Ubuntu"
        info "         or: sudo yum install ${missing[*]} # RHEL/CentOS"
        return 1
    fi

    info "All prerequisites satisfied"
}

# Get latest release info
get_latest_version() {
    section "Fetching Release Information"
    LATEST_VERSION=$(curl -s https://api.github.com/repos/NothingDNS/NothingDNS/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
    if [ -z "$LATEST_VERSION" ]; then
        error "Could not fetch latest release"
        return 1
    fi
    info "Latest version: ${LATEST_VERSION}"
}

# Download and install binary
download_and_install() {
    section "Downloading and Installing"

    fetch_checksums

    local download_url="https://github.com/NothingDNS/NothingDNS/releases/download/${LATEST_VERSION}/${BINARY_NAME}-${PLATFORM}"
    info "Downloading ${BINARY_NAME} from ${download_url}..."

    local temp_bin=$(mktemp)
    trap "rm -f ${temp_bin} ${CHECKSUMS_FILE}" RETURN

    curl -fsSL -o "${temp_bin}" "${download_url}" || {
        error "Download failed"
        return 1
    }
    verify_checksum "${temp_bin}" "${BINARY_NAME}-${PLATFORM}"
    chmod +x "${temp_bin}"

    if [ -w "${INSTALL_DIR}" ]; then
        mv "${temp_bin}" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        sudo mv "${temp_bin}" "${INSTALL_DIR}/${BINARY_NAME}"
    fi
    info "Installed to ${INSTALL_DIR}/${BINARY_NAME}"

    # Download dnsctl
    local dnsctl_url="https://github.com/NothingDNS/NothingDNS/releases/download/${LATEST_VERSION}/${DNSCTL_NAME}-${PLATFORM}"
    info "Downloading ${DNSCTL_NAME}..."

    local temp_dnsctl=$(mktemp)
    if curl -fsSL -o "${temp_dnsctl}" "${dnsctl_url}" 2>/dev/null; then
        verify_checksum "${temp_dnsctl}" "${DNSCTL_NAME}-${PLATFORM}"
        chmod +x "${temp_dnsctl}"
        if [ -w "${INSTALL_DIR}" ]; then
            mv "${temp_dnsctl}" "${INSTALL_DIR}/${DNSCTL_NAME}"
        else
            sudo mv "${temp_dnsctl}" "${INSTALL_DIR}/${DNSCTL_NAME}"
        fi
        info "Installed ${DNSCTL_NAME} to ${INSTALL_DIR}/${DNSCTL_NAME}"
    else
        warn "dnsctl download failed, skipping..."
    fi
}

# Create directory structure
create_dirs() {
    section "Creating Directory Structure"

    if [ ! -d "${CONFIG_DIR}" ]; then
        if [ -w "$(dirname ${CONFIG_DIR})" ]; then
            mkdir -p "${CONFIG_DIR}/zones" "${CONFIG_DIR}/keys" "${CONFIG_DIR}/tls"
        else
            sudo mkdir -p "${CONFIG_DIR}/zones" "${CONFIG_DIR}/keys" "${CONFIG_DIR}/tls"
        fi
    fi

    if [ ! -d "${DATA_DIR}" ]; then
        if [ -w "$(dirname ${DATA_DIR})" ]; then
            sudo mkdir -p "${DATA_DIR}"
        else
            sudo mkdir -p "${DATA_DIR}"
        fi
    fi

    sudo mkdir -p /var/log/nothingdns

    info "Config directory: ${CONFIG_DIR}"
    info "Data directory: ${DATA_DIR}"
}

# Generate secure secret
generate_secret() {
    if command -v openssl &> /dev/null; then
        openssl rand -base64 32 | head -c 32
    else
        head -c 32 /dev/urandom | base64 | head -c 32
    fi
}

# Create default config
create_config() {
    section "Creating Configuration"

    local config_file="${CONFIG_FILE}"

    if [ -f "${config_file}" ]; then
        warn "Config already exists at ${config_file}"
        if is_interactive; then
            read -p "Overwrite? (y/N): " -n 1 -r; echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                info "Keeping existing config"
                return 0
            fi
        fi
    fi

    local secret=$(generate_secret)

    info "Creating default config..."

    cat > "${config_file}" << EOF
# NothingDNS Configuration
# https://github.com/NothingDNS/NothingDNS
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Version: ${LATEST_VERSION}

server:
  port: 53
  bind:
    - 0.0.0.0
    - "::"
  udp_workers: 0
  tcp_workers: 0
  http:
    enabled: true
    bind: "0.0.0.0:8080"
    auth_secret: "${secret}"

upstream:
  strategy: round_robin
  servers:
    - 1.1.1.1:53
    - 8.8.8.8:53
    - 8.8.4.4:53
  timeout: 5s
  health_check: 30s
  failover_timeout: 5s

cache:
  enabled: true
  size: 10000
  default_ttl: 3600
  max_ttl: 86400
  min_ttl: 300
  negative_ttl: 60
  prefetch: true
  prefetch_threshold: 60
  serve_stale: true
  stale_grace_secs: 86400

dnssec:
  enabled: true

rrl:
  enabled: true
  rate: 100
  burst: 200

cookie:
  enabled: true

logging:
  level: info
  format: json
  output: stdout
  query_log: false
  query_log_file: /var/log/nothingdns/query.log

metrics:
  enabled: true
  bind: ":9153"
  path: /metrics

cluster:
  enabled: false
  gossip_port: 7946
  weight: 100
  cache_sync: true

zones: []
slave_zones: []
transfer:
  allow_list: []
  require_tsig: false
blocklist:
  enabled: false
EOF

    if [ ! -w "${config_file}" ]; then
        sudo chown root:root "${config_file}"
        sudo chmod 600 "${config_file}"
    fi

    info "Config created at ${config_file}"
    info "Auth secret generated - save this for dashboard login!"
}

# Setup systemd service
setup_service() {
    section "Setting Up Systemd Service"

    if ! command -v systemctl &> /dev/null; then
        warn "systemd not found, skipping service setup"
        return 0
    fi

    if [ ! -f "/etc/systemd/system/nothingdns.service" ]; then
        cat > /tmp/nothingdns.service << EOF
[Unit]
Description=NothingDNS Authoritative DNS Server
Documentation=https://github.com/NothingDNS/NothingDNS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/nothingdns --config ${CONFIG_FILE}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
LimitNOFILE=1048576

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/nothingdns /var/lib/nothingdns /var/log/nothingdns
PrivateTmp=true

# Pin stdout/stderr to a file under /var/log/nothingdns so the logrotate
# rule below (which globs /var/log/nothingdns/*.log) actually catches the
# running app's log stream, not just the query log. `append:` (systemd >= 246)
# preserves the file across restarts and matches the audit logger's O_APPEND
# open mode.
StandardOutput=append:/var/log/nothingdns/server.log
StandardError=append:/var/log/nothingdns/server.log
SyslogIdentifier=nothingdns

[Install]
WantedBy=multi-user.target
EOF
        sudo mv /tmp/nothingdns.service /etc/systemd/system/
        sudo systemctl daemon-reload
        info "Service installed"
    else
        info "Service already exists"
    fi

    if is_interactive; then
        read -p "Enable and start nothingdns now? (Y/n): " -n 1 -r; echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            sudo systemctl enable nothingdns
            sudo systemctl restart nothingdns
            sleep 2
            sudo systemctl status nothingdns --no-pager || true
        fi
    fi
}

# Setup log rotation
setup_logging() {
    section "Setting Up Log Rotation"

    if [ -d /etc/logrotate.d ] || [ -w /etc/logrotate.d ]; then
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
        if [ -w /etc/logrotate.d ]; then
            mv /tmp/nothingdns.logrotate /etc/logrotate.d/nothingdns
        else
            sudo mv /tmp/nothingdns.logrotate /etc/logrotate.d/nothingdns
        fi
        sudo mkdir -p /var/log/nothingdns
        sudo chown nobody:nogroup /var/log/nothingdns
        info "Log rotation configured"
    fi
}

# Print next steps
print_next_steps() {
    section "Installation Complete!"

    echo ""
    echo -e "${GREEN}NothingDNS ${LATEST_VERSION} installed successfully!${NC}"
    echo ""
    echo "Next steps:"
    echo ""
    echo -e "${CYAN}1. Configure zones:${NC}"
    echo "   sudo nano ${CONFIG_FILE}"
    echo "   # Add your zones under 'zones:' section"
    echo ""
    echo -e "${CYAN}2. Manage service:${NC}"
    echo "   sudo systemctl start nothingdns   # Start"
    echo "   sudo systemctl stop nothingdns    # Stop"
    echo "   sudo systemctl restart nothingdns # Restart"
    echo "   sudo systemctl status nothingdns  # Status"
    echo ""
    echo -e "${CYAN}3. View logs:${NC}"
    echo "   sudo journalctl -u nothingdns -f   # Live logs"
    echo "   sudo journalctl -u nothingdns --since '1 hour ago'"
    echo ""
    echo -e "${CYAN}4. Check health:${NC}"
    echo "   curl http://localhost:8080/health"
    echo ""
    echo -e "${CYAN}5. Update to new version:${NC}"
    echo "   curl -fsSL https://raw.githubusercontent.com/NothingDNS/NothingDNS/main/update.sh | bash"
    echo ""
    echo -e "${CYAN}Dashboard:${NC}"
    echo "   http://localhost:8080"
    echo ""
    echo "======================================"
}

# Main
main() {
    echo ""
    echo "======================================"
    echo -e "  ${CYAN}NothingDNS Master Setup${NC} v1.1"
    echo "======================================"
    echo ""

    detect_os
    check_prereqs || exit 1
    get_latest_version || exit 1
    download_and_install || exit 1
    create_dirs
    create_config
    setup_service
    setup_logging
    print_next_steps
}

main "$@"
