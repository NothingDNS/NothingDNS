#!/bin/bash
#
# NothingDNS Update Script
# Updates NothingDNS to the latest version without losing config
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
NC='\033[0m'

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

    info "Detected platform: ${PLATFORM}"
}

# Get latest version
get_latest_version() {
    LATEST_VERSION=$(curl -s https://api.github.com/repos/${REPO}/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
    if [ -z "$LATEST_VERSION" ]; then
        error "Could not fetch latest release version"
    fi
    info "Latest version: ${LATEST_VERSION}"
}

# Get current version
get_current_version() {
    if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        CURRENT_VERSION=$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null | grep -oP 'v?\d+\.\d+\.\d+' | head -1 || echo "unknown")
    else
        CURRENT_VERSION="not installed"
    fi
    info "Current version: ${CURRENT_VERSION}"
}

# Check if update is needed
check_update_needed() {
    if [ "$CURRENT_VERSION" = "v${LATEST_VERSION}" ] || [ "$CURRENT_VERSION" = "${LATEST_VERSION}" ]; then
        info "NothingDNS is already up to date!"
        exit 0
    fi
    info "Update available: ${CURRENT_VERSION} -> ${LATEST_VERSION}"
}

# Stop service
stop_service() {
    info "Stopping NothingDNS service..."
    if command -v systemctl &> /dev/null; then
        sudo systemctl stop nothingdns 2>/dev/null || true
    else
        sudo pkill nothingdns 2>/dev/null || true
    fi
    sleep 2
}

# Download new binary
download_binary() {
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/${BINARY_NAME}-${PLATFORM}"
    info "Downloading from ${DOWNLOAD_URL}..."

    TEMP_FILE=$(mktemp)
    trap "rm -f ${TEMP_FILE}" EXIT

    curl -fsSL -o "${TEMP_FILE}" "${DOWNLOAD_URL}" || error "Download failed"
    chmod +x "${TEMP_FILE}"

    sudo mv "${TEMP_FILE}" "${INSTALL_DIR}/${BINARY_NAME}" || error "Failed to install to ${INSTALL_DIR}"
    info "Updated ${INSTALL_DIR}/${BINARY_NAME}"
}

# Download dnsctl
download_dnsctl() {
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/dnsctl-${PLATFORM}"
    info "Downloading dnsctl..."

    TEMP_FILE=$(mktemp)
    curl -fsSL -o "${TEMP_FILE}" "${DOWNLOAD_URL}" 2>/dev/null || {
        warn "dnsctl download failed, skipping..."
        return
    }
    chmod +x "${TEMP_FILE}"

    sudo mv "${TEMP_FILE}" "${INSTALL_DIR}/dnsctl" 2>/dev/null || warn "Failed to update dnsctl"
    info "Updated dnsctl"
}

# Start service
start_service() {
    info "Starting NothingDNS service..."
    if command -v systemctl &> /dev/null; then
        sudo systemctl start nothingdns
        sleep 2
        if systemctl is-active --quiet nothingdns; then
            info "NothingDNS is running"
        else
            warn "NothingDNS failed to start. Check logs: sudo journalctl -u nothingdns"
        fi
    else
        sudo ${INSTALL_DIR}/${BINARY_NAME} --config ${CONFIG_FILE} &
        sleep 3
        info "NothingDNS started in background"
    fi
}

# Check health
check_health() {
    local max_attempts=10
    local attempt=0

    info "Checking health..."
    while [ $attempt -lt $max_attempts ]; do
        if curl -s --max-time 2 http://localhost:8080/health > /dev/null 2>&1; then
            info "Health check passed!"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    warn "Health check failed. Check logs."
    return 1
}

# Show update summary
show_summary() {
    echo ""
    echo "======================================"
    echo -e "${GREEN}  NothingDNS Updated${NC}"
    echo "======================================"
    echo ""
    echo "Previous version: ${CURRENT_VERSION}"
    echo "New version: ${LATEST_VERSION}"
    echo ""
    echo "Dashboard: http://localhost:8080"
    echo ""
    if command -v systemctl &> /dev/null; then
        echo "Manage service:"
        echo "  sudo systemctl status nothingdns"
        echo "  sudo systemctl restart nothingdns"
    fi
    echo "======================================"
}

# Check if stdin is a terminal
is_interactive() {
    [ -t 0 ]
}

# Main update
main() {
    echo ""
    echo "======================================"
    echo "  NothingDNS Update Script v1.0"
    echo "======================================"
    echo ""

    # Check if installed
    if [ ! -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        error "NothingDNS is not installed. Use install.sh instead."
    fi

    detect_os
    get_latest_version
    get_current_version
    check_update_needed

    # Prompt for update
    if is_interactive; then
        echo ""
        read -p "Proceed with update? (Y/n): " -n 1 -r; echo
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            info "Update cancelled"
            exit 0
        fi
    fi

    stop_service
    download_binary
    download_dnsctl
    start_service
    check_health
    show_summary
}

main "$@"
