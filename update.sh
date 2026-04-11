#!/bin/bash
#
# NothingDNS Update Script
# Updates NothingDNS to the latest or specific version
#

set -e

REPO="NothingDNS/NothingDNS"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nothingdns"
BINARY_NAME="nothingdns"
DNSCTL_NAME="dnsctl"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
section() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

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
        *) error "Unsupported OS: $OS" ;;
    esac

    info "Platform: $PLATFORM"
}

# Get current version
get_current_version() {
    if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        CURRENT_VERSION=$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null | grep -o 'v[0-9]*\.[0-9]*\.[0-9]*' | head -1)
    fi
    if [ -z "$CURRENT_VERSION" ]; then
        CURRENT_VERSION="unknown"
    fi
}

# Get latest version
get_latest_version() {
    LATEST_VERSION=$(curl -s https://api.github.com/repos/${REPO}/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
    if [ -z "$LATEST_VERSION" ]; then
        error "Could not fetch latest release"
        return 1
    fi
}

# Stop service
stop_service() {
    if command -v systemctl &> /dev/null; then
        if systemctl is-active --quiet nothingdns 2>/dev/null; then
            info "Stopping nothingdns service..."
            sudo systemctl stop nothingdns
        fi
    elif pgrep -f "${BINARY_NAME}" > /dev/null; then
        info "Stopping nothingdns process..."
        sudo pkill -f "${BINARY_NAME}" || true
    fi
}

# Start service
start_service() {
    if command -v systemctl &> /dev/null; then
        info "Starting nothingdns service..."
        sudo systemctl start nothingdns
    else
        info "Starting nothingdns..."
        sudo "${INSTALL_DIR}/${BINARY_NAME}" --config "${CONFIG_DIR}/config.yaml" &
    fi
}

# Download and install new version
download_and_install() {
    section "Downloading ${LATEST_VERSION}"

    local download_url="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/${BINARY_NAME}-${PLATFORM}"
    info "Downloading from ${download_url}..."

    local temp_bin=$(mktemp)
    trap "rm -f ${temp_bin}" RETURN

    curl -fsSL -o "${temp_bin}" "${download_url}" || {
        error "Download failed"
        return 1
    }
    chmod +x "${temp_bin}"

    # Backup current binary
    if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        local backup="${INSTALL_DIR}/${BINARY_NAME}.backup"
        info "Backing up current binary to ${backup}"
        sudo cp "${INSTALL_DIR}/${BINARY_NAME}" "${backup}"
    fi

    # Install new binary
    sudo mv "${temp_bin}" "${INSTALL_DIR}/${BINARY_NAME}"
    info "Installed new version to ${INSTALL_DIR}/${BINARY_NAME}"

    # Download and update dnsctl
    local dnsctl_url="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/${DNSCTL_NAME}-${PLATFORM}"
    info "Downloading ${DNSCTL_NAME}..."

    local temp_dnsctl=$(mktemp)
    if curl -fsSL -o "${temp_dnsctl}" "${dnsctl_url}" 2>/dev/null; then
        chmod +x "${temp_dnsctl}"
        if [ -f "${INSTALL_DIR}/${DNSCTL_NAME}" ]; then
            sudo cp "${INSTALL_DIR}/${DNSCTL_NAME}" "${INSTALL_DIR}/${DNSCTL_NAME}.backup"
        fi
        sudo mv "${temp_dnsctl}" "${INSTALL_DIR}/${DNSCTL_NAME}"
        info "Updated ${DNSCTL_NAME}"
    fi
}

# Verify installation
verify_installation() {
    section "Verifying Installation"

    local new_version=$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null | grep -o 'v[0-9]*\.[0-9]*\.[0-9]*' | head -1)
    if [ "$new_version" = "$LATEST_VERSION" ]; then
        info "Version verified: ${new_version}"
    else
        warn "Version mismatch: expected ${LATEST_VERSION}, got ${new_version}"
    fi
}

# Rollback
rollback() {
    section "Rolling Back"

    local backup="${INSTALL_DIR}/${BINARY_NAME}.backup"
    if [ -f "${backup}" ]; then
        sudo cp "${backup}" "${INSTALL_DIR}/${BINARY_NAME}"
        info "Rolled back to previous version"
    else
        error "No backup found - cannot rollback"
    fi
}

# Main
main() {
    echo ""
    echo "======================================"
    echo -e "  ${CYAN}NothingDNS Update Script${NC} v1.0"
    echo "======================================"
    echo ""

    detect_os
    get_current_version
    get_latest_version

    info "Current version: ${CURRENT_VERSION}"
    info "Latest version: ${LATEST_VERSION}"

    if [ "$CURRENT_VERSION" = "$LATEST_VERSION" ]; then
        info "Already on latest version!"
        exit 0
    fi

    echo ""
    read -p "Update from ${CURRENT_VERSION} to ${LATEST_VERSION}? (Y/n): " -n 1 -r; echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        info "Update cancelled"
        exit 0
    fi

    stop_service
    download_and_install || { rollback; error "Update failed"; exit 1; }
    verify_installation
    start_service

    section "Update Complete!"

    echo ""
    echo "Updated from ${CURRENT_VERSION} to ${LATEST_VERSION}"
    echo ""
    echo -e "${CYAN}Service status:${NC}"
    if command -v systemctl &> /dev/null; then
        sudo systemctl status nothingdns --no-pager || true
    fi
    echo ""
    echo -e "${YELLOW}To rollback, run:${NC}"
    echo "  sudo cp ${INSTALL_DIR}/${BINARY_NAME}.backup ${INSTALL_DIR}/${BINARY_NAME}"
    echo "  sudo systemctl restart nothingdns"
    echo ""
}

# Handle rollback flag
if [ "$1" = "--rollback" ]; then
    detect_os
    rollback
    exit 0
fi

main "$@"
