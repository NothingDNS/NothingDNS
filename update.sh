#!/bin/bash
#
# NothingDNS Update Script v1.1
# Updates NothingDNS to the latest version without losing config
#

set -e

REPO="NothingDNS/NothingDNS"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nothingdns"
# Canonical config name; legacy installs (pre-v1.0.0) used config.yaml.
CONFIG_FILE="${CONFIG_DIR}/nothingdns.yaml"
if [ ! -f "${CONFIG_FILE}" ] && [ -f "${CONFIG_DIR}/config.yaml" ]; then
    CONFIG_FILE="${CONFIG_DIR}/config.yaml"
fi
BINARY_NAME="nothingdns"
DNSCTL_NAME="dnsctl"
# Release assets are verified against the published SHA256SUMS (same control as
# install.sh). Override only in trusted/offline environments.
SKIP_CHECKSUM="${NOTHINGDNS_SKIP_CHECKSUM:-0}"
CHECKSUMS_FILE=""
TEMP_FILES=()
cleanup() { rm -f "${TEMP_FILES[@]}"; }
trap cleanup EXIT

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check if stdin is a terminal
is_interactive() {
    [ -t 0 ]
}

sha256_of() {
    if command -v sha256sum &> /dev/null; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum &> /dev/null; then
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Download the release SHA256SUMS (fail-closed).
fetch_checksums() {
    if [ "${SKIP_CHECKSUM}" = "1" ]; then
        warn "NOTHINGDNS_SKIP_CHECKSUM=1 — release integrity verification DISABLED"
        return
    fi
    [ -n "$(sha256_of /dev/null)" ] || error "No sha256sum/shasum tool available to verify the release (set NOTHINGDNS_SKIP_CHECKSUM=1 to bypass, NOT recommended)."
    CHECKSUMS_FILE=$(mktemp)
    TEMP_FILES+=("${CHECKSUMS_FILE}")
    local url="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/SHA256SUMS"
    curl -fsSL -o "${CHECKSUMS_FILE}" "${url}" || error "Could not download release checksums (${url}); refusing to install unverified binaries."
}

verify_checksum() {
    local file="$1" asset="$2"
    [ "${SKIP_CHECKSUM}" = "1" ] && return
    local expected actual
    expected=$(grep -E "[[:space:]][*]?${asset}\$" "${CHECKSUMS_FILE}" | awk '{print $1}' | head -n1)
    [ -n "${expected}" ] || error "No checksum entry for ${asset} in SHA256SUMS — refusing to install."
    actual=$(sha256_of "${file}")
    [ "${expected}" = "${actual}" ] || error "Checksum mismatch for ${asset}: expected ${expected}, got ${actual}."
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
        CURRENT_VERSION=$("${INSTALL_DIR}/${BINARY_NAME}" -version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        CURRENT_VERSION="${CURRENT_VERSION:-unknown}"
    else
        CURRENT_VERSION="not installed"
    fi
    info "Current version: ${CURRENT_VERSION}"
}

# Check if update is needed
check_update_needed() {
    # Release tags carry a "v" prefix; the binary reports bare semver.
    if [ "${CURRENT_VERSION}" = "${LATEST_VERSION#v}" ]; then
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

    NEW_BINARY=$(mktemp)
    TEMP_FILES+=("${NEW_BINARY}")
    curl -fsSL -o "${NEW_BINARY}" "${DOWNLOAD_URL}" || error "Download failed"
    verify_checksum "${NEW_BINARY}" "${BINARY_NAME}-${PLATFORM}"
    chmod +x "${NEW_BINARY}"

    # Refuse to swap in a binary that rejects the current config: the service
    # would stay down after the update.
    if [ -f "${CONFIG_FILE}" ] && ! sudo "${NEW_BINARY}" -config "${CONFIG_FILE}" -validate-config; then
        error "The new version rejects ${CONFIG_FILE}; fix the config first. Nothing was changed."
    fi
}

install_binary() {
    sudo install -m 0755 "${NEW_BINARY}" "${INSTALL_DIR}/${BINARY_NAME}" || error "Failed to install to ${INSTALL_DIR}"
    info "Updated ${INSTALL_DIR}/${BINARY_NAME}"
}

# Download dnsctl
download_dnsctl() {
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/${DNSCTL_NAME}-${PLATFORM}"
    info "Downloading dnsctl..."

    local tmp
    tmp=$(mktemp)
    TEMP_FILES+=("${tmp}")
    curl -fsSL -o "${tmp}" "${DOWNLOAD_URL}" 2>/dev/null || {
        warn "dnsctl download failed, skipping..."
        return
    }
    verify_checksum "${tmp}" "${DNSCTL_NAME}-${PLATFORM}"
    sudo install -m 0755 "${tmp}" "${INSTALL_DIR}/${DNSCTL_NAME}" || { warn "Failed to update dnsctl"; return; }
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
            warn "NothingDNS failed to start. Recent log:"
            sudo journalctl -u nothingdns -n 30 --no-pager 2>/dev/null || true
        fi
    else
        sudo "${INSTALL_DIR}/${BINARY_NAME}" -config "${CONFIG_FILE}" &
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
        if curl -s --max-time 2 http://127.0.0.1:8080/health > /dev/null 2>&1; then
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

# Main update
main() {
    echo ""
    echo "======================================"
    echo "  NothingDNS Update Script v1.1"
    echo "======================================"
    echo ""

    # Check if installed
    if [ ! -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        error "NothingDNS is not installed. Use install.sh or setup.sh instead."
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

    fetch_checksums
    download_binary
    stop_service
    install_binary
    download_dnsctl
    start_service
    check_health
    show_summary
}

main "$@"