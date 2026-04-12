#!/bin/bash
#
# NothingDNS Uninstall Script
# Removes NothingDNS and optionally cleans up config and data
#

set -e

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nothingdns"
BINARY_NAME="nothingdns"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check if NothingDNS is installed
check_installed() {
    if [ ! -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        error "NothingDNS is not installed at ${INSTALL_DIR}/${BINARY_NAME}"
    fi
    info "NothingDNS found at ${INSTALL_DIR}/${BINARY_NAME}"
}

# Stop and disable service
stop_service() {
    if command -v systemctl &> /dev/null; then
        if systemctl is-active --quiet nothingdns 2>/dev/null; then
            info "Stopping NothingDNS service..."
            sudo systemctl stop nothingdns || true
        fi
        if systemctl is-enabled --quiet nothingdns 2>/dev/null; then
            info "Disabling NothingDNS service..."
            sudo systemctl disable nothingdns || true
        fi
        if [ -f /etc/systemd/system/nothingdns.service ]; then
            info "Removing systemd service file..."
            sudo rm -f /etc/systemd/system/nothingdns.service
            sudo systemctl daemon-reload
        fi
    else
        # Kill process if running
        if pgrep -x nothingdns > /dev/null 2>&1; then
            info "Stopping NothingDNS process..."
            sudo pkill nothingdns || true
        fi
    fi
}

# Remove binaries
remove_binaries() {
    info "Removing binaries..."
    sudo rm -f "${INSTALL_DIR}/${BINARY_NAME}"
    sudo rm -f "${INSTALL_DIR}/dnsctl"
    info "Binaries removed from ${INSTALL_DIR}"
}

# Remove log rotation
remove_logrotate() {
    if [ -f /etc/logrotate.d/nothingdns ]; then
        info "Removing log rotation config..."
        sudo rm -f /etc/logrotate.d/nothingdns
    fi
}

# Prompt for config/data removal
prompt_cleanup() {
    local remove_config=false
    local remove_data=false

    if [ -d "${CONFIG_DIR}" ] || [ -f "${CONFIG_FILE}" ]; then
        echo ""
        echo "======================================"
        echo "  Cleanup Options"
        echo "======================================"
        echo ""
        echo "Config directory: ${CONFIG_DIR}"
        ls -la "${CONFIG_DIR}" 2>/dev/null || true
        echo ""

        if is_interactive; then
            read -p "Remove config files? (y/N): " -n 1 -r; echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                remove_config=true
            fi
        fi
    fi

    if [ -d /var/lib/nothingdns ] || [ -d /var/log/nothingdns ]; then
        echo ""
        echo "Data directories:"
        ls -la /var/lib/nothingdns 2>/dev/null || true
        ls -la /var/log/nothingdns 2>/dev/null || true
        echo ""

        if is_interactive; then
            read -p "Remove data and log files? (y/N): " -n 1 -r; echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                remove_data=true
            fi
        fi
    fi

    # Non-interactive: don't remove config/data by default
    if [ "$remove_config" = true ]; then
        info "Removing config files..."
        sudo rm -rf "${CONFIG_DIR}"
    else
        info "Keeping config files (${CONFIG_DIR})"
    fi

    if [ "$remove_data" = true ]; then
        info "Removing data and log files..."
        sudo rm -rf /var/lib/nothingdns /var/log/nothingdns
    else
        info "Keeping data and log files"
    fi
}

# Check if stdin is a terminal
is_interactive() {
    [ -t 0 ]
}

# Show uninstall summary
show_summary() {
    echo ""
    echo "======================================"
    echo -e "${GREEN}  NothingDNS Uninstalled${NC}"
    echo "======================================"
    echo ""
    echo "Removed:"
    echo "  - ${INSTALL_DIR}/${BINARY_NAME}"
    echo "  - ${INSTALL_DIR}/dnsctl"
    echo "  - systemd service"
    echo "  - log rotation config"
    echo ""
    echo "Kept (if exists):"
    echo "  - ${CONFIG_DIR}"
    echo "  - /var/lib/nothingdns"
    echo "  - /var/log/nothingdns"
    echo ""
    echo "To complete removal, manually run:"
    echo "  sudo rm -rf ${CONFIG_DIR}"
    echo "  sudo rm -rf /var/lib/nothingdns /var/log/nothingdns"
    echo "======================================"
}

# Main uninstall
main() {
    echo ""
    echo "======================================"
    echo "  NothingDNS Uninstall Script v1.0"
    echo "======================================"
    echo ""

    check_installed
    stop_service
    remove_binaries
    remove_logrotate
    prompt_cleanup
    show_summary
}

main "$@"
