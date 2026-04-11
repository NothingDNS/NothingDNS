#!/bin/bash
#
# NothingDNS Uninstall Script
# Removes NothingDNS and optionally cleans up configuration
#

set -e

BINARY_NAME="nothingdns"
DNSCTL_NAME="dnsctl"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nothingdns"
DATA_DIR="/var/lib/nothingdns"

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

# Stop service
stop_service() {
    section "Stopping Service"

    if command -v systemctl &> /dev/null; then
        if systemctl is-active --quiet nothingdns 2>/dev/null; then
            info "Stopping nothingdns service..."
            sudo systemctl stop nothingdns
            sudo systemctl disable nothingdns
            sudo rm -f /etc/systemd/system/nothingdns.service
            sudo systemctl daemon-reload
            info "Service stopped and disabled"
        fi
    fi

    # Kill any remaining processes
    if pgrep -f "${BINARY_NAME}" > /dev/null; then
        warn "Killing remaining processes..."
        sudo pkill -f "${BINARY_NAME}" || true
    fi
}

# Remove binaries
remove_binaries() {
    section "Removing Binaries"

    if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        sudo rm -f "${INSTALL_DIR}/${BINARY_NAME}"
        info "Removed ${INSTALL_DIR}/${BINARY_NAME}"
    fi

    if [ -f "${INSTALL_DIR}/${DNSCTL_NAME}" ]; then
        sudo rm -f "${INSTALL_DIR}/${DNSCTL_NAME}"
        info "Removed ${INSTALL_DIR}/${DNSCTL_NAME}"
    fi
}

# Remove config
remove_config() {
    section "Removing Configuration"

    if [ -d "${CONFIG_DIR}" ]; then
        warn "Configuration directory: ${CONFIG_DIR}"
        read -p "Remove config directory? (y/N): " -n 1 -r; echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo rm -rf "${CONFIG_DIR}"
            info "Removed ${CONFIG_DIR}"
        else
            info "Keeping ${CONFIG_DIR}"
        fi
    fi
}

# Remove data
remove_data() {
    section "Removing Data"

    if [ -d "${DATA_DIR}" ]; then
        warn "Data directory: ${DATA_DIR}"
        read -p "Remove data directory? (y/N): " -n 1 -r; echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo rm -rf "${DATA_DIR}"
            info "Removed ${DATA_DIR}"
        else
            info "Keeping ${DATA_DIR}"
        fi
    fi
}

# Remove log rotation
remove_logging() {
    if [ -f /etc/logrotate.d/nothingdns ]; then
        sudo rm -f /etc/logrotate.d/nothingdns
        info "Removed log rotation config"
    fi
}

# Remove logs
remove_logs() {
    if [ -d /var/log/nothingdns ]; then
        sudo rm -rf /var/log/nothingdns
        info "Removed logs"
    fi
}

# Main
main() {
    echo ""
    echo "======================================"
    echo -e "  ${CYAN}NothingDNS Uninstall${NC} v1.0"
    echo "======================================"
    echo ""
    echo -e "${YELLOW}This will remove NothingDNS from your system.${NC}"
    echo ""

    if [ "$(id -u)" -ne 0 ]; then
        warn "Not running as root - some operations may fail"
    fi

    stop_service
    remove_binaries
    remove_logging

    read -p "Remove configuration? (y/N): " -n 1 -r; echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        remove_config
        remove_data
        remove_logs
    fi

    section "Uninstall Complete!"

    echo ""
    echo "NothingDNS has been removed from your system."
    echo ""
    echo -e "${YELLOW}Note:${NC} If you want to completely remove everything including zones,"
    echo "manually remove the following directories:"
    echo "  ${CONFIG_DIR}"
    echo "  ${DATA_DIR}"
    echo "  /var/log/nothingdns"
    echo ""
}

main "$@"
