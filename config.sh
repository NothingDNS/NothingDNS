#!/bin/bash
#
# NothingDNS Config Management Script
# Validates, edits, and manages NothingDNS configuration
#

set -e

CONFIG_DIR="/etc/nothingdns"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
BINARY_NAME="nothingdns"
EDITOR="${EDITOR:-nano}"

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

# Check if config exists
check_config() {
    if [ ! -f "${CONFIG_FILE}" ]; then
        error "Config not found at ${CONFIG_FILE}"
        info "Run setup.sh first to create config"
        return 1
    fi
}

# Validate YAML syntax
validate_yaml() {
    section "Validating Configuration"

    if ! command -v python3 &> /dev/null; then
        warn "python3 not found, skipping YAML validation"
        return 0
    fi

    if python3 -c "import yaml; yaml.safe_load(open('${CONFIG_FILE}'))" 2>/dev/null; then
        info "YAML syntax is valid"
        return 0
    else
        error "YAML syntax error in config file"
        return 1
    fi
}

# Validate config with nothingdns
validate_config() {
    section "Validating with NothingDNS"

    if ! command -v "${BINARY_NAME}" &> /dev/null; then
        if [ ! -f "/usr/local/bin/${BINARY_NAME}" ]; then
            warn "nothingdns not found, skipping binary validation"
            return 0
        fi
    fi

    if /usr/local/bin/${BINARY_NAME} --config "${CONFIG_FILE}" --validate 2>/dev/null; then
        info "Config is valid"
        return 0
    else
        warn "Config validation failed - check syntax and restart"
        return 1
    fi
}

# Edit config
edit_config() {
    check_config || return 1

    section "Editing Configuration"

    if [ ! -w "${CONFIG_FILE}" ]; then
        info "Using sudo to edit config..."
        sudo "${EDITOR}" "${CONFIG_FILE}"
    else
        "${EDITOR}" "${CONFIG_FILE}"
    fi
}

# Show config
show_config() {
    check_config || return 1

    section "Current Configuration"

    echo ""
    if command -v bat &> /dev/null; then
        bat "${CONFIG_FILE}" --language yaml 2>/dev/null || cat "${CONFIG_FILE}"
    else
        cat "${CONFIG_FILE}"
    fi
    echo ""
}

# Backup config
backup_config() {
    check_config || return 1

    section "Backing Up Configuration"

    local backup="${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    cp "${CONFIG_FILE}" "${backup}"
    info "Backed up to ${backup}"
}

# Restore config
restore_config() {
    section "Restoring Configuration"

    local backups=($(ls -t "${CONFIG_FILE}.backup."* 2>/dev/null | head -5))

    if [ ${#backups[@]} -eq 0 ]; then
        error "No backups found"
        return 1
    fi

    echo "Available backups:"
    select backup in "${backups[@]}" "Cancel"; do
        if [ "$backup" = "Cancel" ]; then
            info "Restore cancelled"
            return 0
        fi
        if [ -n "$backup" ]; then
            cp "${backup}" "${CONFIG_FILE}"
            info "Restored from ${backup}"
            break
        fi
    done
}

# Diff config
diff_config() {
    check_config || return 1

    section "Comparing Config Versions"

    local backups=($(ls -t "${CONFIG_FILE}.backup."* 2>/dev/null | head -2))

    if [ ${#backups[@]} -lt 2 ]; then
        error "Need at least 2 backups to compare"
        return 1
    fi

    if command -v diff &> /dev/null; then
        diff -u "${backups[1]}" "${backups[0]}" || true
    else
        warn "diff not available"
    fi
}

# Add zone
add_zone() {
    check_config || return 1

    section "Adding Zone"

    read -p "Zone name (e.g., example.com): " zone_name

    if [ -z "$zone_name" ]; then
        error "Zone name required"
        return 1
    fi

    local zone_file="${CONFIG_DIR}/zones/${zone_name}.zone"

    if [ -f "$zone_file" ]; then
        warn "Zone file already exists at ${zone_file}"
    else
        cat > "$zone_file" << EOF
\$ORIGIN ${zone_name}.
\$TTL 3600

@   IN  SOA ns1.${zone_name}. admin.${zone_name}. (
            $(date +%Y%m%d)01  ; Serial
            3600        ; Refresh
            1800        ; Retry
            604800      ; Expire
            86400 )     ; Minimum TTL

@   IN  NS      ns1.${zone_name}.
@   IN  A       192.0.2.1
www IN  A       192.0.2.2
EOF
        info "Created zone file at ${zone_file}"
    fi

    # Add to config
    if grep -q "zones:" "${CONFIG_FILE}"; then
        if grep -q "^zones: \[\]$\|^- name:" "${CONFIG_FILE}"; then
            # zones array is empty or has entries - need to modify
            info "Zone file created. Manually add to config zones section:"
            echo "  - name: \"${zone_name}\""
            echo "    type: \"primary\""
            echo "    file: \"${zone_file}\""
        fi
    fi
}

# Reload config
reload_config() {
    section "Reloading Configuration"

    if command -v systemctl &> /dev/null; then
        if systemctl is-active --quiet nothingdns 2>/dev/null; then
            info "Sending SIGHUP to reload config..."
            sudo systemctl kill -s HUP nothingdns
            sleep 1
            sudo systemctl status nothingdns --no-pager || true
            return 0
        fi
    fi

    warn "nothingdns service not running or no systemd"
    info "Restart nothingdns manually to apply changes"
}

# Show status
show_status() {
    section "Server Status"

    if command -v systemctl &> /dev/null; then
        sudo systemctl status nothingdns --no-pager || true
    fi

    echo ""
    if curl -s http://127.0.0.1:8080/health > /dev/null 2>&1; then
        info "HTTP API is responding"
        curl -s http://127.0.0.1:8080/api/v1/status | python3 -m json.tool 2>/dev/null || curl -s http://127.0.0.1:8080/api/v1/status
    else
        warn "HTTP API not responding"
    fi
}

# Usage
usage() {
    cat << EOF
NothingDNS Config Management

Usage: $(basename "$0") <command>

Commands:
    show          Show current configuration
    edit          Edit configuration in \$EDITOR
    validate      Validate YAML syntax
    check         Full validation (YAML + binary)
    backup        Backup configuration
    restore       Restore from backup
    diff          Compare two latest backups
    add-zone      Add a new zone
    reload        Send SIGHUP to reload config
    status        Show server status
    help          Show this help

Examples:
    $(basename "$0") show
    $(basename "$0") edit
    $(basename "$0") validate
    $(basename "$0") add-zone
EOF
}

# Main
main() {
    if [ $# -eq 0 ]; then
        usage
        exit 1
    fi

    case "$1" in
        show) show_config ;;
        edit) edit_config ;;
        validate) validate_yaml ;;
        check) validate_yaml && validate_config ;;
        backup) backup_config ;;
        restore) restore_config ;;
        diff) diff_config ;;
        add-zone) add_zone ;;
        reload) reload_config ;;
        status) show_status ;;
        -h|--help|help) usage ;;
        *) error "Unknown command: $1"; usage; exit 1 ;;
    esac
}

main "$@"
