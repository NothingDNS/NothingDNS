#!/bin/bash
#
# NothingDNS Config Management Script v1.1
# Validates, edits, and manages NothingDNS configuration
#

set -e

CONFIG_DIR="/etc/nothingdns"
# Canonical config name; legacy installs (pre-v1.0.0) used config.yaml.
CONFIG_FILE="${CONFIG_DIR}/nothingdns.yaml"
if [ ! -f "${CONFIG_FILE}" ] && [ -f "${CONFIG_DIR}/config.yaml" ]; then
    CONFIG_FILE="${CONFIG_DIR}/config.yaml"
fi
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

# Check if stdin is a terminal
is_interactive() {
    [ -t 0 ]
}

# Check if config exists
check_config() {
    if ! sudo test -f "${CONFIG_FILE}"; then
        error "Config not found at ${CONFIG_FILE}"
        info "Run setup.sh first to create config"
        return 1
    fi
}

# Locate the nothingdns binary.
find_binary() {
    if command -v "${BINARY_NAME}" &> /dev/null; then
        command -v "${BINARY_NAME}"
    elif [ -x "/usr/local/bin/${BINARY_NAME}" ]; then
        echo "/usr/local/bin/${BINARY_NAME}"
    fi
}

# Validate the config with the server's own parser and validator. A generic
# YAML parser is not a substitute: NothingDNS has its own YAML dialect and
# semantic checks (ports, metrics auth, ACLs, ...).
validate_config() {
    check_config || return 1
    section "Validating Configuration"

    local binary
    binary=$(find_binary)
    if [ -z "${binary}" ]; then
        error "nothingdns binary not found; cannot validate"
        return 1
    fi

    if sudo "${binary}" -config "${CONFIG_FILE}" -validate-config; then
        info "Config is valid"
    else
        error "Config validation failed"
        return 1
    fi
}

# Edit config
edit_config() {
    check_config || return 1

    section "Editing Configuration"

    if [ ! -w "${CONFIG_FILE}" ]; then
        info "Using sudoedit to edit config..."
        SUDO_EDITOR="${EDITOR}" sudoedit "${CONFIG_FILE}"
    else
        "${EDITOR}" "${CONFIG_FILE}"
    fi
    validate_config || warn "Fix the errors above before reloading"
}

# Show config
show_config() {
    check_config || return 1

    section "Current Configuration"

    echo ""
    sudo cat "${CONFIG_FILE}"
    echo ""
}

# Backup config
backup_config() {
    check_config || return 1

    section "Backing Up Configuration"

    local backup
    backup="${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    # -p keeps the restrictive owner/mode: the config holds auth_secret.
    sudo cp -p "${CONFIG_FILE}" "${backup}"
    info "Backed up to ${backup}"
}

# Restore config
restore_config() {
    section "Restoring Configuration"

    local backups=()
    mapfile -t backups < <(sudo sh -c "ls -t '${CONFIG_FILE}'.backup.* 2>/dev/null" | head -5)

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
            sudo cp -p "${backup}" "${CONFIG_FILE}"
            info "Restored from ${backup}"
            validate_config || warn "The restored config does not validate"
            break
        fi
    done
}

# Diff config
diff_config() {
    check_config || return 1

    section "Comparing Config Versions"

    local backups=()
    mapfile -t backups < <(sudo sh -c "ls -t '${CONFIG_FILE}'.backup.* 2>/dev/null" | head -2)

    if [ ${#backups[@]} -lt 2 ]; then
        error "Need at least 2 backups to compare"
        return 1
    fi

    if command -v diff &> /dev/null; then
        sudo diff -u "${backups[1]}" "${backups[0]}" || true
    else
        warn "diff not available"
    fi
}

# Add zone
add_zone() {
    check_config || return 1

    section "Adding Zone"

    read -r -p "Zone name (e.g., example.com): " zone_name

    zone_name="${zone_name%.}"
    if ! [[ "${zone_name}" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]]; then
        error "Invalid zone name: ${zone_name}"
        return 1
    fi

    local zone_file="${CONFIG_DIR}/zones/${zone_name}.zone"

    if sudo test -f "$zone_file"; then
        warn "Zone file already exists at ${zone_file}"
    else
        sudo mkdir -p "${CONFIG_DIR}/zones"
        sudo tee "$zone_file" > /dev/null << EOF
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

    info "Add the zone file to the zones: list in ${CONFIG_FILE}, e.g."
    echo "  zones:"
    echo "    - ${zone_file}"
    info "then run: $(basename "$0") check && $(basename "$0") reload"
}

# Reload config
reload_config() {
    section "Reloading Configuration"

    if command -v systemctl &> /dev/null; then
        if systemctl is-active --quiet nothingdns 2>/dev/null; then
            validate_config || { error "Not reloading an invalid config"; return 1; }
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
    if curl -s --max-time 3 http://127.0.0.1:8080/health > /dev/null 2>&1; then
        info "HTTP API is responding"
        curl -s --max-time 3 http://127.0.0.1:8080/health
        echo ""
    else
        warn "HTTP API not responding"
    fi
}

# Usage
usage() {
    cat << EOF
NothingDNS Config Management v1.1

Usage: $(basename "$0") <command>

Commands:
    show          Show current configuration
    edit          Edit configuration in \$EDITOR
    validate      Validate the config with the nothingdns binary
    check         Same as validate
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
        validate|check) validate_config ;;
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