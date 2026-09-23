#!/bin/bash
#
# NothingDNS Master Setup Script v1.1
# Complete installation, configuration, and management
#

set -e

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
        *) error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    case "$OS" in
        linux) PLATFORM="linux-${ARCH}" ;;
        darwin) PLATFORM="darwin-${ARCH}" ;;
        *) error "Unsupported OS: $OS (only Linux and macOS supported)"; exit 1 ;;
    esac

    info "Platform: $PLATFORM"
    info "User: $(whoami)"
}

# Check prerequisites
check_prereqs() {
    section "Checking Prerequisites"

    local missing=()

    command -v curl &> /dev/null || missing+=("curl")

    if [ ${#missing[@]} -gt 0 ]; then
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

    local temp_bin
    temp_bin=$(mktemp)
    # shellcheck disable=SC2064 # expand the temp paths now, while they are set
    trap "rm -f ${temp_bin} ${CHECKSUMS_FILE}" RETURN

    curl -fsSL -o "${temp_bin}" "${download_url}" || {
        error "Download failed"
        return 1
    }
    verify_checksum "${temp_bin}" "${BINARY_NAME}-${PLATFORM}"
    sudo install -m 0755 "${temp_bin}" "${INSTALL_DIR}/${BINARY_NAME}"
    info "Installed to ${INSTALL_DIR}/${BINARY_NAME}"

    # Download dnsctl
    local dnsctl_url="https://github.com/NothingDNS/NothingDNS/releases/download/${LATEST_VERSION}/${DNSCTL_NAME}-${PLATFORM}"
    info "Downloading ${DNSCTL_NAME}..."

    local temp_dnsctl
    temp_dnsctl=$(mktemp)
    if curl -fsSL -o "${temp_dnsctl}" "${dnsctl_url}" 2>/dev/null; then
        verify_checksum "${temp_dnsctl}" "${DNSCTL_NAME}-${PLATFORM}"
        sudo install -m 0755 "${temp_dnsctl}" "${INSTALL_DIR}/${DNSCTL_NAME}"
        rm -f "${temp_dnsctl}"
        info "Installed ${DNSCTL_NAME} to ${INSTALL_DIR}/${DNSCTL_NAME}"
    else
        warn "dnsctl download failed, skipping..."
    fi
}

SERVICE_USER="nothingdns"

# Dedicated unprivileged service account (see install.sh).
create_service_user() {
    if [ "$(uname -s)" != "Linux" ] || id -u "${SERVICE_USER}" &> /dev/null; then
        return 0
    fi
    info "Creating system user ${SERVICE_USER}..."
    local nologin=/usr/sbin/nologin
    [ -x "${nologin}" ] || nologin=/sbin/nologin
    if command -v useradd &> /dev/null; then
        sudo useradd --system --no-create-home --home-dir "${DATA_DIR}" --shell "${nologin}" "${SERVICE_USER}"
    elif command -v adduser &> /dev/null; then
        sudo addgroup -S "${SERVICE_USER}" 2>/dev/null || true
        sudo adduser -S -D -H -h "${DATA_DIR}" -s "${nologin}" -G "${SERVICE_USER}" "${SERVICE_USER}"
    else
        fatal "Cannot create the ${SERVICE_USER} system user (no useradd/adduser)"
    fi
}

# Create directory structure
create_dirs() {
    section "Creating Directory Structure"

    create_service_user
    # CLUSTER_DIR holds Raft WAL/HardState/snapshots. Pre-create so enabling
    # cluster.enabled later does not fail with permission denied.
    local cluster_dir="${DATA_DIR}/cluster"
    sudo mkdir -p "${CONFIG_DIR}/zones" "${CONFIG_DIR}/keys" "${CONFIG_DIR}/tls" \
        "${DATA_DIR}" "${cluster_dir}" /var/log/nothingdns
    if id -u "${SERVICE_USER}" &> /dev/null; then
        sudo chown -R "${SERVICE_USER}:${SERVICE_USER}" "${DATA_DIR}" /var/log/nothingdns "${CONFIG_DIR}/zones"
        sudo chown "root:${SERVICE_USER}" "${CONFIG_DIR}"
        sudo chmod 0750 "${CONFIG_DIR}" "${DATA_DIR}" "${cluster_dir}" /var/log/nothingdns
    fi

    info "Config directory: ${CONFIG_DIR}"
    info "Data directory: ${DATA_DIR}"
    info "Cluster data directory: ${cluster_dir}"
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

    local secret
    secret=$(generate_secret)

    info "Creating default config..."

    sudo tee "${config_file}" > /dev/null << EOF
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
  # Web dashboard and REST API on every interface. Put it behind a TLS reverse
  # proxy or restrict it with a firewall on untrusted networks.
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

# Prometheus metrics. Without auth_token the endpoint may only listen on
# loopback; set auth_token before binding it to a reachable address.
metrics:
  enabled: true
  bind: "127.0.0.1:9153"
  path: /metrics

# Zone database, IXFR journals and dashboard users (users.json). Must be
# writable by the service user.
storage:
  data_dir: /var/lib/nothingdns

# Recursion (forwarding to upstreams, cached answers) only for loopback and
# private networks, so the server is not an open resolver. Every client still
# gets answers from this server's own zones. Add your client ranges here or
# on the dashboard's ACL page.
allow_recursion:
  - 127.0.0.0/8
  - ::1/128
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
  - fc00::/7

# General access control for every query (empty: everyone may query the
# server's own zones). Example:
# acl:
#   - name: block-abuser
#     action: deny
#     networks:
#       - 198.51.100.0/24

# Clustering is off by default. data_dir is pre-created by create_dirs for the
# service user so enabling Raft later only needs peers/encryption_key here.
cluster:
  enabled: false
  gossip_port: 7946
  weight: 100
  cache_sync: true
  consensus_mode: raft
  data_dir: /var/lib/nothingdns/cluster

zones: []
slave_zones: []
transfer:
  allow_list: []
  require_tsig: false
blocklist:
  enabled: false
EOF

    if id -u "${SERVICE_USER}" &> /dev/null; then
        sudo chown "root:${SERVICE_USER}" "${config_file}"
        sudo chmod 0640 "${config_file}"
    else
        sudo chmod 0600 "${config_file}"
    fi

    info "Config created at ${config_file}"
    info "Create the dashboard admin after the service starts (see next steps)."
}

# Setup systemd service
# When port 53 is held (often Ubuntu systemd-resolved), offer the same
# take-over / fallback choices as install.sh.
STOPPED_DNS_SERVICES=()
RESOLVED_DROPIN="/etc/systemd/resolved.conf.d/nothingdns.conf"
RESOLV_CONF_BACKUP="/etc/resolv.conf.nothingdns-backup"
RESOLVED_CHANGED=false

collect_port_53_listeners() {
    if command -v ss &> /dev/null; then
        PORT_53_USERS=$(ss -tulpn 2>/dev/null | grep -E '[:.]53[[:space:]]' | grep -v nothingdns || true)
    else
        PORT_53_USERS=""
    fi
}

check_port_53_free() {
    collect_port_53_listeners
    [ -z "$PORT_53_USERS" ]
}

unit_for_pid() {
    local pid="$1"
    [ -n "${pid}" ] && [ -r "/proc/${pid}/cgroup" ] || return 0
    tr '\0' '\n' < "/proc/${pid}/cgroup" 2>/dev/null \
        | grep -oE '[^/]+\.service' \
        | grep -v '^user@' \
        | tail -n1 || true
}

point_resolv_conf_upstream() {
    if [ -f /run/systemd/resolve/resolv.conf ] && grep -qE '^nameserver[[:space:]]' /run/systemd/resolve/resolv.conf; then
        sudo ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf 2>/dev/null \
            || sudo cat /run/systemd/resolve/resolv.conf | sudo tee /etc/resolv.conf > /dev/null
    else
        warn "systemd-resolved has no upstream DNS servers; writing public resolvers to /etc/resolv.conf"
        sudo rm -f /etc/resolv.conf 2>/dev/null || true
        printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' | sudo tee /etc/resolv.conf > /dev/null
    fi
}

explain_port_53_conflict() {
    collect_port_53_listeners
    [ -n "$PORT_53_USERS" ] || return 0
    echo ""
    warn "Port 53 is already in use — NothingDNS needs it for standard DNS."
    echo ""
    echo "Listeners:"
    echo "$PORT_53_USERS" | sed 's/^/  /'
    echo ""
    echo "Identified holders:"
    local line pid proc unit found=false
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        proc=$(echo "$line" | grep -oE 'users:\(\("[^"]+"' | head -1 | sed 's/users:((\"//;s/\"$//' || true)
        pid=$(echo "$line" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2 || true)
        unit=""
        [ -n "$pid" ] && unit=$(unit_for_pid "$pid")
        [ -z "$proc" ] && [ -n "$pid" ] && [ -r "/proc/${pid}/comm" ] \
            && proc=$(tr -d '\0' < "/proc/${pid}/comm" 2>/dev/null || true)
        if [ -n "$proc" ] || [ -n "$unit" ] || [ -n "$pid" ]; then
            found=true
            printf '  - process=%s  pid=%s  unit=%s\n' \
                "${proc:-unknown}" "${pid:-?}" "${unit:-unknown}"
        fi
    done <<< "$PORT_53_USERS"
    [ "$found" = true ] || echo "  (could not map PIDs — see listeners above)"
    if echo "$PORT_53_USERS" | grep -qiE 'systemd-resolve|resolved'; then
        echo ""
        echo "Note (Ubuntu/Debian): systemd-resolved often owns 127.0.0.53:53."
        echo "Option 1 disables only the stub listener; host DNS keeps working."
    fi
    echo ""
}

release_port_53() {
    info "Freeing port 53 (stop conflicting DNS services + disable on boot)..."
    if systemctl list-unit-files systemd-resolved.service &>/dev/null \
        && { systemctl is-active --quiet systemd-resolved 2>/dev/null \
             || echo "${PORT_53_USERS}" | grep -qiE 'systemd-resolve|resolved'; }; then
        info "Disabling the systemd-resolved stub listener on 127.0.0.53:53..."
        sudo mkdir -p "$(dirname "${RESOLVED_DROPIN}")"
        printf '[Resolve]\nDNSStubListener=no\n' | sudo tee "${RESOLVED_DROPIN}" > /dev/null
        if [ -L /etc/resolv.conf ] || [ -f /etc/resolv.conf ]; then
            sudo cp -P /etc/resolv.conf "${RESOLV_CONF_BACKUP}" 2>/dev/null || true
        fi
        sudo systemctl restart systemd-resolved || true
        point_resolv_conf_upstream
        RESOLVED_CHANGED=true
    fi
    local svc
    for svc in unbound bind9 named dnsmasq pdns pdns-recursor knot knot-resolver coredns stubby; do
        if systemctl list-unit-files "${svc}.service" &>/dev/null \
            && { systemctl is-active --quiet "${svc}" 2>/dev/null \
                 || systemctl is-enabled --quiet "${svc}" 2>/dev/null; }; then
            info "Stopping and disabling ${svc}.service..."
            sudo systemctl stop "${svc}" 2>/dev/null || true
            sudo systemctl disable "${svc}" 2>/dev/null || true
            STOPPED_DNS_SERVICES+=("${svc}")
        fi
    done
    collect_port_53_listeners
    local line pid unit base
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        pid=$(echo "$line" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2 || true)
        [ -n "$pid" ] || continue
        unit=$(unit_for_pid "$pid")
        [ -n "$unit" ] || continue
        base="${unit%.service}"
        case "${base}" in nothingdns|systemd-resolved) continue ;; esac
        case "${base}" in
            *dns*|*bind*|*named*|*unbound*|*pdns*|*knot*|*coredns*|*stubby*|*resolve*)
                info "Stopping and disabling ${unit} (holds port 53, pid ${pid})..."
                sudo systemctl stop "${unit}" 2>/dev/null || true
                sudo systemctl disable "${unit}" 2>/dev/null || true
                STOPPED_DNS_SERVICES+=("${base}")
                ;;
            *)
                warn "Port 53 still held by ${unit} (pid ${pid}); not auto-stopping unknown unit."
                ;;
        esac
    done <<< "${PORT_53_USERS}"
    sleep 1
}

restore_host_dns() {
    local svc
    if [ "${RESOLVED_CHANGED}" = true ]; then
        warn "Restoring systemd-resolved stub listener and /etc/resolv.conf..."
        sudo rm -f "${RESOLVED_DROPIN}"
        if [ -L "${RESOLV_CONF_BACKUP}" ] || [ -f "${RESOLV_CONF_BACKUP}" ]; then
            sudo mv -f "${RESOLV_CONF_BACKUP}" /etc/resolv.conf 2>/dev/null \
                || { sudo cat "${RESOLV_CONF_BACKUP}" | sudo tee /etc/resolv.conf > /dev/null && sudo rm -f "${RESOLV_CONF_BACKUP}"; }
        fi
        sudo systemctl restart systemd-resolved || true
    fi
    for svc in "${STOPPED_DNS_SERVICES[@]}"; do
        warn "Re-enabling ${svc}..."
        sudo systemctl enable "${svc}" 2>/dev/null || true
        sudo systemctl start "${svc}" || true
    done
}

maybe_free_port_53() {
    check_port_53_free && return 0
    explain_port_53_conflict
    if ! is_interactive; then
        warn "Non-interactive setup: leaving port 53 as-is. Free it manually or set server.port: 5353."
        return 0
    fi
    echo "Choose how to continue:"
    echo "  1) Free port 53 — stop/disable the service(s) above (install/start on 53)"
    echo "  2) Leave them running — you must set server.port (e.g. 5353) yourself"
    echo "  3) Cancel"
    echo ""
    read -p "Select [1/2/3]: " -n 1 -r; echo
    case "$REPLY" in
        1)
            release_port_53
            if ! check_port_53_free; then
                warn "Port 53 is still in use; restoring previous DNS and continuing without changes."
                explain_port_53_conflict
                restore_host_dns
            else
                info "Port 53 is free."
            fi
            ;;
        2) info "Keeping existing DNS on port 53." ;;
        *) fatal "Setup cancelled" ;;
    esac
}

setup_service() {
    section "Setting Up Systemd Service"

    if ! command -v systemctl &> /dev/null; then
        warn "systemd not found, skipping service setup"
        return 0
    fi

    maybe_free_port_53

    if [ ! -f "/etc/systemd/system/nothingdns.service" ]; then
        local unit_tmp
        unit_tmp=$(mktemp)
        cat > "${unit_tmp}" << EOF
[Unit]
Description=NothingDNS Authoritative DNS Server
Documentation=https://github.com/NothingDNS/NothingDNS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nothingdns
Group=nothingdns
WorkingDirectory=/var/lib/nothingdns
ExecStart=/usr/local/bin/nothingdns -config ${CONFIG_FILE}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
LimitNOFILE=1048576

# Bind port 53 without running as root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/nothingdns /var/log/nothingdns -/etc/nothingdns/zones
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
        sudo install -m 0644 "${unit_tmp}" /etc/systemd/system/nothingdns.service
        rm -f "${unit_tmp}"
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

    if [ -d /etc/logrotate.d ]; then
        local rotate_tmp
        rotate_tmp=$(mktemp)
        cat > "${rotate_tmp}" << 'EOF'
/var/log/nothingdns/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    # NothingDNS and systemd (StandardOutput=append:) keep their log files
    # open; copy and truncate in place so writes continue in the new file.
    copytruncate
}
EOF
        sudo install -m 0644 "${rotate_tmp}" /etc/logrotate.d/nothingdns
        rm -f "${rotate_tmp}"
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
    echo "   sudo tail -f /var/log/nothingdns/server.log"
    echo ""
    echo -e "${CYAN}4. Check health:${NC}"
    echo "   curl http://127.0.0.1:8080/health"
    echo ""
    echo -e "${CYAN}5. Create the dashboard admin (run on this host):${NC}"
    echo "   curl -X POST http://127.0.0.1:8080/api/v1/auth/bootstrap \\"
    echo "     -H 'Content-Type: application/json' \\"
    echo "     -d '{\"username\":\"admin\",\"password\":\"<strong-password>\"}'"
    echo ""
    echo -e "${CYAN}6. Update to new version:${NC}"
    echo "   curl -fsSL https://raw.githubusercontent.com/NothingDNS/NothingDNS/main/update.sh | bash"
    echo ""
    echo -e "${CYAN}Dashboard:${NC}"
    echo "   http://<this-host>:8080"
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
