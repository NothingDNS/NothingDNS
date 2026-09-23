#!/bin/bash
#
# NothingDNS Install Script v1.1
# Downloads latest release, creates config, and sets up the server
#

set -e

REPO="NothingDNS/NothingDNS"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nothingdns"
# Canonical config name (matches the server default, Dockerfile,
# docker-compose.yml and deploy/nothingdns.service).
CONFIG_FILE="${CONFIG_DIR}/nothingdns.yaml"
# Legacy installs (pre-v1.0.0) created config.yaml — keep using it if present.
LEGACY_CONFIG_FILE="${CONFIG_DIR}/config.yaml"
BINARY_NAME="nothingdns"
DNSCTL_NAME="dnsctl"
SKIP_DOWNLOAD=false
BOOTSTRAP_USER="admin"
BOOTSTRAP_PASS=""
USE_PORT_5353=false
TAKE_PORT_53=false
# Release assets are verified against the published SHA256SUMS by default. This
# is the integrity control that stops a hijacked/MITM'd release from achieving
# root code execution (the binary is chmod +x'd and run as root). Override only
# in trusted/offline environments: NOTHINGDNS_SKIP_CHECKSUM=1.
SKIP_CHECKSUM="${NOTHINGDNS_SKIP_CHECKSUM:-0}"
CHECKSUMS_FILE=""
# In fully non-interactive installs with no TTY (e.g. cloud-init), taking over
# a real DNS package (bind/unbound/dnsmasq) requires NOTHINGDNS_STOP_HOST_DNS=1.
# The Ubuntu systemd-resolved stub alone is freed automatically (safe path).
STOP_HOST_DNS="${NOTHINGDNS_STOP_HOST_DNS:-0}"
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

# Promptable when stdin is a TTY, or when curl|bash still has /dev/tty
# (operator is at a real terminal even though the script body arrives on a pipe).
is_interactive() {
    [ -t 0 ] && return 0
    [ -c /dev/tty ] && [ -r /dev/tty ] && [ -w /dev/tty ] 2>/dev/null && return 0
    return 1
}

# Single-key prompt. Uses /dev/tty when stdin is not a terminal so
# `curl … | bash` can still ask the operator.
read_reply() {
    local prompt="$1"
    if [ -t 0 ]; then
        read -r -n 1 -p "${prompt}"
        echo
    else
        printf '%s' "${prompt}" > /dev/tty
        read -r -n 1 < /dev/tty
        echo > /dev/tty
    fi
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

# Download the release SHA256SUMS once, into CHECKSUMS_FILE. Fails closed unless
# the operator explicitly opted out via NOTHINGDNS_SKIP_CHECKSUM=1.
fetch_checksums() {
    if [ "${SKIP_DOWNLOAD}" = true ]; then
        return
    fi
    if [ "${SKIP_CHECKSUM}" = "1" ]; then
        warn "NOTHINGDNS_SKIP_CHECKSUM=1 — release integrity verification DISABLED"
        return
    fi
    if [ -z "$(sha256_of /dev/null)" ]; then
        error "No sha256sum/shasum tool available to verify the release. Install coreutils, or set NOTHINGDNS_SKIP_CHECKSUM=1 to bypass (NOT recommended)."
    fi
    CHECKSUMS_FILE=$(mktemp)
    TEMP_FILES+=("${CHECKSUMS_FILE}")
    local url="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/SHA256SUMS"
    curl -fsSL -o "${CHECKSUMS_FILE}" "${url}" || \
        error "Could not download release checksums (${url}). Refusing to install unverified binaries; set NOTHINGDNS_SKIP_CHECKSUM=1 to bypass (NOT recommended)."
}

# Verify a downloaded file against the published checksum for the given asset
# name. Aborts on mismatch or a missing entry (fail-closed).
verify_checksum() {
    local file="$1" asset="$2"
    if [ "${SKIP_CHECKSUM}" = "1" ]; then
        return
    fi
    local expected
    expected=$(grep -E "[[:space:]][*]?${asset}\$" "${CHECKSUMS_FILE}" | awk '{print $1}' | head -n1)
    [ -n "${expected}" ] || error "No checksum entry for ${asset} in SHA256SUMS — refusing to install."
    local actual
    actual=$(sha256_of "${file}")
    if [ "${expected}" != "${actual}" ]; then
        error "Checksum mismatch for ${asset}: expected ${expected}, got ${actual}. Aborting — the download may be corrupt or tampered with."
    fi
    info "Verified ${asset} (sha256 ${actual})"
}

# Match port 53 exactly (not :5353 or :530). Fills PORT_53_USERS.
collect_port_53_listeners() {
    if command -v ss &> /dev/null; then
        PORT_53_USERS=$(ss -tulpn 2>/dev/null | grep -E '[:.]53[[:space:]]' | grep -v nothingdns || true)
    elif command -v netstat &> /dev/null; then
        PORT_53_USERS=$(netstat -tulpn 2>/dev/null | grep -E '[:.]53[[:space:]]' | grep -v nothingdns || true)
    else
        PORT_53_USERS=""
    fi
}

# True when every :53 listener is systemd-resolved on the loopback stub
# addresses (127.0.0.53 / 127.0.0.54). Safe to free via DNSStubListener=no
# without stopping a real authoritative/recursive DNS package.
port_53_only_resolved_stub() {
    collect_port_53_listeners
    [ -n "${PORT_53_USERS}" ] || return 1
    local line
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        echo "$line" | grep -qiE 'systemd-resolve|resolved' || return 1
        echo "$line" | grep -qE '127\.0\.0\.(53|54)' || return 1
    done <<< "${PORT_53_USERS}"
    return 0
}

# Quiet check: 0 = free, 1 = in use.
check_port_53() {
    collect_port_53_listeners
    [ -z "$PORT_53_USERS" ]
}


# Resolve a PID to its systemd unit name (empty if unknown).
unit_for_pid() {
    local pid="$1"
    [ -n "${pid}" ] && [ -r "/proc/${pid}/cgroup" ] || return 0
    tr '\0' '\n' < "/proc/${pid}/cgroup" 2>/dev/null \
        | grep -oE '[^/]+\.service' \
        | grep -v '^user@' \
        | tail -n1 || true
}

# Print a clear summary of who holds port 53 (Ubuntu resolved, bind, etc.).
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

    local found=false
    local line pid proc unit
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        # ss: users:(("systemd-resolve",pid=123,fd=14))
        proc=$(echo "$line" | grep -oE 'users:\(\("[^"]+"' | head -1 | sed 's/users:((\"//;s/\"$//' || true)
        pid=$(echo "$line" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2 || true)
        unit=""
        if [ -n "$pid" ]; then
            unit=$(unit_for_pid "$pid")
        fi
        if [ -z "$proc" ] && [ -n "$pid" ] && [ -r "/proc/${pid}/comm" ]; then
            proc=$(tr -d '\0' < "/proc/${pid}/comm" 2>/dev/null || true)
        fi
        if [ -n "$proc" ] || [ -n "$unit" ] || [ -n "$pid" ]; then
            found=true
            printf '  - process=%s  pid=%s  unit=%s\n' \
                "${proc:-unknown}" "${pid:-?}" "${unit:-unknown}"
        fi
    done <<< "$PORT_53_USERS"

    if [ "$found" = false ]; then
        echo "  (could not map PIDs — see listeners above)"
    fi

    if echo "$PORT_53_USERS" | grep -qiE 'systemd-resolve|resolved'; then
        echo ""
        echo "Note (Ubuntu/Debian): systemd-resolved often owns 127.0.0.53:53."
        echo "Taking port 53 will disable only its stub listener and keep host"
        echo "DNS working via upstream resolvers — resolved itself stays running."
    fi
    echo ""
}

# Stop and remove existing NothingDNS installation
stop_existing_nothingdns() {
    info "Checking for existing NothingDNS installation..."

    # Stop systemd service if exists
    if systemctl is-active --quiet nothingdns 2>/dev/null; then
        info "Stopping existing NothingDNS service..."
        sudo systemctl stop nothingdns 2>/dev/null || true
    fi

    # Disable service
    if systemctl is-enabled --quiet nothingdns 2>/dev/null; then
        sudo systemctl disable nothingdns 2>/dev/null || true
    fi

    # The binary itself is left in place: download_binary replaces it
    # atomically, and when the download is skipped (already up to date)
    # deleting it here would leave no binary at all.

    # Remove old service file
    if [ -f /etc/systemd/system/nothingdns.service ]; then
        info "Removing old systemd service file..."
        sudo rm -f /etc/systemd/system/nothingdns.service
        sudo systemctl daemon-reload
    fi

    info "Existing NothingDNS service stopped"
}

# Services stopped by release_port_53, restarted by restore_host_dns.
STOPPED_DNS_SERVICES=()
RESOLVED_DROPIN="/etc/systemd/resolved.conf.d/nothingdns.conf"
RESOLV_CONF_BACKUP="/etc/resolv.conf.nothingdns-backup"
RESOLVED_CHANGED=false

# Point /etc/resolv.conf at resolved's upstream list, or at public resolvers
# when resolved knows none. Falls back to copying when /etc/resolv.conf cannot
# be replaced (e.g. a bind mount in containers).
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

# Free port 53 without leaving the host unable to resolve names.
#
# systemd-resolved keeps running with only its 127.0.0.53 stub listener
# disabled, and /etc/resolv.conf is pointed at the upstream servers it learned
# (DHCP/netplan). Stopping resolved outright would leave /etc/resolv.conf
# pointing at a dead 127.0.0.53 and break every lookup on the host.
# Other resolvers are stopped and disabled so they do not reclaim port 53
# after reboot; if the host used them via 127.0.0.1, NothingDNS answers there
# once it starts.
release_port_53() {
    info "Freeing port 53 (stop conflicting DNS services + disable on boot)..."

    # Ubuntu/Debian default: stub listener on 127.0.0.53:53
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
    # Well-known DNS packages on Ubuntu and other distros.
    for svc in unbound bind9 named dnsmasq pdns pdns-recursor \
               knot knot-resolver coredns stubby systemd-resolved; do
        # systemd-resolved: never stop/disable the unit — stub already handled.
        if [ "${svc}" = "systemd-resolved" ]; then
            continue
        fi
        if systemctl list-unit-files "${svc}.service" &>/dev/null \
            && { systemctl is-active --quiet "${svc}" 2>/dev/null \
                 || systemctl is-enabled --quiet "${svc}" 2>/dev/null; }; then
            info "Stopping and disabling ${svc}.service..."
            sudo systemctl stop "${svc}" 2>/dev/null || true
            sudo systemctl disable "${svc}" 2>/dev/null || true
            STOPPED_DNS_SERVICES+=("${svc}")
        fi
    done

    # Any remaining listener: map PID → unit and stop DNS-like units.
    collect_port_53_listeners
    local line pid unit base
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        pid=$(echo "$line" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2 || true)
        [ -n "$pid" ] || continue
        unit=$(unit_for_pid "$pid")
        [ -n "$unit" ] || continue
        base="${unit%.service}"
        case "${base}" in
            nothingdns|systemd-resolved) continue ;;
        esac
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

# Earlier installers stopped systemd-resolved but left /etc/resolv.conf
# pointing at its dead 127.0.0.53 stub, so the host could not resolve anything
# (including the release download). Repair that state before downloading.
repair_dead_resolved_stub() {
    grep -qE '^nameserver[[:space:]]+127\.0\.0\.53' /etc/resolv.conf 2>/dev/null || return 0
    systemctl is-active --quiet systemd-resolved 2>/dev/null && return 0
    warn "/etc/resolv.conf points at 127.0.0.53 but systemd-resolved is not running; host DNS is broken."
    if systemctl list-unit-files systemd-resolved.service 2>/dev/null | grep -q systemd-resolved; then
        info "Re-enabling systemd-resolved without its port 53 stub listener..."
        sudo mkdir -p "$(dirname "${RESOLVED_DROPIN}")"
        printf '[Resolve]\nDNSStubListener=no\n' | sudo tee "${RESOLVED_DROPIN}" > /dev/null
        sudo systemctl enable systemd-resolved 2>/dev/null || true
        sudo systemctl start systemd-resolved || true
    fi
    point_resolv_conf_upstream
    info "Host DNS repaired"
}

# Undo release_port_53 when NothingDNS could not take over port 53.
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

# Check if NothingDNS is already installed
check_existing_install() {
    if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        local current_version
        current_version=$("${INSTALL_DIR}/${BINARY_NAME}" -version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        current_version="${current_version:-unknown}"
        info "NothingDNS already installed: ${current_version}"
        info "Latest release: ${LATEST_VERSION}"

        # Release tags carry a "v" prefix; the binary reports bare semver.
        if [ "${current_version}" = "${LATEST_VERSION#v}" ]; then
            info "NothingDNS is up to date!"
            if is_interactive; then
                echo ""
                echo "  1) Reinstall anyway"
                echo "  2) Skip download (use existing)"
                echo "  3) Exit"
                echo ""
                read_reply "Select [2]: "
                case "$REPLY" in
                    1) info "Reinstalling..." ;;
                    3) info "Nothing to do. Exiting."; exit 0 ;;
                    *) info "Using existing installation."; SKIP_DOWNLOAD=true ;;
                esac
            else
                info "Non-interactive: using existing installation."
                SKIP_DOWNLOAD=true
            fi
        else
            echo ""
            echo "A newer version is available."
            echo "  1) Upgrade to ${LATEST_VERSION}"
            echo "  2) Keep current version"
            echo "  3) Exit"
            echo ""
            if is_interactive; then
                read_reply "Select [1]: "
                case "$REPLY" in
                    2) info "Keeping current version."; SKIP_DOWNLOAD=true ;;
                    3) info "Exiting."; exit 0 ;;
                    *) info "Upgrading to ${LATEST_VERSION}..." ;;
                esac
            else
                info "Non-interactive: upgrading to ${LATEST_VERSION}..."
            fi
        fi
    fi
}

# Download binary
download_binary() {
    if [ "${SKIP_DOWNLOAD}" = true ]; then
        info "Skipping download (using existing installation)"
        return
    fi

    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/${BINARY_NAME}-${PLATFORM}"
    info "Downloading from ${DOWNLOAD_URL}..."

    TEMP_FILE=$(mktemp)
    TEMP_FILES+=("${TEMP_FILE}")

    curl -fsSL -o "${TEMP_FILE}" "${DOWNLOAD_URL}" || error "Download failed"
    verify_checksum "${TEMP_FILE}" "${BINARY_NAME}-${PLATFORM}"
    sudo install -m 0755 "${TEMP_FILE}" "${INSTALL_DIR}/${BINARY_NAME}" || error "Failed to install to ${INSTALL_DIR}"
    info "Installed to ${INSTALL_DIR}/${BINARY_NAME}"

    # Set capability for privileged port binding (port 53)
    if command -v setcap &> /dev/null; then
        if [ -w /proc/sys/kernel/cap_last_cap ] && capsh --print | grep -q "cap_net_bind_service"; then
            if setcap 'cap_net_bind_service=+ep' "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null; then
                info "Setcap: enabled privileged port binding (cap_net_bind_service)"
            else
                warn "Setcap failed - may need root or manual configuration for port 53"
            fi
        fi
    fi
}

# Download dnsctl (CLI tool)
download_dnsctl() {
    if [ "${SKIP_DOWNLOAD}" = true ]; then
        info "Skipping dnsctl download"
        return
    fi

    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/${DNSCTL_NAME}-${PLATFORM}"
    info "Downloading dnsctl..."

    TEMP_FILE=$(mktemp)
    TEMP_FILES+=("${TEMP_FILE}")
    curl -fsSL -o "${TEMP_FILE}" "${DOWNLOAD_URL}" 2>/dev/null || {
        warn "dnsctl download failed, skipping..."
        return
    }
    verify_checksum "${TEMP_FILE}" "${DNSCTL_NAME}-${PLATFORM}"
    sudo install -m 0755 "${TEMP_FILE}" "${INSTALL_DIR}/${DNSCTL_NAME}" || { warn "Failed to install dnsctl"; return; }
    info "Installed dnsctl to ${INSTALL_DIR}/${DNSCTL_NAME}"
}

# Dedicated unprivileged service account. "nobody" is shared with other
# daemons and its group is "nogroup" on Debian but "nobody" on RHEL, so a unit
# hardcoding nobody:nogroup fails to start there.
SERVICE_USER="nothingdns"
DATA_DIR="/var/lib/nothingdns"
# Raft WAL, HardState and snapshots (cluster.data_dir). Created empty so
# enabling cluster later does not hit "permission denied" on first start.
CLUSTER_DIR="${DATA_DIR}/cluster"
LOG_DIR="/var/log/nothingdns"

create_service_user() {
    if [ "$(uname -s)" != "Linux" ]; then
        return
    fi
    if id -u "${SERVICE_USER}" &> /dev/null; then
        return
    fi
    info "Creating system user ${SERVICE_USER}..."
    local nologin=/usr/sbin/nologin
    [ -x "${nologin}" ] || nologin=/sbin/nologin
    if command -v useradd &> /dev/null; then
        sudo useradd --system --no-create-home --home-dir "${DATA_DIR}" --shell "${nologin}" "${SERVICE_USER}"
    elif command -v adduser &> /dev/null; then
        # BusyBox/Alpine
        sudo addgroup -S "${SERVICE_USER}" 2>/dev/null || true
        sudo adduser -S -D -H -h "${DATA_DIR}" -s "${nologin}" -G "${SERVICE_USER}" "${SERVICE_USER}"
    else
        error "Cannot create the ${SERVICE_USER} system user (no useradd/adduser)"
    fi
}

# Create directories with ownership the service account can use.
# Includes CLUSTER_DIR so Raft can mkdir raft-wal/snapshots without a
# manual chown when the operator later sets cluster.enabled: true.
setup_dirs() {
    sudo mkdir -p \
        "${CONFIG_DIR}/tls" \
        "${CONFIG_DIR}/zones" \
        "${DATA_DIR}" \
        "${CLUSTER_DIR}" \
        "${LOG_DIR}"
    if id -u "${SERVICE_USER}" &> /dev/null; then
        sudo chown -R "${SERVICE_USER}:${SERVICE_USER}" "${DATA_DIR}" "${LOG_DIR}" "${CONFIG_DIR}/zones"
        sudo chown "root:${SERVICE_USER}" "${CONFIG_DIR}"
        sudo chmod 0750 "${CONFIG_DIR}" "${DATA_DIR}" "${CLUSTER_DIR}" "${LOG_DIR}"
    fi
}

# Make the config readable by the service account but not by other users
# (it holds auth_secret).
secure_config_file() {
    if id -u "${SERVICE_USER}" &> /dev/null; then
        sudo chown "root:${SERVICE_USER}" "${CONFIG_FILE}"
        sudo chmod 0640 "${CONFIG_FILE}"
    else
        sudo chmod 0600 "${CONFIG_FILE}"
    fi
}

# Rewrite "port:" under server: in an existing config.
set_config_port() {
    local port="$1"
    info "Applying port change to ${port}..."
    local tmp
    tmp=$(mktemp)
    sudo cat "${CONFIG_FILE}" | awk -v port="${port}" '
        /^server:/ { in_server = 1; print; next }
        /^[^[:space:]#]/ { in_server = 0 }
        in_server && !done && /^  port:[[:space:]]*[0-9]+[[:space:]]*$/ { print "  port: " port; done = 1; next }
        { print }
    ' > "${tmp}"
    sudo cp "${tmp}" "${CONFIG_FILE}"
    rm -f "${tmp}"
}

# Create default config
create_config() {
    local port="${1:-53}"

    # Backward compatibility: if only the legacy config.yaml exists, leave it
    # untouched and keep pointing the service at it. New installs get the
    # canonical nothingdns.yaml.
    if [ ! -f "${CONFIG_FILE}" ] && [ -f "${LEGACY_CONFIG_FILE}" ]; then
        CONFIG_FILE="${LEGACY_CONFIG_FILE}"
    fi

    if [ -f "${CONFIG_FILE}" ]; then
        warn "Config already exists at ${CONFIG_FILE}"
        if is_interactive; then
            read_reply "Overwrite config? (y/N): "
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                info "Keeping existing config"
                if [ "$port" != "53" ]; then
                    set_config_port "${port}"
                fi
                return
            fi
        else
            info "Non-interactive: keeping existing config"
            if [ "$port" != "53" ]; then
                set_config_port "${port}"
            fi
            return
        fi
    fi

    info "Creating default config at ${CONFIG_FILE}..."

    setup_dirs

    # Generate a random auth secret
    AUTH_SECRET=$(openssl rand -base64 32 2>/dev/null || head -c 32 /dev/urandom | base64)

    sudo tee "${CONFIG_FILE}" > /dev/null << EOF
# NothingDNS Configuration
# https://github.com/NothingDNS/NothingDNS
# Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
# Version: ${LATEST_VERSION}

server:
  port: ${port}
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
    auth_secret: "${AUTH_SECRET}"

  # TLS/DoT (optional)
  # tls:
  #   enabled: true
  #   cert_file: /etc/nothingdns/tls/server.crt
  #   key_file: /etc/nothingdns/tls/server.key
  #   bind: ":853"

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

# Zone database and IXFR journals. Must be writable by the service user.
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

# Clustering is off by default. Directories under cluster.data_dir are
# pre-created for the service user so enabling Raft later only needs
# peers/encryption_key in this file (no manual mkdir/chown).
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

    secure_config_file
    info "Config created at ${CONFIG_FILE}"
    # Persist the API auth secret to a root-only file rather than echoing it to
    # stdout, which can leak into terminal scrollback or logs — especially under
    # curl | bash (V25).
    printf 'api_auth_secret: %s\n' "${AUTH_SECRET}" | sudo tee "${CONFIG_DIR}/credentials" >/dev/null
    sudo chmod 600 "${CONFIG_DIR}/credentials"
    info "API auth secret saved to ${CONFIG_DIR}/credentials (root-only)."
    info "Retrieve with: sudo cat ${CONFIG_DIR}/credentials"
}

# Create bootstrap user via API
create_bootstrap_user() {
    BOOTSTRAP_PASS=$(openssl rand -base64 12 2>/dev/null | tr -d '/+=' | head -c 12)

    local max_attempts=15
    local attempt=0

    info "Waiting for server to start..."
    while [ $attempt -lt $max_attempts ]; do
        if curl -s --max-time 2 http://127.0.0.1:8080/health > /dev/null 2>&1; then
            break
        fi
        attempt=$((attempt + 1))
        sleep 1
    done

    if [ $attempt -eq $max_attempts ]; then
        BOOTSTRAP_PASS=""
        warn "Server did not start in time, skipping bootstrap user creation"
        if command -v systemctl &> /dev/null; then
            warn "Recent service log:"
            sudo journalctl -u nothingdns -n 20 --no-pager 2>/dev/null || true
        fi
        warn "Once the server runs, create the admin account on this host with:"
        warn "curl -X POST http://127.0.0.1:8080/api/v1/auth/bootstrap -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"<your-password>\"}'"
        return
    fi

    local bootstrap_needed=true
    if sudo grep -q '^password:' "${CONFIG_DIR}/credentials" 2>/dev/null; then
        info "Admin credentials already exist in ${CONFIG_DIR}/credentials, skipping bootstrap"
        BOOTSTRAP_PASS=""
        bootstrap_needed=false
    fi

    if [ "$bootstrap_needed" = true ]; then
        local response
        response=$(curl -s -X POST http://127.0.0.1:8080/api/v1/auth/bootstrap \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"${BOOTSTRAP_USER}\",\"password\":\"${BOOTSTRAP_PASS}\"}" 2>&1)

        if echo "$response" | grep -q "token"; then
            info "Bootstrap user created successfully"
            # Save the generated admin password to the root-only credentials file
            # instead of printing it to stdout (V25).
            printf 'username: %s\npassword: %s\n' "${BOOTSTRAP_USER}" "${BOOTSTRAP_PASS}" | sudo tee -a "${CONFIG_DIR}/credentials" >/dev/null
            sudo chmod 600 "${CONFIG_DIR}/credentials"
            info "Admin credentials saved to ${CONFIG_DIR}/credentials (root-only). Retrieve with: sudo cat ${CONFIG_DIR}/credentials"
        else
            BOOTSTRAP_PASS=""
            warn "Bootstrap response: $response"
            warn "The admin account was not created. If an admin already exists, sign in with its password;"
            warn "otherwise create one on this host via POST http://127.0.0.1:8080/api/v1/auth/bootstrap"
        fi
    fi
}

# Setup service (systemd)
setup_service() {
    create_service_user
    setup_dirs
    if [ -f "${CONFIG_FILE}" ]; then
        secure_config_file
    fi

    if command -v systemctl &> /dev/null; then
        info "Setting up systemd service..."

        SERVICE_FILE="/etc/systemd/system/nothingdns.service"

        local unit_tmp
        unit_tmp=$(mktemp)
        cat > "${unit_tmp}" << EOF
[Unit]
Description=NothingDNS DNS Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nothingdns
Group=nothingdns
WorkingDirectory=/var/lib/nothingdns
ExecStart=/usr/local/bin/nothingdns -config ${CONFIG_FILE}

# Reload configuration on SIGHUP
ExecReload=/bin/kill -HUP \$MAINPID

Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
TimeoutStopSec=30s

# Security - bind to privileged ports without running as root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW

# Hardening (keep in sync with deploy/nothingdns.service)
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
PrivateTmp=true
PrivateDevices=true
# /var/lib/nothingdns covers storage + Raft cluster/ subdirectory.
ReadWritePaths=/var/lib/nothingdns /var/log/nothingdns -/etc/nothingdns/zones

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nothingdns

[Install]
WantedBy=multi-user.target
EOF

        sudo install -m 0644 "${unit_tmp}" "${SERVICE_FILE}"
        rm -f "${unit_tmp}"
        sudo systemctl daemon-reload
        sudo systemctl enable nothingdns
        info "Service installed. Run 'sudo systemctl start nothingdns' to start"
    else
        warn "systemd not found, skipping service setup"
    fi
}

# Setup log rotation
setup_logrotate() {
    # Always rewrite: rules from older installers moved open log files away.
    if [ -d /etc/logrotate.d ]; then
        info "Setting up log rotation..."
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
        sudo install -m 0644 -o root -g root "${rotate_tmp}" /etc/logrotate.d/nothingdns
        rm -f "${rotate_tmp}"
        info "Log rotation configured"
    fi
}

# Main installation
main() {
    echo ""
    echo "======================================"
    echo "  NothingDNS Install Script v1.1"
    echo "======================================"
    echo ""

    local install_mode=""

    if is_interactive; then
        echo "Choose installation method:"
        echo "  1) Binary (recommended for servers)"
        echo "  2) Docker (GHCR: ghcr.io/nothingdns/nothingdns)"
        echo ""
        read_reply "Select [1/2]: "
        install_mode="$REPLY"
    else
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

    command -v curl &> /dev/null || error "curl is required but not installed"
    repair_dead_resolved_stub

    detect_os
    get_latest_version
    check_existing_install

    if ! check_port_53; then
        explain_port_53_conflict
        if is_interactive; then
            echo "Choose how to continue:"
            echo "  1) Free port 53 — stop/disable the service(s) above and install on port 53"
            echo "     (recommended for a primary DNS server; Ubuntu resolved stub is kept alive"
            echo "      without binding :53 so host name resolution still works)"
            echo "  2) Keep existing DNS — install NothingDNS on port 5353 instead"
            echo "  3) Cancel installation"
            echo ""
            read_reply "Select [1/2/3] (default 1): "
            case "${REPLY:-1}" in
                2)
                    info "Using port 5353 instead of 53"
                    USE_PORT_5353=true
                    ;;
                3) error "Installation cancelled" ;;
                *)
                    TAKE_PORT_53=true
                    info "Will free port 53 after binaries are downloaded and verified."
                    ;;
            esac
        elif [ "${STOP_HOST_DNS}" = "1" ]; then
            info "NOTHINGDNS_STOP_HOST_DNS=1 — existing DNS services will release port 53 after the download is verified"
            TAKE_PORT_53=true
        elif port_53_only_resolved_stub; then
            # Ubuntu/Debian default: only the resolved stub holds :53 on
            # 127.0.0.53/54. Freeing it via DNSStubListener=no is the planned
            # primary-DNS install path and keeps host resolution working.
            info "Only systemd-resolved stub listeners hold port 53 — freeing them for NothingDNS on port 53."
            TAKE_PORT_53=true
        else
            warn "Port 53 is in use by a non-stub DNS service and this install cannot prompt."
            warn "Falling back to port 5353 to avoid disrupting host DNS."
            warn "To take over port 53: re-run on a TTY, or set NOTHINGDNS_STOP_HOST_DNS=1."
            USE_PORT_5353=true
        fi
    fi

    # Download and verify everything before touching host DNS: the downloads
    # themselves need working name resolution.
    fetch_checksums
    download_binary
    download_dnsctl
    stop_existing_nothingdns

    if [ "${TAKE_PORT_53}" = true ]; then
        release_port_53
        if ! check_port_53; then
            warn "Port 53 is still in use after stopping known DNS services:"
            explain_port_53_conflict
            warn "Restoring previous DNS setup and completing install on port 5353 instead."
            restore_host_dns
            TAKE_PORT_53=false
            USE_PORT_5353=true
        else
            info "Port 53 is free — continuing install as the system DNS on port 53."
        fi
    fi

    local port=53
    if [ "$USE_PORT_5353" = true ]; then
        port=5353
        info "Using port 5353 instead of 53"
    fi

    create_config $port
    setup_service
    setup_logrotate

    info "Starting NothingDNS..."
    if command -v systemctl &> /dev/null; then
        sudo systemctl restart nothingdns
        sleep 2
        if ! systemctl is-active --quiet nothingdns; then
            warn "NothingDNS failed to start. Recent log:"
            sudo journalctl -u nothingdns -n 30 --no-pager 2>/dev/null || true
            if [ "${TAKE_PORT_53}" = true ]; then
                restore_host_dns
            fi
        fi
    else
        sudo "${INSTALL_DIR}/${BINARY_NAME}" -config "${CONFIG_FILE}" &
        sleep 3
    fi

    create_bootstrap_user

    echo ""
    echo "======================================"
    echo -e "${GREEN}  Installation Complete!${NC}"
    echo "======================================"
    echo ""
    echo "Dashboard: http://<this-host>:8080"
    echo ""
    if [ -n "${BOOTSTRAP_PASS}" ]; then
        echo "Login: user '${BOOTSTRAP_USER}', password in ${CONFIG_DIR}/credentials"
        echo "  sudo cat ${CONFIG_DIR}/credentials"
    fi
    echo "DNS port: ${port}"
    echo ""
    echo "Edit config: sudo nano ${CONFIG_FILE}"
    echo ""
    echo "Docker alternative:"
    echo "  docker pull ghcr.io/nothingdns/nothingdns:latest"
    echo "======================================"
    echo ""
}

main "$@"
