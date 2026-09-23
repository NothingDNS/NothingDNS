#!/usr/bin/env bash
# Local integration test for install.sh credential / bootstrap helpers.
# Spins up a temporary nothingdns on free ports (no sudo, no /etc).
#
# Usage:
#   go build -o /tmp/ndns-test/nothingdns ./cmd/nothingdns
#   ./scripts/test-install-credentials.sh [/path/to/nothingdns]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-/tmp/ndns-test/nothingdns}"
if [ ! -x "${BIN}" ]; then
    mkdir -p "$(dirname "${BIN}")"
    echo "Building ${BIN}..."
    (cd "${ROOT}" && CGO_ENABLED=0 go build -o "${BIN}" ./cmd/nothingdns)
fi

pick_port() {
    python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
}

HTTP_PORT="$(pick_port)"
DNS_PORT="$(pick_port)"
METRICS_PORT="$(pick_port)"
BASE="$(mktemp -d /tmp/ndns-cred-test.XXXXXX)"
CONFIG_DIR="${BASE}/etc"
DATA_DIR="${BASE}/data"
CONFIG_FILE="${CONFIG_DIR}/nothingdns.yaml"
AUTH_SECRET="$(openssl rand -base64 48 | tr -d '\n')"
BOOTSTRAP_USER="admin"
BOOTSTRAP_PASS=""
BOOTSTRAP_HTTP_BODY=""
BOOTSTRAP_HTTP_CODE=""
SERVER_PID=""

mkdir -p "${CONFIG_DIR}/zones" "${DATA_DIR}/cluster"
chmod 700 "${CONFIG_DIR}" "${DATA_DIR}"

info() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*"; }

write_credentials_secret() {
    local secret="$1" tmp existing_user existing_pass
    tmp=$(mktemp)
    existing_user=$(grep -E '^username:' "${CONFIG_DIR}/credentials" 2>/dev/null | head -1 | sed 's/^username:[[:space:]]*//' || true)
    existing_pass=$(grep -E '^password:' "${CONFIG_DIR}/credentials" 2>/dev/null | head -1 | sed 's/^password:[[:space:]]*//' || true)
    {
        printf 'api_auth_secret: %s\n' "${secret}"
        if [ -n "${existing_pass}" ]; then
            printf 'username: %s\n' "${existing_user:-admin}"
            printf 'password: %s\n' "${existing_pass}"
        fi
    } > "${tmp}"
    cp "${tmp}" "${CONFIG_DIR}/credentials"
    rm -f "${tmp}"
    chmod 600 "${CONFIG_DIR}/credentials"
}

write_credentials_admin() {
    local user="$1" pass="$2" secret tmp
    secret=$(grep -E '^api_auth_secret:' "${CONFIG_DIR}/credentials" 2>/dev/null | head -1 | sed 's/^api_auth_secret:[[:space:]]*//' || true)
    if [ -z "${secret}" ] && [ -n "${AUTH_SECRET:-}" ]; then
        secret="${AUTH_SECRET}"
    fi
    tmp=$(mktemp)
    {
        if [ -n "${secret}" ]; then
            printf 'api_auth_secret: %s\n' "${secret}"
        fi
        printf 'username: %s\n' "${user}"
        printf 'password: %s\n' "${pass}"
    } > "${tmp}"
    cp "${tmp}" "${CONFIG_DIR}/credentials"
    rm -f "${tmp}"
    chmod 600 "${CONFIG_DIR}/credentials"
}

load_credentials_admin() {
    BOOTSTRAP_USER=$(grep -E '^username:' "${CONFIG_DIR}/credentials" 2>/dev/null | head -1 | sed 's/^username:[[:space:]]*//' || true)
    BOOTSTRAP_PASS=$(grep -E '^password:' "${CONFIG_DIR}/credentials" 2>/dev/null | head -1 | sed 's/^password:[[:space:]]*//' || true)
    BOOTSTRAP_USER="${BOOTSTRAP_USER:-admin}"
}

wait_for_api() {
    local max_attempts="${1:-40}" attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if curl -s --max-time 2 "http://127.0.0.1:${HTTP_PORT}/health" > /dev/null 2>&1; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 0.25
    done
    return 1
}

post_bootstrap() {
    local user="$1" pass="$2" raw
    raw=$(curl -s -w '\n%{http_code}' -X POST "http://127.0.0.1:${HTTP_PORT}/api/v1/auth/bootstrap" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${user}\",\"password\":\"${pass}\"}" 2>&1) || true
    BOOTSTRAP_HTTP_CODE=$(printf '%s\n' "${raw}" | tail -n1)
    BOOTSTRAP_HTTP_BODY=$(printf '%s\n' "${raw}" | sed '$d')
}

bootstrap_succeeded() {
    [ "${BOOTSTRAP_HTTP_CODE}" = "200" ] && echo "${BOOTSTRAP_HTTP_BODY}" | grep -qE '"token"[[:space:]]*:'
}

start_server() {
    "${BIN}" -config "${CONFIG_FILE}" > "${BASE}/server.log" 2>&1 &
    SERVER_PID=$!
}

stop_server() {
    if [ -n "${SERVER_PID:-}" ]; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
        SERVER_PID=""
    fi
}

reset_runtime_users() {
    info "Resetting runtime users..."
    stop_server
    rm -f "${DATA_DIR}/users.json"
    start_server
    wait_for_api 40 || return 1
    return 0
}

print_login_summary() {
    load_credentials_admin
    echo ""
    if [ -n "${BOOTSTRAP_PASS}" ]; then
        echo "Dashboard login:"
        echo "  Username: ${BOOTSTRAP_USER}"
        echo "  Password: ${BOOTSTRAP_PASS}"
        echo "  Saved in: ${CONFIG_DIR}/credentials"
    else
        echo "Admin login was not written."
        return 1
    fi
}

create_bootstrap_user() {
    BOOTSTRAP_USER="admin"
    BOOTSTRAP_PASS=$(openssl rand -base64 32 2>/dev/null | tr -d '/+=\n' | head -c 16)
    if [ ${#BOOTSTRAP_PASS} -lt 12 ]; then
        BOOTSTRAP_PASS=$(head -c 48 /dev/urandom | base64 | tr -d '/+=\n' | head -c 16)
    fi

    info "Waiting for server..."
    if ! wait_for_api 40; then
        BOOTSTRAP_PASS=""
        warn "Server did not start"
        tail -20 "${BASE}/server.log" || true
        return 1
    fi

    local existing_pass existing_user
    existing_pass=$(grep -E '^password:' "${CONFIG_DIR}/credentials" 2>/dev/null | head -1 | sed 's/^password:[[:space:]]*//' || true)
    existing_user=$(grep -E '^username:' "${CONFIG_DIR}/credentials" 2>/dev/null | head -1 | sed 's/^username:[[:space:]]*//' || true)
    if [ -n "${existing_pass}" ]; then
        BOOTSTRAP_USER="${existing_user:-admin}"
        BOOTSTRAP_PASS="${existing_pass}"
        write_credentials_admin "${BOOTSTRAP_USER}" "${BOOTSTRAP_PASS}"
        info "Using existing credentials"
        return 0
    fi

    write_credentials_admin "${BOOTSTRAP_USER}" "${BOOTSTRAP_PASS}"

    local attempt=0 max_attempts=5
    while [ $attempt -lt $max_attempts ]; do
        post_bootstrap "${BOOTSTRAP_USER}" "${BOOTSTRAP_PASS}"
        if bootstrap_succeeded; then
            info "Bootstrap OK"
            return 0
        fi
        attempt=$((attempt + 1))
        if [ "${BOOTSTRAP_HTTP_CODE}" = "000" ] || [ "${BOOTSTRAP_HTTP_CODE}" = "503" ] || [ -z "${BOOTSTRAP_HTTP_CODE}" ]; then
            sleep 1
            continue
        fi
        break
    done

    if echo "${BOOTSTRAP_HTTP_BODY}" | grep -qiE 'Old password required|already exists|Conflict|Invalid old password'; then
        warn "Bootstrap blocked: ${BOOTSTRAP_HTTP_BODY}"
        if reset_runtime_users; then
            post_bootstrap "${BOOTSTRAP_USER}" "${BOOTSTRAP_PASS}"
            if bootstrap_succeeded; then
                write_credentials_admin "${BOOTSTRAP_USER}" "${BOOTSTRAP_PASS}"
                info "Bootstrap OK after reset"
                return 0
            fi
        fi
    fi
    warn "Bootstrap failed HTTP=${BOOTSTRAP_HTTP_CODE} body=${BOOTSTRAP_HTTP_BODY}"
    return 1
}

cleanup() {
    stop_server
    rm -rf "${BASE}"
}
trap cleanup EXIT

cat > "${CONFIG_FILE}" << EOF
server:
  port: ${DNS_PORT}
  bind:
    - 127.0.0.1
  http:
    enabled: true
    bind: "127.0.0.1:${HTTP_PORT}"
    auth_secret: "${AUTH_SECRET}"
upstream:
  strategy: round_robin
  servers:
    - 1.1.1.1:53
  health_check: 30s
  failover_timeout: 5s
cache:
  enabled: true
  size: 1000
dnssec:
  enabled: false
logging:
  level: warn
  format: text
metrics:
  enabled: true
  bind: "127.0.0.1:${METRICS_PORT}"
storage:
  data_dir: ${DATA_DIR}
cluster:
  enabled: false
  data_dir: ${DATA_DIR}/cluster
EOF

write_credentials_secret "${AUTH_SECRET}"

echo "======== TEST 1: fresh install bootstrap ========"
if grep -q '^username:' "${CONFIG_DIR}/credentials"; then
    echo "FAIL: username present before bootstrap"
    exit 1
fi
start_server
create_bootstrap_user
OUT="$(print_login_summary)"
echo "${OUT}"
echo "${OUT}" | grep -q 'Username: admin'
echo "${OUT}" | grep -q 'Password: '
grep -q "^api_auth_secret: ${AUTH_SECRET}$" "${CONFIG_DIR}/credentials"
grep -q '^username: admin$' "${CONFIG_DIR}/credentials"
PASS1=$(grep '^password:' "${CONFIG_DIR}/credentials" | sed 's/^password:[[:space:]]*//')
[ ${#PASS1} -ge 12 ]
LOGIN=$(curl -s -w '\n%{http_code}' -X POST "http://127.0.0.1:${HTTP_PORT}/api/v1/auth/login" \
    -H 'Content-Type: application/json' -d "{\"username\":\"admin\",\"password\":\"${PASS1}\"}")
[ "$(printf '%s\n' "${LOGIN}" | tail -n1)" = "200" ]
echo "TEST 1 PASS"

echo "======== TEST 2: secret refresh preserves user/pass ========"
write_credentials_secret 'rotated-secret-xyz'
grep -q 'api_auth_secret: rotated-secret-xyz' "${CONFIG_DIR}/credentials"
grep -q 'username: admin' "${CONFIG_DIR}/credentials"
grep -q "password: ${PASS1}" "${CONFIG_DIR}/credentials"
echo "TEST 2 PASS"

echo "======== TEST 3: reinstall keeps existing credentials ========"
create_bootstrap_user
[ "${BOOTSTRAP_PASS}" = "${PASS1}" ]
echo "TEST 3 PASS"

echo "======== TEST 4: wiped credentials + stale users.json reclaim ========"
printf 'api_auth_secret: %s\n' "${AUTH_SECRET}" > "${CONFIG_DIR}/credentials"
chmod 600 "${CONFIG_DIR}/credentials"
[ -f "${DATA_DIR}/users.json" ]
create_bootstrap_user
print_login_summary >/dev/null
PASS4=$(grep '^password:' "${CONFIG_DIR}/credentials" | sed 's/^password:[[:space:]]*//')
USER4=$(grep '^username:' "${CONFIG_DIR}/credentials" | sed 's/^username:[[:space:]]*//')
[ -n "${PASS4}" ] && [ -n "${USER4}" ]
LOGIN=$(curl -s -w '\n%{http_code}' -X POST "http://127.0.0.1:${HTTP_PORT}/api/v1/auth/login" \
    -H 'Content-Type: application/json' -d "{\"username\":\"${USER4}\",\"password\":\"${PASS4}\"}")
[ "$(printf '%s\n' "${LOGIN}" | tail -n1)" = "200" ]
echo "TEST 4 PASS"

echo "======== TEST 5: password-only legacy file ========"
printf 'api_auth_secret: s\npassword: onlypass123456\n' > "${CONFIG_DIR}/credentials"
write_credentials_secret 's2'
grep -q 'username: admin' "${CONFIG_DIR}/credentials"
grep -q 'password: onlypass123456' "${CONFIG_DIR}/credentials"
echo "TEST 5 PASS"

echo "======== TEST 6: finish banner shape ========"
SUMMARY="$(print_login_summary)"
echo "${SUMMARY}" | grep -q 'Dashboard login:'
echo "${SUMMARY}" | grep -q 'Username:'
echo "${SUMMARY}" | grep -q 'Password:'
echo "${SUMMARY}" | grep -q 'Saved in:'
echo "TEST 6 PASS"

echo ""
echo "ALL LOCAL CREDENTIAL TESTS PASSED"
