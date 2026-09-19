#!/usr/bin/env bash
# Validates every configuration this repository ships or generates with the
# real server binary (-validate-config), so a sample or installer config the
# server would refuse to start with fails CI instead of a user's install.
#
# Covers: config.example.yaml, deploy/*.yaml, deploy/docker/nothingdns.yaml,
# the Kubernetes ConfigMap, and the configs written by install.sh, setup.sh
# and install.ps1. The Helm chart's rendered config is validated by the helm
# job in .github/workflows/go.yml.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

BIN="${WORK}/nothingdns"
(cd "${ROOT_DIR}" && CGO_ENABLED=0 go build -o "${BIN}" ./cmd/nothingdns)

# Placeholder values for ${VAR} references in the deployment configs.
export NOTHINGDNS_METRICS_AUTH_TOKEN="ci-metrics-token-0123456789abcdef0123"
export NOTHINGDNS_AUTH_SECRET="ci-auth-secret-0123456789abcdef0123456789"
export NOTHINGDNS_CLUSTER_ENCRYPTION_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
export NOTHINGDNS_AUTH_TOKEN="ci-api-token-0123456789abcdef0123456789ab"
export NOTHINGDNS_ADMIN_PASSWORD="Ci-Admin-Passw0rd-123"
export NOTHINGDNS_OPERATOR_PASSWORD="Ci-Operator-Passw0rd-123"
export NOTHINGDNS_VIEWER_PASSWORD="Ci-Viewer-Passw0rd-123"
export NOTHINGDNS_STORAGE_ENCRYPTION_KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
export NOTHINGDNS_CLUSTER_SNAPSHOT_ENCRYPTION_KEY="ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
export POD_NAME="nothingdns-0"
export POD_IP="10.0.0.10"

failures=0
check() {
    local name="$1" file="$2" dir="${3:-${ROOT_DIR}}"
    local out
    # Deployment configs reference zone files at their install location;
    # point them at the repository's example zone so only the config itself
    # is being judged.
    local staged
    staged="${WORK}/staged-$(basename "${file}")"
    sed -E "s#/etc/nothingdns/zones/([a-z]+/)?example\.com\.zone#${ROOT_DIR}/examples/example.com.zone#g" "${file}" > "${staged}"
    file="${staged}"
    if out=$(cd "${dir}" && "${BIN}" -config "${file}" -validate-config 2>&1); then
        if grep -q 'unknown key\|unknown top-level key' <<<"${out}"; then
            printf 'FAIL %s (unknown keys)\n%s\n' "${name}" "${out}"
            failures=$((failures + 1))
        else
            printf 'ok   %s\n' "${name}"
        fi
    else
        printf 'FAIL %s\n%s\n' "${name}" "${out}"
        failures=$((failures + 1))
    fi
}

# Extract a heredoc body that starts on the line matching $2 and ends at a
# line equal to $3.
extract() {
    awk -v start="$2" -v end="$3" 'index($0, start) { p = 1; next } p && $0 == end { exit } p' "$1"
}

check config.example.yaml "${ROOT_DIR}/config.example.yaml"
for f in "${ROOT_DIR}"/deploy/*.yaml; do
    check "deploy/$(basename "${f}")" "${f}"
done
check deploy/docker/nothingdns.yaml "${ROOT_DIR}/deploy/docker/nothingdns.yaml"

# Kubernetes ConfigMap: the nothingdns.yaml block is indented by 4 spaces.
awk '/nothingdns.yaml: \|/ { p = 1; next } p && /^[^ ]/ { exit } p { sub(/^    /, ""); print }' \
    "${ROOT_DIR}/deploy/k8s/configmap.yaml" > "${WORK}/k8s.yaml"
check deploy/k8s/configmap.yaml "${WORK}/k8s.yaml"

render_installer_config() {
    sed -e 's/\${port}/53/g' \
        -e 's/\${AUTH_SECRET}/ci-auth-secret-0123456789abcdef0123456789/g' \
        -e 's/\${secret}/ci-auth-secret-0123456789abcdef0123456789/g' \
        -e 's/\${LATEST_VERSION}/v0.0.0/g' \
        -e 's/\${DATA_DIR_YAML}/C:\/ProgramData\/NothingDNS\/data/g' \
        -e 's/\$(date[^)]*)/now/g' \
        -e 's/\$(Get-Date[^)]*)/now/g'
}
extract "${ROOT_DIR}/install.sh" 'sudo tee "${CONFIG_FILE}" > /dev/null << EOF' 'EOF' | render_installer_config > "${WORK}/install-sh.yaml"
check "install.sh (generated config)" "${WORK}/install-sh.yaml"
extract "${ROOT_DIR}/setup.sh" 'sudo tee "${config_file}" > /dev/null << EOF' 'EOF' | render_installer_config > "${WORK}/setup-sh.yaml"
check "setup.sh (generated config)" "${WORK}/setup-sh.yaml"
extract "${ROOT_DIR}/install.ps1" '$CONFIG = @"' '"@' | render_installer_config > "${WORK}/install-ps1.yaml"
check "install.ps1 (generated config)" "${WORK}/install-ps1.yaml"

for f in install-sh setup-sh install-ps1; do
    [ -s "${WORK}/${f}.yaml" ] || { echo "FAIL could not extract ${f} config"; failures=$((failures + 1)); }
done

if [ "${failures}" -gt 0 ]; then
    echo "${failures} config(s) failed validation"
    exit 1
fi
echo "All shipped configs are valid"
