#!/usr/bin/env bash
# Restore a NothingDNS backup created by scripts/backup.sh.
# Usage: ./scripts/restore.sh /path/to/nothingdns-backup-YYYYmmdd_HHMMSS.tar.gz

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 /path/to/nothingdns-backup-*.tar.gz" >&2
    exit 2
fi

ARCHIVE="$1"
CHECKSUM_FILE="${NOTHINGDNS_RESTORE_CHECKSUM:-${ARCHIVE}.sha256}"
CONFIG_FILE="${NOTHINGDNS_CONFIG_FILE:-/etc/nothingdns/nothingdns.yaml}"
ZONES_DIR="${NOTHINGDNS_ZONES_DIR:-/etc/nothingdns/zones}"
DATA_DIR="${NOTHINGDNS_DATA_DIR:-/var/lib/nothingdns}"
OVERWRITE="${NOTHINGDNS_RESTORE_OVERWRITE:-0}"
STAMP="$(date -u +%Y%m%d_%H%M%S)_$$"

if [[ ! -f "${ARCHIVE}" ]]; then
    echo "backup archive not found: ${ARCHIVE}" >&2
    exit 1
fi
if [[ ! -f "${CHECKSUM_FILE}" ]]; then
    echo "backup checksum not found: ${CHECKSUM_FILE}" >&2
    exit 1
fi
if command -v systemctl >/dev/null 2>&1 && \
   systemctl is-active --quiet nothingdns 2>/dev/null && \
   [[ "${NOTHINGDNS_RESTORE_ALLOW_LIVE:-0}" != "1" ]]; then
    echo "nothingdns is running; stop it before restore" >&2
    exit 1
fi

expected_hash="$(awk 'NR == 1 { print $1 }' "${CHECKSUM_FILE}")"
if [[ ! "${expected_hash}" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "invalid SHA-256 checksum file: ${CHECKSUM_FILE}" >&2
    exit 1
fi
actual_hash="$(sha256sum "${ARCHIVE}" | awk '{ print $1 }')"
if [[ "${actual_hash}" != "${expected_hash}" ]]; then
    echo "backup checksum verification failed: ${ARCHIVE}" >&2
    exit 1
fi

# Reject absolute paths, parent traversal, unexpected top-level entries, and
# links/special files before extraction. Only regular files and directories in
# the versioned NothingDNS archive layout are accepted.
archive_entries="$(mktemp "${TMPDIR:-/tmp}/nothingdns-archive-entries.XXXXXX")"
trap 'rm -f -- "${archive_entries}"' EXIT
tar -tzf "${ARCHIVE}" >"${archive_entries}"
while IFS= read -r entry; do
    normalized="${entry#./}"
    if [[ -z "${normalized}" || "${normalized}" == /* || "/${normalized}/" == *"/../"* ]]; then
        echo "unsafe backup archive path: ${entry}" >&2
        exit 1
    fi
    case "${normalized}" in
        MANIFEST.txt|config|config/*|zones|zones/*|data|data/*) ;;
        *)
            echo "unexpected backup archive entry: ${entry}" >&2
            exit 1
            ;;
    esac
done <"${archive_entries}"

if tar -tvzf "${ARCHIVE}" | awk 'substr($1, 1, 1) !~ /[-d]/ { exit 1 }'; then
    :
else
    echo "backup archive contains links or special files" >&2
    exit 1
fi
rm -f -- "${archive_entries}"
trap - EXIT

extract_dir="$(mktemp -d "${TMPDIR:-/tmp}/nothingdns-restore.XXXXXX")"
config_stage=""
zones_stage=""
data_stage=""
config_backup=""
zones_backup=""
data_backup=""
installed_config=0
installed_zones=0
installed_data=0
completed=0

rollback() {
    if (( completed == 0 )); then
        if (( installed_data == 1 )); then rm -rf -- "${DATA_DIR}"; fi
        if (( installed_zones == 1 )); then rm -rf -- "${ZONES_DIR}"; fi
        if (( installed_config == 1 )); then rm -f -- "${CONFIG_FILE}"; fi
        if [[ -n "${data_backup}" && -e "${data_backup}" ]]; then mv -- "${data_backup}" "${DATA_DIR}"; fi
        if [[ -n "${zones_backup}" && -e "${zones_backup}" ]]; then mv -- "${zones_backup}" "${ZONES_DIR}"; fi
        if [[ -n "${config_backup}" && -e "${config_backup}" ]]; then mv -- "${config_backup}" "${CONFIG_FILE}"; fi
    fi
    rm -rf -- "${extract_dir}"
    [[ -z "${config_stage}" ]] || rm -rf -- "${config_stage}"
    [[ -z "${zones_stage}" ]] || rm -rf -- "${zones_stage}"
    [[ -z "${data_stage}" ]] || rm -rf -- "${data_stage}"
    return 0
}
trap rollback EXIT

tar -xzf "${ARCHIVE}" -C "${extract_dir}"
if [[ ! -f "${extract_dir}/MANIFEST.txt" ]] || \
   ! grep -qx 'format=1' "${extract_dir}/MANIFEST.txt" || \
   [[ ! -f "${extract_dir}/config/nothingdns.yaml" ]]; then
    echo "unsupported or incomplete NothingDNS backup" >&2
    exit 1
fi

if [[ "${OVERWRITE}" != "1" ]] && \
   { [[ -e "${CONFIG_FILE}" ]] || [[ -e "${ZONES_DIR}" ]] || [[ -e "${DATA_DIR}" ]]; }; then
    echo "restore targets already exist; set NOTHINGDNS_RESTORE_OVERWRITE=1 to replace them" >&2
    exit 1
fi

mkdir -p -- "$(dirname "${CONFIG_FILE}")" "$(dirname "${ZONES_DIR}")" "$(dirname "${DATA_DIR}")"
config_stage="$(mktemp "$(dirname "${CONFIG_FILE}")/.nothingdns-config.XXXXXX")"
zones_stage="$(mktemp -d "$(dirname "${ZONES_DIR}")/.nothingdns-zones.XXXXXX")"
data_stage="$(mktemp -d "$(dirname "${DATA_DIR}")/.nothingdns-data.XXXXXX")"
install -m 0600 "${extract_dir}/config/nothingdns.yaml" "${config_stage}"
cp -a -- "${extract_dir}/zones/." "${zones_stage}/"
cp -a -- "${extract_dir}/data/." "${data_stage}/"

if [[ -e "${CONFIG_FILE}" ]]; then
    config_backup="${CONFIG_FILE}.pre-restore-${STAMP}"
    mv -- "${CONFIG_FILE}" "${config_backup}"
fi
mv -- "${config_stage}" "${CONFIG_FILE}"
config_stage=""
installed_config=1

if [[ -e "${ZONES_DIR}" ]]; then
    zones_backup="${ZONES_DIR}.pre-restore-${STAMP}"
    mv -- "${ZONES_DIR}" "${zones_backup}"
fi
mv -- "${zones_stage}" "${ZONES_DIR}"
zones_stage=""
installed_zones=1

if [[ -e "${DATA_DIR}" ]]; then
    data_backup="${DATA_DIR}.pre-restore-${STAMP}"
    mv -- "${DATA_DIR}" "${data_backup}"
fi
mv -- "${data_stage}" "${DATA_DIR}"
data_stage=""
installed_data=1

completed=1
echo "Restore complete. Validate config and start NothingDNS:"
echo "  nothingdns -config ${CONFIG_FILE} -validate-production-config"
if [[ -n "${config_backup}${zones_backup}${data_backup}" ]]; then
    echo "Pre-restore targets were retained until validation succeeds:"
    [[ -z "${config_backup}" ]] || echo "  ${config_backup}"
    [[ -z "${zones_backup}" ]] || echo "  ${zones_backup}"
    [[ -z "${data_backup}" ]] || echo "  ${data_backup}"
fi
