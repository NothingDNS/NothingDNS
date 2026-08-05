#!/usr/bin/env bash
# NothingDNS consistent backup archive creator.
# Usage: ./scripts/backup.sh [/path/to/backupdir]
# Stop the daemon (or snapshot its volume) before running so WAL/KV files are
# captured at one point in time.

set -euo pipefail

BACKUP_DIR="${1:-/var/backups/nothingdns}"
CONFIG_FILE="${NOTHINGDNS_CONFIG_FILE:-/etc/nothingdns/nothingdns.yaml}"
ZONES_DIR="${NOTHINGDNS_ZONES_DIR:-/etc/nothingdns/zones}"
DATA_DIR="${NOTHINGDNS_DATA_DIR:-/var/lib/nothingdns}"
RETENTION_COUNT="${NOTHINGDNS_BACKUP_RETENTION:-7}"
DATE="$(date -u +%Y%m%d_%H%M%S)"
BACKUP_FILE="nothingdns-backup-${DATE}.tar.gz"

if [[ ! "${RETENTION_COUNT}" =~ ^[0-9]+$ ]] || (( RETENTION_COUNT < 1 )); then
    echo "NOTHINGDNS_BACKUP_RETENTION must be a positive integer" >&2
    exit 2
fi
if [[ ! -f "${CONFIG_FILE}" ]]; then
    echo "required config file not found: ${CONFIG_FILE}" >&2
    exit 1
fi
if command -v systemctl >/dev/null 2>&1 && \
   systemctl is-active --quiet nothingdns 2>/dev/null && \
   [[ "${NOTHINGDNS_BACKUP_ALLOW_LIVE:-0}" != "1" ]]; then
    echo "nothingdns is running; stop it or set NOTHINGDNS_BACKUP_ALLOW_LIVE=1 after taking a consistent volume snapshot" >&2
    exit 1
fi

mkdir -p "${BACKUP_DIR}"
staging="$(mktemp -d "${BACKUP_DIR}/.nothingdns-backup.XXXXXX")"
archive_tmp="${BACKUP_DIR}/.${BACKUP_FILE}.tmp"
cleanup() {
    rm -rf -- "${staging}"
    rm -f -- "${archive_tmp}"
}
trap cleanup EXIT

mkdir -p "${staging}/config" "${staging}/zones" "${staging}/data"
cp -a -- "${CONFIG_FILE}" "${staging}/config/nothingdns.yaml"
if [[ -d "${ZONES_DIR}" ]]; then
    cp -a -- "${ZONES_DIR}/." "${staging}/zones/"
fi
if [[ -d "${DATA_DIR}" ]]; then
    cp -a -- "${DATA_DIR}/." "${staging}/data/"
fi

cat >"${staging}/MANIFEST.txt" <<EOF
format=1
created_at=${DATE}
config=config/nothingdns.yaml
zones=zones/
data=data/
EOF

echo "Creating ${BACKUP_DIR}/${BACKUP_FILE}..."
tar -C "${staging}" -czf "${archive_tmp}" MANIFEST.txt config zones data
mv -f -- "${archive_tmp}" "${BACKUP_DIR}/${BACKUP_FILE}"
(
    cd "${BACKUP_DIR}"
    sha256sum "${BACKUP_FILE}" >"${BACKUP_FILE}.sha256"
)

mapfile -t expired < <(
    find "${BACKUP_DIR}" -maxdepth 1 -type f -name 'nothingdns-backup-*.tar.gz' \
        -printf '%T@ %p\n' | sort -nr | tail -n "+$((RETENTION_COUNT + 1))" | cut -d' ' -f2-
)
for old_archive in "${expired[@]}"; do
    rm -f -- "${old_archive}" "${old_archive}.sha256"
done

echo "Backup complete: ${BACKUP_DIR}/${BACKUP_FILE}"
echo "Checksum: ${BACKUP_DIR}/${BACKUP_FILE}.sha256"