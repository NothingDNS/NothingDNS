#!/usr/bin/env bash
# Isolated backup/restore contract test; writes only below a temporary directory.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/nothingdns-backup-smoke.XXXXXX")"
cleanup() { rm -rf -- "${work}"; }
trap cleanup EXIT

source_root="${work}/source"
restore_root="${work}/restore"
backup_dir="${work}/backups"
mkdir -p "${source_root}/config" "${source_root}/zones/sub" "${source_root}/data/raft" "${backup_dir}"
printf 'server:\n  port: 5353\n' >"${source_root}/config/nothingdns.yaml"
printf 'example.com. 60 IN A 192.0.2.10\n' >"${source_root}/zones/example.com.zone"
printf 'nested-zone-data\n' >"${source_root}/zones/sub/nested.zone"
printf 'kv-state\n' >"${source_root}/data/zones.kv"
printf 'wal-state\n' >"${source_root}/data/raft/raft.wal"

NOTHINGDNS_CONFIG_FILE="${source_root}/config/nothingdns.yaml" \
NOTHINGDNS_ZONES_DIR="${source_root}/zones" \
NOTHINGDNS_DATA_DIR="${source_root}/data" \
NOTHINGDNS_BACKUP_RETENTION=2 \
NOTHINGDNS_BACKUP_ALLOW_LIVE=1 \
    "${ROOT_DIR}/scripts/backup.sh" "${backup_dir}"

archive="$(find "${backup_dir}" -maxdepth 1 -name 'nothingdns-backup-*.tar.gz' -print -quit)"
test -n "${archive}"
(
    cd "${backup_dir}"
    sha256sum -c "$(basename "${archive}.sha256")"
)
archive_entries="${work}/archive-entries.txt"
tar -tzf "${archive}" >"${archive_entries}"
grep -Fxq 'config/nothingdns.yaml' "${archive_entries}"
grep -Fxq 'zones/example.com.zone' "${archive_entries}"
grep -Fxq 'data/zones.kv' "${archive_entries}"
grep -Fxq 'data/raft/raft.wal' "${archive_entries}"

mkdir -p "${restore_root}"
NOTHINGDNS_CONFIG_FILE="${restore_root}/config/nothingdns.yaml" \
NOTHINGDNS_ZONES_DIR="${restore_root}/zones" \
NOTHINGDNS_DATA_DIR="${restore_root}/data" \
NOTHINGDNS_RESTORE_ALLOW_LIVE=1 \
    "${ROOT_DIR}/scripts/restore.sh" "${archive}"

cmp "${source_root}/config/nothingdns.yaml" "${restore_root}/config/nothingdns.yaml"
diff -ru "${source_root}/zones" "${restore_root}/zones"
diff -ru "${source_root}/data" "${restore_root}/data"

# Explicit overwrite must replace targets while retaining pre-restore rollback copies.
printf 'operator-local-config\n' >"${restore_root}/config/nothingdns.yaml"
printf 'operator-local-zone\n' >"${restore_root}/zones/local.zone"
printf 'operator-local-data\n' >"${restore_root}/data/local.kv"
NOTHINGDNS_CONFIG_FILE="${restore_root}/config/nothingdns.yaml" \
NOTHINGDNS_ZONES_DIR="${restore_root}/zones" \
NOTHINGDNS_DATA_DIR="${restore_root}/data" \
NOTHINGDNS_RESTORE_ALLOW_LIVE=1 \
NOTHINGDNS_RESTORE_OVERWRITE=1 \
    "${ROOT_DIR}/scripts/restore.sh" "${archive}"
cmp "${source_root}/config/nothingdns.yaml" "${restore_root}/config/nothingdns.yaml"
test -n "$(find "${restore_root}/config" -maxdepth 1 -name 'nothingdns.yaml.pre-restore-*' -print -quit)"
test -n "$(find "${restore_root}" -maxdepth 1 -name 'zones.pre-restore-*' -type d -print -quit)"
test -n "$(find "${restore_root}" -maxdepth 1 -name 'data.pre-restore-*' -type d -print -quit)"

# Checksum corruption must fail before any restore target is created.
printf 'corrupt' >>"${archive}"
corrupt_root="${work}/corrupt-restore"
if NOTHINGDNS_CONFIG_FILE="${corrupt_root}/config/nothingdns.yaml" \
   NOTHINGDNS_ZONES_DIR="${corrupt_root}/zones" \
   NOTHINGDNS_DATA_DIR="${corrupt_root}/data" \
   NOTHINGDNS_RESTORE_ALLOW_LIVE=1 \
       "${ROOT_DIR}/scripts/restore.sh" "${archive}" >/dev/null 2>&1; then
    echo "restore unexpectedly accepted a corrupt backup" >&2
    exit 1
fi
test ! -e "${corrupt_root}"

# An archive outside the versioned NothingDNS layout must be rejected even
# when its checksum is valid.
unsafe_dir="${work}/unsafe"
unsafe_archive="${work}/unsafe.tar.gz"
mkdir -p "${unsafe_dir}"
printf 'escape-attempt\n' >"${unsafe_dir}/unexpected.txt"
tar -C "${unsafe_dir}" -czf "${unsafe_archive}" unexpected.txt
(
    cd "${work}"
    sha256sum "$(basename "${unsafe_archive}")" >"$(basename "${unsafe_archive}").sha256"
)
unsafe_root="${work}/unsafe-restore"
if NOTHINGDNS_CONFIG_FILE="${unsafe_root}/config/nothingdns.yaml" \
   NOTHINGDNS_ZONES_DIR="${unsafe_root}/zones" \
   NOTHINGDNS_DATA_DIR="${unsafe_root}/data" \
   NOTHINGDNS_RESTORE_ALLOW_LIVE=1 \
       "${ROOT_DIR}/scripts/restore.sh" "${unsafe_archive}" >/dev/null 2>&1; then
    echo "restore unexpectedly accepted an unsafe archive layout" >&2
    exit 1
fi
test ! -e "${unsafe_root}"

echo "backup/restore smoke passed"
