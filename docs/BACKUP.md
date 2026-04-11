# NothingDNS Backup & Recovery Guide

> Automated backup strategy for NothingDNS KV store and WAL

---

## Overview

NothingDNS stores all zone data and state in two key locations:

| Component | Default Path | Purpose |
|-----------|-------------|---------|
| KV Store | `data/nothingdns.db` | Primary data storage |
| WAL | `data/nothingdns.wal` | Write-Ahead Log for crash recovery |

Both are located under the `--data-dir` flag (default: `./data`).

---

## Backup Strategy

### 1. Online Backup (Recommended)

NothingDNS supports hot-backup via SIGUSR1 signal:

```bash
# Trigger online backup (creates data/nothingdns-backup-{timestamp}.db)
kill -USR1 $(pidof nothingdns)
```

This snapshots the KV store without stopping the server.

### 2. Filesystem Snapshots

For production, use filesystem-level snapshots:

```bash
# Btrfs
btrfs subvolume snapshot /var/lib/nothingdns /var/lib/nothingdns/backups/$(date +%Y%m%d)

# ZFS
zfs snapshot tank/nothingdns@$(date +%Y%m%d)

# LVM
lvcreate --snapshot --size=1G --name=nothingdns-backup /dev/vg0/nothingdns
```

### 3. Continuous Backup with WAL

The WAL provides point-in-time recovery. Rotate WAL segments:

```bash
# In data/ directory, WAL files are: nothingdns.wal, nothingdns.wal.1, nothingdns.wal.2, ...
# Old segments are automatically recycled during normal operation
```

---

## Recovery Procedures

### 1. Point-in-Time Recovery

To recover to a specific point in time:

```bash
# Stop the server
systemctl stop nothingdns

# Restore KV store from backup
cp data/nothingdns-backup-20260411.db data/nothingdns.db

# Remove WAL to replay from backup point
rm data/nothingdns.wal*

# Start the server
systemctl start nothingdns
```

### 2. Crash Recovery

NothingDNS automatically replays WAL on startup. No manual action needed.

### 3. Full Disaster Recovery

```bash
# 1. Restore from last known good backup
cp /backup/nothingdns-20260410.db /var/lib/nothingdns/data/nothingdns.db

# 2. Start server - WAL replay brings it up to date
./nothingdns --config /etc/nothingdns/production.yaml

# 3. Verify zone integrity
./dnsctl zone list
./dnsctl zone verify example.com
```

---

## Automated Backup Script

Add to crontab for daily backups:

```bash
#!/bin/bash
# /etc/cron.d/nothingdns-backup

BACKUP_DIR="/backups/nothingdns"
DATA_DIR="/var/lib/nothingdns/data"
RETENTION_DAYS=30

mkdir -p "$BACKUP_DIR"

# Hot backup trigger
kill -USR1 $(pidof nothingdns) 2>/dev/null || true

# Copy with timestamp
cp "$DATA_DIR/nothingdns.db" "$BACKUP_DIR/nothingdns-$(date +%Y%m%d).db"

# Rotate old backups
find "$BACKUP_DIR" -name "nothingdns-*.db" -mtime +$RETENTION_DAYS -delete

# Also backup WAL segments
cp "$DATA_DIR"/nothingdns.wal* "$BACKUP_DIR/"

echo "Backup completed: $(date)" >> "$BACKUP_DIR/backup.log"
```

Crontab entry:
```
0 2 * * * /etc/cron.d/nothingdns-backup
```

---

## Backup Verification

Always verify backups can be restored:

```bash
# Test restore in isolation
./nothingdns --config /etc/nothingdns/test-backup.yaml --data-dir /tmp/test-restore

# Verify zones load correctly
./dnsctl zone list
```

---

## Replication (Cluster Mode)

When running in cluster mode with `cache_sync: true`, zone data is replicated across nodes. However, this does NOT replace backups — still maintain offline backups.

---

## Quick Reference

| Action | Command |
|--------|---------|
| Hot backup | `kill -USR1 $(pidof nothingdns)` |
| Check data dir | `./dnsctl info` |
| Verify integrity | `./dnsctl zone verify <zone>` |
| Export zone | `./dnsctl zone export <zone> --format=bind -o zone.txt` |

---

*Document Version: 1.0*
*Generated: 2026-04-11*
