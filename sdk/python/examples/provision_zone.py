"""Idempotent zone provisioning with NothingDNS.

Creates a zone if it is missing and reconciles a desired set of records against
what the server already has. Run with ``--dry-run`` to see the diff without
touching the server.

Usage:
    export NDNS_URL="http://dns.example.com:8080"
    export NDNS_USER="admin"
    export NDNS_PASSWORD="..."
    python examples/provision_zone.py example.com \\
        --nameserver ns1.example.com --nameserver ns2.example.com \\
        --record "www A 192.0.2.1" \\
        --record "@ TXT 'v=spf1 mx -all'"
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Tuple

from nothingdns import NothingDNSApiError, NothingDNSClient, is_not_found

DesiredRecord = Tuple[str, str, str, int]


def parse_record(raw: str) -> DesiredRecord:
    """Parse ``name TYPE data [ttl]`` (the data may contain spaces, e.g. TXT)."""
    parts = raw.split(None, 3)
    if len(parts) < 3:
        raise argparse.ArgumentTypeError(
            f"invalid record {raw!r}; expected 'name TYPE data [ttl]'"
        )
    name, rtype, data = parts[0], parts[1].upper(), parts[2]
    ttl = int(parts[3]) if len(parts) == 4 and parts[3].isdigit() else 3600
    return name, rtype, data, ttl


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision a zone with the NothingDNS SDK")
    parser.add_argument("zone", help="zone name, e.g. example.com")
    parser.add_argument("--nameserver", action="append", required=True, dest="nameservers",
                        help="NS hostname; repeat for each nameserver")
    parser.add_argument("--admin-email", help="zone admin e-mail for the SOA rname")
    parser.add_argument("--ttl", type=int, default=3600, help="zone default TTL")
    parser.add_argument("--record", action="append", default=[], dest="records",
                        type=parse_record, help="desired record 'name TYPE data [ttl]'; repeatable")
    parser.add_argument("--dry-run", action="store_true", help="report changes without applying them")
    args = parser.parse_args()

    base_url = os.environ.get("NDNS_URL", "http://localhost:8080")
    changes: List[str] = []

    with NothingDNSClient(base_url, timeout=20.0) as client:
        token = os.environ.get("NDNS_TOKEN")
        if token:
            client.set_token(token)
        else:
            username = os.environ.get("NDNS_USER", "admin")
            password = os.environ.get("NDNS_PASSWORD")
            if not password:
                print("set NDNS_PASSWORD (or NDNS_TOKEN) before running", file=sys.stderr)
                return 2
            client.auth.login(username, password)

        # 1. Make sure the zone exists.
        try:
            detail = client.zones.get(args.zone)
            print(f"zone {detail.name} exists (serial {detail.serial}, {detail.records} records)")
        except NothingDNSApiError as exc:
            if not is_not_found(exc):
                raise
            print(f"zone {args.zone} does not exist yet")
            if args.dry_run:
                changes.append(f"create zone {args.zone}")
            else:
                client.zones.create(
                    args.zone,
                    nameservers=args.nameservers,
                    admin_email=args.admin_email,
                    ttl=args.ttl,
                )
                print(f"  created with NS {', '.join(args.nameservers)}")
            detail = None

        if not args.records:
            print("no records requested")
            return 0

        # 2. Reconcile the desired records against the current ones.
        existing = client.zones.list_records(args.zone).records
        have = {(r.name, r.type, r.data) for r in existing}

        for name, rtype, data, ttl in args.records:
            key = (name, rtype, data)
            if key in have:
                print(f"  ok       {name} {rtype} {data}")
                continue
            # A different value for the same (name, type) means "replace".
            current = next((r for r in existing if r.name == name and r.type == rtype), None)
            if current is not None:
                changes.append(f"replace {name} {rtype} {current.data} -> {data}")
                if not args.dry_run:
                    client.zones.replace_record(args.zone, name, rtype, current.data, data, ttl=ttl)
                    print(f"  replaced {name} {rtype} {current.data} -> {data}")
            else:
                changes.append(f"add {name} {rtype} {data}")
                if not args.dry_run:
                    client.zones.add_record(args.zone, name, rtype, data, ttl=ttl)
                    print(f"  added    {name} {rtype} {data} (ttl {ttl})")

    if args.dry_run:
        print(f"\ndry run — {len(changes)} change(s) would be applied:")
        for change in changes:
            print(f"  - {change}")
    else:
        print(f"\napplied {len(changes)} change(s)")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except NothingDNSApiError as exc:
        print(f"API error {exc.status_code}: {exc.message}", file=sys.stderr)
        sys.exit(1)
