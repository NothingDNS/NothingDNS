"""NothingDNS SDK quick start.

Logs in, checks health, lists zones and their records, and adds a record.

Usage:
    export NDNS_URL="http://dns.example.com:8080"
    export NDNS_USER="admin"
    export NDNS_PASSWORD="..."          # or set NDNS_TOKEN for the static token
    python examples/quickstart.py
"""

from __future__ import annotations

import os
import sys

from nothingdns import (
    NothingDNSApiError,
    NothingDNSClient,
    NothingDNSConnectionError,
)


def main() -> int:
    base_url = os.environ.get("NDNS_URL", "http://localhost:8080")

    with NothingDNSClient(base_url, timeout=15.0) as client:
        # 1. Health probe needs no authentication.
        health = client.health()
        print(f"server health: {health.status} at {health.timestamp}")

        # 2. Authenticate. NDNS_TOKEN short-circuits the login round trip.
        token = os.environ.get("NDNS_TOKEN")
        if token:
            client.set_token(token)
            print("using the static service token")
        else:
            username = os.environ.get("NDNS_USER", "admin")
            password = os.environ.get("NDNS_PASSWORD")
            if not password:
                print("set NDNS_PASSWORD (or NDNS_TOKEN) before running", file=sys.stderr)
                return 2
            session = client.auth.login(username, password)
            print(f"signed in as {session.username} (role {session.role})")

        # 3. Server status.
        status = client.status()
        print(f"NothingDNS {status.version} is {status.status}")

        # 4. Zones.
        zones = client.zones.list()
        print(f"\n{len(zones.zones)} zone(s):")
        for zone in zones.zones:
            print(f"  {zone.name:<30} serial={zone.serial:<10} records={zone.records}")

        if zones.zones:
            first = zones.zones[0].name
            detail = client.zones.get(first)
            if detail.soa:
                print(f"\nSOA of {first}: {detail.soa.mname} serial {detail.soa.serial}")

            records = client.zones.list_records(first)
            print(f"\n{records.total} record(s) in {first}:")
            for record in records.records[:10]:
                print(f"  {record.name:<20} {record.type:<6} {record.ttl:<7} {record.data}")
            if records.total > len(records.records):
                print(f"  … {records.total - len(records.records)} more (response truncated)")

        # 5. Cache statistics (operator role and above).
        cache = client.cache.stats()
        print(
            f"\ncache: {cache.size}/{cache.capacity} entries, "
            f"hit ratio {cache.hit_ratio:.1%} ({cache.hits} hits / {cache.misses} misses)"
        )

        # 6. Write example: add a record, then remove it again.
        if os.environ.get("NDNS_DEMO_WRITE") and zones.zones:
            zone = zones.zones[0].name
            print(f"\nadding a TXT record to {zone} …")
            client.zones.add_record(zone, "sdk-demo", "TXT", '"added by the NothingDNS SDK"', ttl=60)
            print("done — remove it again with:")
            print(f"    client.zones.delete_records({zone!r}, 'sdk-demo', 'TXT')")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except NothingDNSApiError as exc:
        print(f"API error {exc.status_code}: {exc.message}", file=sys.stderr)
        sys.exit(1)
    except NothingDNSConnectionError as exc:
        print(f"cannot reach NothingDNS: {exc}", file=sys.stderr)
        sys.exit(1)
