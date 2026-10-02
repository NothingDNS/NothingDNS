"""Poll a NothingDNS server and print a compact health line.

Usage:
    export NDNS_URL="http://dns.example.com:8080"
    export NDNS_TOKEN="..."        # operator or admin role
    python examples/monitor.py --interval 10 --count 12
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from nothingdns import (
    NothingDNSApiError,
    NothingDNSClient,
    NothingDNSConnectionError,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Poll NothingDNS and print counters")
    parser.add_argument("--interval", type=float, default=10.0, help="seconds between polls")
    parser.add_argument("--count", type=int, default=0, help="number of polls (0 = forever)")
    args = parser.parse_args()

    base_url = os.environ.get("NDNS_URL", "http://localhost:8080")
    token = os.environ.get("NDNS_TOKEN")
    username = os.environ.get("NDNS_USER")
    password = os.environ.get("NDNS_PASSWORD")
    if not token and not (username and password):
        print("set NDNS_TOKEN, or NDNS_USER + NDNS_PASSWORD", file=sys.stderr)
        return 2

    failures = 0
    with NothingDNSClient(base_url, timeout=10.0) as client:
        if token:
            client.set_token(token)
        else:
            client.auth.login(username, password)

        poll = 0
        while args.count == 0 or poll < args.count:
            poll += 1
            try:
                stats = client.dashboard.stats()
                cache = client.cache.stats()
                cluster = client.cluster.status()
                blocked = stats.blockedQueries
                blocked_note = f" blocked={blocked}" if blocked else ""
                leader = "leader" if cluster.raft and cluster.raft.is_leader else "follower"
                print(
                    f"[{poll:>4}] up={stats.uptime}s "
                    f"qps={stats.queriesPerSec:.1f} "
                    f"cache={cache.size}/{cache.capacity} hit={cache.hit_ratio:.0%} "
                    f"clients={stats.activeClients} "
                    f"nodes={cluster.alive_count}/{cluster.node_count} ({leader})"
                    f"{blocked_note}"
                )
                failures = 0
            except NothingDNSConnectionError as exc:
                failures += 1
                print(f"[{poll:>4}] unreachable: {exc}", file=sys.stderr)
            except NothingDNSApiError as exc:
                failures += 1
                print(f"[{poll:>4}] API error {exc.status_code}: {exc.message}", file=sys.stderr)

            if args.count == 0 or poll < args.count:
                time.sleep(args.interval)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
