"""Client and resource namespaces for the NothingDNS management API.

The client mirrors the server's API groups as namespaces::

    client.auth       # login, bootstrap, session, users, roles
    client.zones      # zones, records, export, bulk PTR
    client.cache      # cache statistics and flush
    client.config     # effective config + runtime tunables
    client.acl        # ACL rules and recursion allow list
    client.blocklists # blocklist sources and filtering
    client.rpz        # response policy zones
    client.dnssec     # validation status and signing keys
    client.upstreams  # upstream pool health
    client.geoip      # GeoDNS statistics
    client.cluster    # gossip + Raft cluster management
    client.dashboard  # dashboard counters, query events, zone summary
    client.metrics    # query log, top domains, metrics history

Every method returns typed models (see :mod:`nothingdns.models`) and raises
:class:`~nothingdns.errors.NothingDNSApiError` for any non-2xx response.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from . import models as m
from ._http import DEFAULT_BASE_URL, DEFAULT_TIMEOUT, Transport, drop_none, message_of
from .auth import AuthResource
from .errors import NothingDNSValidationError

# Log levels accepted by :meth:`ConfigResource.set_logging`.
LOG_LEVELS = ("debug", "info", "warn", "warning", "error", "fatal")
# Actions accepted by :meth:`RPZResource.add_rule`.
RPZ_ACTIONS = ("NXDOMAIN", "NODATA", "CNAME", "OVERRIDE", "DROP", "PASSTHROUGH", "TCPONLY")


class _Namespace:
    """A group of related API calls sharing one transport."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def _models(self, payload: Any, key: Optional[str], model: Any) -> List[Any]:
        """Map a JSON array (optionally nested under *key*) into models."""
        items = payload.get(key) if key and isinstance(payload, dict) else payload
        if not isinstance(items, list):
            raise NothingDNSValidationError("NothingDNS returned an unexpected list payload")
        return [model.from_dict(item) for item in items]


class ZonesResource(_Namespace):
    """Zones, records, export and bulk PTR generation (``/api/v1/zones``)."""

    def list(self) -> m.ZoneList:
        """List every zone served by this node (operator+).

        Returns:
            A :class:`~nothingdns.models.ZoneList`. When ``truncated`` is True
            the server capped the response and ``total`` may be larger than
            ``len(zones)``.
        """
        return m.ZoneList.from_dict(self._t.get("/api/v1/zones"))

    def create(
        self,
        name: str,
        nameservers: Sequence[str],
        *,
        admin_email: Optional[str] = None,
        ttl: Optional[int] = None,
    ) -> str:
        """Create a new authoritative zone (operator+).

        Args:
            name: Zone name, e.g. ``example.com``. A trailing dot is added when
                missing, so both forms work.
            nameservers: NS hostnames written into the zone's SOA record.
            admin_email: Zone admin e-mail; the server derives the SOA
                ``rname`` from it.
            ttl: Default TTL for records in the new zone.

        Returns:
            The server's confirmation message.

        Raises:
            NothingDNSApiError: 409 when the zone already exists, 421 when the
                name cannot become its own zone (for example because it is a
                subdomain of an existing zone).
            NothingDNSValidationError: when *nameservers* is empty.
        """
        if not nameservers:
            raise NothingDNSValidationError("nameservers must contain at least one hostname")
        return message_of(
            self._t.post(
                "/api/v1/zones",
                json=drop_none(
                    {
                        "name": name,
                        "nameservers": list(nameservers),
                        "admin_email": admin_email,
                        "ttl": ttl,
                    }
                ),
            )
        )

    def get(self, zone: str) -> m.ZoneDetail:
        """Get one zone with its SOA record and NS set (operator+).

        Args:
            zone: Zone name; a trailing dot is optional.

        Raises:
            NothingDNSApiError: 404 when the zone does not exist.
        """
        return m.ZoneDetail.from_dict(self._t.get(f"/api/v1/zones/{self._t.escape(zone)}"))

    def delete(self, zone: str) -> str:
        """Delete a zone together with all of its records (operator+).

        Returns:
            The server's confirmation message.
        """
        return message_of(self._t.delete(f"/api/v1/zones/{self._t.escape(zone)}"))

    def reload(self, zone: str) -> str:
        """Re-read one zone from its on-disk zone file (admin only).

        Call this after editing a zone file by hand; a full config reload also
        re-reads every zone.

        Returns:
            The server's confirmation message.
        """
        return message_of(self._t.post("/api/v1/zones/reload", params={"zone": zone}))

    def transfers(self) -> List[m.SlaveZone]:
        """List secondary (slave) zones and their transfer state (operator+).

        Returns:
            One entry per zone this node serves as a secondary, with the
            master address, serial, status and record count.
        """
        return self._models(self._t.get("/api/v1/zones/transfers"), "slave_zones", m.SlaveZone)

    def list_records(self, zone: str, *, name: Optional[str] = None) -> m.RecordList:
        """List records in a zone (operator+).

        Args:
            zone: Zone name.
            name: Optional owner-name filter — ``www`` or ``www.example.com``.

        Returns:
            A :class:`~nothingdns.models.RecordList`; check ``truncated`` before
            relying on ``total`` for large zones.
        """
        data = self._t.get(
            f"/api/v1/zones/{self._t.escape(zone)}/records", params=drop_none({"name": name})
        )
        return m.RecordList.from_dict(data)

    def add_record(
        self,
        zone: str,
        name: str,
        type: str,
        data: str,
        *,
        ttl: Optional[int] = None,
    ) -> str:
        """Add a record to a zone (operator+).

        Args:
            zone: Zone name.
            name: Owner name relative to the zone; ``@`` is the apex.
            type: Record type, e.g. ``A``, ``AAAA``, ``CNAME``, ``MX``, ``TXT``,
                ``SRV``, ``CAA``, ``PTR``.
            data: Record data in zone-file presentation format — a bare
                address for ``A``, the target hostname for ``MX``/``SRV``,
                quoted text for ``TXT``.
            ttl: Record TTL; the zone default is used when omitted.

        Returns:
            The server's confirmation message.

        Raises:
            NothingDNSApiError: 400 for invalid record data, 421 when the
                record conflicts with one that already exists.
        """
        return message_of(
            self._t.post(
                f"/api/v1/zones/{self._t.escape(zone)}/records",
                json=drop_none({"name": name, "type": type, "data": data, "ttl": ttl}),
            )
        )

    def replace_record(
        self,
        zone: str,
        name: str,
        type: str,
        old_data: str,
        data: str,
        *,
        ttl: Optional[int] = None,
    ) -> str:
        """Replace the data of an existing record (operator+).

        The server identifies the record by ``(name, type, old_data)``, so pass
        the record's *current* data as ``old_data`` and the new value as
        ``data``.

        Returns:
            The server's confirmation message.
        """
        return message_of(
            self._t.put(
                f"/api/v1/zones/{self._t.escape(zone)}/records",
                json=drop_none(
                    {
                        "name": name,
                        "type": type,
                        "old_data": old_data,
                        "data": data,
                        "ttl": ttl,
                    }
                ),
            )
        )

    def delete_records(self, zone: str, name: str, type: str) -> str:
        """Delete every record of *type* owned by *name* (operator+).

        Args:
            zone: Zone name.
            name: Owner name relative to the zone.
            type: Record type; all records of this type for the owner are
                removed, so pass ``A`` to clear every address of a host.

        Returns:
            The server's confirmation message.
        """
        return message_of(
            self._t.delete(
                f"/api/v1/zones/{self._t.escape(zone)}/records",
                json={"name": name, "type": type},
            )
        )

    def export(self, zone: str) -> str:
        """Export a zone in BIND zone-file format (operator+).

        Returns:
            The raw zone-file text, ready to write to disk or feed to
            ``named-checkzone``.
        """
        return self._t.get(f"/api/v1/zones/{self._t.escape(zone)}/export", raw=True)

    def ptr_bulk(
        self,
        zone: str,
        cidr: str,
        pattern: str,
        *,
        override: bool = False,
        add_a: bool = False,
        preview: bool = True,
    ) -> Union[m.PTRBulkPreview, m.PTRBulkResult]:
        """Generate PTR (and optionally forward-confirmed A) records for a range (operator+).

        Args:
            zone: Reverse zone, e.g. ``2.0.192.in-addr.arpa``.
            cidr: IPv4 CIDR to cover, e.g. ``192.0.2.0/24``. Ranges larger
                than ``/16`` are rejected by the server.
            pattern: Target hostname template; ``{ip}`` is replaced with the
                address, e.g. ``host-{ip}.example.com``.
            override: Replace records that already exist instead of skipping them.
            add_a: Also create the matching A records (forward-confirmed PTR).
            preview: When True — the default — nothing is written and the
                planned changes are returned instead.

        Returns:
            A :class:`~nothingdns.models.PTRBulkPreview` when *preview* is True,
            otherwise a :class:`~nothingdns.models.PTRBulkResult` with the
            applied counts.

        Raises:
            NothingDNSApiError: 400 for an invalid CIDR, a non-IPv4 range or
                an oversized range.
        """
        data = self._t.post(
            f"/api/v1/zones/{self._t.escape(zone)}/ptr-bulk",
            json=drop_none(
                {
                    "cidr": cidr,
                    "pattern": pattern,
                    "override": override,
                    "addA": add_a,
                    "preview": preview,
                }
            ),
        )
        if preview:
            return m.PTRBulkPreview.from_dict(data)
        return m.PTRBulkResult.from_dict(data)

    def ptr6_lookup(self, zone: str, ip: str) -> m.PTRLookup:
        """Look up the PTR record for an IPv6 address in a zone (operator+).

        Args:
            zone: The IPv6 reverse zone, e.g. ``8.b.d.0.1.0.0.2.ip6.arpa``.
            ip: The IPv6 address to resolve.

        Returns:
            A :class:`~nothingdns.models.PTRLookup`; check ``found`` before
            reading ``ptr``/``target``.
        """
        data = self._t.get(
            f"/api/v1/zones/{self._t.escape(zone)}/ptr6-lookup", params={"ip": ip}
        )
        return m.PTRLookup.from_dict(data)


class CacheResource(_Namespace):
    """The DNS response cache (``/api/v1/cache``)."""

    def stats(self) -> m.CacheStats:
        """Return cache size, capacity, hit/miss counters and hit ratio (operator+)."""
        return m.CacheStats.from_dict(self._t.get("/api/v1/cache/stats"))

    def flush(self) -> str:
        """Drop every cached entry (admin only).

        Useful right after a bulk zone change so clients see new data
        immediately.

        Returns:
            The server's confirmation message.
        """
        return message_of(self._t.post("/api/v1/cache/flush", expect_json=False))


class ConfigResource(_Namespace):
    """Configuration inspection and runtime tunables (``/api/v1/config``).

    Runtime changes are persisted to ``runtime_overrides.json`` in the data
    directory and re-applied over the YAML section on every config reload, so
    they survive a restart. Every setter requires the admin role.
    """

    def get(self) -> Dict[str, Any]:
        """Return the effective configuration with secrets redacted (operator+).

        Returns:
            The merged config as plain nested dicts. Secrets are replaced with
            a redaction marker by the server.
        """
        return self._t.get("/api/v1/config")

    def reload(self) -> str:
        """Re-read the YAML config file without dropping the listener (admin only)."""
        return message_of(self._t.post("/api/v1/config/reload", expect_json=False))

    def set_logging(self, level: str) -> str:
        """Change the log level at runtime (admin only).

        Args:
            level: One of ``debug``, ``info``, ``warn``, ``warning``,
                ``error``, ``fatal``.

        Raises:
            NothingDNSValidationError: for an unknown level.
        """
        if level not in LOG_LEVELS:
            raise NothingDNSValidationError(f"level must be one of {', '.join(LOG_LEVELS)}")
        return self._put("/api/v1/config/logging", {"level": level})

    def set_rrl(
        self,
        *,
        enabled: Optional[bool] = None,
        rate: Optional[float] = None,
        burst: Optional[int] = None,
        max_buckets: Optional[int] = None,
    ) -> str:
        """Tune the per-client response-rate limiter (admin only).

        Args:
            enabled: Turn the limiter on or off.
            rate: Sustained queries per second allowed per client.
            burst: Bucket burst size.
            max_buckets: Maximum number of client buckets tracked.
        """
        return self._put(
            "/api/v1/config/rrl",
            drop_none(
                {"enabled": enabled, "rate": rate, "burst": burst, "max_buckets": max_buckets}
            ),
        )

    def set_cache(
        self,
        *,
        enabled: Optional[bool] = None,
        size: Optional[int] = None,
        default_ttl: Optional[int] = None,
        max_ttl: Optional[int] = None,
        min_ttl: Optional[int] = None,
        negative_ttl: Optional[int] = None,
        prefetch: Optional[bool] = None,
        prefetch_threshold: Optional[int] = None,
        serve_stale: Optional[bool] = None,
        stale_grace_secs: Optional[int] = None,
    ) -> str:
        """Tune the response cache at runtime (admin only).

        Every argument is optional; omitted keys keep their current value, so
        this is a partial update rather than a replacement.
        """
        return self._put(
            "/api/v1/config/cache",
            drop_none(
                {
                    "enabled": enabled,
                    "size": size,
                    "default_ttl": default_ttl,
                    "max_ttl": max_ttl,
                    "min_ttl": min_ttl,
                    "negative_ttl": negative_ttl,
                    "prefetch": prefetch,
                    "prefetch_threshold": prefetch_threshold,
                    "serve_stale": serve_stale,
                    "stale_grace_secs": stale_grace_secs,
                }
            ),
        )

    def set_resolution(
        self,
        *,
        recursive: Optional[bool] = None,
        authoritative_only: Optional[bool] = None,
        max_depth: Optional[int] = None,
        timeout: Optional[str] = None,
        edns0_buffer_size: Optional[int] = None,
        qname_minimization: Optional[bool] = None,
        use_0x20: Optional[bool] = None,
    ) -> str:
        """Tune iterative resolution at runtime (admin only).

        Args:
            recursive: Resolve recursively for clients that are allowed to.
            authoritative_only: Answer only from local zones; everything else
                is refused.
            max_depth: Maximum CNAME/answer chain depth.
            timeout: Resolver timeout as a duration string, e.g. ``"2s"``.
            edns0_buffer_size: EDNS0 buffer size advertised to clients.
            qname_minimization: Send minimal (label-count) QNAME queries upstream.
            use_0x20: Randomise QNAME letter case to defeat cache poisoning.
        """
        return self._put(
            "/api/v1/config/resolution",
            drop_none(
                {
                    "recursive": recursive,
                    "authoritative_only": authoritative_only,
                    "max_depth": max_depth,
                    "timeout": timeout,
                    "edns0_buffer_size": edns0_buffer_size,
                    "qname_minimization": qname_minimization,
                    "use_0x20": use_0x20,
                }
            ),
        )

    def set_dns64(self, enabled: bool) -> str:
        """Enable or disable DNS64 synthesis for NAT64 networks (RFC 6147) (admin only)."""
        return self._put("/api/v1/config/dns64", {"enabled": enabled})

    def set_cookie(self, enabled: bool) -> str:
        """Enable or disable DNS Cookies (RFC 7873) (admin only)."""
        return self._put("/api/v1/config/cookie", {"enabled": enabled})

    def _put(self, path: str, payload: Mapping[str, Any]) -> str:
        return message_of(self._t.put(path, json=dict(payload), expect_json=False))


class ACLResource(_Namespace):
    """Client ACLs and the recursion allow list (``/api/v1/acl``).

    Rules are evaluated in server-config order and the first match wins; once
    any rule exists, a client matching none of them is refused.
    """

    def get(self) -> m.ACLConfig:
        """Return the ACL rules plus the recursion allow list (operator+).

        Returns:
            A :class:`~nothingdns.models.ACLConfig`. When ``persistent`` is
            True the list is served from ``access_policy.json`` — the
            dashboard-managed file that overrides the YAML config on reload.
        """
        return m.ACLConfig.from_dict(self._t.get("/api/v1/acl"))

    def set(self, rules: Sequence[Union[m.ACLRule, Mapping[str, Any]]]) -> str:
        """Replace the full ACL rule list (admin only).

        Args:
            rules: The complete new rule list, in evaluation order.

        Warning:
            This replaces the whole list — not a merge. To change one rule,
            read the current list with :meth:`get`, edit it and send it back::

                current = client.acl.get().rules
                client.acl.set([*current, new_rule])
        """
        payload = [r.to_dict() if isinstance(r, m.ACLRule) else dict(r) for r in rules]
        if not payload:
            raise NothingDNSValidationError(
                "refusing to send an empty rule list; pass [] only deliberately"
            )
        return message_of(self._t.put("/api/v1/acl", json={"rules": payload}, expect_json=False))

    def recursion(self) -> m.RecursionAllowList:
        """Return the recursion allow list (operator+)."""
        return m.RecursionAllowList.from_dict(self._t.get("/api/v1/acl/recursion"))

    def set_recursion(self, networks: Sequence[str]) -> m.RecursionAllowList:
        """Replace the recursion allow list (admin only).

        Args:
            networks: CIDR networks allowed to send recursive queries. An
                empty list denies recursion to every client.

        Returns:
            The stored list as the server returned it.
        """
        return m.RecursionAllowList.from_dict(
            self._t.put("/api/v1/acl/recursion", json={"networks": list(networks)})
        )


class BlocklistsResource(_Namespace):
    """Blocklist sources and global filtering (``/api/v1/blocklists``)."""

    def stats(self) -> m.BlocklistStats:
        """Return blocklist statistics: enabled flag and rule counts (operator+)."""
        return m.BlocklistStats.from_dict(self._t.get("/api/v1/blocklists"))

    def add(self, *, file: Optional[str] = None, url: Optional[str] = None) -> str:
        """Add a blocklist source (admin only).

        Args:
            file: Path of a hosts-format file on the server to load.
            url: HTTP(S) URL of a hosts-format list for the server to fetch.

        Exactly one of *file* / *url* must be given.

        Raises:
            NothingDNSValidationError: when neither or both are supplied.
        """
        if bool(file) == bool(url):
            raise NothingDNSValidationError("pass exactly one of file or url")
        return message_of(
            self._t.post("/api/v1/blocklists", json=drop_none({"file": file, "url": url}), expect_json=False)
        )

    def sources(self) -> List[m.BlocklistSource]:
        """List every configured blocklist source (operator+).

        Returns:
            One entry per source with its type, enabled flag and the number
            of domains it contributes.
        """
        return self._models(self._t.get("/api/v1/blocklists/sources"), None, m.BlocklistSource)

    def toggle(self) -> str:
        """Flip blocklist filtering on/off globally (admin only).

        The toggle is server-side, so call :meth:`stats` to see the result.
        """
        return message_of(self._t.post("/api/v1/blocklists/toggle", expect_json=False))

    def remove(self, source: str) -> str:
        """Remove one blocklist source by id (admin only).

        Args:
            source: Source id as reported by :meth:`sources`.
        """
        return message_of(
            self._t.delete(f"/api/v1/blocklists/{self._t.escape(source)}", expect_json=False)
        )

    def toggle_source(self, source: str) -> str:
        """Enable or disable a single blocklist source (admin only)."""
        return message_of(
            self._t.post(
                f"/api/v1/blocklists/{self._t.escape(source)}/toggle", expect_json=False
            )
        )


class RPZResource(_Namespace):
    """Response Policy Zones (``/api/v1/rpz``)."""

    def stats(self) -> m.RPZStats:
        """Return RPZ statistics: rule counts, matches, lookups, last reload (operator+)."""
        return m.RPZStats.from_dict(self._t.get("/api/v1/rpz"))

    def rules(self) -> m.RPZRuleList:
        """List the QNAME rules (operator+).

        Returns:
            A :class:`~nothingdns.models.RPZRuleList`; check ``truncated``.
        """
        return m.RPZRuleList.from_dict(self._t.get("/api/v1/rpz/rules"))

    def add_rule(
        self,
        pattern: str,
        *,
        action: str = "NXDOMAIN",
        override_data: Optional[str] = None,
    ) -> str:
        """Add a QNAME rule (admin only).

        Args:
            pattern: Domain pattern, e.g. ``ads.example.com`` or
                ``*.tracker.com``.
            action: ``NXDOMAIN`` (refuse the name), ``NODATA``, ``CNAME`` or
                ``OVERRIDE`` (with *override_data*), ``DROP``, ``PASSTHROUGH``
                or ``TCPONLY``.
            override_data: Replacement answer for ``CNAME``/``OVERRIDE``.

        Raises:
            NothingDNSValidationError: for an unknown action.
        """
        if action not in RPZ_ACTIONS:
            raise NothingDNSValidationError(f"action must be one of {', '.join(RPZ_ACTIONS)}")
        return message_of(
            self._t.post(
                "/api/v1/rpz/rules",
                json=drop_none({"pattern": pattern, "action": action, "override_data": override_data}),
                expect_json=False,
            )
        )

    def delete_rule(self, pattern: str) -> str:
        """Delete a QNAME rule by pattern (admin only)."""
        return message_of(
            self._t.delete("/api/v1/rpz/rules", params={"pattern": pattern}, expect_json=False)
        )

    def toggle(self) -> str:
        """Flip RPZ filtering on/off (admin only)."""
        return message_of(self._t.post("/api/v1/rpz/toggle", expect_json=False))


class DNSSECResource(_Namespace):
    """DNSSEC validation status and signing keys (``/api/v1/dnssec``)."""

    def status(self) -> m.DNSSECStatus:
        """Return the validation status (operator+).

        ``enabled`` reports whether validation runs at all; ``require_dnssec``
        reports whether bogus answers are refused rather than served.
        """
        return m.DNSSECStatus.from_dict(self._t.get("/api/v1/dnssec/status"))

    def keys(self) -> m.DNSSECKeyList:
        """List the DNSSEC signing keys — public metadata only (admin).

        Private key material is never exposed by the API.
        """
        return m.DNSSECKeyList.from_dict(self._t.get("/api/v1/dnssec/keys"))


class UpstreamsResource(_Namespace):
    """The upstream resolver pool (``/api/v1/upstreams``)."""

    def list(self) -> m.Upstreams:
        """Return upstream health and counters (operator+).

        Returns:
            Pool-wide per-upstream counters (``upstreams``) and the
            configured servers with latency and health (``servers``).
        """
        return m.Upstreams.from_dict(self._t.get("/api/v1/upstreams"))

    def add(self, server: str) -> str:
        """Add one upstream server at runtime (admin only).

        Args:
            server: Address in ``host:port`` form, e.g. ``9.9.9.9:53``.

        Raises:
            NothingDNSApiError: 409 when the server is already in the pool.
        """
        return self._change("add", server)

    def remove(self, server: str) -> str:
        """Remove one upstream server at runtime (admin only)."""
        return self._change("remove", server)

    def _change(self, action: str, server: str) -> str:
        return message_of(
            self._t.put(
                "/api/v1/upstreams", json={"action": action, "server": server}, expect_json=False
            )
        )


class GeoIPResource(_Namespace):
    """GeoDNS statistics (``/api/v1/geoip``)."""

    def stats(self) -> m.GeoIPStats:
        """Return GeoDNS statistics, including whether the MMDB is loaded (operator+)."""
        return m.GeoIPStats.from_dict(self._t.get("/api/v1/geoip/stats"))


class ClusterResource(_Namespace):
    """Gossip membership and Raft consensus (``/api/v1/cluster``)."""

    def status(self) -> m.ClusterStatus:
        """Return cluster status: node id, consensus, Raft state, metrics (operator+)."""
        return m.ClusterStatus.from_dict(self._t.get("/api/v1/cluster/status"))

    def nodes(self) -> List[m.ClusterNode]:
        """List every node known to the gossip layer (operator+)."""
        return self._models(self._t.get("/api/v1/cluster/nodes"), "nodes", m.ClusterNode)

    def join(self, seed_address: str) -> str:
        """Join a cluster through a seed node (admin only).

        Args:
            seed_address: ``host:port`` of a node that is already a member.

        Warning:
            Joining changes this node's cluster identity. Run it once on a
            freshly provisioned node, never on a node that already serves
            traffic.
        """
        return message_of(
            self._t.post(
                "/api/v1/cluster/join", json={"seed_address": seed_address}, expect_json=False
            )
        )

    def leave(self) -> str:
        """Drain this node and leave the cluster (admin only)."""
        return message_of(self._t.delete("/api/v1/cluster/leave", expect_json=False))


class DashboardResource(_Namespace):
    """Dashboard counters and live query events (``/api/dashboard``)."""

    def stats(self) -> m.DashboardStats:
        """Return the dashboard counter block (operator+)."""
        return m.DashboardStats.from_dict(self._t.get("/api/dashboard/stats"))

    def queries(self) -> List[m.QueryEvent]:
        """Return the last 100 query events (operator+).

        Event fields are camelCase (``clientIp``, ``queryType``, …) — this
        endpoint differs from the rest of the API, which is snake_case.
        """
        return self._models(self._t.get("/api/dashboard/queries"), None, m.QueryEvent)

    def zones(self) -> List[m.Zone]:
        """Return the dashboard zone summary (operator+)."""
        return self._models(self._t.get("/api/dashboard/zones"), None, m.Zone)


class MetricsResource(_Namespace):
    """Query log, top domains and the metrics history ring buffer."""

    def query_log(
        self,
        *,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        q: Optional[str] = None,
    ) -> m.QueryLogPage:
        """Return one page of the query log (operator+).

        Args:
            offset: Index of the first row to return.
            limit: Page size.
            q: Substring filter matched against the queried domain.
        """
        return m.QueryLogPage.from_dict(
            self._t.get("/api/v1/queries", params=drop_none({"offset": offset, "limit": limit, "q": q}))
        )

    def top_domains(self, *, limit: Optional[int] = None) -> m.TopDomains:
        """Return the most-queried domains (operator+)."""
        return m.TopDomains.from_dict(
            self._t.get("/api/v1/topdomains", params=drop_none({"limit": limit}))
        )

    def history(self) -> m.MetricsHistory:
        """Return the recent metrics ring buffer (operator+).

        The series are parallel arrays: ``queries[i]`` was recorded at
        ``timestamps[i]``.
        """
        return m.MetricsHistory.from_dict(self._t.get("/api/v1/metrics/history"))


class NothingDNSClient:
    """Client for the NothingDNS management API.

    Use it as a context manager to close the underlying connection pool, or
    call :meth:`close` yourself. Give each thread its own instance for
    concurrent use; the transport keeps no mutable per-request state.

    Example:
        >>> import os
        >>> from nothingdns import NothingDNSClient
        >>> with NothingDNSClient("http://dns.example.com:8080") as client:
        ...     client.auth.login(os.environ["NDNS_USER"], os.environ["NDNS_PASSWORD"])
        ...     for zone in client.zones.list().zones:
        ...         print(zone.name, zone.records)

    Args:
        base_url: Base URL of the server's HTTP listener (the ``server.http``
            section of the config; the default is ``http://localhost:8080``).
        token: Bearer token to start with — a JWT from ``auth.login`` /
            ``auth.bootstrap``, or the static ``server.http.auth_token`` value.
            May also be set later with :meth:`set_token`.
        timeout: Per-request timeout in seconds (default 30).
        verify: TLS verification — ``True`` (default), ``False`` or a path to a
            CA bundle.
        headers: Extra headers merged into every request.
        session: A pre-built :class:`requests.Session` to reuse, e.g. to share
            a proxy or connection pool with other code.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        token: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        verify: Union[bool, str] = True,
        headers: Optional[Mapping[str, str]] = None,
        session: Optional[Any] = None,
    ) -> None:
        self._transport = Transport(
            base_url, token, timeout, verify, headers, session
        )
        self._auth = AuthResource(self._transport)
        self.zones = ZonesResource(self._transport)
        self.cache = CacheResource(self._transport)
        self.config = ConfigResource(self._transport)
        self.acl = ACLResource(self._transport)
        self.blocklists = BlocklistsResource(self._transport)
        self.rpz = RPZResource(self._transport)
        self.dnssec = DNSSECResource(self._transport)
        self.upstreams = UpstreamsResource(self._transport)
        self.geoip = GeoIPResource(self._transport)
        self.cluster = ClusterResource(self._transport)
        self.dashboard = DashboardResource(self._transport)
        self.metrics = MetricsResource(self._transport)

    # -- shared plumbing ----------------------------------------------------

    @property
    def auth(self) -> AuthResource:
        """Authentication, users and roles."""
        return self._auth

    @property
    def base_url(self) -> str:
        """Base URL of the server, without a trailing slash."""
        return self._transport.base_url

    @property
    def token(self) -> Optional[str]:
        """The bearer token currently in use."""
        return self._transport.token

    def set_token(self, token: Optional[str]) -> None:
        """Set the bearer token used by every namespace.

        Args:
            token: A JWT from ``auth.login`` / ``auth.bootstrap``, the static
                ``server.http.auth_token`` value, or ``None`` to continue
                unauthenticated.

        Example:
            >>> import os
            >>> client.set_token(os.environ["NOTHINGDNS_TOKEN"])
        """
        self._transport.set_token(token)

    def close(self) -> None:
        """Close the underlying HTTP session."""
        self._transport.close()

    def __enter__(self) -> "NothingDNSClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- health & status ----------------------------------------------------

    def health(self) -> m.HealthResponse:
        """``GET /health`` — health check; no authentication required.

        Raises:
            NothingDNSApiError: 429 when the endpoint's own rate limit is hit.
        """
        return m.HealthResponse.from_dict(self._transport.get("/health"))

    def ready(self) -> m.HealthResponse:
        """``GET /readyz`` — readiness probe; no authentication required.

        Raises:
            NothingDNSApiError: 503 when the server is not ready to answer
                queries; treat that as "not ready", not as a hard failure.
        """
        return m.HealthResponse.from_dict(self._transport.get("/readyz"))

    def live(self) -> m.HealthResponse:
        """``GET /livez`` — liveness probe; no authentication required."""
        return m.HealthResponse.from_dict(self._transport.get("/livez"))

    def status(self) -> m.StatusResponse:
        """``GET /api/v1/status`` — status, version, cache and cluster summary.

        Any authenticated user may call this; the ``cache`` block is only
        present for operators and admins.
        """
        return m.StatusResponse.from_dict(self._transport.get("/api/v1/status"))

    def server_config(self) -> m.ServerConfig:
        """``GET /api/v1/server/config`` — port, log level, DNS64, cookies (operator+)."""
        return m.ServerConfig.from_dict(self._transport.get("/api/v1/server/config"))

    def openapi_spec(self) -> Dict[str, Any]:
        """Return the server's OpenAPI document (``GET /api/openapi.json``).

        Useful to detect server capabilities this SDK version predates.
        """
        return self._transport.get("/api/openapi.json")


def from_env(**overrides: Any) -> NothingDNSClient:
    """Build a client from environment variables.

    Reads ``NOTHINGDNS_URL`` (default ``http://localhost:8080``),
    ``NOTHINGDNS_TOKEN`` and ``NOTHINGDNS_TIMEOUT``. Keyword arguments win
    over the environment.

    Example:
        >>> client = from_env()  # with NOTHINGDNS_URL and NOTHINGDNS_TOKEN set
    """
    kwargs: Dict[str, Any] = {
        "base_url": os.environ.get("NOTHINGDNS_URL", DEFAULT_BASE_URL),
        "timeout": float(os.environ.get("NOTHINGDNS_TIMEOUT", DEFAULT_TIMEOUT)),
    }
    token = os.environ.get("NOTHINGDNS_TOKEN")
    if token:
        kwargs["token"] = token
    kwargs.update(overrides)
    return NothingDNSClient(**kwargs)
