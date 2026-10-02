"""Typed models for the NothingDNS management API.

Field names are intentionally identical to the server's JSON field names
(``snake_case``) so that what you read in the API reference is exactly what
you get on the model — no camelCase mapping layer to drift.

Every model provides a ``from_dict`` classmethod that tolerates missing or
extra fields, so a newer server never breaks an older client.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def _d(data: Any) -> Dict[str, Any]:
    """Coerce a JSON value into a dict (returns ``{}`` for None/non-objects)."""
    return data if isinstance(data, dict) else {}


def _l(data: Any) -> List[Any]:
    """Coerce a JSON value into a list (returns ``[]`` for None/non-arrays)."""
    return data if isinstance(data, list) else []


# --------------------------------------------------------------------------
# Health & status
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class HealthResponse:
    """``GET /health``, ``/readyz``, ``/livez``."""

    status: str
    """``healthy`` | ``ready`` | ``alive`` (or ``unhealthy``)."""
    timestamp: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HealthResponse":
        d = _d(data)
        return cls(status=d.get("status", ""), timestamp=d.get("timestamp"))


@dataclass(frozen=True)
class CacheStats:
    """Cache counters, embedded in :class:`StatusResponse` and returned by ``cache.stats``."""

    size: int = 0
    capacity: int = 0
    hits: int = 0
    misses: int = 0
    hit_ratio: float = 0.0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CacheStats":
        d = _d(data)
        return cls(
            size=int(d.get("size", 0) or 0),
            capacity=int(d.get("capacity", 0) or 0),
            hits=int(d.get("hits", 0) or 0),
            misses=int(d.get("misses", 0) or 0),
            hit_ratio=float(d.get("hit_ratio", 0.0) or 0.0),
        )


@dataclass(frozen=True)
class ClusterSummary:
    """Cluster summary embedded in :class:`StatusResponse`."""

    enabled: bool = False
    node_id: str = ""
    node_count: int = 0
    alive_count: int = 0
    healthy: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClusterSummary":
        d = _d(data)
        return cls(
            enabled=bool(d.get("enabled", False)),
            node_id=d.get("node_id", ""),
            node_count=int(d.get("node_count", 0) or 0),
            alive_count=int(d.get("alive_count", 0) or 0),
            healthy=bool(d.get("healthy", False)),
        )


@dataclass(frozen=True)
class StatusResponse:
    """``GET /api/v1/status`` — server status (requires any authenticated user)."""

    status: str = ""
    timestamp: Optional[str] = None
    version: str = ""
    cache: Optional[CacheStats] = None
    """Present for operators and admins only."""
    cluster: Optional[ClusterSummary] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StatusResponse":
        d = _d(data)
        return cls(
            status=d.get("status", ""),
            timestamp=d.get("timestamp"),
            version=d.get("version", ""),
            cache=CacheStats.from_dict(d["cache"]) if d.get("cache") else None,
            cluster=ClusterSummary.from_dict(d["cluster"]) if d.get("cluster") else None,
        )


@dataclass(frozen=True)
class DNS64Config:
    enabled: bool = False
    prefix: str = ""
    prefix_len: int = 0
    exclude_nets: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DNS64Config":
        d = _d(data)
        return cls(
            enabled=bool(d.get("enabled", False)),
            prefix=d.get("prefix", ""),
            prefix_len=int(d.get("prefix_len", 0) or 0),
            exclude_nets=[str(n) for n in _l(d.get("exclude_nets"))],
        )


@dataclass(frozen=True)
class CookieConfig:
    enabled: bool = False
    secret_rotation: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CookieConfig":
        d = _d(data)
        return cls(
            enabled=bool(d.get("enabled", False)),
            secret_rotation=d.get("secret_rotation", ""),
        )


@dataclass(frozen=True)
class ServerConfig:
    """``GET /api/v1/server/config`` — server configuration summary."""

    version: str = ""
    listen_port: int = 0
    log_level: str = ""
    dns64: Optional[DNS64Config] = None
    cookie: Optional[CookieConfig] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServerConfig":
        d = _d(data)
        return cls(
            version=d.get("version", ""),
            listen_port=int(d.get("listen_port", 0) or 0),
            log_level=d.get("log_level", ""),
            dns64=DNS64Config.from_dict(d["dns64"]) if d.get("dns64") else None,
            cookie=CookieConfig.from_dict(d["cookie"]) if d.get("cookie") else None,
        )


# --------------------------------------------------------------------------
# Authentication & users
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Session:
    """Login/session result: the bearer token plus who it belongs to."""

    token: str = ""
    username: str = ""
    role: str = ""
    """``admin`` | ``operator`` | ``viewer``."""
    expires: Optional[str] = None
    """RFC 3339 expiry timestamp (absent on bootstrap responses)."""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Session":
        d = _d(data)
        return cls(
            token=d.get("token", ""),
            username=d.get("username", ""),
            role=d.get("role", ""),
            expires=d.get("expires"),
        )


@dataclass(frozen=True)
class User:
    username: str = ""
    role: str = "viewer"
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "User":
        d = _d(data)
        return cls(
            username=d.get("username", ""),
            role=d.get("role", "viewer"),
            created_at=d.get("created_at"),
            updated_at=d.get("updated_at"),
        )


@dataclass(frozen=True)
class Role:
    name: str = ""
    description: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Role":
        d = _d(data)
        return cls(name=d.get("name", ""), description=d.get("description", ""))


# --------------------------------------------------------------------------
# Zones
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SOA:
    mname: str = ""
    rname: str = ""
    serial: int = 0
    refresh: int = 0
    retry: int = 0
    expire: int = 0
    minimum: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SOA":
        d = _d(data)
        return cls(
            mname=d.get("mname", ""),
            rname=d.get("rname", ""),
            serial=int(d.get("serial", 0) or 0),
            refresh=int(d.get("refresh", 0) or 0),
            retry=int(d.get("retry", 0) or 0),
            expire=int(d.get("expire", 0) or 0),
            minimum=int(d.get("minimum", 0) or 0),
        )


@dataclass(frozen=True)
class Zone:
    """Zone summary — also used for the dashboard zone list."""

    name: str = ""
    serial: int = 0
    records: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Zone":
        d = _d(data)
        return cls(
            name=d.get("name", ""),
            serial=int(d.get("serial", 0) or 0),
            records=int(d.get("records", 0) or 0),
        )


@dataclass(frozen=True)
class ZoneList:
    zones: List[Zone] = field(default_factory=list)
    total: int = 0
    truncated: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ZoneList":
        d = _d(data)
        return cls(
            zones=[Zone.from_dict(z) for z in _l(d.get("zones"))],
            total=int(d.get("total", 0) or 0),
            truncated=bool(d.get("truncated", False)),
        )


@dataclass(frozen=True)
class ZoneDetail:
    """``GET /api/v1/zones/{zone}``."""

    name: str = ""
    serial: int = 0
    records: int = 0
    soa: Optional[SOA] = None
    nameservers: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ZoneDetail":
        d = _d(data)
        return cls(
            name=d.get("name", ""),
            serial=int(d.get("serial", 0) or 0),
            records=int(d.get("records", 0) or 0),
            soa=SOA.from_dict(d["soa"]) if d.get("soa") else None,
            nameservers=[str(n) for n in _l(d.get("nameservers"))],
        )


@dataclass(frozen=True)
class Record:
    name: str = ""
    type: str = ""
    ttl: int = 0
    class_: str = ""
    """DNS class (``IN`` for internet)."""
    data: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Record":
        d = _d(data)
        return cls(
            name=d.get("name", ""),
            type=d.get("type", ""),
            ttl=int(d.get("ttl", 0) or 0),
            class_=d.get("class", ""),
            data=d.get("data", ""),
        )


@dataclass(frozen=True)
class RecordList:
    records: List[Record] = field(default_factory=list)
    total: int = 0
    truncated: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RecordList":
        d = _d(data)
        return cls(
            records=[Record.from_dict(r) for r in _l(d.get("records"))],
            total=int(d.get("total", 0) or 0),
            truncated=bool(d.get("truncated", False)),
        )


@dataclass(frozen=True)
class SlaveZone:
    zone: str = ""
    masters: str = ""
    serial: int = 0
    last_transfer: Optional[str] = None
    status: str = ""
    """``pending`` | ``synced``."""
    records: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SlaveZone":
        d = _d(data)
        return cls(
            zone=d.get("zone", ""),
            masters=d.get("masters", ""),
            serial=int(d.get("serial", 0) or 0),
            last_transfer=d.get("last_transfer"),
            status=d.get("status", ""),
            records=int(d.get("records", 0) or 0),
        )


@dataclass(frozen=True)
class PTRChange:
    """One record the bulk PTR generator would create."""

    name: str = ""
    type: str = ""
    ttl: int = 0
    data: str = ""
    action: str = ""
    """What the generator would do: add, skip or override."""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PTRChange":
        d = _d(data)
        return cls(
            name=d.get("name", ""),
            type=d.get("type", ""),
            ttl=int(d.get("ttl", 0) or 0),
            data=d.get("data", ""),
            action=d.get("action", ""),
        )


@dataclass(frozen=True)
class PTRBulkPreview:
    """Result of ``zones.ptr_bulk`` with ``preview=True``."""

    preview: bool = True
    total: int = 0
    willAdd: int = 0
    willAddA: int = 0
    willSkip: int = 0
    willOverride: int = 0
    changes: List[PTRChange] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PTRBulkPreview":
        d = _d(data)
        return cls(
            preview=bool(d.get("preview", True)),
            total=int(d.get("total", 0) or 0),
            willAdd=int(d.get("willAdd", 0) or 0),
            willAddA=int(d.get("willAddA", 0) or 0),
            willSkip=int(d.get("willSkip", 0) or 0),
            willOverride=int(d.get("willOverride", 0) or 0),
            changes=[PTRChange.from_dict(c) for c in _l(d.get("changes"))],
        )


@dataclass(frozen=True)
class PTRBulkResult:
    """Result of ``zones.ptr_bulk`` when records were actually written."""

    added: int = 0
    addedA: int = 0
    exists: int = 0
    existsA: int = 0
    skipped: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PTRBulkResult":
        d = _d(data)
        return cls(
            added=int(d.get("added", 0) or 0),
            addedA=int(d.get("addedA", 0) or 0),
            exists=int(d.get("exists", 0) or 0),
            existsA=int(d.get("existsA", 0) or 0),
            skipped=int(d.get("skipped", 0) or 0),
        )


@dataclass(frozen=True)
class PTRLookup:
    """Result of ``zones.ptr6_lookup``."""

    ip: str = ""
    ptr: str = ""
    ptrFQDN: str = ""
    target: str = ""
    ttl: int = 0
    found: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PTRLookup":
        d = _d(data)
        return cls(
            ip=d.get("ip", ""),
            ptr=d.get("ptr", ""),
            ptrFQDN=d.get("ptrFQDN", ""),
            target=d.get("target", ""),
            ttl=int(d.get("ttl", 0) or 0),
            found=bool(d.get("found", False)),
        )


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CacheStatsResult(CacheStats):
    """``GET /api/v1/cache/stats`` (same shape as :class:`CacheStats`)."""


# --------------------------------------------------------------------------
# ACL
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ACLRule:
    """One ACL rule. Also the request shape for ``acl.set``."""

    name: str
    networks: List[str]
    action: str
    """``allow`` | ``deny`` | ``redirect``."""
    types: List[str] = field(default_factory=list)
    """Query types this rule applies to; empty means all types."""
    redirect: str = ""
    """Redirect target for ``action='redirect'`` rules (e.g. ``127.0.0.1``)."""

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "name": self.name,
            "networks": list(self.networks),
            "action": self.action,
        }
        if self.types:
            payload["types"] = list(self.types)
        if self.redirect:
            payload["redirect"] = self.redirect
        return payload

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ACLRule":
        d = _d(data)
        return cls(
            name=d.get("name", ""),
            networks=[str(n) for n in _l(d.get("networks"))],
            action=d.get("action", ""),
            types=[str(t) for t in _l(d.get("types"))],
            redirect=d.get("redirect", ""),
        )


@dataclass(frozen=True)
class RecursionAllowList:
    """Clients permitted to use recursive resolution."""

    allow_all: bool = False
    networks: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RecursionAllowList":
        d = _d(data)
        return cls(
            allow_all=bool(d.get("allow_all", False)),
            networks=[str(n) for n in _l(d.get("networks"))],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {"allow_all": self.allow_all, "networks": list(self.networks)}


@dataclass(frozen=True)
class ACLConfig:
    """``GET /api/v1/acl`` — rules plus the recursion allow list."""

    rules: List[ACLRule] = field(default_factory=list)
    allow_recursion: Optional[RecursionAllowList] = None
    persistent: bool = False
    """True when the list is served from ``access_policy.json`` rather than the config file."""
    policy_file: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ACLConfig":
        d = _d(data)
        return cls(
            rules=[ACLRule.from_dict(r) for r in _l(d.get("rules"))],
            allow_recursion=(
                RecursionAllowList.from_dict(d["allow_recursion"])
                if d.get("allow_recursion")
                else None
            ),
            persistent=bool(d.get("persistent", False)),
            policy_file=d.get("policy_file", ""),
        )


# --------------------------------------------------------------------------
# Blocklists
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class BlocklistStats:
    enabled: bool = False
    total_rules: int = 0
    files_count: int = 0
    urls_count: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BlocklistStats":
        d = _d(data)
        return cls(
            enabled=bool(d.get("enabled", False)),
            total_rules=int(d.get("total_rules", 0) or 0),
            files_count=int(d.get("files_count", 0) or 0),
            urls_count=int(d.get("urls_count", 0) or 0),
        )


@dataclass(frozen=True)
class BlocklistSource:
    id: str = ""
    type: str = ""
    """``file`` | ``url``."""
    enabled: bool = True
    domains: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BlocklistSource":
        d = _d(data)
        return cls(
            id=d.get("id", ""),
            type=d.get("type", ""),
            enabled=bool(d.get("enabled", True)),
            domains=int(d.get("domains", 0) or 0),
        )


# --------------------------------------------------------------------------
# RPZ
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RPZStats:
    enabled: bool = False
    total_rules: int = 0
    qname_rules: int = 0
    client_ip_rules: int = 0
    resp_ip_rules: int = 0
    files_count: int = 0
    total_matches: int = 0
    total_lookups: int = 0
    last_reload: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RPZStats":
        d = _d(data)
        return cls(
            enabled=bool(d.get("enabled", False)),
            total_rules=int(d.get("total_rules", 0) or 0),
            qname_rules=int(d.get("qname_rules", 0) or 0),
            client_ip_rules=int(d.get("client_ip_rules", 0) or 0),
            resp_ip_rules=int(d.get("resp_ip_rules", 0) or 0),
            files_count=int(d.get("files_count", 0) or 0),
            total_matches=int(d.get("total_matches", 0) or 0),
            total_lookups=int(d.get("total_lookups", 0) or 0),
            last_reload=d.get("last_reload"),
        )


@dataclass(frozen=True)
class RPZRule:
    pattern: str = ""
    action: str = ""
    trigger: str = ""
    override_data: str = ""
    policy_name: str = ""
    priority: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RPZRule":
        d = _d(data)
        return cls(
            pattern=d.get("pattern", ""),
            action=d.get("action", ""),
            trigger=d.get("trigger", ""),
            override_data=d.get("override_data", ""),
            policy_name=d.get("policy_name", ""),
            priority=int(d.get("priority", 0) or 0),
        )


@dataclass(frozen=True)
class RPZRuleList:
    rules: List[RPZRule] = field(default_factory=list)
    total: int = 0
    truncated: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RPZRuleList":
        d = _d(data)
        return cls(
            rules=[RPZRule.from_dict(r) for r in _l(d.get("rules"))],
            total=int(d.get("total", 0) or 0),
            truncated=bool(d.get("truncated", False)),
        )


# --------------------------------------------------------------------------
# DNSSEC
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class DNSSECStatus:
    enabled: bool = False
    require_dnssec: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DNSSECStatus":
        d = _d(data)
        return cls(
            enabled=bool(d.get("enabled", False)),
            require_dnssec=bool(d.get("require_dnssec", False)),
        )


@dataclass(frozen=True)
class DNSSECKey:
    keyTag: int = 0
    algorithm: int = 0
    flags: int = 0
    isKSK: bool = False
    isZSK: bool = False
    zone: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DNSSECKey":
        d = _d(data)
        return cls(
            keyTag=int(d.get("keyTag", 0) or 0),
            algorithm=int(d.get("algorithm", 0) or 0),
            flags=int(d.get("flags", 0) or 0),
            isKSK=bool(d.get("isKSK", False)),
            isZSK=bool(d.get("isZSK", False)),
            zone=d.get("zone", ""),
        )


@dataclass(frozen=True)
class DNSSECKeyList:
    zones: List[DNSSECKey] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DNSSECKeyList":
        d = _d(data)
        return cls(zones=[DNSSECKey.from_dict(k) for k in _l(d.get("zones"))])


# --------------------------------------------------------------------------
# Upstreams & GeoDNS
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class UpstreamHealth:
    """Per-upstream counters inside the upstream pool."""

    address: str = ""
    healthy: bool = False
    queries: int = 0
    failed: int = 0
    failovers: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UpstreamHealth":
        d = _d(data)
        return cls(
            address=d.get("address", ""),
            healthy=bool(d.get("healthy", False)),
            queries=int(d.get("queries", 0) or 0),
            failed=int(d.get("failed", 0) or 0),
            failovers=int(d.get("failovers", 0) or 0),
        )


@dataclass(frozen=True)
class UpstreamServer:
    address: str = ""
    healthy: bool = False
    latency_ms: float = 0.0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UpstreamServer":
        d = _d(data)
        return cls(
            address=d.get("address", ""),
            healthy=bool(d.get("healthy", False)),
            latency_ms=float(d.get("latency_ms", 0.0) or 0.0),
        )


@dataclass(frozen=True)
class Upstreams:
    """``GET /api/v1/upstreams`` — pool counters and server health."""

    upstreams: List[UpstreamHealth] = field(default_factory=list)
    servers: List[UpstreamServer] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Upstreams":
        d = _d(data)
        return cls(
            upstreams=[UpstreamHealth.from_dict(u) for u in _l(d.get("upstreams"))],
            servers=[UpstreamServer.from_dict(s) for s in _l(d.get("servers"))],
        )


@dataclass(frozen=True)
class GeoIPStats:
    enabled: bool = False
    rules: int = 0
    mmdb_loaded: bool = False
    lookups: int = 0
    hits: int = 0
    misses: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GeoIPStats":
        d = _d(data)
        return cls(
            enabled=bool(d.get("enabled", False)),
            rules=int(d.get("rules", 0) or 0),
            mmdb_loaded=bool(d.get("mmdb_loaded", False)),
            lookups=int(d.get("lookups", 0) or 0),
            hits=int(d.get("hits", 0) or 0),
            misses=int(d.get("misses", 0) or 0),
        )


# --------------------------------------------------------------------------
# Cluster
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class GossipStats:
    messages_sent: int = 0
    messages_received: int = 0
    ping_sent: int = 0
    ping_received: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GossipStats":
        d = _d(data)
        return cls(
            messages_sent=int(d.get("messages_sent", 0) or 0),
            messages_received=int(d.get("messages_received", 0) or 0),
            ping_sent=int(d.get("ping_sent", 0) or 0),
            ping_received=int(d.get("ping_received", 0) or 0),
        )


@dataclass(frozen=True)
class RaftStats:
    state: str = ""
    term: int = 0
    commit_index: int = 0
    applied_index: int = 0
    is_leader: bool = False
    leader_id: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RaftStats":
        d = _d(data)
        return cls(
            state=d.get("state", ""),
            term=int(d.get("term", 0) or 0),
            commit_index=int(d.get("commit_index", 0) or 0),
            applied_index=int(d.get("applied_index", 0) or 0),
            is_leader=bool(d.get("is_leader", False)),
            leader_id=d.get("leader_id", ""),
        )


@dataclass(frozen=True)
class ClusterMetrics:
    queries_total: int = 0
    queries_per_sec: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    cache_hit_rate: float = 0.0
    latency_avg_ms: float = 0.0
    latency_p99_ms: float = 0.0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClusterMetrics":
        d = _d(data)
        return cls(
            queries_total=int(d.get("queries_total", 0) or 0),
            queries_per_sec=float(d.get("queries_per_sec", 0.0) or 0.0),
            cache_hits=int(d.get("cache_hits", 0) or 0),
            cache_misses=int(d.get("cache_misses", 0) or 0),
            cache_hit_rate=float(d.get("cache_hit_rate", 0.0) or 0.0),
            latency_avg_ms=float(d.get("latency_avg_ms", 0.0) or 0.0),
            latency_p99_ms=float(d.get("latency_p99_ms", 0.0) or 0.0),
        )


@dataclass(frozen=True)
class ClusterStatus:
    """``GET /api/v1/cluster/status``."""

    node_id: str = ""
    consensus: str = ""
    node_count: int = 0
    alive_count: int = 0
    healthy: bool = False
    gossip: Optional[GossipStats] = None
    raft: Optional[RaftStats] = None
    metrics: Optional[ClusterMetrics] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClusterStatus":
        d = _d(data)
        return cls(
            node_id=d.get("node_id", ""),
            consensus=d.get("consensus", ""),
            node_count=int(d.get("node_count", 0) or 0),
            alive_count=int(d.get("alive_count", 0) or 0),
            healthy=bool(d.get("healthy", False)),
            gossip=GossipStats.from_dict(d["gossip"]) if d.get("gossip") else None,
            raft=RaftStats.from_dict(d["raft"]) if d.get("raft") else None,
            metrics=ClusterMetrics.from_dict(d["metrics"]) if d.get("metrics") else None,
        )


@dataclass(frozen=True)
class ClusterNode:
    id: str = ""
    addr: str = ""
    port: int = 0
    state: str = ""
    role: str = ""
    region: str = ""
    zone: str = ""
    weight: int = 0
    http_addr: str = ""
    version: int = 0
    health_score: int = 0
    queries_per_second: float = 0.0
    latency_ms: float = 0.0
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    active_connections: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClusterNode":
        d = _d(data)
        return cls(
            id=d.get("id", ""),
            addr=d.get("addr", ""),
            port=int(d.get("port", 0) or 0),
            state=d.get("state", ""),
            role=d.get("role", ""),
            region=d.get("region", ""),
            zone=d.get("zone", ""),
            weight=int(d.get("weight", 0) or 0),
            http_addr=d.get("http_addr", ""),
            version=int(d.get("version", 0) or 0),
            health_score=int(d.get("health_score", 0) or 0),
            queries_per_second=float(d.get("queries_per_second", 0.0) or 0.0),
            latency_ms=float(d.get("latency_ms", 0.0) or 0.0),
            cpu_percent=float(d.get("cpu_percent", 0.0) or 0.0),
            memory_percent=float(d.get("memory_percent", 0.0) or 0.0),
            active_connections=int(d.get("active_connections", 0) or 0),
        )


@dataclass(frozen=True)
class ClusterNodeList:
    nodes: List[ClusterNode] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClusterNodeList":
        d = _d(data)
        return cls(nodes=[ClusterNode.from_dict(n) for n in _l(d.get("nodes"))])


# --------------------------------------------------------------------------
# Dashboard & metrics
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class DashboardStats:
    """``GET /api/dashboard/stats`` — counters shown on the dashboard landing page."""

    uptime: int = 0
    queriesTotal: int = 0
    queriesPerSec: float = 0.0
    cacheHitRate: float = 0.0
    blockedQueries: int = 0
    activeClients: int = 0
    zoneCount: int = 0
    upstreamLatency: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DashboardStats":
        d = _d(data)
        return cls(
            uptime=int(d.get("uptime", 0) or 0),
            queriesTotal=int(d.get("queriesTotal", 0) or 0),
            queriesPerSec=float(d.get("queriesPerSec", 0.0) or 0.0),
            cacheHitRate=float(d.get("cacheHitRate", 0.0) or 0.0),
            blockedQueries=int(d.get("blockedQueries", 0) or 0),
            activeClients=int(d.get("activeClients", 0) or 0),
            zoneCount=int(d.get("zoneCount", 0) or 0),
            upstreamLatency=int(d.get("upstreamLatency", 0) or 0),
        )


@dataclass(frozen=True)
class QueryEvent:
    """One live query event from ``/api/dashboard/queries`` (camelCase on the wire)."""

    timestamp: str = ""
    clientIp: str = ""
    countryCode: str = ""
    domain: str = ""
    queryType: str = ""
    responseCode: str = ""
    answers: List[str] = field(default_factory=list)
    duration: int = 0
    cached: bool = False
    blocked: bool = False
    protocol: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QueryEvent":
        d = _d(data)
        return cls(
            timestamp=d.get("timestamp", ""),
            clientIp=d.get("clientIp", ""),
            countryCode=d.get("countryCode", ""),
            domain=d.get("domain", ""),
            queryType=d.get("queryType", ""),
            responseCode=d.get("responseCode", ""),
            answers=[str(a) for a in _l(d.get("answers"))],
            duration=int(d.get("duration", 0) or 0),
            cached=bool(d.get("cached", False)),
            blocked=bool(d.get("blocked", False)),
            protocol=d.get("protocol", ""),
        )


@dataclass(frozen=True)
class QueryLogEntry:
    """One row of the paginated query log (``/api/v1/queries``)."""

    timestamp: str = ""
    client_ip: str = ""
    domain: str = ""
    query_type: str = ""
    response_code: str = ""
    answers: List[str] = field(default_factory=list)
    duration_ms: int = 0
    cached: bool = False
    blocked: bool = False
    protocol: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QueryLogEntry":
        d = _d(data)
        return cls(
            timestamp=d.get("timestamp", ""),
            client_ip=d.get("client_ip", ""),
            domain=d.get("domain", ""),
            query_type=d.get("query_type", ""),
            response_code=d.get("response_code", ""),
            answers=[str(a) for a in _l(d.get("answers"))],
            duration_ms=int(d.get("duration_ms", 0) or 0),
            cached=bool(d.get("cached", False)),
            blocked=bool(d.get("blocked", False)),
            protocol=d.get("protocol", ""),
        )


@dataclass(frozen=True)
class QueryLogPage:
    """Paginated page of :class:`QueryLogEntry`."""

    queries: List[QueryLogEntry] = field(default_factory=list)
    total: int = 0
    offset: int = 0
    limit: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QueryLogPage":
        d = _d(data)
        return cls(
            queries=[QueryLogEntry.from_dict(q) for q in _l(d.get("queries"))],
            total=int(d.get("total", 0) or 0),
            offset=int(d.get("offset", 0) or 0),
            limit=int(d.get("limit", 0) or 0),
        )


@dataclass(frozen=True)
class TopDomain:
    domain: str = ""
    count: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TopDomain":
        d = _d(data)
        return cls(domain=d.get("domain", ""), count=int(d.get("count", 0) or 0))


@dataclass(frozen=True)
class TopDomains:
    domains: List[TopDomain] = field(default_factory=list)
    limit: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TopDomains":
        d = _d(data)
        return cls(
            domains=[TopDomain.from_dict(x) for x in _l(d.get("domains"))],
            limit=int(d.get("limit", 0) or 0),
        )


@dataclass(frozen=True)
class MetricsHistory:
    """Ring buffer of recent metric samples (``/api/v1/metrics/history``)."""

    timestamps: List[int] = field(default_factory=list)
    queries: List[int] = field(default_factory=list)
    cache_hits: List[int] = field(default_factory=list)
    cache_misses: List[int] = field(default_factory=list)
    latency_ms: List[int] = field(default_factory=list)
    count: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MetricsHistory":
        d = _d(data)
        return cls(
            timestamps=[int(t) for t in _l(d.get("timestamps"))],
            queries=[int(t) for t in _l(d.get("queries"))],
            cache_hits=[int(t) for t in _l(d.get("cache_hits"))],
            cache_misses=[int(t) for t in _l(d.get("cache_misses"))],
            latency_ms=[int(t) for t in _l(d.get("latency_ms"))],
            count=int(d.get("count", 0) or 0),
        )
