/**
 * Typed models for the NothingDNS management API.
 *
 * The wire format is `snake_case` (with two camelCase exceptions: the
 * `/api/dashboard` endpoints and the PTR helpers, which keep their camelCase
 * names). These interfaces use idiomatic TypeScript `camelCase` properties, and
 * every model ships a `fromJson` mapper so the translation lives in exactly one
 * place.
 *
 * All mappers tolerate missing and unknown fields, so a newer server never
 * breaks an older client.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

/** Decode helpers — defensive against missing/typed-wrong fields. */
/** JSON object type used by the mappers below. */
type JsonObject = { [key: string]: unknown };

const asRecord = (value: unknown): JsonObject =>
  typeof value === 'object' && value !== null ? (value as JsonObject) : {};

const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

const str = (value: unknown, fallback = ''): string =>
  typeof value === 'string' ? value : fallback;

const num = (value: unknown, fallback = 0): number =>
  typeof value === 'number' && Number.isFinite(value) ? value : fallback;

const bool = (value: unknown, fallback = false): boolean =>
  typeof value === 'boolean' ? value : fallback;

const strArray = (value: unknown): string[] => asArray(value).map((item) => str(item));

/* -------------------------------------------------------------------------- */
/* Health & status                                                             */
/* -------------------------------------------------------------------------- */

/** `GET /health`, `/readyz`, `/livez`. */
export interface HealthResponse {
  /** `healthy` | `ready` | `alive` (or `unhealthy`). */
  status: string;
  timestamp?: string;
}

export const healthFromJson = (json: unknown): HealthResponse => {
  const d = asRecord(json);
  return { status: str(d.status), timestamp: d.timestamp === undefined ? undefined : str(d.timestamp) };
};

/** Cache counters, embedded in {@link StatusResponse} and returned by `cache.stats`. */
export interface CacheStats {
  size: number;
  capacity: number;
  hits: number;
  misses: number;
  /** Fraction between 0 and 1. */
  hitRatio: number;
}

export const cacheStatsFromJson = (json: unknown): CacheStats => {
  const d = asRecord(json);
  return {
    size: num(d.size),
    capacity: num(d.capacity),
    hits: num(d.hits),
    misses: num(d.misses),
    hitRatio: num(d.hit_ratio),
  };
};

/** Cluster summary embedded in {@link StatusResponse}. */
export interface ClusterSummary {
  enabled: boolean;
  nodeId: string;
  nodeCount: number;
  aliveCount: number;
  healthy: boolean;
}

export const clusterSummaryFromJson = (json: unknown): ClusterSummary => {
  const d = asRecord(json);
  return {
    enabled: bool(d.enabled),
    nodeId: str(d.node_id),
    nodeCount: num(d.node_count),
    aliveCount: num(d.alive_count),
    healthy: bool(d.healthy),
  };
};

/** `GET /api/v1/status`. */
export interface StatusResponse {
  status: string;
  timestamp?: string;
  version: string;
  /** Present for operators and admins only. */
  cache?: CacheStats;
  cluster?: ClusterSummary;
}

export const statusFromJson = (json: unknown): StatusResponse => {
  const d = asRecord(json);
  return {
    status: str(d.status),
    timestamp: d.timestamp === undefined ? undefined : str(d.timestamp),
    version: str(d.version),
    cache: d.cache === undefined || d.cache === null ? undefined : cacheStatsFromJson(d.cache),
    cluster:
      d.cluster === undefined || d.cluster === null ? undefined : clusterSummaryFromJson(d.cluster),
  };
};

export interface DNS64Config {
  enabled: boolean;
  prefix: string;
  prefixLength: number;
  excludeNets: string[];
}

const dns64FromJson = (json: unknown): DNS64Config => {
  const d = asRecord(json);
  return {
    enabled: bool(d.enabled),
    prefix: str(d.prefix),
    prefixLength: num(d.prefix_len),
    excludeNets: strArray(d.exclude_nets),
  };
};

export interface CookieConfig {
  enabled: boolean;
  secretRotation: string;
}

const cookieFromJson = (json: unknown): CookieConfig => {
  const d = asRecord(json);
  return { enabled: bool(d.enabled), secretRotation: str(d.secret_rotation) };
};

/** `GET /api/v1/server/config`. */
export interface ServerConfig {
  version: string;
  listenPort: number;
  logLevel: string;
  dns64?: DNS64Config;
  cookie?: CookieConfig;
}

export const serverConfigFromJson = (json: unknown): ServerConfig => {
  const d = asRecord(json);
  return {
    version: str(d.version),
    listenPort: num(d.listen_port),
    logLevel: str(d.log_level),
    dns64: d.dns64 === undefined || d.dns64 === null ? undefined : dns64FromJson(d.dns64),
    cookie: d.cookie === undefined || d.cookie === null ? undefined : cookieFromJson(d.cookie),
  };
};

/* -------------------------------------------------------------------------- */
/* Auth & users                                                                */
/* -------------------------------------------------------------------------- */

/** Login/session result: the bearer token plus who it belongs to. */
export interface Session {
  token: string;
  username: string;
  /** `admin` | `operator` | `viewer`. */
  role: string;
  /** RFC 3339 expiry timestamp (absent on bootstrap responses). */
  expires?: string;
}

export const sessionFromJson = (json: unknown): Session => {
  const d = asRecord(json);
  return {
    token: str(d.token),
    username: str(d.username),
    role: str(d.role),
    expires: d.expires === undefined ? undefined : str(d.expires),
  };
};

export interface User {
  username: string;
  role: string;
  createdAt?: string;
  updatedAt?: string;
}

export const userFromJson = (json: unknown): User => {
  const d = asRecord(json);
  return {
    username: str(d.username),
    role: str(d.role, 'viewer'),
    createdAt: d.created_at === undefined ? undefined : str(d.created_at),
    updatedAt: d.updated_at === undefined ? undefined : str(d.updated_at),
  };
};

export interface Role {
  name: string;
  description: string;
}

export const roleFromJson = (json: unknown): Role => {
  const d = asRecord(json);
  return { name: str(d.name), description: str(d.description) };
};

/* -------------------------------------------------------------------------- */
/* Zones                                                                       */
/* -------------------------------------------------------------------------- */

export interface SOA {
  mname: string;
  rname: string;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  minimum: number;
}

const soaFromJson = (json: unknown): SOA => {
  const d = asRecord(json);
  return {
    mname: str(d.mname),
    rname: str(d.rname),
    serial: num(d.serial),
    refresh: num(d.refresh),
    retry: num(d.retry),
    expire: num(d.expire),
    minimum: num(d.minimum),
  };
};

/** Zone summary — also used for the dashboard zone list. */
export interface Zone {
  name: string;
  serial: number;
  records: number;
}

export const zoneFromJson = (json: unknown): Zone => {
  const d = asRecord(json);
  return { name: str(d.name), serial: num(d.serial), records: num(d.records) };
};

export interface ZoneList {
  zones: Zone[];
  total: number;
  /** True when the server capped the list — `total` may exceed `zones.length`. */
  truncated: boolean;
}

export const zoneListFromJson = (json: unknown): ZoneList => {
  const d = asRecord(json);
  return {
    zones: asArray(d.zones).map(zoneFromJson),
    total: num(d.total),
    truncated: bool(d.truncated),
  };
};

export interface ZoneDetail {
  name: string;
  serial: number;
  records: number;
  soa?: SOA;
  nameservers: string[];
}

export const zoneDetailFromJson = (json: unknown): ZoneDetail => {
  const d = asRecord(json);
  return {
    name: str(d.name),
    serial: num(d.serial),
    records: num(d.records),
    soa: d.soa === undefined || d.soa === null ? undefined : soaFromJson(d.soa),
    nameservers: strArray(d.nameservers),
  };
};

export interface DNSRecord {
  name: string;
  type: string;
  ttl: number;
  /** DNS class (`IN` for internet). */
  class: string;
  data: string;
}

export const recordFromJson = (json: unknown): DNSRecord => {
  const d = asRecord(json);
  return {
    name: str(d.name),
    type: str(d.type),
    ttl: num(d.ttl),
    class: str(d.class),
    data: str(d.data),
  };
};

export interface RecordList {
  records: DNSRecord[];
  total: number;
  truncated: boolean;
}

export const recordListFromJson = (json: unknown): RecordList => {
  const d = asRecord(json);
  return {
    records: asArray(d.records).map(recordFromJson),
    total: num(d.total),
    truncated: bool(d.truncated),
  };
};

export interface SlaveZone {
  zone: string;
  masters: string;
  serial: number;
  lastTransfer?: string;
  /** `pending` | `synced`. */
  status: string;
  records: number;
}

export const slaveZoneFromJson = (json: unknown): SlaveZone => {
  const d = asRecord(json);
  return {
    zone: str(d.zone),
    masters: str(d.masters),
    serial: num(d.serial),
    lastTransfer: d.last_transfer === undefined ? undefined : str(d.last_transfer),
    status: str(d.status),
    records: num(d.records),
  };
};

/** One record the bulk PTR generator would create (wire format is camelCase). */
export interface PTRChange {
  name: string;
  type: string;
  ttl: number;
  data: string;
  action: string;
}

const ptrChangeFromJson = (json: unknown): PTRChange => {
  const d = asRecord(json);
  return {
    name: str(d.name),
    type: str(d.type),
    ttl: num(d.ttl),
    data: str(d.data),
    action: str(d.action),
  };
};

/** Result of `zones.ptrBulk` with `preview: true`. */
export interface PTRBulkPreview {
  preview: boolean;
  total: number;
  willAdd: number;
  willAddA: number;
  willSkip: number;
  willOverride: number;
  changes: PTRChange[];
}

export const ptrBulkPreviewFromJson = (json: unknown): PTRBulkPreview => {
  const d = asRecord(json);
  return {
    preview: bool(d.preview, true),
    total: num(d.total),
    willAdd: num(d.willAdd),
    willAddA: num(d.willAddA),
    willSkip: num(d.willSkip),
    willOverride: num(d.willOverride),
    changes: asArray(d.changes).map(ptrChangeFromJson),
  };
};

/** Result of `zones.ptrBulk` when records were actually written. */
export interface PTRBulkResult {
  added: number;
  addedA: number;
  exists: number;
  existsA: number;
  skipped: number;
}

export const ptrBulkResultFromJson = (json: unknown): PTRBulkResult => {
  const d = asRecord(json);
  return {
    added: num(d.added),
    addedA: num(d.addedA),
    exists: num(d.exists),
    existsA: num(d.existsA),
    skipped: num(d.skipped),
  };
};

/** Result of `zones.ptr6Lookup` (wire format is camelCase). */
export interface PTRLookup {
  ip: string;
  ptr: string;
  /** FQDN form of {@link PTRLookup.ptr}. */
  ptrFQDN: string;
  target: string;
  ttl: number;
  found: boolean;
}

export const ptrLookupFromJson = (json: unknown): PTRLookup => {
  const d = asRecord(json);
  return {
    ip: str(d.ip),
    ptr: str(d.ptr),
    ptrFQDN: str(d.ptrFQDN),
    target: str(d.target),
    ttl: num(d.ttl),
    found: bool(d.found),
  };
};

/* -------------------------------------------------------------------------- */
/* ACL                                                                          */
/* -------------------------------------------------------------------------- */

/** One ACL rule; also the request shape for `acl.set`. */
export interface ACLRule {
  name: string;
  networks: string[];
  /** `allow` | `deny` | `redirect`. */
  action: 'allow' | 'deny' | 'redirect';
  /** Query types this rule applies to; empty means all types. */
  types?: string[];
  /** Redirect target for `action: 'redirect'` rules. */
  redirect?: string;
}

export const aclRuleToJson = (rule: ACLRule): JsonObject => ({
  name: rule.name,
  networks: rule.networks,
  action: rule.action,
  ...(rule.types && rule.types.length ? { types: rule.types } : {}),
  ...(rule.redirect ? { redirect: rule.redirect } : {}),
});

const aclRuleFromJson = (json: unknown): ACLRule => {
  const d = asRecord(json);
  const action = str(d.action) as ACLRule['action'];
  return {
    name: str(d.name),
    networks: strArray(d.networks),
    action: action === 'allow' || action === 'deny' || action === 'redirect' ? action : 'deny',
    types: strArray(d.types),
    redirect: d.redirect === undefined ? undefined : str(d.redirect),
  };
};

/** Clients permitted to use recursive resolution. */
export interface RecursionAllowList {
  allowAll: boolean;
  networks: string[];
}

const recursionFromJson = (json: unknown): RecursionAllowList => {
  const d = asRecord(json);
  return { allowAll: bool(d.allow_all), networks: strArray(d.networks) };
};

/** `GET /api/v1/acl`. */
export interface ACLConfig {
  rules: ACLRule[];
  allowRecursion?: RecursionAllowList;
  /** True when served from `access_policy.json` rather than the config file. */
  persistent: boolean;
  policyFile: string;
}

export const aclConfigFromJson = (json: unknown): ACLConfig => {
  const d = asRecord(json);
  return {
    rules: asArray(d.rules).map(aclRuleFromJson),
    allowRecursion:
      d.allow_recursion === undefined || d.allow_recursion === null
        ? undefined
        : recursionFromJson(d.allow_recursion),
    persistent: bool(d.persistent),
    policyFile: str(d.policy_file),
  };
};

/* -------------------------------------------------------------------------- */
/* Blocklists, RPZ, DNSSEC, upstreams, GeoDNS                                  */
/* -------------------------------------------------------------------------- */

export interface BlocklistStats {
  enabled: boolean;
  totalRules: number;
  filesCount: number;
  urlsCount: number;
}

const blocklistStatsFromJson = (json: unknown): BlocklistStats => {
  const d = asRecord(json);
  return {
    enabled: bool(d.enabled),
    totalRules: num(d.total_rules),
    filesCount: num(d.files_count),
    urlsCount: num(d.urls_count),
  };
};

export interface BlocklistSource {
  id: string;
  /** `file` | `url`. */
  type: string;
  enabled: boolean;
  domains: number;
}

const blocklistSourceFromJson = (json: unknown): BlocklistSource => {
  const d = asRecord(json);
  return { id: str(d.id), type: str(d.type), enabled: bool(d.enabled, true), domains: num(d.domains) };
};

export interface RPZStats {
  enabled: boolean;
  totalRules: number;
  qnameRules: number;
  clientIpRules: number;
  respIpRules: number;
  filesCount: number;
  totalMatches: number;
  totalLookups: number;
  lastReload?: string;
}

const rpzStatsFromJson = (json: unknown): RPZStats => {
  const d = asRecord(json);
  return {
    enabled: bool(d.enabled),
    totalRules: num(d.total_rules),
    qnameRules: num(d.qname_rules),
    clientIpRules: num(d.client_ip_rules),
    respIpRules: num(d.resp_ip_rules),
    filesCount: num(d.files_count),
    totalMatches: num(d.total_matches),
    totalLookups: num(d.total_lookups),
    lastReload: d.last_reload === undefined ? undefined : str(d.last_reload),
  };
};

export type RPZAction = 'NXDOMAIN' | 'NODATA' | 'CNAME' | 'OVERRIDE' | 'DROP' | 'PASSTHROUGH' | 'TCPONLY';

export interface RPZRule {
  pattern: string;
  action: string;
  trigger: string;
  overrideData: string;
  policyName: string;
  priority: number;
}

const rpzRuleFromJson = (json: unknown): RPZRule => {
  const d = asRecord(json);
  return {
    pattern: str(d.pattern),
    action: str(d.action),
    trigger: str(d.trigger),
    overrideData: str(d.override_data),
    policyName: str(d.policy_name),
    priority: num(d.priority),
  };
};

export interface RPZRuleList {
  rules: RPZRule[];
  total: number;
  truncated: boolean;
}

const rpzRuleListFromJson = (json: unknown): RPZRuleList => {
  const d = asRecord(json);
  return {
    rules: asArray(d.rules).map(rpzRuleFromJson),
    total: num(d.total),
    truncated: bool(d.truncated),
  };
};

export interface DNSSECStatus {
  enabled: boolean;
  requireDnssec: boolean;
}

const dnssecStatusFromJson = (json: unknown): DNSSECStatus => {
  const d = asRecord(json);
  return { enabled: bool(d.enabled), requireDnssec: bool(d.require_dnssec) };
};

/** Public signing-key metadata; the API never exposes private keys. */
export interface DNSSECKey {
  keyTag: number;
  algorithm: number;
  flags: number;
  isKSK: boolean;
  isZSK: boolean;
  zone: string;
}

const dnssecKeyFromJson = (json: unknown): DNSSECKey => {
  const d = asRecord(json);
  return {
    keyTag: num(d.keyTag),
    algorithm: num(d.algorithm),
    flags: num(d.flags),
    isKSK: bool(d.isKSK),
    isZSK: bool(d.isZSK),
    zone: str(d.zone),
  };
};

export interface DNSSECKeyList {
  keys: DNSSECKey[];
}

const dnssecKeyListFromJson = (json: unknown): DNSSECKeyList => {
  const d = asRecord(json);
  return { keys: asArray(d.zones).map(dnssecKeyFromJson) };
};

export interface UpstreamHealth {
  address: string;
  healthy: boolean;
  queries: number;
  failed: number;
  failovers: number;
}

const upstreamHealthFromJson = (json: unknown): UpstreamHealth => {
  const d = asRecord(json);
  return {
    address: str(d.address),
    healthy: bool(d.healthy),
    queries: num(d.queries),
    failed: num(d.failed),
    failovers: num(d.failovers),
  };
};

export interface UpstreamServer {
  address: string;
  healthy: boolean;
  latencyMs: number;
}

const upstreamServerFromJson = (json: unknown): UpstreamServer => {
  const d = asRecord(json);
  return { address: str(d.address), healthy: bool(d.healthy), latencyMs: num(d.latency_ms) };
};

export interface Upstreams {
  upstreams: UpstreamHealth[];
  servers: UpstreamServer[];
}

const upstreamsFromJson = (json: unknown): Upstreams => {
  const d = asRecord(json);
  return {
    upstreams: asArray(d.upstreams).map(upstreamHealthFromJson),
    servers: asArray(d.servers).map(upstreamServerFromJson),
  };
};

export interface GeoIPStats {
  enabled: boolean;
  rules: number;
  mmdbLoaded: boolean;
  lookups: number;
  hits: number;
  misses: number;
}

const geoipStatsFromJson = (json: unknown): GeoIPStats => {
  const d = asRecord(json);
  return {
    enabled: bool(d.enabled),
    rules: num(d.rules),
    mmdbLoaded: bool(d.mmdb_loaded),
    lookups: num(d.lookups),
    hits: num(d.hits),
    misses: num(d.misses),
  };
};

/* -------------------------------------------------------------------------- */
/* Cluster                                                                     */
/* -------------------------------------------------------------------------- */

export interface GossipStats {
  messagesSent: number;
  messagesReceived: number;
  pingSent: number;
  pingReceived: number;
}

const gossipFromJson = (json: unknown): GossipStats => {
  const d = asRecord(json);
  return {
    messagesSent: num(d.messages_sent),
    messagesReceived: num(d.messages_received),
    pingSent: num(d.ping_sent),
    pingReceived: num(d.ping_received),
  };
};

export interface RaftStats {
  state: string;
  term: number;
  commitIndex: number;
  appliedIndex: number;
  isLeader: boolean;
  leaderId: string;
}

const raftFromJson = (json: unknown): RaftStats => {
  const d = asRecord(json);
  return {
    state: str(d.state),
    term: num(d.term),
    commitIndex: num(d.commit_index),
    appliedIndex: num(d.applied_index),
    isLeader: bool(d.is_leader),
    leaderId: str(d.leader_id),
  };
};

export interface ClusterMetrics {
  queriesTotal: number;
  queriesPerSecond: number;
  cacheHits: number;
  cacheMisses: number;
  cacheHitRate: number;
  latencyAvgMs: number;
  latencyP99Ms: number;
}

const clusterMetricsFromJson = (json: unknown): ClusterMetrics => {
  const d = asRecord(json);
  return {
    queriesTotal: num(d.queries_total),
    queriesPerSecond: num(d.queries_per_sec),
    cacheHits: num(d.cache_hits),
    cacheMisses: num(d.cache_misses),
    cacheHitRate: num(d.cache_hit_rate),
    latencyAvgMs: num(d.latency_avg_ms),
    latencyP99Ms: num(d.latency_p99_ms),
  };
};

export interface ClusterStatus {
  nodeId: string;
  consensus: string;
  nodeCount: number;
  aliveCount: number;
  healthy: boolean;
  gossip?: GossipStats;
  raft?: RaftStats;
  metrics?: ClusterMetrics;
}

export const clusterStatusFromJson = (json: unknown): ClusterStatus => {
  const d = asRecord(json);
  return {
    nodeId: str(d.node_id),
    consensus: str(d.consensus),
    nodeCount: num(d.node_count),
    aliveCount: num(d.alive_count),
    healthy: bool(d.healthy),
    gossip: d.gossip === undefined || d.gossip === null ? undefined : gossipFromJson(d.gossip),
    raft: d.raft === undefined || d.raft === null ? undefined : raftFromJson(d.raft),
    metrics:
      d.metrics === undefined || d.metrics === null ? undefined : clusterMetricsFromJson(d.metrics),
  };
};

export interface ClusterNode {
  id: string;
  addr: string;
  port: number;
  state: string;
  role: string;
  region: string;
  zone: string;
  weight: number;
  httpAddr: string;
  version: number;
  healthScore: number;
  queriesPerSecond: number;
  latencyMs: number;
  cpuPercent: number;
  memoryPercent: number;
  activeConnections: number;
}

const clusterNodeFromJson = (json: unknown): ClusterNode => {
  const d = asRecord(json);
  return {
    id: str(d.id),
    addr: str(d.addr),
    port: num(d.port),
    state: str(d.state),
    role: str(d.role),
    region: str(d.region),
    zone: str(d.zone),
    weight: num(d.weight),
    httpAddr: str(d.http_addr),
    version: num(d.version),
    healthScore: num(d.health_score),
    queriesPerSecond: num(d.queries_per_second),
    latencyMs: num(d.latency_ms),
    cpuPercent: num(d.cpu_percent),
    memoryPercent: num(d.memory_percent),
    activeConnections: num(d.active_connections),
  };
};

/* -------------------------------------------------------------------------- */
/* Dashboard & metrics                                                         */
/* -------------------------------------------------------------------------- */

/** `GET /api/dashboard/stats` — camelCase on the wire. */
export interface DashboardStats {
  uptime: number;
  queriesTotal: number;
  queriesPerSecond: number;
  cacheHitRate: number;
  blockedQueries: number;
  activeClients: number;
  zoneCount: number;
  upstreamLatency: number;
}

const dashboardStatsFromJson = (json: unknown): DashboardStats => {
  const d = asRecord(json);
  return {
    uptime: num(d.uptime),
    queriesTotal: num(d.queriesTotal),
    queriesPerSecond: num(d.queriesPerSec),
    cacheHitRate: num(d.cacheHitRate),
    blockedQueries: num(d.blockedQueries),
    activeClients: num(d.activeClients),
    zoneCount: num(d.zoneCount),
    upstreamLatency: num(d.upstreamLatency),
  };
};

/** One live query event from `/api/dashboard/queries` (camelCase on the wire). */
export interface QueryEvent {
  timestamp: string;
  clientIp: string;
  countryCode: string;
  domain: string;
  queryType: string;
  responseCode: string;
  answers: string[];
  duration: number;
  cached: boolean;
  blocked: boolean;
  protocol: string;
}

const queryEventFromJson = (json: unknown): QueryEvent => {
  const d = asRecord(json);
  return {
    timestamp: str(d.timestamp),
    clientIp: str(d.clientIp),
    countryCode: str(d.countryCode),
    domain: str(d.domain),
    queryType: str(d.queryType),
    responseCode: str(d.responseCode),
    answers: strArray(d.answers),
    duration: num(d.duration),
    cached: bool(d.cached),
    blocked: bool(d.blocked),
    protocol: str(d.protocol),
  };
};

/** One row of the paginated query log (`/api/v1/queries`, snake_case). */
export interface QueryLogEntry {
  timestamp: string;
  clientIp: string;
  domain: string;
  queryType: string;
  responseCode: string;
  answers: string[];
  durationMs: number;
  cached: boolean;
  blocked: boolean;
  protocol: string;
}

const queryLogEntryFromJson = (json: unknown): QueryLogEntry => {
  const d = asRecord(json);
  return {
    timestamp: str(d.timestamp),
    clientIp: str(d.client_ip),
    domain: str(d.domain),
    queryType: str(d.query_type),
    responseCode: str(d.response_code),
    answers: strArray(d.answers),
    durationMs: num(d.duration_ms),
    cached: bool(d.cached),
    blocked: bool(d.blocked),
    protocol: str(d.protocol),
  };
};

export interface QueryLogPage {
  queries: QueryLogEntry[];
  total: number;
  offset: number;
  limit: number;
}

export const queryLogPageFromJson = (json: unknown): QueryLogPage => {
  const d = asRecord(json);
  return {
    queries: asArray(d.queries).map(queryLogEntryFromJson),
    total: num(d.total),
    offset: num(d.offset),
    limit: num(d.limit),
  };
};

export interface TopDomain {
  domain: string;
  count: number;
}

export interface TopDomains {
  domains: TopDomain[];
  limit: number;
}

const topDomainsFromJson = (json: unknown): TopDomains => {
  const d = asRecord(json);
  return {
    domains: asArray(d.domains).map((entry) => {
      const item = asRecord(entry);
      return { domain: str(item.domain), count: num(item.count) };
    }),
    limit: num(d.limit),
  };
};

/** Ring buffer of recent metric samples; the arrays are parallel. */
export interface MetricsHistory {
  timestamps: number[];
  queries: number[];
  cacheHits: number[];
  cacheMisses: number[];
  latencyMs: number[];
  count: number;
}

const metricsHistoryFromJson = (json: unknown): MetricsHistory => {
  const d = asRecord(json);
  const nums = (value: unknown): number[] => asArray(value).map((item) => num(item));
  return {
    timestamps: nums(d.timestamps),
    queries: nums(d.queries),
    cacheHits: nums(d.cache_hits),
    cacheMisses: nums(d.cache_misses),
    latencyMs: nums(d.latency_ms),
    count: num(d.count),
  };
};

/* -------------------------------------------------------------------------- */
/* Internal mappers reused by the resource namespaces                          */
/* -------------------------------------------------------------------------- */

export const internalMappers = {
  aclRuleFromJson,
  recursionFromJson,
  blocklistStatsFromJson,
  blocklistSourceFromJson,
  rpzStatsFromJson,
  rpzRuleListFromJson,
  dnssecStatusFromJson,
  dnssecKeyListFromJson,
  upstreamsFromJson,
  geoipStatsFromJson,
  clusterNodeFromJson,
  dashboardStatsFromJson,
  queryEventFromJson,
  topDomainsFromJson,
  metricsHistoryFromJson,
};
