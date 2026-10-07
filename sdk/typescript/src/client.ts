/**
 * Client and resource namespaces for the NothingDNS management API.
 *
 * The client mirrors the server's API groups as namespaces:
 *
 * ```ts
 * const client = new NothingDNSClient({ baseUrl: 'http://dns.example.com:8080' });
 * await client.auth.login(process.env.NDNS_USER!, process.env.NDNS_PASSWORD!);
 * const zones = await client.zones.list();
 * ```
 */

import { NothingDNSValidationError } from './errors.js';
import { AuthResource, ROLES, type RoleName } from './auth.js';
import {
  aclConfigFromJson,
  aclRuleToJson,
  cacheStatsFromJson,
  clusterStatusFromJson,
  healthFromJson,
  internalMappers,
  ptrBulkPreviewFromJson,
  ptrBulkResultFromJson,
  ptrLookupFromJson,
  queryLogPageFromJson,
  recordListFromJson,
  serverConfigFromJson,
  slaveZoneFromJson,
  statusFromJson,
  zoneDetailFromJson,
  zoneFromJson,
  zoneListFromJson,
} from './models.js';
import type {
  ACLConfig,
  ACLRule,
  BlocklistSource,
  BlocklistStats,
  CacheStats,
  ClusterNode,
  ClusterStatus,
  DNSSECKeyList,
  DNSSECStatus,
  DashboardStats,
  GeoIPStats,
  HealthResponse,
  MetricsHistory,
  PTRBulkPreview,
  PTRBulkResult,
  PTRLookup,
  QueryEvent,
  QueryLogPage,
  RPZAction,
  RPZRuleList,
  RPZStats,
  RecordList,
  RecursionAllowList,
  ServerConfig,
  SlaveZone,
  StatusResponse,
  TopDomains,
  Upstreams,
  Zone,
  ZoneDetail,
  ZoneList,
} from './models.js';
import { Transport, dropNone, escapeSegment, messageOf, type TransportOptions } from './transport.js';

/** Log levels accepted by {@link ConfigResource.setLogging}. */
export const LOG_LEVELS = ['debug', 'info', 'warn', 'warning', 'error', 'fatal'] as const;

/** One of the log levels the server accepts. */
export type LogLevel = (typeof LOG_LEVELS)[number];

/** Actions accepted by {@link RPZResource.addRule}. */
export const RPZ_ACTIONS = [
  'NXDOMAIN',
  'NODATA',
  'CNAME',
  'OVERRIDE',
  'DROP',
  'PASSTHROUGH',
  'TCPONLY',
] as const;

/** Zones, records, export and bulk PTR generation (`/api/v1/zones`). */
export class ZonesResource {
  constructor(private readonly t: Transport) {}

  /**
   * List every zone served by this node (operator+).
   *
   * When `truncated` is true the server capped the response and `total` may be
   * larger than `zones.length`.
   */
  async list(): Promise<ZoneList> {
    return zoneListFromJson(await this.t.get('/api/v1/zones'));
  }

  /**
   * Create a new authoritative zone (operator+).
   *
   * @param name - Zone name; a trailing dot is added when missing.
   * @param nameservers - NS hostnames written into the zone's SOA record.
   * @param adminEmail - Zone admin e-mail; the server derives the SOA `rname`.
   * @throws {@link NothingDNSApiError} 409 when the zone exists, 421 when the
   *   name cannot become its own zone.
   */
  async create(
    name: string,
    nameservers: string[],
    options: { adminEmail?: string; ttl?: number } = {},
  ): Promise<string> {
    if (nameservers.length === 0) {
      throw new NothingDNSValidationError('nameservers must contain at least one hostname');
    }
    return messageOf(
      await this.t.post('/api/v1/zones', {
        body: dropNone({
          name,
          nameservers,
          admin_email: options.adminEmail,
          ttl: options.ttl,
        }),
      }),
    );
  }

  /** Get one zone with its SOA record and NS set (operator+). Throws 404 when absent. */
  async get(zone: string): Promise<ZoneDetail> {
    return zoneDetailFromJson(await this.t.get(`/api/v1/zones/${escapeSegment(zone)}`));
  }

  /** Delete a zone together with all of its records (operator+). */
  async delete(zone: string): Promise<string> {
    return messageOf(await this.t.delete(`/api/v1/zones/${escapeSegment(zone)}`));
  }

  /** Re-read one zone from its on-disk zone file (admin only). */
  async reload(zone: string): Promise<string> {
    return messageOf(
      await this.t.post('/api/v1/zones/reload', { query: { zone }, expectJson: false }),
    );
  }

  /** List secondary (slave) zones and their transfer state (operator+). */
  async transfers(): Promise<SlaveZone[]> {
    const json = await this.t.get<{ slave_zones?: unknown }>('/api/v1/zones/transfers');
    return Array.isArray(json?.slave_zones) ? json.slave_zones.map(slaveZoneFromJson) : [];
  }

  /**
   * List records in a zone (operator+).
   *
   * @param name - Optional owner-name filter (`www` or `www.example.com`).
   */
  async listRecords(zone: string, options: { name?: string } = {}): Promise<RecordList> {
    const json = await this.t.get(`/api/v1/zones/${escapeSegment(zone)}/records`, {
      query: { name: options.name },
    });
    return recordListFromJson(json);
  }

  /**
   * Add a record to a zone (operator+).
   *
   * @param name - Owner name relative to the zone; `@` is the apex.
   * @param data - Record data in zone-file presentation format.
   * @throws {@link NothingDNSApiError} 400 for invalid data, 421 on conflict.
   */
  async addRecord(
    zone: string,
    name: string,
    type: string,
    data: string,
    options: { ttl?: number } = {},
  ): Promise<string> {
    return messageOf(
      await this.t.post(`/api/v1/zones/${escapeSegment(zone)}/records`, {
        body: dropNone({ name, type, data, ttl: options.ttl }),
      }),
    );
  }

  /**
   * Replace the data of an existing record (operator+).
   *
   * The server identifies the record by `(name, type, oldData)`, so pass the
   * record's *current* data as `oldData` and the new value as `data`.
   */
  async replaceRecord(
    zone: string,
    name: string,
    type: string,
    oldData: string,
    data: string,
    options: { ttl?: number } = {},
  ): Promise<string> {
    return messageOf(
      await this.t.put(`/api/v1/zones/${escapeSegment(zone)}/records`, {
        body: dropNone({ name, type, old_data: oldData, data, ttl: options.ttl }),
      }),
    );
  }

  /** Delete every record of `type` owned by `name` (operator+). */
  async deleteRecords(zone: string, name: string, type: string): Promise<string> {
    return messageOf(
      await this.t.delete(`/api/v1/zones/${escapeSegment(zone)}/records`, {
        body: { name, type },
      }),
    );
  }

  /**
   * Delete the single record of `type` owned by `name` whose RDATA equals
   * `data`, leaving the rest of the RRset in place (operator+). The server
   * compares RDATA in canonical form (names case-insensitively, TXT exactly).
   *
   * @throws {@link NothingDNSApiError} 404 when no record matches; 400 for SOA
   *   records and the zone apex NS RRset.
   * @throws {@link NothingDNSValidationError} when `data` is blank (an empty
   *   data field would delete the whole RRset — use `deleteRecords` for that).
   */
  async deleteRecord(zone: string, name: string, type: string, data: string): Promise<string> {
    if (data.trim() === '') {
      throw new NothingDNSValidationError(
        'data is required to delete a single record; use deleteRecords to delete the whole RRset',
      );
    }
    return messageOf(
      await this.t.delete(`/api/v1/zones/${escapeSegment(zone)}/records`, {
        body: { name, type, data },
      }),
    );
  }

  /** Export a zone in BIND zone-file format (operator+). */
  async export(zone: string): Promise<string> {
    return this.t.get<string>(`/api/v1/zones/${escapeSegment(zone)}/export`, { raw: true });
  }

  /**
   * Generate PTR (and optionally forward-confirmed A) records for an IPv4 range
   * (operator+).
   *
   * @param cidr - IPv4 CIDR to cover; the server rejects ranges larger than /16.
   * @param pattern - Target hostname template; `{ip}` is replaced with the
   *   address, e.g. `host-{ip}.example.com`.
   * @param preview - When true (the default) nothing is written and the planned
   *   changes are returned instead.
   * @returns A {@link PTRBulkPreview} for a preview, otherwise a
   *   {@link PTRBulkResult} with the applied counts.
   */
  async ptrBulk(
    zone: string,
    cidr: string,
    pattern: string,
    options: { override?: boolean; addA?: boolean; preview?: boolean } = {},
  ): Promise<PTRBulkPreview | PTRBulkResult> {
    const preview = options.preview ?? true;
    const json = await this.t.post(`/api/v1/zones/${escapeSegment(zone)}/ptr-bulk`, {
      body: {
        cidr,
        pattern,
        override: options.override ?? false,
        addA: options.addA ?? false,
        preview,
      },
    });
    return preview ? ptrBulkPreviewFromJson(json) : ptrBulkResultFromJson(json);
  }

  /** Look up the PTR record for an IPv6 address in a zone (operator+). */
  async ptr6Lookup(zone: string, ip: string): Promise<PTRLookup> {
    return ptrLookupFromJson(
      await this.t.get(`/api/v1/zones/${escapeSegment(zone)}/ptr6-lookup`, { query: { ip } }),
    );
  }
}

/** The DNS response cache (`/api/v1/cache`). */
export class CacheResource {
  constructor(private readonly t: Transport) {}

  /** Cache size, capacity, hit/miss counters and hit ratio (operator+). */
  async stats(): Promise<CacheStats> {
    return cacheStatsFromJson(await this.t.get('/api/v1/cache/stats'));
  }

  /** Drop every cached entry (admin only). */
  async flush(): Promise<string> {
    return messageOf(await this.t.post('/api/v1/cache/flush', { expectJson: false }));
  }
}

/** Options for the partial runtime-config setters. All fields are optional. */
export interface RRLOptions {
  enabled?: boolean;
  rate?: number;
  burst?: number;
  maxBuckets?: number;
}

/** Options for {@link ConfigResource.setCache}. */
export interface CacheConfigOptions {
  enabled?: boolean;
  size?: number;
  defaultTtl?: number;
  maxTtl?: number;
  minTtl?: number;
  negativeTtl?: number;
  prefetch?: boolean;
  prefetchThreshold?: number;
  serveStale?: boolean;
  staleGraceSecs?: number;
}

/** Options for {@link ConfigResource.setResolution}. */
export interface ResolutionOptions {
  recursive?: boolean;
  authoritativeOnly?: boolean;
  maxDepth?: number;
  /** Resolver timeout as a duration string, e.g. `2s`. */
  timeout?: string;
  edns0BufferSize?: number;
  qnameMinimization?: boolean;
  use0x20?: boolean;
}

/**
 * Configuration inspection and runtime tunables (`/api/v1/config`).
 *
 * Runtime changes are persisted to `runtime_overrides.json` in the data
 * directory and re-applied over the YAML section on every config reload, so
 * they survive a restart. Every setter requires the admin role and is a
 * *partial* update — omitted options keep their current value.
 */
export class ConfigResource {
  constructor(private readonly t: Transport) {}

  /** Effective configuration with secrets redacted (operator+). */
  async get(): Promise<Record<string, unknown>> {
    return this.t.get<Record<string, unknown>>('/api/v1/config');
  }

  /** Re-read the YAML config file without dropping the listener (admin only). */
  async reload(): Promise<string> {
    return messageOf(await this.t.post('/api/v1/config/reload', { expectJson: false }));
  }

  /** Change the log level at runtime (admin only). */
  async setLogging(level: LogLevel): Promise<string> {
    if (!LOG_LEVELS.includes(level)) {
      throw new NothingDNSValidationError(`level must be one of ${LOG_LEVELS.join(', ')}`);
    }
    return this.put('/api/v1/config/logging', { level });
  }

  /** Tune the per-client response-rate limiter (admin only). */
  async setRRL(options: RRLOptions = {}): Promise<string> {
    return this.put(
      '/api/v1/config/rrl',
      dropNone({
        enabled: options.enabled,
        rate: options.rate,
        burst: options.burst,
        max_buckets: options.maxBuckets,
      }),
    );
  }

  /** Tune the response cache at runtime (admin only). */
  async setCache(options: CacheConfigOptions = {}): Promise<string> {
    return this.put(
      '/api/v1/config/cache',
      dropNone({
        enabled: options.enabled,
        size: options.size,
        default_ttl: options.defaultTtl,
        max_ttl: options.maxTtl,
        min_ttl: options.minTtl,
        negative_ttl: options.negativeTtl,
        prefetch: options.prefetch,
        prefetch_threshold: options.prefetchThreshold,
        serve_stale: options.serveStale,
        stale_grace_secs: options.staleGraceSecs,
      }),
    );
  }

  /** Tune iterative resolution at runtime (admin only). */
  async setResolution(options: ResolutionOptions = {}): Promise<string> {
    return this.put(
      '/api/v1/config/resolution',
      dropNone({
        recursive: options.recursive,
        authoritative_only: options.authoritativeOnly,
        max_depth: options.maxDepth,
        timeout: options.timeout,
        edns0_buffer_size: options.edns0BufferSize,
        qname_minimization: options.qnameMinimization,
        use_0x20: options.use0x20,
      }),
    );
  }

  /** Enable or disable DNS64 synthesis for NAT64 networks (RFC 6147) (admin only). */
  async setDns64(enabled: boolean): Promise<string> {
    return this.put('/api/v1/config/dns64', { enabled });
  }

  /** Enable or disable DNS Cookies (RFC 7873) (admin only). */
  async setCookie(enabled: boolean): Promise<string> {
    return this.put('/api/v1/config/cookie', { enabled });
  }

  private async put(path: string, body: Record<string, unknown>): Promise<string> {
    return messageOf(await this.t.put(path, { body, expectJson: false }));
  }
}

/**
 * Client ACLs and the recursion allow list (`/api/v1/acl`).
 *
 * Rules are evaluated in server-config order and the first match wins; once any
 * rule exists, a client matching none of them is refused.
 */
export class ACLResource {
  constructor(private readonly t: Transport) {}

  /**
   * Return ACL rules plus the recursion allow list (operator+).
   *
   * When `persistent` is true the list is served from `access_policy.json` — the
   * dashboard-managed file that overrides the YAML config on reload.
   */
  async get(): Promise<ACLConfig> {
    return aclConfigFromJson(await this.t.get('/api/v1/acl'));
  }

  /**
   * Replace the full ACL rule list (admin only).
   *
   * @warning This replaces the whole list — it is not a merge. To change one
   *   rule, read the current list, edit it and send it back:
   *
   *   ```ts
   *   const current = await client.acl.get();
   *   await client.acl.set([...current.rules, newRule]);
   *   ```
   */
  async set(rules: ACLRule[]): Promise<string> {
    if (rules.length === 0) {
      throw new NothingDNSValidationError(
        'refusing to send an empty rule list; pass [] only deliberately',
      );
    }
    return messageOf(
      await this.t.put('/api/v1/acl', {
        body: { rules: rules.map(aclRuleToJson) },
        expectJson: false,
      }),
    );
  }

  /** Return the recursion allow list (operator+). */
  async recursion(): Promise<RecursionAllowList> {
    const json = await this.t.get<unknown>('/api/v1/acl/recursion');
    return internalMappers.recursionFromJson(json);
  }

  /**
   * Replace the recursion allow list (admin only).
   *
   * @param networks - CIDR networks allowed to send recursive queries. An empty
   *   list denies recursion to every client.
   * @returns The stored list as the server returned it.
   */
  async setRecursion(networks: string[]): Promise<RecursionAllowList> {
    const json = await this.t.put<unknown>('/api/v1/acl/recursion', { body: { networks } });
    return internalMappers.recursionFromJson(json);
  }
}

/** Blocklist sources and global filtering (`/api/v1/blocklists`). */
export class BlocklistsResource {
  constructor(private readonly t: Transport) {}

  /** Blocklist statistics: enabled flag and rule counts (operator+). */
  async stats(): Promise<BlocklistStats> {
    return internalMappers.blocklistStatsFromJson(await this.t.get('/api/v1/blocklists'));
  }

  /**
   * Add a blocklist source (admin only). Pass exactly one of `file` or `url`.
   *
   * @param file - Path of a hosts-format file on the server to load.
   * @param url - HTTP(S) URL of a hosts-format list for the server to fetch.
   */
  async add(options: { file?: string; url?: string }): Promise<string> {
    const provided = [options.file, options.url].filter((value) => value !== undefined).length;
    if (provided !== 1) {
      throw new NothingDNSValidationError('pass exactly one of file or url');
    }
    return messageOf(
      await this.t.post('/api/v1/blocklists', {
        body: dropNone({ file: options.file, url: options.url }),
        expectJson: false,
      }),
    );
  }

  /** List every configured blocklist source (operator+). */
  async sources(): Promise<BlocklistSource[]> {
    const json = await this.t.get<unknown[]>('/api/v1/blocklists/sources');
    return Array.isArray(json) ? json.map(internalMappers.blocklistSourceFromJson) : [];
  }

  /** Flip blocklist filtering on/off globally (admin only). */
  async toggle(): Promise<string> {
    return messageOf(await this.t.post('/api/v1/blocklists/toggle', { expectJson: false }));
  }

  /** Remove one blocklist source by id (admin only). */
  async remove(source: string): Promise<string> {
    return messageOf(
      await this.t.delete(`/api/v1/blocklists/${escapeSegment(source)}`, { expectJson: false }),
    );
  }

  /** Enable or disable a single blocklist source (admin only). */
  async toggleSource(source: string): Promise<string> {
    return messageOf(
      await this.t.post(`/api/v1/blocklists/${escapeSegment(source)}/toggle`, { expectJson: false }),
    );
  }
}

/** Response Policy Zones (`/api/v1/rpz`). */
export class RPZResource {
  constructor(private readonly t: Transport) {}

  /** RPZ statistics: rule counts, matches, lookups, last reload (operator+). */
  async stats(): Promise<RPZStats> {
    return internalMappers.rpzStatsFromJson(await this.t.get('/api/v1/rpz'));
  }

  /** List the QNAME rules (operator+). */
  async rules(): Promise<RPZRuleList> {
    return internalMappers.rpzRuleListFromJson(await this.t.get('/api/v1/rpz/rules'));
  }

  /**
   * Add a QNAME rule (admin only).
   *
   * @param pattern - Domain pattern, e.g. `ads.example.com` or `*.tracker.com`.
   * @param action - Policy action; `CNAME` and `OVERRIDE` need `overrideData`.
   */
  async addRule(
    pattern: string,
    action: RPZAction = 'NXDOMAIN',
    options: { overrideData?: string } = {},
  ): Promise<string> {
    if (!RPZ_ACTIONS.includes(action)) {
      throw new NothingDNSValidationError(`action must be one of ${RPZ_ACTIONS.join(', ')}`);
    }
    return messageOf(
      await this.t.post('/api/v1/rpz/rules', {
        body: dropNone({ pattern, action, override_data: options.overrideData }),
        expectJson: false,
      }),
    );
  }

  /** Delete a QNAME rule by pattern (admin only). */
  async deleteRule(pattern: string): Promise<string> {
    return messageOf(
      await this.t.delete('/api/v1/rpz/rules', { query: { pattern }, expectJson: false }),
    );
  }

  /** Flip RPZ filtering on/off (admin only). */
  async toggle(): Promise<string> {
    return messageOf(await this.t.post('/api/v1/rpz/toggle', { expectJson: false }));
  }
}

/** DNSSEC validation status and signing keys (`/api/v1/dnssec`). */
export class DNSSECResource {
  constructor(private readonly t: Transport) {}

  /**
   * Validation status (operator+).
   *
   * `enabled` reports whether validation runs at all; `requireDnssec` whether
   * bogus answers are refused rather than served.
   */
  async status(): Promise<DNSSECStatus> {
    return internalMappers.dnssecStatusFromJson(await this.t.get('/api/v1/dnssec/status'));
  }

  /** Public signing-key metadata (admin). Private key material is never exposed. */
  async keys(): Promise<DNSSECKeyList> {
    return internalMappers.dnssecKeyListFromJson(await this.t.get('/api/v1/dnssec/keys'));
  }
}

/** The upstream resolver pool (`/api/v1/upstreams`). */
export class UpstreamsResource {
  constructor(private readonly t: Transport) {}

  /** Upstream health and counters (operator+). */
  async list(): Promise<Upstreams> {
    return internalMappers.upstreamsFromJson(await this.t.get('/api/v1/upstreams'));
  }

  /**
   * Add one upstream server at runtime (admin only).
   *
   * @param server - Address in `host:port` form, e.g. `9.9.9.9:53`.
   * @throws {@link NothingDNSApiError} 409 when the server is already present;
   *   400 when the address has no valid port or is private.
   */
  async add(server: string): Promise<string> {
    return this.change('add', server);
  }

  /**
   * Remove one upstream server at runtime (admin only).
   *
   * @throws {@link NothingDNSApiError} 400 when it is the last server.
   */
  async remove(server: string): Promise<string> {
    return this.change('remove', server);
  }

  private async change(action: 'add' | 'remove', server: string): Promise<string> {
    return messageOf(
      await this.t.put('/api/v1/upstreams', { body: { action, server }, expectJson: false }),
    );
  }
}

/** GeoDNS statistics (`/api/v1/geoip`). */
export class GeoIPResource {
  constructor(private readonly t: Transport) {}

  /** GeoDNS statistics, including whether the MMDB is loaded (operator+). */
  async stats(): Promise<GeoIPStats> {
    return internalMappers.geoipStatsFromJson(await this.t.get('/api/v1/geoip/stats'));
  }
}

/** Gossip membership and Raft consensus (`/api/v1/cluster`). */
export class ClusterResource {
  constructor(private readonly t: Transport) {}

  /** Cluster status: node id, consensus, Raft state, metrics (operator+). */
  async status(): Promise<ClusterStatus> {
    return clusterStatusFromJson(await this.t.get('/api/v1/cluster/status'));
  }

  /** List every node known to the gossip layer (operator+). */
  async nodes(): Promise<ClusterNode[]> {
    const json = await this.t.get<{ nodes?: unknown }>('/api/v1/cluster/nodes');
    return Array.isArray(json?.nodes) ? json.nodes.map(internalMappers.clusterNodeFromJson) : [];
  }

  /**
   * Join a cluster through a seed node (admin only).
   *
   * @param seedAddress - `host:port` of a node that is already a member.
   * @warning Joining changes this node's cluster identity. Run it once on a
   *   freshly provisioned node, never on a node already serving traffic.
   */
  async join(seedAddress: string): Promise<string> {
    return messageOf(
      await this.t.post('/api/v1/cluster/join', {
        body: { seed_address: seedAddress },
        expectJson: false,
      }),
    );
  }

  /** Drain this node and leave the cluster (admin only). */
  async leave(): Promise<string> {
    return messageOf(await this.t.delete('/api/v1/cluster/leave', { expectJson: false }));
  }
}

/** Dashboard counters and live query events (`/api/dashboard`). */
export class DashboardResource {
  constructor(private readonly t: Transport) {}

  /** The dashboard counter block (operator+). */
  async stats(): Promise<DashboardStats> {
    return internalMappers.dashboardStatsFromJson(await this.t.get('/api/dashboard/stats'));
  }

  /**
   * The last 100 query events (operator+).
   *
   * Event properties are camelCase (`clientIp`, `queryType`, …) — this endpoint
   * differs from the rest of the API, which is snake_case.
   */
  async queries(): Promise<QueryEvent[]> {
    const json = await this.t.get<unknown[]>('/api/dashboard/queries');
    return Array.isArray(json) ? json.map(internalMappers.queryEventFromJson) : [];
  }

  /** The dashboard zone summary (operator+). */
  async zones(): Promise<Zone[]> {
    const json = await this.t.get<unknown[]>('/api/dashboard/zones');
    return Array.isArray(json) ? json.map(zoneFromJson) : [];
  }
}

/** Query log, top domains and the metrics history ring buffer. */
export class MetricsResource {
  constructor(private readonly t: Transport) {}

  /**
   * One page of the query log (operator+).
   *
   * @param offset - Index of the first row to return.
   * @param limit - Page size.
   * @param q - Substring filter matched against the queried domain.
   */
  async queryLog(
    options: { offset?: number; limit?: number; q?: string } = {},
  ): Promise<QueryLogPage> {
    const json = await this.t.get('/api/v1/queries', {
      query: { offset: options.offset, limit: options.limit, q: options.q },
    });
    return queryLogPageFromJson(json);
  }

  /** The most-queried domains (operator+). */
  async topDomains(options: { limit?: number } = {}): Promise<TopDomains> {
    return internalMappers.topDomainsFromJson(
      await this.t.get('/api/v1/topdomains', { query: { limit: options.limit } }),
    );
  }

  /**
   * The recent metrics ring buffer (operator+).
   *
   * The arrays are parallel: `queries[i]` was recorded at `timestamps[i]`.
   */
  async history(): Promise<MetricsHistory> {
    return internalMappers.metricsHistoryFromJson(await this.t.get('/api/v1/metrics/history'));
  }
}

/** Options for the {@link NothingDNSClient} constructor. */
export interface NothingDNSClientOptions extends TransportOptions {}

/**
 * Client for the NothingDNS management API.
 *
 * @example
 * ```ts
 * const client = new NothingDNSClient({ baseUrl: 'http://dns.example.com:8080' });
 * await client.auth.login(process.env.NDNS_USER!, process.env.NDNS_PASSWORD!);
 * for (const zone of (await client.zones.list()).zones) {
 *   console.log(zone.name, zone.records);
 * }
 * ```
 */
export class NothingDNSClient {
  /** Authentication, users and roles. */
  readonly auth: AuthResource;
  readonly zones: ZonesResource;
  readonly cache: CacheResource;
  readonly config: ConfigResource;
  readonly acl: ACLResource;
  readonly blocklists: BlocklistsResource;
  readonly rpz: RPZResource;
  readonly dnssec: DNSSECResource;
  readonly upstreams: UpstreamsResource;
  readonly geoip: GeoIPResource;
  readonly cluster: ClusterResource;
  readonly dashboard: DashboardResource;
  readonly metrics: MetricsResource;

  private readonly transport: Transport;

  constructor(options: NothingDNSClientOptions = {}) {
    this.transport = new Transport(options);
    this.auth = new AuthResource(this.transport);
    this.zones = new ZonesResource(this.transport);
    this.cache = new CacheResource(this.transport);
    this.config = new ConfigResource(this.transport);
    this.acl = new ACLResource(this.transport);
    this.blocklists = new BlocklistsResource(this.transport);
    this.rpz = new RPZResource(this.transport);
    this.dnssec = new DNSSECResource(this.transport);
    this.upstreams = new UpstreamsResource(this.transport);
    this.geoip = new GeoIPResource(this.transport);
    this.cluster = new ClusterResource(this.transport);
    this.dashboard = new DashboardResource(this.transport);
    this.metrics = new MetricsResource(this.transport);
  }

  /** Base URL of the server, without a trailing slash. */
  get baseUrl(): string {
    return this.transport.baseUrl;
  }

  /** The bearer token currently in use. */
  get token(): string | null {
    return this.transport.getToken();
  }

  /**
   * Set the bearer token used by every namespace.
   *
   * Pass a JWT from `auth.login` / `auth.bootstrap`, the static
   * `server.http.auth_token` value, or `null` to continue unauthenticated.
   */
  setToken(token: string | null): void {
    this.transport.setToken(token);
  }

  /* -- health & status ---------------------------------------------------- */

  /** `GET /health` — health check; no authentication required. */
  async health(): Promise<HealthResponse> {
    return healthFromJson(await this.transport.get('/health'));
  }

  /**
   * `GET /readyz` — readiness probe; no authentication required.
   *
   * @throws {@link NothingDNSApiError} 503 when the server is not ready to
   *   answer queries; treat that as "not ready", not as a hard failure.
   */
  async ready(): Promise<HealthResponse> {
    return healthFromJson(await this.transport.get('/readyz'));
  }

  /** `GET /livez` — liveness probe; no authentication required. */
  async live(): Promise<HealthResponse> {
    return healthFromJson(await this.transport.get('/livez'));
  }

  /**
   * `GET /api/v1/status` — status, version, cache and cluster summary.
   *
   * Any authenticated user may call this; the `cache` field is only populated
   * for operators and admins.
   */
  async status(): Promise<StatusResponse> {
    return statusFromJson(await this.transport.get('/api/v1/status'));
  }

  /** `GET /api/v1/server/config` — port, log level, DNS64, cookies (operator+). */
  async serverConfig(): Promise<ServerConfig> {
    return serverConfigFromJson(await this.transport.get('/api/v1/server/config'));
  }

  /**
   * Return the server's OpenAPI document (`GET /api/openapi.json`).
   *
   * Useful to detect server capabilities this SDK version predates.
   */
  async openapiSpec(): Promise<Record<string, unknown>> {
    return this.transport.get<Record<string, unknown>>('/api/openapi.json');
  }
}

export { ROLES };
export type { RoleName };
