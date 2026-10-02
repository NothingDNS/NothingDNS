/**
 * NothingDNS TypeScript/JavaScript SDK.
 *
 * A typed client for the NothingDNS DNS server management API, covering every
 * operation the server exposes over HTTP: zones, records, cache, configuration,
 * ACLs, blocklists, RPZ, DNSSEC, upstreams, GeoDNS, clustering, users and the
 * dashboard/metrics endpoints.
 *
 * The SDK is a thin, well-typed layer over the REST API. It does **not** speak
 * the DNS wire protocols; use a DNS library (for example `dns-packet`) for
 * actual lookups.
 *
 * @example
 * ```ts
 * import { NothingDNSClient } from '@nothingdns/sdk';
 *
 * const client = new NothingDNSClient({ baseUrl: 'http://dns.example.com:8080' });
 * await client.auth.login(process.env.NDNS_USER!, process.env.NDNS_PASSWORD!);
 *
 * for (const zone of (await client.zones.list()).zones) {
 *   console.log(zone.name, zone.records);
 * }
 * ```
 *
 * @packageDocumentation
 */

export { NothingDNSClient, LOG_LEVELS } from './client.js';
export type {
  LogLevel,
  NothingDNSClientOptions,
  CacheConfigOptions,
  ResolutionOptions,
  RRLOptions,
} from './client.js';

export { AuthResource, ROLES } from './auth.js';
export type { RoleName } from './auth.js';

export {
  DEFAULT_BASE_URL,
  DEFAULT_TIMEOUT_MS,
  Transport,
  buildQuery,
  dropNone,
  escapeSegment,
  messageOf,
} from './transport.js';
export type { TransportOptions, QueryValue } from './transport.js';

export {
  NothingDNSApiError,
  NothingDNSConnectionError,
  NothingDNSError,
  NothingDNSValidationError,
  isForbidden,
  isNotFound,
  isRateLimited,
  isUnauthorized,
} from './errors.js';

export * from './models.js';

/** SDK version; kept in step with `package.json`. */
export const VERSION = '1.0.0';
