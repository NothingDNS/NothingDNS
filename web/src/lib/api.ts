const API_BASE = '';

function getToken(): string | null {
  const match = document.cookie.match(/ndns_token=([^;]+)/);
  if (match) return decodeURIComponent(match[1]);
  return null;
}

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const opts: RequestInit = { method, headers };
  if (body) opts.body = JSON.stringify(body);
  const resp = await fetch(`${API_BASE}${path}`, opts);

  // Handle non-JSON responses gracefully
  const contentType = resp.headers.get('content-type');
  if (!resp.ok) {
    // Try to parse error from JSON response
    if (contentType?.includes('application/json')) {
      try {
        const data = await resp.json();
        throw new Error(data.error || `HTTP ${resp.status}: ${resp.statusText}`);
      } catch (e) {
        if (e instanceof SyntaxError) {
          // Non-JSON error body
          throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
        }
        throw e; // Re-throw if we already have a meaningful Error
      }
    }
    throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
  }

  // Only parse JSON on success
  if (contentType?.includes('application/json')) {
    return await resp.json() as T;
  }
  // Return empty object for non-JSON success responses
  return {} as T;
}

export interface DashboardStats {
  uptime: number;
  queriesTotal: number;
  queriesPerSec: number;
  cacheHitRate: number;
  blockedQueries: number;
  activeClients: number;
  zoneCount: number;
  upstreamLatency: number;
}

export interface QueryEvent {
  timestamp: string;
  clientIp: string;
  domain: string;
  queryType: string;
  responseCode: string;
  duration: number;
  cached: boolean;
  blocked: boolean;
  protocol: string;
}

export interface Zone {
  name: string;
  serial: number;
  records: number;
}

export interface ZoneDetail {
  name: string;
  records: number;
  serial?: number;
  soa?: { mname: string; rname: string; serial: number; refresh: number; retry: number; expire: number; minimum: number };
  nameservers?: string[];
}

export interface DnsRecord {
  name: string;
  type: string;
  ttl: number;
  class: string;
  data: string;
}

export interface ServerStatus {
  status: string;
  timestamp: string;
  version: string;
  cache?: { size: number; capacity: number; hits: number; misses: number; hit_ratio: number };
  cluster?: { enabled: boolean; node_id?: string; node_count?: number; alive_count?: number; healthy?: boolean };
}

export interface QueryLogEntry {
  timestamp: string;
  client_ip: string;
  domain: string;
  query_type: string;
  response_code: string;
  duration_ms: number;
  cached: boolean;
  blocked: boolean;
  protocol: string;
}

export interface QueryLogResponse {
  queries: QueryLogEntry[];
  total: number;
  offset: number;
  limit: number;
}

export interface TopDomainsEntry {
  domain: string;
  count: number;
}

export interface TopDomainsResponse {
  domains: TopDomainsEntry[];
  limit: number;
}

export interface DNSSECStatus {
  enabled: boolean;
  require_dnssec: boolean;
}

export interface BlocklistStatus {
  enabled: boolean;
  total_rules: number;
  files_count: number;
  urls_count: number;
}

export interface UpstreamServer {
  address: string;
  healthy: boolean;
  queries: number;
  failed: number;
  failovers: number;
}

export interface UpstreamsResponse {
  upstreams: UpstreamServer[];
}

export interface UserInfo {
  username: string;
  role: string;
  created_at?: string;
  updated_at?: string;
}

export interface CreateUserRequest {
  username: string;
  password: string;
  role: string;
}

export interface MetricsHistory {
  timestamps: number[];
  queries: number[];
  cache_hits: number[];
  cache_misses: number[];
  latency_ms: number[];
  count: number;
}

export interface RPZStats {
  enabled: boolean;
  total_rules: number;
  qname_rules: number;
  client_ip_rules: number;
  resp_ip_rules: number;
  files_count: number;
  total_matches: number;
  total_lookups: number;
  last_reload?: string;
}

export interface RPZRule {
  pattern: string;
  action: string;
  trigger: string;
  override_data?: string;
  policy_name: string;
  priority: number;
}

export interface RPZRulesResponse {
  rules: RPZRule[];
}

export interface ServerConfig {
  version: string;
  listen_port: number;
  log_level: string;
  dns64: {
    enabled: boolean;
    prefix: string;
    prefix_len: number;
    exclude_nets?: string[];
  };
  cookie: {
    enabled: boolean;
    secret_rotation?: string;
  };
}

export interface GeoDNSStats {
  enabled: boolean;
  rules: number;
  mmdb_loaded: boolean;
  lookups: number;
  hits: number;
  misses: number;
}

export interface ZoneTransfer {
  zone: string;
  masters: string;
  serial: number;
  last_transfer: string;
  status: 'synced' | 'syncing' | 'failed' | 'pending';
  records: number;
}

export interface SlaveZonesResponse {
  slave_zones: ZoneTransfer[];
}
