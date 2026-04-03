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
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error || 'Request failed');
  return data as T;
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
