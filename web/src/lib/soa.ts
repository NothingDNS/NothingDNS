import type { Soa } from '@/lib/api';

// Largest SOA TTL or timer the server accepts (RFC 2181 §8).
export const MAX_SOA_VALUE = 2147483647;

export const SOA_TIMERS = [
  { key: 'ttl', label: 'SOA TTL', hint: 'TTL of the SOA record' },
  { key: 'refresh', label: 'Refresh', hint: 'Seconds between secondary serial checks' },
  { key: 'retry', label: 'Retry', hint: 'Seconds before a failed check is retried' },
  { key: 'expire', label: 'Expire', hint: 'Seconds until a cut-off secondary stops answering' },
  { key: 'minimum', label: 'Minimum (negative TTL)', hint: 'How long resolvers cache NXDOMAIN/NODATA' },
] as const;

type TimerKey = (typeof SOA_TIMERS)[number]['key'];
export type SoaFields = { mname: string; rname: string } & Record<TimerKey, string>;

// rnameToEmail shows an SOA RNAME as an address: "hostmaster.example.com."
// becomes "hostmaster@example.com". The server takes either form back.
export function rnameToEmail(rname: string): string {
  const name = rname.replace(/\.$/, '');
  const dot = name.indexOf('.');
  return dot > 0 ? `${name.slice(0, dot)}@${name.slice(dot + 1)}` : rname;
}

export function fieldsFrom(soa: Soa): SoaFields {
  return {
    mname: soa.mname,
    rname: rnameToEmail(soa.rname),
    ttl: String(soa.ttl ?? ''),
    refresh: String(soa.refresh),
    retry: String(soa.retry),
    expire: String(soa.expire),
    minimum: String(soa.minimum),
  };
}

// soaProblem mirrors the server's checks so most mistakes are caught before
// the request; the server stays the authority.
export function soaProblem(f: SoaFields): string | null {
  if (!f.mname.trim()) return 'Enter the primary nameserver';
  if (!f.rname.trim()) return 'Enter the admin e-mail';
  const n: Partial<Record<TimerKey, number>> = {};
  for (const t of SOA_TIMERS) {
    const v = f[t.key].trim();
    if (!/^\d+$/.test(v) || Number(v) > MAX_SOA_VALUE) {
      return `${t.label} must be a whole number from 0 to ${MAX_SOA_VALUE}`;
    }
    n[t.key] = Number(v);
  }
  if (!n.refresh || !n.retry || !n.expire) return 'Refresh, retry and expire must be greater than zero';
  if (n.retry! >= n.refresh) return 'Retry must be shorter than refresh';
  if (n.expire! <= n.refresh) return 'Expire must be longer than refresh';
  return null;
}
