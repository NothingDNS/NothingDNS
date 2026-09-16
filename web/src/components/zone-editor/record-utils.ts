import type { DnsRecord } from '@/lib/api';

export interface EditableRecord extends DnsRecord {
  selected?: boolean;
  edited?: boolean;
  original?: DnsRecord;
}

export interface HistoryState {
  records: EditableRecord[];
  description: string;
}

export type RecordFormFields = Record<string, string>;

export interface RecordEditValue {
  name: string;
  ttl: number;
  data: string;
}

export const recordTypeGroups = [
  { label: 'Address', types: ['A', 'AAAA', 'PTR'] },
  { label: 'Routing', types: ['CNAME', 'MX', 'NS', 'SRV'] },
  { label: 'Policy', types: ['TXT', 'CAA', 'NAPTR'] },
  { label: 'DNSSEC', types: ['DNSKEY', 'DS'] },
];

export const recordTypePalette = ['SOA', ...recordTypeGroups.flatMap(group => group.types)];

export const recordTypeDescriptions: Record<string, string> = {
  A: 'IPv4 host address',
  AAAA: 'IPv6 host address',
  CNAME: 'Alias to canonical name',
  MX: 'Mail routing with priority and exchanger',
  NS: 'Authoritative nameserver',
  TXT: 'Quoted text value',
  SRV: 'Service priority, weight, port, and target',
  CAA: 'Certificate authority authorization',
  DNSKEY: 'DNSSEC public key material',
  DS: 'Delegation signer digest',
  PTR: 'Reverse DNS target',
  NAPTR: 'Rewrite rule for service discovery',
};

export const defaultRecordFields: RecordFormFields = {
  address: '',
  target: '',
  priority: '10',
  exchange: '',
  text: '',
  weight: '5',
  port: '',
  flags: '0',
  tag: 'issue',
  value: '',
  order: '100',
  preference: '10',
  service: '',
  regexp: '',
  replacement: '.',
  keyTag: '',
  algorithm: '13',
  digestType: '2',
  digest: '',
  protocol: '3',
  publicKey: '',
  raw: '',
};

export const recordTypeBadgeVariants: Record<string, 'success' | 'warning' | 'secondary' | 'default' | 'outline'> = {
  SOA: 'warning', NS: 'secondary', A: 'success', AAAA: 'success',
  CNAME: 'default', MX: 'outline', TXT: 'outline', SRV: 'outline',
  DNSKEY: 'warning', DS: 'warning', RRSIG: 'secondary', NSEC: 'secondary',
};

export function cleanValue(value: string): string {
  return value.trim();
}

export function isReverseIPv4Zone(zoneName: string): boolean {
  const normalized = zoneName.trim().toLowerCase().replace(/\.$/, '');
  return normalized === 'in-addr.arpa' || normalized.endsWith('.in-addr.arpa');
}

export function stripOuterQuotes(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    const inner = trimmed.slice(1, -1);
    // Single-pass unescape, the exact inverse of quoteDNSString's escape
    // (" → \" ; backslash passes through untouched): a backslash escapes
    // only the immediately following character — a quote or another
    // backslash — and a backslash before anything else (e.g. the \. of a
    // NAPTR regexp) is a literal backslash and must survive the round
    // trip. The previous two-pass regex decode consumed an isolated
    // backslash into a following quote escape and halved backslash pairs,
    // corrupting values on every edit.
    let out = '';
    for (let i = 0; i < inner.length; i++) {
      if (inner[i] === '\\' && inner[i + 1] === '"') {
        out += '"';
        i += 1;
      } else {
        out += inner[i];
      }
    }
    return out;
  }
  return trimmed;
}

export function quoteDNSString(value: string): string {
  const trimmed = value.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed;
  }
  // Escape only the field delimiter quote. Backslashes pass through
  // untouched: doubling them (the old behavior) changed the meaning of
  // DNS data such as NAPTR regexps (\. is an escaped dot) and made
  // stripOuterQuotes non-idempotent on edit round trips.
  return `"${trimmed.replace(/"/g, '\\"')}"`;
}

export function requireField(label: string, value: string): string | null {
  return value.trim() ? null : `${label} is required`;
}

export function fieldsFromRecordData(type: string, data: string): RecordFormFields {
  const fields: RecordFormFields = { ...defaultRecordFields, raw: data };
  const parts = data.trim().split(/\s+/).filter(Boolean);

  switch (type) {
    case 'A':
    case 'AAAA':
      fields.address = data.trim();
      break;
    case 'CNAME':
    case 'NS':
    case 'PTR':
      fields.target = data.trim();
      break;
    case 'MX':
      fields.priority = parts[0] || '10';
      fields.exchange = parts.slice(1).join(' ');
      break;
    case 'TXT':
      fields.text = stripOuterQuotes(data);
      break;
    case 'SRV':
      fields.priority = parts[0] || '10';
      fields.weight = parts[1] || '5';
      fields.port = parts[2] || '';
      fields.target = parts.slice(3).join(' ');
      break;
    case 'CAA':
      fields.flags = parts[0] || '0';
      fields.tag = parts[1] || 'issue';
      fields.value = stripOuterQuotes(parts.slice(2).join(' '));
      break;
    case 'DS':
      fields.keyTag = parts[0] || '';
      fields.algorithm = parts[1] || '13';
      fields.digestType = parts[2] || '2';
      fields.digest = parts.slice(3).join('');
      break;
    case 'DNSKEY':
      fields.flags = parts[0] || '256';
      fields.protocol = parts[1] || '3';
      fields.algorithm = parts[2] || '13';
      fields.publicKey = parts.slice(3).join('');
      break;
    case 'NAPTR':
      fields.order = parts[0] || '100';
      fields.preference = parts[1] || '10';
      fields.flags = stripOuterQuotes(parts[2] || '');
      fields.service = stripOuterQuotes(parts[3] || '');
      fields.regexp = stripOuterQuotes(parts[4] || '');
      fields.replacement = parts[5] || '.';
      break;
    default:
      break;
  }

  return fields;
}

export function buildRecordData(type: string, fields: RecordFormFields): { data: string } | { error: string } {
  const f = (key: string) => cleanValue(fields[key] || '');
  let missing: string | null;

  switch (type) {
    case 'A':
    case 'AAAA':
      missing = requireField('Address', f('address'));
      return missing ? { error: missing } : { data: f('address') };
    case 'CNAME':
    case 'NS':
    case 'PTR':
      missing = requireField('Target', f('target'));
      return missing ? { error: missing } : { data: f('target') };
    case 'MX':
      missing = requireField('Mail exchanger', f('exchange'));
      return missing ? { error: missing } : { data: `${f('priority') || '10'} ${f('exchange')}` };
    case 'TXT':
      missing = requireField('Text', f('text'));
      return missing ? { error: missing } : { data: quoteDNSString(f('text')) };
    case 'SRV':
      missing = requireField('Target', f('target')) || requireField('Port', f('port'));
      return missing ? { error: missing } : { data: `${f('priority') || '10'} ${f('weight') || '5'} ${f('port')} ${f('target')}` };
    case 'CAA':
      missing = requireField('Value', f('value'));
      return missing ? { error: missing } : { data: `${f('flags') || '0'} ${f('tag') || 'issue'} ${quoteDNSString(f('value'))}` };
    case 'DS':
      missing = requireField('Key tag', f('keyTag')) || requireField('Digest', f('digest'));
      return missing ? { error: missing } : { data: `${f('keyTag')} ${f('algorithm') || '13'} ${f('digestType') || '2'} ${f('digest')}` };
    case 'DNSKEY':
      missing = requireField('Public key', f('publicKey'));
      return missing ? { error: missing } : { data: `${f('flags') || '256'} ${f('protocol') || '3'} ${f('algorithm') || '13'} ${f('publicKey')}` };
    case 'NAPTR':
      // RFC 3403 §4.2: the Services field may be empty (the textbook
      // terminal-NAPTR form is `100 10 "" "" "<regexp>" target`), so only
      // the Replacement is mandatory. Requiring Service made every
      // empty-service NAPTR re-save-averse in the zone editor.
      missing = requireField('Replacement', f('replacement'));
      return missing ? { error: missing } : { data: `${f('order') || '100'} ${f('preference') || '10'} ${quoteDNSString(f('flags'))} ${quoteDNSString(f('service'))} ${quoteDNSString(f('regexp'))} ${f('replacement') || '.'}` };
    default:
      missing = requireField('Raw data', f('raw'));
      return missing ? { error: missing } : { data: f('raw') };
  }
}

export function recordDataParts(type: string, data: string): { label: string; value: string }[] {
  const fields = fieldsFromRecordData(type, data);
  switch (type) {
    case 'MX':
      return [
        { label: 'Priority', value: fields.priority },
        { label: 'Exchange', value: fields.exchange },
      ];
    case 'SRV':
      return [
        { label: 'Priority', value: fields.priority },
        { label: 'Weight', value: fields.weight },
        { label: 'Port', value: fields.port },
        { label: 'Target', value: fields.target },
      ];
    case 'CAA':
      return [
        { label: 'Flags', value: fields.flags },
        { label: 'Tag', value: fields.tag },
        { label: 'Value', value: fields.value },
      ];
    case 'DS':
      return [
        { label: 'Key tag', value: fields.keyTag },
        { label: 'Algorithm', value: fields.algorithm },
        { label: 'Digest type', value: fields.digestType },
        { label: 'Digest', value: fields.digest },
      ];
    case 'DNSKEY':
      return [
        { label: 'Flags', value: fields.flags },
        { label: 'Protocol', value: fields.protocol },
        { label: 'Algorithm', value: fields.algorithm },
        { label: 'Public key', value: fields.publicKey },
      ];
    case 'NAPTR':
      return [
        { label: 'Order', value: fields.order },
        { label: 'Preference', value: fields.preference },
        { label: 'Flags', value: fields.flags },
        { label: 'Service', value: fields.service },
        { label: 'Regexp', value: fields.regexp },
        { label: 'Replacement', value: fields.replacement },
      ];
    case 'A':
    case 'AAAA':
      return [{ label: 'Address', value: fields.address }];
    case 'CNAME':
    case 'NS':
    case 'PTR':
      return [{ label: 'Target', value: fields.target }];
    case 'TXT':
      return [{ label: 'Text', value: fields.text }];
    default:
      return [{ label: 'Data', value: data }];
  }
}
