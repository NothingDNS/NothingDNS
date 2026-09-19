import type { ReactNode } from 'react';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { Settings2 } from 'lucide-react';
import {
  type RecordFormFields,
  recordTypeDescriptions,
  recordDataParts,
} from './record-utils';

export function FormField({ label, children }: { label: string; children: ReactNode }) {
  // Nest the control inside the <label> so the text is associated with it
  // implicitly (clicking the label focuses the field; screen readers announce
  // the name) — no id/htmlFor plumbing needed for these single-field rows.
  return (
    <label className="block space-y-1.5">
      <span className="block text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</span>
      {children}
    </label>
  );
}

export function RecordDataDisplay({ type, data }: { type: string; data: string }) {
  const parts = recordDataParts(type, data);
  return (
    <div className="flex min-w-[220px] flex-wrap gap-1.5">
      {parts.map((part) => (
        <span key={part.label} className="inline-flex max-w-full items-baseline gap-1 rounded-md border bg-muted/40 px-2 py-1 text-xs">
          <span className="shrink-0 text-muted-foreground">{part.label}</span>
          <span className="min-w-0 font-mono [overflow-wrap:anywhere]">{part.value || '-'}</span>
        </span>
      ))}
    </div>
  );
}

export function RecordTypePanel({ type, children }: { type: string; children: ReactNode }) {
  return (
    <div className="rounded-lg border bg-muted/20 p-4">
      <div className="mb-4 flex items-start gap-3">
        <div className="rounded-md bg-primary/10 p-2 text-primary">
          <Settings2 className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline">{type}</Badge>
            <span className="text-sm font-medium">Record data</span>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">{recordTypeDescriptions[type] || 'Raw DNS record data'}</p>
        </div>
      </div>
      {children}
    </div>
  );
}

export function RecordDataForm({ type, fields, onFieldChange }: {
  type: string;
  fields: RecordFormFields;
  onFieldChange: (key: string, value: string) => void;
}) {
  const input = (key: string, placeholder: string, inputType = 'text') => (
    <Input
      type={inputType}
      placeholder={placeholder}
      value={fields[key] || ''}
      onChange={e => onFieldChange(key, e.target.value)}
    />
  );

  switch (type) {
    case 'A':
      return <RecordTypePanel type={type}><FormField label="IPv4 address">{input('address', '192.0.2.10')}</FormField></RecordTypePanel>;
    case 'AAAA':
      return <RecordTypePanel type={type}><FormField label="IPv6 address">{input('address', '2001:db8::10')}</FormField></RecordTypePanel>;
    case 'CNAME':
      return <RecordTypePanel type={type}><FormField label="Canonical target">{input('target', 'app.example.com.')}</FormField></RecordTypePanel>;
    case 'NS':
      return <RecordTypePanel type={type}><FormField label="Nameserver">{input('target', 'ns1.example.com.')}</FormField></RecordTypePanel>;
    case 'PTR':
      return <RecordTypePanel type={type}><FormField label="PTR target">{input('target', 'host.example.com.')}</FormField></RecordTypePanel>;
    case 'MX':
      return (
        <RecordTypePanel type={type}>
          <div className="grid gap-4 sm:grid-cols-[120px_1fr]">
            <FormField label="Priority">{input('priority', '10', 'number')}</FormField>
            <FormField label="Mail exchanger">{input('exchange', 'mail.example.com.')}</FormField>
          </div>
        </RecordTypePanel>
      );
    case 'TXT':
      return (
        <RecordTypePanel type={type}>
          <FormField label="Text value">
            <Textarea
              rows={3}
              placeholder="v=spf1 mx ~all"
              value={fields.text || ''}
              onChange={e => onFieldChange('text', e.target.value)}
            />
          </FormField>
        </RecordTypePanel>
      );
    case 'SRV':
      return (
        <RecordTypePanel type={type}>
          <div className="grid gap-4 sm:grid-cols-2">
            <FormField label="Priority">{input('priority', '10', 'number')}</FormField>
            <FormField label="Weight">{input('weight', '5', 'number')}</FormField>
            <FormField label="Port">{input('port', '443', 'number')}</FormField>
            <FormField label="Target">{input('target', 'service.example.com.')}</FormField>
          </div>
        </RecordTypePanel>
      );
    case 'CAA':
      return (
        <RecordTypePanel type={type}>
          <div className="grid gap-4 sm:grid-cols-[100px_150px_1fr]">
            <FormField label="Flags">{input('flags', '0', 'number')}</FormField>
            <FormField label="Tag">
              <select
                value={fields.tag || 'issue'}
                onChange={e => onFieldChange('tag', e.target.value)}
                className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="issue">issue</option>
                <option value="issuewild">issuewild</option>
                <option value="iodef">iodef</option>
                <option value="accounturi">accounturi</option>
                <option value="validationmethods">validationmethods</option>
              </select>
            </FormField>
            <FormField label="Value">{input('value', 'letsencrypt.org')}</FormField>
          </div>
        </RecordTypePanel>
      );
    case 'DS':
      return (
        <RecordTypePanel type={type}>
          <div className="grid gap-4 sm:grid-cols-3">
            <FormField label="Key tag">{input('keyTag', '60485', 'number')}</FormField>
            <FormField label="Algorithm">{input('algorithm', '13', 'number')}</FormField>
            <FormField label="Digest type">{input('digestType', '2', 'number')}</FormField>
            <div className="sm:col-span-3">
              <FormField label="Digest">{input('digest', 'hex digest')}</FormField>
            </div>
          </div>
        </RecordTypePanel>
      );
    case 'DNSKEY':
      return (
        <RecordTypePanel type={type}>
          <div className="grid gap-4 sm:grid-cols-3">
            <FormField label="Flags">{input('flags', '256', 'number')}</FormField>
            <FormField label="Protocol">{input('protocol', '3', 'number')}</FormField>
            <FormField label="Algorithm">{input('algorithm', '13', 'number')}</FormField>
            <div className="sm:col-span-3">
              <FormField label="Public key">
                <Textarea
                  rows={3}
                  placeholder="base64 public key"
                  value={fields.publicKey || ''}
                  onChange={e => onFieldChange('publicKey', e.target.value)}
                />
              </FormField>
            </div>
          </div>
        </RecordTypePanel>
      );
    case 'NAPTR':
      return (
        <RecordTypePanel type={type}>
          <div className="grid gap-4 sm:grid-cols-2">
            <FormField label="Order">{input('order', '100', 'number')}</FormField>
            <FormField label="Preference">{input('preference', '10', 'number')}</FormField>
            <FormField label="Flags">{input('flags', 'U')}</FormField>
            <FormField label="Service">{input('service', 'E2U+sip')}</FormField>
            <FormField label="Regexp">{input('regexp', '!^.*$!sip:info@example.com!')}</FormField>
            <FormField label="Replacement">{input('replacement', '.')}</FormField>
          </div>
        </RecordTypePanel>
      );
    default:
      return <RecordTypePanel type={type}><FormField label="Raw data">{input('raw', 'record data')}</FormField></RecordTypePanel>;
  }
}
