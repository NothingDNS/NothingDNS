import { useState, useEffect, useId } from 'react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogTitle } from '@/components/ui/dialog';
import { api } from '@/lib/api';
import { Check, AlertTriangle } from 'lucide-react';
import {
  type EditableRecord,
  type RecordEditValue,
  type RecordFormFields,
  defaultRecordFields,
  recordTypeGroups,
  recordTypeDescriptions,
  fieldsFromRecordData,
  buildRecordData,
} from './record-utils';
import { FormField, RecordDataForm } from './record-form';

export function AddRecordDialog({ open, onClose, zoneName, initialType, onSaved }: {
  open: boolean;
  onClose: () => void;
  zoneName: string;
  initialType: string;
  onSaved: () => void;
}) {
  // useId gives a stable, collision-free prefix so multiple mounted instances
  // of this dialog never emit duplicate DOM ids for their form controls.
  const fieldId = useId();
  const nameId = `${fieldId}-name`;
  const ttlId = `${fieldId}-ttl`;
  const [name, setName] = useState('');
  const [type, setType] = useState('A');
  const [ttl, setTtl] = useState('3600');
  const [fields, setFields] = useState<RecordFormFields>(() => ({ ...defaultRecordFields }));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const built = buildRecordData(type, fields);

  useEffect(() => {
    if (!open) return;
    setType(initialType);
    setFields(fieldsFromRecordData(initialType, ''));
    setError('');
  }, [open, initialType]);

  const handleTypeChange = (nextType: string) => {
    setType(nextType);
    setFields(fieldsFromRecordData(nextType, ''));
  };

  const handleFieldChange = (key: string, value: string) => {
    setFields(prev => ({ ...prev, [key]: value }));
  };

  const handleSave = async () => {
    setError('');
    if (!name.trim()) {
      setError('Name is required');
      return;
    }
    const nextData = buildRecordData(type, fields);
    if ('error' in nextData) {
      setError(nextData.error);
      return;
    }
    setSaving(true);
    try {
      await api('POST', `/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
        name: name.trim(),
        type,
        ttl: parseInt(ttl) || 3600,
        data: nextData.data
      });
      setName(''); setType('A'); setTtl('3600'); setFields({ ...defaultRecordFields });
      onSaved();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to add record');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose}>
      <DialogTitle>Add Record</DialogTitle>
      <div className="space-y-4 mt-5">
        {error && (
          <div role="alert" className="text-sm text-destructive bg-destructive/10 px-3 py-2 rounded-lg flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" /> {error}
          </div>
        )}

        <div className="grid gap-4 sm:grid-cols-[1fr_150px]">
          <div className="space-y-1.5">
            <label htmlFor={nameId} className="block text-xs font-medium uppercase tracking-wide text-muted-foreground">Name</label>
            <Input
              id={nameId}
              placeholder="@ or subdomain"
              value={name}
              onChange={e => setName(e.target.value)}
              autoFocus
            />
          </div>
          <div className="space-y-1.5">
            <label htmlFor={ttlId} className="block text-xs font-medium uppercase tracking-wide text-muted-foreground">TTL</label>
            <Input id={ttlId} type="number" value={ttl} onChange={e => setTtl(e.target.value)} />
          </div>
        </div>

        <div className="rounded-lg border bg-muted/20 p-3">
          <div className="mb-3 flex items-center justify-between gap-3">
            <div>
              <div className="text-sm font-medium">Record type</div>
              <div className="text-xs text-muted-foreground">{recordTypeDescriptions[type]}</div>
            </div>
            <Badge variant="outline">{type}</Badge>
          </div>
          <div className="space-y-3">
            {recordTypeGroups.map(group => (
              <div key={group.label} className="space-y-2">
                <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{group.label}</div>
                <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {group.types.map(typeName => (
                    <button
                      key={typeName}
                      type="button"
                      onClick={() => handleTypeChange(typeName)}
                      className={`rounded-md border p-3 text-left transition-colors ${type === typeName ? 'border-primary bg-primary/10 text-primary' : 'bg-background hover:bg-muted/50'}`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-medium">{typeName}</span>
                        {type === typeName && <Check className="h-4 w-4" />}
                      </div>
                      <div className="mt-1 line-clamp-2 text-xs text-muted-foreground">{recordTypeDescriptions[typeName]}</div>
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        <RecordDataForm type={type} fields={fields} onFieldChange={handleFieldChange} />

        {'data' in built && built.data && (
          <div className="rounded-md border bg-muted/30 px-3 py-2 text-xs">
            <span className="text-muted-foreground">Will save as </span>
            <span className="break-all font-mono">{built.data}</span>
          </div>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={handleSave} disabled={saving}>
            {saving ? 'Adding...' : 'Add Record'}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

export function EditRecordDialog({ open, record, onClose, onSave }: {
  open: boolean;
  record: EditableRecord | null;
  onClose: () => void;
  onSave: (next: RecordEditValue) => Promise<void>;
}) {
  const [name, setName] = useState('');
  const [ttl, setTtl] = useState('3600');
  const [fields, setFields] = useState<RecordFormFields>(() => ({ ...defaultRecordFields }));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const built = record ? buildRecordData(record.type, fields) : { data: '' };

  useEffect(() => {
    if (!record) return;
    setName(record.name);
    setTtl(String(record.ttl));
    setFields(fieldsFromRecordData(record.type, record.data));
    setError('');
  }, [record]);

  const handleFieldChange = (key: string, value: string) => {
    setFields(prev => ({ ...prev, [key]: value }));
  };

  const handleSave = async () => {
    if (!record) return;
    setError('');
    if (!name.trim()) {
      setError('Name is required');
      return;
    }
    const nextData = buildRecordData(record.type, fields);
    if ('error' in nextData) {
      setError(nextData.error);
      return;
    }
    setSaving(true);
    try {
      await onSave({
        name: name.trim(),
        ttl: parseInt(ttl) || 3600,
        data: nextData.data,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to save record');
    } finally {
      setSaving(false);
    }
  };

  if (!record) return null;

  return (
    <Dialog open={open} onClose={onClose}>
      <DialogTitle>Edit {record.type} Record</DialogTitle>
      <div className="space-y-4 mt-5">
        {error && (
          <div role="alert" className="text-sm text-destructive bg-destructive/10 px-3 py-2 rounded-lg flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" /> {error}
          </div>
        )}

        <div className="grid gap-4 sm:grid-cols-[1fr_120px]">
          <FormField label="Name">
            <Input value={name} onChange={e => setName(e.target.value)} autoFocus />
          </FormField>
          <FormField label="TTL">
            <Input type="number" value={ttl} onChange={e => setTtl(e.target.value)} />
          </FormField>
        </div>

        <div className="flex items-center gap-2 rounded-lg border bg-muted/20 px-3 py-2">
          <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Type</span>
          <Badge variant="outline">{record.type}</Badge>
          <span className="text-xs text-muted-foreground">{recordTypeDescriptions[record.type] || 'Raw DNS record data'}</span>
        </div>

        <RecordDataForm type={record.type} fields={fields} onFieldChange={handleFieldChange} />

        {'data' in built && built.data && (
          <div className="rounded-md border bg-muted/30 px-3 py-2 text-xs">
            <span className="text-muted-foreground">Will save as </span>
            <span className="break-all font-mono">{built.data}</span>
          </div>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={handleSave} disabled={saving}>
            {saving ? 'Saving...' : 'Save Record'}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

export function BulkPTRDialog({ open, onClose, zoneName, onSaved }: {
  open: boolean;
  onClose: () => void;
  zoneName: string;
  onSaved: () => void;
}) {
  // useId gives a stable, collision-free prefix so multiple mounted instances
  // of this dialog never emit duplicate DOM ids for their form controls.
  const fieldId = useId();
  const cidrId = `${fieldId}-cidr`;
  const patternId = `${fieldId}-pattern`;
  const [cidr, setCidr] = useState('');
  const [pattern, setPattern] = useState('ip-[A]-[B]-[C]-[D].example.com');
  const [override, setOverride] = useState(false);
  const [addA, setAddA] = useState(true);
  const [saving, setSaving] = useState(false);
  const [previewing, setPreviewing] = useState(false);
  const [error, setError] = useState('');
  const [preview, setPreview] = useState<{
    total: number;
    willAdd: number;
    willAddA: number;
    willSkip: number;
    willOverride: number;
    changes: { ip: string; ptrName: string; aName?: string; action: string; ptrExist: boolean; aExist?: boolean; oldPtr?: string; oldA?: string }[];
  } | null>(null);
  const [result, setResult] = useState<{ added: number; addedA: number; exists: number; existsA: number; skipped: number } | null>(null);

  const handlePreview = async () => {
    setError('');
    if (!cidr.trim()) {
      setError('CIDR is required');
      return;
    }
    if (!pattern.includes('[A]') || !pattern.includes('[B]') ||
        !pattern.includes('[C]') || !pattern.includes('[D]')) {
      setError('Pattern must contain [A], [B], [C], [D] placeholders');
      return;
    }
    setPreviewing(true);
    try {
      const res = await api<typeof preview>(
        'POST',
        `/api/v1/zones/${encodeURIComponent(zoneName)}/ptr-bulk`,
        { cidr: cidr.trim(), pattern: pattern.trim(), override, addA, preview: true }
      );
      setPreview(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to preview');
    } finally {
      setPreviewing(false);
    }
  };

  const handleSave = async () => {
    setError('');
    if (!cidr.trim()) {
      setError('CIDR is required');
      return;
    }
    if (!pattern.includes('[A]') || !pattern.includes('[B]') ||
        !pattern.includes('[C]') || !pattern.includes('[D]')) {
      setError('Pattern must contain [A], [B], [C], [D] placeholders');
      return;
    }
    setSaving(true);
    try {
      const res = await api<{ added: number; addedA: number; exists: number; existsA: number; skipped: number }>(
        'POST',
        `/api/v1/zones/${encodeURIComponent(zoneName)}/ptr-bulk`,
        { cidr: cidr.trim(), pattern: pattern.trim(), override, addA, preview: false }
      );
      setResult(res);
      setPreview(null);
      if (res.added > 0 || res.skipped > 0 || res.addedA > 0) {
        setCidr('');
        onSaved();
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to add PTR records');
    } finally {
      setSaving(false);
    }
  };

  const reset = () => {
    setPreview(null);
    setResult(null);
    setError('');
  };

  return (
    <Dialog open={open} onClose={onClose}>
      <DialogTitle>Bulk PTR Records</DialogTitle>
      <div className="space-y-4 mt-5">
        {error && (
          <div role="alert" className="text-sm text-destructive bg-destructive/10 px-3 py-2 rounded-lg flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" /> {error}
          </div>
        )}

        {result && (
          <div className="text-sm bg-success/10 text-success px-3 py-2 rounded-lg space-y-1">
            <div>PTR: +{result.added} / {result.exists} exists / {result.skipped} skipped</div>
            {result.addedA > 0 && <div>A: +{result.addedA} / {result.existsA} exists</div>}
            <button onClick={reset} className="text-xs underline mt-1">Clear</button>
          </div>
        )}

        {!result && preview && (
          <div className="text-sm bg-primary/10 px-3 py-2 rounded-lg">
            <div className="flex justify-between mb-2">
              <span className="text-primary font-medium">Preview: {preview.total} IPs</span>
              <button onClick={() => setPreview(null)} className="text-xs underline">Edit</button>
            </div>
            <div className="grid grid-cols-3 gap-2 text-xs mb-2">
              <div className="text-success">+{preview.willAdd} add</div>
              {preview.willAddA > 0 && <div className="text-success">+{preview.willAddA} A</div>}
              {preview.willSkip > 0 && <div className="text-warning">~{preview.willSkip} skip</div>}
              {preview.willOverride > 0 && <div className="text-destructive">!{preview.willOverride} override</div>}
            </div>
            <div className="max-h-48 overflow-y-auto space-y-1">
              {preview.changes.slice(0, 20).map((ch, i) => (
                <div key={i} className={`text-xs font-mono flex items-center gap-1 ${
                  ch.action === 'skip' ? 'text-warning' : ch.action === 'override' ? 'text-destructive' : 'text-success'
                }`}>
                  <span>{ch.ip}</span>
                  <span>→</span>
                  <span className="truncate">{ch.ptrName}</span>
                  {ch.action === 'skip' && <span className="text-muted-foreground">exists</span>}
                  {ch.action === 'override' && <span className="text-destructive">→ {ch.oldPtr}</span>}
                </div>
              ))}
              {preview.changes.length > 20 && (
                <div className="text-xs text-muted-foreground text-center">
                  +{preview.changes.length - 20} more...
                </div>
              )}
            </div>
          </div>
        )}

        <div>
          <label htmlFor={cidrId} className="text-sm font-medium mb-1.5 block">CIDR Range</label>
          <Input
            id={cidrId}
            placeholder="192.168.1.0/24"
            value={cidr}
            onChange={e => { setCidr(e.target.value); setPreview(null); }}
            autoFocus
          />
          <p className="text-xs text-muted-foreground mt-1">IPv4 range (max /16)</p>
        </div>

        <div>
          <label htmlFor={patternId} className="text-sm font-medium mb-1.5 block">Pattern</label>
          <Input
            id={patternId}
            placeholder="ip-[A]-[B]-[C]-[D].example.com"
            value={pattern}
            onChange={e => { setPattern(e.target.value); setPreview(null); }}
          />
          <p className="text-xs text-muted-foreground mt-1">Use [A], [B], [C], [D] for IP octets</p>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="checkbox"
            id="addA"
            checked={addA}
            onChange={e => { setAddA(e.target.checked); setPreview(null); }}
            className="h-4 w-4 rounded border-input"
          />
          <label htmlFor="addA" className="text-sm">Also add A records (pattern name → IP)</label>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="checkbox"
            id="override"
            checked={override}
            onChange={e => { setOverride(e.target.checked); setPreview(null); }}
            className="h-4 w-4 rounded border-input"
          />
          <label htmlFor="override" className="text-sm">Override existing records</label>
        </div>

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={onClose}>Close</Button>
          {!preview ? (
            <Button variant="outline" onClick={handlePreview} disabled={previewing || !cidr.trim()}>
              {previewing ? 'Preview...' : 'Preview'}
            </Button>
          ) : null}
          <Button onClick={handleSave} disabled={saving}>
            {saving ? 'Adding...' : preview ? 'Confirm & Add' : 'Add PTR Records'}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
