import { type FormEvent, useEffect, useId, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api, SoaSchema, type Soa } from '@/lib/api';
import { MAX_SOA_VALUE, SOA_TIMERS, fieldsFrom, soaProblem, type SoaFields } from '@/lib/soa';

// EditSoaDialog edits a zone's SOA (PUT /api/v1/zones/{zone}/soa, #19). Only
// the fields that changed are sent; the server bumps the serial, which
// notifies the secondaries. Controlled — the parent owns `open`.
export function EditSoaDialog({ zoneName, soa, open, onClose, onSaved }: {
  zoneName: string;
  soa: Soa;
  open: boolean;
  onClose: () => void;
  onSaved: (soa: Soa) => void;
}) {
  const [fields, setFields] = useState<SoaFields>(() => fieldsFrom(soa));
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const idBase = useId();

  // Start from the current SOA each time the dialog opens.
  useEffect(() => {
    if (open) {
      setFields(fieldsFrom(soa));
      setError('');
    }
  }, [open, soa]);

  const close = () => {
    if (saving) return;
    onClose();
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const problem = soaProblem(fields);
    if (problem) {
      setError(problem);
      return;
    }
    const initial = fieldsFrom(soa);
    const body: Record<string, string | number> = {};
    if (fields.mname.trim() !== initial.mname) body.mname = fields.mname.trim();
    if (fields.rname.trim() !== initial.rname) body.rname = fields.rname.trim();
    for (const t of SOA_TIMERS) {
      if (fields[t.key].trim() !== initial[t.key]) body[t.key] = Number(fields[t.key]);
    }
    if (Object.keys(body).length === 0) {
      onClose();
      return;
    }
    setSaving(true);
    setError('');
    try {
      const updated = await api('PUT', `/api/v1/zones/${encodeURIComponent(zoneName)}/soa`, body, SoaSchema);
      toast.success(`SOA updated, serial ${updated.serial}`);
      onSaved(updated);
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update the SOA');
    } finally {
      setSaving(false);
    }
  };

  const set = (key: keyof SoaFields) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setFields(f => ({ ...f, [key]: e.target.value }));
  const labelClass = 'text-sm font-medium mb-1.5 block';
  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) close(); }}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Edit SOA</DialogTitle>
          <DialogDescription>
            The serial ({soa.serial}) is bumped on save, so secondaries are notified and pick up the change.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="space-y-4">
          <div>
            <label htmlFor={`${idBase}-mname`} className={labelClass}>Primary nameserver</label>
            <Input id={`${idBase}-mname`} className="font-mono" value={fields.mname} onChange={set('mname')} autoFocus />
          </div>
          <div>
            <label htmlFor={`${idBase}-rname`} className={labelClass}>Admin e-mail</label>
            <Input id={`${idBase}-rname`} className="font-mono" value={fields.rname} onChange={set('rname')} />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {SOA_TIMERS.map(t => (
              <div key={t.key}>
                <label htmlFor={`${idBase}-${t.key}`} className={labelClass}>{t.label}</label>
                <Input
                  id={`${idBase}-${t.key}`}
                  type="number"
                  min={0}
                  max={MAX_SOA_VALUE}
                  inputMode="numeric"
                  className="font-mono"
                  value={fields[t.key]}
                  onChange={set(t.key)}
                  aria-describedby={`${idBase}-${t.key}-hint`}
                />
                <p id={`${idBase}-${t.key}-hint`} className="text-xs text-muted-foreground mt-1">{t.hint}</p>
              </div>
            ))}
          </div>
          {error && <p role="alert" className="text-destructive text-sm">{error}</p>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={close} disabled={saving}>Cancel</Button>
            <Button type="submit" disabled={saving}>
              {saving && <Loader2 className="h-4 w-4 animate-spin" />}
              Save SOA
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
