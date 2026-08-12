import { useEffect, useId, useState } from 'react';
import { useNavigate } from 'react-router';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Dialog, DialogTitle } from '@/components/ui/dialog';
import { Skeleton } from '@/components/ui/skeleton';
import { api, type Zone } from '@/lib/api';
import { ErrorState, EmptyState } from '@/components/states';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { toast } from 'sonner';
import { Globe, Plus, Trash2, ExternalLink, Search } from 'lucide-react';

function normalizeZoneName(name: string): string {
  const trimmed = name.trim().toLowerCase();
  return trimmed.endsWith('.') ? trimmed : `${trimmed}.`;
}

function defaultNameserverFor(zoneName: string): string {
  const zone = normalizeZoneName(zoneName || 'example.com');
  return `ns1.${zone}`;
}

function defaultAdminEmailFor(zoneName: string): string {
  const zone = normalizeZoneName(zoneName || 'example.com');
  return `admin.${zone}`;
}

export function ZonesPage() {
  const [zones, setZones] = useState<Zone[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [search, setSearch] = useState('');
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const navigate = useNavigate();
  const load = () => { setLoading(true); api<{ zones: Zone[] }>('GET', '/api/v1/zones').then((d) => { setZones(d.zones || []); setError(null); }).catch((e) => setError(e instanceof Error ? e.message : 'Failed to load zones')).finally(() => setLoading(false)); };
  useEffect(() => { load(); }, []);
  const filtered = zones.filter((z) => z.name.toLowerCase().includes(search.toLowerCase()));

  const confirmDelete = async () => {
    if (!pendingDelete) return;
    setDeleting(true);
    try {
      await api('DELETE', `/api/v1/zones/${encodeURIComponent(pendingDelete)}`);
      toast.success(`Zone ${pendingDelete} deleted`);
      setPendingDelete(null);
      load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed');
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div><h1 className="text-2xl font-bold tracking-tight">DNS Zones</h1><p className="text-muted-foreground text-sm">Manage authoritative zones and records</p></div>
        <Button onClick={() => setShowCreate(true)}><Plus className="h-4 w-4" /> Create Zone</Button>
      </div>
      <div className="relative max-w-sm"><Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" /><Input placeholder="Search zones..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9" /></div>
      {loading ? <div className="space-y-3">{Array.from({ length: 3 }).map((_, i) => <Card key={i}><CardContent className="p-6"><Skeleton className="h-12 w-full" /></CardContent></Card>)}</div>
      : error ? <ErrorState message={error} onRetry={load} />
      : filtered.length === 0 ? <EmptyState icon={Globe} title={zones.length === 0 ? 'No zones configured' : 'No matching zones'} description={zones.length === 0 ? 'Create your first DNS zone to get started.' : 'Try a different search term.'} action={zones.length === 0 ? <Button onClick={() => setShowCreate(true)}><Plus className="h-4 w-4" /> Create Zone</Button> : undefined} />
      : <div className="grid gap-3">{filtered.map((z) => (
          <Card key={z.name} className="group hover:shadow-md transition-shadow cursor-pointer" onClick={() => navigate(`/zones/${encodeURIComponent(z.name)}`)}>
            <CardContent className="flex items-center justify-between p-5">
              <div className="flex items-center gap-4"><div className="p-2.5 rounded-lg bg-primary/10"><Globe className="h-5 w-5 text-primary" /></div><div><div className="font-semibold font-mono text-sm">{z.name}</div><div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground"><span>Serial: <span className="font-mono">{z.serial ?? '-'}</span></span><span>{z.records ?? '-'} records</span></div></div></div>
              <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
                <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Open zone ${z.name}`} onClick={(e) => { e.stopPropagation(); navigate(`/zones/${encodeURIComponent(z.name)}`); }}><ExternalLink className="h-4 w-4" /></Button>
                <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Delete zone ${z.name}`} onClick={(e) => { e.stopPropagation(); setPendingDelete(z.name); }}><Trash2 className="h-4 w-4 text-destructive" /></Button>
              </div>
            </CardContent>
          </Card>
        ))}</div>}
      <CreateZoneDialog open={showCreate} onClose={() => setShowCreate(false)} onCreated={load} />
      <ConfirmDialog open={pendingDelete !== null} title="Delete zone" description={pendingDelete ? `Delete zone ${pendingDelete}? This cannot be undone.` : ''} confirmLabel="Delete" destructive loading={deleting} onConfirm={confirmDelete} onCancel={() => setPendingDelete(null)} />
    </div>
  );
}

function CreateZoneDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  // useId gives a stable, collision-free prefix so multiple mounted instances
  // of this dialog never emit duplicate DOM ids for their form controls.
  const fieldId = useId();
  const nameId = `${fieldId}-name`;
  const ttlId = `${fieldId}-ttl`;
  const emailId = `${fieldId}-email`;
  const nsId = `${fieldId}-ns`;
  const [name, setName] = useState('');
  const [ttl, setTTL] = useState('3600');
  const [email, setEmail] = useState(defaultAdminEmailFor(''));
  const [ns, setNs] = useState(defaultNameserverFor(''));
  const [emailTouched, setEmailTouched] = useState(false);
  const [nsTouched, setNsTouched] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!open) return;
    if (!emailTouched) setEmail(defaultAdminEmailFor(name));
    if (!nsTouched) setNs(defaultNameserverFor(name));
  }, [open, name, emailTouched, nsTouched]);

  const handle = async () => {
    setError(''); if (!name.trim()) { setError('Zone name is required'); return; } const nameservers = ns.split('\n').map((s) => s.trim()).filter(Boolean); if (!nameservers.length) { setError('At least one nameserver is required'); return; }
    const zoneName = normalizeZoneName(name);
    setSaving(true); try { await api('POST', '/api/v1/zones', { name: zoneName, ttl: parseInt(ttl) || 3600, admin_email: email.trim(), nameservers }); setName(''); setTTL('3600'); setEmail(defaultAdminEmailFor('')); setNs(defaultNameserverFor('')); setEmailTouched(false); setNsTouched(false); toast.success(`Zone ${zoneName} created`); onCreated(); onClose(); } catch (e) { setError(e instanceof Error ? e.message : 'Failed'); } finally { setSaving(false); }
  };
  return (<Dialog open={open} onClose={onClose}><DialogTitle>Create New Zone</DialogTitle><div className="space-y-4 mt-5">
    {error && <div className="text-sm text-destructive bg-destructive/10 px-3 py-2 rounded-lg">{error}</div>}
    <div><label htmlFor={nameId} className="text-sm font-medium mb-1.5 block">Zone Name</label><Input id={nameId} placeholder="example.com." value={name} onChange={(e) => setName(e.target.value)} autoFocus /></div>
    <div className="grid grid-cols-2 gap-4"><div><label htmlFor={ttlId} className="text-sm font-medium mb-1.5 block">Default TTL</label><Input id={ttlId} type="number" value={ttl} onChange={(e) => setTTL(e.target.value)} /></div><div><label htmlFor={emailId} className="text-sm font-medium mb-1.5 block">Admin Email</label><Input id={emailId} placeholder="admin.example.com." value={email} onChange={(e) => { setEmailTouched(true); setEmail(e.target.value); }} /></div></div>
    <div><label htmlFor={nsId} className="text-sm font-medium mb-1.5 block">Nameservers (one per line)</label><Textarea id={nsId} rows={3} placeholder={"ns1.example.com.\nns2.example.com."} value={ns} onChange={(e) => { setNsTouched(true); setNs(e.target.value); }} /></div>
    <div className="flex justify-end gap-2 pt-2"><Button variant="outline" onClick={onClose}>Cancel</Button><Button onClick={handle} disabled={saving}>{saving ? 'Creating...' : 'Create Zone'}</Button></div>
  </div></Dialog>);
}
