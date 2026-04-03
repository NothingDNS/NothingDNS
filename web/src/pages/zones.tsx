import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Dialog, DialogTitle } from '@/components/ui/dialog';
import { Skeleton } from '@/components/ui/skeleton';
import { api, type Zone } from '@/lib/api';
import { Globe, Plus, Trash2, ExternalLink, Search } from 'lucide-react';

export function ZonesPage() {
  const [zones, setZones] = useState<Zone[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [search, setSearch] = useState('');
  const navigate = useNavigate();
  const load = () => api<{ zones: Zone[] }>('GET', '/api/v1/zones').then((d) => setZones(d.zones || [])).catch(console.error).finally(() => setLoading(false));
  useEffect(() => { load(); }, []);
  const filtered = zones.filter((z) => z.name.toLowerCase().includes(search.toLowerCase()));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div><h1 className="text-2xl font-bold tracking-tight">DNS Zones</h1><p className="text-muted-foreground text-sm">Manage authoritative zones and records</p></div>
        <Button onClick={() => setShowCreate(true)}><Plus className="h-4 w-4" /> Create Zone</Button>
      </div>
      <div className="relative max-w-sm"><Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" /><Input placeholder="Search zones..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9" /></div>
      {loading ? <div className="space-y-3">{Array.from({ length: 3 }).map((_, i) => <Card key={i}><CardContent className="p-6"><Skeleton className="h-12 w-full" /></CardContent></Card>)}</div>
      : filtered.length === 0 ? <Card><CardContent className="py-16 text-center"><Globe className="h-12 w-12 mx-auto text-muted-foreground/50 mb-4" /><h3 className="text-lg font-semibold mb-1">{zones.length === 0 ? 'No zones configured' : 'No matching zones'}</h3><p className="text-sm text-muted-foreground mb-4">{zones.length === 0 ? 'Create your first DNS zone to get started.' : 'Try a different search term.'}</p>{zones.length === 0 && <Button onClick={() => setShowCreate(true)}><Plus className="h-4 w-4" /> Create Zone</Button>}</CardContent></Card>
      : <div className="grid gap-3">{filtered.map((z) => (
          <Card key={z.name} className="group hover:shadow-md transition-shadow cursor-pointer" onClick={() => navigate(`/zones/${encodeURIComponent(z.name)}`)}>
            <CardContent className="flex items-center justify-between p-5">
              <div className="flex items-center gap-4"><div className="p-2.5 rounded-lg bg-primary/10"><Globe className="h-5 w-5 text-primary" /></div><div><div className="font-semibold font-mono text-sm">{z.name}</div><div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground"><span>Serial: <span className="font-mono">{z.serial || '-'}</span></span><span>{z.records} records</span></div></div></div>
              <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                <Button variant="ghost" size="icon" className="h-8 w-8" onClick={(e) => { e.stopPropagation(); navigate(`/zones/${encodeURIComponent(z.name)}`); }}><ExternalLink className="h-4 w-4" /></Button>
                <Button variant="ghost" size="icon" className="h-8 w-8" onClick={(e) => { e.stopPropagation(); if (confirm(`Delete zone ${z.name}?`)) api('DELETE', `/api/v1/zones/${encodeURIComponent(z.name)}`).then(load); }}><Trash2 className="h-4 w-4 text-destructive" /></Button>
              </div>
            </CardContent>
          </Card>
        ))}</div>}
      <CreateZoneDialog open={showCreate} onClose={() => setShowCreate(false)} onCreated={load} />
    </div>
  );
}

function CreateZoneDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState(''); const [ttl, setTTL] = useState('3600'); const [email, setEmail] = useState(''); const [ns, setNs] = useState(''); const [saving, setSaving] = useState(false); const [error, setError] = useState('');
  const handle = async () => {
    setError(''); if (!name.trim()) { setError('Zone name is required'); return; } const nameservers = ns.split('\n').map((s) => s.trim()).filter(Boolean); if (!nameservers.length) { setError('At least one nameserver is required'); return; }
    setSaving(true); try { await api('POST', '/api/v1/zones', { name: name.trim(), ttl: parseInt(ttl) || 3600, admin_email: email.trim(), nameservers }); setName(''); setTTL('3600'); setEmail(''); setNs(''); onCreated(); onClose(); } catch (e) { setError(e instanceof Error ? e.message : 'Failed'); } finally { setSaving(false); }
  };
  return (<Dialog open={open} onClose={onClose}><DialogTitle>Create New Zone</DialogTitle><div className="space-y-4 mt-5">
    {error && <div className="text-sm text-destructive bg-destructive/10 px-3 py-2 rounded-lg">{error}</div>}
    <div><label className="text-sm font-medium mb-1.5 block">Zone Name</label><Input placeholder="example.com." value={name} onChange={(e) => setName(e.target.value)} autoFocus /></div>
    <div className="grid grid-cols-2 gap-4"><div><label className="text-sm font-medium mb-1.5 block">Default TTL</label><Input type="number" value={ttl} onChange={(e) => setTTL(e.target.value)} /></div><div><label className="text-sm font-medium mb-1.5 block">Admin Email</label><Input placeholder="admin.example.com." value={email} onChange={(e) => setEmail(e.target.value)} /></div></div>
    <div><label className="text-sm font-medium mb-1.5 block">Nameservers (one per line)</label><Textarea rows={3} placeholder={"ns1.example.com.\nns2.example.com."} value={ns} onChange={(e) => setNs(e.target.value)} /></div>
    <div className="flex justify-end gap-2 pt-2"><Button variant="outline" onClick={onClose}>Cancel</Button><Button onClick={handle} disabled={saving}>{saving ? 'Creating...' : 'Create Zone'}</Button></div>
  </div></Dialog>);
}
