import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogTitle } from '@/components/ui/dialog';
import { Skeleton } from '@/components/ui/skeleton';
import { api, type ZoneDetail, type DnsRecord } from '@/lib/api';
import { ChevronRight, Download, Plus, Pencil, Trash2, Filter } from 'lucide-react';

export function ZoneDetailPage() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const zn = decodeURIComponent(name || '');
  const [zone, setZone] = useState<ZoneDetail | null>(null);
  const [records, setRecords] = useState<DnsRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const [editRec, setEditRec] = useState<DnsRecord | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [zd, rd] = await Promise.all([
        api<ZoneDetail>('GET', `/api/v1/zones/${encodeURIComponent(zn)}`),
        api<{ records: DnsRecord[] }>('GET', `/api/v1/zones/${encodeURIComponent(zn)}/records`),
      ]);
      setZone(zd); setRecords(rd.records || []);
    } catch (e) { console.error(e); } finally { setLoading(false); }
  }, [zn]);
  useEffect(() => { load(); }, [load]);

  const filtered = typeFilter ? records.filter((r) => r.type === typeFilter) : records;
  const types = [...new Set(records.map((r) => r.type))].sort();
  const tc: Record<string, 'success' | 'warning' | 'secondary' | 'default' | 'outline'> = { SOA: 'warning', NS: 'secondary', A: 'success', AAAA: 'success', CNAME: 'default', MX: 'outline', TXT: 'outline', SRV: 'outline' };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
        <button onClick={() => navigate('/zones')} className="hover:text-foreground transition-colors cursor-pointer">Zones</button>
        <ChevronRight className="h-3.5 w-3.5" /><span className="text-foreground font-medium">{zn}</span>
      </div>
      {zone && <Card><CardContent className="flex items-start justify-between p-6">
        <div><h1 className="text-2xl font-bold tracking-tight font-mono">{zn}</h1>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-2 text-sm text-muted-foreground">
            {zone.soa && <><span>Serial: <span className="font-mono font-medium text-foreground">{zone.soa.serial}</span></span><span>Primary NS: <span className="font-mono">{zone.soa.mname}</span></span></>}
            <span>Records: <span className="font-medium text-foreground">{zone.records}</span></span>
          </div>
        </div>
        <Button variant="outline" size="sm" onClick={() => { window.location.href = `/api/v1/zones/${encodeURIComponent(zn)}/export`; }}><Download className="h-4 w-4" /> Export</Button>
      </CardContent></Card>}

      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2"><Filter className="h-4 w-4 text-muted-foreground" /><Select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} className="w-[130px]"><option value="">All Types</option>{types.map((t) => <option key={t} value={t}>{t}</option>)}</Select><span className="text-xs text-muted-foreground">{filtered.length} record{filtered.length !== 1 ? 's' : ''}</span></div>
        <Button size="sm" onClick={() => setShowAdd(true)}><Plus className="h-4 w-4" /> Add Record</Button>
      </div>

      <Card><div className="overflow-x-auto"><table className="w-full">
        <thead><tr className="border-b bg-muted/50">
          <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3">Name</th>
          <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3">Type</th>
          <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3">TTL</th>
          <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3">Data</th>
          <th className="text-right text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3">Actions</th>
        </tr></thead>
        <tbody>
          {loading ? Array.from({ length: 5 }).map((_, i) => <tr key={i} className="border-b"><td colSpan={5} className="px-4 py-3"><Skeleton className="h-4 w-full" /></td></tr>)
          : filtered.length === 0 ? <tr><td colSpan={5} className="text-center py-12 text-muted-foreground">No records found</td></tr>
          : filtered.map((r, i) => (
            <tr key={`${r.name}-${r.type}-${i}`} className="border-b hover:bg-muted/30 transition-colors">
              <td className="px-4 py-3 font-mono text-sm">{r.name}</td>
              <td className="px-4 py-3"><Badge variant={tc[r.type] || 'outline'}>{r.type}</Badge></td>
              <td className="px-4 py-3 font-mono text-sm text-muted-foreground">{r.ttl}</td>
              <td className="px-4 py-3 font-mono text-sm max-w-[300px] truncate">{r.data}</td>
              <td className="px-4 py-3 text-right">
                {r.type !== 'SOA' ? <div className="flex items-center justify-end gap-1">
                  <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => setEditRec(r)}><Pencil className="h-3.5 w-3.5" /></Button>
                  <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive hover:text-destructive" onClick={() => { if (confirm(`Delete ${r.type} for ${r.name}?`)) api('DELETE', `/api/v1/zones/${encodeURIComponent(zn)}/records`, { name: r.name, type: r.type }).then(load); }}><Trash2 className="h-3.5 w-3.5" /></Button>
                </div> : <span className="text-xs text-muted-foreground">auto</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table></div></Card>

      <AddDialog open={showAdd} onClose={() => setShowAdd(false)} zn={zn} onSaved={load} />
      <EditDialog open={!!editRec} rec={editRec} onClose={() => setEditRec(null)} zn={zn} onSaved={() => { setEditRec(null); load(); }} />
    </div>
  );
}

function AddDialog({ open, onClose, zn, onSaved }: { open: boolean; onClose: () => void; zn: string; onSaved: () => void }) {
  const [n, setN] = useState(''); const [tp, setTp] = useState('A'); const [ttl, setTtl] = useState('3600'); const [d, setD] = useState(''); const [saving, setSaving] = useState(false); const [err, setErr] = useState('');
  const save = async () => {
    setErr(''); if (!n.trim() || !d.trim()) { setErr('Name and data required'); return; }
    setSaving(true); try { await api('POST', `/api/v1/zones/${encodeURIComponent(zn)}/records`, { name: n.trim(), type: tp, ttl: parseInt(ttl) || 3600, data: d.trim() }); setN(''); setTp('A'); setTtl('3600'); setD(''); onSaved(); onClose(); } catch (e) { setErr(e instanceof Error ? e.message : 'Failed'); } finally { setSaving(false); }
  };
  return (<Dialog open={open} onClose={onClose}><DialogTitle>Add Record</DialogTitle><div className="space-y-4 mt-5">
    {err && <div className="text-sm text-destructive bg-destructive/10 px-3 py-2 rounded-lg">{err}</div>}
    <div className="grid grid-cols-2 gap-4"><div><label className="text-sm font-medium mb-1.5 block">Name</label><Input placeholder="www" value={n} onChange={(e) => setN(e.target.value)} autoFocus /></div><div><label className="text-sm font-medium mb-1.5 block">Type</label><Select value={tp} onChange={(e) => setTp(e.target.value)}>{['A','AAAA','CNAME','MX','NS','TXT','SRV','CAA'].map((t) => <option key={t} value={t}>{t}</option>)}</Select></div></div>
    <div className="grid grid-cols-2 gap-4"><div><label className="text-sm font-medium mb-1.5 block">TTL</label><Input type="number" value={ttl} onChange={(e) => setTtl(e.target.value)} /></div><div><label className="text-sm font-medium mb-1.5 block">Data</label><Input placeholder="192.168.1.1" value={d} onChange={(e) => setD(e.target.value)} /></div></div>
    <div className="flex justify-end gap-2 pt-2"><Button variant="outline" onClick={onClose}>Cancel</Button><Button onClick={save} disabled={saving}>{saving ? 'Saving...' : 'Add'}</Button></div>
  </div></Dialog>);
}

function EditDialog({ open, rec, onClose, zn, onSaved }: { open: boolean; rec: DnsRecord | null; onClose: () => void; zn: string; onSaved: () => void }) {
  const [ttl, setTtl] = useState(''); const [d, setD] = useState(''); const [saving, setSaving] = useState(false); const [err, setErr] = useState('');
  useEffect(() => { if (rec) { setTtl(rec.ttl.toString()); setD(rec.data); } }, [rec]);
  if (!rec) return null;
  const save = async () => {
    setErr(''); setSaving(true); try { await api('PUT', `/api/v1/zones/${encodeURIComponent(zn)}/records`, { name: rec.name, type: rec.type, old_data: rec.data, ttl: parseInt(ttl) || 3600, data: d.trim() }); onSaved(); } catch (e) { setErr(e instanceof Error ? e.message : 'Failed'); } finally { setSaving(false); }
  };
  return (<Dialog open={open} onClose={onClose}><DialogTitle>Edit Record</DialogTitle><div className="space-y-4 mt-5">
    {err && <div className="text-sm text-destructive bg-destructive/10 px-3 py-2 rounded-lg">{err}</div>}
    <div className="grid grid-cols-2 gap-4"><div><label className="text-sm font-medium mb-1.5 block">Name</label><Input value={rec.name} readOnly className="opacity-60" /></div><div><label className="text-sm font-medium mb-1.5 block">Type</label><Input value={rec.type} readOnly className="opacity-60" /></div></div>
    <div className="grid grid-cols-2 gap-4"><div><label className="text-sm font-medium mb-1.5 block">TTL</label><Input type="number" value={ttl} onChange={(e) => setTtl(e.target.value)} /></div><div><label className="text-sm font-medium mb-1.5 block">Data</label><Input value={d} onChange={(e) => setD(e.target.value)} /></div></div>
    <div className="flex justify-end gap-2 pt-2"><Button variant="outline" onClick={onClose}>Cancel</Button><Button onClick={save} disabled={saving}>{saving ? 'Saving...' : 'Save'}</Button></div>
  </div></Dialog>);
}
