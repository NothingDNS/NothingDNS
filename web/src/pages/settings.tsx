import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { api, type ServerStatus } from '@/lib/api';
import { Server, Database, Network, RefreshCw, Trash2, Clock, Cpu, HardDrive } from 'lucide-react';

export function SettingsPage() {
  const [status, setStatus] = useState<ServerStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [flushing, setFlushing] = useState(false);
  const [reloading, setReloading] = useState(false);

  useEffect(() => {
    api<ServerStatus>('GET', '/api/v1/status').then(setStatus).catch(console.error).finally(() => setLoading(false));
    const iv = setInterval(() => api<ServerStatus>('GET', '/api/v1/status').then(setStatus).catch(() => {}), 10000);
    return () => clearInterval(iv);
  }, []);

  const handleFlush = async () => { setFlushing(true); try { await api('POST', '/api/v1/cache/flush'); } catch (e) { console.error('Flush failed:', e); } setFlushing(false); };
  const handleReload = async () => { setReloading(true); try { await api('POST', '/api/v1/config/reload'); } catch (e) { console.error('Reload failed:', e); } setReloading(false); };

  if (loading) return <div className="space-y-6"><div><h1 className="text-2xl font-bold tracking-tight">Settings</h1><p className="text-muted-foreground text-sm">Server configuration</p></div><div className="space-y-4"><Skeleton className="h-48 w-full rounded-xl" /><Skeleton className="h-36 w-full rounded-xl" /></div></div>;

  return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">Settings</h1><p className="text-muted-foreground text-sm">Server configuration and management</p></div>

      <Card>
        <CardHeader><CardTitle className="flex items-center gap-2 text-base"><Server className="h-4 w-4" /> Server Status</CardTitle></CardHeader>
        <CardContent><div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <InfoRow icon={<Cpu className="h-4 w-4" />} label="Status"><Badge variant="success">{status?.status || 'running'}</Badge></InfoRow>
          <InfoRow icon={<HardDrive className="h-4 w-4" />} label="Version"><span className="font-mono text-sm">{status?.version || '-'}</span></InfoRow>
          <InfoRow icon={<Clock className="h-4 w-4" />} label="Updated"><span className="font-mono text-sm">{status?.timestamp ? new Date(status.timestamp).toLocaleTimeString() : '-'}</span></InfoRow>
        </div></CardContent>
      </Card>

      {status?.cache && <Card>
        <CardHeader><CardTitle className="flex items-center gap-2 text-base"><Database className="h-4 w-4" /> Cache</CardTitle></CardHeader>
        <CardContent>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <InfoItem label="Size" value={`${status.cache.size} / ${status.cache.capacity}`} />
            <InfoItem label="Hits" value={status.cache.hits.toLocaleString()} />
            <InfoItem label="Misses" value={status.cache.misses.toLocaleString()} />
            <InfoItem label="Hit Ratio" value={`${(status.cache.hit_ratio * 100).toFixed(1)}%`} />
          </div>
          <div className="mt-4"><div className="h-2 rounded-full bg-muted overflow-hidden"><div className="h-full rounded-full bg-primary transition-all duration-500" style={{ width: `${status.cache.hit_ratio * 100}%` }} /></div></div>
        </CardContent>
      </Card>}

      <Card>
        <CardHeader><CardTitle className="flex items-center gap-2 text-base"><Network className="h-4 w-4" /> Cluster</CardTitle></CardHeader>
        <CardContent>
          {status?.cluster ? (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <InfoItem label="Status" value={status.cluster.enabled ? 'Enabled' : 'Disabled'} />
              {status.cluster.enabled && <><InfoItem label="Node ID" value={status.cluster.node_id || '-'} mono /><InfoItem label="Nodes" value={`${status.cluster.alive_count || 0} / ${status.cluster.node_count || 0}`} /><InfoItem label="Healthy" value={status.cluster.healthy ? 'Yes' : 'No'} /></>}
            </div>
          ) : <p className="text-sm text-muted-foreground">Cluster not configured</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-base">Actions</CardTitle></CardHeader>
        <CardContent><div className="flex flex-wrap gap-3">
          <Button variant="outline" onClick={handleFlush} disabled={flushing}><Trash2 className="h-4 w-4" /> {flushing ? 'Flushing...' : 'Flush Cache'}</Button>
          <Button variant="outline" onClick={handleReload} disabled={reloading}><RefreshCw className="h-4 w-4" /> {reloading ? 'Reloading...' : 'Reload Config'}</Button>
        </div></CardContent>
      </Card>
    </div>
  );
}

function InfoRow({ icon, label, children }: { icon: React.ReactNode; label: string; children: React.ReactNode }) {
  return <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50"><div className="text-muted-foreground">{icon}</div><div><div className="text-xs text-muted-foreground">{label}</div><div className="mt-0.5">{children}</div></div></div>;
}

function InfoItem({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return <div className="p-3 rounded-lg bg-muted/50"><div className="text-xs text-muted-foreground">{label}</div><div className={mono ? 'font-mono text-sm mt-0.5' : 'text-sm mt-0.5'}>{value}</div></div>;
}
