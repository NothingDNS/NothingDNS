import { useId, useState } from 'react';
import { Network, Globe, Plus, Trash2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';
import { useUpdateUpstreamServer } from '@/hooks/useApi';
import { useAuthStore } from '@/stores/authStore';
import { type ServerConfig } from './types';
import { Card, CardContent, SectionHeader, KVRow } from './shared';

export function UpstreamSettings({ config, onReload }: { config: ServerConfig; onReload: () => Promise<void> }) {
  const upstream = config.Upstream;
  const updateUpstream = useUpdateUpstreamServer();
  const isAdmin = useAuthStore((s) => s.role) === 'admin';
  const [newServer, setNewServer] = useState('');
  const fieldId = useId();

  const servers = upstream?.Servers ?? [];

  const handleAdd = async () => {
    const server = newServer.trim();
    if (!server) return;
    try {
      await updateUpstream.mutateAsync({ action: 'add', server });
      setNewServer('');
      await onReload();
      toast.success(`Added ${server}`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to add upstream');
    }
  };

  const handleRemove = async (server: string) => {
    try {
      await updateUpstream.mutateAsync({ action: 'remove', server });
      await onReload();
      toast.success(`Removed ${server}`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to remove upstream');
    }
  };

  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader
          title="Upstream Servers"
          description="Add or remove recursive upstreams without restart (persisted to runtime overrides)"
          icon={<Network className="h-4 w-4" />}
          badge="Live edit"
        />
        <CardContent className="space-y-4">
          <KVRow label="Strategy" value={upstream?.Strategy || 'random'} />
          <KVRow label="Health Check" value={upstream?.HealthCheck || '30s'} />
          <KVRow label="Failover Timeout" value={upstream?.FailoverTimeout || '5s'} />

          {servers.length === 0 ? (
            <p className="text-sm text-muted-foreground py-2">No upstream servers configured</p>
          ) : (
            <ul className="divide-y rounded-md border" aria-label="Upstream servers">
              {servers.map((s) => (
                <li key={s} className="flex items-center justify-between px-3 py-2">
                  <span className="font-mono text-sm">{s}</span>
                  {isAdmin && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => void handleRemove(s)}
                      disabled={updateUpstream.isPending}
                      aria-label={`Remove ${s}`}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          )}

          {isAdmin ? (
            <form
              className="flex gap-2"
              onSubmit={(e) => { e.preventDefault(); void handleAdd(); }}
            >
              <Input
                id={`${fieldId}-server`}
                value={newServer}
                onChange={(e) => setNewServer(e.target.value)}
                placeholder="8.8.8.8:53 or 1.1.1.1:53"
                aria-label="Upstream server address"
                className="font-mono"
                disabled={updateUpstream.isPending}
              />
              <Button type="submit" disabled={updateUpstream.isPending || !newServer.trim()}>
                <Plus className="h-4 w-4" /> Add
              </Button>
            </form>
          ) : (
            <p className="text-xs text-muted-foreground">Only administrators can change upstream servers.</p>
          )}
          <p className="text-xs text-muted-foreground">Strategy, health check and failover remain file-backed (edit YAML and reload).</p>
        </CardContent>
      </Card>

      {upstream?.AnycastGroups && upstream.AnycastGroups.length > 0 && (
        <Card>
          <SectionHeader title="Anycast Groups" description="Geographic load balancing" icon={<Globe className="h-4 w-4" />} />
          <CardContent className="space-y-4">
            {upstream.AnycastGroups.map((ag, i) => (
              <div key={i} className="p-3 rounded-lg bg-muted/50 space-y-2">
                <div className="font-medium text-sm flex items-center gap-2">
                  <Badge variant="outline">{ag.AnycastIP}</Badge>
                </div>
                {ag.Backends?.map((b, j) => (
                  <div key={j} className="pl-3 border-l-2 border-border space-y-0.5">
                    <KVRow label="Backend" value={`${b.PhysicalIP}:${b.Port}`} mono />
                    <KVRow label="Region/Zone" value={`${b.Region || '-'}/${b.Zone || '-'}`} />
                    <KVRow label="Weight" value={b.Weight} />
                  </div>
                ))}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {upstream?.Topology && (
        <Card>
          <SectionHeader title="Topology" description="This node's location" icon={<Globe className="h-4 w-4" />} />
          <CardContent className="space-y-1">
            <KVRow label="Region" value={upstream.Topology.Region || '-'} />
            <KVRow label="Zone" value={upstream.Topology.Zone || '-'} />
            <KVRow label="Weight" value={upstream.Topology.Weight} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
