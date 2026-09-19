import { useEffect, useRef, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState } from '@/components/states';
import { api } from '@/lib/api';
import { Server, RefreshCw, Network, AlertCircle, Info } from 'lucide-react';

interface ClusterNode {
  id: string;
  addr: string;
  port: number;
  state: string;
  region: string;
  zone: string;
  weight: number;
  http_addr: string;
  version: number;
}

interface RaftInfo {
  state: string;
  term: number;
  commit_index: number;
  applied_index: number;
  is_leader: boolean;
  leader_id: string;
}

interface ClusterStatus {
  node_id: string;
  consensus: string;
  raft?: RaftInfo;
}

export function ClusterPage() {
  const [nodes, setNodes] = useState<ClusterNode[]>([]);
  const [status, setStatus] = useState<ClusterStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  // Generation guard for load(): the 10s polling interval and the Refresh
  // button can overlap an in-flight load, and an older response landing
  // after a newer one must not overwrite fresher state (api() has no
  // timeout, so a stalled request can stay in flight indefinitely).
  const loadGeneration = useRef(0);

  const load = async () => {
    const gen = ++loadGeneration.current;
    setLoading(true);
    try {
      const [data, st] = await Promise.all([
        api<{ nodes: ClusterNode[] }>('GET', '/api/v1/cluster/nodes'),
        api<ClusterStatus>('GET', '/api/v1/cluster/status').catch(() => null),
      ]);
      if (gen !== loadGeneration.current) return; // superseded by a newer load
      setNodes(data.nodes || []);
      setStatus(st);
      setError('');
    } catch (e: unknown) {
      if (gen !== loadGeneration.current) return; // superseded
      setError(e instanceof Error ? e.message : 'Failed to load cluster status');
    } finally {
      if (gen === loadGeneration.current) setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, []);

  if (loading && nodes.length === 0) {
    return (
      <div className="space-y-6">
        <div><h1 className="text-2xl font-bold tracking-tight">Cluster</h1><p className="text-muted-foreground text-sm">Multi-node DNS cluster management</p></div>
        <div className="space-y-4"><Skeleton className="h-48 w-full rounded-xl" /><Skeleton className="h-48 w-full rounded-xl" /></div>
      </div>
    );
  }

  const onlineCount = nodes.filter(n => n.state === "alive").length;
  const quorum = nodes.length > 0 && onlineCount >= Math.floor(nodes.length / 2) + 1;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Cluster</h1>
          <p className="text-muted-foreground text-sm">Multi-node DNS cluster management</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={quorum ? 'success' : 'destructive'}>
            {quorum ? 'Quorum OK' : 'No Quorum'}
          </Badge>
          <Button variant="outline" size="sm" onClick={load}>
            <RefreshCw className="h-4 w-4 mr-2" /> Refresh
          </Button>
        </div>
      </div>

      {error ? <ErrorState message={error} onRetry={load} /> : (
      <>
      {/* Membership is config-driven, not editable from the dashboard */}
      <Card className="border-border">
        <CardContent className="p-4">
          <div className="flex items-start gap-3">
            <Info className="h-5 w-5 text-muted-foreground mt-0.5 shrink-0" />
            <p className="text-sm text-muted-foreground">
              Cluster membership is configured in the server config file and applied on restart. Add or remove nodes by editing the configuration and reloading the server.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Overview */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary/10">
                <Server className="h-5 w-5 text-primary" />
              </div>
              <div>
                <div className="text-2xl font-bold">{nodes.length}</div>
                <div className="text-xs text-muted-foreground">Total Nodes</div>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-success/10">
                <Network className="h-5 w-5 text-success" />
              </div>
              <div>
                <div className="text-2xl font-bold text-success">{onlineCount}</div>
                <div className="text-xs text-muted-foreground">Online</div>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-destructive/10">
                <AlertCircle className="h-5 w-5 text-destructive" />
              </div>
              <div>
                <div className="text-2xl font-bold text-destructive">{nodes.length - onlineCount}</div>
                <div className="text-xs text-muted-foreground">Offline</div>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-warning/10">
                <Network className="h-5 w-5 text-warning" />
              </div>
              <div>
                <div className="text-2xl font-bold">{quorum ? 'Yes' : 'No'}</div>
                <div className="text-xs text-muted-foreground">Quorum</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Raft consensus status — only shown when the cluster runs in Raft mode */}
      {status?.consensus === 'raft' && status.raft && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Network className="h-4 w-4" /> Raft Consensus
              <Badge variant={status.raft.is_leader ? 'success' : 'secondary'}>
                {status.raft.state}
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <div className="text-xs text-muted-foreground">Leader</div>
                <div className="text-sm font-semibold">{status.raft.leader_id || '—'}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground">Term</div>
                <div className="text-sm font-semibold tabular-nums">{status.raft.term}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground">Commit Index</div>
                <div className="text-sm font-semibold tabular-nums">{status.raft.commit_index}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground">Applied Index</div>
                <div className="text-sm font-semibold tabular-nums">{status.raft.applied_index}</div>
              </div>
            </div>
            {status.raft.commit_index !== status.raft.applied_index && (
              <p className="text-xs text-warning mt-3">
                Applying {status.raft.commit_index - status.raft.applied_index} pending committed entr
                {status.raft.commit_index - status.raft.applied_index === 1 ? 'y' : 'ies'}…
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {/* Nodes List */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Cluster Nodes</CardTitle>
        </CardHeader>
        <CardContent>
          {nodes.length === 0 ? (
            <div className="text-center py-12">
              <Server className="h-12 w-12 mx-auto text-muted-foreground/50 mb-4" />
              <h3 className="text-lg font-semibold mb-1">No nodes in cluster</h3>
              <p className="text-sm text-muted-foreground">
                Configure cluster nodes in the server config file and restart to start clustering.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {nodes.map(node => (
                <NodeCard
                  key={node.id}
                  node={node}
                  selected={selectedNode === node.id}
                  onSelect={() => setSelectedNode(selectedNode === node.id ? null : node.id)}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Cluster Topology */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Cluster Topology</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-center justify-center gap-4 p-8">
            {nodes.map(node => (
              <div key={node.id} className="relative">
                <div className={`w-16 h-16 rounded-full flex items-center justify-center ${
                  node.state === 'alive' ? 'bg-success/20 border-2 border-success' :
                  node.state === 'dead' ? 'bg-destructive/20 border-2 border-destructive' :
                  'bg-warning/20 border-2 border-warning'
                }`}>
                  <Server className={`h-6 w-6 ${
                    node.state === 'alive' ? 'text-success' :
                    node.state === 'dead' ? 'text-destructive' :
                    'text-warning'
                  }`} />
                </div>
                <div className="text-center mt-2">
                  <div className="text-xs font-medium">{node.state}</div>
                  <div className="text-xs text-muted-foreground">{node.addr}</div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
      </>
      )}
    </div>
  );
}

function NodeCard({ node, selected, onSelect }: {
  node: ClusterNode;
  selected: boolean;
  onSelect: () => void;
}) {
  const statusColors: Record<string, string> = {
    alive: 'text-success bg-success/10 border-success/20',
    dead: 'text-destructive bg-destructive/10 border-destructive/20',
    suspect: 'text-warning bg-warning/10 border-warning/20',
    draining: 'text-muted-foreground bg-muted border-muted',
  };

  return (
    <button
      type="button"
      aria-expanded={selected}
      className={`w-full text-left border rounded-lg p-4 transition-all hover:shadow-md ${
        selected ? 'border-primary shadow-md' : 'border-border'
      }`}
      onClick={onSelect}
    >
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${statusColors[node.state] || 'border-muted'}`}>
            <Server className="h-4 w-4" />
          </div>
          <div>
            <div className="font-medium text-sm flex items-center gap-2">
              {node.id}
              <Badge variant={node.state === 'alive' ? 'success' : node.state === 'dead' ? 'destructive' : 'secondary'} className="text-[10px]">
                {node.state}
              </Badge>
              {node.weight === 1 && <Badge variant="warning" className="text-[10px]">primary</Badge>}
            </div>
            <div className="text-xs text-muted-foreground mt-0.5">
              {node.addr}:{node.port} • v{node.version}
            </div>
          </div>
        </div>
      </div>

      {selected && (
        <div className="mt-4 pt-4 border-t grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <div className="text-xs text-muted-foreground">Region</div>
            <div className="text-sm font-medium">{node.region || 'N/A'}</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">Zone</div>
            <div className="text-sm font-medium">{node.zone || 'N/A'}</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">HTTPAddr</div>
            <div className="text-sm font-medium">{node.http_addr || 'N/A'}</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">Weight</div>
            <div className="text-sm font-medium">{node.weight}</div>
          </div>
        </div>
      )}
    </button>
  );
}
