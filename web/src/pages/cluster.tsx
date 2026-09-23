import { useEffect, useMemo, useRef, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState } from '@/components/states';
import { api } from '@/lib/api';
import { Server, RefreshCw, Network, AlertCircle, Info, Crown } from 'lucide-react';

interface ClusterNode {
  id: string;
  addr: string;
  port: number;
  state: string;
  role?: string;
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

  const onlineCount = nodes.filter(n => n.state === 'alive').length;
  const quorum = nodes.length > 0 && onlineCount >= Math.floor(nodes.length / 2) + 1;
  const leaderId = status?.raft?.leader_id
    || nodes.find(n => n.role === 'leader')?.id
    || '';

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
      <Card className="border-border">
        <CardContent className="p-4">
          <div className="flex items-start gap-3">
            <Info className="h-5 w-5 text-muted-foreground mt-0.5 shrink-0" />
            <p className="text-sm text-muted-foreground">
              {status?.consensus === 'raft'
                ? 'Raft membership comes from cluster.peers in the config. Zone writes must target the current leader.'
                : 'Cluster membership is configured in the server config file and applied on restart.'}
            </p>
          </div>
        </CardContent>
      </Card>

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

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Cluster Topology</CardTitle>
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
            <TopologyDiagram
              nodes={nodes}
              leaderId={leaderId}
              localId={status?.node_id}
              selectedId={selectedNode}
              onSelect={(id) => setSelectedNode(selectedNode === id ? null : id)}
            />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Cluster Nodes</CardTitle>
        </CardHeader>
        <CardContent>
          {nodes.length === 0 ? (
            <div className="text-center py-8 text-sm text-muted-foreground">
              No members to list.
            </div>
          ) : (
            <div className="space-y-3">
              {nodes.map(node => (
                <NodeCard
                  key={node.id}
                  node={node}
                  isLocal={node.id === status?.node_id}
                  selected={selectedNode === node.id}
                  onSelect={() => setSelectedNode(selectedNode === node.id ? null : node.id)}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>
      </>
      )}
    </div>
  );
}

function TopologyDiagram({
  nodes,
  leaderId,
  localId,
  selectedId,
  onSelect,
}: {
  nodes: ClusterNode[];
  leaderId: string;
  localId?: string;
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const layout = useMemo(() => {
    const width = 640;
    const height = 360;
    const cx = width / 2;
    const cy = height / 2;
    const leader = nodes.find(n => n.id === leaderId) || nodes.find(n => n.role === 'leader') || nodes[0];
    const followers = nodes.filter(n => n.id !== leader?.id);
    const radius = followers.length <= 1 ? 130 : Math.min(150, 90 + followers.length * 12);

    const positions = new Map<string, { x: number; y: number }>();
    if (leader) positions.set(leader.id, { x: cx, y: cy });

    followers.forEach((node, i) => {
      const angle = (-Math.PI / 2) + (2 * Math.PI * i) / Math.max(followers.length, 1);
      positions.set(node.id, {
        x: cx + Math.cos(angle) * radius,
        y: cy + Math.sin(angle) * radius,
      });
    });

    return { width, height, cx, cy, leader, followers, positions };
  }, [nodes, leaderId]);

  const leaderPos = layout.leader ? layout.positions.get(layout.leader.id) : null;

  return (
    <div className="relative overflow-hidden rounded-xl border border-border bg-[radial-gradient(ellipse_at_center,rgba(59,92,228,0.08),transparent_65%)]">
      <svg
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        className="w-full h-auto max-h-[420px]"
        role="img"
        aria-label="Cluster topology diagram"
      >
        <defs>
          <linearGradient id="raft-link" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="var(--color-primary)" stopOpacity="0.55" />
            <stop offset="100%" stopColor="var(--color-success)" stopOpacity="0.35" />
          </linearGradient>
        </defs>

        {leaderPos && layout.followers.map((node) => {
          const pos = layout.positions.get(node.id);
          if (!pos) return null;
          const healthy = node.state === 'alive';
          return (
            <g key={`link-${node.id}`}>
              <line
                x1={leaderPos.x}
                y1={leaderPos.y}
                x2={pos.x}
                y2={pos.y}
                stroke={healthy ? 'url(#raft-link)' : 'var(--color-warning)'}
                strokeWidth={healthy ? 2.5 : 1.5}
                strokeDasharray={healthy ? undefined : '6 6'}
                className={healthy ? 'animate-[pulse_2.8s_ease-in-out_infinite]' : undefined}
              />
            </g>
          );
        })}

        {nodes.map((node) => {
          const pos = layout.positions.get(node.id);
          if (!pos) return null;
          const isLeader = node.id === layout.leader?.id || node.role === 'leader';
          const isLocal = node.id === localId;
          const selected = node.id === selectedId;
          const r = isLeader ? 34 : 26;
          const fill =
            node.state === 'alive' ? (isLeader ? 'rgba(59,92,228,0.18)' : 'rgba(34,197,94,0.14)') :
            node.state === 'dead' ? 'rgba(239,68,68,0.16)' :
            'rgba(245,158,11,0.16)';
          const stroke =
            selected ? 'var(--color-primary)' :
            isLeader ? 'var(--color-primary)' :
            node.state === 'alive' ? 'var(--color-success)' :
            node.state === 'dead' ? 'var(--color-destructive)' :
            'var(--color-warning)';

          return (
            <g
              key={node.id}
              transform={`translate(${pos.x}, ${pos.y})`}
              className="cursor-pointer"
              onClick={() => onSelect(node.id)}
            >
              {isLeader && (
                <circle r={r + 10} fill="none" stroke="var(--color-primary)" strokeOpacity="0.25" strokeWidth="2">
                  <animate attributeName="r" values={`${r + 8};${r + 14};${r + 8}`} dur="2.4s" repeatCount="indefinite" />
                  <animate attributeName="stroke-opacity" values="0.35;0.12;0.35" dur="2.4s" repeatCount="indefinite" />
                </circle>
              )}
              <circle r={r} fill={fill} stroke={stroke} strokeWidth={selected || isLeader ? 3 : 2} />
              <text
                textAnchor="middle"
                dominantBaseline="central"
                className="fill-foreground"
                style={{ fontSize: isLeader ? 11 : 10, fontWeight: 600 }}
              >
                {isLeader ? '★' : '●'}
              </text>
              <text
                y={r + 16}
                textAnchor="middle"
                className="fill-foreground"
                style={{ fontSize: 12, fontWeight: 600 }}
              >
                {node.id}
              </text>
              <text
                y={r + 32}
                textAnchor="middle"
                className="fill-muted-foreground"
                style={{ fontSize: 10 }}
              >
                {isLeader ? 'Leader' : (node.role || 'Member')}
                {isLocal ? ' · you' : ''}
              </text>
              <text
                y={r + 46}
                textAnchor="middle"
                className="fill-muted-foreground"
                style={{ fontSize: 10 }}
              >
                {node.addr || '—'}
              </text>
            </g>
          );
        })}
      </svg>

      <div className="flex flex-wrap items-center justify-center gap-3 px-4 pb-4 text-[11px] text-muted-foreground">
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full bg-primary" /> Leader
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full bg-success" /> Follower
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full bg-warning" /> Suspect
        </span>
      </div>
    </div>
  );
}

function NodeCard({ node, isLocal, selected, onSelect }: {
  node: ClusterNode;
  isLocal?: boolean;
  selected: boolean;
  onSelect: () => void;
}) {
  const statusColors: Record<string, string> = {
    alive: 'text-success bg-success/10 border-success/20',
    dead: 'text-destructive bg-destructive/10 border-destructive/20',
    suspect: 'text-warning bg-warning/10 border-warning/20',
    draining: 'text-muted-foreground bg-muted border-muted',
  };
  const isLeader = node.role === 'leader';

  return (
    <button
      type="button"
      aria-expanded={selected}
      className={`w-full text-left border rounded-lg p-4 transition-all hover:shadow-md ${
        selected ? 'border-primary shadow-md' : isLeader ? 'border-primary/40' : 'border-border'
      }`}
      onClick={onSelect}
    >
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${statusColors[node.state] || 'border-muted'}`}>
            {isLeader ? <Crown className="h-4 w-4 text-primary" /> : <Server className="h-4 w-4" />}
          </div>
          <div>
            <div className="font-medium text-sm flex items-center gap-2 flex-wrap">
              {node.id}
              <Badge variant={node.state === 'alive' ? 'success' : node.state === 'dead' ? 'destructive' : 'secondary'} className="text-[10px]">
                {node.state}
              </Badge>
              {isLeader && <Badge variant="default" className="text-[10px]">Leader</Badge>}
              {node.role === 'follower' && <Badge variant="secondary" className="text-[10px]">Follower</Badge>}
              {node.role === 'candidate' && <Badge variant="warning" className="text-[10px]">Candidate</Badge>}
              {isLocal && <Badge variant="outline" className="text-[10px]">this node</Badge>}
            </div>
            <div className="text-xs text-muted-foreground mt-0.5">
              {node.addr}:{node.port} • v{node.version || 1}
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
