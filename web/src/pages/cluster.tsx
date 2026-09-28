import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState } from '@/components/states';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';
import { layoutMembers, rectEdge } from '@/pages/cluster-layout';
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

export function ClusterPage({ preview }: { preview?: { nodes: ClusterNode[]; status: ClusterStatus | null } } = {}) {
  const [nodes, setNodes] = useState<ClusterNode[]>(preview?.nodes ?? []);
  const [status, setStatus] = useState<ClusterStatus | null>(preview?.status ?? null);
  const [loading, setLoading] = useState(!preview);
  const [error, setError] = useState('');
  const [selectedNode, setSelectedNode] = useState<string | null>(() => {
    const seed = preview?.nodes ?? [];
    const local = preview?.status?.node_id;
    if (local && seed.some((n) => n.id === local)) return local;
    return preview?.status?.raft?.leader_id || seed[0]?.id || null;
  });

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

  const previewActive = preview != null;

  useEffect(() => {
    if (previewActive) return;
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, [previewActive]);

  const leaderId = status?.raft?.leader_id
    || nodes.find(n => n.role === 'leader')?.id
    || '';

  useEffect(() => {
    if (nodes.length === 0) {
      setSelectedNode(null);
      return;
    }
    setSelectedNode((cur) => {
      if (cur && nodes.some((n) => n.id === cur)) return cur;
      if (status?.node_id && nodes.some((n) => n.id === status.node_id)) return status.node_id;
      return leaderId || nodes[0].id;
    });
  }, [nodes, status?.node_id, leaderId]);

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
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Members</CardTitle>
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
            <MembershipBoard
              nodes={nodes}
              leaderId={leaderId}
              localId={status?.node_id}
              selectedId={selectedNode}
              onSelect={setSelectedNode}
            />
          )}
        </CardContent>
      </Card>
      </>
      )}
    </div>
  );
}

function memberRole(node: ClusterNode, isLeader: boolean) {
  if (isLeader) return 'Leader';
  if (node.role === 'candidate') return 'Candidate';
  if (node.role === 'follower') return 'Follower';
  return node.role || 'Member';
}

function stateDot(state: string) {
  if (state === 'alive') return 'bg-success';
  if (state === 'dead') return 'bg-destructive';
  return 'bg-warning';
}

function MembershipBoard({
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
  const layout = useMemo(() => layoutMembers(nodes, leaderId), [nodes, leaderId]);
  const frameRef = useRef<HTMLDivElement>(null);
  const [scale, setScale] = useState(1);
  const leaderPos = layout.leaderId ? layout.positions.get(layout.leaderId) : undefined;
  const selected = nodes.find(n => n.id === selectedId) ?? null;
  const followers = nodes.filter(n => n.id !== layout.leaderId);

  useLayoutEffect(() => {
    const el = frameRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const fit = () => {
      const available = el.clientWidth;
      if (available <= 0) return;
      setScale(Math.min(1, available / layout.width));
    };
    fit();
    const obs = new ResizeObserver(fit);
    obs.observe(el);
    return () => obs.disconnect();
  }, [layout.width]);

  return (
    <div className="flex flex-col gap-4 lg:flex-row lg:items-start">
      <div ref={frameRef} className="min-w-0 flex-1 overflow-hidden rounded-xl border border-border bg-[radial-gradient(ellipse_at_center,rgba(79,109,245,0.10),transparent_62%)]">
        <div className="mx-auto overflow-hidden" style={{ width: layout.width * scale, height: layout.height * scale }}>
        <div className="relative" style={{ width: layout.width, height: layout.height, transform: `scale(${scale})`, transformOrigin: 'top left' }}>
          <svg
            width={layout.width}
            height={layout.height}
            viewBox={`0 0 ${layout.width} ${layout.height}`}
            className="absolute inset-0"
            role="img"
            aria-label="Cluster topology diagram"
          >
            {leaderPos && followers.map((node) => {
              const pos = layout.positions.get(node.id);
              if (!pos) return null;
              const healthy = node.state === 'alive';
              const dx = pos.x - leaderPos.x;
              const dy = pos.y - leaderPos.y;
              const len = Math.hypot(dx, dy) || 1;
              const ux = dx / len;
              const uy = dy / len;
              const from = rectEdge(leaderPos, ux, uy);
              const to = rectEdge(pos, -ux, -uy);
              return (
                <line
                  key={`link-${node.id}`}
                  x1={from.x}
                  y1={from.y}
                  x2={to.x}
                  y2={to.y}
                  stroke={healthy ? 'var(--color-primary)' : node.state === 'dead' ? 'var(--color-destructive)' : 'var(--color-warning)'}
                  strokeOpacity={healthy ? 0.7 : 0.85}
                  strokeWidth={healthy ? 2 : 1.5}
                  strokeLinecap="round"
                  strokeDasharray={healthy ? undefined : '5 5'}
                />
              );
            })}
          </svg>

          {nodes.map((node) => {
            const pos = layout.positions.get(node.id);
            if (!pos) return null;
            const isLeader = node.id === layout.leaderId;
            const isLocal = node.id === localId;
            const pressed = node.id === selectedId;
            const role = memberRole(node, isLeader);
            const endpoint = node.addr ? `${node.addr}:${node.port}` : '—';
            return (
              <button
                key={node.id}
                type="button"
                aria-pressed={pressed}
                title={endpoint}
                onClick={() => onSelect(node.id)}
                className={cn(
                  'absolute flex flex-col justify-center gap-0.5 rounded-xl border bg-card px-3 text-left shadow-sm',
                  'hover:shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                  isLeader ? 'border-primary bg-primary/10 ring-4 ring-primary/20' : 'border-border',
                  !isLeader && node.state === 'alive' && 'border-success/50',
                  node.state === 'dead' && 'border-destructive/60 bg-destructive/5',
                  node.state !== 'alive' && node.state !== 'dead' && 'border-warning/60',
                  pressed && 'z-10 outline outline-2 outline-offset-2 outline-primary',
                )}
                style={{
                  left: pos.x - pos.w / 2,
                  top: pos.y - pos.h / 2,
                  width: pos.w,
                  height: pos.h,
                }}
              >
                <span className="flex items-center gap-1.5">
                  {isLeader
                    ? <Crown className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden />
                    : <span className={cn('h-1.5 w-1.5 shrink-0 rounded-full', stateDot(node.state))} aria-hidden />}
                  <span className="truncate text-sm font-semibold">{node.id}</span>
                  {isLocal && (
                    <span className="ml-auto shrink-0 rounded border border-border px-1 text-[10px] text-muted-foreground">You</span>
                  )}
                </span>
                <span className="truncate text-[11px] text-muted-foreground">{role}</span>
                <span className="truncate font-mono text-[11px] text-muted-foreground">{endpoint}</span>
              </button>
            );
          })}
        </div>
        </div>
        <div className="flex flex-wrap items-center justify-center gap-3 px-4 py-3 text-[11px] text-muted-foreground">
          <span className="inline-flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full bg-primary" /> Leader</span>
          <span className="inline-flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full bg-success" /> Alive</span>
          <span className="inline-flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full bg-warning" /> Suspect</span>
          <span className="inline-flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full bg-destructive" /> Dead</span>
        </div>
      </div>

      <NodeDetail node={selected} isLocal={selected?.id === localId} isLeader={selected?.id === layout.leaderId} />
    </div>
  );
}

function NodeDetail({ node, isLocal, isLeader }: {
  node: ClusterNode | null;
  isLocal: boolean;
  isLeader: boolean;
}) {
  return (
    <aside className="w-full shrink-0 rounded-xl border border-border bg-card p-4 lg:w-72" aria-label="Node details">
      {!node ? (
        <p className="text-sm text-muted-foreground">Select a node to see its address, region and weight.</p>
      ) : (
        <div className="space-y-4">
          <div>
            <div className="flex items-center gap-2">
              {isLeader ? <Crown className="h-4 w-4 text-primary" /> : <Server className="h-4 w-4 text-muted-foreground" />}
              <h3 className="text-sm font-semibold">{node.id}</h3>
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              <Badge variant={node.state === 'alive' ? 'success' : node.state === 'dead' ? 'destructive' : 'secondary'} className="text-[10px]">
                {node.state}
              </Badge>
              <Badge variant={isLeader ? 'default' : node.role === 'candidate' ? 'warning' : 'secondary'} className="text-[10px]">
                {memberRole(node, isLeader)}
              </Badge>
              {isLocal && <Badge variant="outline" className="text-[10px]">this node</Badge>}
            </div>
            <p className="mt-2 font-mono text-xs text-muted-foreground">
              {node.addr || '—'}:{node.port}
              <span className="ml-2">v{node.version || 1}</span>
            </p>
          </div>
          <dl className="grid grid-cols-2 gap-3 border-t border-border pt-3">
            <div>
              <dt className="text-xs text-muted-foreground">Region</dt>
              <dd className="text-sm font-medium">{node.region || 'N/A'}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Zone</dt>
              <dd className="text-sm font-medium">{node.zone || 'N/A'}</dd>
            </div>
            <div className="col-span-2">
              <dt className="text-xs text-muted-foreground">HTTP address</dt>
              <dd className="break-all font-mono text-sm font-medium">{node.http_addr || 'N/A'}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Weight</dt>
              <dd className="text-sm font-medium tabular-nums">{node.weight}</dd>
            </div>
          </dl>
        </div>
      )}
    </aside>
  );
}

