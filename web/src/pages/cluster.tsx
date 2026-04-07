import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/api';
import { Server, Plus, RefreshCw, Trash2, Network, AlertCircle } from 'lucide-react';

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

export function ClusterPage() {
  const [nodes, setNodes] = useState<ClusterNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const data = await api<{ nodes: ClusterNode[] }>('GET', '/api/v1/cluster/nodes');
      setNodes(data.nodes || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleRemoveNode = async (_id: string) => {
    alert('Node removal requires configuration change and server restart. Use the Reload Config action after editing your configuration file.');
  };

  const handleJoinNode = () => {
    alert('Adding nodes requires configuration change and server restart. Edit your configuration file to add new cluster nodes.');
  };

  if (loading && nodes.length === 0) {
    return (
      <div className="space-y-6">
        <div><h1 className="text-2xl font-bold tracking-tight">Cluster</h1><p className="text-muted-foreground text-sm">Multi-node DNS cluster management</p></div>
        <div className="space-y-4"><Skeleton className="h-48 w-full rounded-xl" /><Skeleton className="h-48 w-full rounded-xl" /></div>
      </div>
    );
  }

  const onlineCount = nodes.filter(n => n.state === "online").length;
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
          <Button size="sm" onClick={handleJoinNode}>
            <Plus className="h-4 w-4 mr-2" /> Join Node
          </Button>
        </div>
      </div>

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
              <p className="text-sm text-muted-foreground mb-4">
                Add your first node to start clustering.
              </p>
              <Button onClick={handleJoinNode}>
                <Plus className="h-4 w-4 mr-2" /> Add Node
              </Button>
            </div>
          ) : (
            <div className="space-y-3">
              {nodes.map(node => (
                <NodeCard
                  key={node.id}
                  node={node}
                  selected={selectedNode === node.id}
                  onSelect={() => setSelectedNode(selectedNode === node.id ? null : node.id)}
                  onRemove={() => handleRemoveNode(node.id)}
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
                  node.state === 'online' ? 'bg-success/20 border-2 border-success' :
                  node.state === 'offline' ? 'bg-destructive/20 border-2 border-destructive' :
                  'bg-warning/20 border-2 border-warning'
                }`}>
                  <Server className={`h-6 w-6 ${
                    node.state === 'online' ? 'text-success' :
                    node.state === 'offline' ? 'text-destructive' :
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
    </div>
  );
}

function NodeCard({ node, selected, onSelect, onRemove }: {
  node: ClusterNode;
  selected: boolean;
  onSelect: () => void;
  onRemove: () => void;
}) {
  const statusColors: Record<string, string> = {
    online: 'text-success bg-success/10 border-success/20',
    offline: 'text-destructive bg-destructive/10 border-destructive/20',
    joining: 'text-warning bg-warning/10 border-warning/20',
    leaving: 'text-muted-foreground bg-muted border-muted',
  };

  return (
    <div
      className={`border rounded-lg p-4 cursor-pointer transition-all hover:shadow-md ${
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
              <Badge variant={node.state === 'online' ? 'success' : node.state === 'offline' ? 'destructive' : 'secondary'} className="text-[10px]">
                {node.state}
              </Badge>
              {node.weight === 1 && <Badge variant="warning" className="text-[10px]">primary</Badge>}
            </div>
            <div className="text-xs text-muted-foreground mt-0.5">
              {node.addr}:{node.port} • v{node.version}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="icon" className="h-8 w-8" onClick={e => { e.stopPropagation(); onRemove(); }}>
            <Trash2 className="h-4 w-4 text-destructive" />
          </Button>
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
    </div>
  );
}
