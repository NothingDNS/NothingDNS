import { useEffect, useRef, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState } from '@/components/states';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { toast } from 'sonner';
import { api, type RPZStats, type RPZRule } from '@/lib/api';
import { Shield, Plus, RefreshCw, Wifi, WifiOff, Trash2, AlertTriangle } from 'lucide-react';

export function RPZPage() {
  const [stats, setStats] = useState<RPZStats | null>(null);
  const [rules, setRules] = useState<RPZRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [toggling, setToggling] = useState(false);
  const [adding, setAdding] = useState(false);
  const [newPattern, setNewPattern] = useState('');
  const [newAction, setNewAction] = useState('NXDOMAIN');
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  // Generation guard for fetchData(): the 10s polling interval and the
  // toggle/add/delete handlers can overlap an in-flight load, and an older
  // snapshot — or its late rejection — must not overwrite fresher state
  // (e.g. a just-added rule reverting out of the list).
  const fetchDataGeneration = useRef(0);

  const fetchData = () => {
    const gen = ++fetchDataGeneration.current;
    setLoading(true);
    Promise.all([
      api<RPZStats>('GET', '/api/v1/rpz'),
      api<{ rules: RPZRule[] }>('GET', '/api/v1/rpz/rules').then(r => r.rules).catch(() => []),
    ]).then(([s, r]) => {
      if (gen !== fetchDataGeneration.current) return; // superseded by a newer load
      setStats(s);
      setRules(r);
      setError('');
    }).catch((e: unknown) => {
      if (gen !== fetchDataGeneration.current) return; // superseded
      setError(e instanceof Error ? e.message : 'Failed to load RPZ data');
    }).finally(() => {
      if (gen === fetchDataGeneration.current) setLoading(false);
    });
  };

  useEffect(() => {
    fetchData();
    const iv = setInterval(fetchData, 10000);
    return () => clearInterval(iv);
  }, []);

  const handleToggle = async () => {
    setToggling(true);
    try {
      await api('POST', '/api/v1/rpz/toggle');
      toast.success(stats?.enabled ? 'RPZ disabled' : 'RPZ enabled');
      fetchData();
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : 'Failed to toggle RPZ'); }
    setToggling(false);
  };

  const handleAddRule = async () => {
    if (!newPattern.trim()) return;
    setAdding(true);
    try {
      await api('POST', '/api/v1/rpz/rules', { pattern: newPattern.trim(), action: newAction });
      toast.success('Rule added');
      setNewPattern('');
      fetchData();
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : 'Failed to add rule'); }
    setAdding(false);
  };

  const handleDeleteRule = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await api('DELETE', `/api/v1/rpz/rules?pattern=${encodeURIComponent(deleteTarget)}`);
      toast.success('Rule deleted');
      setDeleteTarget(null);
      fetchData();
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : 'Failed to delete rule'); }
    setDeleting(false);
  };

  if (loading) return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">RPZ</h1><p className="text-muted-foreground text-sm">Response Policy Zone configuration</p></div>
      <Skeleton className="h-48 w-full rounded-xl" />
    </div>
  );

  const actionColors: Record<string, string> = {
    NXDOMAIN: 'text-destructive bg-destructive/10',
    NODATA: 'text-warning bg-warning/10',
    CNAME: 'text-primary bg-primary/10',
    OVERRIDE: 'text-chart-2 bg-chart-2/10',
    DROP: 'text-muted-foreground bg-muted',
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div><h1 className="text-2xl font-bold tracking-tight">RPZ</h1><p className="text-muted-foreground text-sm">Response Policy Zone management</p></div>
        <div className="flex items-center gap-3">
          <Badge variant={stats?.enabled ? 'success' : 'secondary'} className="flex items-center gap-1">
            {stats?.enabled ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
            {stats?.enabled ? 'Enabled' : 'Disabled'}
          </Badge>
          <Button variant="outline" size="sm" onClick={handleToggle} disabled={toggling}>
            <RefreshCw className="h-4 w-4" /> {toggling ? 'Toggling...' : stats?.enabled ? 'Disable' : 'Enable'}
          </Button>
        </div>
      </div>

      {error ? <ErrorState message={error} onRetry={fetchData} /> : (
      <>
      <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
        <Card><CardContent className="p-6">
          <div className="text-2xl font-bold">{stats?.total_rules?.toLocaleString() ?? '-'}</div>
          <p className="text-xs text-muted-foreground mt-1">Total Rules</p>
        </CardContent></Card>
        <Card><CardContent className="p-6">
          <div className="text-2xl font-bold">{stats?.qname_rules ?? '-'}</div>
          <p className="text-xs text-muted-foreground mt-1">QNAME Rules</p>
        </CardContent></Card>
        <Card><CardContent className="p-6">
          <div className="text-2xl font-bold">{stats?.total_matches?.toLocaleString() ?? '-'}</div>
          <p className="text-xs text-muted-foreground mt-1">Total Matches</p>
        </CardContent></Card>
        <Card><CardContent className="p-6">
          <div className="text-2xl font-bold">{stats?.total_lookups?.toLocaleString() ?? '-'}</div>
          <p className="text-xs text-muted-foreground mt-1">Total Lookups</p>
        </CardContent></Card>
      </div>

      {!stats?.enabled && (
        <Card className="border-warning/50">
          <CardContent className="p-6">
            <div className="flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-warning mt-0.5" />
              <div>
                <h4 className="font-medium">RPZ is disabled</h4>
                <p className="text-sm text-muted-foreground mt-1">Enable RPZ to start blocking queries based on policy rules.</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Plus className="h-4 w-4" /> Add QNAME Rule
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-3">
            <Input
              placeholder="domain.example.com"
              value={newPattern}
              onChange={e => setNewPattern(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleAddRule()}
              className="flex-1"
            />
            <select
              aria-label="RPZ rule action"
              value={newAction}
              onChange={e => setNewAction(e.target.value)}
              className="h-10 px-3 rounded-md border border-input bg-background text-sm"
            >
              <option value="NXDOMAIN">NXDOMAIN</option>
              <option value="NODATA">NODATA</option>
              <option value="CNAME">CNAME</option>
              <option value="OVERRIDE">Override</option>
              <option value="DROP">Drop</option>
            </select>
            <Button onClick={handleAddRule} disabled={adding || !newPattern.trim()}>
              {adding ? 'Adding...' : 'Add Rule'}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">QNAME Rules ({rules.length})</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {rules.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <Shield className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No RPZ rules configured</p>
            </div>
          ) : (
            <div className="divide-y">
              {rules.map((rule) => (
                <div key={rule.pattern} className="flex items-center justify-between p-4 hover:bg-muted/50">
                  <div className="flex items-center gap-4">
                    <div className={`px-2 py-1 rounded text-xs font-medium ${actionColors[rule.action] || ''}`}>
                      {(rule.action || 'UNKNOWN').toUpperCase()}
                    </div>
                    <div>
                      <p className="font-mono text-sm">{rule.pattern}</p>
                      <p className="text-xs text-muted-foreground">Priority: {rule.priority} • Trigger: {rule.trigger}</p>
                    </div>
                  </div>
                  <Button variant="ghost" size="icon" aria-label={`Delete rule ${rule.pattern}`} onClick={() => setDeleteTarget(rule.pattern)}>
                    <Trash2 className="h-4 w-4 text-destructive" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
      </>
      )}

      <ConfirmDialog
        open={deleteTarget !== null}
        title="Delete RPZ rule"
        description={deleteTarget ? `Delete rule "${deleteTarget}"? This cannot be undone.` : ''}
        confirmLabel="Delete"
        destructive
        loading={deleting}
        onConfirm={handleDeleteRule}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  );
}