import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { api, type RPZStats, type RPZRule } from '@/lib/api';
import { Shield, Plus, RefreshCw, Wifi, WifiOff, Trash2, AlertTriangle } from 'lucide-react';

export function RPZPage() {
  const [stats, setStats] = useState<RPZStats | null>(null);
  const [rules, setRules] = useState<RPZRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [toggling, setToggling] = useState(false);
  const [adding, setAdding] = useState(false);
  const [newPattern, setNewPattern] = useState('');
  const [newAction, setNewAction] = useState('nxdomain');

  const fetchData = () => {
    Promise.all([
      api<RPZStats>('GET', '/api/v1/rpz'),
      api<{ rules: RPZRule[] }>('GET', '/api/v1/rpz/rules').then(r => r.rules).catch(() => []),
    ]).then(([s, r]) => {
      setStats(s);
      setRules(r);
    }).catch(console.error).finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchData();
    const iv = setInterval(fetchData, 10000);
    return () => clearInterval(iv);
  }, []);

  const handleToggle = async () => {
    setToggling(true);
    try { await api('POST', '/api/v1/rpz/toggle'); fetchData(); }
    catch (e) { console.error(e); }
    setToggling(false);
  };

  const handleAddRule = async () => {
    if (!newPattern.trim()) return;
    setAdding(true);
    try {
      await api('POST', '/api/v1/rpz/rules', { pattern: newPattern.trim(), action: newAction });
      setNewPattern('');
      fetchData();
    } catch (e) { console.error(e); }
    setAdding(false);
  };

  const handleDeleteRule = async (pattern: string) => {
    if (!confirm(`Delete rule "${pattern}"?`)) return;
    try { await api('DELETE', `/api/v1/rpz/rules?pattern=${encodeURIComponent(pattern)}`); fetchData(); }
    catch (e) { console.error(e); }
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
              value={newAction}
              onChange={e => setNewAction(e.target.value)}
              className="h-10 px-3 rounded-md border border-input bg-background text-sm"
            >
              <option value="nxdomain">NXDOMAIN</option>
              <option value="nodata">NODATA</option>
              <option value="cname">CNAME</option>
              <option value="override">Override</option>
              <option value="drop">Drop</option>
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
              {rules.map((rule, i) => (
                <div key={i} className="flex items-center justify-between p-4 hover:bg-muted/50">
                  <div className="flex items-center gap-4">
                    <div className={`px-2 py-1 rounded text-xs font-medium ${actionColors[rule.action] || ''}`}>
                      {rule.action.toUpperCase()}
                    </div>
                    <div>
                      <p className="font-mono text-sm">{rule.pattern}</p>
                      <p className="text-xs text-muted-foreground">Priority: {rule.priority} • Trigger: {rule.trigger}</p>
                    </div>
                  </div>
                  <Button variant="ghost" size="icon" onClick={() => handleDeleteRule(rule.pattern)}>
                    <Trash2 className="h-4 w-4 text-destructive" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}