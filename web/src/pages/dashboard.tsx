import { useEffect, useState, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Button } from '@/components/ui/button';
import { api, type DashboardStats, type QueryEvent } from '@/lib/api';
import { useWebSocket } from '@/hooks/useWebSocket';
import { Activity, Database, Shield, Clock, RefreshCw, Globe, Zap, Server, TrendingUp, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

export function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [queries, setQueries] = useState<QueryEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const streamRef = useRef<HTMLDivElement>(null);

  const { connected } = useWebSocket('/ws', {
    onQuery: (event) => setQueries((p) => [event, ...p].slice(0, 100)),
  });

  const loadStats = async () => {
    try {
      const data = await api<DashboardStats>('GET', '/api/dashboard/stats');
      setStats(data);
      setLastUpdate(new Date());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load stats');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStats();
    const iv = setInterval(loadStats, 5000);
    return () => clearInterval(iv);
  }, []);

  const cards = [
    { t: 'Total Queries', v: stats?.queriesTotal?.toLocaleString() ?? '-', s: `${(stats?.queriesPerSec ?? 0).toFixed(1)} q/s`, i: Activity, c: 'text-primary', b: 'bg-primary/10' },
    { t: 'Cache Hit Rate', v: `${(stats?.cacheHitRate ?? 0).toFixed(1)}%`, s: 'Efficiency', i: Database, c: 'text-success', b: 'bg-success/10' },
    { t: 'Blocked', v: stats?.blockedQueries?.toLocaleString() ?? '-', s: 'Ad / malware', i: Shield, c: 'text-destructive', b: 'bg-destructive/10' },
    { t: 'Zones', v: String(stats?.zoneCount ?? '-'), s: 'Active', i: Globe, c: 'text-warning', b: 'bg-warning/10' },
    { t: 'Avg Latency', v: `${stats?.upstreamLatency ?? 0}ms`, s: 'Upstream', i: Zap, c: 'text-chart-5', b: 'bg-chart-5/10' },
    { t: 'Uptime', v: fmtUptime(stats?.uptime ?? 0), s: 'Since start', i: Clock, c: 'text-chart-1', b: 'bg-chart-1/10' },
    { t: 'Clients', v: String(stats?.activeClients ?? '-'), s: 'Connected', i: Server, c: 'text-chart-2', b: 'bg-chart-2/10' },
    { t: 'Live Feed', v: connected ? 'Connected' : 'Offline', s: 'WebSocket', i: TrendingUp, c: connected ? 'text-success' : 'text-muted-foreground', b: connected ? 'bg-success/10' : 'bg-muted' },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div><h1 className="text-2xl font-bold tracking-tight">Dashboard</h1><p className="text-muted-foreground text-sm">Real-time DNS server monitoring</p></div>
        <div className="flex items-center gap-2">
          {lastUpdate && <span className="text-xs text-muted-foreground">Updated {lastUpdate.toLocaleTimeString()}</span>}
          <Button variant="outline" size="sm" onClick={loadStats}><RefreshCw className="h-4 w-4" /></Button>
        </div>
      </div>

      {error && (
        <Card className="border-destructive/50">
          <CardContent className="p-4 flex items-center gap-3">
            <AlertCircle className="h-5 w-5 text-destructive" />
            <div className="text-sm text-destructive">{error}</div>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
        {loading ? Array.from({ length: 8 }).map((_, i) => <Card key={i}><CardContent className="p-6"><Skeleton className="h-4 w-20 mb-3" /><Skeleton className="h-8 w-16 mb-1" /><Skeleton className="h-3 w-12" /></CardContent></Card>)
        : cards.map(({ t, v, s, i: I, c, b }) => (
          <Card key={t}><CardContent className="p-6">
            <div className="flex items-center justify-between mb-3"><span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{t}</span><div className={cn('p-1.5 rounded-lg', b)}><I className={cn('h-4 w-4', c)} /></div></div>
            <div className="text-2xl font-bold">{v}</div><p className="text-xs text-muted-foreground mt-0.5">{s}</p>
          </CardContent></Card>
        ))}
      </div>
      <Card>
        <CardHeader className="pb-3"><div className="flex items-center justify-between"><CardTitle className="text-base">Live Query Stream</CardTitle><Badge variant={connected ? 'success' : 'secondary'}>{connected ? 'Live' : 'Polling'}</Badge></div></CardHeader>
        <CardContent><div ref={streamRef} className="space-y-1 max-h-[400px] overflow-y-auto font-mono text-xs">
          {queries.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground"><Activity className="h-8 w-8 mx-auto mb-2 opacity-50" /><p>Waiting for DNS queries...</p><p className="text-[11px] mt-1">Queries will appear here in real-time</p></div>
          ) : queries.map((q) => (
            <div key={`${q.domain}-${q.timestamp}`} className="flex items-center gap-3 py-1.5 px-2 rounded-md hover:bg-muted/50 transition-colors">
              <span className="text-muted-foreground w-[70px] shrink-0">{new Date(q.timestamp).toLocaleTimeString()}</span>
              <Badge variant={q.responseCode === 'NOERROR' ? 'success' : q.blocked ? 'destructive' : 'warning'} className="w-[60px] justify-center text-[10px]">{q.responseCode}</Badge>
              <span className="text-muted-foreground w-[40px]">{q.queryType}</span>
              <span className="font-medium truncate flex-1">{q.domain}</span>
              <span className="text-muted-foreground hidden sm:inline">{q.clientIp}</span>
              <span className="text-muted-foreground w-[50px] text-right">{q.duration}ms</span>
              {q.cached && <Badge variant="secondary" className="text-[10px]">cached</Badge>}
              {q.blocked && <Badge variant="destructive" className="text-[10px]">blocked</Badge>}
            </div>
          ))}
        </div></CardContent>
      </Card>
    </div>
  );
}

function fmtUptime(s: number): string {
  if (s <= 0) return '0m';
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`; if (h > 0) return `${h}h ${m}m`; return `${m}m`;
}
