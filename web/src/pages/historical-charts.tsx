import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { api, type MetricsHistory } from '@/lib/api';
import { Activity, Database, Zap } from 'lucide-react';

export function HistoricalChartsPage() {
  const [data, setData] = useState<MetricsHistory | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api<MetricsHistory>('GET', '/api/v1/metrics/history')
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));

    const iv = setInterval(() => {
      api<MetricsHistory>('GET', '/api/v1/metrics/history')
        .then(setData)
        .catch(() => {});
    }, 30000);
    return () => clearInterval(iv);
  }, []);

  if (loading) return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">Metrics History</h1><p className="text-muted-foreground text-sm">Time-series performance data</p></div>
      <div className="space-y-4">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-48 w-full" />)}</div>
    </div>
  );

  if (!data || data.count === 0) return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">Metrics History</h1><p className="text-muted-foreground text-sm">Time-series performance data</p></div>
      <Card><CardContent className="p-12 text-center text-muted-foreground">
        <Activity className="h-8 w-8 mx-auto mb-2 opacity-50" />
        <p>No historical data available yet</p>
        <p className="text-xs mt-1">Data is collected every minute</p>
      </CardContent></Card>
    </div>
  );

  const maxQueries = Math.max(...data.queries, 1);
  const maxHits = Math.max(...data.cache_hits, 1);
  const maxLatency = Math.max(...data.latency_ms, 1);

  return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">Metrics History</h1><p className="text-muted-foreground text-sm">Last {data.count} minutes of performance data</p></div>

      <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
        <Card><CardContent className="p-6">
          <div className="flex items-center gap-2 mb-1"><Activity className="h-4 w-4 text-primary" /><span className="text-xs text-muted-foreground">Total Points</span></div>
          <div className="text-2xl font-bold">{data.count}</div>
        </CardContent></Card>
        <Card><CardContent className="p-6">
          <div className="flex items-center gap-2 mb-1"><Activity className="h-4 w-4 text-success" /><span className="text-xs text-muted-foreground">Peak Q/min</span></div>
          <div className="text-2xl font-bold">{maxQueries.toLocaleString()}</div>
        </CardContent></Card>
        <Card><CardContent className="p-6">
          <div className="flex items-center gap-2 mb-1"><Database className="h-4 w-4 text-chart-2" /><span className="text-xs text-muted-foreground">Peak Cache Hits</span></div>
          <div className="text-2xl font-bold">{Math.max(...data.cache_hits).toLocaleString()}</div>
        </CardContent></Card>
        <Card><CardContent className="p-6">
          <div className="flex items-center gap-2 mb-1"><Zap className="h-4 w-4 text-warning" /><span className="text-xs text-muted-foreground">Max Latency</span></div>
          <div className="text-2xl font-bold">{maxLatency}ms</div>
        </CardContent></Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Activity className="h-4 w-4" /> Queries per Minute
          </CardTitle>
        </CardHeader>
        <CardContent>
          <BarChart data={data.queries} max={maxQueries} color="bg-primary" timestamps={data.timestamps} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Database className="h-4 w-4" /> Cache Hits vs Misses
          </CardTitle>
        </CardHeader>
        <CardContent>
          <BarChart data={data.cache_hits} max={maxHits} color="bg-success" timestamps={data.timestamps} />
          <BarChart data={data.cache_misses} max={maxHits} color="bg-muted" timestamps={data.timestamps} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Zap className="h-4 w-4" /> Upstream Latency (ms)
          </CardTitle>
        </CardHeader>
        <CardContent>
          <BarChart data={data.latency_ms} max={maxLatency} color="bg-warning" timestamps={data.timestamps} />
        </CardContent>
      </Card>
    </div>
  );
}

function BarChart({ data, max, color, timestamps }: { data: number[]; max: number; color: string; timestamps?: number[] }) {
  return (
    <div className="flex items-end gap-0.5 h-24">
      {data.map((v, i) => (
        <div key={i} className="flex-1 flex flex-col justify-end items-center group relative">
          <div
            className={`w-full rounded-sm ${color} transition-all hover:opacity-80`}
            style={{ height: `${Math.max((v / max) * 100, 2)}%` }}
          />
          <div className="absolute bottom-full mb-1 hidden group-hover:block bg-background border rounded px-1 text-[10px] whitespace-nowrap z-10">
            {v.toLocaleString()}{timestamps ? ` @ ${new Date(timestamps[i] * 1000).toLocaleTimeString()}` : ''}
          </div>
        </div>
      ))}
    </div>
  );
}
