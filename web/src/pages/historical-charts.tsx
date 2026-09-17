import { useEffect, useMemo, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { api, type MetricsHistory } from '@/lib/api';
import { ErrorState } from '@/components/states';
import { Activity, Database, Zap } from 'lucide-react';

/** API returns newest-first cumulative counters; charts want oldest→newest per-interval deltas. */
export function toPerIntervalSeries(values: number[], timestamps: number[]): { values: number[]; timestamps: number[] } {
  const chronValues = [...values].reverse();
  const chronTs = [...timestamps].reverse();
  if (chronValues.length < 2) {
    return { values: [], timestamps: [] };
  }
  const outValues: number[] = [];
  const outTs: number[] = [];
  for (let i = 1; i < chronValues.length; i++) {
    outValues.push(Math.max(0, chronValues[i] - chronValues[i - 1]));
    outTs.push(chronTs[i] ?? chronTs[i - 1] ?? 0);
  }
  return { values: outValues, timestamps: outTs };
}

/** Latency samples are gauges (not counters): reverse to chronological order only. */
export function toChronological(values: number[], timestamps: number[]): { values: number[]; timestamps: number[] } {
  return {
    values: [...values].reverse(),
    timestamps: [...timestamps].reverse(),
  };
}

export function HistoricalChartsPage() {
  const [data, setData] = useState<MetricsHistory | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    api<MetricsHistory>('GET', '/api/v1/metrics/history')
      .then((d) => { setData(d); setError(null); })
      .catch((e) => setError(e instanceof Error ? e.message : 'Failed to load metrics history'))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();

    const iv = setInterval(() => {
      api<MetricsHistory>('GET', '/api/v1/metrics/history')
        .then((d) => { setData(d); setError(null); })
        .catch(() => {});
    }, 30000);
    return () => clearInterval(iv);
  }, []);

  const series = useMemo(() => {
    if (!data || data.count === 0) return null;
    const ts = data.timestamps ?? [];
    const queries = toPerIntervalSeries(data.queries ?? [], ts);
    const hits = toPerIntervalSeries(data.cache_hits ?? [], ts);
    const misses = toPerIntervalSeries(data.cache_misses ?? [], ts);
    const latency = toChronological(data.latency_ms ?? [], ts);
    return { queries, hits, misses, latency, sampleCount: data.count };
  }, [data]);

  if (loading) return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">Metrics History</h1><p className="text-muted-foreground text-sm">Time-series performance data</p></div>
      <div className="space-y-4">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-48 w-full" />)}</div>
    </div>
  );

  if (error) return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">Metrics History</h1><p className="text-muted-foreground text-sm">Time-series performance data</p></div>
      <ErrorState message={error} onRetry={load} />
    </div>
  );

  if (!series || series.sampleCount === 0) return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">Metrics History</h1><p className="text-muted-foreground text-sm">Time-series performance data</p></div>
      <Card><CardContent className="p-12 text-center text-muted-foreground">
        <Activity className="h-8 w-8 mx-auto mb-2 opacity-50" />
        <p>No historical data available yet</p>
        <p className="text-xs mt-1">Data is collected every minute</p>
      </CardContent></Card>
    </div>
  );

  if (series.sampleCount < 2) return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">Metrics History</h1><p className="text-muted-foreground text-sm">Time-series performance data</p></div>
      <Card><CardContent className="p-12 text-center text-muted-foreground">
        <Activity className="h-8 w-8 mx-auto mb-2 opacity-50" />
        <p>Collecting the first samples…</p>
        <p className="text-xs mt-1">Per-minute charts need at least two snapshots (about two minutes after start)</p>
      </CardContent></Card>
    </div>
  );

  const maxQueries = Math.max(0, ...series.queries.values, 1);
  const maxCache = Math.max(0, ...series.hits.values, ...series.misses.values, 1);
  const maxLatency = Math.max(0, ...series.latency.values, 1);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Metrics History</h1>
        <p className="text-muted-foreground text-sm">
          Last {series.sampleCount} minutes · {series.queries.values.length} interval{series.queries.values.length === 1 ? '' : 's'}
        </p>
      </div>

      <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
        <Card><CardContent className="p-6">
          <div className="flex items-center gap-2 mb-1"><Activity className="h-4 w-4 text-primary" /><span className="text-xs text-muted-foreground">Intervals</span></div>
          <div className="text-2xl font-bold">{series.queries.values.length}</div>
        </CardContent></Card>
        <Card><CardContent className="p-6">
          <div className="flex items-center gap-2 mb-1"><Activity className="h-4 w-4 text-success" /><span className="text-xs text-muted-foreground">Peak Q/min</span></div>
          <div className="text-2xl font-bold">{maxQueries.toLocaleString()}</div>
        </CardContent></Card>
        <Card><CardContent className="p-6">
          <div className="flex items-center gap-2 mb-1"><Database className="h-4 w-4 text-chart-2" /><span className="text-xs text-muted-foreground">Peak Cache Hits/min</span></div>
          <div className="text-2xl font-bold">{Math.max(0, ...series.hits.values, 0).toLocaleString()}</div>
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
          <BarChart data={series.queries.values} max={maxQueries} color="bg-primary" timestamps={series.queries.timestamps} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Database className="h-4 w-4" /> Cache Hits vs Misses (per minute)
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm bg-success" /> Hits</span>
            <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm bg-warning" /> Misses</span>
          </div>
          <BarChart data={series.hits.values} max={maxCache} color="bg-success" timestamps={series.hits.timestamps} />
          <BarChart data={series.misses.values} max={maxCache} color="bg-warning" timestamps={series.misses.timestamps} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Zap className="h-4 w-4" /> Upstream Latency (ms)
          </CardTitle>
        </CardHeader>
        <CardContent>
          <BarChart data={series.latency.values} max={maxLatency} color="bg-chart-2" timestamps={series.latency.timestamps} unit="ms" />
        </CardContent>
      </Card>
    </div>
  );
}

function BarChart({
  data,
  max,
  color,
  timestamps,
  unit = '',
}: {
  data: number[];
  max: number;
  color: string;
  timestamps?: number[];
  unit?: string;
}) {
  if (data.length === 0) {
    return <p className="text-sm text-muted-foreground py-8 text-center">No interval data yet</p>;
  }

  return (
    <div className="flex items-end gap-0.5 h-32 w-full" role="img" aria-label="Bar chart">
      {data.map((v, i) => {
        const pct = max > 0 ? (v / max) * 100 : 0;
        const heightPct = v > 0 ? Math.max(pct, 3) : 0;
        return (
          <div key={i} className="flex-1 h-full min-w-0 flex flex-col justify-end items-center group relative">
            <div
              className={`w-full min-h-0 rounded-sm ${color} transition-opacity hover:opacity-80`}
              style={{ height: `${heightPct}%` }}
            />
            <div className="pointer-events-none absolute bottom-full mb-1 hidden group-hover:block bg-popover text-popover-foreground border rounded px-1.5 py-0.5 text-[10px] whitespace-nowrap z-10 shadow-sm">
              {v.toLocaleString()}{unit}
              {timestamps && timestamps[i] != null ? ` · ${new Date(timestamps[i] * 1000).toLocaleTimeString()}` : ''}
            </div>
          </div>
        );
      })}
    </div>
  );
}
