import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { api, type UpstreamsResponse } from '@/lib/api';
import { Wifi, WifiOff, Activity, RefreshCw } from 'lucide-react';

export function UpstreamsPage() {
  const [data, setData] = useState<UpstreamsResponse | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchUpstreams = () => {
    api<UpstreamsResponse>('GET', '/api/v1/upstreams')
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchUpstreams();
    const iv = setInterval(fetchUpstreams, 10000);
    return () => clearInterval(iv);
  }, []);

  if (loading) return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">Upstreams</h1><p className="text-muted-foreground text-sm">Upstream DNS server management</p></div>
      <div className="space-y-3">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-24 w-full" />)}</div>
    </div>
  );

  const upstreams = data?.upstreams ?? [];

  return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">Upstreams</h1><p className="text-muted-foreground text-sm">Upstream DNS server health and status</p></div>

      {upstreams.length === 0 ? (
        <Card><CardContent className="p-12 text-center text-muted-foreground">
          <WifiOff className="h-8 w-8 mx-auto mb-2 opacity-50" />
          <p>No upstream servers configured</p>
        </CardContent></Card>
      ) : (
        <div className="space-y-3">
          {upstreams.map((u) => (
            <Card key={u.address}>
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    {u.healthy ? (
                      <div className="p-2 rounded-lg bg-success/10"><Wifi className="h-5 w-5 text-success" /></div>
                    ) : (
                      <div className="p-2 rounded-lg bg-destructive/10"><WifiOff className="h-5 w-5 text-destructive" /></div>
                    )}
                    <div>
                      <p className="font-medium font-mono text-sm">{u.address}</p>
                      <div className="flex items-center gap-2 mt-1">
                        <Badge variant={u.healthy ? 'success' : 'destructive'}>{u.healthy ? 'Healthy' : 'Unhealthy'}</Badge>
                        {u.failovers > 0 && <Badge variant="warning"><RefreshCw className="h-3 w-3 mr-1" />{u.failovers} failovers</Badge>}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-6 text-right">
                    <div>
                      <p className="text-xs text-muted-foreground">Queries</p>
                      <p className="text-lg font-bold">{u.queries.toLocaleString()}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Failed</p>
                      <p className={`text-lg font-bold ${u.failed > 0 ? 'text-destructive' : ''}`}>{u.failed.toLocaleString()}</p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Activity className="h-4 w-4" /> Upstream Health
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {upstreams.map((u) => {
              const total = u.queries + u.failed;
              return (
                <div key={u.address} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono">{u.address}</span>
                    <span className={u.healthy ? 'text-success' : 'text-destructive'}>{u.healthy ? 'UP' : 'DOWN'}</span>
                  </div>
                  <div className="h-2 rounded-full bg-muted overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${u.healthy ? 'bg-success' : 'bg-destructive'}`}
                      style={{ width: `${total > 0 ? Math.max((u.queries / total) * 100, 1) : 100}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
