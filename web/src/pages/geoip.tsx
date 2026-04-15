import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/api';

interface GeoDNSStats {
  enabled: boolean;
  rules: number;
  mmdb_loaded: boolean;
  lookups: number;
  hits: number;
  misses: number;
}

export function GeoIPPage() {
  const [stats, setStats] = useState<GeoDNSStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<GeoDNSStats>('GET', '/api/v1/geoip/stats')
      .then(setStats)
      .catch(() => setError('Failed to load GeoDNS statistics'))
      .finally(() => setIsLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">GeoIP Distribution</h1>
        <p className="text-muted-foreground text-sm">GeoDNS engine status and query metrics</p>
      </div>

      {isLoading ? (
        <div className="grid gap-4 md:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <Skeleton className="h-4 w-24" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-8 w-16" />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : error ? (
        <p className="text-destructive">{error}</p>
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">GeoDNS Engine</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {stats?.enabled ? (
                    <Badge variant="success">Enabled</Badge>
                  ) : (
                    <Badge variant="secondary">Disabled</Badge>
                  )}
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  {stats?.mmdb_loaded ? 'MMDB loaded' : 'No MMDB database'}
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Geo Rules</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{stats?.rules ?? 0}</div>
                <p className="text-xs text-muted-foreground mt-1">Configured rules</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Total Lookups</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{(stats?.lookups ?? 0).toLocaleString()}</div>
                <p className="text-xs text-muted-foreground mt-1">
                  {stats && stats.lookups > 0
                    ? `${Math.round((stats.hits / stats.lookups) * 100)}% hit rate`
                    : 'No lookups yet'}
                </p>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>GeoDNS Metrics</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-3">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Hits</p>
                  <p className="text-xl font-mono">{(stats?.hits ?? 0).toLocaleString()}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Misses</p>
                  <p className="text-xl font-mono">{(stats?.misses ?? 0).toLocaleString()}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Hit Rate</p>
                  <p className="text-xl font-mono">
                    {stats && stats.lookups > 0
                      ? `${((stats.hits / stats.lookups) * 100).toFixed(1)}%`
                      : '0.0%'}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </>
      )}

      <Card>
        <CardHeader>
          <CardTitle>GeoDNS Status</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">GeoDNS Engine</span>
              <Badge variant={stats?.enabled ? 'success' : 'secondary'}>
                {stats?.enabled ? 'Enabled' : 'Disabled'}
              </Badge>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">MMDB Database</span>
              <Badge variant={stats?.mmdb_loaded ? 'success' : 'secondary'}>
                {stats?.mmdb_loaded ? 'Loaded' : 'Not loaded'}
              </Badge>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Rules Active</span>
              <Badge variant="success">{stats?.rules ?? 0} rules</Badge>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
