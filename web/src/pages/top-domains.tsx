import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { api, type TopDomainsResponse } from '@/lib/api';
import { TrendingUp } from 'lucide-react';

export function TopDomainsPage() {
  const [data, setData] = useState<TopDomainsResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api<TopDomainsResponse>('GET', '/api/v1/topdomains?limit=20')
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const domains = data?.domains ?? [];

  return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">Top Domains</h1><p className="text-muted-foreground text-sm">Most queried domains</p></div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <TrendingUp className="h-4 w-4" /> Domain Rankings
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="space-y-3">{Array.from({ length: 10 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
          ) : domains.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground"><p>No data available</p></div>
          ) : (
            <div className="space-y-2">
              {domains.map((d, i) => (
                <div key={d.domain} className="flex items-center gap-4 p-3 rounded-lg hover:bg-muted/50 transition-colors">
                  <span className="w-6 text-center font-bold text-muted-foreground text-sm">{i + 1}</span>
                  <div className="flex-1 min-w-0">
                    <p className="font-medium truncate">{d.domain}</p>
                  </div>
                  <Badge variant="outline">{d.count.toLocaleString()} queries</Badge>
                  <div className="w-24 h-2 rounded-full bg-muted overflow-hidden">
                    <div
                      className="h-full rounded-full bg-primary transition-all"
                      style={{ width: `${domains.length > 0 ? (d.count / domains[0].count) * 100 : 0}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
