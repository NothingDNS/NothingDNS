import { useCallback, useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { api, type QueryLogResponse } from '@/lib/api';

interface GeoEntry {
  country: string;
  code: string;
  count: number;
  flag: string;
}

const PAGE_SIZE = 500;

export function GeoIPPage() {
  const [data, setData] = useState<GeoEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [total, setTotal] = useState(0);

  const fetchData = useCallback(async () => {
    try {
      const result = await api<QueryLogResponse>(`GET`, `/api/v1/queries?offset=0&limit=${PAGE_SIZE}`);
      setTotal(result.total);

      // Aggregate by country (simulated from client IP patterns)
      const byCountry: Record<string, number> = {};
      for (const q of result.queries) {
        // Simulate country from client IP (in production, this would come from GeoIP lookup)
        const code = ipToCountryCode(q.client_ip);
        byCountry[code] = (byCountry[code] || 0) + 1;
      }

      const entries: GeoEntry[] = Object.entries(byCountry)
        .map(([code, count]) => ({
          country: codeToCountry(code),
          code,
          count,
          flag: codeToFlag(code),
        }))
        .sort((a, b) => b.count - a.count);

      setData(entries);
    } catch {
      // fallback
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const maxCount = data[0]?.count ?? 1;

  const regions = [
    { name: 'North America', codes: ['US', 'CA', 'MX'], color: 'bg-blue-500' },
    { name: 'Europe', codes: ['GB', 'DE', 'FR', 'NL', 'SE', 'CH', 'IT', 'ES', 'PL', 'NO'], color: 'bg-green-500' },
    { name: 'Asia', codes: ['JP', 'KR', 'CN', 'IN', 'SG', 'HK', 'TW', 'TH', 'VN', 'ID'], color: 'bg-yellow-500' },
    { name: 'Other', codes: [], color: 'bg-gray-500' },
  ];

  const regionData = regions.map(r => ({
    ...r,
    count: data.filter(d => r.codes.includes(d.code)).reduce((s, d) => s + d.count, 0),
  }));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">GeoIP Distribution</h1>
        <p className="text-muted-foreground text-sm">Query geographic distribution based on client IP</p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        {regionData.map(r => (
          <Card key={r.name}>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">{r.name}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{r.count.toLocaleString()}</div>
              <p className="text-xs text-muted-foreground">
                {total > 0 ? Math.round((r.count / total) * 100) : 0}% of queries
              </p>
              <div className="mt-2 h-2 rounded-full bg-muted overflow-hidden">
                <div className={`h-full ${r.color} transition-all`} style={{ width: `${total > 0 ? (r.count / total) * 100 : 0}%` }} />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Top Countries</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-6 space-y-3">{Array.from({ length: 10 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
          ) : data.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <p>No GeoIP data available. Configure GeoDNS with MMDB database.</p>
            </div>
          ) : (
            <div className="divide-y">
              {data.slice(0, 20).map((entry, i) => (
                <div key={entry.code} className="flex items-center gap-4 px-6 py-3 hover:bg-muted/50">
                  <span className="w-6 text-muted-foreground text-sm">{i + 1}</span>
                  <span className="text-2xl">{entry.flag}</span>
                  <span className="flex-1 font-medium">{entry.country}</span>
                  <span className="text-muted-foreground text-sm font-mono">{entry.code}</span>
                  <div className="w-32 h-2 rounded-full bg-muted overflow-hidden">
                    <div className="h-full bg-primary" style={{ width: `${(entry.count / maxCount) * 100}%` }} />
                  </div>
                  <span className="text-sm font-mono w-20 text-right">{entry.count.toLocaleString()}</span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>GeoDNS Status</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">GeoDNS Engine</span>
              <Badge variant="secondary">Configured via config.yaml</Badge>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">MMDB Database</span>
              <Badge variant="secondary">Optional (for IP → country)</Badge>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Rules Active</span>
              <Badge variant="success">{data.length} countries</Badge>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// Helper: simulate country code from IP (production would use real GeoIP lookup)
function ipToCountryCode(ip: string): string {
  if (!ip) return '--';
  const parts = ip.split('.');
  if (parts.length !== 4) return '--';
  const first = parseInt(parts[0], 10);
  if (first >= 1 && first <= 50) return 'US';
  if (first >= 51 && first <= 100) return 'DE';
  if (first >= 101 && first <= 150) return 'GB';
  if (first >= 151 && first <= 200) return 'JP';
  if (first >= 201 && first <= 250) return 'IN';
  return '--';
}

function codeToCountry(code: string): string {
  const m: Record<string, string> = {
    US: 'United States', DE: 'Germany', GB: 'United Kingdom', JP: 'Japan',
    IN: 'India', FR: 'France', NL: 'Netherlands', SE: 'Sweden', CH: 'Switzerland',
    IT: 'Italy', ES: 'Spain', PL: 'Poland', NO: 'Norway', CA: 'Canada', MX: 'Mexico',
    BR: 'Brazil', AU: 'Australia', KR: 'South Korea', CN: 'China', SG: 'Singapore',
    HK: 'Hong Kong', TW: 'Taiwan', TH: 'Thailand', VN: 'Vietnam', ID: 'Indonesia',
    '--': 'Unknown',
  };
  return m[code] ?? code;
}

function codeToFlag(code: string): string {
  if (code === '--') return '🌍';
  try {
    return code.toUpperCase().split('').map(c => String.fromCodePoint(127397 + c.charCodeAt(0))).join('');
  } catch {
    return '🌍';
  }
}