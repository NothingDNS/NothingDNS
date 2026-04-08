import { useCallback, useEffect, useRef, useState } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Input } from '@/components/ui/input';
import { api, type QueryLogResponse } from '@/lib/api';
import { ChevronLeft, ChevronRight } from 'lucide-react';

const PAGE_SIZE = 50;

export function QueryLogPage() {
  const [data, setData] = useState<QueryLogResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [offset, setOffset] = useState(0);
  const [filter, setFilter] = useState('');
  const loadTriggerRef = useRef({ offset, shouldLoad: true });

  const fetchData = useCallback(async (currentOffset: number) => {
    const result = await api<QueryLogResponse>('GET', `/api/v1/queries?offset=${currentOffset}&limit=${PAGE_SIZE}`);
    return result;
  }, []);

  // Track offset changes and trigger load via ref
  useEffect(() => {
    loadTriggerRef.current = { offset, shouldLoad: true };
  }, [offset]);

  // Handle loading data when trigger changes
  useEffect(() => {
    if (!loadTriggerRef.current.shouldLoad) return;

    loadTriggerRef.current.shouldLoad = false;
    const currentOffset = loadTriggerRef.current.offset;

    // Use requestAnimationFrame to defer state update
    const rafId = requestAnimationFrame(() => {
      setIsLoading(true);
    });

    fetchData(currentOffset)
      .then(result => {
        setData(result);
        setIsLoading(false);
      })
      .catch(() => {
        setIsLoading(false);
      });

    return () => cancelAnimationFrame(rafId);
  }, [fetchData, offset]);

  const total = data?.total ?? 0;
  const queries = data?.queries ?? [];
  const filtered = filter
    ? queries.filter(q => q.domain.toLowerCase().includes(filter.toLowerCase()))
    : queries;

  const pages = Math.ceil(total / PAGE_SIZE);
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">Query Log</h1><p className="text-muted-foreground text-sm">Historical DNS query log</p></div>

      <div className="flex items-center gap-3">
        <Input
          placeholder="Filter by domain..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
          className="max-w-sm"
        />
        <Badge variant="secondary">{total} total</Badge>
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-6 space-y-3">{Array.from({ length: 10 }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}</div>
          ) : filtered.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground"><p>No queries found</p></div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b bg-muted/50">
                  <tr>
                    <th className="text-left p-3 font-medium">Time</th>
                    <th className="text-left p-3 font-medium">Domain</th>
                    <th className="text-left p-3 font-medium">Type</th>
                    <th className="text-left p-3 font-medium">Status</th>
                    <th className="text-left p-3 font-medium">Duration</th>
                    <th className="text-left p-3 font-medium">Client</th>
                    <th className="text-left p-3 font-medium">Flags</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((q, i) => (
                    <tr key={i} className="border-b hover:bg-muted/50 transition-colors">
                      <td className="p-3 font-mono text-xs">{new Date(q.timestamp).toLocaleTimeString()}</td>
                      <td className="p-3 font-medium truncate max-w-[200px]">{q.domain}</td>
                      <td className="p-3"><Badge variant="outline">{q.query_type}</Badge></td>
                      <td className="p-3"><Badge variant={q.response_code === 'NOERROR' ? 'success' : 'warning'}>{q.response_code}</Badge></td>
                      <td className="p-3 text-muted-foreground">{q.duration_ms}ms</td>
                      <td className="p-3 text-muted-foreground font-mono text-xs">{q.client_ip}</td>
                      <td className="p-3">{q.cached && <Badge variant="secondary" className="mr-1">cached</Badge>}{q.blocked && <Badge variant="destructive">blocked</Badge>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {pages > 1 && (
        <div className="flex items-center justify-center gap-4">
          <button onClick={() => setOffset(o => Math.max(0, o - PAGE_SIZE))} disabled={offset === 0} className="p-2 rounded-lg border hover:bg-muted disabled:opacity-50">
            <ChevronLeft className="h-4 w-4" />
          </button>
          <span className="text-sm">Page {currentPage} of {pages}</span>
          <button onClick={() => setOffset(o => o + PAGE_SIZE)} disabled={offset + PAGE_SIZE >= total} className="p-2 rounded-lg border hover:bg-muted disabled:opacity-50">
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      )}
    </div>
  );
}
