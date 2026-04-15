import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/api';

interface ZoneTransfer {
  zone: string;
  masters: string;
  serial: number;
  last_transfer: string;
  status: 'synced' | 'syncing' | 'failed' | 'pending';
  records: number;
}

interface SlaveZonesResponse {
  slave_zones: ZoneTransfer[];
}

export function ZoneTransferPage() {
  const [transfers, setTransfers] = useState<ZoneTransfer[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<SlaveZonesResponse>('GET', '/api/v1/zones/transfers')
      .then((res) => setTransfers(res.slave_zones || []))
      .catch(() => setError('Failed to load zone transfer status'))
      .finally(() => setIsLoading(false));
  }, []);

  const statusBadge = (s: ZoneTransfer['status']) => {
    switch (s) {
      case 'synced': return <Badge variant="success">Synced</Badge>;
      case 'syncing': return <Badge variant="warning">Syncing</Badge>;
      case 'failed': return <Badge variant="destructive">Failed</Badge>;
      case 'pending': return <Badge variant="secondary">Pending</Badge>;
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Zone Transfers</h1>
        <p className="text-muted-foreground text-sm">Slave zone synchronization status</p>
      </div>

      {isLoading ? (
        <Card>
          <CardHeader>
            <Skeleton className="h-6 w-32" />
          </CardHeader>
          <CardContent className="p-0">
            <div className="p-6 space-y-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-16 w-full" />
              ))}
            </div>
          </CardContent>
        </Card>
      ) : error ? (
        <p className="text-destructive">{error}</p>
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Slave Zones</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              {transfers.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <p>No slave zones configured</p>
                  <p className="text-sm mt-1">Add slave zones in config.yaml to track transfer status</p>
                </div>
              ) : (
                <div className="divide-y">
                  {transfers.map(t => (
                    <div key={t.zone} className="px-6 py-4">
                      <div className="flex items-center justify-between mb-3">
                        <div>
                          <h3 className="font-medium">{t.zone}</h3>
                          <p className="text-sm text-muted-foreground">Master: {t.masters}</p>
                        </div>
                        {statusBadge(t.status)}
                      </div>
                      <div className="grid grid-cols-4 gap-4 text-sm">
                        <div>
                          <p className="text-muted-foreground">Serial</p>
                          <p className="font-mono">{t.serial}</p>
                        </div>
                        <div>
                          <p className="text-muted-foreground">Last Transfer</p>
                          <p className="font-mono">{t.last_transfer ? new Date(t.last_transfer).toLocaleString() : 'Never'}</p>
                        </div>
                        <div>
                          <p className="text-muted-foreground">Records</p>
                          <p className="font-mono">{t.records}</p>
                        </div>
                        <div>
                          <p className="text-muted-foreground">Status</p>
                          <p className="capitalize">{t.status}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>AXFR/IXFR Status</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">AXFR Support</span>
                    <Badge variant="success">Enabled</Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">IXFR Support</span>
                    <Badge variant="success">Enabled</Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">NOTIFY Handling</span>
                    <Badge variant="success">Active</Badge>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Recent Transfers</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 text-sm">
                  {transfers.length === 0 ? (
                    <p className="text-muted-foreground">No recent transfers</p>
                  ) : (
                    transfers
                      .filter(t => t.last_transfer)
                      .sort((a, b) => new Date(b.last_transfer).getTime() - new Date(a.last_transfer).getTime())
                      .slice(0, 5)
                      .map(t => (
                        <div key={`recent-${t.zone}`} className="flex justify-between items-center">
                          <span className="font-medium">{t.zone}</span>
                          <span className="text-muted-foreground text-xs">
                            {new Date(t.last_transfer).toLocaleString()}
                          </span>
                        </div>
                      ))
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
