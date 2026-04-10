import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

interface ZoneTransfer {
  zone: string;
  master: string;
  serial: number;
  lastTransfer: string;
  status: 'synced' | 'syncing' | 'failed' | 'pending';
  records: number;
}

export function ZoneTransferPage() {
  const [transfers, setTransfers] = useState<ZoneTransfer[]>([]);

  useEffect(() => {
    // Simulated data — in production this comes from API
    setTransfers([
      { zone: 'example.com', master: '192.0.2.1', serial: 2024041001, lastTransfer: new Date(Date.now() - 3600000).toISOString(), status: 'synced', records: 42 },
      { zone: 'test.net', master: '192.0.2.2', serial: 2024040901, lastTransfer: new Date(Date.now() - 86400000).toISOString(), status: 'synced', records: 15 },
    ]);
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
                      <p className="text-sm text-muted-foreground">Master: {t.master}</p>
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
                      <p className="font-mono">{new Date(t.lastTransfer).toLocaleString()}</p>
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
                <span className="text-muted-foreground">TSIG Auth</span>
                <Badge variant="success">Required</Badge>
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
                transfers.slice(0, 3).map(t => (
                  <div key={t.zone} className="flex justify-between items-center">
                    <span className="font-medium">{t.zone}</span>
                    <span className="text-muted-foreground text-xs">
                      {new Date(t.lastTransfer).toLocaleString()}
                    </span>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}