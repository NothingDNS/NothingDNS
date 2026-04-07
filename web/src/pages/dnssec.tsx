import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { api, type DNSSECStatus } from '@/lib/api';
import { Shield, AlertTriangle, CheckCircle2, XCircle, Info } from 'lucide-react';

export function DNSSECPage() {
  const [status, setStatus] = useState<DNSSECStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api<DNSSECStatus>('GET', '/api/v1/dnssec/status')
      .then(setStatus)
      .catch(console.error)
      .finally(() => setLoading(false));

    const interval = setInterval(() => {
      api<DNSSECStatus>('GET', '/api/v1/dnssec/status')
        .then(setStatus)
        .catch(() => {});
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="space-y-6">
        <div><h1 className="text-2xl font-bold tracking-tight">DNSSEC</h1><p className="text-muted-foreground text-sm">DNS Security Extensions management</p></div>
        <div className="space-y-4"><Skeleton className="h-48 w-full rounded-xl" /><Skeleton className="h-48 w-full rounded-xl" /></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">DNSSEC</h1>
        <p className="text-muted-foreground text-sm">DNS Security Extensions status and configuration</p>
      </div>

      {/* Status Overview */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" /> Security Status
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
            <StatusItem
              icon={status?.enabled ? <CheckCircle2 className="h-5 w-5 text-success" /> : <XCircle className="h-5 w-5 text-destructive" />}
              label="DNSSEC Status"
              value={status?.enabled ? 'Enabled' : 'Disabled'}
              variant={status?.enabled ? 'success' : 'destructive'}
            />
            <StatusItem
              icon={status?.require_dnssec ? <Shield className="h-5 w-5 text-warning" /> : <Shield className="h-5 w-5 text-muted-foreground" />}
              label="Validation"
              value={status?.require_dnssec ? 'Required' : 'Optional'}
              variant={status?.require_dnssec ? 'warning' : 'default'}
            />
          </div>

          {!status?.enabled && (
            <div className="mt-6 p-4 border border-warning/50 bg-warning/10 rounded-lg">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-warning mt-0.5" />
                <div>
                  <h4 className="font-medium">DNSSEC is not enabled</h4>
                  <p className="text-sm text-muted-foreground mt-1">
                    Enable DNSSEC in your configuration file and reload the server to protect your DNS queries from spoofing attacks.
                  </p>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Info Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Info className="h-4 w-4" /> DNSSEC Configuration
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4 text-sm text-muted-foreground">
            <p>DNSSEC provides cryptographic authentication for DNS responses. To enable DNSSEC:</p>
            <ol className="list-decimal list-inside space-y-2 ml-4">
              <li>Configure DNSSEC settings in your server configuration file</li>
              <li>Sign your zones with KSK (Key Signing Key) and ZSK (Zone Signing Key)</li>
              <li>Publish DS records at your parent zone for delegation</li>
              <li>Use "Reload Config" in Settings to apply changes</li>
            </ol>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function StatusItem({ icon, label, value, variant = 'default' }: {
  icon: React.ReactNode;
  label: string;
  value: string;
  variant?: 'default' | 'success' | 'warning' | 'destructive';
}) {
  const valueColor = variant === 'success' ? 'text-success' :
                     variant === 'warning' ? 'text-warning' :
                     variant === 'destructive' ? 'text-destructive' :
                     'text-foreground';
  return (
    <div className="p-4 rounded-lg border">
      <div className="flex items-center gap-2 mb-2">
        {icon}
        <span className="text-sm text-muted-foreground">{label}</span>
      </div>
      <div className={`text-xl font-bold ${valueColor}`}>{value}</div>
    </div>
  );
}
