import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { api, type DNSSECStatus } from '@/lib/api';
import { Shield, Key, Clock, AlertTriangle, CheckCircle2, XCircle, Zap } from 'lucide-react';

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
        <p className="text-muted-foreground text-sm">DNS Security Extensions management and monitoring</p>
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
            <StatusItem
              icon={<Key className="h-5 w-5 text-primary" />}
              label="Key Status"
              value="Active"
              variant="default"
            />
            <StatusItem
              icon={<Clock className="h-5 w-5 text-muted-foreground" />}
              label="Last Rollover"
              value="N/A"
              variant="default"
            />
          </div>

          {!status?.enabled && (
            <div className="mt-6 p-4 border border-warning/50 bg-warning/10 rounded-lg">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-warning mt-0.5" />
                <div>
                  <h4 className="font-medium">DNSSEC is not enabled</h4>
                  <p className="text-sm text-muted-foreground mt-1">
                    Enable DNSSEC to protect your DNS queries from spoofing attacks.
                  </p>
                  <Button variant="outline" size="sm" className="mt-3">
                    Enable DNSSEC
                  </Button>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Key Management */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Key className="h-5 w-5" /> Key Management
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <KeyRow
              type="KSK (Key Signing Key)"
              keyTag="12345"
              algorithm="ECDSAP256SHA256"
              status="Active"
              created="2024-01-15"
              expires="2025-01-15"
            />
            <KeyRow
              type="ZSK (Zone Signing Key)"
              keyTag="67890"
              algorithm="ECDSAP256SHA256"
              status="Active"
              created="2024-03-01"
              expires="2024-09-01"
            />
          </div>

          <div className="mt-6 pt-6 border-t">
            <h4 className="text-sm font-medium mb-3">Key Rollover Information</h4>
            <div className="grid gap-4 md:grid-cols-3">
              <InfoCard label="Algorithm" value="ECDSAP256SHA256" />
              <InfoCard label="Key Size" value="256 bits" />
              <InfoCard label="TTL" value="3600s" />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* DS Records */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="h-5 w-5" /> DS Records (Parent)
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground mb-4">
            DS records are published by your parent zone to delegate DNSSEC validation.
          </p>
          <div className="space-y-2 font-mono text-sm">
            <div className="p-3 bg-muted rounded-lg">
              <span className="text-muted-foreground">example.com. IN DS 12345 13 2 ABCDEF123456...</span>
            </div>
          </div>
          <Button variant="outline" size="sm" className="mt-4">
            Copy DS Records
          </Button>
        </CardContent>
      </Card>

      {/* Validation Chain */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" /> Validation Chain
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <Badge variant="outline">Root</Badge>
            <span className="text-muted-foreground">→</span>
            <Badge variant="outline">.com</Badge>
            <span className="text-muted-foreground">→</span>
            <Badge variant="outline">example.com</Badge>
            <span className="text-muted-foreground">→</span>
            <Badge variant="success">Validated</Badge>
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

function KeyRow({ type, keyTag, algorithm, status, created, expires }: {
  type: string;
  keyTag: string;
  algorithm: string;
  status: string;
  created: string;
  expires: string;
}) {
  return (
    <div className="flex items-center justify-between p-4 border rounded-lg">
      <div className="flex items-center gap-4">
        <div className="p-2 rounded-lg bg-primary/10">
          <Key className="h-4 w-4 text-primary" />
        </div>
        <div>
          <div className="font-medium text-sm">{type}</div>
          <div className="text-xs text-muted-foreground mt-0.5">
            KeyTag: {keyTag} • {algorithm}
          </div>
        </div>
      </div>
      <div className="flex items-center gap-4">
        <div className="text-right">
          <div className="text-xs text-muted-foreground">Created</div>
          <div className="text-sm font-mono">{created}</div>
        </div>
        <div className="text-right">
          <div className="text-xs text-muted-foreground">Expires</div>
          <div className="text-sm font-mono">{expires}</div>
        </div>
        <Badge variant={status === 'Active' ? 'success' : 'secondary'}>{status}</Badge>
      </div>
    </div>
  );
}

function InfoCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="p-3 bg-muted rounded-lg">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-sm font-medium font-mono mt-0.5">{value}</div>
    </div>
  );
}
