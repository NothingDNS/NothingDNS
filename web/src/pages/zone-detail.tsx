import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { api, downloadAuthenticated, type ZoneDetail, type DnsRecord } from '@/lib/api';
import { ZoneEditor } from '@/components/zone-editor';
import { ChevronRight, Download, Shield, Zap, Database, Clock, Globe } from 'lucide-react';

export function ZoneDetailPage() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const zn = decodeURIComponent(name || '');
  const [zone, setZone] = useState<ZoneDetail | null>(null);
  const [records, setRecords] = useState<DnsRecord[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [zd, rd] = await Promise.all([
        api<ZoneDetail>('GET', `/api/v1/zones/${encodeURIComponent(zn)}`),
        api<{ records: DnsRecord[] }>('GET', `/api/v1/zones/${encodeURIComponent(zn)}/records`),
      ]);
      setZone(zd);
      setRecords(rd.records || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [zn]);

  useEffect(() => {
    load();
  }, [load]);

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
          <button onClick={() => navigate('/zones')} className="hover:text-foreground transition-colors cursor-pointer">Zones</button>
          <ChevronRight className="h-3.5 w-3.5" />
          <span className="text-foreground font-medium">{zn}</span>
        </div>
        <Card><CardContent className="p-6"><Skeleton className="h-20 w-full" /></CardContent></Card>
        <Card><CardContent className="p-6"><Skeleton className="h-64 w-full" /></CardContent></Card>
      </div>
    );
  }

  const dnssecEnabled = zone?.nameservers && zone.nameservers.length > 0;

  return (
    <div className="space-y-6">
      {/* Breadcrumb */}
      <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
        <button onClick={() => navigate('/zones')} className="hover:text-foreground transition-colors cursor-pointer">Zones</button>
        <ChevronRight className="h-3.5 w-3.5" />
        <span className="text-foreground font-medium">{zn}</span>
      </div>

      {/* Zone Header */}
      <Card>
        <CardContent className="p-6">
          <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-3">
                <div className="p-2.5 rounded-lg bg-primary/10">
                  <Globe className="h-6 w-6 text-primary" />
                </div>
                <div>
                  <h1 className="text-2xl font-bold tracking-tight font-mono">{zn}</h1>
                  {zone?.soa && (
                    <p className="text-sm text-muted-foreground mt-0.5">
                      Primary: {zone.soa.mname} • Serial: {zone.soa.serial}
                    </p>
                  )}
                </div>
              </div>

              <div className="flex flex-wrap gap-3 mt-4">
                <StatBadge icon={<Database className="h-3.5 w-3.5" />} label={`${zone?.records || 0} records`} />
                {zone?.soa && (
                  <>
                    <StatBadge icon={<Clock className="h-3.5 w-3.5" />} label={`Refresh: ${zone.soa.refresh}s`} />
                    <StatBadge icon={<Zap className="h-3.5 w-3.5" />} label={`Retry: ${zone.soa.retry}s`} />
                  </>
                )}
                <StatBadge
                  icon={<Shield className="h-3.5 w-3.5" />}
                  label="DNSSEC"
                  variant={dnssecEnabled ? 'success' : 'secondary'}
                />
              </div>
            </div>

            <div className="flex flex-wrap gap-2">
              <Button variant="outline" size="sm" onClick={() => {
                downloadAuthenticated(
                  `/api/v1/zones/${encodeURIComponent(zn)}/export`,
                  `${zn}.zone`,
                ).catch((e) => console.error('zone export failed', e));
              }}>
                <Download className="h-4 w-4 mr-2" /> Export Zone
              </Button>
            </div>
          </div>

          {/* SOA Info */}
          {zone?.soa && (
            <div className="mt-4 pt-4 border-t">
              <h3 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">SOA Record</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <SoaField label="MName" value={zone.soa.mname} />
                <SoaField label="RName" value={zone.soa.rname} />
                <SoaField label="Serial" value={String(zone.soa.serial)} mono />
                <SoaField label="Minimum" value={String(zone.soa.minimum)} />
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Zone Editor */}
      <ZoneEditor
        zoneName={zn}
        initialRecords={records}
        onRefresh={load}
      />
    </div>
  );
}

function StatBadge({ icon, label, variant = 'default' }: {
  icon: React.ReactNode;
  label: string;
  variant?: 'default' | 'success' | 'secondary';
}) {
  const bgClass = variant === 'success' ? 'bg-success/10 text-success' :
                  variant === 'secondary' ? 'bg-muted text-muted-foreground' :
                  'bg-primary/10 text-primary';
  return (
    <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${bgClass}`}>
      {icon}
      {label}
    </div>
  );
}

function SoaField({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="space-y-1">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className={`text-sm font-medium block ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  );
}
