import { useEffect, useId, useState } from 'react';
import { Globe, Activity, Network, FileText } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { toast } from 'sonner';
import { api } from '@/lib/api';
import { useUpdateResolutionConfig } from '@/hooks/useApi';
import { type ServerConfig } from './types';
import { Card, CardContent, SectionHeader, ReadOnlyNotice, KVRow, SaveBar } from './shared';

const intOr = (x: string, def: number): number => {
  const n = parseInt(x, 10);
  return Number.isNaN(n) ? def : n;
};

export function DNSSettings({ config, onReload }: { config: ServerConfig; onReload: () => Promise<void> }) {
  const resolution = config.Resolution;
  const updateResolution = useUpdateResolutionConfig();
  const fieldId = useId();

  const [recursive, setRecursive] = useState(resolution?.Recursive ?? false);
  const [authoritativeOnly, setAuthoritativeOnly] = useState(resolution?.AuthoritativeOnly ?? false);
  const [qnameMin, setQnameMin] = useState(resolution?.QnameMinimization ?? false);
  const [use0x20, setUse0x20] = useState(resolution?.Use0x20 ?? false);
  const [maxDepth, setMaxDepth] = useState(String(resolution?.MaxDepth ?? 10));
  const [timeout, setTimeoutVal] = useState(resolution?.Timeout || '5s');
  const [edns, setEdns] = useState(String(resolution?.EDNS0BufferSize ?? 4096));

  useEffect(() => {
    setRecursive(resolution?.Recursive ?? false);
    setAuthoritativeOnly(resolution?.AuthoritativeOnly ?? false);
    setQnameMin(resolution?.QnameMinimization ?? false);
    setUse0x20(resolution?.Use0x20 ?? false);
    setMaxDepth(String(resolution?.MaxDepth ?? 10));
    setTimeoutVal(resolution?.Timeout || '5s');
    setEdns(String(resolution?.EDNS0BufferSize ?? 4096));
  }, [resolution]);

  const reset = () => {
    setRecursive(resolution?.Recursive ?? false);
    setAuthoritativeOnly(resolution?.AuthoritativeOnly ?? false);
    setQnameMin(resolution?.QnameMinimization ?? false);
    setUse0x20(resolution?.Use0x20 ?? false);
    setMaxDepth(String(resolution?.MaxDepth ?? 10));
    setTimeoutVal(resolution?.Timeout || '5s');
    setEdns(String(resolution?.EDNS0BufferSize ?? 4096));
  };

  const dirty =
    recursive !== (resolution?.Recursive ?? false) ||
    authoritativeOnly !== (resolution?.AuthoritativeOnly ?? false) ||
    qnameMin !== (resolution?.QnameMinimization ?? false) ||
    use0x20 !== (resolution?.Use0x20 ?? false) ||
    maxDepth !== String(resolution?.MaxDepth ?? 10) ||
    timeout !== (resolution?.Timeout || '5s') ||
    edns !== String(resolution?.EDNS0BufferSize ?? 4096);

  const handleSave = async () => {
    try {
      await updateResolution.mutateAsync({
        recursive,
        authoritative_only: authoritativeOnly,
        qname_minimization: qnameMin,
        use_0x20: use0x20,
        max_depth: intOr(maxDepth, 10),
        timeout: timeout.trim() || '5s',
        edns0_buffer_size: intOr(edns, 4096),
      });
      // Resolver-construction fields take effect after reload; authoritative_only is immediate.
      await api('POST', '/api/v1/config/reload');
      await onReload();
      toast.success('Resolution settings saved and reloaded');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to save resolution settings');
    }
  };

  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader
          title="Resolution"
          description="authoritative_only applies immediately; other fields apply after reload (done automatically on save)"
          icon={<Globe className="h-4 w-4" />}
          badge="Live edit"
        />
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <Label htmlFor={`${fieldId}-recursive`}>Recursive</Label>
            <Switch id={`${fieldId}-recursive`} checked={recursive} onCheckedChange={setRecursive} />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor={`${fieldId}-auth-only`}>Authoritative only</Label>
            <Switch id={`${fieldId}-auth-only`} checked={authoritativeOnly} onCheckedChange={setAuthoritativeOnly} />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor={`${fieldId}-qname`}>QNAME minimization</Label>
            <Switch id={`${fieldId}-qname`} checked={qnameMin} onCheckedChange={setQnameMin} />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor={`${fieldId}-0x20`}>0x20 encoding</Label>
            <Switch id={`${fieldId}-0x20`} checked={use0x20} onCheckedChange={setUse0x20} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor={`${fieldId}-depth`}>Max depth</Label>
              <Input id={`${fieldId}-depth`} type="number" min="0" value={maxDepth} onChange={(e) => setMaxDepth(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${fieldId}-timeout`}>Timeout</Label>
              <Input id={`${fieldId}-timeout`} value={timeout} onChange={(e) => setTimeoutVal(e.target.value)} placeholder="5s" className="font-mono" />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${fieldId}-edns`}>EDNS0 buffer size</Label>
              <Input id={`${fieldId}-edns`} type="number" min="0" max="65535" value={edns} onChange={(e) => setEdns(e.target.value)} />
            </div>
          </div>
          <KVRow label="Root hints" value={resolution?.RootHints || '-'} mono />
          <p className="text-xs text-muted-foreground">Root hints path is file-backed (edit YAML and reload).</p>
          <SaveBar dirty={dirty} saving={updateResolution.isPending} onSave={handleSave} onReset={reset} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="Metrics" description="Prometheus metrics endpoint (restart to change bind)" icon={<Activity className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Status" value={config.Metrics?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Bind" value={config.Metrics?.Bind || '-'} mono />
          <KVRow label="Path" value={config.Metrics?.Path || '/metrics'} mono />
        </CardContent>
      </Card>

      {config.Views && config.Views.length > 0 && (
        <Card>
          <SectionHeader title="Split-Horizon Views" description="Client-based zone routing" icon={<Network className="h-4 w-4" />} />
          <CardContent className="space-y-3">
            {config.Views.map((view, i) => (
              <div key={i} className="p-3 rounded-lg bg-muted/50 space-y-1">
                <div className="font-medium text-sm">{view.Name}</div>
                <KVRow label="Match Clients" value={view.MatchClients?.join(', ') || '-'} mono />
                <KVRow label="Zone Files" value={view.ZoneFiles?.join(', ') || '-'} mono />
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {config.SlaveZones && config.SlaveZones.length > 0 && (
        <Card>
          <SectionHeader title="Slave Zones" description="Zone transfer from masters" icon={<FileText className="h-4 w-4" />} />
          <CardContent className="space-y-3">
            {config.SlaveZones.map((sz, i) => (
              <div key={i} className="p-3 rounded-lg bg-muted/50 space-y-1">
                <div className="font-medium text-sm">{sz.ZoneName}</div>
                <KVRow label="Masters" value={sz.Masters?.join(', ') || '-'} mono />
                <KVRow label="Transfer Type" value={sz.TransferType || 'ixfr'} />
                <KVRow label="TSIG" value={sz.TSIGKeyName ? 'Enabled' : 'Disabled'} />
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {(!config.Views || config.Views.length === 0) && (!config.SlaveZones || config.SlaveZones.length === 0) && (
        <ReadOnlyNotice title="Views and slave zones" />
      )}
    </div>
  );
}
