import { useEffect, useId, useState } from 'react';
import { Shield, Lock, Activity, Globe } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { toast } from 'sonner';
import { useUpdateRRLConfig } from '@/hooks/useApi';
import { type ServerConfig } from './types';
import { Card, CardContent, SectionHeader, ReadOnlyNotice, KVRow, SaveBar } from './shared';

// Parse numbers, falling back to `def` only when the input is not a number.
// A legitimate 0 must be preserved (a plain `parse(x) || def` coerces 0 → def).
const intOr = (x: string, def: number): number => {
  const n = parseInt(x, 10);
  return Number.isNaN(n) ? def : n;
};
const floatOr = (x: string, def: number): number => {
  const n = parseFloat(x);
  return Number.isNaN(n) ? def : n;
};

export function SecuritySettings({ config, onReload }: { config: ServerConfig; onReload: () => Promise<void> }) {
  const dnssec = config.DNSSEC;
  const acl = config.ACL;
  const rrl = config.RRL;
  const updateRRL = useUpdateRRLConfig();
  // useId gives a collision-safe prefix per component instance, so these ids
  // stay unique even if the panel is ever rendered twice.
  const fieldId = useId();
  const rrlEnabledId = `${fieldId}-rrl-enabled`;
  const rrlRateId = `${fieldId}-rrl-rate`;
  const rrlBurstId = `${fieldId}-rrl-burst`;
  const [rrlEnabled, setRrlEnabled] = useState(rrl?.Enabled ?? false);
  const [rrlRate, setRrlRate] = useState(String(rrl?.Rate ?? 5));
  const [rrlBurst, setRrlBurst] = useState(String(rrl?.Burst ?? 20));

  useEffect(() => {
    setRrlEnabled(rrl?.Enabled ?? false);
    setRrlRate(String(rrl?.Rate ?? 5));
    setRrlBurst(String(rrl?.Burst ?? 20));
  }, [rrl?.Enabled, rrl?.Rate, rrl?.Burst]);

  const resetRRLForm = () => {
    setRrlEnabled(rrl?.Enabled ?? false);
    setRrlRate(String(rrl?.Rate ?? 5));
    setRrlBurst(String(rrl?.Burst ?? 20));
  };

  const rrlDirty =
    rrlEnabled !== (rrl?.Enabled ?? false) ||
    rrlRate !== String(rrl?.Rate ?? 5) ||
    rrlBurst !== String(rrl?.Burst ?? 20);

  const handleSaveRRL = async () => {
    try {
      await updateRRL.mutateAsync({
        enabled: rrlEnabled,
        rate: floatOr(rrlRate, 5),
        burst: intOr(rrlBurst, 20),
      });
      await onReload();
      toast.success('RRL settings saved');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to save RRL settings');
    }
  };

  return (
    <div className="space-y-4">
      <ReadOnlyNotice title="File-backed security settings" />
      <Card>
        <SectionHeader title="DNSSEC" description="DNS Security Extensions" icon={<Shield className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Validation" value={dnssec?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Trust Anchor" value={dnssec?.TrustAnchor || 'builtin'} mono />
          <KVRow label="Require DNSSEC" value={dnssec?.RequireDNSSEC ? 'Yes' : 'No'} />
          <KVRow label="Ignore Time" value={dnssec?.IgnoreTime ? 'Yes' : 'No'} />
          <KVRow label="Zone Signing" value={dnssec?.Signing?.Enabled ? 'Enabled' : 'Disabled'} />
          {dnssec?.Signing?.Enabled && (
            <>
              <KVRow label="Signature Validity" value={dnssec.Signing.SignatureValidity || '-'} />
              <KVRow label="Keys" value={dnssec.Signing.Keys?.length || 0} />
              <KVRow label="NSEC3" value={dnssec.Signing.NSEC3 ? 'Enabled' : 'NSEC'} />
            </>
          )}
        </CardContent>
      </Card>
      <Card>
        <SectionHeader title="ACL Rules" description="Access control lists" icon={<Lock className="h-4 w-4" />} />
        <CardContent className="space-y-3">
          {acl?.length === 0 && <p className="text-sm text-muted-foreground">No ACL rules configured</p>}
          {acl?.map((rule, i) => (
            <div key={i} className="p-3 rounded-lg bg-muted/50 space-y-1">
              <div className="font-medium text-sm flex items-center gap-2">
                {rule.Name || `Rule ${i + 1}`}
                <Badge variant={rule.Action === 'allow' ? 'success' : rule.Action === 'deny' ? 'destructive' : 'outline'}>{rule.Action}</Badge>
              </div>
              <KVRow label="Networks" value={rule.Networks?.join(', ') || '-'} mono />
              <KVRow label="Types" value={rule.Types?.join(', ') || 'all'} />
            </div>
          ))}
        </CardContent>
      </Card>
      <Card>
        <SectionHeader title="Rate Limiting (RRL)" description="Response rate limiting" icon={<Activity className="h-4 w-4" />} badge="Live edit" />
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <Label htmlFor={rrlEnabledId}>Enabled</Label>
            <Switch id={rrlEnabledId} checked={rrlEnabled} onCheckedChange={setRrlEnabled} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor={rrlRateId}>Rate (resp/s)</Label>
              <Input id={rrlRateId} type="number" value={rrlRate} onChange={(e) => setRrlRate(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor={rrlBurstId}>Burst</Label>
              <Input id={rrlBurstId} type="number" value={rrlBurst} onChange={(e) => setRrlBurst(e.target.value)} />
            </div>
          </div>
          <SaveBar dirty={rrlDirty} saving={updateRRL.isPending} onSave={handleSaveRRL} onReset={resetRRLForm} />
        </CardContent>
      </Card>
      <Card>
        <SectionHeader title="IDNA" description="Internationalized Domain Names (RFC 5891)" icon={<Globe className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.IDNA?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="STD3 Rules" value={config.IDNA?.UseSTD3Rules ? 'Yes' : 'No'} />
          <KVRow label="Allow Unassigned" value={config.IDNA?.AllowUnassigned ? 'Yes' : 'No'} />
          <KVRow label="Check Bidi" value={config.IDNA?.CheckBidi ? 'Yes' : 'No'} />
          <KVRow label="Check Joiner" value={config.IDNA?.CheckJoiner ? 'Yes' : 'No'} />
        </CardContent>
      </Card>
    </div>
  );
}
