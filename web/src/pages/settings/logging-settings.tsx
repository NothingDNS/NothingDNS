import { useEffect, useId, useState } from 'react';
import { FileText, Shield, Activity } from 'lucide-react';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { toast } from 'sonner';
import { useUpdateCookieConfig, useUpdateLoggingConfig } from '@/hooks/useApi';
import { type ServerConfig } from './types';
import { Card, CardContent, SectionHeader, KVRow, SaveBar } from './shared';

export function LoggingSettings({ config, onReload }: { config: ServerConfig; onReload: () => Promise<void> }) {
  const logging = config.Logging;
  const updateLogging = useUpdateLoggingConfig();
  const updateCookie = useUpdateCookieConfig();
  const fieldId = useId();
  const levelId = `${fieldId}-level`;
  const cookieId = `${fieldId}-cookie`;
  const [level, setLevel] = useState(logging?.Level || 'info');
  const [cookieEnabled, setCookieEnabled] = useState(config.Cookie?.Enabled ?? false);

  useEffect(() => {
    setLevel(logging?.Level || 'info');
  }, [logging?.Level]);

  useEffect(() => {
    setCookieEnabled(config.Cookie?.Enabled ?? false);
  }, [config.Cookie?.Enabled]);

  const resetLoggingForm = () => {
    setLevel(logging?.Level || 'info');
  };

  const loggingDirty = level !== (logging?.Level || 'info');
  const cookieDirty = cookieEnabled !== (config.Cookie?.Enabled ?? false);

  const handleSave = async () => {
    try {
      await updateLogging.mutateAsync({ level });
      await onReload();
      toast.success('Log level saved');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to save log level');
    }
  };

  const handleSaveCookie = async () => {
    try {
      await updateCookie.mutateAsync({ enabled: cookieEnabled });
      await onReload();
      toast.success('DNS Cookies updated');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to update DNS Cookies');
    }
  };

  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader title="Logging" description="Log level is live and persisted; format/output remain file-backed" icon={<FileText className="h-4 w-4" />} badge="Live edit" />
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor={levelId}>Level</Label>
            <Select value={level} onValueChange={setLevel}>
              <SelectTrigger id={levelId} className="w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="debug">debug</SelectItem>
                <SelectItem value="info">info</SelectItem>
                <SelectItem value="warn">warn</SelectItem>
                <SelectItem value="error">error</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <KVRow label="Format" value={logging?.Format || 'text'} />
          <KVRow label="Output" value={logging?.Output || 'stdout'} />
          <KVRow label="Query Log" value={logging?.QueryLog ? 'Enabled' : 'Disabled'} />
          <KVRow label="Query Log File" value={logging?.QueryLogFile || '-'} mono />
          <SaveBar dirty={loggingDirty} saving={updateLogging.isPending} onSave={handleSave} onReset={resetLoggingForm} />
        </CardContent>
      </Card>
      <Card>
        <SectionHeader title="DNS Cookies" description="RFC 7873 cookie jar can be toggled live" icon={<Shield className="h-4 w-4" />} badge="Live edit" />
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <Label htmlFor={cookieId}>Enabled</Label>
            <Switch id={cookieId} checked={cookieEnabled} onCheckedChange={setCookieEnabled} />
          </div>
          <KVRow label="Secret Rotation" value={config.Cookie?.SecretRotation || '1h'} />
          <SaveBar
            dirty={cookieDirty}
            saving={updateCookie.isPending}
            onSave={handleSaveCookie}
            onReset={() => setCookieEnabled(config.Cookie?.Enabled ?? false)}
          />
        </CardContent>
      </Card>
      <Card>
        <SectionHeader title="Audit" description="Configuration change audit" icon={<Activity className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Audit Log" value={logging?.QueryLog ? 'Enabled (via query log)' : 'Disabled'} />
        </CardContent>
      </Card>
    </div>
  );
}
