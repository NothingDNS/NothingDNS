import { useEffect, useId, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Skeleton } from '@/components/ui/skeleton';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import { useUpdateCookieConfig, useUpdateDNS64Config } from '@/hooks/useApi';
import { useAuthStore } from '@/stores/authStore';
import { toast } from 'sonner';
import { Save } from 'lucide-react';

interface ServerConfig {
  version: string;
  listen_port: number;
  log_level: string;
  dns64: {
    enabled: boolean;
    prefix: string;
    prefix_len: number;
    exclude_nets?: string[];
  };
  cookie: {
    enabled: boolean;
    secret_rotation?: string;
  };
}

export function DNS64CookiesPage() {
  const [config, setConfig] = useState<ServerConfig | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [dns64Enabled, setDns64Enabled] = useState(false);
  const [cookieEnabled, setCookieEnabled] = useState(false);
  const updateDNS64 = useUpdateDNS64Config();
  const updateCookie = useUpdateCookieConfig();
  const isAdmin = useAuthStore((s) => s.role) === 'admin';
  const fieldId = useId();

  const load = () => {
    setIsLoading(true);
    api<ServerConfig>('GET', '/api/v1/server/config')
      .then((d) => {
        setConfig(d);
        setDns64Enabled(d.dns64?.enabled ?? false);
        setCookieEnabled(d.cookie?.enabled ?? false);
        setError(null);
      })
      .catch(() => setError('Failed to load server configuration'))
      .finally(() => setIsLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  const dns64 = config?.dns64;
  const cookie = config?.cookie;
  const dns64Dirty = dns64Enabled !== (dns64?.enabled ?? false);
  const cookieDirty = cookieEnabled !== (cookie?.enabled ?? false);

  const saveDNS64 = async () => {
    try {
      await updateDNS64.mutateAsync({ enabled: dns64Enabled });
      load();
      toast.success('DNS64 updated');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to update DNS64');
    }
  };

  const saveCookie = async () => {
    try {
      await updateCookie.mutateAsync({ enabled: cookieEnabled });
      load();
      toast.success('DNS Cookies updated');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to update DNS Cookies');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">DNS64 & DNS Cookies</h1>
        <p className="text-muted-foreground text-sm">Toggle without restart; prefix and rotation stay file-backed</p>
      </div>

      {isLoading ? (
        <div className="grid gap-4 md:grid-cols-2">
          {Array.from({ length: 2 }).map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <Skeleton className="h-5 w-32" />
              </CardHeader>
              <CardContent className="space-y-4">
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-3/4" />
                <Skeleton className="h-4 w-1/2" />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : error ? (
        <p className="text-destructive">{error}</p>
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  IPv6 / DNS64
                  <Badge variant={dns64Enabled ? 'success' : 'secondary'}>
                    {dns64Enabled ? 'Active' : 'Disabled'}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <Label htmlFor={`${fieldId}-dns64`}>Enabled</Label>
                  <Switch
                    id={`${fieldId}-dns64`}
                    checked={dns64Enabled}
                    onCheckedChange={setDns64Enabled}
                    disabled={!isAdmin}
                  />
                </div>
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Prefix</span>
                    <span className="font-mono">{dns64?.prefix || '64:ff9b::'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Prefix length</span>
                    <span className="font-mono">{dns64?.prefix_len ?? 96}</span>
                  </div>
                  {(dns64?.exclude_nets?.length ?? 0) > 0 && (
                    <div className="flex justify-between gap-4">
                      <span className="text-muted-foreground shrink-0">Exclude nets</span>
                      <span className="font-mono text-right">{dns64?.exclude_nets?.join(', ')}</span>
                    </div>
                  )}
                </div>
                {isAdmin && (
                  <Button size="sm" onClick={() => void saveDNS64()} disabled={!dns64Dirty || updateDNS64.isPending}>
                    <Save className="h-4 w-4" /> {updateDNS64.isPending ? 'Saving...' : 'Save'}
                  </Button>
                )}
                <p className="text-xs text-muted-foreground">
                  Enabling requires DNS64 to have been configured in YAML at least once (prefix). Prefix changes still need a YAML edit and reload.
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  DNS Cookies
                  <Badge variant={cookieEnabled ? 'success' : 'secondary'}>
                    {cookieEnabled ? 'Active' : 'Disabled'}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <Label htmlFor={`${fieldId}-cookie`}>Enabled</Label>
                  <Switch
                    id={`${fieldId}-cookie`}
                    checked={cookieEnabled}
                    onCheckedChange={setCookieEnabled}
                    disabled={!isAdmin}
                  />
                </div>
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Secret rotation</span>
                    <span className="font-mono">{cookie?.secret_rotation || '1h'}</span>
                  </div>
                </div>
                {isAdmin && (
                  <Button size="sm" onClick={() => void saveCookie()} disabled={!cookieDirty || updateCookie.isPending}>
                    <Save className="h-4 w-4" /> {updateCookie.isPending ? 'Saving...' : 'Save'}
                  </Button>
                )}
                <p className="text-xs text-muted-foreground">
                  Rotation interval is file-backed. Toggle is live and persisted to runtime overrides.
                </p>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">About DNS64</CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground space-y-2">
              <p>DNS64 synthesizes AAAA records from A records so IPv6-only clients can reach IPv4-only destinations via NAT64 (RFC 6147).</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">About DNS Cookies (RFC 7873)</CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground space-y-2">
              <p>DNS Cookies reduce amplification and spoofing by establishing a shared cookie between client and server.</p>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
