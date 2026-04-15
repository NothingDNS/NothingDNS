import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/api';

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

  useEffect(() => {
    api<ServerConfig>('GET', '/api/v1/server/config')
      .then(setConfig)
      .catch(() => setError('Failed to load server configuration'))
      .finally(() => setIsLoading(false));
  }, []);

  const dns64 = config?.dns64;
  const cookie = config?.cookie;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">DNS64 & DNS Cookies</h1>
        <p className="text-muted-foreground text-sm">IPv6 transition and anti-spoofing status</p>
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
                  IPv6
                  <Badge variant={dns64?.enabled ? 'success' : 'secondary'}>
                    {dns64?.enabled ? 'Active' : 'Disabled'}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">DNS64 Enabled</span>
                    <Badge variant={dns64?.enabled ? 'success' : 'destructive'}>
                      {dns64?.enabled ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">IPv6 Prefix</span>
                    <code className="text-xs bg-muted px-2 py-1 rounded">
                      {dns64?.prefix || '64:ff9b::/96'}
                    </code>
                  </div>
                  {dns64?.prefix_len ? (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Prefix Length</span>
                      <span className="font-mono">{dns64.prefix_len}</span>
                    </div>
                  ) : null}
                  {dns64?.exclude_nets && dns64.exclude_nets.length > 0 ? (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Exclude Nets</span>
                      <span className="font-mono text-xs">{dns64.exclude_nets.join(', ')}</span>
                    </div>
                  ) : null}
                </div>

                <div className="rounded-lg border p-3 text-xs space-y-2">
                  <p className="font-medium">About DNS64</p>
                  <p className="text-muted-foreground">
                    DNS64 (RFC 6147) synthesizes AAAA records from A records when no native IPv6
                    exists. This enables IPv6-only clients to communicate with IPv4-only servers
                    via a NAT64 gateway.
                  </p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  DNS Cookies
                  <Badge variant={cookie?.enabled ? 'success' : 'secondary'}>
                    {cookie?.enabled ? 'Active' : 'Disabled'}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">DNS Cookies</span>
                    <Badge variant={cookie?.enabled ? 'success' : 'destructive'}>
                      {cookie?.enabled ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </div>
                  {cookie?.secret_rotation ? (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Secret Rotation</span>
                      <span className="font-mono">{cookie.secret_rotation}</span>
                    </div>
                  ) : null}
                </div>

                <div className="rounded-lg border p-3 text-xs space-y-2">
                  <p className="font-medium">About DNS Cookies (RFC 7873)</p>
                  <p className="text-muted-foreground">
                    DNS Cookies provide lightweight protection against DNS amplification
                    attacks by establishing a shared secret between client and server.
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
