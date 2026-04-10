import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

interface DNS64Status {
  enabled: boolean;
  synthEnabled: boolean;
  prefix: string;
  queries: number;
}

interface DNSCookieStatus {
  enabled: boolean;
  clientEnabled: boolean;
  serverEnabled: boolean;
  valid: number;
  invalid: number;
}

export function DNS64CookiesPage() {
  const [dns64, setDNS64] = useState<DNS64Status | null>(null);
  const [cookie, setCookie] = useState<DNSCookieStatus | null>(null);

  useEffect(() => {
    // Simulated stats — in production these would come from API
    setDNS64({
      enabled: true,
      synthEnabled: true,
      prefix: '64:ff9b::/96',
      queries: 0,
    });
    setCookie({
      enabled: true,
      clientEnabled: true,
      serverEnabled: true,
      valid: 0,
      invalid: 0,
    });
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">DNS64 & DNS Cookies</h1>
        <p className="text-muted-foreground text-sm">IPv6 transition and anti-spoofing status</p>
      </div>

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
                <span className="text-muted-foreground">Synthesis (A→AAAA)</span>
                <Badge variant={dns64?.synthEnabled ? 'success' : 'secondary'}>
                  {dns64?.synthEnabled ? 'Active' : 'Inactive'}
                </Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">IPv6 Prefix</span>
                <code className="text-xs bg-muted px-2 py-1 rounded">
                  {dns64?.prefix ?? '64:ff9b::/96'}
                </code>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Total Synthesized</span>
                <span className="font-mono">{dns64?.queries?.toLocaleString() ?? 0}</span>
              </div>
            </div>

            <div className="rounded-lg border p-3 text-xs space-y-2">
              <p className="font-medium">About DNS64</p>
              <p className="text-muted-foreground">
                DNS64 (RFC 6147) synthesizes AAAA records from A records when no native IPv6
                exists. This enables IPv6-only clients to communicate with IPv4-only servers
                via a NAT64 gateway.
              </p>
              <p className="text-muted-foreground">
                The Well-Known Prefix <code>64:ff9b::/96</code> is used for synthesis.
                Configure custom prefixes in <code>config.yaml</code>.
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
              <div className="flex justify-between">
                <span className="text-muted-foreground">Client Cookie</span>
                <Badge variant={cookie?.clientEnabled ? 'success' : 'secondary'}>
                  {cookie?.clientEnabled ? 'Supported' : 'Unsupported'}
                </Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Server Cookie</span>
                <Badge variant={cookie?.serverEnabled ? 'success' : 'secondary'}>
                  {cookie?.serverEnabled ? 'Supported' : 'Unsupported'}
                </Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Valid Cookies</span>
                <span className="font-mono">{cookie?.valid?.toLocaleString() ?? 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Invalid Cookies</span>
                <span className="font-mono text-destructive">{cookie?.invalid?.toLocaleString() ?? 0}</span>
              </div>
            </div>

            <div className="rounded-lg border p-3 text-xs space-y-2">
              <p className="font-medium">About DNS Cookies (RFC 7873)</p>
              <p className="text-muted-foreground">
                DNS Cookies provide lightweight protection against DNS amplification
                attacks by establishing a shared secret between client and server.
              </p>
              <p className="text-muted-foreground">
                HMAC-SHA256 is used to generate cookies. The server returns a cookie
                on the first request, and the client echoes it in subsequent queries.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Configuration</CardTitle>
        </CardHeader>
        <CardContent className="text-sm">
          <div className="space-y-2">
            <p className="text-muted-foreground">
              These features are configured in <code>config.yaml</code> under
              the <code>dns64</code> and <code>cookie</code> sections.
            </p>
            <pre className="bg-muted p-4 rounded-lg text-xs overflow-x-auto">{`dns64:
  enabled: true
  prefix: "64:ff9b::/96"

cookie:
  enabled: true
  server_secret: "your-secret-here"`}</pre>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}