import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/api';
import { Shield, Network } from 'lucide-react';

interface ACLRule {
  name: string;
  networks: string[];
  action: string;
  types?: string[];
}

export function ACLPage() {
  const [rules, setRules] = useState<ACLRule[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchRules = () => {
    api<{ rules: ACLRule[] }>('GET', '/api/v1/acl')
      .then(d => setRules(d.rules || []))
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const actionColors: Record<string, string> = {
    allow: 'text-success bg-success/10 border-success/20',
    deny: 'text-destructive bg-destructive/10 border-destructive/20',
    redirect: 'text-warning bg-warning/10 border-warning/20',
  };

  return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">ACL</h1><p className="text-muted-foreground text-sm">Access Control List management</p></div>

      <div className="grid gap-4 grid-cols-2 md:grid-cols-3">
        <Card><CardContent className="p-6">
          <div className="text-2xl font-bold">{rules.length}</div>
          <p className="text-xs text-muted-foreground mt-1">Total Rules</p>
        </CardContent></Card>
        <Card><CardContent className="p-6">
          <div className="text-2xl font-bold">{rules.filter(r => r.action === 'allow').length}</div>
          <p className="text-xs text-muted-foreground mt-1">Allow Rules</p>
        </CardContent></Card>
        <Card><CardContent className="p-6">
          <div className="text-2xl font-bold">{rules.filter(r => r.action === 'deny').length}</div>
          <p className="text-xs text-muted-foreground mt-1">Deny Rules</p>
        </CardContent></Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Shield className="h-4 w-4" /> ACL Rules
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 space-y-3">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-16 w-full" />)}</div>
          ) : rules.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <Network className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No ACL rules configured</p>
              <p className="text-xs mt-1">Rules are defined in the configuration file</p>
            </div>
          ) : (
            <div className="divide-y">
              {rules.map((rule, i) => (
                <div key={i} className="p-4 hover:bg-muted/50">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-4">
                      <div className={`px-3 py-1.5 rounded-lg border text-sm font-medium ${actionColors[rule.action] || 'border-muted'}`}>
                        {rule.action.toUpperCase()}
                      </div>
                      <div>
                        <p className="font-medium text-sm">{rule.name}</p>
                        <div className="flex flex-wrap gap-2 mt-2">
                          {rule.networks.map((net, j) => (
                            <Badge key={j} variant="outline" className="font-mono text-xs">{net}</Badge>
                          ))}
                        </div>
                        {rule.types && rule.types.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-2">
                            {rule.types.map((t, j) => (
                              <Badge key={j} variant="secondary" className="text-[10px]">{t}</Badge>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Rule Types</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="p-4 rounded-lg border">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-3 h-3 rounded-full bg-success" />
                <span className="font-medium text-sm">ALLOW</span>
              </div>
              <p className="text-xs text-muted-foreground">Permits queries from matching networks</p>
            </div>
            <div className="p-4 rounded-lg border">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-3 h-3 rounded-full bg-destructive" />
                <span className="font-medium text-sm">DENY</span>
              </div>
              <p className="text-xs text-muted-foreground">Blocks queries from matching networks</p>
            </div>
            <div className="p-4 rounded-lg border">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-3 h-3 rounded-full bg-muted" />
                <span className="font-medium text-sm">DROP</span>
              </div>
              <p className="text-xs text-muted-foreground">Silently drops queries without response</p>
            </div>
            <div className="p-4 rounded-lg border">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-3 h-3 rounded-full bg-warning" />
                <span className="font-medium text-sm">REFUSE</span>
              </div>
              <p className="text-xs text-muted-foreground">Returns REFUSED response to matching networks</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}