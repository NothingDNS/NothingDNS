import { useEffect, useRef, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState } from '@/components/states';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { api, type ACLResponse } from '@/lib/api';
import { isEverywhere, isIPOrCIDR } from '@/lib/network';
import { useAuthStore } from '@/stores/authStore';
import { toast } from 'sonner';
import { Shield, Network, Repeat, Plus, Trash2, AlertTriangle } from 'lucide-react';

const actionColors: Record<string, string> = {
  allow: 'text-success bg-success/10 border-success/20',
  deny: 'text-destructive bg-destructive/10 border-destructive/20',
  redirect: 'text-warning bg-warning/10 border-warning/20',
};

type PendingChange = { networks: string[]; title: string; description: string; label: string; destructive: boolean };

export function ACLPage() {
  const [data, setData] = useState<ACLResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [newNetwork, setNewNetwork] = useState('');
  const [saving, setSaving] = useState(false);
  const [pending, setPending] = useState<PendingChange | null>(null);
  const isAdmin = useAuthStore((s) => s.role) === 'admin';

  // Guards against an older load finishing after a save's refresh.
  const loadGeneration = useRef(0);

  const fetchACL = () => {
    const gen = ++loadGeneration.current;
    setLoading(true);
    api<ACLResponse>('GET', '/api/v1/acl')
      .then((d) => {
        if (gen !== loadGeneration.current) return;
        setData(d);
        setError('');
      })
      .catch((e: unknown) => {
        if (gen !== loadGeneration.current) return;
        setError(e instanceof Error ? e.message : 'Failed to load ACL');
      })
      .finally(() => {
        if (gen === loadGeneration.current) setLoading(false);
      });
  };

  useEffect(() => {
    fetchACL();
  }, []);

  const rules = data?.rules ?? [];
  const recursion = data?.allow_recursion ?? { allow_all: false, networks: [] };

  const saveRecursion = async (networks: string[], message: string) => {
    setSaving(true);
    try {
      const updated = await api<ACLResponse['allow_recursion']>('PUT', '/api/v1/acl/recursion', { networks });
      setData((d) => (d ? { ...d, allow_recursion: updated } : d));
      toast.success(message);
      return true;
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to update recursion allow list');
      return false;
    } finally {
      setSaving(false);
      setPending(null);
    }
  };

  const handleAdd = () => {
    const entry = newNetwork.trim();
    if (!isIPOrCIDR(entry)) {
      toast.error('Enter an IP address or CIDR network, e.g. 192.168.1.0/24');
      return;
    }
    // Switching from "all clients" to an explicit list starts from empty.
    const current = recursion.allow_all ? [] : recursion.networks;
    if (current.includes(entry)) {
      toast.error(`${entry} is already in the list`);
      return;
    }
    const networks = [...current, entry];
    if (isEverywhere(entry)) {
      setPending({
        networks,
        title: 'Allow recursion for every client?',
        description: `${entry} lets any client on the internet use this server as a resolver (open resolver), which attackers abuse for DNS amplification.`,
        label: 'Allow anyway',
        destructive: true,
      });
      return;
    }
    if (recursion.allow_all) {
      setPending({
        networks,
        title: 'Restrict recursion?',
        description: `Recursion is currently allowed for every client the ACL admits. After this change only ${entry} may recurse; other clients get answers from local zones only.`,
        label: 'Restrict',
        destructive: false,
      });
      return;
    }
    void saveRecursion(networks, `${entry} may now use recursion`).then((ok) => ok && setNewNetwork(''));
  };

  const handleRemove = (entry: string) => {
    const networks = recursion.networks.filter((n) => n !== entry);
    if (networks.length === 0) {
      setPending({
        networks,
        title: 'Remove the last network?',
        description: 'No client will be able to use recursion. This server will only answer for its own zones.',
        label: 'Remove',
        destructive: true,
      });
      return;
    }
    void saveRecursion(networks, `${entry} removed`);
  };

  return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">ACL</h1><p className="text-muted-foreground text-sm">Access control and recursion</p></div>

      <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
        <Card><CardContent className="p-6">
          <div className="text-2xl font-bold">{rules.length}</div>
          <p className="text-xs text-muted-foreground mt-1">ACL Rules</p>
        </CardContent></Card>
        <Card><CardContent className="p-6">
          <div className="text-2xl font-bold">{rules.filter(r => r.action === 'allow').length}</div>
          <p className="text-xs text-muted-foreground mt-1">Allow Rules</p>
        </CardContent></Card>
        <Card><CardContent className="p-6">
          <div className="text-2xl font-bold">{rules.filter(r => r.action === 'deny').length}</div>
          <p className="text-xs text-muted-foreground mt-1">Deny Rules</p>
        </CardContent></Card>
        <Card><CardContent className="p-6">
          <div className="text-2xl font-bold">{recursion.allow_all ? 'All' : recursion.networks.length}</div>
          <p className="text-xs text-muted-foreground mt-1">Recursion Networks</p>
        </CardContent></Card>
      </div>

      {data && !data.persistent && (
        <div role="alert" className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 px-4 py-3 text-sm">
          <AlertTriangle className="h-4 w-4 mt-0.5 text-warning shrink-0" />
          <span>Changes are not saved to disk and are lost on restart or reload. Set <code className="font-mono">storage.data_dir</code> in the config to keep them.</span>
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Repeat className="h-4 w-4" /> Allow Recursion
          </CardTitle>
          <p className="text-sm text-muted-foreground">
            Clients in these networks may use recursion: upstream forwarding, iterative resolution and cached answers.
            Everyone else still gets answers from this server's own zones; other names are refused.
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          {loading && !data ? (
            <div className="space-y-2">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
          ) : error ? (
            <ErrorState message={error} onRetry={fetchACL} />
          ) : (
            <>
              {recursion.allow_all ? (
                <div className="rounded-md border p-4 text-sm">
                  <Badge variant="warning">All clients</Badge>
                  <p className="mt-2 text-muted-foreground">
                    Every client admitted by the ACL rules may use recursion. Add a network below to limit recursion to specific clients.
                  </p>
                </div>
              ) : recursion.networks.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Network className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No client may use recursion</p>
                  <p className="text-xs mt-1">The server only answers for its own zones</p>
                </div>
              ) : (
                <ul className="divide-y rounded-md border" aria-label="Recursion allow list">
                  {recursion.networks.map((net) => (
                    <li key={net} className="flex items-center justify-between px-4 py-2">
                      <span className="font-mono text-sm">{net}</span>
                      {isAdmin && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleRemove(net)}
                          disabled={saving}
                          aria-label={`Remove ${net}`}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      )}
                    </li>
                  ))}
                </ul>
              )}

              {isAdmin ? (
                <form
                  className="flex gap-2"
                  onSubmit={(e) => { e.preventDefault(); handleAdd(); }}
                >
                  <Input
                    value={newNetwork}
                    onChange={(e) => setNewNetwork(e.target.value)}
                    placeholder="192.168.1.0/24, 203.0.113.10 or 2001:db8::/32"
                    aria-label="Network to allow recursion"
                    className="font-mono"
                    disabled={saving}
                  />
                  <Button type="submit" disabled={saving || !newNetwork.trim()}>
                    <Plus className="h-4 w-4" /> Add
                  </Button>
                </form>
              ) : (
                <p className="text-xs text-muted-foreground">Only administrators can change the recursion allow list.</p>
              )}
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Shield className="h-4 w-4" /> ACL Rules
          </CardTitle>
          <p className="text-sm text-muted-foreground">
            General access control for every query. Rules are checked in order and the first match wins; once any rule exists, clients matching none are refused.
          </p>
        </CardHeader>
        <CardContent className="p-0">
          {loading && !data ? (
            <div className="p-6 space-y-3">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-16 w-full" />)}</div>
          ) : error ? (
            <div className="p-6"><ErrorState message={error} onRetry={fetchACL} /></div>
          ) : rules.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <Network className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No ACL rules configured</p>
              <p className="text-xs mt-1">All clients can query this server's own zones</p>
            </div>
          ) : (
            <div className="divide-y">
              {rules.map((rule, i) => (
                <div key={i} className="p-4 hover:bg-muted/50">
                  <div className="flex items-start gap-4">
                    <div className={`px-3 py-1.5 rounded-lg border text-sm font-medium ${actionColors[rule.action] || 'border-muted'}`}>
                      {(rule.action || 'UNKNOWN').toUpperCase()}
                    </div>
                    <div>
                      <p className="font-medium text-sm">{rule.name}</p>
                      <div className="flex flex-wrap gap-2 mt-2">
                        {(rule.networks || []).map((net, j) => (
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
                      {rule.redirect && <p className="text-xs text-muted-foreground mt-2">Redirect to <span className="font-mono">{rule.redirect}</span></p>}
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
          <CardTitle className="text-base">Rule Actions</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
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
              <p className="text-xs text-muted-foreground">Answers REFUSED to matching networks</p>
            </div>
            <div className="p-4 rounded-lg border">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-3 h-3 rounded-full bg-warning" />
                <span className="font-medium text-sm">REDIRECT</span>
              </div>
              <p className="text-xs text-muted-foreground">Answers matching networks with the redirect target</p>
            </div>
          </div>
        </CardContent>
      </Card>

      <ConfirmDialog
        open={pending !== null}
        title={pending?.title ?? ''}
        description={pending?.description}
        confirmLabel={pending?.label}
        destructive={pending?.destructive}
        loading={saving}
        onConfirm={() => {
          if (!pending) return;
          void saveRecursion(pending.networks, 'Recursion allow list updated').then((ok) => ok && setNewNetwork(''));
        }}
        onCancel={() => setPending(null)}
      />
    </div>
  );
}
