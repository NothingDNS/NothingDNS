import { useEffect, useRef, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState } from '@/components/states';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { api, type ACLResponse, type ACLRule } from '@/lib/api';
import { isEverywhere, isIPOrCIDR } from '@/lib/network';
import { useAuthStore } from '@/stores/authStore';
import { toast } from 'sonner';
import {
  Shield, Network, Repeat, Plus, Trash2, AlertTriangle,
  ChevronUp, ChevronDown, Pencil, X,
} from 'lucide-react';

const actionColors: Record<string, string> = {
  allow: 'text-success bg-success/10 border-success/20',
  deny: 'text-destructive bg-destructive/10 border-destructive/20',
  redirect: 'text-warning bg-warning/10 border-warning/20',
};

const ACTIONS = ['allow', 'deny', 'redirect'] as const;
type ACLAction = (typeof ACTIONS)[number];

type RuleDraft = {
  name: string;
  networks: string;
  action: ACLAction;
  types: string;
  redirect: string;
};

const emptyDraft = (): RuleDraft => ({
  name: '',
  networks: '',
  action: 'allow',
  types: '',
  redirect: '',
});

type PendingChange =
  | {
      kind: 'recursion';
      networks: string[];
      title: string;
      description: string;
      label: string;
      destructive: boolean;
      successMessage: string;
    }
  | {
      kind: 'acl';
      rules: ACLRule[];
      title: string;
      description: string;
      label: string;
      destructive: boolean;
      successMessage: string;
      clearDraft?: boolean;
    };

/** Domain name suitable as an ACL redirect CNAME target (not an IP). */
function isRedirectTarget(value: string): boolean {
  const v = value.trim().replace(/\.$/, '');
  if (!v || isIPOrCIDR(v)) return false;
  return /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(v);
}

function parseNetworks(raw: string): string[] | null {
  const parts = raw.split(/[,\s]+/).map((p) => p.trim()).filter(Boolean);
  if (parts.length === 0) return [];
  for (const p of parts) {
    if (!isIPOrCIDR(p)) return null;
  }
  return parts;
}

function parseTypes(raw: string): string[] {
  return raw.split(/[,\s]+/).map((t) => t.trim().toUpperCase()).filter(Boolean);
}

function draftToRule(draft: RuleDraft): ACLRule | null {
  const name = draft.name.trim();
  if (!name) {
    toast.error('Rule name is required');
    return null;
  }
  const networks = parseNetworks(draft.networks);
  if (networks === null) {
    toast.error('Networks must be IP addresses or CIDRs, separated by commas');
    return null;
  }
  if (!ACTIONS.includes(draft.action)) {
    toast.error('Action must be allow, deny, or redirect');
    return null;
  }
  const rule: ACLRule = { name, networks, action: draft.action };
  const types = parseTypes(draft.types);
  if (types.length > 0) rule.types = types;
  if (draft.action === 'redirect') {
    const target = draft.redirect.trim();
    if (!isRedirectTarget(target)) {
      toast.error('Redirect requires a domain name (not an IP), e.g. blocked.example.com');
      return null;
    }
    rule.redirect = target;
  }
  return rule;
}

function ruleToDraft(rule: ACLRule): RuleDraft {
  return {
    name: rule.name,
    networks: (rule.networks || []).join(', '),
    action: (ACTIONS.includes(rule.action as ACLAction) ? rule.action : 'allow') as ACLAction,
    types: (rule.types || []).join(', '),
    redirect: rule.redirect || '',
  };
}

export function ACLPage() {
  const [data, setData] = useState<ACLResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [newNetwork, setNewNetwork] = useState('');
  const [draft, setDraft] = useState<RuleDraft>(emptyDraft);
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
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

  const refreshAfterSave = async () => {
    const d = await api<ACLResponse>('GET', '/api/v1/acl');
    setData(d);
  };

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

  const saveRules = async (next: ACLRule[], message: string, clearDraft = false) => {
    setSaving(true);
    try {
      await api('PUT', '/api/v1/acl', { rules: next });
      await refreshAfterSave();
      toast.success(message);
      if (clearDraft) {
        setDraft(emptyDraft());
        setEditingIndex(null);
      }
      return true;
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to update ACL rules');
      return false;
    } finally {
      setSaving(false);
      setPending(null);
    }
  };

  const handleAddRecursion = () => {
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
        kind: 'recursion',
        networks,
        title: 'Allow recursion for every client?',
        description: `${entry} lets any client on the internet use this server as a resolver (open resolver), which attackers abuse for DNS amplification.`,
        label: 'Allow anyway',
        destructive: true,
        successMessage: 'Recursion allow list updated',
      });
      return;
    }
    if (recursion.allow_all) {
      setPending({
        kind: 'recursion',
        networks,
        title: 'Restrict recursion?',
        description: `Recursion is currently allowed for every client the ACL admits. After this change only ${entry} may recurse; other clients get answers from local zones only.`,
        label: 'Restrict',
        destructive: false,
        successMessage: 'Recursion allow list updated',
      });
      return;
    }
    void saveRecursion(networks, `${entry} may now use recursion`).then((ok) => ok && setNewNetwork(''));
  };

  const handleRemoveRecursion = (entry: string) => {
    const networks = recursion.networks.filter((n) => n !== entry);
    if (networks.length === 0) {
      setPending({
        kind: 'recursion',
        networks,
        title: 'Remove the last network?',
        description: 'No client will be able to use recursion. This server will only answer for its own zones.',
        label: 'Remove',
        destructive: true,
        successMessage: 'Recursion allow list updated',
      });
      return;
    }
    void saveRecursion(networks, `${entry} removed`);
  };

  const submitRule = () => {
    const rule = draftToRule(draft);
    if (!rule) return;

    let next: ACLRule[];
    if (editingIndex !== null) {
      next = rules.map((r, i) => (i === editingIndex ? rule : r));
    } else {
      next = [...rules, rule];
    }

    const isFirst = rules.length === 0 && editingIndex === null;
    const matchesAll = rule.networks.length === 0 || rule.networks.some(isEverywhere);

    if (isFirst) {
      setPending({
        kind: 'acl',
        rules: next,
        title: 'Add the first ACL rule?',
        description: 'Once any rule exists, clients that match none are refused. Make sure your own networks are covered by an allow rule.',
        label: 'Continue',
        destructive: false,
        successMessage: editingIndex !== null ? 'ACL rule updated' : `Rule "${rule.name}" added`,
        clearDraft: true,
      });
      return;
    }
    if (matchesAll && rule.action === 'deny') {
      setPending({
        kind: 'acl',
        rules: next,
        title: 'Deny every client?',
        description: 'This rule matches all networks and denies them. Clients that hit it get REFUSED.',
        label: 'Deny anyway',
        destructive: true,
        successMessage: editingIndex !== null ? 'ACL rule updated' : `Rule "${rule.name}" added`,
        clearDraft: true,
      });
      return;
    }
    void saveRules(next, editingIndex !== null ? 'ACL rule updated' : `Rule "${rule.name}" added`, true);
  };

  const handleDeleteRule = (index: number) => {
    const rule = rules[index];
    const next = rules.filter((_, i) => i !== index);
    setPending({
      kind: 'acl',
      rules: next,
      title: `Delete rule "${rule.name}"?`,
      description: next.length === 0
        ? 'Removing the last rule lets every client query this server\'s own zones again.'
        : 'Rules after this one move up; first match still wins.',
      label: 'Delete',
      destructive: true,
      successMessage: `Rule "${rule.name}" deleted`,
    });
  };

  const moveRule = (index: number, delta: number) => {
    const target = index + delta;
    if (target < 0 || target >= rules.length) return;
    const next = [...rules];
    const [item] = next.splice(index, 1);
    next.splice(target, 0, item);
    void saveRules(next, 'ACL rule order updated');
  };

  const startEdit = (index: number) => {
    setEditingIndex(index);
    setDraft(ruleToDraft(rules[index]));
  };

  const cancelEdit = () => {
    setEditingIndex(null);
    setDraft(emptyDraft());
  };

  const confirmPending = () => {
    if (!pending) return;
    if (pending.kind === 'recursion') {
      void saveRecursion(pending.networks, pending.successMessage).then((ok) => ok && setNewNetwork(''));
      return;
    }
    void saveRules(pending.rules, pending.successMessage, pending.clearDraft);
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
                          onClick={() => handleRemoveRecursion(net)}
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
                  onSubmit={(e) => { e.preventDefault(); handleAddRecursion(); }}
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
            Who may query this server at all. Rules are checked in order and the first match wins; once any rule exists, clients matching none are refused.
            Recursion (above) only applies to clients this list already admits.
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          {loading && !data ? (
            <div className="space-y-3">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-16 w-full" />)}</div>
          ) : error ? (
            <ErrorState message={error} onRetry={fetchACL} />
          ) : (
            <>
              {rules.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Network className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No ACL rules configured</p>
                  <p className="text-xs mt-1">All clients can query this server's own zones</p>
                </div>
              ) : (
                <ul className="divide-y rounded-md border" aria-label="ACL rules">
                  {rules.map((rule, i) => (
                    <li key={`${rule.name}-${i}`} className="p-4 hover:bg-muted/50">
                      <div className="flex items-start gap-4">
                        <div className={`px-3 py-1.5 rounded-lg border text-sm font-medium shrink-0 ${actionColors[rule.action] || 'border-muted'}`}>
                          {(rule.action || 'UNKNOWN').toUpperCase()}
                        </div>
                        <div className="min-w-0 flex-1">
                          <p className="font-medium text-sm">{rule.name}</p>
                          <div className="flex flex-wrap gap-2 mt-2">
                            {(rule.networks || []).length === 0 ? (
                              <Badge variant="outline" className="font-mono text-xs">all networks</Badge>
                            ) : (
                              (rule.networks || []).map((net, j) => (
                                <Badge key={j} variant="outline" className="font-mono text-xs">{net}</Badge>
                              ))
                            )}
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
                        {isAdmin && (
                          <div className="flex items-center gap-1 shrink-0">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => moveRule(i, -1)}
                              disabled={saving || i === 0}
                              aria-label={`Move ${rule.name} up`}
                            >
                              <ChevronUp className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => moveRule(i, 1)}
                              disabled={saving || i === rules.length - 1}
                              aria-label={`Move ${rule.name} down`}
                            >
                              <ChevronDown className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => startEdit(i)}
                              disabled={saving}
                              aria-label={`Edit ${rule.name}`}
                            >
                              <Pencil className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleDeleteRule(i)}
                              disabled={saving}
                              aria-label={`Delete ${rule.name}`}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              )}

              {isAdmin ? (
                <form
                  className="space-y-3 rounded-md border p-4"
                  onSubmit={(e) => { e.preventDefault(); submitRule(); }}
                  aria-label={editingIndex !== null ? 'Edit ACL rule' : 'Add ACL rule'}
                >
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm font-medium">
                      {editingIndex !== null ? `Edit rule #${editingIndex + 1}` : 'Add rule'}
                    </p>
                    {editingIndex !== null && (
                      <Button type="button" variant="ghost" size="sm" onClick={cancelEdit} disabled={saving}>
                        <X className="h-4 w-4" /> Cancel
                      </Button>
                    )}
                  </div>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label htmlFor="acl-rule-name">Name</Label>
                      <Input
                        id="acl-rule-name"
                        value={draft.name}
                        onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
                        placeholder="allow-lan"
                        aria-label="Rule name"
                        disabled={saving}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="acl-rule-action">Action</Label>
                      <select
                        id="acl-rule-action"
                        aria-label="Rule action"
                        value={draft.action}
                        onChange={(e) => setDraft((d) => ({ ...d, action: e.target.value as ACLAction }))}
                        disabled={saving}
                        className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      >
                        <option value="allow">allow</option>
                        <option value="deny">deny</option>
                        <option value="redirect">redirect</option>
                      </select>
                    </div>
                    <div className="space-y-1.5 sm:col-span-2">
                      <Label htmlFor="acl-rule-networks">Networks</Label>
                      <Input
                        id="acl-rule-networks"
                        value={draft.networks}
                        onChange={(e) => setDraft((d) => ({ ...d, networks: e.target.value }))}
                        placeholder="192.168.0.0/16, 10.0.0.0/8 (empty = all)"
                        aria-label="Rule networks"
                        className="font-mono"
                        disabled={saving}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="acl-rule-types">Query types (optional)</Label>
                      <Input
                        id="acl-rule-types"
                        value={draft.types}
                        onChange={(e) => setDraft((d) => ({ ...d, types: e.target.value }))}
                        placeholder="A, AAAA"
                        aria-label="Rule query types"
                        className="font-mono"
                        disabled={saving}
                      />
                    </div>
                    {draft.action === 'redirect' && (
                      <div className="space-y-1.5">
                        <Label htmlFor="acl-rule-redirect">Redirect target</Label>
                        <Input
                          id="acl-rule-redirect"
                          value={draft.redirect}
                          onChange={(e) => setDraft((d) => ({ ...d, redirect: e.target.value }))}
                          placeholder="blocked.example.com"
                          aria-label="Redirect target"
                          className="font-mono"
                          disabled={saving}
                        />
                      </div>
                    )}
                  </div>
                  <Button type="submit" disabled={saving || !draft.name.trim()}>
                    {editingIndex !== null ? (
                      <>Save changes</>
                    ) : (
                      <><Plus className="h-4 w-4" /> Add rule</>
                    )}
                  </Button>
                </form>
              ) : (
                <p className="text-xs text-muted-foreground">Only administrators can change ACL rules.</p>
              )}
            </>
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
        onConfirm={confirmPending}
        onCancel={() => setPending(null)}
      />
    </div>
  );
}
