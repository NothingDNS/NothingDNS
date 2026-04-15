import { useEffect, useState, type ReactNode } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { api } from '@/lib/api';
import { useUpdateLoggingConfig, useUpdateRRLConfig, useUpdateCacheConfig } from '@/hooks/useApi';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Server, Network, Database, Shield, Globe, HardDrive, Zap,
  Lock, Key, Users, FileText, Activity, RefreshCw, AlertCircle, Save
} from 'lucide-react';

// Full config type matching internal/config/config.go JSON output (Go encoding/json uses field names as-is).
// Note: Go structs have no json tags, so PascalCase field names are used in JSON output.
interface ServerConfig {
  Server: {
    Bind: string[];
    TCPBind: string[];
    UDPBind: string[];
    Port: number;
    UDPWorkers: number;
    TCPWorkers: number;
    TLS: { Enabled: boolean; CertFile: string; KeyFile: string; Bind: string };
    QUIC: { Enabled: boolean; CertFile: string; KeyFile: string; Bind: string };
    HTTP: {
      Enabled: boolean;
      Bind: string;
      AuthToken: string;
      DoHEnabled: boolean;
      DoHPath: string;
      DoWSEnabled: boolean;
      DoWSPath: string;
      ODoHEnabled: boolean;
      ODoHPath: string;
    };
  };
  Cluster: {
    Enabled: boolean;
    NodeID: string;
    BindAddr: string;
    GossipPort: number;
    Region: string;
    Zone: string;
    Weight: number;
    SeedNodes: string[];
    CacheSync: boolean;
    EncryptionKey: string;
  };
  Resolution: {
    Recursive: boolean;
    RootHints: string;
    MaxDepth: number;
    Timeout: string;
    EDNS0BufferSize: number;
    QnameMinimization: boolean;
    Use0x20: boolean;
  };
  Upstream: {
    Servers: string[];
    Strategy: string;
    HealthCheck: string;
    FailoverTimeout: string;
    AnycastGroups: Array<{
      AnycastIP: string;
      Backends: Array<{
        PhysicalIP: string;
        Port: number;
        Region: string;
        Zone: string;
        Weight: number;
      }>;
    }>;
    Topology: { Region: string; Zone: string; Weight: number };
  };
  Cache: {
    Enabled: boolean;
    Size: number;
    DefaultTTL: number;
    MaxTTL: number;
    MinTTL: number;
    NegativeTTL: number;
    Prefetch: boolean;
    PrefetchThreshold: number;
    ServeStale: boolean;
    StaleGraceSecs: number;
  };
  Logging: {
    Level: string;
    Format: string;
    Output: string;
    QueryLog: boolean;
    QueryLogFile: string;
  };
  Metrics: {
    Enabled: boolean;
    Bind: string;
    Path: string;
  };
  DNSSEC: {
    Enabled: boolean;
    TrustAnchor: string;
    IgnoreTime: boolean;
    RequireDNSSEC: boolean;
    Signing: {
      Enabled: boolean;
      SignatureValidity: string;
      Keys: Array<{ PrivateKey: string; Type: string; Algorithm: number }>;
      NSEC3: { Iterations: number; Salt: string; OptOut: boolean } | null;
    };
  };
  Zones: string[];
  ZoneDir: string;
  ACL: Array<{ Name: string; Networks: string[]; Types: string[]; Action: string; Redirect: string }>;
  RRL: { Enabled: boolean; Rate: number; Burst: number };
  Blocklist: { Enabled: boolean; Files: string[]; URLs: string[] };
  RPZ: {
    Enabled: boolean;
    Files: string[];
    Zones: Array<{ Name: string; File: string; Priority: number }>;
  };
  GeoDNS: { Enabled: boolean; MMDBFile: string; Rules: Array<{ Domain: string; Type: string; Default: string; Records: Record<string, string> }> };
  DNS64: { Enabled: boolean; Prefix: string; PrefixLen: number; ExcludeNets: string[] };
  Cookie: { Enabled: boolean; SecretRotation: string };
  IDNA: { Enabled: boolean; UseSTD3Rules: boolean; AllowUnassigned: boolean; CheckBidi: boolean; CheckJoiner: boolean };
  ODoH: { Enabled: boolean; Bind: string; TargetURL: string; ProxyURL: string; KEM: number; KDF: number; AEAD: number };
  MDNS: { Enabled: boolean; MulticastIP: string; Port: number; Browser: boolean; HostName: string };
  Catalog: { Enabled: boolean; CatalogZone: string; ProducerClass: string; ConsumerClass: string };
  DSO: { Enabled: boolean; SessionTimeout: string; MaxSessions: number; HeartbeatInterval: string };
  YANG: { Enabled: boolean; EnableCLI: boolean; EnableNETCONF: boolean; NETCONFBind: string; Models: string[] };
  SlaveZones: Array<{
    ZoneName: string;
    Masters: string[];
    TransferType: string;
    TSIGKeyName: string;
    TSIGSecret: string;
    Timeout: string;
    RetryInterval: string;
    MaxRetries: number;
  }>;
  Views: Array<{ Name: string; MatchClients: string[]; ZoneFiles: string[] }>;
  MemoryLimitMB: number;
  ShutdownTimeout: string;
}

type TabId = 'general' | 'dns' | 'upstream' | 'cache' | 'security' | 'logging' | 'cluster' | 'advanced';

const TABS: { id: TabId; label: string; icon: ReactNode }[] = [
  { id: 'general', label: 'General', icon: <Server className="h-4 w-4" /> },
  { id: 'dns', label: 'DNS', icon: <Globe className="h-4 w-4" /> },
  { id: 'upstream', label: 'Upstream', icon: <Network className="h-4 w-4" /> },
  { id: 'cache', label: 'Cache', icon: <Database className="h-4 w-4" /> },
  { id: 'security', label: 'Security', icon: <Shield className="h-4 w-4" /> },
  { id: 'logging', label: 'Logging', icon: <FileText className="h-4 w-4" /> },
  { id: 'cluster', label: 'Cluster', icon: <Users className="h-4 w-4" /> },
  { id: 'advanced', label: 'Advanced', icon: <Zap className="h-4 w-4" /> },
];

export function SettingsPage() {
  const [config, setConfig] = useState<ServerConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('general');

  useEffect(() => {
    loadConfig();
  }, []);

  const loadConfig = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api<ServerConfig>('GET', '/api/v1/config');
      setConfig(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load config');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <div><h1 className="text-2xl font-bold tracking-tight">Settings</h1><p className="text-muted-foreground text-sm">Server configuration</p></div>
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  if (error || !config) {
    return (
      <div className="space-y-6">
        <div><h1 className="text-2xl font-bold tracking-tight">Settings</h1><p className="text-muted-foreground text-sm">Server configuration</p></div>
        <Card>
          <CardContent className="flex items-center justify-center h-48 gap-3">
            <AlertCircle className="h-5 w-5 text-destructive" />
            <span className="text-destructive">{error || 'Failed to load configuration'}</span>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
          <p className="text-muted-foreground text-sm">Comprehensive server configuration</p>
        </div>
        <Button variant="outline" size="sm" onClick={loadConfig}>
          <RefreshCw className="h-4 w-4 mr-2" /> Refresh
        </Button>
      </div>

      <Tabs value={activeTab} onValueChange={(v: string) => setActiveTab(v as TabId)} className="w-full">
        <TabsList className="grid w-full grid-cols-4 lg:grid-cols-8">
          {TABS.map(tab => (
            <TabsTrigger key={tab.id} value={tab.id} className="gap-1.5 text-xs">
              {tab.icon}
              <span className="hidden sm:inline">{tab.label}</span>
            </TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value="general" className="mt-4 space-y-4">
          <GeneralSettings config={config} />
        </TabsContent>

        <TabsContent value="dns" className="mt-4 space-y-4">
          <DNSSettings config={config} />
        </TabsContent>

        <TabsContent value="upstream" className="mt-4 space-y-4">
          <UpstreamSettings config={config} />
        </TabsContent>

        <TabsContent value="cache" className="mt-4 space-y-4">
          <CacheSettings config={config} />
        </TabsContent>

        <TabsContent value="security" className="mt-4 space-y-4">
          <SecuritySettings config={config} />
        </TabsContent>

        <TabsContent value="logging" className="mt-4 space-y-4">
          <LoggingSettings config={config} />
        </TabsContent>

        <TabsContent value="cluster" className="mt-4 space-y-4">
          <ClusterSettings config={config} />
        </TabsContent>

        <TabsContent value="advanced" className="mt-4 space-y-4">
          <AdvancedSettings config={config} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// Section header helper
function SectionHeader({ title, description, icon }: { title: string; description?: string; icon: ReactNode }) {
  return (
    <CardHeader className="pb-3">
      <div className="flex items-center gap-2">
        <div className="p-1.5 rounded-md bg-primary/10 text-primary">{icon}</div>
        <div>
          <CardTitle className="text-base">{title}</CardTitle>
          {description && <CardDescription className="text-xs">{description}</CardDescription>}
        </div>
      </div>
    </CardHeader>
  );
}

// Key-value display row
function KVRow({ label, value, mono }: { label: string; value: string | number | boolean | undefined; mono?: boolean }) {
  if (value === undefined || value === null) return null;
  const displayValue = typeof value === 'boolean' ? (value ? 'Enabled' : 'Disabled') : String(value);
  return (
    <div className="flex justify-between items-center py-1.5 border-b border-border/50 last:border-0">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className={`text-sm font-medium ${mono ? 'font-mono' : ''}`}>{displayValue}</span>
    </div>
  );
}

// GENERAL SETTINGS
function GeneralSettings({ config }: { config: ServerConfig }) {
  const server = config.Server;
  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader title="Server Bind" description="DNS server listen addresses" icon={<Server className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Bind Addresses" value={server?.Bind?.join(', ') || '-'} mono />
          <KVRow label="TCP Bind" value={server?.TCPBind?.join(', ') || 'default'} mono />
          <KVRow label="UDP Bind" value={server?.UDPBind?.join(', ') || 'default'} mono />
          <KVRow label="Port" value={server?.Port || 53} />
          <KVRow label="UDP Workers" value={server?.UDPWorkers || 'auto'} />
          <KVRow label="TCP Workers" value={server?.TCPWorkers || 'auto'} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="TLS (DoT)" description="DNS over TLS configuration" icon={<Lock className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Status" value={server?.TLS?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Bind" value={server?.TLS?.Bind || '-'} mono />
          <KVRow label="Cert File" value={server?.TLS?.CertFile || '-'} mono />
          <KVRow label="Key File" value={server?.TLS?.KeyFile ? '(set)' : '-'} mono />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="QUIC (DoQ)" description="DNS over QUIC (RFC 9250)" icon={<Zap className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Status" value={server?.QUIC?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Bind" value={server?.QUIC?.Bind || '-'} mono />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="HTTP API & DoH" description="REST API and DNS over HTTPS" icon={<Globe className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="HTTP API" value={server?.HTTP?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Bind" value={server?.HTTP?.Bind || '-'} mono />
          <KVRow label="DoH" value={server?.HTTP?.DoHEnabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="DoH Path" value={server?.HTTP?.DoHPath || '/dns-query'} mono />
          <KVRow label="DoWS" value={server?.HTTP?.DoWSEnabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="DoWS Path" value={server?.HTTP?.DoWSPath || '/dns-ws'} mono />
          <KVRow label="ODoH" value={server?.HTTP?.ODoHEnabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="ODoH Path" value={server?.HTTP?.ODoHPath || '/odoh'} mono />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="Zones" description="Zone file configuration" icon={<FileText className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Zone Directory" value={config.ZoneDir || './zones/'} mono />
          <KVRow label="Zone Files" value={config.Zones?.length || 0} />
          {config.Zones?.map((z, i) => <KVRow key={i} label={`  ${i + 1}.`} value={z} mono />)}
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="Resource Limits" description="Memory and shutdown settings" icon={<HardDrive className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Memory Limit" value={config.MemoryLimitMB ? `${config.MemoryLimitMB} MB` : 'Unlimited'} />
          <KVRow label="Shutdown Timeout" value={config.ShutdownTimeout || '30s'} />
        </CardContent>
      </Card>
    </div>
  );
}

// DNS SETTINGS
function DNSSettings({ config }: { config: ServerConfig }) {
  const resolution = config.Resolution;
  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader title="Resolution" description="DNS resolution behavior" icon={<Globe className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Recursive" value={resolution?.Recursive ? 'Enabled' : 'Disabled'} />
          <KVRow label="Root Hints" value={resolution?.RootHints || '-'} mono />
          <KVRow label="Max Depth" value={resolution?.MaxDepth || 10} />
          <KVRow label="Timeout" value={resolution?.Timeout || '5s'} />
          <KVRow label="EDNS0 Buffer Size" value={resolution?.EDNS0BufferSize || 4096} />
          <KVRow label="QNAME Minimization" value={resolution?.QnameMinimization ? 'Enabled' : 'Disabled'} />
          <KVRow label="0x20 Encoding" value={resolution?.Use0x20 ? 'Enabled' : 'Disabled'} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="Metrics" description="Prometheus metrics endpoint" icon={<Activity className="h-4 w-4" />} />
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
    </div>
  );
}

// UPSTREAM SETTINGS
function UpstreamSettings({ config }: { config: ServerConfig }) {
  const upstream = config.Upstream;
  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader title="Upstream Servers" description="Recursive resolution upstreams" icon={<Network className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Strategy" value={upstream?.Strategy || 'random'} />
          <KVRow label="Health Check" value={upstream?.HealthCheck || '30s'} />
          <KVRow label="Failover Timeout" value={upstream?.FailoverTimeout || '5s'} />
          {upstream?.Servers?.map((s, i) => <KVRow key={i} label={`Server ${i + 1}`} value={s} mono />)}
        </CardContent>
      </Card>

      {upstream?.AnycastGroups && upstream.AnycastGroups.length > 0 && (
        <Card>
          <SectionHeader title="Anycast Groups" description="Geographic load balancing" icon={<Globe className="h-4 w-4" />} />
          <CardContent className="space-y-4">
            {upstream.AnycastGroups.map((ag, i) => (
              <div key={i} className="p-3 rounded-lg bg-muted/50 space-y-2">
                <div className="font-medium text-sm flex items-center gap-2">
                  <Badge variant="outline">{ag.AnycastIP}</Badge>
                </div>
                {ag.Backends?.map((b, j) => (
                  <div key={j} className="pl-3 border-l-2 border-border space-y-0.5">
                    <KVRow label="Backend" value={`${b.PhysicalIP}:${b.Port}`} mono />
                    <KVRow label="Region/Zone" value={`${b.Region || '-'}/${b.Zone || '-'}`} />
                    <KVRow label="Weight" value={b.Weight} />
                  </div>
                ))}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {upstream?.Topology && (
        <Card>
          <SectionHeader title="Topology" description="This node's location" icon={<Globe className="h-4 w-4" />} />
          <CardContent className="space-y-1">
            <KVRow label="Region" value={upstream.Topology.Region || '-'} />
            <KVRow label="Zone" value={upstream.Topology.Zone || '-'} />
            <KVRow label="Weight" value={upstream.Topology.Weight} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// CACHE SETTINGS
function CacheSettings({ config }: { config: ServerConfig }) {
  const cache = config.Cache;
  const updateCache = useUpdateCacheConfig();
  const [cacheEnabled, setCacheEnabled] = useState(cache?.Enabled ?? true);
  const [cacheSize, setCacheSize] = useState(String(cache?.Size ?? 10000));
  const [defaultTTL, setDefaultTTL] = useState(String(cache?.DefaultTTL ?? 300));
  const [maxTTL, setMaxTTL] = useState(String(cache?.MaxTTL ?? 86400));
  const [minTTL, setMinTTL] = useState(String(cache?.MinTTL ?? 5));
  const [negativeTTL, setNegativeTTL] = useState(String(cache?.NegativeTTL ?? 60));
  const [prefetch, setPrefetch] = useState(cache?.Prefetch ?? false);
  const [prefetchThreshold, setPrefetchThreshold] = useState(String(cache?.PrefetchThreshold ?? 60));
  const [serveStale, setServeStale] = useState(cache?.ServeStale ?? false);
  const [staleGrace, setStaleGrace] = useState(String(cache?.StaleGraceSecs ?? 86400));

  useEffect(() => {
    setCacheEnabled(cache?.Enabled ?? true);
    setCacheSize(String(cache?.Size ?? 10000));
    setDefaultTTL(String(cache?.DefaultTTL ?? 300));
    setMaxTTL(String(cache?.MaxTTL ?? 86400));
    setMinTTL(String(cache?.MinTTL ?? 5));
    setNegativeTTL(String(cache?.NegativeTTL ?? 60));
    setPrefetch(cache?.Prefetch ?? false);
    setPrefetchThreshold(String(cache?.PrefetchThreshold ?? 60));
    setServeStale(cache?.ServeStale ?? false);
    setStaleGrace(String(cache?.StaleGraceSecs ?? 86400));
  }, [cache]);

  const handleSave = async () => {
    await updateCache.mutateAsync({
      enabled: cacheEnabled,
      size: parseInt(cacheSize) || 10000,
      default_ttl: parseInt(defaultTTL) || 300,
      max_ttl: parseInt(maxTTL) || 86400,
      min_ttl: parseInt(minTTL) || 5,
      negative_ttl: parseInt(negativeTTL) || 60,
      prefetch: prefetch,
      prefetch_threshold: parseInt(prefetchThreshold) || 60,
      serve_stale: serveStale,
      stale_grace_secs: parseInt(staleGrace) || 86400,
    });
  };

  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader title="Cache Configuration" description="DNS response caching" icon={<Database className="h-4 w-4" />} />
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <Label>Enabled</Label>
            <Switch checked={cacheEnabled} onCheckedChange={setCacheEnabled} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Max Size</Label>
              <Input type="number" value={cacheSize} onChange={(e) => setCacheSize(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label>Default TTL (seconds)</Label>
              <Input type="number" value={defaultTTL} onChange={(e) => setDefaultTTL(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label>Max TTL (seconds)</Label>
              <Input type="number" value={maxTTL} onChange={(e) => setMaxTTL(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label>Min TTL (seconds)</Label>
              <Input type="number" value={minTTL} onChange={(e) => setMinTTL(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label>Negative TTL (seconds)</Label>
              <Input type="number" value={negativeTTL} onChange={(e) => setNegativeTTL(e.target.value)} />
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="Prefetch & Stale" description="Cache optimization features" icon={<Zap className="h-4 w-4" />} />
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <Label>Prefetch</Label>
            <Switch checked={prefetch} onCheckedChange={setPrefetch} />
          </div>
          <div className="space-y-2">
            <Label>Prefetch Threshold (seconds)</Label>
            <Input type="number" value={prefetchThreshold} onChange={(e) => setPrefetchThreshold(e.target.value)} disabled={!prefetch} />
          </div>
          <div className="flex items-center justify-between">
            <Label>Serve Stale</Label>
            <Switch checked={serveStale} onCheckedChange={setServeStale} />
          </div>
          <div className="space-y-2">
            <Label>Stale Grace Period (seconds)</Label>
            <Input type="number" value={staleGrace} onChange={(e) => setStaleGrace(e.target.value)} disabled={!serveStale} />
          </div>
          <div className="flex justify-end">
            <Button size="sm" onClick={handleSave} disabled={updateCache.isPending}>
              <Save className="h-4 w-4 mr-2" />
              {updateCache.isPending ? 'Saving...' : 'Save'}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// SECURITY SETTINGS
function SecuritySettings({ config }: { config: ServerConfig }) {
  const dnssec = config.DNSSEC;
  const acl = config.ACL;
  const rrl = config.RRL;
  const updateRRL = useUpdateRRLConfig();
  const [rrlEnabled, setRrlEnabled] = useState(rrl?.Enabled ?? false);
  const [rrlRate, setRrlRate] = useState(String(rrl?.Rate ?? 5));
  const [rrlBurst, setRrlBurst] = useState(String(rrl?.Burst ?? 20));

  useEffect(() => {
    setRrlEnabled(rrl?.Enabled ?? false);
    setRrlRate(String(rrl?.Rate ?? 5));
    setRrlBurst(String(rrl?.Burst ?? 20));
  }, [rrl?.Enabled, rrl?.Rate, rrl?.Burst]);

  const handleSaveRRL = async () => {
    await updateRRL.mutateAsync({
      enabled: rrlEnabled,
      rate: parseFloat(rrlRate) || 5,
      burst: parseInt(rrlBurst, 10) || 20,
    });
  };

  return (
    <div className="space-y-4">
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
        <SectionHeader title="Rate Limiting (RRL)" description="Response rate limiting" icon={<Activity className="h-4 w-4" />} />
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <Label>Enabled</Label>
            <Switch checked={rrlEnabled} onCheckedChange={setRrlEnabled} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Rate (resp/s)</Label>
              <Input type="number" value={rrlRate} onChange={(e) => setRrlRate(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label>Burst</Label>
              <Input type="number" value={rrlBurst} onChange={(e) => setRrlBurst(e.target.value)} />
            </div>
          </div>
          <div className="flex justify-end">
            <Button size="sm" onClick={handleSaveRRL} disabled={updateRRL.isPending}>
              <Save className="h-4 w-4 mr-2" />
              {updateRRL.isPending ? 'Saving...' : 'Save'}
            </Button>
          </div>
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

// LOGGING SETTINGS
function LoggingSettings({ config }: { config: ServerConfig }) {
  const logging = config.Logging;
  const updateLogging = useUpdateLoggingConfig();
  const [level, setLevel] = useState(logging?.Level || 'info');

  useEffect(() => {
    setLevel(logging?.Level || 'info');
  }, [logging?.Level]);

  const handleSave = async () => {
    await updateLogging.mutateAsync({ level });
  };

  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader title="Logging" description="Server logging configuration" icon={<FileText className="h-4 w-4" />} />
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Level</Label>
            <div className="flex items-center gap-2">
              <Select value={level} onValueChange={setLevel}>
                <SelectTrigger className="w-40">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="debug">debug</SelectItem>
                  <SelectItem value="info">info</SelectItem>
                  <SelectItem value="warn">warn</SelectItem>
                  <SelectItem value="error">error</SelectItem>
                  <SelectItem value="fatal">fatal</SelectItem>
                </SelectContent>
              </Select>
              <Button size="sm" onClick={handleSave} disabled={updateLogging.isPending}>
                <Save className="h-4 w-4 mr-2" />
                {updateLogging.isPending ? 'Saving...' : 'Save'}
              </Button>
            </div>
          </div>
          <KVRow label="Format" value={logging?.Format || 'text'} />
          <KVRow label="Output" value={logging?.Output || 'stdout'} />
          <KVRow label="Query Log" value={logging?.QueryLog ? 'Enabled' : 'Disabled'} />
          <KVRow label="Query Log File" value={logging?.QueryLogFile || '-'} mono />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="DNSSEC Validation" description="DNS cookie mechanism (RFC 7873)" icon={<Shield className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="DNS Cookie" value={config.Cookie?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Secret Rotation" value={config.Cookie?.SecretRotation || '1h'} />
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

// CLUSTER SETTINGS
function ClusterSettings({ config }: { config: ServerConfig }) {
  const cluster = config.Cluster;
  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader title="Cluster" description="Gossip-based clustering" icon={<Users className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={cluster?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Node ID" value={cluster?.NodeID || 'auto'} mono />
          <KVRow label="Bind Address" value={cluster?.BindAddr || '-'} mono />
          <KVRow label="Gossip Port" value={cluster?.GossipPort || 7946} />
          <KVRow label="Region" value={cluster?.Region || '-'} />
          <KVRow label="Zone" value={cluster?.Zone || '-'} />
          <KVRow label="Weight" value={cluster?.Weight || 100} />
          <KVRow label="Cache Sync" value={cluster?.CacheSync ? 'Enabled' : 'Disabled'} />
          <KVRow label="Encryption" value={cluster?.EncryptionKey ? 'Enabled (AES-256-GCM)' : 'Disabled'} />
        </CardContent>
      </Card>

      {cluster?.SeedNodes && cluster.SeedNodes.length > 0 && (
        <Card>
          <SectionHeader title="Seed Nodes" description="Initial cluster peers" icon={<Network className="h-4 w-4" />} />
          <CardContent className="space-y-1">
            {cluster.SeedNodes.map((n, i) => <KVRow key={i} label={`Node ${i + 1}`} value={n} mono />)}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ADVANCED SETTINGS
function AdvancedSettings({ config }: { config: ServerConfig }) {
  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader title="Blocklist" description="Domain blocking" icon={<Shield className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.Blocklist?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Files" value={config.Blocklist?.Files?.length || 0} />
          <KVRow label="URLs" value={config.Blocklist?.URLs?.length || 0} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="RPZ" description="Response Policy Zones" icon={<Shield className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.RPZ?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Files" value={config.RPZ?.Files?.length || 0} />
          <KVRow label="Policy Zones" value={config.RPZ?.Zones?.length || 0} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="GeoDNS" description="Geographic DNS routing" icon={<Globe className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.GeoDNS?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="MMDB File" value={config.GeoDNS?.MMDBFile || '-'} mono />
          <KVRow label="Rules" value={config.GeoDNS?.Rules?.length || 0} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="DNS64" description="NAT64 translation (RFC 6140)" icon={<Network className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.DNS64?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Prefix" value={config.DNS64?.Prefix || '64:ff9b::'} mono />
          <KVRow label="Prefix Length" value={config.DNS64?.PrefixLen || 96} />
          <KVRow label="Exclude Networks" value={config.DNS64?.ExcludeNets?.join(', ') || '-'} mono />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="mDNS" description="Multicast DNS (RFC 6762)" icon={<Network className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.MDNS?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Multicast IP" value={config.MDNS?.MulticastIP || '224.0.0.251'} mono />
          <KVRow label="Port" value={config.MDNS?.Port || 5353} />
          <KVRow label="Browser" value={config.MDNS?.Browser ? 'Enabled' : 'Disabled'} />
          <KVRow label="Hostname" value={config.MDNS?.HostName || '-'} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="ODoH" description="Oblivious DNS over HTTPS (RFC 9230)" icon={<Lock className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.ODoH?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Bind" value={config.ODoH?.Bind || '-'} mono />
          <KVRow label="Target URL" value={config.ODoH?.TargetURL || '-'} mono />
          <KVRow label="Proxy URL" value={config.ODoH?.ProxyURL || '-'} mono />
          <KVRow label="KEM" value={config.ODoH?.KEM || 4} />
          <KVRow label="KDF" value={config.ODoH?.KDF || 1} />
          <KVRow label="AEAD" value={config.ODoH?.AEAD || 1} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="Catalog Zones" description="Zone catalog (RFC 9432)" icon={<FileText className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.Catalog?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Catalog Zone" value={config.Catalog?.CatalogZone || 'catalog.inbound.'} mono />
          <KVRow label="Producer Class" value={config.Catalog?.ProducerClass || 'CLDNSET'} />
          <KVRow label="Consumer Class" value={config.Catalog?.ConsumerClass || 'CLDNSET'} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="DSO" description="DNS Stateful Operations (RFC 1034)" icon={<Database className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.DSO?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Session Timeout" value={config.DSO?.SessionTimeout || '10m'} />
          <KVRow label="Max Sessions" value={config.DSO?.MaxSessions || 10000} />
          <KVRow label="Heartbeat Interval" value={config.DSO?.HeartbeatInterval || '1m'} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="YANG" description="NETCONF/YANG models (RFC 9094)" icon={<Key className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.YANG?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="CLI" value={config.YANG?.EnableCLI ? 'Enabled' : 'Disabled'} />
          <KVRow label="NETCONF" value={config.YANG?.EnableNETCONF ? 'Enabled' : 'Disabled'} />
          <KVRow label="NETCONF Bind" value={config.YANG?.NETCONFBind || '-'} mono />
          <KVRow label="Models" value={config.YANG?.Models?.join(', ') || '-'} />
        </CardContent>
      </Card>
    </div>
  );
}
