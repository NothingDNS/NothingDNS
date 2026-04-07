import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { api } from '@/lib/api';
import {
  Server, Network, Database, Shield, Globe, HardDrive, Zap,
  Lock, Key, Users, FileText, Activity, RefreshCw, AlertCircle
} from 'lucide-react';

// Full config type matching internal/config/config.go
interface ServerConfig {
  server: {
    bind: string[];
    tcp_bind: string[];
    udp_bind: string[];
    port: number;
    udp_workers: number;
    tcp_workers: number;
    tls: { enabled: boolean; cert_file: string; key_file: string; bind: string };
    quic: { enabled: boolean; cert_file: string; key_file: string; bind: string };
    http: {
      enabled: boolean;
      bind: string;
      auth_token: string;
      doh_enabled: boolean;
      doh_path: string;
      dows_enabled: boolean;
      dows_path: string;
      odoh_enabled: boolean;
      odoh_path: string;
    };
  };
  cluster: {
    enabled: boolean;
    node_id: string;
    bind_addr: string;
    gossip_port: number;
    region: string;
    zone: string;
    weight: number;
    seed_nodes: string[];
    cache_sync: boolean;
    encryption_key: string;
  };
  resolution: {
    recursive: boolean;
    root_hints: string;
    max_depth: number;
    timeout: string;
    edns0_buffer_size: number;
    qname_minimization: boolean;
    use_0x20: boolean;
  };
  upstream: {
    servers: string[];
    strategy: string;
    health_check: string;
    failover_timeout: string;
    anycast_groups: Array<{
      anycast_ip: string;
      backends: Array<{
        physical_ip: string;
        port: number;
        region: string;
        zone: string;
        weight: number;
      }>;
    }>;
    topology: { region: string; zone: string; weight: number };
  };
  cache: {
    enabled: boolean;
    size: number;
    default_ttl: number;
    max_ttl: number;
    min_ttl: number;
    negative_ttl: number;
    prefetch: boolean;
    prefetch_threshold: number;
    serve_stale: boolean;
    stale_grace_secs: number;
  };
  logging: {
    level: string;
    format: string;
    output: string;
    query_log: boolean;
    query_log_file: string;
  };
  metrics: {
    enabled: boolean;
    bind: string;
    path: string;
  };
  dnssec: {
    enabled: boolean;
    trust_anchor: string;
    ignore_time: boolean;
    require_dnssec: boolean;
    signing: {
      enabled: boolean;
      signature_validity: string;
      keys: Array<{ private_key: string; type: string; algorithm: number }>;
      nsec3: { iterations: number; salt: string; opt_out: boolean } | null;
    };
  };
  zones: string[];
  zone_dir: string;
  acl: Array<{ name: string; networks: string[]; types: string[]; action: string; redirect: string }>;
  rrl: { enabled: boolean; rate: number; burst: number };
  blocklist: { enabled: boolean; files: string[]; urls: string[] };
  rpz: {
    enabled: boolean;
    files: string[];
    zones: Array<{ name: string; file: string; priority: number }>;
  };
  geodns: { enabled: boolean; mmdb_file: string; rules: Array<{ domain: string; type: string; default: string; records: Record<string, string> }> };
  dns64: { enabled: boolean; prefix: string; prefix_len: number; exclude_nets: string[] };
  cookie: { enabled: boolean; secret_rotation: string };
  idna: { enabled: boolean; use_std3_rules: boolean; allow_unassigned: boolean; check_bidi: boolean; check_joiner: boolean };
  odoh: { enabled: boolean; bind: string; target_url: string; proxy_url: string; kem: number; kdf: number; aead: number };
  mdns: { enabled: boolean; multicast_ip: string; port: number; browser: boolean; hostname: string };
  catalog: { enabled: boolean; catalog_zone: string; producer_class: string; consumer_class: string };
  dso: { enabled: boolean; session_timeout: string; max_sessions: number; heartbeat_interval: string };
  yang: { enabled: boolean; enable_cli: boolean; enable_netconf: boolean; netconf_bind: string; models: string[] };
  slave_zones: Array<{
    zone_name: string;
    masters: string[];
    transfer_type: string;
    tsig_key_name: string;
    tsig_secret: string;
    timeout: string;
    retry_interval: string;
    max_retries: number;
  }>;
  views: Array<{ name: string; match_clients: string[]; zone_files: string[] }>;
  memory_limit_mb: number;
  shutdown_timeout: string;
}

type TabId = 'general' | 'dns' | 'upstream' | 'cache' | 'security' | 'logging' | 'cluster' | 'advanced';

const TABS: { id: TabId; label: string; icon: React.ReactNode }[] = [
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
function SectionHeader({ title, description, icon }: { title: string; description?: string; icon: React.ReactNode }) {
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
  const { server } = config;
  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader title="Server Bind" description="DNS server listen addresses" icon={<Server className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Bind Addresses" value={server.bind?.join(', ') || '-'} mono />
          <KVRow label="TCP Bind" value={server.tcp_bind?.join(', ') || 'default'} mono />
          <KVRow label="UDP Bind" value={server.udp_bind?.join(', ') || 'default'} mono />
          <KVRow label="Port" value={server.port || 53} />
          <KVRow label="UDP Workers" value={server.udp_workers || 'auto'} />
          <KVRow label="TCP Workers" value={server.tcp_workers || 'auto'} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="TLS (DoT)" description="DNS over TLS configuration" icon={<Lock className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Status" value={server.tls?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Bind" value={server.tls?.bind || '-'} mono />
          <KVRow label="Cert File" value={server.tls?.cert_file || '-'} mono />
          <KVRow label="Key File" value={server.tls?.key_file ? '(set)' : '-'} mono />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="QUIC (DoQ)" description="DNS over QUIC (RFC 9250)" icon={<Zap className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Status" value={server.quic?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Bind" value={server.quic?.bind || '-'} mono />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="HTTP API & DoH" description="REST API and DNS over HTTPS" icon={<Globe className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="HTTP API" value={server.http?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Bind" value={server.http?.bind || '-'} mono />
          <KVRow label="DoH" value={server.http?.doh_enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="DoH Path" value={server.http?.doh_path || '/dns-query'} mono />
          <KVRow label="DoWS" value={server.http?.dows_enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="DoWS Path" value={server.http?.dows_path || '/dns-ws'} mono />
          <KVRow label="ODoH" value={server.http?.odoh_enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="ODoH Path" value={server.http?.odoh_path || '/odoh'} mono />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="Zones" description="Zone file configuration" icon={<FileText className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Zone Directory" value={config.zone_dir || './zones/'} mono />
          <KVRow label="Zone Files" value={config.zones?.length || 0} />
          {config.zones?.map((z, i) => <KVRow key={i} label={`  ${i + 1}.`} value={z} mono />)}
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="Resource Limits" description="Memory and shutdown settings" icon={<HardDrive className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Memory Limit" value={config.memory_limit_mb ? `${config.memory_limit_mb} MB` : 'Unlimited'} />
          <KVRow label="Shutdown Timeout" value={config.shutdown_timeout || '30s'} />
        </CardContent>
      </Card>
    </div>
  );
}

// DNS SETTINGS
function DNSSettings({ config }: { config: ServerConfig }) {
  const { resolution } = config;
  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader title="Resolution" description="DNS resolution behavior" icon={<Globe className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Recursive" value={resolution?.recursive ? 'Enabled' : 'Disabled'} />
          <KVRow label="Root Hints" value={resolution?.root_hints || '-'} mono />
          <KVRow label="Max Depth" value={resolution?.max_depth || 10} />
          <KVRow label="Timeout" value={resolution?.timeout || '5s'} />
          <KVRow label="EDNS0 Buffer Size" value={resolution?.edns0_buffer_size || 4096} />
          <KVRow label="QNAME Minimization" value={resolution?.qname_minimization ? 'Enabled' : 'Disabled'} />
          <KVRow label="0x20 Encoding" value={resolution?.use_0x20 ? 'Enabled' : 'Disabled'} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="Metrics" description="Prometheus metrics endpoint" icon={<Activity className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Status" value={config.metrics?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Bind" value={config.metrics?.bind || '-'} mono />
          <KVRow label="Path" value={config.metrics?.path || '/metrics'} mono />
        </CardContent>
      </Card>

      {config.views?.length > 0 && (
        <Card>
          <SectionHeader title="Split-Horizon Views" description="Client-based zone routing" icon={<Network className="h-4 w-4" />} />
          <CardContent className="space-y-3">
            {config.views.map((view, i) => (
              <div key={i} className="p-3 rounded-lg bg-muted/50 space-y-1">
                <div className="font-medium text-sm">{view.name}</div>
                <KVRow label="Match Clients" value={view.match_clients?.join(', ') || '-'} mono />
                <KVRow label="Zone Files" value={view.zone_files?.join(', ') || '-'} mono />
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {config.slave_zones?.length > 0 && (
        <Card>
          <SectionHeader title="Slave Zones" description="Zone transfer from masters" icon={<FileText className="h-4 w-4" />} />
          <CardContent className="space-y-3">
            {config.slave_zones.map((sz, i) => (
              <div key={i} className="p-3 rounded-lg bg-muted/50 space-y-1">
                <div className="font-medium text-sm">{sz.zone_name}</div>
                <KVRow label="Masters" value={sz.masters?.join(', ') || '-'} mono />
                <KVRow label="Transfer Type" value={sz.transfer_type || 'ixfr'} />
                <KVRow label="TSIG" value={sz.tsig_key_name ? 'Enabled' : 'Disabled'} />
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
  const { upstream } = config;
  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader title="Upstream Servers" description="Recursive resolution upstreams" icon={<Network className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Strategy" value={upstream?.strategy || 'random'} />
          <KVRow label="Health Check" value={upstream?.health_check || '30s'} />
          <KVRow label="Failover Timeout" value={upstream?.failover_timeout || '5s'} />
          {upstream?.servers?.map((s, i) => <KVRow key={i} label={`Server ${i + 1}`} value={s} mono />)}
        </CardContent>
      </Card>

      {upstream?.anycast_groups?.length > 0 && (
        <Card>
          <SectionHeader title="Anycast Groups" description="Geographic load balancing" icon={<Globe className="h-4 w-4" />} />
          <CardContent className="space-y-4">
            {upstream.anycast_groups.map((ag, i) => (
              <div key={i} className="p-3 rounded-lg bg-muted/50 space-y-2">
                <div className="font-medium text-sm flex items-center gap-2">
                  <Badge variant="outline">{ag.anycast_ip}</Badge>
                </div>
                {ag.backends?.map((b, j) => (
                  <div key={j} className="pl-3 border-l-2 border-border space-y-0.5">
                    <KVRow label="Backend" value={`${b.physical_ip}:${b.port}`} mono />
                    <KVRow label="Region/Zone" value={`${b.region || '-'}/${b.zone || '-'}`} />
                    <KVRow label="Weight" value={b.weight} />
                  </div>
                ))}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {upstream?.topology && (
        <Card>
          <SectionHeader title="Topology" description="This node's location" icon={<Globe className="h-4 w-4" />} />
          <CardContent className="space-y-1">
            <KVRow label="Region" value={upstream.topology.region || '-'} />
            <KVRow label="Zone" value={upstream.topology.zone || '-'} />
            <KVRow label="Weight" value={upstream.topology.weight} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// CACHE SETTINGS
function CacheSettings({ config }: { config: ServerConfig }) {
  const { cache } = config;
  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader title="Cache Configuration" description="DNS response caching" icon={<Database className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={cache?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Max Size" value={cache?.size?.toLocaleString() || 10000} />
          <KVRow label="Default TTL" value={cache?.default_ttl ? `${cache.default_ttl}s` : '300s'} />
          <KVRow label="Max TTL" value={cache?.max_ttl ? `${cache.max_ttl}s` : '86400s'} />
          <KVRow label="Min TTL" value={cache?.min_ttl ? `${cache.min_ttl}s` : '5s'} />
          <KVRow label="Negative TTL" value={cache?.negative_ttl ? `${cache.negative_ttl}s` : '60s'} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="Prefetch & Stale" description="Cache optimization features" icon={<Zap className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Prefetch" value={cache?.prefetch ? 'Enabled' : 'Disabled'} />
          <KVRow label="Prefetch Threshold" value={cache?.prefetch_threshold ? `${cache.prefetch_threshold}s` : '60s'} />
          <KVRow label="Serve Stale" value={cache?.serve_stale ? 'Enabled' : 'Disabled'} />
          <KVRow label="Stale Grace Period" value={cache?.stale_grace_secs ? `${cache.stale_grace_secs}s` : '86400s'} />
        </CardContent>
      </Card>
    </div>
  );
}

// SECURITY SETTINGS
function SecuritySettings({ config }: { config: ServerConfig }) {
  const { dnssec, acl, rrl } = config;
  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader title="DNSSEC" description="DNS Security Extensions" icon={<Shield className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Validation" value={dnssec?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Trust Anchor" value={dnssec?.trust_anchor || 'builtin'} mono />
          <KVRow label="Require DNSSEC" value={dnssec?.require_dnssec ? 'Yes' : 'No'} />
          <KVRow label="Ignore Time" value={dnssec?.ignore_time ? 'Yes' : 'No'} />
          <KVRow label="Zone Signing" value={dnssec?.signing?.enabled ? 'Enabled' : 'Disabled'} />
          {dnssec?.signing?.enabled && (
            <>
              <KVRow label="Signature Validity" value={dnssec.signing.signature_validity || '-'} />
              <KVRow label="Keys" value={dnssec.signing.keys?.length || 0} />
              <KVRow label="NSEC3" value={dnssec.signing.nsec3 ? 'Enabled' : 'NSEC'} />
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
                {rule.name || `Rule ${i + 1}`}
                <Badge variant={rule.action === 'allow' ? 'success' : rule.action === 'deny' ? 'destructive' : 'outline'}>{rule.action}</Badge>
              </div>
              <KVRow label="Networks" value={rule.networks?.join(', ') || '-'} mono />
              <KVRow label="Types" value={rule.types?.join(', ') || 'all'} />
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="Rate Limiting (RRL)" description="Response rate limiting" icon={<Activity className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={rrl?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Rate" value={rrl?.rate ? `${rrl.rate} resp/s` : '5 resp/s'} />
          <KVRow label="Burst" value={rrl?.burst || 20} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="IDNA" description="Internationalized Domain Names (RFC 5891)" icon={<Globe className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.idna?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="STD3 Rules" value={config.idna?.use_std3_rules ? 'Yes' : 'No'} />
          <KVRow label="Allow Unassigned" value={config.idna?.allow_unassigned ? 'Yes' : 'No'} />
          <KVRow label="Check Bidi" value={config.idna?.check_bidi ? 'Yes' : 'No'} />
          <KVRow label="Check Joiner" value={config.idna?.check_joiner ? 'Yes' : 'No'} />
        </CardContent>
      </Card>
    </div>
  );
}

// LOGGING SETTINGS
function LoggingSettings({ config }: { config: ServerConfig }) {
  const { logging } = config;
  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader title="Logging" description="Server logging configuration" icon={<FileText className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Level" value={logging?.level || 'info'} />
          <KVRow label="Format" value={logging?.format || 'text'} />
          <KVRow label="Output" value={logging?.output || 'stdout'} />
          <KVRow label="Query Log" value={logging?.query_log ? 'Enabled' : 'Disabled'} />
          <KVRow label="Query Log File" value={logging?.query_log_file || '-'} mono />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="DNSSEC Validation" description="DNS cookie mechanism (RFC 7873)" icon={<Shield className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="DNS Cookie" value={config.cookie?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Secret Rotation" value={config.cookie?.secret_rotation || '1h'} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="Audit" description="Configuration change audit" icon={<Activity className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Audit Log" value={logging?.query_log ? 'Enabled (via query log)' : 'Disabled'} />
        </CardContent>
      </Card>
    </div>
  );
}

// CLUSTER SETTINGS
function ClusterSettings({ config }: { config: ServerConfig }) {
  const { cluster } = config;
  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader title="Cluster" description="Gossip-based clustering" icon={<Users className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={cluster?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Node ID" value={cluster?.node_id || 'auto'} mono />
          <KVRow label="Bind Address" value={cluster?.bind_addr || '-'} mono />
          <KVRow label="Gossip Port" value={cluster?.gossip_port || 7946} />
          <KVRow label="Region" value={cluster?.region || '-'} />
          <KVRow label="Zone" value={cluster?.zone || '-'} />
          <KVRow label="Weight" value={cluster?.weight || 100} />
          <KVRow label="Cache Sync" value={cluster?.cache_sync ? 'Enabled' : 'Disabled'} />
          <KVRow label="Encryption" value={cluster?.encryption_key ? 'Enabled (AES-256-GCM)' : 'Disabled'} />
        </CardContent>
      </Card>

      {cluster?.seed_nodes?.length > 0 && (
        <Card>
          <SectionHeader title="Seed Nodes" description="Initial cluster peers" icon={<Network className="h-4 w-4" />} />
          <CardContent className="space-y-1">
            {cluster.seed_nodes.map((n, i) => <KVRow key={i} label={`Node ${i + 1}`} value={n} mono />)}
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
          <KVRow label="Enabled" value={config.blocklist?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Files" value={config.blocklist?.files?.length || 0} />
          <KVRow label="URLs" value={config.blocklist?.urls?.length || 0} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="RPZ" description="Response Policy Zones" icon={<Shield className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.rpz?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Files" value={config.rpz?.files?.length || 0} />
          <KVRow label="Policy Zones" value={config.rpz?.zones?.length || 0} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="GeoDNS" description="Geographic DNS routing" icon={<Globe className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.geodns?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="MMDB File" value={config.geodns?.mmdb_file || '-'} mono />
          <KVRow label="Rules" value={config.geodns?.rules?.length || 0} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="DNS64" description="NAT64 translation (RFC 6140)" icon={<Network className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.dns64?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Prefix" value={config.dns64?.prefix || '64:ff9b::'} mono />
          <KVRow label="Prefix Length" value={config.dns64?.prefix_len || 96} />
          <KVRow label="Exclude Networks" value={config.dns64?.exclude_nets?.join(', ') || '-'} mono />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="mDNS" description="Multicast DNS (RFC 6762)" icon={<Network className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.mdns?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Multicast IP" value={config.mdns?.multicast_ip || '224.0.0.251'} mono />
          <KVRow label="Port" value={config.mdns?.port || 5353} />
          <KVRow label="Browser" value={config.mdns?.browser ? 'Enabled' : 'Disabled'} />
          <KVRow label="Hostname" value={config.mdns?.hostname || '-'} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="ODoH" description="Oblivious DNS over HTTPS (RFC 9230)" icon={<Lock className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.odoh?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Bind" value={config.odoh?.bind || '-'} mono />
          <KVRow label="Target URL" value={config.odoh?.target_url || '-'} mono />
          <KVRow label="Proxy URL" value={config.odoh?.proxy_url || '-'} mono />
          <KVRow label="KEM" value={config.odoh?.kem || 4} />
          <KVRow label="KDF" value={config.odoh?.kdf || 1} />
          <KVRow label="AEAD" value={config.odoh?.aead || 1} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="Catalog Zones" description="Zone catalog (RFC 9432)" icon={<FileText className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.catalog?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Catalog Zone" value={config.catalog?.catalog_zone || 'catalog.inbound.'} mono />
          <KVRow label="Producer Class" value={config.catalog?.producer_class || 'CLDNSET'} />
          <KVRow label="Consumer Class" value={config.catalog?.consumer_class || 'CLDNSET'} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="DSO" description="DNS Stateful Operations (RFC 1034)" icon={<Database className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.dso?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Session Timeout" value={config.dso?.session_timeout || '10m'} />
          <KVRow label="Max Sessions" value={config.dso?.max_sessions || 10000} />
          <KVRow label="Heartbeat Interval" value={config.dso?.heartbeat_interval || '1m'} />
        </CardContent>
      </Card>

      <Card>
        <SectionHeader title="YANG" description="NETCONF/YANG models (RFC 9094)" icon={<Key className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={config.yang?.enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="CLI" value={config.yang?.enable_cli ? 'Enabled' : 'Disabled'} />
          <KVRow label="NETCONF" value={config.yang?.enable_netconf ? 'Enabled' : 'Disabled'} />
          <KVRow label="NETCONF Bind" value={config.yang?.netconf_bind || '-'} mono />
          <KVRow label="Models" value={config.yang?.models?.join(', ') || '-'} />
        </CardContent>
      </Card>
    </div>
  );
}
