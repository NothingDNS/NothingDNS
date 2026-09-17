import type { ReactNode } from 'react';
import {
  Server, Network, Database, Shield, Globe,
  Users, FileText, Zap,
} from 'lucide-react';

export interface ServerConfig {
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
    AuthoritativeOnly?: boolean;
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
  RRL: { Enabled: boolean; Rate: number; Burst: number; MaxBuckets?: number };
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

export type TabId = 'general' | 'dns' | 'upstream' | 'cache' | 'security' | 'logging' | 'cluster' | 'advanced';

export const TABS: { id: TabId; label: string; icon: ReactNode }[] = [
  { id: 'general', label: 'General', icon: <Server className="h-4 w-4" /> },
  { id: 'dns', label: 'DNS', icon: <Globe className="h-4 w-4" /> },
  { id: 'upstream', label: 'Upstream', icon: <Network className="h-4 w-4" /> },
  { id: 'cache', label: 'Cache', icon: <Database className="h-4 w-4" /> },
  { id: 'security', label: 'Security', icon: <Shield className="h-4 w-4" /> },
  { id: 'logging', label: 'Logging', icon: <FileText className="h-4 w-4" /> },
  { id: 'cluster', label: 'Cluster', icon: <Users className="h-4 w-4" /> },
  { id: 'advanced', label: 'Advanced', icon: <Zap className="h-4 w-4" /> },
];
