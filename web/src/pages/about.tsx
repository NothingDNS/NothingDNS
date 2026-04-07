import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Globe, Shield, Zap, Server, Lock, Network, Database, Heart, ExternalLink, Layers } from 'lucide-react';
import { api } from '@/lib/api';

interface ServerInfo {
  version: string;
}

export function AboutPage() {
  const [serverInfo, setServerInfo] = useState<ServerInfo | null>(null);

  useEffect(() => {
    api<ServerInfo>('GET', '/api/v1/status')
      .then(data => setServerInfo({ version: data.version || 'unknown' }))
      .catch(() => setServerInfo({ version: 'unknown' }));
  }, []);

  const features = [
    { icon: <Globe className="h-5 w-5" />, title: 'Authoritative DNS', desc: 'Full authoritative DNS server with BIND-format zone files, SOA, NS, A, AAAA, CNAME, MX, TXT, SRV, and CAA records.' },
    { icon: <Server className="h-5 w-5" />, title: 'Multi-Transport', desc: 'UDP, TCP, TLS (DoT), and DNS-over-HTTPS (DoH) support. Full protocol compliance with RFC standards.' },
    { icon: <Shield className="h-5 w-5" />, title: 'DNSSEC', desc: 'Built-in DNSSEC validation and zone signing with KSK/ZSK key management, RRSIG, and NSEC3 support.' },
    { icon: <Database className="h-5 w-5" />, title: 'Smart Caching', desc: 'TTL-aware DNS cache with prefetch, negative caching, and cluster-wide cache synchronization.' },
    { icon: <Network className="h-5 w-5" />, title: 'Clustering', desc: 'Gossip-based cluster membership, automatic node discovery, health checking, and distributed cache invalidation.' },
    { icon: <Zap className="h-5 w-5" />, title: 'Load Balancing', desc: 'Anycast-aware upstream load balancing with weighted round-robin, geo-routing, and automatic failover.' },
    { icon: <Lock className="h-5 w-5" />, title: 'Security', desc: 'ACL-based access control, rate limiting (RRL), blocklists, TSIG-authenticated transfers, and audit logging.' },
    { icon: <Layers className="h-5 w-5" />, title: 'Zone Transfers', desc: 'AXFR/IXFR zone transfers, NOTIFY for slave sync, and Dynamic DNS Updates (RFC 2136).' },
  ];

  const arch = [
    { p: 'cmd/', d: 'Server binary and CLI companion' },
    { p: 'internal/protocol/', d: 'Custom DNS protocol parser (no miekg/dns)' },
    { p: 'internal/config/', d: 'Custom YAML parser (no gopkg.in/yaml)' },
    { p: 'internal/zone/', d: 'BIND zone file parser and manager' },
    { p: 'internal/server/', d: 'UDP, TCP, TLS, and DoH transports' },
    { p: 'web/', d: 'React dashboard (embedded into binary)' },
  ];

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      <div className="text-center py-8">
        <div className="inline-flex items-center justify-center h-20 w-20 rounded-2xl bg-primary/10 text-primary mb-6"><Globe className="h-10 w-10" /></div>
        <h1 className="text-4xl font-bold tracking-tight mb-3">NothingDNS</h1>
        <p className="text-lg text-muted-foreground max-w-xl mx-auto leading-relaxed">A zero-dependency, production-grade authoritative DNS server written in pure Go.</p>
        <div className="flex items-center justify-center gap-2 mt-4">
          <Badge variant="secondary">v{serverInfo?.version || '...'}</Badge>
          <Badge variant="outline">MIT License</Badge>
          <Badge variant="success">Production Ready</Badge>
        </div>
      </div>

      <div><h2 className="text-xl font-semibold mb-4">Features</h2><div className="grid gap-4 sm:grid-cols-2">
        {features.map(({ icon, title, desc }) => <Card key={title} className="hover:shadow-md transition-shadow"><CardContent className="flex gap-4 p-5"><div className="p-2.5 rounded-lg bg-primary/10 text-primary shrink-0">{icon}</div><div><h3 className="font-semibold text-sm mb-1">{title}</h3><p className="text-xs text-muted-foreground leading-relaxed">{desc}</p></div></CardContent></Card>)}
      </div></div>

      <Card>
        <CardHeader><CardTitle className="text-base">Architecture</CardTitle></CardHeader>
        <CardContent><div className="grid gap-3">
          {arch.map(({ p, d }) => <div key={p} className="flex items-start gap-3 p-3 rounded-lg bg-muted/50"><span className="font-mono text-xs bg-primary/10 text-primary px-2 py-0.5 rounded shrink-0">{p}</span><span className="text-sm text-muted-foreground">{d}</span></div>)}
        </div></CardContent>
      </Card>

      <div className="text-center py-8 border-t">
        <div className="flex items-center justify-center gap-1.5 text-sm text-muted-foreground">Made with <Heart className="h-3.5 w-3.5 text-destructive fill-destructive" /></div>
        <div className="mt-3 flex items-center justify-center gap-4">
          <a href="https://github.com/nothingdns/nothingdns" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-sm text-primary hover:underline"><ExternalLink className="h-3.5 w-3.5" /> GitHub</a>
        </div>
      </div>
    </div>
  );
}
