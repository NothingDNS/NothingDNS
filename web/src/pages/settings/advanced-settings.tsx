import { Shield, Globe, Network, FileText, Database, Lock, Key } from 'lucide-react';
import { type ServerConfig } from './types';
import { Card, CardContent, SectionHeader, ReadOnlyNotice, KVRow } from './shared';

export function AdvancedSettings({ config }: { config: ServerConfig }) {
  return (
    <div className="space-y-4">
      <ReadOnlyNotice title="File-backed advanced settings" />
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
        <SectionHeader title="DNS64" description="NAT64 translation (RFC 6147)" icon={<Network className="h-4 w-4" />} />
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
          <KVRow label="KEM" value={config.ODoH?.KEM || 32} />
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
        <SectionHeader title="DSO" description="DNS Stateful Operations (RFC 8490)" icon={<Database className="h-4 w-4" />} />
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
