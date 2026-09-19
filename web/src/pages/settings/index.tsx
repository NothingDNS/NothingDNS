import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { api } from '@/lib/api';
import { toast } from 'sonner';
import { RefreshCw, AlertCircle, RotateCcw } from 'lucide-react';
import { type ServerConfig, type TabId, TABS } from './types';
import { GeneralSettings } from './general-settings';
import { DNSSettings } from './dns-settings';
import { UpstreamSettings } from './upstream-settings';
import { CacheSettings } from './cache-settings';
import { SecuritySettings } from './security-settings';
import { LoggingSettings } from './logging-settings';
import { ClusterSettings } from './cluster-settings';
import { AdvancedSettings } from './advanced-settings';

export function SettingsPage() {
  const [config, setConfig] = useState<ServerConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('general');
  const [reloading, setReloading] = useState(false);

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

  useEffect(() => {
    loadConfig();
  }, []);

  const reloadRuntimeConfig = async () => {
    setReloading(true);
    try {
      await api('POST', '/api/v1/config/reload');
      await loadConfig();
      toast.success('Configuration reloaded');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to reload configuration');
    } finally {
      setReloading(false);
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
        <div className="flex items-center justify-center h-48 gap-3 rounded-lg border">
          <AlertCircle className="h-5 w-5 text-destructive" />
          <span className="text-destructive">{error || 'Failed to load configuration'}</span>
        </div>
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
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={loadConfig}>
            <RefreshCw className="h-4 w-4 mr-2" /> Refresh
          </Button>
          <Button size="sm" onClick={reloadRuntimeConfig} disabled={reloading}>
            <RotateCcw className="h-4 w-4 mr-2" /> {reloading ? 'Reloading...' : 'Reload Config'}
          </Button>
        </div>
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
          <DNSSettings config={config} onReload={loadConfig} />
        </TabsContent>
        <TabsContent value="upstream" className="mt-4 space-y-4">
          <UpstreamSettings config={config} onReload={loadConfig} />
        </TabsContent>
        <TabsContent value="cache" className="mt-4 space-y-4">
          <CacheSettings config={config} onReload={loadConfig} />
        </TabsContent>
        <TabsContent value="security" className="mt-4 space-y-4">
          <SecuritySettings config={config} onReload={loadConfig} />
        </TabsContent>
        <TabsContent value="logging" className="mt-4 space-y-4">
          <LoggingSettings config={config} onReload={loadConfig} />
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
