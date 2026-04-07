import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Input } from '@/components/ui/input';
import { api, type BlocklistStatus } from '@/lib/api';
import { Shield, Plus, RefreshCw, Wifi, WifiOff } from 'lucide-react';

export function BlocklistPage() {
  const [status, setStatus] = useState<BlocklistStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(false);
  const [newFile, setNewFile] = useState('');
  const [toggling, setToggling] = useState(false);

  const fetchStatus = () => {
    api<BlocklistStatus>('GET', '/api/v1/blocklists')
      .then(setStatus)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchStatus();
    const iv = setInterval(fetchStatus, 10000);
    return () => clearInterval(iv);
  }, []);

  const handleAddFile = async () => {
    if (!newFile.trim()) return;
    setAdding(true);
    try {
      await api('POST', '/api/v1/blocklists', { file: newFile.trim() });
      setNewFile('');
      fetchStatus();
    } catch (e) {
      console.error('Failed to add blocklist:', e);
    } setAdding(false);
  };

  const handleToggle = async () => {
    setToggling(true);
    try {
      await api('POST', '/api/v1/blocklists/toggle');
      fetchStatus();
    } catch (e) {
      console.error('Failed to toggle blocklist:', e);
    } setToggling(false);
  };

  if (loading) return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">Blocklist</h1><p className="text-muted-foreground text-sm">Domain blocking configuration</p></div>
      <Skeleton className="h-48 w-full rounded-xl" />
    </div>
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div><h1 className="text-2xl font-bold tracking-tight">Blocklist</h1><p className="text-muted-foreground text-sm">Domain blocking management</p></div>
        <div className="flex items-center gap-3">
          <Badge variant={status?.enabled ? 'success' : 'secondary'} className="flex items-center gap-1">
            {status?.enabled ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
            {status?.enabled ? 'Enabled' : 'Disabled'}
          </Badge>
          <Button variant="outline" size="sm" onClick={handleToggle} disabled={toggling}>
            <RefreshCw className="h-4 w-4" /> {toggling ? 'Toggling...' : status?.enabled ? 'Disable' : 'Enable'}
          </Button>
        </div>
      </div>

      <div className="grid gap-4 grid-cols-1 md:grid-cols-4">
        <Card><CardContent className="p-6">
          <div className="text-2xl font-bold">{status?.total_rules?.toLocaleString() ?? '-'}</div>
          <p className="text-xs text-muted-foreground mt-1">Blocked Domains</p>
        </CardContent></Card>
        <Card><CardContent className="p-6">
          <div className="text-2xl font-bold">{status?.files_count ?? '-'}</div>
          <p className="text-xs text-muted-foreground mt-1">Blocklist Files</p>
        </CardContent></Card>
        <Card><CardContent className="p-6">
          <div className="text-2xl font-bold">{status?.urls_count ?? '-'}</div>
          <p className="text-xs text-muted-foreground mt-1">Blocklist URLs</p>
        </CardContent></Card>
        <Card><CardContent className="p-6 flex items-center gap-3">
          <Shield className="h-8 w-8 text-primary" />
          <div>
            <div className="text-2xl font-bold">{status?.enabled ? 'Active' : 'Inactive'}</div>
            <p className="text-xs text-muted-foreground mt-1">Protection Status</p>
          </div>
        </CardContent></Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Plus className="h-4 w-4" /> Add Blocklist File
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-3">
            <Input
              placeholder="/etc/nothingdns/blocklist.txt"
              value={newFile}
              onChange={e => setNewFile(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleAddFile()}
              className="flex-1"
            />
            <Button onClick={handleAddFile} disabled={adding || !newFile.trim()}>
              {adding ? 'Adding...' : 'Add File'}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground mt-2">Enter the full path to a blocklist file (hosts-style format)</p>
        </CardContent>
      </Card>
    </div>
  );
}
