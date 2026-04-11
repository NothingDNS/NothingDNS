import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Globe, Eye, EyeOff } from 'lucide-react';

export function LoginPage({ onSuccess }: { onSuccess: () => void }) {
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [show, setShow] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token.trim()) return;
    setLoading(true); setError('');
    try {
      const r = await fetch('/api/v1/status', { headers: { Authorization: `Bearer ${token.trim()}` } });
      if (r.ok) { document.cookie = `ndns_token=${encodeURIComponent(token.trim())}; path=/; max-age=86400; SameSite=Strict`; onSuccess(); return; }
      // Provide specific error messages based on response
      if (r.status === 401) setError('Invalid token. Please check your token and try again.');
      else if (r.status === 403) setError('Access forbidden. Contact your administrator.');
      else setError(`Connection error (${r.status}). Please try again.`);
    } catch { setError('Connection error. Please check your network.'); } finally { setLoading(false); }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-background">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center h-16 w-16 rounded-2xl bg-primary/10 text-primary mb-4"><Globe className="h-8 w-8" /></div>
          <h1 className="text-2xl font-bold">NothingDNS</h1>
          <p className="text-sm text-muted-foreground mt-1">Enter your access token to continue</p>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div><label className="text-sm font-medium mb-1.5 block">Access Token</label>
            <div className="relative"><Input type={show ? 'text' : 'password'} placeholder="Enter auth token" value={token} onChange={(e) => setToken(e.target.value)} className={error ? 'border-destructive' : ''} autoFocus />
              <button type="button" onClick={() => setShow(!show)} className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground cursor-pointer">{show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button>
            </div>
          </div>
          {error && <div className="text-sm text-destructive bg-destructive/10 px-3 py-2 rounded-lg">{error}</div>}
          <Button type="submit" className="w-full" disabled={loading || !token.trim()}>{loading ? 'Signing in...' : 'Sign In'}</Button>
        </form>
      </div>
    </div>
  );
}
