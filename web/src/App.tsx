import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from '@/hooks/useTheme';
import { QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'sonner';
import { queryClient } from '@/lib/queryClient';
import { useAuthStore } from '@/stores/authStore';
import { useWebSocket } from '@/hooks/useWebSocket';
import { Sidebar } from '@/components/layout/sidebar';
import { DashboardPage } from '@/pages/dashboard';
import { ZonesPage } from '@/pages/zones';
import { ZoneDetailPage } from '@/pages/zone-detail';
import { SettingsPage } from '@/pages/settings';
import { AboutPage } from '@/pages/about';
import { LoginPage } from '@/pages/login';
import { QueryLogPage } from '@/pages/query-log';
import { TopDomainsPage } from '@/pages/top-domains';
import { BlocklistPage } from '@/pages/blocklist';
import { UpstreamsPage } from '@/pages/upstreams';
import { UsersPage } from '@/pages/users';
import { HistoricalChartsPage } from '@/pages/historical-charts';
import { DNSSECPage } from '@/pages/dnssec';
import { ClusterPage } from '@/pages/cluster';
import { RPZPage } from '@/pages/rpz';
import { ACLPage } from '@/pages/acl';
import { GeoIPPage } from '@/pages/geoip';
import { DNS64CookiesPage } from '@/pages/dns64-cookies';
import { ZoneTransferPage } from '@/pages/zone-transfer';
import { useEffect } from 'react';

function AppContent() {
  const { isAuthenticated, token } = useAuthStore();
  const { connected } = useWebSocket('/ws');

  useEffect(() => {
    // Validate token on mount if authenticated
    if (isAuthenticated && token) {
      fetch('/api/v1/status', { headers: { Authorization: `Bearer ${token}` } })
        .then((r) => { if (!r.ok) useAuthStore.getState().clearAuth(); })
        .catch(() => {});
    }
  }, [isAuthenticated, token]);

  if (!isAuthenticated) return <LoginPage />;

  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-background text-foreground">
        <Sidebar connected={connected} />
        <main className="flex-1 overflow-y-auto h-screen">
          <div className="p-6 max-w-6xl mx-auto">
            <Routes>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/zones" element={<ZonesPage />} />
              <Route path="/zones/:name" element={<ZoneDetailPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/about" element={<AboutPage />} />
              <Route path="/query-log" element={<QueryLogPage />} />
              <Route path="/top-domains" element={<TopDomainsPage />} />
              <Route path="/blocklist" element={<BlocklistPage />} />
              <Route path="/upstreams" element={<UpstreamsPage />} />
              <Route path="/users" element={<UsersPage />} />
              <Route path="/charts" element={<HistoricalChartsPage />} />
              <Route path="/dnssec" element={<DNSSECPage />} />
              <Route path="/cluster" element={<ClusterPage />} />
              <Route path="/rpz" element={<RPZPage />} />
              <Route path="/acl" element={<ACLPage />} />
              <Route path="/geoip" element={<GeoIPPage />} />
              <Route path="/dns64-cookies" element={<DNS64CookiesPage />} />
              <Route path="/zone-transfer" element={<ZoneTransferPage />} />
            </Routes>
          </div>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AppContent />
        <Toaster position="bottom-right" richColors closeButton />
      </ThemeProvider>
    </QueryClientProvider>
  );
}
