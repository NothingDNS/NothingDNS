import { BrowserRouter, Routes, Route, useLocation, Link } from 'react-router';
import { ThemeProvider } from '@/hooks/useTheme';
import { useTheme } from '@/hooks/useThemeHook';
import { QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'sonner';
import { queryClient } from '@/lib/queryClient';
import { useAuthStore } from '@/stores/authStore';
import { useQueryStream } from '@/stores/queryStream';
import { useWebSocket } from '@/hooks/useWebSocket';
import { Sidebar } from '@/components/layout/sidebar';
import { ErrorBoundary } from '@/components/error-boundary';
import { RequireRole } from '@/components/require-role';
import { EmptyState } from '@/components/states';
import { Button } from '@/components/ui/button';
import { FileQuestion } from 'lucide-react';
import { LoginPage } from '@/pages/login';
import { lazy, Suspense, useEffect } from 'react';

const DashboardPage = lazy(() => import('@/pages/dashboard').then(({ DashboardPage }) => ({ default: DashboardPage })));
const ZonesPage = lazy(() => import('@/pages/zones').then(({ ZonesPage }) => ({ default: ZonesPage })));
const ZoneDetailPage = lazy(() => import('@/pages/zone-detail').then(({ ZoneDetailPage }) => ({ default: ZoneDetailPage })));
const SettingsPage = lazy(() => import('@/pages/settings').then(({ SettingsPage }) => ({ default: SettingsPage })));
const AboutPage = lazy(() => import('@/pages/about').then(({ AboutPage }) => ({ default: AboutPage })));
const QueryLogPage = lazy(() => import('@/pages/query-log').then(({ QueryLogPage }) => ({ default: QueryLogPage })));
const TopDomainsPage = lazy(() => import('@/pages/top-domains').then(({ TopDomainsPage }) => ({ default: TopDomainsPage })));
const BlocklistPage = lazy(() => import('@/pages/blocklist').then(({ BlocklistPage }) => ({ default: BlocklistPage })));
const UpstreamsPage = lazy(() => import('@/pages/upstreams').then(({ UpstreamsPage }) => ({ default: UpstreamsPage })));
const UsersPage = lazy(() => import('@/pages/users').then(({ UsersPage }) => ({ default: UsersPage })));
const HistoricalChartsPage = lazy(() => import('@/pages/historical-charts').then(({ HistoricalChartsPage }) => ({ default: HistoricalChartsPage })));
const DNSSECPage = lazy(() => import('@/pages/dnssec').then(({ DNSSECPage }) => ({ default: DNSSECPage })));
const ClusterPage = lazy(() => import('@/pages/cluster').then(({ ClusterPage }) => ({ default: ClusterPage })));
const RPZPage = lazy(() => import('@/pages/rpz').then(({ RPZPage }) => ({ default: RPZPage })));
const ACLPage = lazy(() => import('@/pages/acl').then(({ ACLPage }) => ({ default: ACLPage })));
const GeoIPPage = lazy(() => import('@/pages/geoip').then(({ GeoIPPage }) => ({ default: GeoIPPage })));
const DNS64CookiesPage = lazy(() => import('@/pages/dns64-cookies').then(({ DNS64CookiesPage }) => ({ default: DNS64CookiesPage })));
const ZoneTransferPage = lazy(() => import('@/pages/zone-transfer').then(({ ZoneTransferPage }) => ({ default: ZoneTransferPage })));

function PageFallback() {
  return (
    <div className="space-y-4" aria-label="Loading page">
      <div className="h-8 w-48 rounded bg-muted animate-pulse" />
      <div className="grid gap-4 md:grid-cols-3">
        <div className="h-28 rounded-lg bg-muted animate-pulse" />
        <div className="h-28 rounded-lg bg-muted animate-pulse" />
        <div className="h-28 rounded-lg bg-muted animate-pulse" />
      </div>
      <div className="h-64 rounded-lg bg-muted animate-pulse" />
    </div>
  );
}

function NotFoundPage() {
  return (
    <EmptyState
      icon={FileQuestion}
      title="Page not found"
      description="The page you're looking for doesn't exist or may have moved."
      action={
        <Button asChild variant="outline" size="sm">
          <Link to="/">Back to dashboard</Link>
        </Button>
      }
    />
  );
}

// RoutedContent lives inside BrowserRouter so it can read the active path and
// key the error boundary to it — a crash on one page self-heals on navigation.
function RoutedContent() {
  const location = useLocation();
  return (
    <ErrorBoundary resetKey={location.pathname}>
      <Suspense fallback={<PageFallback />}>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/zones" element={<ZonesPage />} />
          <Route path="/zones/:name" element={<ZoneDetailPage />} />
          {/* Management pages: API reads gate on requireOperator (mutations on
              requireAdmin), so viewers get an access-denied panel instead of a
              page of 403s. The sidebar hides these entries for viewers too. */}
          <Route path="/settings" element={<RequireRole minRole="operator"><SettingsPage /></RequireRole>} />
          <Route path="/about" element={<AboutPage />} />
          <Route path="/query-log" element={<QueryLogPage />} />
          <Route path="/top-domains" element={<TopDomainsPage />} />
          <Route path="/blocklist" element={<RequireRole minRole="operator"><BlocklistPage /></RequireRole>} />
          <Route path="/upstreams" element={<RequireRole minRole="operator"><UpstreamsPage /></RequireRole>} />
          <Route path="/users" element={<RequireRole minRole="operator"><UsersPage /></RequireRole>} />
          <Route path="/charts" element={<HistoricalChartsPage />} />
          <Route path="/dnssec" element={<RequireRole minRole="operator"><DNSSECPage /></RequireRole>} />
          <Route path="/cluster" element={<RequireRole minRole="operator"><ClusterPage /></RequireRole>} />
          <Route path="/rpz" element={<RequireRole minRole="operator"><RPZPage /></RequireRole>} />
          <Route path="/acl" element={<RequireRole minRole="operator"><ACLPage /></RequireRole>} />
          <Route path="/geoip" element={<GeoIPPage />} />
          <Route path="/dns64-cookies" element={<DNS64CookiesPage />} />
          <Route path="/zone-transfer" element={<ZoneTransferPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </Suspense>
    </ErrorBoundary>
  );
}

function AppContent() {
  const { isAuthenticated, token } = useAuthStore();
  const pushEvent = useQueryStream((s) => s.pushEvent);
  const setStreamConnected = useQueryStream((s) => s.setConnected);
  // The app's single shared WebSocket. Pages subscribe to events via the
  // queryStream store rather than opening their own socket.
  const { connected, error: streamError } = useWebSocket('/ws', { enabled: isAuthenticated, onQuery: pushEvent });

  useEffect(() => { setStreamConnected(connected); }, [connected, setStreamConnected]);

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
        <Sidebar connected={connected} streamError={streamError} />
        <main className="flex-1 overflow-y-auto h-screen">
          <div className="p-6 max-w-6xl mx-auto">
            <RoutedContent />
          </div>
        </main>
      </div>
    </BrowserRouter>
  );
}

// ThemedToaster keeps sonner in sync with the app theme — a light-themed toast
// stack over the dark UI (the default) reads as a bug.
function ThemedToaster() {
  const { resolved } = useTheme();
  return <Toaster position="bottom-right" theme={resolved} richColors closeButton />;
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AppContent />
        <ThemedToaster />
      </ThemeProvider>
    </QueryClientProvider>
  );
}
