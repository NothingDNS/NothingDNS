import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from '@/hooks/useTheme';
import { useWebSocket } from '@/hooks/useWebSocket';
import { Sidebar } from '@/components/layout/sidebar';
import { DashboardPage } from '@/pages/dashboard';
import { ZonesPage } from '@/pages/zones';
import { ZoneDetailPage } from '@/pages/zone-detail';
import { SettingsPage } from '@/pages/settings';
import { AboutPage } from '@/pages/about';
import { LoginPage } from '@/pages/login';
import { useState, useEffect } from 'react';

function getToken(): string | null {
  const match = document.cookie.match(/ndns_token=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

function AppContent() {
  const [authed, setAuthed] = useState(() => !!getToken());
  const { connected } = useWebSocket('/ws');

  useEffect(() => {
    const token = getToken();
    if (token && authed) {
      fetch('/api/v1/status', { headers: { Authorization: `Bearer ${token}` } })
        .then((r) => { if (!r.ok) setAuthed(false); })
        .catch(() => {});
    }
  }, [authed]);

  if (!authed) return <LoginPage onSuccess={() => setAuthed(true)} />;

  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-background">
        <Sidebar connected={connected} />
        <main className="flex-1 overflow-y-auto h-screen">
          <div className="p-6 max-w-6xl mx-auto">
            <Routes>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/zones" element={<ZonesPage />} />
              <Route path="/zones/:name" element={<ZoneDetailPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/about" element={<AboutPage />} />
            </Routes>
          </div>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <AppContent />
    </ThemeProvider>
  );
}
