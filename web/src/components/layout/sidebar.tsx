import { NavLink, useLocation } from 'react-router-dom';
import { LayoutDashboard, Globe, Settings, Info, ChevronLeft, ChevronRight, Wifi, WifiOff, Sun, Moon, Monitor, ScrollText, TrendingUp, Shield, Wifi as WifiIcon, Users, BarChart3, Key, Network, ShieldCheck } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useTheme } from '@/hooks/useThemeHook';
import { useState } from 'react';

const nav = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/zones', icon: Globe, label: 'Zones' },
  { to: '/dnssec', icon: Key, label: 'DNSSEC' },
  { to: '/cluster', icon: Network, label: 'Cluster' },
  { to: '/query-log', icon: ScrollText, label: 'Query Log' },
  { to: '/top-domains', icon: TrendingUp, label: 'Top Domains' },
  { to: '/blocklist', icon: Shield, label: 'Blocklist' },
  { to: '/rpz', icon: ShieldCheck, label: 'RPZ' },
  { to: '/acl', icon: Shield, label: 'ACL' },
  { to: '/upstreams', icon: WifiIcon, label: 'Upstreams' },
  { to: '/charts', icon: BarChart3, label: 'Charts' },
  { to: '/users', icon: Users, label: 'Users' },
  { to: '/settings', icon: Settings, label: 'Settings' },
  { to: '/about', icon: Info, label: 'About' },
];

export function Sidebar({ connected }: { connected: boolean }) {
  const [collapsed, setCollapsed] = useState(false);
  const { theme, setTheme } = useTheme();
  const loc = useLocation();
  const ThemeIcon = theme === 'dark' ? Moon : theme === 'light' ? Sun : Monitor;

  return (
    <aside className={cn('flex flex-col border-r bg-sidebar text-sidebar-foreground transition-all duration-200 h-screen sticky top-0', collapsed ? 'w-16' : 'w-56')}>
      <div className={cn('flex items-center gap-3 border-b px-4 py-5', collapsed && 'justify-center px-2')}>
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground font-bold text-sm shrink-0">N</div>
        {!collapsed && <div className="overflow-hidden"><h1 className="text-sm font-bold truncate">NothingDNS</h1><p className="text-[11px] text-muted-foreground truncate">Authoritative DNS</p></div>}
      </div>
      <nav className="flex-1 py-2 space-y-1 px-2">
        {nav.map(({ to, icon: Icon, label }) => {
          const active = to === '/' ? loc.pathname === '/' : loc.pathname.startsWith(to);
          return (
            <NavLink key={to} to={to} className={cn('flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors', active ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground', collapsed && 'justify-center px-2')}>
              <Icon className="h-4 w-4 shrink-0" />{!collapsed && <span className="truncate">{label}</span>}
            </NavLink>
          );
        })}
      </nav>
      <div className="border-t p-2 space-y-1">
        <div className={cn('flex items-center gap-2 px-3 py-2 text-xs', collapsed && 'justify-center px-2')}>
          {connected ? <Wifi className="h-3.5 w-3.5 text-success shrink-0" /> : <WifiOff className="h-3.5 w-3.5 text-muted-foreground shrink-0" />}
          {!collapsed && <span className={connected ? 'text-success' : 'text-muted-foreground'}>{connected ? 'Live' : 'Disconnected'}</span>}
        </div>
        <button onClick={() => setTheme(theme === 'dark' ? 'light' : theme === 'light' ? 'system' : 'dark')} className={cn('flex items-center gap-2 rounded-lg px-3 py-2 text-xs text-muted-foreground hover:bg-accent hover:text-accent-foreground transition-colors w-full cursor-pointer', collapsed && 'justify-center px-2')}>
          <ThemeIcon className="h-3.5 w-3.5 shrink-0" />{!collapsed && <span className="capitalize">{theme} mode</span>}
        </button>
        <button onClick={() => setCollapsed(!collapsed)} className={cn('flex items-center gap-2 rounded-lg px-3 py-2 text-xs text-muted-foreground hover:bg-accent hover:text-accent-foreground transition-colors w-full cursor-pointer', collapsed && 'justify-center px-2')}>
          {collapsed ? <ChevronRight className="h-3.5 w-3.5 shrink-0" /> : <><ChevronLeft className="h-3.5 w-3.5 shrink-0" /><span>Collapse</span></>}
        </button>
      </div>
    </aside>
  );
}
