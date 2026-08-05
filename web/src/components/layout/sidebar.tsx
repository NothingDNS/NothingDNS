import {
	ArrowLeftRight,
	BarChart3,
	ChevronLeft,
	ChevronRight,
	CloudCog,
	Globe,
	Globe2,
	Info,
	Key,
	LayoutDashboard,
	LogOut,
	Menu,
	Monitor,
	Moon,
	Network,
	ScrollText,
	Settings,
	Shield,
	ShieldCheck,
	Sun,
	TrendingUp,
	Users,
	Wifi,
	Wifi as WifiIcon,
	WifiOff,
	X,
} from "lucide-react";
import { useEffect, useState } from "react";
import { NavLink, useLocation } from "react-router";
import { useTheme } from "@/hooks/useThemeHook";
import { api } from "@/lib/api";
import { hasMinRole, type Role } from "@/lib/roles";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/stores/authStore";

// minRole hides management pages from viewers — their API reads gate on
// requireOperator (mutations on requireAdmin), matching the RequireRole
// wrappers on the corresponding routes in App.tsx.
const nav: { to: string; icon: typeof Globe; label: string; minRole?: Role }[] = [
	{ to: "/", icon: LayoutDashboard, label: "Dashboard" },
	{ to: "/zones", icon: Globe, label: "Zones" },
	{ to: "/dnssec", icon: Key, label: "DNSSEC", minRole: "operator" },
	{ to: "/cluster", icon: Network, label: "Cluster", minRole: "operator" },
	{ to: "/query-log", icon: ScrollText, label: "Query Log" },
	{ to: "/top-domains", icon: TrendingUp, label: "Top Domains" },
	{ to: "/geoip", icon: Globe2, label: "GeoIP" },
	{ to: "/blocklist", icon: Shield, label: "Blocklist", minRole: "operator" },
	{ to: "/rpz", icon: ShieldCheck, label: "RPZ", minRole: "operator" },
	{ to: "/acl", icon: Shield, label: "ACL", minRole: "operator" },
	{ to: "/upstreams", icon: WifiIcon, label: "Upstreams", minRole: "operator" },
	{ to: "/zone-transfer", icon: ArrowLeftRight, label: "Zone Transfer" },
	{ to: "/dns64-cookies", icon: CloudCog, label: "DNS64/Cookies" },
	{ to: "/charts", icon: BarChart3, label: "Charts" },
	{ to: "/users", icon: Users, label: "Users", minRole: "operator" },
	{ to: "/settings", icon: Settings, label: "Settings", minRole: "operator" },
	{ to: "/about", icon: Info, label: "About" },
];

export function Sidebar({
	connected,
	streamError,
}: {
	connected: boolean;
	streamError?: string | null;
}) {
	const [collapsed, setCollapsed] = useState(false);
	const [mobileOpen, setMobileOpen] = useState(false);
	const { theme, setTheme } = useTheme();
	const username = useAuthStore((s) => s.username);
	const role = useAuthStore((s) => s.role);
	const loc = useLocation();
	const _pathname = loc.pathname;
	const ThemeIcon = theme === "dark" ? Moon : theme === "light" ? Sun : Monitor;
	const streamLabel = connected
		? "Live queries"
		: streamError
			? "Stream offline"
			: "Stream idle";

	// Close mobile menu on route change
	useEffect(() => {
		void _pathname;
		setMobileOpen(false);
	}, [_pathname]);

	const handleLogout = async () => {
		// Invalidate the server-side session / HttpOnly cookie before clearing
		// local state; ignore network errors so logout always proceeds locally.
		// clearAuth flips isAuthenticated → AppContent renders <LoginPage/>.
		try {
			await api("POST", "/api/v1/auth/logout");
		} catch {
			// best-effort: clear client state regardless of network outcome
		}
		useAuthStore.getState().clearAuth();
	};

	return (
		<>
			{/* Mobile toggle button */}
			<button
				type="button"
				onClick={() => setMobileOpen(!mobileOpen)}
				className="fixed top-4 left-4 z-50 p-2 rounded-lg border bg-background shadow-md md:hidden"
				aria-label="Toggle menu"
			>
				{mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
			</button>

			{/* Mobile overlay */}
			{mobileOpen && (
				<button
					type="button"
					className="fixed inset-0 z-40 bg-black/50 md:hidden"
					onClick={() => setMobileOpen(false)}
					aria-label="Close menu"
				/>
			)}

			{/* Sidebar */}
			<aside
				className={cn(
					"fixed inset-y-0 left-0 flex flex-col border-r bg-sidebar text-sidebar-foreground transition-all duration-200 h-screen z-50 md:sticky md:top-0",
					collapsed ? "w-16" : "w-56",
					mobileOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0",
				)}
			>
				<div
					className={cn(
						"flex items-center gap-3 border-b px-4 py-5",
						collapsed && "justify-center px-2",
					)}
				>
					<div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground font-bold text-sm shrink-0">
						N
					</div>
					{!collapsed && (
						<div className="overflow-hidden">
							<h1 className="text-sm font-bold truncate">NothingDNS</h1>
							<p className="text-[11px] text-muted-foreground truncate">
								Authoritative DNS
							</p>
						</div>
					)}
				</div>
				<nav className="flex-1 py-2 space-y-1 px-2 overflow-y-auto">
					{nav
						.filter((item) => !item.minRole || hasMinRole(role, item.minRole))
						.map(({ to, icon: Icon, label }) => {
							const active =
								to === "/" ? loc.pathname === "/" : loc.pathname.startsWith(to);
							return (
								<NavLink
									key={to}
									to={to}
									className={cn(
										"flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
										active
											? "bg-primary/10 text-primary"
											: "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
										collapsed && "justify-center px-2",
									)}
									onClick={() => setMobileOpen(false)}
								>
									<Icon className="h-4 w-4 shrink-0" />
									{!collapsed && <span className="truncate">{label}</span>}
								</NavLink>
							);
						})}
				</nav>
				<div className="border-t p-2 space-y-1">
					{username && (
						<div
							className={cn(
								"flex items-center gap-2 px-3 py-2",
								collapsed && "justify-center px-2",
							)}
							title={`${username}${role ? ` (${role})` : ""}`}
						>
							<div className="flex h-6 w-6 items-center justify-center rounded-full bg-primary/10 text-primary text-[11px] font-semibold uppercase shrink-0">
								{username.charAt(0)}
							</div>
							{!collapsed && (
								<div className="min-w-0 overflow-hidden">
									<div className="truncate text-xs font-medium">{username}</div>
									{role && (
										<div className="truncate text-[11px] capitalize text-muted-foreground">
											{role}
										</div>
									)}
								</div>
							)}
						</div>
					)}
					<div
						className={cn(
							"flex items-center gap-2 px-3 py-2 text-xs",
							collapsed && "justify-center px-2",
						)}
						title={streamError || streamLabel}
					>
						{connected ? (
							<Wifi className="h-3.5 w-3.5 text-success shrink-0" />
						) : (
							<WifiOff className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
						)}
						{!collapsed && (
							<span
								className={connected ? "text-success" : "text-muted-foreground"}
							>
								{streamLabel}
							</span>
						)}
					</div>
					<button
						type="button"
						onClick={() =>
							setTheme(
								theme === "dark"
									? "light"
									: theme === "light"
										? "system"
										: "dark",
							)
						}
						className={cn(
							"flex items-center gap-2 rounded-lg px-3 py-2 text-xs text-muted-foreground hover:bg-accent hover:text-accent-foreground transition-colors w-full cursor-pointer",
							collapsed && "justify-center px-2",
						)}
					>
						<ThemeIcon className="h-3.5 w-3.5 shrink-0" />
						{!collapsed && <span className="capitalize">{theme} mode</span>}
					</button>
					<button
						type="button"
						onClick={() => {
							setCollapsed(!collapsed);
							setMobileOpen(false);
						}}
						className={cn(
							"flex items-center gap-2 rounded-lg px-3 py-2 text-xs text-muted-foreground hover:bg-accent hover:text-accent-foreground transition-colors w-full cursor-pointer",
							collapsed && "justify-center px-2",
						)}
					>
						{collapsed ? (
							<ChevronRight className="h-3.5 w-3.5 shrink-0" />
						) : (
							<>
								<ChevronLeft className="h-3.5 w-3.5 shrink-0" />
								<span>Collapse</span>
							</>
						)}
					</button>
					<button
						type="button"
						onClick={handleLogout}
						className={cn(
							"flex items-center gap-2 rounded-lg px-3 py-2 text-xs text-destructive hover:bg-destructive/10 transition-colors w-full cursor-pointer",
							collapsed && "justify-center px-2",
						)}
					>
						<LogOut className="h-3.5 w-3.5 shrink-0" />
						{!collapsed && <span>Logout</span>}
					</button>
				</div>
			</aside>
		</>
	);
}
