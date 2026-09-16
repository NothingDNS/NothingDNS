import { useAuthStore } from "@/stores/authStore";

const API_BASE = "";

function _errorMessageFromPayload(payload: unknown, fallback: string): string {
	if (!payload || typeof payload !== "object") return fallback;

	const error = (payload as { error?: unknown }).error;
	if (typeof error === "string" && error.trim()) return error;
	if (error && typeof error === "object") {
		const message = (error as { message?: unknown }).message;
		if (typeof message === "string" && message.trim()) return message;
		const code = (error as { code?: unknown }).code;
		if (typeof code === "string" && code.trim()) return code;
	}

	const message = (payload as { message?: unknown }).message;
	return typeof message === "string" && message.trim() ? message : fallback;
}

// SECURITY: Token comes from the in-memory zustand store, not document.cookie.
// The backend cookie is HttpOnly and cannot (and should not) be read from JS.
// If the token is missing — typically right after a page reload — the Bearer
// header is omitted, and mutating requests will 401, triggering re-login.
function getToken(): string | null {
	return useAuthStore.getState().token;
}

// downloadAuthenticated fetches a binary/text asset with the Bearer header
// and triggers a browser download, avoiding `window.location.href` which
// skips every `fetch` header and loses the Authorization header (VULN-033).
export async function downloadAuthenticated(
	path: string,
	filename: string,
): Promise<void> {
	const headers: Record<string, string> = {};
	const token = getToken();
	if (token) headers.Authorization = `Bearer ${token}`;
	const resp = await fetch(`${API_BASE}${path}`, { headers });
	if (!resp.ok) {
		throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
	}
	const blob = await resp.blob();
	const url = URL.createObjectURL(blob);
	try {
		const a = document.createElement("a");
		a.href = url;
		a.download = filename;
		document.body.appendChild(a);
		a.click();
		a.remove();
	} finally {
		URL.revokeObjectURL(url);
	}
}

export async function api<T = unknown>(
	method: string,
	path: string,
	body?: unknown,
): Promise<T> {
	const headers: Record<string, string> = {
		"Content-Type": "application/json",
		"X-Requested-With": "XMLHttpRequest",
	};
	const token = getToken();
	if (token) headers.Authorization = `Bearer ${token}`;
	const opts: RequestInit = { method, headers };
	if (body) opts.body = JSON.stringify(body);
	// Mirror fetchApi's 10s timeout: a stalled upstream must not leave the
	// request pending forever (with the dashboard's 10s polling pattern, each
	// tick would otherwise pile up another permanently in-flight connection).
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), 10_000);
	let resp: Response;
	try {
		resp = await fetch(`${API_BASE}${path}`, {
			...opts,
			signal: controller.signal,
		});
	} finally {
		clearTimeout(timeout);
	}

	// Global 401 handling: a token that expired mid-session must bounce the
	// user back to login, not surface "HTTP 401" on every page. Clearing auth
	// flips isAuthenticated → AppContent reactively renders <LoginPage/>.
	if (resp.status === 401) {
		useAuthStore.getState().clearAuth();
		throw new Error("Session expired. Please sign in again.");
	}

	// Handle non-JSON responses gracefully
	const contentType = resp.headers.get("content-type");
	if (!resp.ok) {
		// Try to parse error from JSON response
		if (contentType?.includes("application/json")) {
			try {
				const data = await resp.json();
				throw new Error(
					_errorMessageFromPayload(
						data,
						`HTTP ${resp.status}: ${resp.statusText}`,
					),
				);
			} catch (e) {
				if (e instanceof SyntaxError) {
					// Non-JSON error body
					throw new Error(`HTTP ${resp.status}: ${resp.statusText}`, {
						cause: e,
					});
				}
				throw e; // Re-throw if we already have a meaningful Error
			}
		}
		throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
	}

	// Only parse JSON on success
	if (contentType?.includes("application/json")) {
		return (await resp.json()) as T;
	}
	// Return empty object for non-JSON success responses
	return {} as T;
}

export interface DashboardStats {
	uptime: number;
	queriesTotal: number;
	queriesPerSec: number;
	cacheHitRate: number;
	blockedQueries: number;
	activeClients: number;
	zoneCount: number;
	upstreamLatency: number;
}

export interface QueryEvent {
	timestamp: string;
	clientIp: string;
	domain: string;
	queryType: string;
	responseCode: string;
	duration: number;
	cached: boolean;
	blocked: boolean;
	protocol: string;
}

export interface Zone {
	name: string;
	serial: number;
	records: number;
}

export interface ZoneDetail {
	name: string;
	records: number;
	serial?: number;
	soa?: {
		mname: string;
		rname: string;
		serial: number;
		refresh: number;
		retry: number;
		expire: number;
		minimum: number;
	};
	nameservers?: string[];
}

export interface DnsRecord {
	name: string;
	type: string;
	ttl: number;
	class: string;
	data: string;
}

export interface ServerStatus {
	status: string;
	timestamp: string;
	version: string;
	cache?: {
		size: number;
		capacity: number;
		hits: number;
		misses: number;
		hit_ratio: number;
	};
	cluster?: {
		enabled: boolean;
		node_id?: string;
		node_count?: number;
		alive_count?: number;
		healthy?: boolean;
	};
}

export interface QueryLogEntry {
	timestamp: string;
	client_ip: string;
	domain: string;
	query_type: string;
	response_code: string;
	duration_ms: number;
	cached: boolean;
	blocked: boolean;
	protocol: string;
}

export interface QueryLogResponse {
	queries: QueryLogEntry[];
	total: number;
	offset: number;
	limit: number;
}

export interface TopDomainsEntry {
	domain: string;
	count: number;
}

export interface TopDomainsResponse {
	domains: TopDomainsEntry[];
	limit: number;
}

export interface DNSSECStatus {
	enabled: boolean;
	require_dnssec: boolean;
}

export interface BlocklistStatus {
	enabled: boolean;
	total_rules: number;
	files_count: number;
	urls_count: number;
}

export interface UpstreamServer {
	address: string;
	healthy: boolean;
	queries: number;
	failed: number;
	failovers: number;
}

export interface UpstreamsResponse {
	upstreams: UpstreamServer[];
}

export interface UserInfo {
	username: string;
	role: string;
	created_at?: string;
	updated_at?: string;
}

export interface CreateUserRequest {
	username: string;
	password: string;
	role: string;
}

export interface MetricsHistory {
	timestamps: number[];
	queries: number[];
	cache_hits: number[];
	cache_misses: number[];
	latency_ms: number[];
	count: number;
}

export interface RPZStats {
	enabled: boolean;
	total_rules: number;
	qname_rules: number;
	client_ip_rules: number;
	resp_ip_rules: number;
	files_count: number;
	total_matches: number;
	total_lookups: number;
	last_reload?: string;
}

export interface RPZRule {
	pattern: string;
	action: string;
	trigger: string;
	override_data?: string;
	policy_name: string;
	priority: number;
}

export interface RPZRulesResponse {
	rules: RPZRule[];
}

export interface ServerConfig {
	version: string;
	listen_port: number;
	log_level: string;
	dns64: {
		enabled: boolean;
		prefix: string;
		prefix_len: number;
		exclude_nets?: string[];
	};
	cookie: {
		enabled: boolean;
		secret_rotation?: string;
	};
}

export interface GeoDNSStats {
	enabled: boolean;
	rules: number;
	mmdb_loaded: boolean;
	lookups: number;
	hits: number;
	misses: number;
}

export interface ZoneTransfer {
	zone: string;
	masters: string;
	serial: number;
	last_transfer: string;
	status: "synced" | "syncing" | "failed" | "pending";
	records: number;
}

export interface SlaveZonesResponse {
	slave_zones: ZoneTransfer[];
}
