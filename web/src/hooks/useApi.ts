import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { type DashboardStats, type QueryLogResponse, type Zone, type UpstreamsResponse, type BlocklistStatus, type UserInfo, type MetricsHistory, type RPZRulesResponse } from '@/lib/api';

// Helper to get auth token
function getToken(): string | null {
  const match = document.cookie.match(/ndns_token=([^;]+)/);
  if (match) return decodeURIComponent(match[1]);
  return null;
}

// API fetch wrapper with auth
async function fetchApi<T>(path: string, options?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  
  const resp = await fetch(path, { ...options, headers });
  
  if (!resp.ok) {
    const contentType = resp.headers.get('content-type');
    if (contentType?.includes('application/json')) {
      const data = await resp.json();
      throw new Error(data.error || `HTTP ${resp.status}: ${resp.statusText}`);
    }
    throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
  }
  
  const contentType = resp.headers.get('content-type');
  if (contentType?.includes('application/json')) {
    return resp.json() as Promise<T>;
  }
  return {} as T;
}

// Dashboard Stats
export function useDashboardStats() {
  return useQuery<DashboardStats>({
    queryKey: ['dashboard-stats'],
    queryFn: () => fetchApi<DashboardStats>('/api/dashboard/stats'),
    refetchInterval: 5000, // Poll every 5s for real-time
  });
}

// Query Log
export function useQueryLog(params: { offset?: number; limit?: number }) {
  return useQuery<QueryLogResponse>({
    queryKey: ['query-log', params],
    queryFn: () => fetchApi<QueryLogResponse>(
      `/api/v1/queries?offset=${params.offset ?? 0}&limit=${params.limit ?? 100}`
    ),
  });
}

// Zones
export function useZones() {
  return useQuery<Zone[]>({
    queryKey: ['zones'],
    queryFn: () => fetchApi<Zone[]>('/api/v1/zones'),
  });
}

// Upstreams
export function useUpstreams() {
  return useQuery<UpstreamsResponse>({
    queryKey: ['upstreams'],
    queryFn: () => fetchApi<UpstreamsResponse>('/api/v1/upstreams'),
    refetchInterval: 10000,
  });
}

// Blocklist
export function useBlocklistStatus() {
  return useQuery<BlocklistStatus>({
    queryKey: ['blocklist-status'],
    queryFn: () => fetchApi<BlocklistStatus>('/api/v1/blocklists'),
  });
}

// Users
export function useUsers() {
  return useQuery<UserInfo[]>({
    queryKey: ['users'],
    queryFn: () => fetchApi<UserInfo[]>('/api/v1/auth/users'),
  });
}

// Metrics History
export function useMetricsHistory(params: { start?: number; end?: number }) {
  const searchParams = new URLSearchParams();
  if (params.start) searchParams.set('start', params.start.toString());
  if (params.end) searchParams.set('end', params.end.toString());
  
  return useQuery<MetricsHistory>({
    queryKey: ['metrics-history', params],
    queryFn: () => fetchApi<MetricsHistory>(`/api/v1/metrics/history?${searchParams}`),
  });
}

// RPZ Rules
export function useRPZRules() {
  return useQuery<RPZRulesResponse>({
    queryKey: ['rpz-rules'],
    queryFn: () => fetchApi<RPZRulesResponse>('/api/v1/rpz/rules'),
  });
}

// Login Mutation
interface LoginRequest { username: string; password: string }
interface LoginResponse { token: string; username: string; role: string }

export function useLogin() {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (data: LoginRequest) => 
      fetchApi<LoginResponse>('/api/v1/auth/login', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });
}

// Create User Mutation
interface CreateUserRequest { username: string; password: string; role: string }

export function useCreateUser() {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (data: CreateUserRequest) =>
      fetchApi<UserInfo>('/api/v1/auth/users', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });
}

// Delete User Mutation
export function useDeleteUser() {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (username: string) =>
      fetchApi<void>(`/api/v1/auth/users?username=${encodeURIComponent(username)}`, {
        method: 'DELETE',
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });
}
