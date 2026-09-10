import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import {
  useUpdateLoggingConfig,
  useUpdateRRLConfig,
  useUpdateCacheConfig,
} from './useApi';
import { useAuthStore } from '@/stores/authStore';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        {children}
      </QueryClientProvider>
    );
  };
}

beforeEach(() => {
  mockFetch.mockReset();
  useAuthStore.setState({
    token: null,
    username: null,
    role: null,
    isAuthenticated: false,
  });
});

function mockJsonResponse(data: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

function mockTextResponse(text: string, status = 200) {
  return Promise.resolve(
    new Response(text, {
      status,
      headers: { 'Content-Type': 'text/plain' },
    }),
  );
}

describe('useUpdateLoggingConfig', () => {
  it('sends PUT to /api/v1/config/logging', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ message: 'updated' }));
    const { result } = renderHook(() => useUpdateLoggingConfig(), {
      wrapper: createWrapper(),
    });

    result.current.mutate({ level: 'debug' });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockFetch).toHaveBeenCalledWith('/api/v1/config/logging', expect.objectContaining({
      method: 'PUT',
      body: JSON.stringify({ level: 'debug' }),
      headers: expect.objectContaining({ 'Content-Type': 'application/json' }),
    }));
  });

  it('includes Bearer token when authenticated', async () => {
    useAuthStore.getState().setAuth('tok_config', 'admin', 'admin');
    mockFetch.mockResolvedValue(mockJsonResponse({ message: 'ok' }));

    const { result } = renderHook(() => useUpdateLoggingConfig(), {
      wrapper: createWrapper(),
    });
    result.current.mutate({ level: 'info' });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    const callHeaders = mockFetch.mock.calls[0][1].headers;
    expect(callHeaders.Authorization).toBe('Bearer tok_config');
  });

  it('handles 401 by clearing auth', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ message: 'unauthorized' }, 401));
    const { result } = renderHook(() => useUpdateLoggingConfig(), {
      wrapper: createWrapper(),
    });
    result.current.mutate({ level: 'warn' });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(useAuthStore.getState().token).toBeNull();
  });

  it('extracts error message from error object', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ error: { code: 'INVALID_LEVEL', message: 'invalid level' } }, 400),
    );
    const { result } = renderHook(() => useUpdateLoggingConfig(), {
      wrapper: createWrapper(),
    });
    result.current.mutate({ level: 'trace' });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect((result.current.error as Error).message).toContain('invalid level');
  });

  it('falls back to HTTP status when error is invalid JSON', async () => {
    mockFetch.mockResolvedValue(
      new Response('not-json', {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    const { result } = renderHook(() => useUpdateLoggingConfig(), {
      wrapper: createWrapper(),
    });
    result.current.mutate({ level: 'warn' });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect((result.current.error as Error).message).toMatch(/HTTP 500/);
  });

  it('falls back to HTTP status when content-type is not JSON', async () => {
    mockFetch.mockResolvedValue(mockTextResponse('boom', 502));
    const { result } = renderHook(() => useUpdateLoggingConfig(), {
      wrapper: createWrapper(),
    });
    result.current.mutate({ level: 'warn' });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect((result.current.error as Error).message).toMatch(/HTTP 502/);
  });

  it('uses message field from payload when no error object', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ message: 'simple msg' }, 400));
    const { result } = renderHook(() => useUpdateLoggingConfig(), {
      wrapper: createWrapper(),
    });
    result.current.mutate({ level: 'warn' });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect((result.current.error as Error).message).toContain('simple msg');
  });

  it('falls back to HTTP when error is empty string', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ error: '' }, 400));
    const { result } = renderHook(() => useUpdateLoggingConfig(), {
      wrapper: createWrapper(),
    });
    result.current.mutate({ level: 'warn' });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect((result.current.error as Error).message).toMatch(/HTTP 400/);
  });

  it('returns empty object when content-type is not JSON for success', async () => {
    mockFetch.mockResolvedValue(mockTextResponse('OK', 200));
    const { result } = renderHook(() => useUpdateLoggingConfig(), {
      wrapper: createWrapper(),
    });
    result.current.mutate({ level: 'info' });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual({});
  });

  it('returns empty object when content-type header is missing', async () => {
    mockFetch.mockResolvedValue(
      Promise.resolve(new Response('ok', { status: 200, headers: {} })),
    );
    const { result } = renderHook(() => useUpdateLoggingConfig(), {
      wrapper: createWrapper(),
    });
    result.current.mutate({ level: 'info' });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual({});
  });

  it('falls back to HTTP when error string is whitespace', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ error: '   ' }, 400),
    );
    const { result } = renderHook(() => useUpdateLoggingConfig(), {
      wrapper: createWrapper(),
    });
    result.current.mutate({ level: 'warn' });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect((result.current.error as Error).message).toMatch(/HTTP 400/);
  });

  it('falls back to HTTP when top-level message is whitespace', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ message: '   ' }, 400),
    );
    const { result } = renderHook(() => useUpdateLoggingConfig(), {
      wrapper: createWrapper(),
    });
    result.current.mutate({ level: 'warn' });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect((result.current.error as Error).message).toMatch(/HTTP 400/);
  });

  it('invalidates server-config query on success', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ message: 'ok' }));
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    );
    const { result } = renderHook(() => useUpdateLoggingConfig(), { wrapper });
    result.current.mutate({ level: 'info' });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['server-config'] });
  });
});

describe('useUpdateRRLConfig', () => {
  it('sends PUT to /api/v1/config/rrl', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ message: 'updated' }));
    const { result } = renderHook(() => useUpdateRRLConfig(), {
      wrapper: createWrapper(),
    });

    result.current.mutate({ enabled: true, rate: 10, burst: 20 });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockFetch).toHaveBeenCalledWith('/api/v1/config/rrl', expect.objectContaining({
      method: 'PUT',
      body: JSON.stringify({ enabled: true, rate: 10, burst: 20 }),
      headers: expect.objectContaining({ 'Content-Type': 'application/json' }),
    }));
  });

  it('handles error on RRL update', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ error: { message: 'invalid rate' } }, 400),
    );
    const { result } = renderHook(() => useUpdateRRLConfig(), {
      wrapper: createWrapper(),
    });
    result.current.mutate({ enabled: false, rate: -1, burst: 0 });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect((result.current.error as Error).message).toContain('invalid rate');
  });

  it('falls back to error code when no message', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ error: { code: 'INVALID_BURST' } }, 400),
    );
    const { result } = renderHook(() => useUpdateRRLConfig(), {
      wrapper: createWrapper(),
    });
    result.current.mutate({ enabled: false, rate: 0, burst: 0 });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect((result.current.error as Error).message).toContain('INVALID_BURST');
  });

  it('falls back to top-level message when error object has only whitespace', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ error: { message: '   ' }, unknown: true }, 400),
    );
    const { result } = renderHook(() => useUpdateRRLConfig(), {
      wrapper: createWrapper(),
    });
    result.current.mutate({ enabled: false, rate: 0, burst: 0 });
    await waitFor(() => expect(result.current.isError).toBe(true));
    // Falls through to top-level message field
    expect((result.current.error as Error).message).toMatch(/HTTP 400|unknown/);
  });

  it('invalidates server-config query on success', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ message: 'ok' }));
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    );
    const { result } = renderHook(() => useUpdateRRLConfig(), { wrapper });
    result.current.mutate({ enabled: true, rate: 1, burst: 1 });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['server-config'] });
  });
});

describe('useUpdateCacheConfig', () => {
  const cacheConfig = {
    enabled: true,
    size: 10000,
    default_ttl: 3600,
    max_ttl: 86400,
    min_ttl: 60,
    negative_ttl: 300,
    prefetch: true,
    prefetch_threshold: 0.5,
    serve_stale: true,
    stale_grace_secs: 3600,
  };

  it('sends PUT to /api/v1/config/cache with full payload', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ message: 'updated' }));
    const { result } = renderHook(() => useUpdateCacheConfig(), {
      wrapper: createWrapper(),
    });

    result.current.mutate(cacheConfig);
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockFetch).toHaveBeenCalledWith('/api/v1/config/cache', expect.objectContaining({
      method: 'PUT',
      body: JSON.stringify(cacheConfig),
      headers: expect.objectContaining({ 'Content-Type': 'application/json' }),
    }));
  });

  it('handles API error', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ error: 'invalid cache size' }, 400),
    );
    const { result } = renderHook(() => useUpdateCacheConfig(), {
      wrapper: createWrapper(),
    });

    result.current.mutate(cacheConfig);
    await waitFor(() => expect(result.current.isError).toBe(true));

    expect(result.current.error).toBeDefined();
  });

  it('invalidates server-config query on success', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ message: 'ok' }));
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    );
    const { result } = renderHook(() => useUpdateCacheConfig(), { wrapper });
    result.current.mutate(cacheConfig);
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['server-config'] });
  });
});
