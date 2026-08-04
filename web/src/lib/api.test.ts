import { describe, it, expect, beforeEach, vi } from 'vitest';
import { api, downloadAuthenticated } from './api';
import { useAuthStore } from '@/stores/authStore';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

beforeEach(() => {
  mockFetch.mockReset();
  useAuthStore.setState({
    token: null,
    username: null,
    role: null,
    isAuthenticated: false,
  });
  // Clean up any leftover blobs
  vi.restoreAllMocks();
});

function mockJsonResponse(data: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

function mockNonJsonResponse(status = 200) {
  return Promise.resolve(
    new Response(null, {
      status,
      headers: {},
    }),
  );
}

describe('api()', () => {
  it('sends GET request with correct headers', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ status: 'ok' }));
    await api('GET', '/api/v1/health');
    expect(mockFetch).toHaveBeenCalledWith('/api/v1/health', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
    });
  });

  it('includes Bearer token when authenticated', async () => {
    useAuthStore.getState().setAuth('tok_secret', 'u', 'viewer');
    mockFetch.mockResolvedValue(mockJsonResponse({ status: 'ok' }));
    await api('GET', '/api/v1/status');
    const callHeaders = mockFetch.mock.calls[0][1].headers;
    expect(callHeaders.Authorization).toBe('Bearer tok_secret');
  });

  it('omits Bearer token when not authenticated', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ status: 'ok' }));
    await api('GET', '/api/v1/status');
    const callHeaders = mockFetch.mock.calls[0][1].headers;
    expect(callHeaders.Authorization).toBeUndefined();
  });

  it('sends POST with JSON body', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ id: 'z_1' }));
    const body = { name: 'example.com' };
    await api('POST', '/api/v1/zones', body);
    expect(mockFetch).toHaveBeenCalledWith('/api/v1/zones', {
      method: 'POST',
      headers: expect.objectContaining({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(body),
    });
  });

  it('parses successful JSON response', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ data: [1, 2, 3] }));
    const result = await api('GET', '/api/v1/zones');
    expect(result).toEqual({ data: [1, 2, 3] });
  });

  it('returns empty object for non-JSON success', async () => {
    mockFetch.mockResolvedValue(mockNonJsonResponse(204));
    const result = await api('DELETE', '/api/v1/zones/x');
    expect(result).toEqual({});
  });

  it('throws on 401 and clears auth', async () => {
    useAuthStore.getState().setAuth('tok_expired', 'u', 'admin');
    mockFetch.mockResolvedValue(mockJsonResponse({ error: 'unauthorized' }, 401));
    await expect(api('GET', '/api/v1/status')).rejects.toThrow('Session expired');
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });

  it('extracts error message from response body on 400', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ error: 'name is required' }, 400));
    await expect(api('POST', '/api/v1/zones', {})).rejects.toThrow('name is required');
  });

  it('uses fallback message when error response has no recognizable error field', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ weird: 'shape' }, 500));
    // HTTP/2 has no statusText, so the fallback is just "HTTP 500: "
    await expect(api('GET', '/api/v1/status')).rejects.toThrow('HTTP 500');
  });

  it('handles non-JSON error response', async () => {
    mockFetch.mockResolvedValue(
      Promise.resolve(
        new Response('Gateway Timeout', {
          status: 502,
          headers: { 'content-type': 'text/plain' },
        }),
      ),
    );
    await expect(api('GET', '/api/v1/status')).rejects.toThrow('HTTP 502');
  });

  it('handles invalid JSON error body (SyntaxError)', async () => {
    mockFetch.mockResolvedValue(
      Promise.resolve(
        new Response('not json {{{', {
          status: 500,
          headers: { 'content-type': 'application/json' },
        }),
      ),
    );
    await expect(api('GET', '/api/v1/status')).rejects.toThrow('HTTP 500');
  });

  it('extracts error message from nested error.message object', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ error: { message: 'nested msg', code: 'X' } }, 400),
    );
    await expect(api('GET', '/api/v1/status')).rejects.toThrow('nested msg');
  });

  it('extracts error code when no message in nested error object', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ error: { code: 'CODE_X' } }, 400),
    );
    await expect(api('GET', '/api/v1/status')).rejects.toThrow('CODE_X');
  });

  it('uses top-level message when no error field', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ message: 'top-level msg' }, 400),
    );
    await expect(api('GET', '/api/v1/status')).rejects.toThrow('top-level msg');
  });

  it('returns empty for non-JSON payload (not an object)', async () => {
    // No content-type, no body — should return {} as T
    mockFetch.mockResolvedValue(
      Promise.resolve(
        new Response(null, { status: 200, headers: {} }),
      ),
    );
    const r = await api('GET', '/api/v1/health');
    expect(r).toEqual({});
  });
});

describe('downloadAuthenticated', () => {
  beforeEach(() => {
    // Mock URL.createObjectURL and revokeObjectURL
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn(() => 'blob:http://localhost/test'),
      revokeObjectURL: vi.fn(),
    });
    // Mock document.createElement
    document.body.innerHTML = '';
    // Prevent jsdom's "Not implemented: navigation to another Document"
    // warning when downloadAuthenticated creates and clicks an <a> element.
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  });

  it('triggers download with auth header', async () => {
    useAuthStore.getState().setAuth('tok_dl', 'u', 'admin');
    // Construct the Response from a string, not a Blob: jsdom's Blob lacks
    // .stream() on some Node versions (CI), which throws in the Response
    // constructor. downloadAuthenticated only needs response.blob().
    mockFetch.mockResolvedValue(
      Promise.resolve(
        new Response('zone data', {
          status: 200,
          headers: { 'Content-Type': 'application/octet-stream' },
        }),
      ),
    );

    await downloadAuthenticated('/api/v1/zones/example.com/export', 'example.com.zone');

    // Verify fetch was called with auth
    expect(mockFetch).toHaveBeenCalledWith('/api/v1/zones/example.com/export', {
      headers: expect.objectContaining({ Authorization: 'Bearer tok_dl' }),
    });
  });

  it('throws on failed download', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ error: 'not found' }, 404));
    await expect(
      downloadAuthenticated('/api/v1/zones/missing/export', 'missing.zone'),
    ).rejects.toThrow('HTTP 404');
  });

  it('omits Bearer when not authenticated', async () => {
    mockFetch.mockResolvedValue(
      Promise.resolve(
        new Response('data', {
          status: 200,
          headers: { 'Content-Type': 'application/octet-stream' },
        }),
      ),
    );
    await downloadAuthenticated('/api/v1/file', 'f.txt');
    const headers = mockFetch.mock.calls[0][1].headers;
    expect(headers.Authorization).toBeUndefined();
  });
});
