import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/react';
import App from './App';
import { useAuthStore } from '@/stores/authStore';

// Mount-time token validation must log the operator out ONLY when the
// server says the token is invalid (401). The old code cleared auth on ANY
// non-ok status, so a backend restart or a maintenance proxy answering 503
// silently logged the operator out of a perfectly valid session — and
// contradicted the 401-only convention api.ts and useApi.ts already follow.

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

vi.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: () => ({ connected: false, error: null }),
}));

function jsonBody(body: unknown, status: number) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

// Route-aware mock: the App's status check, the dashboard's stats loads, and
// any other consumer race on mount (child effects run before parent ones),
// so queue-based Once mocks are order-dependent. Matching on the URL makes
// every consumer's response deterministic.
function routeStatusFetch(statusForStatusCheck: number) {
  mockFetch.mockImplementation((input: unknown) => {
    const url = typeof input === 'string' ? input : String((input as Request).url);
    if (url.includes('/api/v1/status')) {
      return Promise.resolve(jsonBody({}, statusForStatusCheck));
    }
    return Promise.resolve(jsonBody({}, 200));
  });
}

function renderAuthedApp() {
  useAuthStore.setState({
    isAuthenticated: true,
    token: 'valid-token',
    username: 'op',
    role: 'admin',
  });
  render(<App />);
}

beforeEach(() => {
  mockFetch.mockReset();
});

describe('mount-time token validation', () => {
  it('keeps the session when the status endpoint fails with a server error', async () => {
    // The implementation must be set BEFORE render: the mount effects fire
    // during render, and an unimplemented stub returns undefined.
    routeStatusFetch(503);
    renderAuthedApp();
    // A 503 is a server problem, not an invalid token.

    await vi.waitFor(() => expect(mockFetch).toHaveBeenCalled());
    // Let the handler's promise chain settle.
    await Promise.resolve();
    await Promise.resolve();

    expect(useAuthStore.getState().isAuthenticated).toBe(true);
  });

  it('still clears the session on an explicit 401', async () => {
    routeStatusFetch(401);
    renderAuthedApp();

    await vi.waitFor(() => expect(mockFetch).toHaveBeenCalled());
    await Promise.resolve();
    await Promise.resolve();

    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });
});
