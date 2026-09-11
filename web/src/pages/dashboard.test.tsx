import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DashboardPage } from './dashboard';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

vi.mock('@/stores/queryStream', () => ({
  useQueryStream: (selector: (s: { events: unknown[]; connected: boolean }) => unknown) => {
    const state = { events: [], connected: false };
    return selector ? selector(state) : state;
  },
}));

function mockJsonResponse(data: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

const sampleStats = {
  uptime: 86400, queriesTotal: 1500000, queriesPerSec: 245.5,
  cacheHitRate: 87.3, blockedQueries: 12345, activeClients: 42,
  zoneCount: 15, upstreamLatency: 12.5,
};

beforeEach(() => {
  mockFetch.mockReset();
});

describe('DashboardPage', () => {
  it('renders loading skeleton initially', () => {
    mockFetch.mockReturnValue(new Promise(() => {}));
    render(<DashboardPage />);
    expect(screen.getByText('Dashboard')).toBeInTheDocument();
    expect(screen.getByLabelText('Refresh stats')).toBeInTheDocument();
  });

  it('renders stat cards after loading', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleStats));
    render(<DashboardPage />);

    expect(await screen.findByText('Total Queries')).toBeInTheDocument();
    expect(screen.getByText('1,500,000')).toBeInTheDocument();
    expect(screen.getByText('87.3%')).toBeInTheDocument();
    expect(screen.getByText('12,345')).toBeInTheDocument();
    expect(screen.getByText('1d 0h')).toBeInTheDocument();
  });

  it('renders error banner when API fails', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ error: 'not ready' }, 503));
    render(<DashboardPage />);

    expect(await screen.findByText('not ready')).toBeInTheDocument();
  });

  it('renders live query stream section', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleStats));
    render(<DashboardPage />);

    expect(await screen.findByText('Live Query Stream')).toBeInTheDocument();
    expect(screen.getByText('Waiting for DNS queries...')).toBeInTheDocument();
  });

  it('shows last update timestamp', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleStats));
    render(<DashboardPage />);

    // Wait for the stats to load, then check "Updated" text exists
    expect(await screen.findByText('Total Queries')).toBeInTheDocument();
    expect(screen.getByText(/Updated/)).toBeInTheDocument();
  });

  it('refreshes stats on refresh button click', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleStats));
    const user = userEvent.setup();
    render(<DashboardPage />);

    expect(await screen.findByText('1,500,000')).toBeInTheDocument();

    mockFetch.mockResolvedValue(mockJsonResponse({ ...sampleStats, queriesTotal: 2000000 }));
    await user.click(screen.getByLabelText('Refresh stats'));

    expect(await screen.findByText('2,000,000')).toBeInTheDocument();
  });

  it('shows stat cards with zero values', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({
      uptime: 0, queriesTotal: 0, queriesPerSec: 0, cacheHitRate: 0,
      blockedQueries: 0, activeClients: 0, zoneCount: 0, upstreamLatency: 0,
    }));
    render(<DashboardPage />);

    expect(await screen.findByText('0m')).toBeInTheDocument();
    expect(screen.getByText('0.0%')).toBeInTheDocument();
  });

  it('ignores stale stats that resolve after a newer load', async () => {
    // loadStats has two overlapping triggers: the 5s polling interval and
    // the Refresh button. An older response landing after a newer one must
    // NOT overwrite fresher state — a stalled request aborts at the 10s
    // api() timeout, two ticks later, so the overlap is reachable on every
    // stall.
    vi.useFakeTimers();
    try {
      // load1: the stats request hangs (will resolve STALE later).
      let resolveStaleStats!: (value: unknown) => void;
      mockFetch.mockImplementation(
        () =>
          new Promise((resolve) => {
            resolveStaleStats = resolve;
          }),
      );
      render(<DashboardPage />);

      // 5s tick: the interval fires load2, whose stats are fresh.
      mockFetch.mockResolvedValue(
        mockJsonResponse({ ...sampleStats, queriesTotal: 2000000 }),
      );
      await act(async () => {
        await vi.advanceTimersByTimeAsync(5000);
      });
      expect(screen.getByText('2,000,000')).toBeInTheDocument();

      // The stale load1 response finally lands. It must be ignored.
      resolveStaleStats(mockJsonResponse(sampleStats));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      expect(screen.queryByText('1,500,000')).not.toBeInTheDocument();
      expect(screen.getByText('2,000,000')).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it('ignores late rejections from superseded loads', async () => {
    // The secondary branch: a stalled load aborts at the 10s api() timeout
    // and its rejection lands after fresher ticks — it must not flip a
    // good render into the error banner.
    vi.useFakeTimers();
    try {
      let rejectStaleStats!: (reason?: unknown) => void;
      mockFetch.mockImplementation(
        () =>
          new Promise((_, reject) => {
            rejectStaleStats = reject;
          }),
      );
      render(<DashboardPage />);

      mockFetch.mockResolvedValue(
        mockJsonResponse({ ...sampleStats, queriesTotal: 2000000 }),
      );
      await act(async () => {
        await vi.advanceTimersByTimeAsync(5000);
      });
      expect(screen.getByText('2,000,000')).toBeInTheDocument();

      rejectStaleStats(new DOMException('The operation was aborted.', 'AbortError'));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      // DOMException is not an Error subclass here, so loadStats renders the
      // fallback message — the banner itself is the bug being guarded against.
      expect(screen.queryByText('Failed to load stats')).not.toBeInTheDocument();
      expect(screen.getByText('2,000,000')).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });
});
