import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { RPZPage } from './rpz';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: vi.fn() },
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
  enabled: true, total_rules: 100, qname_rules: 80,
  total_matches: 5000, total_lookups: 100000,
};

const sampleRules = {
  rules: [
    { pattern: 'bad.example.com', action: 'NXDOMAIN', trigger: 'qname', policy_name: 'default', priority: 10 },
    { pattern: 'malware.test', action: 'NODATA', trigger: 'qname', policy_name: 'default', priority: 20 },
  ],
};

beforeEach(() => {
  mockFetch.mockReset();
});

describe('RPZPage', () => {
  it('renders loading skeleton initially', () => {
    mockFetch.mockReturnValue(new Promise(() => {}));
    render(<RPZPage />);
    expect(screen.getByText('RPZ')).toBeInTheDocument();
  });

  it('renders RPZ stats and rules', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse(sampleStats))
      .mockResolvedValueOnce(mockJsonResponse(sampleRules));
    render(<RPZPage />);

    expect(await screen.findByText('100')).toBeInTheDocument();
    expect(screen.getByText('80')).toBeInTheDocument();
    expect(screen.getByText('5,000')).toBeInTheDocument();
    expect(screen.getByText('100,000')).toBeInTheDocument();
    expect(screen.getByText('bad.example.com')).toBeInTheDocument();
    expect(screen.getByText('malware.test')).toBeInTheDocument();
    // NODATA appears both as select option and rule badge
    expect(screen.getAllByText('NODATA').length).toBeGreaterThanOrEqual(1);
  });

  it('shows disabled warning when RPZ is off', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse({ ...sampleStats, enabled: false }))
      .mockResolvedValueOnce(mockJsonResponse({ rules: [] }));
    render(<RPZPage />);

    expect(await screen.findByText('RPZ is disabled')).toBeInTheDocument();
  });

  it('renders empty rules state', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse(sampleStats))
      .mockResolvedValueOnce(mockJsonResponse({ rules: [] }));
    render(<RPZPage />);

    expect(await screen.findByText('No RPZ rules configured')).toBeInTheDocument();
  });

  it('renders error state when API fails', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse({ error: 'rpz error' }, 500))
      .mockResolvedValueOnce(mockJsonResponse({ error: 'rpz error' }, 500));
    render(<RPZPage />);

    expect(await screen.findByText('rpz error')).toBeInTheDocument();
    expect(screen.getByText('Retry')).toBeInTheDocument();
  });

  it('calls add rule API', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse(sampleStats))
      .mockResolvedValueOnce(mockJsonResponse(sampleRules))
      .mockResolvedValueOnce(mockJsonResponse({ success: true }))
      .mockResolvedValueOnce(mockJsonResponse(sampleStats))
      .mockResolvedValueOnce(mockJsonResponse(sampleRules));

    const user = userEvent.setup();
    render(<RPZPage />);

    expect(await screen.findByText('bad.example.com')).toBeInTheDocument();

    await user.type(screen.getByPlaceholderText('domain.example.com'), 'spam.domain');
    await user.click(screen.getByText('Add Rule'));

    // Wait for the POST call to be made
    await vi.waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/rpz/rules',
        expect.objectContaining({ method: 'POST' }),
      );
    });
  });

  it('calls toggle API', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse(sampleStats))
      .mockResolvedValueOnce(mockJsonResponse(sampleRules))
      .mockResolvedValueOnce(mockJsonResponse({ success: true }))
      .mockResolvedValueOnce(mockJsonResponse({ ...sampleStats, enabled: false }))
      .mockResolvedValueOnce(mockJsonResponse({ rules: [] }));

    const user = userEvent.setup();
    render(<RPZPage />);

    expect(await screen.findByText('bad.example.com')).toBeInTheDocument();
    await user.click(screen.getByText('Disable'));

    await vi.waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/rpz/toggle',
        expect.objectContaining({ method: 'POST' }),
      );
    });
  });

  it('opens delete rule confirmation', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse(sampleStats))
      .mockResolvedValueOnce(mockJsonResponse(sampleRules));
    const user = userEvent.setup();
    render(<RPZPage />);

    expect(await screen.findByText('bad.example.com')).toBeInTheDocument();
    await user.click(screen.getByLabelText('Delete rule bad.example.com'));
    expect(screen.getByText(/Delete rule "bad.example.com"/)).toBeInTheDocument();
  });

  it('ignores stale responses that resolve after a newer load', async () => {
    // fetchData has overlapping triggers: the 10s polling interval plus the
    // toggle/add/delete handlers, which each call fetchData() right after
    // their mutation. A response from a superseded load landing after a
    // newer one's must NOT overwrite fresher state.
    vi.useFakeTimers();
    try {
      // Mount: both requests resolve, the page renders.
      mockFetch
        .mockImplementationOnce(() => mockJsonResponse(sampleStats))
        .mockImplementationOnce(() => mockJsonResponse(sampleRules));
      render(<RPZPage />);
      await act(async () => {
        await Promise.resolve();
      });
      expect(screen.getByText('bad.example.com')).toBeInTheDocument();

      // Tick 1 (t=10s): the interval's fetchData starts; its stats hang.
      let resolveTickStats!: (value: unknown) => void;
      mockFetch
        .mockImplementationOnce(
          () =>
            new Promise((resolve) => {
              resolveTickStats = resolve;
            }),
        )
        .mockImplementationOnce(() => mockJsonResponse(sampleRules));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(10000);
      });

      // Tick 2 (t=20s): the next fetchData resolves FRESH (total_rules=999).
      mockFetch
        .mockImplementationOnce(() => mockJsonResponse({ ...sampleStats, total_rules: 999 }))
        .mockImplementationOnce(() => mockJsonResponse(sampleRules));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(10000);
      });
      expect(screen.getByText('999')).toBeInTheDocument();

      // Tick 1's stale stats finally land. They must be ignored.
      resolveTickStats(mockJsonResponse({ ...sampleStats, total_rules: 1 }));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      expect(screen.queryByText('1')).not.toBeInTheDocument();
      expect(screen.getByText('999')).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it('ignores late rejections from superseded loads', async () => {
    // The secondary branch: a superseded load's rejection landing after the
    // next load's success must not flip a good render into the error page.
    vi.useFakeTimers();
    try {
      // Mount: both requests resolve, the page renders.
      mockFetch
        .mockImplementationOnce(() => mockJsonResponse(sampleStats))
        .mockImplementationOnce(() => mockJsonResponse(sampleRules));
      render(<RPZPage />);
      await act(async () => {
        await Promise.resolve();
      });
      expect(screen.getByText('bad.example.com')).toBeInTheDocument();

      // Tick 1 (t=10s): the interval's fetchData starts; its stats hang and
      // will be REJECTED late (the api() 10s timeout's abort).
      let rejectTickStats!: (reason?: unknown) => void;
      mockFetch
        .mockImplementationOnce(
          (_path: string, init?: RequestInit) =>
            new Promise((_resolve, reject) => {
              rejectTickStats = reject;
              init?.signal?.addEventListener('abort', () => {
                reject(new DOMException('The operation was aborted.', 'AbortError'));
              });
            }),
        )
        .mockImplementationOnce(() => mockJsonResponse(sampleRules));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(10000);
      });

      // Tick 2 (t=20s): the next fetchData resolves FRESH.
      mockFetch
        .mockImplementationOnce(() => mockJsonResponse({ ...sampleStats, total_rules: 999 }))
        .mockImplementationOnce(() => mockJsonResponse(sampleRules));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(10000);
      });
      expect(screen.getByText('999')).toBeInTheDocument();

      // Tick 1's late rejection lands. It must be ignored: DOMException is
      // not an Error subclass here, so fetchData renders the fallback
      // message via ErrorState — its appearance is the bug.
      rejectTickStats(new DOMException('The operation was aborted.', 'AbortError'));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      expect(screen.queryByText('Failed to load RPZ data')).not.toBeInTheDocument();
      expect(screen.getByText('999')).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });
});
