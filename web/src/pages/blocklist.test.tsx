import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BlocklistPage } from './blocklist';

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

const sampleStatus = {
  enabled: true, total_rules: 50000, files_count: 3, urls_count: 2,
};

beforeEach(() => {
  mockFetch.mockReset();
});

describe('BlocklistPage', () => {
  it('renders loading skeleton initially', () => {
    mockFetch.mockReturnValue(new Promise(() => {}));
    render(<BlocklistPage />);
    expect(screen.getByText('Blocklist')).toBeInTheDocument();
  });

  it('renders blocklist status', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleStatus));
    render(<BlocklistPage />);

    await waitFor(() => {
      expect(screen.getByText('50,000')).toBeInTheDocument();
    });
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();
    expect(screen.getByText('Enabled')).toBeInTheDocument();
  });

  it('shows Disabled badge when blocklist is off', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ enabled: false, total_rules: 0, files_count: 0, urls_count: 0 }),
    );
    render(<BlocklistPage />);

    await waitFor(() => {
      expect(screen.getByText('Disabled')).toBeInTheDocument();
    });
  });

  it('renders error state when API fails', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ error: 'blocklist error' }, 500));
    render(<BlocklistPage />);

    await waitFor(() => {
      expect(screen.getByText('blocklist error')).toBeInTheDocument();
    });
    expect(screen.getByText('Retry')).toBeInTheDocument();
  });

  it('calls toggle API', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse(sampleStatus))
      .mockResolvedValueOnce(mockJsonResponse({ success: true }))
      .mockResolvedValueOnce(mockJsonResponse({ ...sampleStatus, enabled: false }));

    const user = userEvent.setup();
    render(<BlocklistPage />);

    await waitFor(() => {
      expect(screen.getByText('50,000')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Disable'));

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/blocklists/toggle',
        expect.objectContaining({ method: 'POST' }),
      );
    });
  });

  it('calls add file API', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse(sampleStatus))
      .mockResolvedValueOnce(mockJsonResponse({ success: true }))
      .mockResolvedValueOnce(mockJsonResponse(sampleStatus));

    const user = userEvent.setup();
    render(<BlocklistPage />);

    await waitFor(() => {
      expect(screen.getByText('50,000')).toBeInTheDocument();
    });

    await user.type(screen.getByPlaceholderText('/etc/nothingdns/blocklist.txt'), '/data/blocklist.txt');
    await user.click(screen.getByText('Add File'));

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/blocklists',
        expect.objectContaining({ method: 'POST', body: JSON.stringify({ file: '/data/blocklist.txt' }) }),
      );
    });
  });

  it('adds file on Enter key', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse(sampleStatus))
      .mockResolvedValueOnce(mockJsonResponse({ success: true }))
      .mockResolvedValueOnce(mockJsonResponse(sampleStatus));

    const user = userEvent.setup();
    render(<BlocklistPage />);

    await waitFor(() => {
      expect(screen.getByText('50,000')).toBeInTheDocument();
    });

    await user.type(screen.getByPlaceholderText('/etc/nothingdns/blocklist.txt'), '/data/blocklist.txt{Enter}');

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/blocklists',
        expect.objectContaining({ method: 'POST' }),
      );
    });
  });

  it('does not call add file API with empty input', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleStatus));
    const user = userEvent.setup();
    render(<BlocklistPage />);

    await waitFor(() => {
      expect(screen.getByText('50,000')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Add File'));
    const postCalls = mockFetch.mock.calls.filter(([, opts]) => opts?.method === 'POST');
    expect(postCalls).toHaveLength(0);
  });

  it('retries loading after error', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse({ error: 'err' }, 500))
      .mockResolvedValueOnce(mockJsonResponse(sampleStatus));

    const user = userEvent.setup();
    render(<BlocklistPage />);

    await waitFor(() => {
      expect(screen.getByText('err')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Retry'));

    await waitFor(() => {
      expect(screen.getByText('50,000')).toBeInTheDocument();
    });
  });

  it('ignores stale status that resolves after a newer load', async () => {
    // fetchStatus has overlapping triggers: the 10s polling interval plus
    // the toggle/add handlers. A superseded load's response landing after a
    // newer one's must NOT revert state — an operator who added a file and
    // then toggled blocking on must not see the counts revert to zero.
    const user = userEvent.setup();
    const staleStatus = { enabled: false, total_rules: 0, files_count: 0, urls_count: 0 };

    // Mount renders the initial (disabled) status.
    mockFetch.mockResolvedValueOnce(mockJsonResponse(staleStatus));
    render(<BlocklistPage />);
    await waitFor(() => {
      expect(screen.getByText('Disabled')).toBeInTheDocument();
    });

    // Add a file: POST resolves, then the post-add refresh HANGS (this load
    // will be superseded by the toggle's).
    let resolveStaleRefresh!: (value: unknown) => void;
    mockFetch
      .mockImplementationOnce(() => mockJsonResponse({ success: true }))
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveStaleRefresh = resolve;
          }),
      );
    await user.type(screen.getByPlaceholderText('/etc/nothingdns/blocklist.txt'), '/data/blocklist.txt');
    await user.click(screen.getByText('Add File'));

    // Toggle: POST resolves, the post-toggle refresh resolves ENABLED.
    mockFetch
      .mockImplementationOnce(() => mockJsonResponse({ success: true }))
      .mockImplementationOnce(() =>
        mockJsonResponse({ enabled: true, total_rules: 1, files_count: 1, urls_count: 1 }),
      );
    await user.click(screen.getByText('Enable'));
    await waitFor(() => {
      expect(screen.getByText('Enabled')).toBeInTheDocument();
    });

    // The superseded post-add refresh lands late. It must be ignored.
    resolveStaleRefresh(mockJsonResponse(staleStatus));
    await act(async () => {
      await Promise.resolve();
    });
    expect(screen.queryByText('Disabled')).not.toBeInTheDocument();
    expect(screen.getByText('Enabled')).toBeInTheDocument();
  });

  it('ignores late rejections from superseded loads', async () => {
    // The secondary branch: a superseded load's rejection landing after the
    // post-toggle refresh must not flip a good render into the error page.
    // DOMException is not an Error subclass here, so fetchStatus renders the
    // fallback message.
    const user = userEvent.setup();
    const staleStatus = { enabled: false, total_rules: 0, files_count: 0, urls_count: 0 };

    // Mount renders the initial (disabled) status.
    mockFetch.mockResolvedValueOnce(mockJsonResponse(staleStatus));
    render(<BlocklistPage />);
    await waitFor(() => {
      expect(screen.getByText('Disabled')).toBeInTheDocument();
    });

    // Add a file: POST resolves, the post-add refresh HANGS (superseded).
    let rejectStaleRefresh!: (reason?: unknown) => void;
    mockFetch
      .mockImplementationOnce(() => mockJsonResponse({ success: true }))
      .mockImplementationOnce(
        () =>
          new Promise((_resolve, reject) => {
            rejectStaleRefresh = reject;
          }),
      );
    await user.type(screen.getByPlaceholderText('/etc/nothingdns/blocklist.txt'), '/data/blocklist.txt');
    await user.click(screen.getByText('Add File'));

    // Toggle: POST resolves, the post-toggle refresh resolves ENABLED.
    mockFetch
      .mockImplementationOnce(() => mockJsonResponse({ success: true }))
      .mockImplementationOnce(() =>
        mockJsonResponse({ enabled: true, total_rules: 1, files_count: 1, urls_count: 1 }),
      );
    await user.click(screen.getByText('Enable'));
    await waitFor(() => {
      expect(screen.getByText('Enabled')).toBeInTheDocument();
    });

    // The superseded post-add rejection lands late. It must be ignored:
    // DOMException is not an Error subclass here, so fetchStatus would
    // render the fallback message via the error state.
    rejectStaleRefresh(new DOMException('The operation was aborted.', 'AbortError'));
    await act(async () => {
      await Promise.resolve();
    });
    expect(screen.queryByText('Failed to load blocklist status')).not.toBeInTheDocument();
    expect(screen.getByText('Enabled')).toBeInTheDocument();
  });
});
