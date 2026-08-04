import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
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
});
