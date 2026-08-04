import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { UpstreamsPage } from './upstreams';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function mockJsonResponse(data: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

const sampleUpstreams = {
  upstreams: [
    { address: '8.8.8.8:53', healthy: true, queries: 50000, failed: 50, failovers: 2 },
    { address: '1.1.1.1:53', healthy: true, queries: 48000, failed: 10, failovers: 0 },
    { address: '9.9.9.9:53', healthy: false, queries: 100, failed: 500, failovers: 5 },
  ],
};

beforeEach(() => {
  mockFetch.mockReset();
});

describe('UpstreamsPage', () => {
  it('renders loading skeleton initially', () => {
    mockFetch.mockReturnValue(new Promise(() => {}));
    render(<UpstreamsPage />);
    expect(screen.getByText('Upstreams')).toBeInTheDocument();
  });

  it('renders upstream list with health status', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleUpstreams));
    render(<UpstreamsPage />);

    // Addresses appear in both the upstream card AND health bar section
    expect(await screen.findByText('Unhealthy')).toBeInTheDocument();
    expect(screen.getAllByText('8.8.8.8:53').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('1.1.1.1:53').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('9.9.9.9:53').length).toBeGreaterThanOrEqual(1);
  });

  it('shows upstream query counts', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleUpstreams));
    render(<UpstreamsPage />);

    expect(await screen.findByText('50,000')).toBeInTheDocument();
    expect(screen.getByText('48,000')).toBeInTheDocument();
  });

  it('shows failover badges', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleUpstreams));
    render(<UpstreamsPage />);

    expect(await screen.findByText('2 failovers')).toBeInTheDocument();
  });

  it('renders empty state when no upstreams', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ upstreams: [] }));
    render(<UpstreamsPage />);

    expect(await screen.findByText('No upstream servers configured')).toBeInTheDocument();
  });

  it('renders error state when API fails', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse({ error: 'upstream err' }, 500));
    render(<UpstreamsPage />);

    expect(await screen.findByText('upstream err')).toBeInTheDocument();
    expect(screen.getByText('Retry')).toBeInTheDocument();
  });

  it('renders upstream health bars', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleUpstreams));
    render(<UpstreamsPage />);

    expect(await screen.findByText('Upstream Health')).toBeInTheDocument();
    expect(screen.getByText('DOWN')).toBeInTheDocument();
  });

  it('retries loading after error', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse({ error: 'err' }, 500))
      .mockResolvedValueOnce(mockJsonResponse(sampleUpstreams));

    const user = userEvent.setup();
    render(<UpstreamsPage />);

    expect(await screen.findByText('err')).toBeInTheDocument();
    await user.click(screen.getByText('Retry'));

    expect(screen.getAllByText('8.8.8.8:53').length).toBeGreaterThanOrEqual(1);
  });
});
