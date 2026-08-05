import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ZoneDetailPage } from './zone-detail';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

const mockNavigate = vi.fn();
vi.mock('react-router', () => ({
  useParams: () => ({ name: 'example.com.' }),
  useNavigate: () => mockNavigate,
}));

function mockJsonResponse(data: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

const sampleZone = {
  name: 'example.com.', records: 5, serial: 2026071501,
  soa: { mname: 'ns1.example.com.', rname: 'admin.example.com.', serial: 2026071501, refresh: 3600, retry: 900, expire: 86400, minimum: 300 },
};

const sampleRecords = {
  records: [
    { name: 'example.com.', type: 'SOA', ttl: 3600, class: 'IN', data: '...' },
    { name: 'example.com.', type: 'A', ttl: 300, class: 'IN', data: '192.0.2.1' },
    { name: 'example.com.', type: 'DNSKEY', ttl: 3600, class: 'IN', data: '256 3 13 ...' },
  ],
};

const sampleRecordsUnsigned = {
  records: [
    { name: 'example.com.', type: 'SOA', ttl: 3600, class: 'IN', data: '...' },
    { name: 'example.com.', type: 'A', ttl: 300, class: 'IN', data: '192.0.2.1' },
  ],
};

beforeEach(() => {
  mockFetch.mockReset();
  mockNavigate.mockReset();
});

describe('ZoneDetailPage', () => {
  it('renders loading skeleton initially', () => {
    mockFetch.mockReturnValue(new Promise(() => {}));
    render(<ZoneDetailPage />);
    expect(screen.getByText('Zones')).toBeInTheDocument();
    expect(screen.getAllByText('example.com.').length).toBeGreaterThanOrEqual(1);
  });

  it('renders zone detail after loading', async () => {
    mockFetch.mockResolvedValueOnce(mockJsonResponse(sampleZone));
    mockFetch.mockResolvedValueOnce(mockJsonResponse(sampleRecords));
    render(<ZoneDetailPage />);

    expect(await screen.findByText('ns1.example.com.')).toBeInTheDocument();
    expect(screen.getByText('5 records')).toBeInTheDocument();
    expect(screen.getByText('DNSSEC signed')).toBeInTheDocument();
  });

  it('shows DNSSEC unsigned when no DNSKEY/RRSIG records', async () => {
    mockFetch.mockResolvedValueOnce(mockJsonResponse(sampleZone));
    mockFetch.mockResolvedValueOnce(mockJsonResponse(sampleRecordsUnsigned));
    render(<ZoneDetailPage />);

    expect(await screen.findByText('DNSSEC unsigned')).toBeInTheDocument();
  });

  it('renders error state when API fails', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse({ error: 'not-found' }, 404))
      .mockResolvedValueOnce(mockJsonResponse({ error: 'not-found' }, 404));
    render(<ZoneDetailPage />);

    expect(await screen.findByText(/not-found/)).toBeInTheDocument();
    expect(screen.getByText('Retry')).toBeInTheDocument();
  });

  it('navigates back to zones on breadcrumb click', async () => {
    mockFetch.mockResolvedValueOnce(mockJsonResponse(sampleZone));
    mockFetch.mockResolvedValueOnce(mockJsonResponse(sampleRecords));
    const user = userEvent.setup();
    render(<ZoneDetailPage />);

    expect(await screen.findByText('ns1.example.com.')).toBeInTheDocument();
    await user.click(screen.getByText('Zones'));
    expect(mockNavigate).toHaveBeenCalledWith('/zones');
  });

  it('retries loading after error', async () => {
    // First: all calls fail; then: success
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse({ error: 'timeout' }, 500))
      .mockResolvedValueOnce(mockJsonResponse({ error: 'timeout' }, 500))
      .mockResolvedValueOnce(mockJsonResponse(sampleZone))
      .mockResolvedValueOnce(mockJsonResponse(sampleRecords));

    const user = userEvent.setup();
    render(<ZoneDetailPage />);

    expect(await screen.findByText(/timeout/)).toBeInTheDocument();
    await user.click(screen.getByText('Retry'));

    expect(await screen.findByText('ns1.example.com.')).toBeInTheDocument();
  });

  it('renders SOA fields', async () => {
    mockFetch.mockResolvedValueOnce(mockJsonResponse(sampleZone));
    mockFetch.mockResolvedValueOnce(mockJsonResponse(sampleRecords));
    render(<ZoneDetailPage />);

    expect(await screen.findByText('SOA Record')).toBeInTheDocument();
    expect(screen.getByText('admin.example.com.')).toBeInTheDocument();
  });
});
