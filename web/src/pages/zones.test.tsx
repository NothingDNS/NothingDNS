import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ZonesPage } from './zones';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

const mockNavigate = vi.fn();
vi.mock('react-router', () => ({
  useNavigate: () => mockNavigate,
}));

vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

const sampleZones = {
  zones: [
    { name: 'example.com.', serial: 2026071501, records: 5 },
    { name: 'test.org.', serial: 2026071502, records: 3 },
  ],
};

function mockJsonResponse(data: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

beforeEach(() => {
  mockFetch.mockReset();
  mockNavigate.mockReset();
});

describe('ZonesPage', () => {
  it('renders loading skeleton initially', () => {
    mockFetch.mockReturnValue(new Promise(() => {}));
    render(<ZonesPage />);
    expect(screen.getByText('DNS Zones')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Search zones...')).toBeInTheDocument();
  });

  it('renders zone list after loading', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleZones));
    render(<ZonesPage />);

    await waitFor(() => {
      expect(screen.getByText('example.com.')).toBeInTheDocument();
    });
    expect(screen.getByText('test.org.')).toBeInTheDocument();
    expect(screen.getByText('2026071501')).toBeInTheDocument();
    expect(screen.getByText('5 records')).toBeInTheDocument();
  });

  it('renders error state when API fails', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ error: 'server error' }, 500));
    render(<ZonesPage />);

    await waitFor(() => {
      expect(screen.getByText('server error')).toBeInTheDocument();
    });
    expect(screen.getByText('Retry')).toBeInTheDocument();
  });

  it('renders empty state when no zones exist', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ zones: [] }));
    render(<ZonesPage />);

    await waitFor(() => {
      expect(screen.getByText('No zones configured')).toBeInTheDocument();
    });
    expect(screen.getByText('Create your first DNS zone to get started.')).toBeInTheDocument();
  });

  it('filters zones by search term', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleZones));
    const user = userEvent.setup();
    render(<ZonesPage />);

    await waitFor(() => {
      expect(screen.getByText('example.com.')).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText('Search zones...');
    await user.type(searchInput, 'test');

    expect(screen.queryByText('example.com.')).not.toBeInTheDocument();
    expect(screen.getByText('test.org.')).toBeInTheDocument();
  });

  it('shows no matching zones message when filter yields no results', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleZones));
    const user = userEvent.setup();
    render(<ZonesPage />);

    await waitFor(() => {
      expect(screen.getByText('example.com.')).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText('Search zones...');
    await user.type(searchInput, 'nonexistent');

    expect(screen.getByText('No matching zones')).toBeInTheDocument();
  });

  it('navigates to zone detail on card click', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleZones));
    const user = userEvent.setup();
    render(<ZonesPage />);

    await waitFor(() => {
      expect(screen.getByText('example.com.')).toBeInTheDocument();
    });

    await user.click(screen.getByText('example.com.'));
    expect(mockNavigate).toHaveBeenCalledWith('/zones/example.com.');
  });

  it('navigates to zone detail via external link button', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleZones));
    const user = userEvent.setup();
    render(<ZonesPage />);

    await waitFor(() => {
      expect(screen.getByText('example.com.')).toBeInTheDocument();
    });

    await user.click(screen.getByLabelText('Open zone example.com.'));
    expect(mockNavigate).toHaveBeenCalledWith('/zones/example.com.');
  });

  it('opens create zone dialog', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleZones));
    const user = userEvent.setup();
    render(<ZonesPage />);

    await waitFor(() => {
      expect(screen.getByText('example.com.')).toBeInTheDocument();
    });

    // Use getAllByText and pick the first (toolbar) button
    const createBtns = screen.getAllByRole('button', { name: /Create Zone/ });
    await user.click(createBtns[0]);

    expect(screen.getByText('Create New Zone')).toBeInTheDocument();
  });

  it('opens delete confirmation dialog', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleZones));
    const user = userEvent.setup();
    render(<ZonesPage />);

    await waitFor(() => {
      expect(screen.getByText('example.com.')).toBeInTheDocument();
    });

    await user.click(screen.getByLabelText('Delete zone example.com.'));
    expect(screen.getByText(/Delete zone example.com./)).toBeInTheDocument();
  });

  it('calls API to delete zone and reloads', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse(sampleZones))
      .mockResolvedValueOnce(mockJsonResponse({ success: true }))
      .mockResolvedValueOnce(mockJsonResponse(sampleZones));

    const user = userEvent.setup();
    render(<ZonesPage />);

    await waitFor(() => {
      expect(screen.getByText('example.com.')).toBeInTheDocument();
    });

    await user.click(screen.getByLabelText('Delete zone example.com.'));
    await user.click(screen.getByText('Delete'));

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/zones/example.com.',
        expect.objectContaining({ method: 'DELETE' }),
      );
    });
  });

  it('shows create zone dialog with auto-filled defaults', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse(sampleZones));
    const user = userEvent.setup();
    render(<ZonesPage />);

    await waitFor(() => {
      expect(screen.getByText('example.com.')).toBeInTheDocument();
    });

    const createBtns = screen.getAllByRole('button', { name: /Create Zone/ });
    await user.click(createBtns[0]);

    expect(screen.getByText('Create New Zone')).toBeInTheDocument();
    expect(screen.getByDisplayValue('3600')).toBeInTheDocument();
  });

  it('retries loading after error', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse({ error: 'err' }, 500))
      .mockResolvedValueOnce(mockJsonResponse(sampleZones));

    const user = userEvent.setup();
    render(<ZonesPage />);

    await waitFor(() => {
      expect(screen.getByText('err')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Retry'));

    await waitFor(() => {
      expect(screen.getByText('example.com.')).toBeInTheDocument();
    });
  });
});
