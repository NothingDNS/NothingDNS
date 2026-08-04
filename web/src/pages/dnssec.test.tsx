import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DNSSECPage } from './dnssec';

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

beforeEach(() => {
  mockFetch.mockReset();
});

describe('DNSSECPage', () => {
  it('renders loading skeleton initially', () => {
    mockFetch.mockReturnValue(new Promise(() => {}));
    render(<DNSSECPage />);
    expect(screen.getByText('DNSSEC')).toBeInTheDocument();
  });

  it('renders DNSSEC enabled status', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ enabled: true, require_dnssec: false }),
    );
    render(<DNSSECPage />);

    await waitFor(() => {
      expect(screen.getByText('Enabled')).toBeInTheDocument();
    });
    expect(screen.getByText('Optional')).toBeInTheDocument();
  });

  it('renders DNSSEC disabled with warning', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ enabled: false, require_dnssec: false }),
    );
    render(<DNSSECPage />);

    await waitFor(() => {
      expect(screen.getByText('Disabled')).toBeInTheDocument();
    });
    expect(screen.getByText('DNSSEC is not enabled')).toBeInTheDocument();
  });

  it('shows required validation when require_dnssec is true', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ enabled: true, require_dnssec: true }),
    );
    render(<DNSSECPage />);

    await waitFor(() => {
      expect(screen.getByText('Required')).toBeInTheDocument();
    });
  });

  it('renders error state when API fails', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ error: 'dnssec error' }, 500));
    render(<DNSSECPage />);

    await waitFor(() => {
      expect(screen.getByText('dnssec error')).toBeInTheDocument();
    });
    expect(screen.getByText('Retry')).toBeInTheDocument();
  });

  it('retries loading after error', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse({ error: 'fail' }, 500))
      .mockResolvedValueOnce(
        mockJsonResponse({ enabled: true, require_dnssec: false }),
      );

    const user = userEvent.setup();
    render(<DNSSECPage />);

    await waitFor(() => {
      expect(screen.getByText('fail')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Retry'));

    await waitFor(() => {
      expect(screen.getByText('Enabled')).toBeInTheDocument();
    });
  });

  it('renders DNSSEC configuration info card', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ enabled: true, require_dnssec: false }),
    );
    render(<DNSSECPage />);

    await waitFor(() => {
      expect(screen.getByText('DNSSEC Configuration')).toBeInTheDocument();
    });
  });
});
