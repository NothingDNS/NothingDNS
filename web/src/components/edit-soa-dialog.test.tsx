import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { toast } from 'sonner';
import { useAuthStore } from '@/stores/authStore';
import { EditSoaDialog } from './edit-soa-dialog';
import { rnameToEmail, soaProblem } from '@/lib/soa';

// Issue #19: an operator edits the SOA of a zone from the dashboard. Only the
// changed fields are sent; the server bumps the serial.

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

function json(data: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json' },
  }));
}

const soa = {
  mname: 'ns1.example.com.', rname: 'hostmaster.example.com.', ttl: 3600, serial: 2026102701,
  refresh: 3600, retry: 600, expire: 604800, minimum: 86400,
};

beforeEach(() => {
  mockFetch.mockReset();
  vi.mocked(toast.success).mockReset();
  useAuthStore.setState({ token: 'tok', username: 'ops', role: 'operator', isAuthenticated: true });
});

describe('EditSoaDialog', () => {
  it('sends only the changed fields and reports the new SOA', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const onSaved = vi.fn();
    const updated = { ...soa, rname: 'dns.example.org.', minimum: 300, serial: 2026102702 };
    mockFetch.mockImplementation(() => json(updated));
    render(<EditSoaDialog zoneName="example.com." soa={soa} open onClose={onClose} onSaved={onSaved} />);

    expect(screen.getByLabelText('Admin e-mail')).toHaveValue('hostmaster@example.com');
    await user.clear(screen.getByLabelText('Admin e-mail'));
    await user.type(screen.getByLabelText('Admin e-mail'), 'dns@example.org');
    await user.clear(screen.getByLabelText('Minimum (negative TTL)'));
    await user.type(screen.getByLabelText('Minimum (negative TTL)'), '300');
    await user.click(screen.getByRole('button', { name: 'Save SOA' }));

    await waitFor(() => expect(onClose).toHaveBeenCalled());
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/zones/example.com./soa');
    expect(init.method).toBe('PUT');
    expect(JSON.parse(init.body as string)).toEqual({ rname: 'dns@example.org', minimum: 300 });
    expect(onSaved).toHaveBeenCalledWith(updated);
    expect(toast.success).toHaveBeenCalled();
  });

  it('closes without a request when nothing changed', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<EditSoaDialog zoneName="example.com." soa={soa} open onClose={onClose} onSaved={vi.fn()} />);
    await user.click(screen.getByRole('button', { name: 'Save SOA' }));
    expect(onClose).toHaveBeenCalled();
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('refuses a retry not shorter than refresh without calling the API', async () => {
    const user = userEvent.setup();
    render(<EditSoaDialog zoneName="example.com." soa={soa} open onClose={vi.fn()} onSaved={vi.fn()} />);
    await user.clear(screen.getByLabelText('Retry'));
    await user.type(screen.getByLabelText('Retry'), '3600');
    await user.click(screen.getByRole('button', { name: 'Save SOA' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/shorter than refresh/i);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('shows the server error and stays open', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    mockFetch.mockImplementation(() => json({ error: 'invalid admin email "a.b@example.com"' }, 400));
    render(<EditSoaDialog zoneName="example.com." soa={soa} open onClose={onClose} onSaved={vi.fn()} />);
    await user.clear(screen.getByLabelText('Admin e-mail'));
    await user.type(screen.getByLabelText('Admin e-mail'), 'a.b@example.com');
    await user.click(screen.getByRole('button', { name: 'Save SOA' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('invalid admin email');
    expect(onClose).not.toHaveBeenCalled();
  });
});

describe('soa helpers', () => {
  it('shows an RNAME as an address', () => {
    expect(rnameToEmail('hostmaster.example.com.')).toBe('hostmaster@example.com');
    expect(rnameToEmail('root.')).toBe('root.');
  });

  it.each([
    [{ expire: '600' }, /expire must be longer/i],
    [{ refresh: '0' }, /greater than zero/i],
    [{ minimum: '-1' }, /whole number/i],
    [{ ttl: '2147483648' }, /whole number/i],
    [{ mname: ' ' }, /primary nameserver/i],
  ])('rejects %o', (change, message) => {
    const fields = {
      mname: soa.mname, rname: 'hostmaster@example.com', ttl: '3600', refresh: '3600',
      retry: '600', expire: '604800', minimum: '86400', ...change,
    };
    expect(soaProblem(fields)).toMatch(message);
  });
});
