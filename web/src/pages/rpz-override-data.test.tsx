import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { RPZPage } from './rpz';

// F432: POST /api/v1/rpz/rules requires override_data for CNAME (a domain
// name) and OVERRIDE (an IP address) rules and answers 400 without it. The
// form offered both actions but never sent override_data, so every
// dashboard-made CNAME/OVERRIDE rule failed (before the server check: was
// stored broken). The form must collect, validate and send it.

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

const stats = { enabled: true, total_rules: 0, qname_rules: 0, total_matches: 0, total_lookups: 0 };

function postBodies(): Record<string, unknown>[] {
  return mockFetch.mock.calls
    .filter(([, init]) => (init as RequestInit | undefined)?.method === 'POST')
    .map(([, init]) => JSON.parse((init as RequestInit).body as string));
}

beforeEach(() => {
  mockFetch.mockReset();
  mockFetch.mockImplementation((url: string, init?: RequestInit) => {
    if (init?.method === 'POST') return json({ message: 'Rule added' }, 201);
    if (url.endsWith('/api/v1/rpz/rules')) return json({ rules: [] });
    return json(stats);
  });
});

async function setup(action: string) {
  const user = userEvent.setup();
  render(<RPZPage />);
  await screen.findByText('No RPZ rules configured');
  await user.type(screen.getByPlaceholderText('domain.example.com'), 'walled.test');
  await user.selectOptions(screen.getByLabelText('RPZ rule action'), action);
  return user;
}

describe('RPZ rule form override_data (F432)', () => {
  it('sends a valid CNAME target as override_data', async () => {
    const user = await setup('CNAME');
    const data = screen.getByLabelText('RPZ override data');
    const add = screen.getByRole('button', { name: 'Add Rule' });
    expect(add).toBeDisabled(); // required for CNAME

    await user.type(data, 'not a name!');
    expect(screen.getByText(/must be a domain name/i)).toBeInTheDocument();
    expect(add).toBeDisabled();

    await user.clear(data);
    await user.type(data, 'garden.example.');
    expect(screen.queryByText(/must be a domain name/i)).not.toBeInTheDocument();
    await user.click(add);
    await waitFor(() => expect(postBodies()).toHaveLength(1));
    expect(postBodies()[0]).toEqual({ pattern: 'walled.test', action: 'CNAME', override_data: 'garden.example.' });
  });

  it('rejects the root name as a CNAME target', async () => {
    const user = await setup('CNAME');
    await user.type(screen.getByLabelText('RPZ override data'), '.');
    expect(screen.getByText(/must be a domain name/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add Rule' })).toBeDisabled();
  });

  it('sends a valid OVERRIDE address as override_data', async () => {
    const user = await setup('OVERRIDE');
    const data = screen.getByLabelText('RPZ override data');
    const add = screen.getByRole('button', { name: 'Add Rule' });
    expect(add).toBeDisabled();

    await user.type(data, 'walled.example.');
    expect(screen.getByText(/must be an IP address/i)).toBeInTheDocument();
    expect(add).toBeDisabled();

    await user.clear(data);
    await user.type(data, '2001:db8::1');
    await user.click(add);
    await waitFor(() => expect(postBodies()).toHaveLength(1));
    expect(postBodies()[0]).toEqual({ pattern: 'walled.test', action: 'OVERRIDE', override_data: '2001:db8::1' });
  });

  it('hides the field and omits override_data for NXDOMAIN', async () => {
    const user = await setup('NXDOMAIN');
    expect(screen.queryByLabelText('RPZ override data')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Add Rule' }));
    await waitFor(() => expect(postBodies()).toHaveLength(1));
    expect(postBodies()[0]).toEqual({ pattern: 'walled.test', action: 'NXDOMAIN' });
  });

  it('does not leak data typed for CNAME into a later NODATA rule', async () => {
    const user = await setup('CNAME');
    await user.type(screen.getByLabelText('RPZ override data'), 'garden.example.');
    await user.selectOptions(screen.getByLabelText('RPZ rule action'), 'NODATA');
    await user.click(screen.getByRole('button', { name: 'Add Rule' }));
    await waitFor(() => expect(postBodies()).toHaveLength(1));
    expect(postBodies()[0]).toEqual({ pattern: 'walled.test', action: 'NODATA' });
  });
});
