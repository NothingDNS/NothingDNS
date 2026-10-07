import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { toast } from 'sonner';
import { UsersPage } from './users';

// F433: GET /api/v1/auth/users marks users that come from the config file
// with config_defined; the API refuses to delete them (409 "user is defined
// in the config file; change it there"). The page offered Delete on every
// row, so the operator only learned after confirming. Config-defined rows
// must have Delete disabled with an explanation, and refused/failed deletes
// must surface the server's message and reload the list.

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

const users = [
  { username: 'root', role: 'admin', config_defined: true },
  { username: 'alice', role: 'operator', config_defined: false },
];

let deleteResponse: () => Promise<Response>;

function getCount() {
  return mockFetch.mock.calls.filter(([, init]) => ((init as RequestInit | undefined)?.method ?? 'GET') === 'GET').length;
}

beforeEach(() => {
  mockFetch.mockReset();
  vi.mocked(toast.error).mockReset();
  vi.mocked(toast.success).mockReset();
  deleteResponse = () => json({ message: 'deleted' });
  mockFetch.mockImplementation((_url: string, init?: RequestInit) => {
    if (init?.method === 'DELETE') return deleteResponse();
    return json(users);
  });
});

describe('UsersPage config-defined users (F433)', () => {
  it('disables Delete for config-defined users and explains why', async () => {
    render(<UsersPage />);
    const del = await screen.findByRole('button', { name: 'Delete user root' });
    expect(del).toBeDisabled();
    const row = del.closest('tr') as HTMLElement;
    expect(within(row).getByText(/config file/i)).toBeInTheDocument();
    expect(del.getAttribute('title') ?? '').toMatch(/config file/i);

    expect(screen.getByRole('button', { name: 'Delete user alice' })).toBeEnabled();
  });

  it('surfaces a 409 refusal and reloads the list', async () => {
    const user = userEvent.setup();
    deleteResponse = () => json({ error: 'user is defined in the config file; change it there' }, 409);
    render(<UsersPage />);
    await user.click(await screen.findByRole('button', { name: 'Delete user alice' }));
    const before = getCount();
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('user is defined in the config file; change it there'));
    await waitFor(() => expect(getCount()).toBeGreaterThan(before));
  });

  it('surfaces a 500 persist failure message', async () => {
    const user = userEvent.setup();
    deleteResponse = () => json({ error: 'Failed to save users file; change not applied' }, 500);
    render(<UsersPage />);
    await user.click(await screen.findByRole('button', { name: 'Delete user alice' }));
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Failed to save users file; change not applied'));
  });
});
