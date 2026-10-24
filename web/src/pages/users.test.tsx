import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { toast } from 'sonner';
import { useAuthStore } from '@/stores/authStore';
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
let putResponse: () => Promise<Response>;

function getCount() {
  return mockFetch.mock.calls.filter(([, init]) => ((init as RequestInit | undefined)?.method ?? 'GET') === 'GET').length;
}

beforeEach(() => {
  mockFetch.mockReset();
  vi.mocked(toast.error).mockReset();
  vi.mocked(toast.success).mockReset();
  deleteResponse = () => json({ message: 'deleted' });
  putResponse = () => json({ username: 'alice', role: 'admin' });
  useAuthStore.setState({ token: 't', username: null, role: null, isAuthenticated: true });
  mockFetch.mockImplementation((_url: string, init?: RequestInit) => {
    if (init?.method === 'DELETE') return deleteResponse();
    if (init?.method === 'PUT') return putResponse();
    return json(users);
  });
});

function putCalls() {
  return mockFetch.mock.calls.filter(([, init]) => (init as RequestInit | undefined)?.method === 'PUT');
}

// Issue #18: an admin can reset another user's password and change their
// role from the Users page.
describe('UsersPage edit user', () => {
  it('disables Edit for config-defined users and for the current user', async () => {
    useAuthStore.setState({ username: 'alice', role: 'admin' });
    render(<UsersPage />);
    const root = await screen.findByRole('button', { name: 'Edit user root' });
    expect(root).toBeDisabled();
    expect(root.getAttribute('title') ?? '').toMatch(/config file/i);
    const self = screen.getByRole('button', { name: 'Edit user alice' });
    expect(self).toBeDisabled();
    expect(self.getAttribute('title') ?? '').toMatch(/change password/i);
  });

  it('hides Edit from operators', async () => {
    useAuthStore.setState({ username: 'ops', role: 'operator' });
    render(<UsersPage />);
    await screen.findByRole('button', { name: 'Delete user alice' });
    expect(screen.queryByRole('button', { name: /^Edit user/ })).toBeNull();
  });

  it('sends only the changed fields and reloads the list', async () => {
    const user = userEvent.setup();
    useAuthStore.setState({ username: 'boss', role: 'admin' });
    render(<UsersPage />);
    await user.click(await screen.findByRole('button', { name: 'Edit user alice' }));
    const dialog = within(await screen.findByRole('dialog'));
    await user.selectOptions(dialog.getByLabelText('Role'), 'admin');
    await user.type(dialog.getByLabelText('New password'), 'reset-pass-123');
    await user.type(dialog.getByLabelText('Confirm new password'), 'reset-pass-123');
    const before = getCount();
    await user.click(dialog.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(putCalls()).toHaveLength(1));
    const [url, init] = putCalls()[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/auth/users/alice');
    expect(JSON.parse(init.body as string)).toEqual({ role: 'admin', password: 'reset-pass-123' });
    await waitFor(() => expect(toast.success).toHaveBeenCalled());
    await waitFor(() => expect(getCount()).toBeGreaterThan(before));
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('refuses mismatched passwords without calling the API', async () => {
    const user = userEvent.setup();
    useAuthStore.setState({ username: 'boss', role: 'admin' });
    render(<UsersPage />);
    await user.click(await screen.findByRole('button', { name: 'Edit user alice' }));
    const dialog = within(await screen.findByRole('dialog'));
    await user.type(dialog.getByLabelText('New password'), 'reset-pass-123');
    await user.type(dialog.getByLabelText('Confirm new password'), 'reset-pass-124');
    await user.click(dialog.getByRole('button', { name: 'Save' }));
    expect(await dialog.findByRole('alert')).toHaveTextContent(/do not match/i);
    expect(putCalls()).toHaveLength(0);
  });

  it('shows the server refusal in the dialog', async () => {
    const user = userEvent.setup();
    useAuthStore.setState({ username: 'boss', role: 'admin' });
    putResponse = () => json({ error: 'Cannot demote the last admin user' }, 409);
    render(<UsersPage />);
    await user.click(await screen.findByRole('button', { name: 'Edit user alice' }));
    const dialog = within(await screen.findByRole('dialog'));
    await user.selectOptions(dialog.getByLabelText('Role'), 'viewer');
    await user.click(dialog.getByRole('button', { name: 'Save' }));
    expect(await dialog.findByRole('alert')).toHaveTextContent('Cannot demote the last admin user');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
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
