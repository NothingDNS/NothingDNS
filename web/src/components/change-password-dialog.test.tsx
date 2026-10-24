import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { toast } from 'sonner';
import { useAuthStore } from '@/stores/authStore';
import { ChangePasswordDialog } from './change-password-dialog';

// Issue #18: the logged-in user changes their own password from the
// dashboard. The server revokes every session and returns a new token, which
// must replace the in-memory bearer so this tab stays signed in.

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

async function fill(user: ReturnType<typeof userEvent.setup>, current: string, next: string, confirm: string) {
  if (current) await user.type(screen.getByLabelText('Current password'), current);
  if (next) await user.type(screen.getByLabelText('New password'), next);
  if (confirm) await user.type(screen.getByLabelText('Confirm new password'), confirm);
  await user.click(screen.getByRole('button', { name: 'Change password' }));
}

beforeEach(() => {
  mockFetch.mockReset();
  vi.mocked(toast.success).mockReset();
  useAuthStore.setState({ token: 'old-token', username: 'alice', role: 'viewer', isAuthenticated: true });
});

describe('ChangePasswordDialog', () => {
  it('posts the passwords and swaps in the new session token', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    mockFetch.mockImplementation(() => json({ token: 'new-token', username: 'alice', role: 'viewer', expires: '2026-10-25T00:00:00Z' }));
    render(<ChangePasswordDialog open onClose={onClose} />);
    await fill(user, 'old-pass-123', 'new-pass-456', 'new-pass-456');

    await waitFor(() => expect(onClose).toHaveBeenCalled());
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/auth/password');
    expect(init.method).toBe('POST');
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer old-token');
    expect(JSON.parse(init.body as string)).toEqual({ old_password: 'old-pass-123', new_password: 'new-pass-456' });
    expect(useAuthStore.getState()).toMatchObject({ token: 'new-token', username: 'alice', isAuthenticated: true });
    expect(toast.success).toHaveBeenCalled();
  });

  it.each([
    ['mismatched confirmation', 'old-pass-123', 'new-pass-456', 'new-pass-457', /do not match/i],
    ['a short new password', 'old-pass-123', 'short', 'short', /at least 8/i],
    ['an unchanged password', 'old-pass-123', 'old-pass-123', 'old-pass-123', /must differ/i],
    ['a missing current password', '', 'new-pass-456', 'new-pass-456', /current password/i],
  ])('refuses %s without calling the API', async (_name, current, next, confirm, message) => {
    const user = userEvent.setup();
    render(<ChangePasswordDialog open onClose={vi.fn()} />);
    await fill(user, current, next, confirm);
    expect(await screen.findByRole('alert')).toHaveTextContent(message);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('shows a wrong current password and keeps the session', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    mockFetch.mockImplementation(() => json({ error: 'Current password is incorrect' }, 400));
    render(<ChangePasswordDialog open onClose={onClose} />);
    await fill(user, 'wrong-pass-1', 'new-pass-456', 'new-pass-456');

    expect(await screen.findByRole('alert')).toHaveTextContent('Current password is incorrect');
    expect(onClose).not.toHaveBeenCalled();
    expect(useAuthStore.getState()).toMatchObject({ token: 'old-token', isAuthenticated: true });
  });
});
