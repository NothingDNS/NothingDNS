import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { LoginPage } from './login';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

// Mock zustand auth store
const mockSetAuth = vi.fn();
vi.mock('@/stores/authStore', () => ({
  useAuthStore: (selector?: (state: unknown) => unknown) => {
    const state = {
      token: null,
      username: null,
      role: null,
      isAuthenticated: false,
      setAuth: mockSetAuth,
      clearAuth: vi.fn(),
    };
    return selector ? selector(state) : state;
  },
}));

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
  mockSetAuth.mockReset();
});

describe('LoginPage', () => {
  it('renders the login form', () => {
    render(<LoginPage />);

    expect(screen.getByText('NothingDNS')).toBeInTheDocument();
    expect(screen.getByText('Sign in to your account to continue')).toBeInTheDocument();
    expect(screen.getByLabelText('Username')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeInTheDocument();
  });

  it('shows validation errors for empty fields', async () => {
    const user = userEvent.setup();
    render(<LoginPage />);

    // Submit without filling fields
    await user.click(screen.getByRole('button', { name: 'Sign In' }));

    expect(screen.getByText('Username is required')).toBeInTheDocument();
    expect(screen.getByText('Password is required')).toBeInTheDocument();
  });

  it('calls API with credentials on submit', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ token: 'tok_abc', username: 'admin', role: 'admin' }),
    );
    const user = userEvent.setup();
    render(<LoginPage />);

    await user.type(screen.getByLabelText('Username'), 'admin');
    await user.type(screen.getByLabelText('Password'), 'secret');
    await user.click(screen.getByRole('button', { name: 'Sign In' }));

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: 'secret' }),
      });
    });
  });

  it('calls setAuth on successful login', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ token: 'tok_abc', username: 'admin', role: 'admin' }),
    );
    const user = userEvent.setup();
    render(<LoginPage />);

    await user.type(screen.getByLabelText('Username'), 'admin');
    await user.type(screen.getByLabelText('Password'), 'secret');
    await user.click(screen.getByRole('button', { name: 'Sign In' }));

    await waitFor(() => {
      expect(mockSetAuth).toHaveBeenCalledWith('tok_abc', 'admin', 'admin');
    });
  });

  it('shows error message on 401', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ error: 'unauthorized' }, 401));
    const user = userEvent.setup();
    render(<LoginPage />);

    await user.type(screen.getByLabelText('Username'), 'admin');
    await user.type(screen.getByLabelText('Password'), 'wrong');
    await user.click(screen.getByRole('button', { name: 'Sign In' }));

    await waitFor(() => {
      expect(
        screen.getByText('Invalid credentials. Please check your username and password.'),
      ).toBeInTheDocument();
    });
  });

  it('shows rate limit message on 429', async () => {
    const headers = new Headers({ 'Content-Type': 'application/json', 'Retry-After': '30' });
    mockFetch.mockResolvedValue(
      Promise.resolve(
        new Response(JSON.stringify({ error: 'rate limited' }), {
          status: 429,
          headers,
        }),
      ),
    );
    const user = userEvent.setup();
    render(<LoginPage />);

    await user.type(screen.getByLabelText('Username'), 'admin');
    await user.type(screen.getByLabelText('Password'), 'secret');
    await user.click(screen.getByRole('button', { name: 'Sign In' }));

    await waitFor(() => {
      expect(
        screen.getByText('Too many attempts. Please try again in 30 seconds.'),
      ).toBeInTheDocument();
    });
  });

  it('shows rate limit message without Retry-After header', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ error: 'rate limited' }, 429));
    const user = userEvent.setup();
    render(<LoginPage />);

    await user.type(screen.getByLabelText('Username'), 'admin');
    await user.type(screen.getByLabelText('Password'), 'secret');
    await user.click(screen.getByRole('button', { name: 'Sign In' }));

    await waitFor(() => {
      expect(
        screen.getByText('Too many attempts. Please try again later.'),
      ).toBeInTheDocument();
    });
  });

  it('shows connection error on network failure', async () => {
    mockFetch.mockRejectedValue(new Error('Network failure'));
    const user = userEvent.setup();
    render(<LoginPage />);

    await user.type(screen.getByLabelText('Username'), 'admin');
    await user.type(screen.getByLabelText('Password'), 'secret');
    await user.click(screen.getByRole('button', { name: 'Sign In' }));

    await waitFor(() => {
      expect(
        screen.getByText('Connection error. Please check your network.'),
      ).toBeInTheDocument();
    });
  });

  it('shows generic error on unexpected status code', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ error: 'server error' }, 503));
    const user = userEvent.setup();
    render(<LoginPage />);

    await user.type(screen.getByLabelText('Username'), 'admin');
    await user.type(screen.getByLabelText('Password'), 'secret');
    await user.click(screen.getByRole('button', { name: 'Sign In' }));

    await waitFor(() => {
      expect(
        screen.getByText('Connection error (503). Please try again.'),
      ).toBeInTheDocument();
    });
  });

  it('toggles password visibility', async () => {
    const user = userEvent.setup();
    render(<LoginPage />);

    const passwordInput = screen.getByLabelText('Password');
    expect(passwordInput).toHaveAttribute('type', 'password');

    const toggleBtn = screen.getByLabelText('Show password');
    await user.click(toggleBtn);
    expect(passwordInput).toHaveAttribute('type', 'text');

    const hideBtn = screen.getByLabelText('Hide password');
    await user.click(hideBtn);
    expect(passwordInput).toHaveAttribute('type', 'password');
  });

  it('shows submitting state while logging in', async () => {
    // Never resolve the fetch so we stay in submitting state
    mockFetch.mockReturnValue(new Promise(() => {}));
    const user = userEvent.setup();
    render(<LoginPage />);

    await user.type(screen.getByLabelText('Username'), 'admin');
    await user.type(screen.getByLabelText('Password'), 'secret');
    await user.click(screen.getByRole('button', { name: 'Sign In' }));

    expect(screen.getByText('Signing in...')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Signing in/ })).toBeDisabled();
  });

  it('clears previous form error on new submit attempt', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse({ error: 'unauthorized' }, 401))
      .mockResolvedValueOnce(
        mockJsonResponse({ token: 'tok', username: 'u', role: 'admin' }),
      );
    const user = userEvent.setup();
    render(<LoginPage />);

    // First attempt — gets 401
    await user.type(screen.getByLabelText('Username'), 'admin');
    await user.type(screen.getByLabelText('Password'), 'wrong');
    await user.click(screen.getByRole('button', { name: 'Sign In' }));

    await waitFor(() => {
      expect(
        screen.getByText('Invalid credentials. Please check your username and password.'),
      ).toBeInTheDocument();
    });

    // Second attempt — mock returns success; the form error should clear
    await user.clear(screen.getByLabelText('Password'));
    await user.type(screen.getByLabelText('Password'), 'correct');
    await user.click(screen.getByRole('button', { name: 'Sign In' }));

    await waitFor(() => {
      expect(mockSetAuth).toHaveBeenCalledWith('tok', 'u', 'admin');
    });
  });
});
