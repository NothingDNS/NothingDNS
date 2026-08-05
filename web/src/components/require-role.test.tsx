import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { RequireRole } from './require-role';
import { useAuthStore } from '@/stores/authStore';

// Reset zustand store between tests
beforeEach(() => {
  useAuthStore.setState({
    token: null,
    username: null,
    role: null,
    isAuthenticated: false,
  });
});

function renderGated(minRole: 'viewer' | 'operator' | 'admin') {
  return render(
    <MemoryRouter>
      <RequireRole minRole={minRole}>
        <p>Secret page</p>
      </RequireRole>
    </MemoryRouter>,
  );
}

describe('RequireRole', () => {
  it('blocks a viewer from an operator-gated page with an access-denied panel', () => {
    useAuthStore.setState({ role: 'viewer' });
    renderGated('operator');
    expect(screen.queryByText('Secret page')).not.toBeInTheDocument();
    expect(screen.getByText('Access denied')).toBeInTheDocument();
    expect(screen.getByText('Back to dashboard')).toBeInTheDocument();
  });

  it('renders children for operator and admin roles', () => {
    useAuthStore.setState({ role: 'operator' });
    const { unmount } = renderGated('operator');
    expect(screen.getByText('Secret page')).toBeInTheDocument();
    unmount();

    useAuthStore.setState({ role: 'admin' });
    renderGated('operator');
    expect(screen.getByText('Secret page')).toBeInTheDocument();
  });

  it('fails open when role is missing (legacy sessions) — API still enforces', () => {
    useAuthStore.setState({ role: null });
    renderGated('operator');
    expect(screen.getByText('Secret page')).toBeInTheDocument();
  });
});
