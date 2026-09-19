import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { useQueryStream } from './queryStream';

interface AuthState {
  token: string | null;
  username: string | null;
  role: string | null;
  isAuthenticated: boolean;
  setAuth: (token: string, username: string, role: string) => void;
  clearAuth: () => void;
}

// SECURITY: `token` is intentionally NOT persisted. Persisting to localStorage
// (or JS-readable cookies) exposes the bearer to any XSS for 24h. The token
// lives in memory only; on page reload App restores it via GET
// /api/v1/auth/session using the HttpOnly+Secure+SameSite=Strict ndns_token
// cookie. That cookie is never read from JS.
export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      username: null,
      role: null,
      isAuthenticated: false,
      setAuth: (token, username, role) =>
        set({ token, username, role, isAuthenticated: true }),
      clearAuth: () => {
        set({ token: null, username: null, role: null, isAuthenticated: false });
        useQueryStream.getState().clear();
      },
    }),
    {
      name: 'ndns-auth',
      partialize: (state) => ({
        username: state.username,
        role: state.role,
      }),
    }
  )
);
