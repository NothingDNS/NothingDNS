import { create } from 'zustand';
import { persist } from 'zustand/middleware';

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
// lives in memory only; on page reload it is gone, so the app treats the
// session as unauthenticated and redirects to login. The backend's
// HttpOnly+Secure+SameSite=Strict cookie remains available for safe-method
// requests but is never read from JS.
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
