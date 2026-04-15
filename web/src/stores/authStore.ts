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
        document.cookie = 'ndns_token=; path=/; max-age=0; SameSite=Strict';
        set({ token: null, username: null, role: null, isAuthenticated: false });
      },
    }),
    {
      name: 'ndns-auth',
    }
  )
);
