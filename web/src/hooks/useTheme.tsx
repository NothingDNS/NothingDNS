import { createContext, useEffect, useState, type ReactNode } from 'react';
import type { Theme } from '@/lib/theme';

interface ThemeContextValue {
  theme: Theme;
  resolved: 'light' | 'dark';
  setTheme: (t: Theme) => void;
}

const ThemeContext = createContext<ThemeContextValue>({
  theme: 'system',
  resolved: 'dark',
  setTheme: () => {},
});

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeRaw] = useState<Theme>(() => {
    if (typeof window !== 'undefined') {
      return (localStorage.getItem('ndns-theme') as Theme) || 'system';
    }
    return 'system';
  });
  const [resolved, setResolved] = useState<'light' | 'dark'>('dark');

  useEffect(() => {
    const apply = (isDark: boolean) => {
      document.documentElement.classList.toggle('dark', isDark);
      setResolved(isDark ? 'dark' : 'light');
    };

    if (theme === 'system') {
      const mq = matchMedia('(prefers-color-scheme: dark)');
      apply(mq.matches);
      const handler = (e: MediaQueryListEvent) => apply(e.matches);
      mq.addEventListener('change', handler);
      return () => mq.removeEventListener('change', handler);
    }

    apply(theme === 'dark');
  }, [theme]);

  const setTheme = (t: Theme) => {
    setThemeRaw(t);
    if (typeof window !== 'undefined') {
      localStorage.setItem('ndns-theme', t);
    }
  };

  return (
    <ThemeContext.Provider value={{ theme, resolved, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export { ThemeContext };
