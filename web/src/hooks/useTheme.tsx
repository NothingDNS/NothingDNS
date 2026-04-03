import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';

type Theme = 'light' | 'dark' | 'system';

const Ctx = createContext<{ theme: Theme; resolved: 'light' | 'dark'; setTheme: (t: Theme) => void }>({
  theme: 'system', resolved: 'dark', setTheme: () => {},
});

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeRaw] = useState<Theme>(() => (localStorage.getItem('ndns-theme') as Theme) || 'system');
  const [resolved, setResolved] = useState<'light' | 'dark'>('dark');

  useEffect(() => {
    const apply = (d: boolean) => {
      document.documentElement.classList.toggle('dark', d);
      setResolved(d ? 'dark' : 'light');
    };
    if (theme === 'system') {
      const mq = matchMedia('(prefers-color-scheme: dark)');
      apply(mq.matches);
      const h = (e: MediaQueryListEvent) => apply(e.matches);
      mq.addEventListener('change', h);
      return () => mq.removeEventListener('change', h);
    }
    apply(theme === 'dark');
  }, [theme]);

  const setTheme = (t: Theme) => { setThemeRaw(t); localStorage.setItem('ndns-theme', t); };
  return <Ctx.Provider value={{ theme, resolved, setTheme }}>{children}</Ctx.Provider>;
}

export const useTheme = () => useContext(Ctx);
