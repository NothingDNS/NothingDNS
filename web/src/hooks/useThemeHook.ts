import { useContext } from 'react';
import { ThemeContext } from './useTheme';

// Separate file for the hook to satisfy fast refresh rules
export function useTheme() {
  return useContext(ThemeContext);
}
