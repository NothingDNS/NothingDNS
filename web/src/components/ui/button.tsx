import { type ButtonHTMLAttributes, forwardRef } from 'react';
import { cn } from '@/lib/utils';

type V = 'default' | 'secondary' | 'destructive' | 'ghost' | 'outline';
type S = 'default' | 'sm' | 'lg' | 'icon';

const vMap: Record<V, string> = {
  default: 'bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm',
  secondary: 'bg-secondary text-secondary-foreground hover:bg-secondary/80 shadow-sm',
  destructive: 'bg-destructive text-destructive-foreground hover:bg-destructive/90 shadow-sm',
  ghost: 'hover:bg-accent hover:text-accent-foreground',
  outline: 'border border-input bg-background hover:bg-accent hover:text-accent-foreground shadow-sm',
};

const sMap: Record<S, string> = { default: 'h-9 px-4 py-2', sm: 'h-8 rounded-md px-3 text-xs', lg: 'h-10 rounded-md px-8', icon: 'h-9 w-9' };

interface P extends ButtonHTMLAttributes<HTMLButtonElement> { variant?: V; size?: S }

export const Button = forwardRef<HTMLButtonElement, P>(({ className, variant = 'default', size = 'default', ...p }, ref) => (
  <button ref={ref} className={cn('inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-lg text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 cursor-pointer', vMap[variant], sMap[size], className)} {...p} />
));
