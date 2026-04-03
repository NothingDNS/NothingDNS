import { type HTMLAttributes, forwardRef } from 'react';
import { cn } from '@/lib/utils';

type V = 'default' | 'secondary' | 'destructive' | 'outline' | 'success' | 'warning';
const m: Record<V, string> = {
  default: 'border-transparent bg-primary text-primary-foreground shadow',
  secondary: 'border-transparent bg-secondary text-secondary-foreground',
  destructive: 'border-transparent bg-destructive text-destructive-foreground shadow',
  outline: 'text-foreground',
  success: 'border-transparent bg-success/15 text-success',
  warning: 'border-transparent bg-warning/15 text-warning',
};

interface P extends HTMLAttributes<HTMLDivElement> { variant?: V }
export const Badge = forwardRef<HTMLDivElement, P>(({ className, variant = 'default', ...p }, ref) => (
  <div ref={ref} className={cn('inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors', m[variant], className)} {...p} />
));
