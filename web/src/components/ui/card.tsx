import { type HTMLAttributes, forwardRef } from 'react';
import { cn } from '@/lib/utils';

const _c = (base: string) => forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(({ className, ...p }, ref) => <div ref={ref} className={cn(base, className)} {...p} />);

export const Card = _c('rounded-xl border bg-card text-card-foreground shadow-sm');
export const CardHeader = _c('flex flex-col space-y-1.5 p-6');
export const CardTitle = forwardRef<HTMLHeadingElement, HTMLAttributes<HTMLHeadingElement>>(({ className, ...p }, ref) => <h3 ref={ref} className={cn('font-semibold leading-none tracking-tight', className)} {...p} />);
export const CardDescription = forwardRef<HTMLParagraphElement, HTMLAttributes<HTMLParagraphElement>>(({ className, ...p }, ref) => <p ref={ref} className={cn('text-sm text-muted-foreground', className)} {...p} />);
export const CardContent = _c('p-6 pt-0');
