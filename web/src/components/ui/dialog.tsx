import { useEffect, type ReactNode, type HTMLAttributes } from 'react';
import { cn } from '@/lib/utils';
import { X } from 'lucide-react';

export function Dialog({ open, onClose, children, className }: { open: boolean; onClose: () => void; children: ReactNode; className?: string }) {
  useEffect(() => {
    if (!open) return;
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', h);
    document.body.style.overflow = 'hidden';
    return () => { document.removeEventListener('keydown', h); document.body.style.overflow = ''; };
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className={cn('relative z-50 w-full max-w-lg rounded-xl border bg-card p-6 shadow-lg', className)}>
        <button onClick={onClose} className="absolute right-4 top-4 rounded-sm opacity-70 hover:opacity-100 cursor-pointer"><X className="h-4 w-4" /></button>
        {children}
      </div>
    </div>
  );
}

export function DialogTitle({ className, children, ...p }: HTMLAttributes<HTMLHeadingElement>) {
  return <h2 className={cn('text-lg font-semibold leading-none tracking-tight', className)} {...p}>{children}</h2>;
}
