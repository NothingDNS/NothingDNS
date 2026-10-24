import { type FormEvent, useId, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api, LoginResponseSchema, passwordProblem } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';

// ChangePasswordDialog changes the logged-in user's own password
// (POST /api/v1/auth/password). The server revokes every session of the user
// and answers with a new token, which replaces the in-memory bearer so this
// tab stays signed in while every other session ends. Controlled — the
// parent owns `open`.
export function ChangePasswordDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const currentId = useId();
  const nextId = useId();
  const confirmId = useId();

  const reset = () => {
    setCurrent('');
    setNext('');
    setConfirm('');
    setError('');
  };

  const close = () => {
    if (saving) return;
    reset();
    onClose();
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const problem = !current
      ? 'Enter your current password'
      : passwordProblem(next) ??
        (next !== confirm ? 'The new passwords do not match' : null) ??
        (next === current ? 'The new password must differ from the current one' : null);
    if (problem) {
      setError(problem);
      return;
    }
    setSaving(true);
    setError('');
    try {
      const res = await api('POST', '/api/v1/auth/password', { old_password: current, new_password: next }, LoginResponseSchema);
      useAuthStore.getState().setAuth(res.token, res.username, res.role);
      toast.success('Password changed. Your other sessions were signed out.');
      reset();
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to change password');
    } finally {
      setSaving(false);
    }
  };

  const labelClass = 'text-sm font-medium mb-1.5 block';
  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) close(); }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Change password</DialogTitle>
          <DialogDescription>Your other sessions are signed out; this one stays signed in.</DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="space-y-4">
          <div>
            <label htmlFor={currentId} className={labelClass}>Current password</label>
            <Input id={currentId} type="password" autoComplete="current-password" value={current} onChange={e => setCurrent(e.target.value)} autoFocus />
          </div>
          <div>
            <label htmlFor={nextId} className={labelClass}>New password</label>
            <Input id={nextId} type="password" autoComplete="new-password" value={next} onChange={e => setNext(e.target.value)} />
          </div>
          <div>
            <label htmlFor={confirmId} className={labelClass}>Confirm new password</label>
            <Input id={confirmId} type="password" autoComplete="new-password" value={confirm} onChange={e => setConfirm(e.target.value)} />
          </div>
          {error && <p role="alert" className="text-destructive text-sm">{error}</p>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={close} disabled={saving}>Cancel</Button>
            <Button type="submit" disabled={saving}>
              {saving && <Loader2 className="h-4 w-4 animate-spin" />}
              Change password
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
