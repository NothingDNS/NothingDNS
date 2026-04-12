import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Globe, Eye, EyeOff, Loader2 } from 'lucide-react';
import { useState, useEffect, useRef } from 'react';
import { useAuthStore } from '@/stores/authStore';

const loginSchema = z.object({
  token: z.string().min(1, 'Token is required'),
});

type LoginValues = z.infer<typeof loginSchema>;

export function LoginPage() {
  const [show, setShow] = useState(false);
  const [pendingToken, setPendingToken] = useState<string | null>(null);
  const setAuth = useAuthStore((state) => state.setAuth);
  const initialized = useRef(false);

  // Set cookie when authentication succeeds
  useEffect(() => {
    if (pendingToken && !initialized.current) {
      initialized.current = true;
      document.cookie = `ndns_token=${encodeURIComponent(pendingToken)}; path=/; max-age=86400; SameSite=Strict`;
    }
  }, [pendingToken]);

  const {
    register,
    handleSubmit,
    setError,
    formState: { errors, isSubmitting },
  } = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      token: '',
    },
  });

  const onSubmit = async (data: LoginValues) => {
    try {
      const r = await fetch('/api/v1/status', {
        headers: { Authorization: `Bearer ${data.token}` },
      });

      if (r.ok) {
        setPendingToken(data.token);
        // Get user info for the store
        const userResp = await fetch('/api/v1/auth/users', {
          headers: { Authorization: `Bearer ${data.token}` },
        });
        if (userResp.ok) {
          const users = await userResp.json();
          if (users.length > 0) {
            setAuth(data.token, users[0].username, users[0].role);
            return;
          }
        }
        // If no users, still authenticate with token
        setAuth(data.token, 'admin', 'admin');
      } else if (r.status === 401) {
        setError('token', { message: 'Invalid token. Please check your token and try again.' });
      } else if (r.status === 403) {
        setError('token', { message: 'Access forbidden. Contact your administrator.' });
      } else {
        setError('token', { message: `Connection error (${r.status}). Please try again.` });
      }
    } catch {
      setError('token', { message: 'Connection error. Please check your network.' });
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-background">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center h-16 w-16 rounded-2xl bg-primary/10 text-primary mb-4">
            <Globe className="h-8 w-8" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">NothingDNS</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Enter your access token to continue
          </p>
        </div>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="token">Access Token</Label>
            <div className="relative">
              <Input
                id="token"
                type={show ? 'text' : 'password'}
                placeholder="Enter auth token"
                {...register('token')}
                className={errors.token ? 'border-destructive' : ''}
                autoFocus
              />
              <button
                type="button"
                onClick={() => setShow(!show)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground cursor-pointer"
                aria-label={show ? 'Hide token' : 'Show token'}
              >
                {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            {errors.token && (
              <p className="text-sm text-destructive">{errors.token.message}</p>
            )}
          </div>

          <Button type="submit" className="w-full" disabled={isSubmitting}>
            {isSubmitting ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Signing in...
              </>
            ) : (
              'Sign In'
            )}
          </Button>
        </form>
      </div>
    </div>
  );
}
