import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Globe, Eye, EyeOff, Loader2 } from 'lucide-react';
import { useState } from 'react';
import { useAuthStore } from '@/stores/authStore';

const loginSchema = z.object({
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
});

type LoginValues = z.infer<typeof loginSchema>;

export function LoginPage() {
  const [showPassword, setShowPassword] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const setAuth = useAuthStore((state) => state.setAuth);

  const {
    register,
    handleSubmit,
    setError,
    formState: { errors, isSubmitting },
  } = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      username: '',
      password: '',
    },
  });

  const onSubmit = async (data: LoginValues) => {
    setFormError(null);
    try {
      const r = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: data.username, password: data.password }),
      });

      if (r.ok) {
        const res = await r.json();
        const token = res.token as string;
        const username = res.username as string;
        const role = res.role as string;

        // SECURITY: Do NOT write the token to document.cookie — that overwrites
        // the backend's HttpOnly+Secure+SameSite=Strict cookie with a weaker
        // JS-readable one that any XSS can exfiltrate. The backend cookie is
        // used by the browser automatically for safe-method requests and for
        // GET /api/v1/auth/session after a hard refresh; the in-memory Bearer
        // token below is used for mutations.
        // setAuth flips isAuthenticated → AppContent re-renders to the
        // dashboard reactively. Do NOT hard-reload (window.location): a full
        // page reload drops the in-memory token until /auth/session restores it.
        setAuth(token, username, role);
      } else if (r.status === 401) {
        setError('password', { message: 'Invalid credentials. Please check your username and password.' });
      } else if (r.status === 429) {
        const retryAfter = r.headers.get('Retry-After');
        setFormError(
          retryAfter
            ? `Too many attempts. Please try again in ${retryAfter} seconds.`
            : 'Too many attempts. Please try again later.',
        );
      } else {
        setFormError(`Connection error (${r.status}). Please try again.`);
      }
    } catch {
      setFormError('Connection error. Please check your network.');
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
            Sign in to your account to continue
          </p>
        </div>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          {formError && (
            <div role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {formError}
            </div>
          )}
          <div className="space-y-2">
            <Label htmlFor="username">Username</Label>
            <Input
              id="username"
              type="text"
              placeholder="Enter username"
              autoComplete="username"
              {...register('username')}
              className={errors.username ? 'border-destructive' : ''}
              autoFocus
            />
            {errors.username && (
              <p className="text-sm text-destructive">{errors.username.message}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <div className="relative">
              <Input
                id="password"
                type={showPassword ? 'text' : 'password'}
                placeholder="Enter password"
                autoComplete="current-password"
                {...register('password')}
                className={errors.password ? 'border-destructive' : ''}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground cursor-pointer"
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            {errors.password && (
              <p className="text-sm text-destructive">{errors.password.message}</p>
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
