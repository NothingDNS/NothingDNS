import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { ShieldOff } from 'lucide-react';
import { EmptyState } from '@/components/states';
import { Button } from '@/components/ui/button';
import { useAuthStore } from '@/stores/authStore';
import { hasMinRole, type Role } from '@/lib/roles';

// RequireRole gates a route by minimum role. Rendering an access-denied panel
// (instead of silently redirecting) makes a deep-linked URL's failure mode
// explicit. This is presentation only — the API enforces the real
// authorization via requireOperator/requireAdmin.
export function RequireRole({ minRole, children }: { minRole: Role; children: ReactNode }) {
  const role = useAuthStore((s) => s.role);
  if (!hasMinRole(role, minRole)) {
    return (
      <EmptyState
        icon={ShieldOff}
        title="Access denied"
        description={`Your role (${role}) does not have permission to view this page.`}
        action={
          <Button asChild variant="outline" size="sm">
            <Link to="/">Back to dashboard</Link>
          </Button>
        }
      />
    );
  }
  return <>{children}</>;
}
