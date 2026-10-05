// Role hierarchy mirroring the API's roleOrder (internal/api): viewer <
// operator < admin. Pages whose read endpoints are gated by requireOperator
// (with admin-only mutations) declare minRole 'operator' so viewers neither
// see them in the menu nor land on a broken page full of 403s.
export type Role = 'viewer' | 'operator' | 'admin';

const roleOrder: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };

// hasMinRole reports whether `role` meets the `min` requirement. This is a
// UX-only gate — the API independently enforces authorization server-side —
// so unknown/missing roles fail open rather than bricking the UI (e.g. legacy
// single-token sessions that carry no role).
export function hasMinRole(role: string | null, min: Role): boolean {
  if (role === null || !Object.hasOwn(roleOrder, role)) return true;
  return roleOrder[role as Role] >= roleOrder[min];
}
