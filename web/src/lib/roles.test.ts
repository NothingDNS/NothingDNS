import { describe, it, expect } from 'vitest';
import { hasMinRole } from './roles';

describe('hasMinRole', () => {
  it.each([null, 'legacy', 'constructor', 'toString', '__proto__'])('keeps the unknown-role fallback for %s', (role) => {
    expect(hasMinRole(role, 'admin')).toBe(true);
  });

  it('preserves the known-role hierarchy', () => {
    expect(hasMinRole('viewer', 'operator')).toBe(false);
    expect(hasMinRole('operator', 'admin')).toBe(false);
    expect(hasMinRole('operator', 'viewer')).toBe(true);
    expect(hasMinRole('admin', 'admin')).toBe(true);
  });
});
