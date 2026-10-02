/**
 * Authentication, users and roles (`/api/v1/auth`).
 *
 * Credential *acquisition* lives here; credential *transmission* is handled by
 * {@link Transport}, which every namespace shares.
 */

import { NothingDNSValidationError } from './errors.js';
import { roleFromJson, sessionFromJson, userFromJson } from './models.js';
import type { Role, Session, User } from './models.js';
import { Transport, escapeSegment, messageOf } from './transport.js';

/** Roles a user account can hold, ordered viewer < operator < admin. */
export const ROLES = ['viewer', 'operator', 'admin'] as const;

/** One of the roles the server accepts. */
export type RoleName = (typeof ROLES)[number];

/** Log in, manage accounts and read the server's role table. */
export class AuthResource {
  constructor(private readonly transport: Transport) {}

  /**
   * Log in and receive a bearer token.
   *
   * @param username - Account name.
   * @param password - Account password.
   * @param storeToken - Keep the returned token on the client so later calls
   *   are authenticated automatically (default `true`).
   * @throws {@link NothingDNSApiError} 400 for a malformed request, 401 for bad
   *   credentials, 429 when the login rate limit is hit.
   */
  async login(
    username: string,
    password: string,
    options: { storeToken?: boolean } = {},
  ): Promise<Session> {
    const json = await this.transport.post<unknown>('/api/v1/auth/login', {
      body: { username, password },
    });
    const session = sessionFromJson(json);
    if (options.storeToken !== false && session.token) this.transport.setToken(session.token);
    return session;
  }

  /**
   * Create the first admin account, or reset an existing account's password.
   *
   * Use this to provision the very first admin on a fresh server, or to recover
   * access when the current password is known.
   *
   * @param oldPassword - Current password of the account being reset; required
   *   when resetting an existing account that is not the initial bootstrap.
   * @throws {@link NothingDNSApiError} 401 when `oldPassword` is wrong, 403 when
   *   the change is not permitted, 409 when the server already has an admin and
   *   no `oldPassword` was given.
   */
  async bootstrap(
    username: string,
    password: string,
    options: { oldPassword?: string; storeToken?: boolean } = {},
  ): Promise<Session> {
    const body: Record<string, string> = { username, password };
    if (options.oldPassword !== undefined) body.old_password = options.oldPassword;

    const json = await this.transport.post<unknown>('/api/v1/auth/bootstrap', { body });
    const session = sessionFromJson(json);
    if (options.storeToken !== false && session.token) this.transport.setToken(session.token);
    return session;
  }

  /**
   * Return the current session: token, username and role.
   *
   * The dashboard calls this to rebuild its in-memory bearer after a page reload
   * without persisting the token in the browser. The server rejects the legacy
   * shared `auth_token` here — a real login session is required.
   */
  async session(): Promise<Session> {
    return sessionFromJson(await this.transport.get('/api/v1/auth/session'));
  }

  /** Invalidate the current session and return the server's message. */
  async logout(): Promise<string> {
    return messageOf(await this.transport.post('/api/v1/auth/logout', { expectJson: false }));
  }

  /** List the roles the server knows about (operator+). */
  async roles(): Promise<Role[]> {
    const json = await this.transport.get<{ roles?: unknown }>('/api/v1/auth/roles');
    return Array.isArray(json?.roles) ? json.roles.map(roleFromJson) : [];
  }

  /** List every user account (operator+). Passwords are never returned. */
  async listUsers(): Promise<User[]> {
    const json = await this.transport.get<unknown[]>('/api/v1/auth/users');
    return Array.isArray(json) ? json.map(userFromJson) : [];
  }

  /**
   * Create a user account (admin only).
   *
   * @param role - `viewer` (read-only), `operator` (zones, cache, config
   *   reads) or `admin` (everything, including users and runtime config).
   * @throws {@link NothingDNSApiError} 409 when the username already exists.
   * @throws {@link NothingDNSValidationError} when `role` is not a known role.
   */
  async createUser(username: string, password: string, role: RoleName = 'viewer'): Promise<User> {
    if (!ROLES.includes(role)) {
      throw new NothingDNSValidationError(`role must be one of ${ROLES.join(', ')}`);
    }
    const json = await this.transport.post<unknown>('/api/v1/auth/users', {
      body: { username, password, role },
    });
    return userFromJson(json);
  }

  /** Delete a user account by name (admin only). */
  async deleteUser(username: string): Promise<string> {
    return messageOf(
      await this.transport.delete(`/api/v1/auth/users/${escapeSegment(username)}`),
    );
  }
}
