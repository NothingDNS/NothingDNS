/**
 * HTTP transport shared by every NothingDNS resource namespace.
 *
 * The transport owns URL construction, the `Authorization` header, query
 * serialisation, JSON encoding, timeouts and the translation of HTTP failures
 * into SDK errors. Resource namespaces only describe *what* to call.
 */

import { NothingDNSApiError, NothingDNSConnectionError, NothingDNSValidationError } from './errors.js';

/** Default server address; matches the server's `server.http` default bind. */
export const DEFAULT_BASE_URL = 'http://localhost:8080';

/** Default per-request timeout, in milliseconds. */
export const DEFAULT_TIMEOUT_MS = 30_000;

/** Options accepted by the {@link Transport} constructor. */
export interface TransportOptions {
  /** Base URL of the server's HTTP listener. */
  baseUrl?: string;
  /** Bearer token to start with — a login JWT or `server.http.auth_token`. */
  token?: string | null;
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number;
  /** Extra headers merged into every request. */
  headers?: Record<string, string>;
  /** Custom `fetch` implementation (proxies, instrumentation, tests). */
  fetch?: typeof globalThis.fetch;
  /** Abort signal applied to every request. */
  signal?: AbortSignal;
}

/** Query parameter values the SDK knows how to serialise. */
export type QueryValue = string | number | boolean | undefined | null;

/** Remove `undefined`/`null` entries so partial updates omit untouched fields. */
export function dropNone<T extends Record<string, unknown>>(payload: T): Partial<T> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(payload)) {
    if (value !== undefined && value !== null) out[key] = value;
  }
  return out as Partial<T>;
}

/** Extract the server's plain acknowledgement `message` from a body. */
export function messageOf(payload: unknown): string {
  if (typeof payload === 'object' && payload !== null && 'message' in payload) {
    const message = (payload as { message?: unknown }).message;
    if (typeof message === 'string') return message;
  }
  return '';
}

/** Percent-encode one path segment (zone names, source ids, usernames). */
export function escapeSegment(value: string | number): string {
  return encodeURIComponent(String(value));
}

/** Build a query string, skipping `undefined`/`null` values. */
export function buildQuery(params?: Record<string, QueryValue>): string {
  if (!params) return '';
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    search.append(key, String(value));
  }
  const rendered = search.toString();
  return rendered ? `?${rendered}` : '';
}

/** HTTP core for one NothingDNS server. */
export class Transport {
  readonly baseUrl: string;
  readonly timeoutMs: number;
  private token: string | null;
  private readonly extraHeaders: Record<string, string>;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly signal?: AbortSignal;

  constructor(options: TransportOptions = {}) {
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
    this.token = options.token ?? null;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.extraHeaders = options.headers ?? {};
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.signal = options.signal;
  }

  /** The bearer token currently sent with requests (or `null`). */
  getToken(): string | null {
    return this.token;
  }

  /**
   * Use `token` for all subsequent requests; `null` goes unauthenticated.
   *
   * Accepts a JWT returned by `auth.login` / `auth.bootstrap` or the static
   * `server.http.auth_token` value from the server config.
   */
  setToken(token: string | null): void {
    this.token = token || null;
  }

  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      ...this.extraHeaders,
    };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    return headers;
  }

  /**
   * Send one request and decode the response.
   *
   * @param method - HTTP verb.
   * @param path - API path starting with `/`; escape dynamic segments with
   * {@link escapeSegment} before interpolating them.
   * @param options.query - Query parameters; `undefined`/`null` are dropped.
   * @param options.body - JSON request body.
   * @param options.raw - Return the response text instead of decoded JSON
   *   (used by the zone export endpoint, which serves a BIND zone file).
   * @param options.expectJson - Decode a JSON body. Set `false` for endpoints
   *   that answer with a bare acknowledgement.
   * @throws {@link NothingDNSApiError} on a 4xx/5xx response.
   * @throws {@link NothingDNSConnectionError} when the server is unreachable.
   * @throws {@link NothingDNSValidationError} when a 2xx body is not valid JSON.
   */
  async request<T = unknown>(
    method: string,
    path: string,
    options: {
      query?: Record<string, QueryValue>;
      body?: unknown;
      raw?: boolean;
      expectJson?: boolean;
    } = {},
  ): Promise<T> {
    const url = `${this.baseUrl}${path}${buildQuery(options.query)}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      let response: Response;
      try {
        response = await this.fetchImpl(url, {
          method,
          headers: this.buildHeaders(),
          body: options.body === undefined ? undefined : JSON.stringify(options.body),
          signal: this.signal
            ? AbortSignal.any([controller.signal, this.signal])
            : controller.signal,
        });
      } catch (cause) {
        if (cause instanceof Error && cause.name === 'AbortError') {
          throw new NothingDNSConnectionError(
            `NothingDNS request to ${url} timed out after ${this.timeoutMs} ms`,
            cause,
          );
        }
        throw new NothingDNSConnectionError(`Could not reach NothingDNS at ${url}`, cause);
      }

      if (!response.ok) {
        throw await apiErrorFrom(response);
      }

      if (options.raw) {
        return (await response.text()) as unknown as T;
      }
      const text = await response.text();
      if (!text) return undefined as unknown as T;
      try {
        return JSON.parse(text) as T;
      } catch (cause) {
        if (options.expectJson === false) {
          // "Don't demand JSON": an unparseable acknowledgement body is
          // tolerated and reported as absent.
          return undefined as unknown as T;
        }
        throw new NothingDNSValidationError(
          `NothingDNS returned a non-JSON body for ${method} ${url}: ${text.slice(0, 200)}`,
          cause,
        );
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  get<T = unknown>(path: string, options?: Parameters<Transport['request']>[2]): Promise<T> {
    return this.request<T>('GET', path, options);
  }

  post<T = unknown>(path: string, options?: Parameters<Transport['request']>[2]): Promise<T> {
    return this.request<T>('POST', path, options);
  }

  put<T = unknown>(path: string, options?: Parameters<Transport['request']>[2]): Promise<T> {
    return this.request<T>('PUT', path, options);
  }

  delete<T = unknown>(path: string, options?: Parameters<Transport['request']>[2]): Promise<T> {
    return this.request<T>('DELETE', path, options);
  }
}

/** Build a {@link NothingDNSApiError} from a non-2xx response. */
async function apiErrorFrom(response: Response): Promise<NothingDNSApiError> {
  let payload: Record<string, unknown> = {};
  let message = `HTTP ${response.status}`;
  const text = await response.text().catch(() => '');
  if (text) {
    try {
      const decoded: unknown = JSON.parse(text);
      if (typeof decoded === 'object' && decoded !== null) {
        payload = decoded as Record<string, unknown>;
        const reported = payload.error ?? payload.message;
        if (typeof reported === 'string' && reported) message = reported;
      }
    } catch {
      message = text.slice(0, 500);
    }
  }
  return new NothingDNSApiError(response.status, message, payload);
}
