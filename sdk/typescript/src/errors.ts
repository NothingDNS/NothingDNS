/**
 * Errors raised by the NothingDNS SDK.
 *
 * Every rejected HTTP response surfaces as {@link NothingDNSApiError}, which
 * carries the status code, the server's message and the decoded body, so
 * callers can branch on the failure without parsing strings.
 */

/** Base class for every error thrown by this SDK. */
export class NothingDNSError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** A 4xx/5xx response returned by the NothingDNS server. */
export class NothingDNSApiError extends NothingDNSError {
  /** HTTP status code of the response. */
  readonly statusCode: number;
  /** Human-readable error text (the server's `error` field, or the raw body). */
  override readonly message: string;
  /** Decoded JSON body, when the server sent one. */
  readonly payload: Record<string, unknown>;

  constructor(statusCode: number, message: string, payload: Record<string, unknown> = {}) {
    super(`NothingDNS API error ${statusCode}: ${message}`);
    this.statusCode = statusCode;
    this.message = message;
    this.payload = payload;
  }

  /** `"NothingDNSApiError: NothingDNS API error <status>: <message>"` (mirrors the Python SDK). */
  override toString(): string {
    return `${this.name}: NothingDNS API error ${this.statusCode}: ${this.message}`;
  }
}

/** The server could not be reached (DNS failure, refused connection, TLS error, timeout). */
export class NothingDNSConnectionError extends NothingDNSError {
  /** The underlying error from `fetch`, when there was one. */
  override readonly cause?: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.cause = cause;
  }
}

/** A response could not be decoded, or an argument failed local validation. */
export class NothingDNSValidationError extends NothingDNSError {
  /** The underlying parse error, when there was one. */
  override readonly cause?: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.cause = cause;
  }
}

/** True when the error is an HTTP 404 from the server. */
export function isNotFound(error: unknown): error is NothingDNSApiError {
  return error instanceof NothingDNSApiError && error.statusCode === 404;
}

/** True when the error is an HTTP 401 (missing or expired token). */
export function isUnauthorized(error: unknown): error is NothingDNSApiError {
  return error instanceof NothingDNSApiError && error.statusCode === 401;
}

/** True when the error is an HTTP 403 — the token's role is too low. */
export function isForbidden(error: unknown): error is NothingDNSApiError {
  return error instanceof NothingDNSApiError && error.statusCode === 403;
}

/** True when the error is an HTTP 429 (rate limited). */
export function isRateLimited(error: unknown): error is NothingDNSApiError {
  return error instanceof NothingDNSApiError && error.statusCode === 429;
}
