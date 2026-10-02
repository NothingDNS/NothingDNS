"""Exceptions raised by the NothingDNS SDK."""

from __future__ import annotations

from typing import Any, Dict, Optional


class NothingDNSError(Exception):
    """Base class for every error raised by the NothingDNS SDK."""


class NothingDNSApiError(NothingDNSError):
    """An HTTP 4xx/5xx response returned by the NothingDNS server.

    Attributes:
        status_code: HTTP status code of the response.
        message: Human-readable error text (the server's ``error`` field,
            or the raw body when the payload is not JSON).
        payload: Decoded JSON body of the response, when available.
    """

    def __init__(
        self,
        status_code: int,
        message: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(f"NothingDNS API error {status_code}: {message}")
        self.status_code = status_code
        self.message = message
        self.payload = payload or {}


class NothingDNSConnectionError(NothingDNSError):
    """The server could not be reached (DNS failure, refused connection, TLS error, timeout)."""

    def __init__(self, message: str, cause: Optional[BaseException] = None) -> None:
        super().__init__(message)
        self.cause = cause


class NothingDNSValidationError(NothingDNSError):
    """A response could not be decoded, or an argument failed local validation."""


# Convenience predicate helpers ---------------------------------------------


def is_not_found(exc: BaseException) -> bool:
    """True when *exc* is the API error raised for HTTP 404."""
    return isinstance(exc, NothingDNSApiError) and exc.status_code == 404


def is_unauthorized(exc: BaseException) -> bool:
    """True when *exc* is the API error raised for HTTP 401 (missing/expired token)."""
    return isinstance(exc, NothingDNSApiError) and exc.status_code == 401


def is_forbidden(exc: BaseException) -> bool:
    """True when *exc* is the API error raised for HTTP 403 (insufficient role).

    Role hierarchy on the server: viewer < operator < admin.
    """
    return isinstance(exc, NothingDNSApiError) and exc.status_code == 403


def is_rate_limited(exc: BaseException) -> bool:
    """True when *exc* is the API error raised for HTTP 429 (rate limited)."""
    return isinstance(exc, NothingDNSApiError) and exc.status_code == 429
