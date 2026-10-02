"""HTTP transport shared by every NothingDNS resource namespace.

The transport owns URL construction, the ``Authorization`` header, query
serialisation, JSON encoding, timeouts and the translation of HTTP failures
into SDK errors. Resource namespaces (see :mod:`nothingdns.client`) only
describe *what* to call; the transport decides *how* the request is made.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Union
from urllib.parse import quote, urlencode

import requests

from .errors import NothingDNSApiError, NothingDNSConnectionError, NothingDNSValidationError

DEFAULT_BASE_URL = "http://localhost:8080"
DEFAULT_TIMEOUT = 30.0


def drop_none(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Return *payload* without keys whose value is ``None``.

    Used by the partial-update endpoints (config, ACL, …) so that an omitted
    argument means "leave unchanged" rather than "send null".
    """
    return {k: v for k, v in payload.items() if v is not None}


def message_of(payload: Any) -> str:
    """Extract the server's plain acknowledgement ``message`` from a body."""
    return payload.get("message", "") if isinstance(payload, dict) else ""


def api_error(response: "requests.Response") -> NothingDNSApiError:
    """Build a :class:`~nothingdns.errors.NothingDNSApiError` from a 4xx/5xx response.

    The server reports failures as ``{"error": "…"}``; a non-JSON body falls
    back to the raw text so the message is never lost.
    """
    payload: Dict[str, Any] = {}
    text = f"HTTP {response.status_code}"
    try:
        decoded = response.json()
    except ValueError:
        decoded = None
    if isinstance(decoded, dict):
        payload = decoded
        reported = decoded.get("error") or decoded.get("message")
        if isinstance(reported, str) and reported:
            text = reported
    else:
        body = (response.text or "").strip()
        if body:
            text = body[:500]
    return NothingDNSApiError(response.status_code, text, payload)


class Transport:
    """Performs authenticated HTTP calls against one NothingDNS server.

    Args:
        base_url: Base URL of the server's HTTP listener, e.g.
            ``http://dns.example.com:8080``.
        token: Bearer token to send, or ``None`` for an unauthenticated client.
        timeout: Per-request timeout in seconds.
        verify: TLS verification — ``True`` (default), ``False``, or a CA
            bundle path.
        headers: Extra default headers merged into every request.
        session: An existing :class:`requests.Session` to reuse (shared
            connection pool, proxy, retries, …).
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        token: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        verify: Union[bool, str] = True,
        headers: Optional[Mapping[str, str]] = None,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.verify = verify
        self._token = token
        self._default_headers: Dict[str, str] = {"Accept": "application/json"}
        if headers:
            self._default_headers.update(headers)

    # -- token --------------------------------------------------------------

    @property
    def token(self) -> Optional[str]:
        """The bearer token currently sent with requests (or ``None``)."""
        return self._token

    def set_token(self, token: Optional[str]) -> None:
        """Use *token* for all subsequent requests (``None`` to go anonymous).

        Accepts a JWT returned by ``auth.login`` / ``auth.bootstrap`` or the
        static ``server.http.auth_token`` value from the server config.
        """
        self._token = token or None

    def clear_token(self) -> None:
        """Forget the bearer token; subsequent requests are sent unauthenticated."""
        self._token = None

    def _headers(self) -> Dict[str, str]:
        headers = dict(self._default_headers)
        if self._token:
            headers["Authorization"] = "Bearer " + self._token
        return headers

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def escape(name: Union[str, int]) -> str:
        """Percent-encode one path segment (zone names, source ids, usernames)."""
        return quote(str(name), safe="")

    @staticmethod
    def query(params: Optional[Mapping[str, Any]] = None) -> str:
        """Serialise query parameters, skipping ``None`` values."""
        if not params:
            return ""
        cleaned = drop_none(params)
        if not cleaned:
            return ""
        return "?" + urlencode({k: str(v) for k, v in cleaned.items()})

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json: Optional[Any] = None,
        raw: bool = False,
        expect_json: bool = True,
    ) -> Any:
        """Send one request and return the decoded body.

        Args:
            method: HTTP verb.
            path: API path starting with ``/``; escape dynamic segments with
                :meth:`escape` before interpolating them.
            params: Query parameters (``None`` values are dropped).
            json: Optional JSON request body.
            raw: Return the response text instead of decoded JSON — used by
                the zone export endpoint, which serves a BIND zone file.
            expect_json: Decode a JSON body whenever the server sends one.
                Set to ``False`` for acknowledgement endpoints so a non-JSON
                2xx body is tolerated (returned as ``None``) instead of
                raising.

        Raises:
            NothingDNSApiError: The server answered with a 4xx/5xx status.
            NothingDNSConnectionError: The server could not be reached.
            NothingDNSValidationError: A 2xx body was not valid JSON.
        """
        url = f"{self.base_url}{path}{self.query(params)}"
        try:
            response = self.session.request(
                method, url, json=json, headers=self._headers(), timeout=self.timeout
            )
        except requests.RequestException as exc:
            raise NothingDNSConnectionError(
                f"Could not reach NothingDNS at {url}: {exc}", cause=exc
            ) from exc

        if not 200 <= response.status_code < 300:
            raise api_error(response)

        if raw:
            return response.text
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            if expect_json:
                raise NothingDNSValidationError(
                    f"NothingDNS returned a non-JSON body for {method} {url}: {response.text[:200]}"
                ) from exc
            # expect_json=False means "don't demand JSON"; an unparseable
            # acknowledgement body is tolerated and reported as absent.
            return None

    def get(self, path: str, **kwargs: Any) -> Any:
        """Shorthand for ``request("GET", path, …)``."""
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Any:
        """Shorthand for ``request("POST", path, …)``."""
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> Any:
        """Shorthand for ``request("PUT", path, …)``."""
        return self.request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Any:
        """Shorthand for ``request("DELETE", path, …)``."""
        return self.request("DELETE", path, **kwargs)

    def close(self) -> None:
        """Close the underlying HTTP session."""
        self.session.close()
