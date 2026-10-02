"""Authentication, users and roles (``/api/v1/auth``).

Credential *acquisition* lives here; credential *transmission* is handled by
:class:`nothingdns._http.Transport`, which every namespace shares. That split
keeps the login payloads and the bearer header in separate modules.
"""

from __future__ import annotations

from typing import List, Optional, Sequence

from . import models as m
from ._http import Transport, message_of
from .errors import NothingDNSValidationError

# Roles a user account can hold, ordered viewer < operator < admin.
ROLES = ("viewer", "operator", "admin")


class AuthResource:
    """Log in, manage accounts and read the server's role table.

    Args:
        transport: The shared :class:`~nothingdns._http.Transport`.
    """

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def login(
        self,
        username: str,
        password: str,
        *,
        store_token: bool = True,
    ) -> m.Session:
        """Log in and receive a bearer token.

        Args:
            username: Account name.
            password: Account password.
            store_token: Keep the returned token on the client so later calls
                are authenticated automatically.

        Returns:
            The :class:`~nothingdns.models.Session` (token, username, role,
            expiry).

        Raises:
            NothingDNSApiError: 400 for a malformed request, 401 for bad
                credentials, 429 when the login rate limit is hit.
        """
        data = self._t.post(
            "/api/v1/auth/login", json={"username": username, "password": password}
        )
        session = m.Session.from_dict(data)
        if store_token and session.token:
            self._t.set_token(session.token)
        return session

    def bootstrap(
        self,
        username: str,
        password: str,
        *,
        old_password: Optional[str] = None,
        store_token: bool = True,
    ) -> m.Session:
        """Create the first admin account, or reset an existing account's password.

        Use this to provision the very first admin on a fresh server, or to
        recover access when the current password is known.

        Args:
            username: New (or first) admin account name.
            password: New password for the account.
            old_password: Current password of the account being reset. Required
                when resetting an existing account that is not the initial
                bootstrap.
            store_token: Keep the returned token on the client.

        Raises:
            NothingDNSApiError: 401 when ``old_password`` is wrong, 403 when
                the change is not permitted for this caller, 409 when the
                server already has an admin and no ``old_password`` was given.
        """
        payload = {"username": username, "password": password}
        if old_password is not None:
            payload["old_password"] = old_password
        data = self._t.post("/api/v1/auth/bootstrap", json=payload)
        session = m.Session.from_dict(data)
        if store_token and session.token:
            self._t.set_token(session.token)
        return session

    def session(self) -> m.Session:
        """Return the current session: token, username and role.

        The dashboard calls this to rebuild its in-memory bearer after a page
        reload without persisting the token in the browser. The server
        rejects the legacy shared ``auth_token`` for this call — a real
        login session is required.
        """
        return m.Session.from_dict(self._t.get("/api/v1/auth/session"))

    def logout(self) -> str:
        """Invalidate the current session and return the server's message."""
        return message_of(self._t.post("/api/v1/auth/logout", expect_json=False))

    def roles(self) -> List[m.Role]:
        """List the roles the server knows about (operator+).

        Returns:
            The role table; the order mirrors the server's own listing.
        """
        return _models(self._t.get("/api/v1/auth/roles"), "roles", m.Role)

    def list_users(self) -> List[m.User]:
        """List every user account (operator+).

        Passwords are never returned by the API.
        """
        return _models(self._t.get("/api/v1/auth/users"), None, m.User)

    def create_user(self, username: str, password: str, role: str = "viewer") -> m.User:
        """Create a user account (admin only).

        Args:
            username: New account name; must be unique on this server.
            password: Password for the new account.
            role: ``viewer`` (read-only), ``operator`` (zones, cache, config
                reads) or ``admin`` (everything, including users and runtime
                config changes).

        Returns:
            The created account.

        Raises:
            NothingDNSApiError: 409 when the username already exists.
            NothingDNSValidationError: when *role* is not a known role.
        """
        if role not in ROLES:
            raise NothingDNSValidationError(f"role must be one of {', '.join(ROLES)}")
        data = self._t.post(
            "/api/v1/auth/users",
            json={"username": username, "password": password, "role": role},
        )
        return m.User.from_dict(data)

    def delete_user(self, username: str) -> str:
        """Delete a user account by name (admin only).

        Returns:
            The server's confirmation message.
        """
        return message_of(self._t.delete(f"/api/v1/auth/users/{self._t.escape(username)}"))


def _models(payload: object, key: Optional[str], model: type) -> List[object]:
    """Map a JSON array (optionally nested under *key*) into model instances."""
    items = payload.get(key) if key and isinstance(payload, dict) else payload
    if not isinstance(items, list):
        raise NothingDNSValidationError("NothingDNS returned an unexpected list payload")
    return [model.from_dict(item) for item in items]


def list_roles(transport: Transport) -> Sequence[m.Role]:
    """Functional shortcut for :meth:`AuthResource.roles`."""
    return AuthResource(transport).roles()
