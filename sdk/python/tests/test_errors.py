"""Error translation and predicate-helper tests."""

from __future__ import annotations

import pytest

from nothingdns import (
    NothingDNSApiError,
    NothingDNSClient,
    NothingDNSConnectionError,
    is_forbidden,
    is_not_found,
    is_rate_limited,
    is_unauthorized,
)


def test_unauthorized_predicate(client):
    with pytest.raises(NothingDNSApiError) as excinfo:
        client.auth.login("admin", "wrong")

    assert excinfo.value.status_code == 401
    assert excinfo.value.message == "invalid credentials"
    assert is_unauthorized(excinfo.value)
    assert not is_forbidden(excinfo.value)


def test_forbidden_predicate(client):
    with pytest.raises(NothingDNSApiError) as excinfo:
        client.dnssec.keys()

    assert excinfo.value.status_code == 403
    assert is_forbidden(excinfo.value)


def test_rate_limited_predicate(client):
    with pytest.raises(NothingDNSApiError) as excinfo:
        client.cache.flush()

    assert excinfo.value.status_code == 429
    assert is_rate_limited(excinfo.value)


def test_not_found_predicate(client):
    with pytest.raises(NothingDNSApiError) as excinfo:
        client.zones.get("missing.com")

    assert is_not_found(excinfo.value)
    assert excinfo.value.payload == {"error": "Zone missing.com not found"}


def test_predicates_reject_non_api_errors():
    assert not is_not_found(RuntimeError("nope"))
    assert not is_unauthorized(ValueError("nope"))
    assert not is_forbidden(None)
    assert not is_rate_limited(404)


def test_api_error_string_includes_status_and_message():
    error = NothingDNSApiError(409, "zone already exists")

    assert "409" in str(error)
    assert "zone already exists" in str(error)


def test_unreachable_server_raises_connection_error():
    # Bind a port, note it, then close it so connections are refused.
    import socket

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()

    client = NothingDNSClient(f"http://127.0.0.1:{dead_port}", timeout=2.0)
    with pytest.raises(NothingDNSConnectionError):
        client.health()
