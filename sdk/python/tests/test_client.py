"""Behavioural tests for the NothingDNS Python client against a mock server.

Mirrors the request-level contract: paths, methods, query strings, JSON bodies,
bearer-auth propagation and typed model decoding.
"""

from __future__ import annotations

import pytest

from nothingdns import (
    ACLRule,
    NothingDNSApiError,
    NothingDNSClient,
    is_not_found,
)
from nothingdns.models import PTRBulkPreview

from .conftest import PASSWORD, TOKEN, USERNAME

SERVICE_TOKEN = f"{TOKEN}-service"
"""A second, distinct token value used to test client.set_token."""

pytestmark = pytest.mark.usefixtures("mock_api")


# --------------------------------------------------------------------------
# Health & authentication
# --------------------------------------------------------------------------


def test_health_needs_no_auth(client, mock_api):
    health = client.health()

    assert health.status == "healthy"
    assert mock_api.last.auth is None


def test_login_stores_token_and_next_request_carries_it(client, mock_api):
    session = client.auth.login(USERNAME, PASSWORD)

    assert session.role == "admin"
    assert session.expires == "2026-10-02T12:00:00Z"
    assert client.token == TOKEN
    # The login request itself must not carry a token; the next one must.
    assert mock_api.requests[-1].auth is None
    client.status()
    assert mock_api.last.auth == f"Bearer {TOKEN}"


def test_login_can_skip_storing_the_token(client):
    session = client.auth.login(USERNAME, PASSWORD, store_token=False)

    assert session.token == TOKEN
    assert client.token is None


def test_set_token_is_used_for_requests(client, mock_api):
    client.set_token(SERVICE_TOKEN)

    client.status()
    assert mock_api.last.auth == f"Bearer {SERVICE_TOKEN}"


def test_logout_invalidates_and_returns_message(client):
    client.set_token(TOKEN)

    assert client.auth.logout() == "logged out"


# --------------------------------------------------------------------------
# Status & models
# --------------------------------------------------------------------------


def test_status_decodes_nested_models(client):
    status = client.status()

    assert status.version == "1.2.17"
    assert status.cache.hit_ratio == 0.9
    assert isinstance(status.cache.hit_ratio, float)
    assert status.cluster.enabled is False
    assert status.cluster.node_id == "n1"


# --------------------------------------------------------------------------
# Zones & records
# --------------------------------------------------------------------------


def test_zone_list_decodes_zones(client):
    zones = client.zones.list()

    assert zones.total == 1
    assert zones.truncated is False
    assert zones.zones[0].name == "example.com"
    assert zones.zones[0].serial == 7


def test_record_crud_bodies_and_methods(client, mock_api):
    records = client.zones.list_records("example.com")
    assert records.records[0].data == "192.0.2.1"
    assert records.records[0].class_ == "IN"  # wire field "class"

    client.zones.add_record("example.com", "api", "A", "192.0.2.9", ttl=60)
    assert mock_api.last.method == "POST"
    assert mock_api.last.path == "/api/v1/zones/example.com/records"
    assert mock_api.last.body == {"name": "api", "type": "A", "data": "192.0.2.9", "ttl": 60}

    client.zones.replace_record("example.com", "api", "A", "192.0.2.9", "192.0.2.10")
    assert mock_api.last.method == "PUT"
    assert mock_api.last.body["old_data"] == "192.0.2.9"

    client.zones.delete_records("example.com", "api", "A")
    assert mock_api.last.method == "DELETE"
    assert mock_api.last.body == {"name": "api", "type": "A"}


def test_zone_export_returns_raw_zone_file(authed_client):
    text = authed_client.zones.export("example.com")

    assert text.startswith("$ORIGIN example.com.")


def test_missing_zone_raises_404_and_predicate_matches(client):
    with pytest.raises(NothingDNSApiError) as excinfo:
        client.zones.get("missing.com")

    assert excinfo.value.status_code == 404
    assert "missing.com" in excinfo.value.message
    assert is_not_found(excinfo.value)


def test_ptr_bulk_preview_decodes_camel_case_wire(client, mock_api):
    preview = client.zones.ptr_bulk(
        "2.0.192.in-addr.arpa", "192.0.2.0/24", "host-{ip}.example.com"
    )

    assert isinstance(preview, PTRBulkPreview)
    assert preview.preview is True
    assert preview.willAdd == 256
    assert preview.changes[0].data == "host-192-0-2-1.example.com"
    # Request keeps the wire's camelCase keys.
    assert mock_api.last.body["addA"] is False
    assert mock_api.last.body["preview"] is True


def test_zone_transfers(client):
    slaves = client.zones.transfers()

    assert slaves[0].zone == "sub.example.com"
    assert slaves[0].status == "synced"
    assert slaves[0].records == 12


# --------------------------------------------------------------------------
# ACL
# --------------------------------------------------------------------------


def test_acl_roundtrip(client, mock_api):
    acl = client.acl.get()
    assert acl.rules[0].action == "allow"
    assert acl.rules[0].networks == ["10.0.0.0/8"]
    assert acl.allow_recursion.allow_all is False
    assert acl.persistent is True

    client.acl.set([ACLRule(name="vpn", networks=["10.1.0.0/16"], action="deny")])
    assert mock_api.last.body == {
        "rules": [{"name": "vpn", "networks": ["10.1.0.0/16"], "action": "deny"}]
    }

    recursion = client.acl.set_recursion(["10.0.0.0/8"])
    assert recursion.networks == ["10.0.0.0/8"]


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def test_config_partial_update_drops_none_and_parses_message(client, mock_api):
    message = client.config.set_logging("debug")

    assert message == "log level updated"
    assert mock_api.last.method == "PUT"
    assert mock_api.last.body == {"level": "debug"}

    client.config.set_cache(size=5000, serve_stale=True)
    assert mock_api.last.body == {"size": 5000, "serve_stale": True}


# --------------------------------------------------------------------------
# Dashboard & metrics
# --------------------------------------------------------------------------


def test_dashboard_queries_keep_camel_case(client):
    events = client.dashboard.queries()

    assert events[0].clientIp == "10.0.0.5"
    assert events[0].countryCode == "NL"
    assert events[0].cached is True


def test_query_log_params_and_snake_case_payload(client, mock_api):
    page = client.metrics.query_log(limit=50, q="example")

    assert mock_api.last.path == "/api/v1/queries?limit=50&q=example"
    assert page.queries[0].client_ip == "10.0.0.5"
    assert page.total == 1


# --------------------------------------------------------------------------
# Upstreams
# --------------------------------------------------------------------------


def test_upstream_listing_and_add(client, mock_api):
    pool = client.upstreams.list()
    assert pool.servers[0].latency_ms == 12.5

    client.upstreams.add("1.1.1.1:53")
    assert mock_api.last.method == "PUT"
    assert mock_api.last.body == {"action": "add", "server": "1.1.1.1:53"}


# --------------------------------------------------------------------------
# Local validation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.acl.set([]),
        lambda c: c.config.set_logging("loud"),
        lambda c: c.blocklists.add(),
        lambda c: c.blocklists.add(file="a.hosts", url="https://example.invalid/hosts"),
        lambda c: c.auth.create_user("ops", "pw-op-1", role="root"),
        lambda c: c.rpz.add_rule("ads.example.com", action="DENY"),
        lambda c: c.zones.create("example.com", nameservers=[]),
    ],
    ids=[
        "empty-acl",
        "bad-log-level",
        "blocklist-without-source",
        "blocklist-with-both-sources",
        "unknown-role",
        "unknown-rpz-action",
        "zone-without-nameservers",
    ],
)
def test_local_validation_rejects_before_any_request(client, mock_api, call):
    with pytest.raises(Exception) as excinfo:  # noqa: B017, PT011 - type asserted below
        call(client)

    assert type(excinfo.value).__name__ == "NothingDNSValidationError"
    assert mock_api.requests == []  # nothing was sent


# --------------------------------------------------------------------------
# Request mechanics
# --------------------------------------------------------------------------


def test_path_segments_are_escaped(client, mock_api):
    with pytest.raises(NothingDNSApiError):
        client.zones.get("weird zone/name")

    assert "%20" in mock_api.last.path
    assert "%2F" in mock_api.last.path


def test_trailing_slash_in_base_url_is_normalised(mock_api):
    with NothingDNSClient(mock_api.base_url + "/", timeout=5.0) as client:
        assert client.base_url == mock_api.base_url
        assert client.health().status == "healthy"
