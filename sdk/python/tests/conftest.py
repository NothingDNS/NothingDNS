"""Shared fixtures: an in-process mock NothingDNS API and a bound client.

The mock implements the response shapes of the real management API contract
(NothingDNS 1.2.17) for the endpoints the suite exercises, and records every
request so tests can assert on methods, paths, bodies and headers.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

import pytest

from nothingdns import NothingDNSClient

USERNAME = "admin"
PASSWORD = "correct"
TOKEN = "tok-123"


class RecordedRequest(dict):
    """One recorded request: method, path (with query), body, auth header."""

    @property
    def method(self) -> str:
        return self["method"]

    @property
    def path(self) -> str:
        return self["path"]

    @property
    def body(self) -> Optional[Dict[str, Any]]:
        return self["body"]

    @property
    def auth(self) -> Optional[str]:
        return self["auth"]


class MockNothingDNS:
    """In-process stand-in for the NothingDNS management API."""

    def __init__(self) -> None:
        self.requests: List[RecordedRequest] = []
        handler = self._make_handler()
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def last(self) -> RecordedRequest:
        return self.requests[-1]

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    # -- request routing ----------------------------------------------------

    def _make_handler(self) -> type:
        mock = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:  # silence test output
                pass

            def _read_body(self) -> Optional[Dict[str, Any]]:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                return json.loads(raw) if raw else None

            def _send(self, code: int, payload: Any, raw: bool = False) -> None:
                body = payload.encode() if raw else json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "text/plain" if raw else "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _handle(self, method: str) -> None:
                body = self._read_body()
                path = self.path
                mock.requests.append(
                    RecordedRequest(method=method, path=path, body=body, auth=self.headers.get("Authorization"))
                )
                route = path.split("?", 1)[0]

                if route == "/health":
                    return self._send(200, {"status": "healthy", "timestamp": "2026-10-02T11:00:00Z"})
                if route == "/api/v1/auth/login":
                    if body.get("password") != PASSWORD:
                        return self._send(401, {"error": "invalid credentials"})
                    return self._send(
                        200,
                        {
                            "token": TOKEN,
                            "username": USERNAME,
                            "role": "admin",
                            "expires": "2026-10-02T12:00:00Z",
                        },
                    )
                if route == "/api/v1/auth/logout":
                    return self._send(200, {"message": "logged out"})
                if route == "/api/v1/status":
                    return self._send(
                        200,
                        {
                            "status": "running",
                            "timestamp": "t",
                            "version": "1.2.17",
                            "cache": {"size": 3, "capacity": 100, "hits": 9, "misses": 1, "hit_ratio": 0.9},
                            "cluster": {
                                "enabled": False,
                                "node_id": "n1",
                                "node_count": 1,
                                "alive_count": 1,
                                "healthy": True,
                            },
                        },
                    )
                if route == "/api/v1/zones":
                    return self._send(
                        200,
                        {"zones": [{"name": "example.com", "serial": 7, "records": 3}], "total": 1, "truncated": False},
                    )
                if route == "/api/v1/zones/example.com/records":
                    if method == "GET":
                        return self._send(
                            200,
                            {
                                "records": [
                                    {"name": "www", "type": "A", "ttl": 300, "class": "IN", "data": "192.0.2.1"}
                                ],
                                "total": 1,
                                "truncated": False,
                            },
                        )
                    if method == "POST":
                        return self._send(201, {"message": "record added"})
                    if method == "PUT":
                        return self._send(200, {"message": "record replaced"})
                    return self._send(200, {"message": "records deleted"})
                if route == "/api/v1/zones/example.com/export":
                    text = "$ORIGIN example.com.\n@ IN SOA ns1 hostmaster 7 3600 600 86400 300\n"
                    return self._send(200, text, raw=True)
                if route == "/api/v1/zones/missing.com":
                    return self._send(404, {"error": "Zone missing.com not found"})
                if route == "/api/v1/zones/2.0.192.in-addr.arpa/ptr-bulk":
                    return self._send(
                        200,
                        {
                            "preview": True,
                            "total": 256,
                            "willAdd": 256,
                            "willAddA": 0,
                            "willSkip": 0,
                            "willOverride": 0,
                            "changes": [
                                {
                                    "name": "1",
                                    "type": "PTR",
                                    "ttl": 300,
                                    "data": "host-192-0-2-1.example.com",
                                    "action": "add",
                                }
                            ],
                        },
                    )
                if route == "/api/v1/acl":
                    if method == "GET":
                        return self._send(
                            200,
                            {
                                "rules": [
                                    {
                                        "name": "office",
                                        "networks": ["10.0.0.0/8"],
                                        "action": "allow",
                                        "types": ["A"],
                                        "redirect": "",
                                    }
                                ],
                                "allow_recursion": {"allow_all": False, "networks": ["10.0.0.0/8"]},
                                "persistent": True,
                                "policy_file": "/var/lib/nothingdns/access_policy.json",
                            },
                        )
                    return self._send(200, {"message": "acl updated"})
                if route == "/api/v1/acl/recursion":
                    return self._send(200, {"allow_all": False, "networks": ["10.0.0.0/8"]})
                if route == "/api/v1/config/logging":
                    return self._send(200, {"message": "log level updated"})
                if route.startswith("/api/v1/config/"):
                    return self._send(200, {"message": "config updated"})
                if route == "/api/dashboard/queries":
                    return self._send(
                        200,
                        [
                            {
                                "timestamp": "t",
                                "clientIp": "10.0.0.5",
                                "countryCode": "NL",
                                "domain": "example.com",
                                "queryType": "A",
                                "responseCode": "NOERROR",
                                "answers": ["192.0.2.1"],
                                "duration": 1,
                                "cached": True,
                                "blocked": False,
                                "protocol": "udp",
                            }
                        ],
                    )
                if route == "/api/v1/queries":
                    return self._send(
                        200,
                        {
                            "queries": [
                                {
                                    "timestamp": "t",
                                    "client_ip": "10.0.0.5",
                                    "domain": "example.com",
                                    "query_type": "A",
                                    "response_code": "NOERROR",
                                    "answers": ["192.0.2.1"],
                                    "duration_ms": 1,
                                    "cached": True,
                                    "blocked": False,
                                    "protocol": "udp",
                                }
                            ],
                            "total": 1,
                            "offset": 0,
                            "limit": 50,
                        },
                    )
                if route == "/api/v1/upstreams":
                    if method == "GET":
                        return self._send(
                            200,
                            {
                                "upstreams": [
                                    {"address": "9.9.9.9:53", "healthy": True, "queries": 5, "failed": 0, "failovers": 0}
                                ],
                                "servers": [{"address": "9.9.9.9:53", "healthy": True, "latency_ms": 12.5}],
                            },
                        )
                    return self._send(200, {"message": "upstream added"})
                if route == "/api/v1/zones/transfers":
                    return self._send(
                        200,
                        {
                            "slave_zones": [
                                {
                                    "zone": "sub.example.com",
                                    "masters": "192.0.2.53",
                                    "serial": 3,
                                    "last_transfer": "2026-10-01T00:00:00Z",
                                    "status": "synced",
                                    "records": 12,
                                }
                            ]
                        },
                    )
                if route == "/api/v1/dnssec/status":
                    return self._send(200, {"enabled": True, "require_dnssec": False})
                if route == "/api/v1/dnssec/keys":
                    return self._send(403, {"error": "admin role required"})
                if route == "/api/v1/cache/flush":
                    return self._send(429, {"error": "rate limited"})
                return self._send(404, {"error": "not found"})

            def do_GET(self) -> None:
                self._handle("GET")

            def do_POST(self) -> None:
                self._handle("POST")

            def do_PUT(self) -> None:
                self._handle("PUT")

            def do_DELETE(self) -> None:
                self._handle("DELETE")

        return Handler


@pytest.fixture()
def mock_api() -> "MockNothingDNS":
    """One mock server per test, so recorded requests never leak between tests."""
    api = MockNothingDNS()
    yield api
    api.close()


@pytest.fixture()
def client(mock_api: MockNothingDNS):
    """An unauthenticated client bound to the mock server."""
    with NothingDNSClient(mock_api.base_url, timeout=5.0) as instance:
        yield instance


@pytest.fixture()
def authed_client(client, mock_api: MockNothingDNS):
    """A client that has logged in as the mock's admin user."""
    client.auth.login(USERNAME, PASSWORD)
    return client
