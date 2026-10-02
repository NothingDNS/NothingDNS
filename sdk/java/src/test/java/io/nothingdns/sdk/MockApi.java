package io.nothingdns.sdk;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * In-process mock NothingDNS management API for the SDK test suite, built on
 * the JDK's own {@code com.sun.net.httpserver} (no extra dependencies).
 *
 * <p>Implements the response shapes of the real management API contract
 * (NothingDNS 1.2.17) for the endpoints the suite exercises, and records every
 * request so tests can assert on methods, paths, bodies and headers. It mirrors
 * {@code sdk/python/tests/conftest.py} and {@code sdk/typescript/test/mock-server.mjs}.</p>
 */
final class MockApi {

    static final String USERNAME = "admin";
    static final String PASSWORD = "correct";
    static final String TOKEN = "tok-123";
    static final String SERVICE_TOKEN = TOKEN + "-service";

    private static final String ZONE_FILE =
            "$ORIGIN example.com.\n@ IN SOA ns1 hostmaster 7 3600 600 86400 300\n";

    /** One recorded request: method, path (with query), JSON body, auth header. */
    record Recorded(String method, String path, JsonObject body, String auth) {
    }

    private final HttpServer server;
    private final List<Recorded> requests = new CopyOnWriteArrayList<>();

    MockApi() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::handle);
        // A single dispatcher thread keeps request handling sequential and
        // deterministic; the suite never issues concurrent calls.
        server.setExecutor(null);
        server.start();
    }

    /** @return the base URL of the mock server, without a trailing slash */
    String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /** @return every request received so far, in arrival order */
    List<Recorded> requests() {
        return requests;
    }

    /** @return the most recent request */
    Recorded last() {
        return requests.get(requests.size() - 1);
    }

    void close() {
        server.stop(0);
    }

    // -- request handling ---------------------------------------------------

    private void handle(HttpExchange exchange) {
        try {
            String raw = new String(exchange.getRequestBody().readAllBytes(),
                    StandardCharsets.UTF_8);
            JsonObject body = raw.isBlank() ? null
                    : JsonParser.parseString(raw).getAsJsonObject();
            // getRequestURI().toString() keeps the raw, percent-encoded
            // path plus query, which is exactly what the tests assert on.
            String path = exchange.getRequestURI().toString();
            requests.add(new Recorded(exchange.getRequestMethod(), path, body,
                    exchange.getRequestHeaders().getFirst("Authorization")));
            route(exchange, path.split("\\?", 2)[0], body);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } finally {
            exchange.close();
        }
    }

    private void route(HttpExchange exchange, String route, JsonObject body) throws IOException {
        switch (route) {
            case "/health", "/readyz", "/livez":
                json(exchange, 200, "{\"status\": \"healthy\", \"timestamp\": \"2026-10-02T11:00:00Z\"}");
                return;
            case "/api/v1/auth/login":
                String password = body != null && body.has("password")
                        ? body.get("password").getAsString() : null;
                if (!PASSWORD.equals(password)) {
                    json(exchange, 401, "{\"error\": \"invalid credentials\"}");
                } else {
                    json(exchange, 200, "{\"token\": \"" + TOKEN + "\", \"username\": \"" + USERNAME
                            + "\", \"role\": \"admin\", \"expires\": \"2026-10-02T12:00:00Z\"}");
                }
                return;
            case "/api/v1/auth/logout":
                json(exchange, 200, "{\"message\": \"logged out\"}");
                return;
            case "/api/v1/status":
                json(exchange, 200, """
                        {
                          "status": "running",
                          "timestamp": "t",
                          "version": "1.2.17",
                          "cache": {"size": 3, "capacity": 100, "hits": 9, "misses": 1, "hit_ratio": 0.9},
                          "cluster": {"enabled": false, "node_id": "n1", "node_count": 1,
                                      "alive_count": 1, "healthy": true}
                        }""");
                return;
            case "/api/v1/zones":
                json(exchange, 200, """
                        {"zones": [{"name": "example.com", "serial": 7, "records": 3}],
                         "total": 1, "truncated": false}""");
                return;
            case "/api/v1/zones/example.com/records":
                if ("GET".equals(exchange.getRequestMethod())) {
                    json(exchange, 200, """
                            {"records": [{"name": "www", "type": "A", "ttl": 300,
                                          "class": "IN", "data": "192.0.2.1"}],
                             "total": 1, "truncated": false}""");
                } else if ("POST".equals(exchange.getRequestMethod())) {
                    json(exchange, 201, "{\"message\": \"record added\"}");
                } else if ("PUT".equals(exchange.getRequestMethod())) {
                    json(exchange, 200, "{\"message\": \"record replaced\"}");
                } else {
                    json(exchange, 200, "{\"message\": \"records deleted\"}");
                }
                return;
            case "/api/v1/zones/example.com/export":
                text(exchange, 200, ZONE_FILE);
                return;
            case "/api/v1/zones/missing.com":
                json(exchange, 404, "{\"error\": \"Zone missing.com not found\"}");
                return;
            case "/api/v1/zones/2.0.192.in-addr.arpa/ptr-bulk":
                json(exchange, 200, """
                        {
                          "preview": true, "total": 256, "willAdd": 256, "willAddA": 0,
                          "willSkip": 0, "willOverride": 0,
                          "changes": [{"name": "1", "type": "PTR", "ttl": 300,
                                       "data": "host-192-0-2-1.example.com", "action": "add"}]
                        }""");
                return;
            case "/api/v1/zones/transfers":
                json(exchange, 200, """
                        {"slave_zones": [{"zone": "sub.example.com", "masters": "192.0.2.53",
                                          "serial": 3, "last_transfer": "2026-10-01T00:00:00Z",
                                          "status": "synced", "records": 12}]}""");
                return;
            case "/api/v1/acl":
                if ("GET".equals(exchange.getRequestMethod())) {
                    json(exchange, 200, """
                            {
                              "rules": [{"name": "office", "networks": ["10.0.0.0/8"],
                                         "action": "allow", "types": ["A"], "redirect": ""}],
                              "allow_recursion": {"allow_all": false, "networks": ["10.0.0.0/8"]},
                              "persistent": true,
                              "policy_file": "/var/lib/nothingdns/access_policy.json"
                            }""");
                } else {
                    json(exchange, 200, "{\"message\": \"acl updated\"}");
                }
                return;
            case "/api/v1/acl/recursion":
                json(exchange, 200, "{\"allow_all\": false, \"networks\": [\"10.0.0.0/8\"]}");
                return;
            case "/api/v1/config/logging":
                json(exchange, 200, "{\"message\": \"log level updated\"}");
                return;
            case "/api/dashboard/stats":
                json(exchange, 200, """
                        {"uptime": 3600, "queriesTotal": 1234, "queriesPerSec": 12.5,
                         "cacheHitRate": 0.91, "blockedQueries": 7, "activeClients": 3,
                         "zoneCount": 5, "upstreamLatency": 4}""");
                return;
            case "/api/dashboard/queries":
                json(exchange, 200, """
                        [{
                          "timestamp": "t", "clientIp": "10.0.0.5", "countryCode": "NL",
                          "domain": "example.com", "queryType": "A", "responseCode": "NOERROR",
                          "answers": ["192.0.2.1"], "duration": 1, "cached": true,
                          "blocked": false, "protocol": "udp"
                        }]""");
                return;
            case "/api/v1/queries":
                json(exchange, 200, """
                        {
                          "queries": [{
                            "timestamp": "t", "client_ip": "10.0.0.5", "domain": "example.com",
                            "query_type": "A", "response_code": "NOERROR",
                            "answers": ["192.0.2.1"], "duration_ms": 1,
                            "cached": true, "blocked": false, "protocol": "udp"
                          }],
                          "total": 1, "offset": 0, "limit": 50
                        }""");
                return;
            case "/api/v1/upstreams":
                if ("GET".equals(exchange.getRequestMethod())) {
                    json(exchange, 200, """
                            {
                              "upstreams": [{"address": "9.9.9.9:53", "healthy": true,
                                             "queries": 5, "failed": 0, "failovers": 0}],
                              "servers": [{"address": "9.9.9.9:53", "healthy": true,
                                           "latency_ms": 12.5}]
                            }""");
                } else {
                    json(exchange, 200, "{\"message\": \"upstream added\"}");
                }
                return;
            case "/api/v1/dnssec/status":
                json(exchange, 200, "{\"enabled\": true, \"require_dnssec\": false}");
                return;
            case "/api/v1/dnssec/keys":
                json(exchange, 403, "{\"error\": \"admin role required\"}");
                return;
            case "/api/v1/cache/flush":
                json(exchange, 429, "{\"error\": \"rate limited\"}");
                return;
            default:
                if (route.startsWith("/api/v1/config/")) {
                    json(exchange, 200, "{\"message\": \"config updated\"}");
                } else {
                    json(exchange, 404, "{\"error\": \"not found\"}");
                }
        }
    }

    // -- response helpers ---------------------------------------------------

    private static void json(HttpExchange exchange, int code, String payload) throws IOException {
        send(exchange, code, "application/json", payload);
    }

    private static void text(HttpExchange exchange, int code, String payload) throws IOException {
        send(exchange, code, "text/plain", payload);
    }

    private static void send(HttpExchange exchange, int code, String contentType, String payload)
            throws IOException {
        byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
