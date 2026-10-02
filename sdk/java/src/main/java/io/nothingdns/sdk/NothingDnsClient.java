package io.nothingdns.sdk;

import com.google.gson.JsonObject;
import io.nothingdns.sdk.model.HealthResponse;
import io.nothingdns.sdk.model.Json;
import io.nothingdns.sdk.model.ServerConfig;
import io.nothingdns.sdk.model.StatusResponse;
import io.nothingdns.sdk.resources.AclResource;
import io.nothingdns.sdk.resources.BlocklistsResource;
import io.nothingdns.sdk.resources.CacheResource;
import io.nothingdns.sdk.resources.ClusterResource;
import io.nothingdns.sdk.resources.ConfigResource;
import io.nothingdns.sdk.resources.DashboardResource;
import io.nothingdns.sdk.resources.DnssecResource;
import io.nothingdns.sdk.resources.GeoipResource;
import io.nothingdns.sdk.resources.MetricsResource;
import io.nothingdns.sdk.resources.RpzResource;
import io.nothingdns.sdk.resources.UpstreamsResource;
import io.nothingdns.sdk.resources.ZonesResource;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;

/**
 * A typed client for the NothingDNS management API.
 *
 * <p>The client mirrors the server's API groups as namespaces:</p>
 * <pre>
 * client.auth()        // login, bootstrap, session, users, roles
 * client.zones()       // zones, records, export, bulk PTR
 * client.cache()       // cache statistics and flush
 * client.config()      // effective config + runtime tunables
 * client.acl()         // ACL rules and the recursion allow list
 * client.blocklists()  // blocklist sources and filtering
 * client.rpz()         // response policy zones
 * client.dnssec()      // validation status and signing keys
 * client.upstreams()   // upstream pool health
 * client.geoip()       // GeoDNS statistics
 * client.cluster()     // gossip + Raft cluster management
 * client.dashboard()   // dashboard counters, query events, zone summary
 * client.metrics()     // query log, top domains, metrics history
 * </pre>
 *
 * <p>Health and status live directly on the client, since they are not part of a
 * resource group: {@link #health()}, {@link #ready()}, {@link #live()},
 * {@link #status()}, {@link #serverConfig()} and {@link #openapiSpec()}.</p>
 *
 * <p>Every method returns a typed model and throws {@link NothingDnsException}
 * for any non-2xx response, or {@link NothingDnsConnectionException} when the
 * server cannot be reached. The client is safe to share between threads; give
 * each thread its own instance only if you also need per-thread tokens.</p>
 *
 * <p>Use it with try-with-resources so the transport is released:</p>
 * <pre>
 * try (NothingDnsClient client = new NothingDnsClient("http://dns.example.com:8080")) {
 *     client.auth().login(System.getenv("NDNS_USER"), System.getenv("NDNS_PASSWORD"));
 *     for (Zone zone : client.zones().list().getZones()) {
 *         System.out.println(zone.getName() + " " + zone.getRecords());
 *     }
 * }
 * </pre>
 */
public final class NothingDnsClient implements AutoCloseable {

    private final NothingDnsTransport transport;
    private final NothingDnsAuth auth;

    private final ZonesResource zones;
    private final CacheResource cache;
    private final ConfigResource config;
    private final AclResource acl;
    private final BlocklistsResource blocklists;
    private final RpzResource rpz;
    private final DnssecResource dnssec;
    private final UpstreamsResource upstreams;
    private final GeoipResource geoip;
    private final ClusterResource cluster;
    private final DashboardResource dashboard;
    private final MetricsResource metrics;

    /**
     * Create an unauthenticated client with default settings.
     *
     * @param baseUrl the base URL of the server's HTTP listener
     */
    public NothingDnsClient(String baseUrl) {
        this(baseUrl, null, null, null, null);
    }

    /**
     * Create a client that starts with a bearer token.
     *
     * @param baseUrl the base URL of the server's HTTP listener
     * @param token   a JWT from {@code auth().login}, or the static
     *                {@code server.http.auth_token} value; {@code null} to stay
     *                unauthenticated
     */
    public NothingDnsClient(String baseUrl, String token) {
        this(baseUrl, token, null, null, null);
    }

    /**
     * Create a fully configured client.
     *
     * @param baseUrl    the base URL of the server's HTTP listener
     * @param token      the bearer token to start with, or {@code null}
     * @param timeout    the per-request timeout, or {@code null} for
     *                   {@link NothingDnsTransport#DEFAULT_TIMEOUT}
     * @param headers    extra headers merged into every request, or {@code null}
     * @param httpClient an {@link HttpClient} to reuse — useful to share a
     *                   connection pool, a proxy or a custom TLS context — or
     *                   {@code null} to create one
     */
    public NothingDnsClient(String baseUrl,
                            String token,
                            Duration timeout,
                            Map<String, String> headers,
                            HttpClient httpClient) {
        this.transport = new NothingDnsTransport(baseUrl, token, timeout, headers, httpClient);
        this.auth = new NothingDnsAuth(transport);
        this.zones = new ZonesResource(transport);
        this.cache = new CacheResource(transport);
        this.config = new ConfigResource(transport);
        this.acl = new AclResource(transport);
        this.blocklists = new BlocklistsResource(transport);
        this.rpz = new RpzResource(transport);
        this.dnssec = new DnssecResource(transport);
        this.upstreams = new UpstreamsResource(transport);
        this.geoip = new GeoipResource(transport);
        this.cluster = new ClusterResource(transport);
        this.dashboard = new DashboardResource(transport);
        this.metrics = new MetricsResource(transport);
    }

    // -- namespaces --------------------------------------------------------

    /**
     * @return authentication, users and roles
     */
    public NothingDnsAuth auth() {
        return auth;
    }

    /**
     * @return zones, records, export and bulk PTR generation
     */
    public ZonesResource zones() {
        return zones;
    }

    /**
     * @return the DNS response cache
     */
    public CacheResource cache() {
        return cache;
    }

    /**
     * @return the effective configuration and runtime tunables
     */
    public ConfigResource config() {
        return config;
    }

    /**
     * @return ACL rules and the recursion allow list
     */
    public AclResource acl() {
        return acl;
    }

    /**
     * @return blocklist sources and filtering
     */
    public BlocklistsResource blocklists() {
        return blocklists;
    }

    /**
     * @return response policy zones
     */
    public RpzResource rpz() {
        return rpz;
    }

    /**
     * @return DNSSEC validation status and signing keys
     */
    public DnssecResource dnssec() {
        return dnssec;
    }

    /**
     * @return upstream pool health and membership
     */
    public UpstreamsResource upstreams() {
        return upstreams;
    }

    /**
     * @return GeoDNS statistics
     */
    public GeoipResource geoip() {
        return geoip;
    }

    /**
     * @return gossip membership and Raft consensus management
     */
    public ClusterResource cluster() {
        return cluster;
    }

    /**
     * @return dashboard counters, live query events and zone summary
     */
    public DashboardResource dashboard() {
        return dashboard;
    }

    /**
     * @return the query log, top domains and metrics history
     */
    public MetricsResource metrics() {
        return metrics;
    }

    // -- shared plumbing ---------------------------------------------------

    /**
     * The base URL of the server, without a trailing slash.
     *
     * @return the base URL
     */
    public String getBaseUrl() {
        return transport.getBaseUrl();
    }

    /**
     * The bearer token currently in use.
     *
     * @return the token, or {@code null} when unauthenticated
     */
    public String getToken() {
        return transport.getToken();
    }

    /**
     * Set the bearer token used by every namespace.
     *
     * @param token a JWT from {@code auth().login}, the static
     *              {@code server.http.auth_token} value, or {@code null} to
     *              continue unauthenticated
     */
    public void setToken(String token) {
        transport.setToken(token);
    }

    /**
     * The underlying transport, for advanced use such as calling an endpoint
     * this SDK version does not wrap yet.
     *
     * @return the shared transport
     */
    public NothingDnsTransport transport() {
        return transport;
    }

    // -- health & status ---------------------------------------------------

    /**
     * {@code GET /health} — health check; no authentication required.
     *
     * @return the health response
     * @throws NothingDnsException 429 when the endpoint's own rate limit is hit
     */
    public HealthResponse health() {
        return HealthResponse.from(transport.get("/health"), transport.gson());
    }

    /**
     * {@code GET /readyz} — readiness probe; no authentication required.
     *
     * @return the health response
     * @throws NothingDnsException 503 when the server is not ready to answer
     *                             queries; treat that as "not ready", not as a
     *                             hard failure
     */
    public HealthResponse ready() {
        return HealthResponse.from(transport.get("/readyz"), transport.gson());
    }

    /**
     * {@code GET /livez} — liveness probe; no authentication required.
     *
     * @return the health response
     */
    public HealthResponse live() {
        return HealthResponse.from(transport.get("/livez"), transport.gson());
    }

    /**
     * {@code GET /api/v1/status} — status, version, cache and cluster summary.
     *
     * <p>Any authenticated user may call this; the {@code cache} block is only
     * present for operators and admins.</p>
     *
     * @return the status
     */
    public StatusResponse status() {
        return StatusResponse.from(transport.get("/api/v1/status"), transport.gson());
    }

    /**
     * {@code GET /api/v1/server/config} — port, log level, DNS64, cookies
     * (operator+).
     *
     * @return the configuration summary
     */
    public ServerConfig serverConfig() {
        return ServerConfig.from(transport.get("/api/v1/server/config"), transport.gson());
    }

    /**
     * {@code GET /api/openapi.json} — the server's own OpenAPI document.
     *
     * <p>Useful to detect server capabilities that this SDK version predates.</p>
     *
     * @return the OpenAPI document
     */
    public JsonObject openapiSpec() {
        return Json.obj(transport.get("/api/openapi.json"));
    }

    /**
     * {@code GET /api/docs} — the API explorer page (HTML).
     *
     * @return the page source
     */
    public String docs() {
        return transport.getRaw("/api/docs", null);
    }

    /**
     * {@code GET /api/docs/app.js} — the API explorer script (JavaScript).
     *
     * @return the script source
     */
    public String docsApp() {
        return transport.getRaw("/api/docs/app.js", null);
    }

    /**
     * {@code POST /api/v1/csp-report} — the Content-Security-Policy violation
     * report sink.
     *
     * <p>The browser posts violation reports here; the server discards them.
     * Exposed so tests and proxies can exercise the endpoint. It answers
     * {@code 204 No Content}.</p>
     *
     * @param report the report body, usually the browser's
     *               {@code {"csp-report": {...}}} envelope; {@code null} sends
     *               an empty object
     * @throws NothingDnsException 429 when the endpoint's rate limit is hit
     */
    public void cspReport(Map<String, Object> report) {
        transport.post("/api/v1/csp-report",
                report == null ? new java.util.LinkedHashMap<>() : report);
    }

    // -- lifecycle ---------------------------------------------------------

    /**
     * Release the client's resources. The JDK {@link HttpClient} manages its
     * own connection pool, so this mainly drops the bearer token.
     */
    @Override
    public void close() {
        transport.close();
    }

    /**
     * Build a client from environment variables.
     *
     * <p>Reads {@code NDNS_URL} (default {@code http://localhost:8080}),
     * {@code NDNS_TOKEN} and {@code NDNS_TIMEOUT} (a number of seconds,
     * default 30).</p>
     *
     * @return a client configured from the environment
     */
    public static NothingDnsClient fromEnv() {
        String baseUrl = env("NDNS_URL", NothingDnsTransport.DEFAULT_BASE_URL);
        String token = env("NDNS_TOKEN", null);
        Duration timeout = NothingDnsTransport.DEFAULT_TIMEOUT;
        String seconds = env("NDNS_TIMEOUT", null);
        if (seconds != null && !seconds.isBlank()) {
            try {
                timeout = Duration.ofSeconds(Long.parseLong(seconds.trim()));
            } catch (NumberFormatException ignored) {
                // Fall back to the default rather than failing to construct.
            }
        }
        return new NothingDnsClient(baseUrl, token, timeout, null, null);
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return (value == null || value.isBlank()) ? fallback : value.trim();
    }
}
