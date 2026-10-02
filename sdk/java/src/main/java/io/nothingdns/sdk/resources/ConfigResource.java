package io.nothingdns.sdk.resources;

import com.google.gson.JsonObject;
import io.nothingdns.sdk.NothingDnsTransport;
import io.nothingdns.sdk.model.Json;

import java.util.List;
import java.util.Map;

/**
 * Effective configuration and the no-restart runtime tunables
 * ({@code /api/v1/config}).
 *
 * <p>Obtained from {@code client.config()}. Every setter is a partial update:
 * an argument left {@code null} is omitted from the request, which the server
 * reads as "leave unchanged". All setters need the admin role.</p>
 */
public final class ConfigResource extends ApiResource {

    /** Log levels accepted by {@link #setLogging(String)}. */
    public static final List<String> LOG_LEVELS =
            java.util.Collections.unmodifiableList(
                    java.util.Arrays.asList("debug", "info", "warn", "warning", "error", "fatal"));

    /**
     * Create the config namespace.
     *
     * @param transport the shared transport
     */
    public ConfigResource(NothingDnsTransport transport) {
        super(transport);
    }

    /**
     * Read the effective configuration, with secrets redacted (operator+).
     *
     * <p>The shape is server-defined and can grow between releases, so it is
     * returned as a raw JSON object rather than a fixed model.</p>
     *
     * @return the effective configuration
     * @throws io.nothingdns.sdk.NothingDnsException 401 or 403 when the caller
     *                                                is below operator
     */
    public JsonObject get() {
        return Json.obj(transport.get("/api/v1/config"));
    }

    /**
     * Reload the configuration file (admin).
     *
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 500 when the file is invalid
     */
    public String reload() {
        return message(transport.post("/api/v1/config/reload", null));
    }

    /**
     * Change the log level at runtime (admin).
     *
     * @param level one of {@code debug}, {@code info}, {@code warn},
     *              {@code warning}, {@code error} or {@code fatal}
     * @return the server's confirmation message
     * @throws IllegalArgumentException when {@code level} is not a known level
     * @throws io.nothingdns.sdk.NothingDnsException 400 when the server rejects it
     */
    public String setLogging(String level) {
        if (level == null || !LOG_LEVELS.contains(level)) {
            throw new IllegalArgumentException(
                    "level must be one of " + String.join(", ", LOG_LEVELS));
        }
        Map<String, Object> payload = body();
        payload.put("level", level);
        return put("/api/v1/config/logging", payload);
    }

    /**
     * Change the per-client DNS rate limiter at runtime (admin).
     *
     * @param enabled     whether the limiter is on, or {@code null} to leave unchanged
     * @param rate        sustained queries per second per client
     * @param burst       burst allowance per client
     * @param maxBuckets  the maximum number of tracked client buckets
     * @return the server's confirmation message
     */
    public String setRrl(Boolean enabled, Double rate, Integer burst, Integer maxBuckets) {
        Map<String, Object> payload = body();
        put(payload, "enabled", enabled);
        put(payload, "rate", rate);
        put(payload, "burst", burst);
        put(payload, "max_buckets", maxBuckets);
        return put("/api/v1/config/rrl", payload);
    }

    /**
     * Change cache settings at runtime (admin).
     *
     * @param enabled           whether the cache is on
     * @param size              the maximum number of entries
     * @param defaultTtl        the default TTL for cached answers
     * @param maxTtl            the ceiling applied to any TTL
     * @param minTtl            the floor applied to any TTL
     * @param negativeTtl       the TTL for NXDOMAIN and NODATA answers
     * @param prefetch          refresh popular entries before they expire
     * @param prefetchThreshold the hit count that triggers prefetching
     * @param serveStale        serve expired entries while a refresh is in flight
     *                         (RFC 8767)
     * @param staleGraceSecs    how long a stale answer may still be served
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 400 for an inconsistent set
     *                                                of values
     */
    public String setCache(Boolean enabled,
                           Integer size,
                           Integer defaultTtl,
                           Integer maxTtl,
                           Integer minTtl,
                           Integer negativeTtl,
                           Boolean prefetch,
                           Integer prefetchThreshold,
                           Boolean serveStale,
                           Integer staleGraceSecs) {
        Map<String, Object> payload = body();
        put(payload, "enabled", enabled);
        put(payload, "size", size);
        put(payload, "default_ttl", defaultTtl);
        put(payload, "max_ttl", maxTtl);
        put(payload, "min_ttl", minTtl);
        put(payload, "negative_ttl", negativeTtl);
        put(payload, "prefetch", prefetch);
        put(payload, "prefetch_threshold", prefetchThreshold);
        put(payload, "serve_stale", serveStale);
        put(payload, "stale_grace_secs", staleGraceSecs);
        return put("/api/v1/config/cache", payload);
    }

    /**
     * Change resolution settings at runtime (admin).
     *
     * @param recursive         whether recursive resolution is available
     * @param authoritativeOnly refuse queries outside the local zones
     * @param maxDepth          the maximum CNAME/NS referral depth
     * @param timeout           the per-query timeout, e.g. {@code 5s}
     * @param edns0BufferSize   the advertised EDNS(0) buffer size
     * @param qnameMinimization send the fewest labels needed at each step
     * @param use0x20           randomise query-name case (DNS 0x20 encoding)
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 400 for an invalid value
     */
    public String setResolution(Boolean recursive,
                                Boolean authoritativeOnly,
                                Integer maxDepth,
                                String timeout,
                                Integer edns0BufferSize,
                                Boolean qnameMinimization,
                                Boolean use0x20) {
        Map<String, Object> payload = body();
        put(payload, "recursive", recursive);
        put(payload, "authoritative_only", authoritativeOnly);
        put(payload, "max_depth", maxDepth);
        put(payload, "timeout", timeout);
        put(payload, "edns0_buffer_size", edns0BufferSize);
        put(payload, "qname_minimization", qnameMinimization);
        put(payload, "use_0x20", use0x20);
        return put("/api/v1/config/resolution", payload);
    }

    /**
     * Enable or disable DNS64 synthesis at runtime (RFC 6147) (admin).
     *
     * @param enabled whether synthesis is on
     * @return the server's confirmation message
     */
    public String setDns64(boolean enabled) {
        Map<String, Object> payload = body();
        payload.put("enabled", enabled);
        return put("/api/v1/config/dns64", payload);
    }

    /**
     * Enable or disable DNS Cookies at runtime (RFC 7873) (admin).
     *
     * @param enabled whether cookies are on
     * @return the server's confirmation message
     */
    public String setCookie(boolean enabled) {
        Map<String, Object> payload = body();
        payload.put("enabled", enabled);
        return put("/api/v1/config/cookie", payload);
    }

    private String put(String path, Map<String, Object> payload) {
        return message(transport.put(path, payload));
    }
}
