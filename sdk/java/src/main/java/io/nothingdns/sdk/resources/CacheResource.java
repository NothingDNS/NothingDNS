package io.nothingdns.sdk.resources;

import io.nothingdns.sdk.NothingDnsTransport;
import io.nothingdns.sdk.model.CacheStats;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The DNS response cache ({@code /api/v1/cache}).
 *
 * <p>Obtained from {@code client.cache()}.</p>
 */
public final class CacheResource extends ApiResource {

    /**
     * Create the cache namespace.
     *
     * @param transport the shared transport
     */
    public CacheResource(NothingDnsTransport transport) {
        super(transport);
    }

    /**
     * Read cache size, capacity, hit/miss counters and hit ratio (operator+).
     *
     * @return the cache statistics
     * @throws io.nothingdns.sdk.NothingDnsException 401 or 403 when the caller
     *                                                is below operator
     */
    public CacheStats stats() {
        return model(transport.get("/api/v1/cache/stats"), CacheStats.class);
    }

    /**
     * Flush the cache (admin).
     *
     * <p>Drops every cached answer; the next query for each name goes back to
     * the upstream resolvers.</p>
     *
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 403 when the caller is not an
     *                                                admin
     */
    public String flush() {
        return message(transport.post("/api/v1/cache/flush", null));
    }

    /**
     * Flush the cached entries of one name only, every type (admin).
     *
     * @param name the owner name to drop from the cache
     * @return the server's message, which carries the number of entries removed
     * @throws io.nothingdns.sdk.NothingDnsException 403 when the caller is not an
     *                                                admin
     * @throws IllegalArgumentException when {@code name} is empty (use
     *                                  {@link #flush()} to clear the whole cache)
     */
    public String flushName(String name) {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException(
                    "name required (use flush to clear the whole cache)");
        }
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("name", name);
        return message(transport.post("/api/v1/cache/flush", params, null));
    }
}
