package io.nothingdns.sdk.resources;

import io.nothingdns.sdk.NothingDnsTransport;
import io.nothingdns.sdk.model.CacheStats;

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
}
