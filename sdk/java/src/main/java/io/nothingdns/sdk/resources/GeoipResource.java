package io.nothingdns.sdk.resources;

import io.nothingdns.sdk.NothingDnsTransport;
import io.nothingdns.sdk.model.GeoIpStats;

/**
 * GeoDNS statistics ({@code /api/v1/geoip}).
 *
 * <p>Obtained from {@code client.geoip()}. Read-only; GeoDNS is configured in
 * the server's YAML file.</p>
 */
public final class GeoipResource extends ApiResource {

    /**
     * Create the GeoDNS namespace.
     *
     * @param transport the shared transport
     */
    public GeoipResource(NothingDnsTransport transport) {
        super(transport);
    }

    /**
     * Read GeoDNS statistics (operator+).
     *
     * @return the statistics
     * @throws io.nothingdns.sdk.NothingDnsException 401 or 403 when the caller
     *                                                is below operator
     */
    public GeoIpStats stats() {
        return model(transport.get("/api/v1/geoip/stats"), GeoIpStats.class);
    }
}
