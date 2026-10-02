package io.nothingdns.sdk.resources;

import io.nothingdns.sdk.NothingDnsTransport;
import io.nothingdns.sdk.model.DashboardStats;
import io.nothingdns.sdk.model.QueryEvent;
import io.nothingdns.sdk.model.Zone;

import java.util.List;

/**
 * Dashboard counters, live query events and zone summary
 * ({@code /api/dashboard}).
 *
 * <p>Obtained from {@code client.dashboard()}. This group serves the embedded
 * dashboard SPA, so its wire format is camelCase throughout. All three methods
 * need at least the operator role.</p>
 */
public final class DashboardResource extends ApiResource {

    /**
     * Create the dashboard namespace.
     *
     * @param transport the shared transport
     */
    public DashboardResource(NothingDnsTransport transport) {
        super(transport);
    }

    /**
     * Read the dashboard counters (operator+).
     *
     * @return the counters
     * @throws io.nothingdns.sdk.NothingDnsException 401 or 403 when the caller
     *                                                is below operator
     */
    public DashboardStats stats() {
        return model(transport.get("/api/dashboard/stats"), DashboardStats.class);
    }

    /**
     * Read the last 100 query events (operator+).
     *
     * <p>These are the events the dashboard's live table shows, not the
     * paginated log from {@code client.metrics().queryLog()}.</p>
     *
     * @return the events, oldest first
     */
    public List<QueryEvent> queries() {
        return list(transport.get("/api/dashboard/queries"), null, QueryEvent.class);
    }

    /**
     * Read the zone summary shown on the dashboard (operator+).
     *
     * @return one entry per zone
     */
    public List<Zone> zones() {
        return list(transport.get("/api/dashboard/zones"), null, Zone.class);
    }
}
