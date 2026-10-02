package io.nothingdns.sdk.resources;

import io.nothingdns.sdk.NothingDnsTransport;
import io.nothingdns.sdk.model.MetricsHistory;
import io.nothingdns.sdk.model.QueryLogPage;
import io.nothingdns.sdk.model.TopDomains;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Query log, top domains and metrics history ({@code /api/v1}).
 *
 * <p>Obtained from {@code client.metrics()}. All three methods need at least the
 * operator role. Unlike the dashboard group, this one uses snake_case on the
 * wire.</p>
 */
public final class MetricsResource extends ApiResource {

    /**
     * Create the metrics namespace.
     *
     * @param transport the shared transport
     */
    public MetricsResource(NothingDnsTransport transport) {
        super(transport);
    }

    /**
     * Read a page of the query log (operator+).
     *
     * @param offset the number of rows to skip, or {@code null} for the default
     * @param limit  the page size, or {@code null} for the server default
     * @param q      a free-text filter over domain, client and type, or {@code null}
     * @return the page
     * @throws io.nothingdns.sdk.NothingDnsException 401 or 403 when the caller
     *                                                is below operator
     */
    public QueryLogPage queryLog(Integer offset, Integer limit, String q) {
        Map<String, Object> params = new LinkedHashMap<>();
        put(params, "offset", offset);
        put(params, "limit", limit);
        put(params, "q", q);
        return model(transport.get("/api/v1/queries", params), QueryLogPage.class);
    }

    /**
     * Read the first page of the query log (operator+).
     *
     * @return the page
     */
    public QueryLogPage queryLog() {
        return queryLog(null, null, null);
    }

    /**
     * Read the most-queried domains (operator+).
     *
     * @param limit how many domains to return, or {@code null} for the server default
     * @return the list
     */
    public TopDomains topDomains(Integer limit) {
        Map<String, Object> params = new LinkedHashMap<>();
        put(params, "limit", limit);
        return model(transport.get("/api/v1/topdomains", params), TopDomains.class);
    }

    /**
     * Read the metrics history ring buffer (operator+).
     *
     * @return the history; its arrays are parallel, index <em>i</em> of each
     *         describing the same sample
     */
    public MetricsHistory history() {
        return model(transport.get("/api/v1/metrics/history"), MetricsHistory.class);
    }
}
