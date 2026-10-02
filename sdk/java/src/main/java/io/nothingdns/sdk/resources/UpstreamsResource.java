package io.nothingdns.sdk.resources;

import io.nothingdns.sdk.NothingDnsTransport;
import io.nothingdns.sdk.model.Upstreams;

import java.util.Map;

/**
 * Upstream pool health and membership ({@code /api/v1/upstreams}).
 *
 * <p>Obtained from {@code client.upstreams()}. Reading health needs operator;
 * adding or removing a server needs admin and takes effect without a restart.</p>
 */
public final class UpstreamsResource extends ApiResource {

    /**
     * Create the upstreams namespace.
     *
     * @param transport the shared transport
     */
    public UpstreamsResource(NothingDnsTransport transport) {
        super(transport);
    }

    /**
     * Read upstream health and per-upstream counters (operator+).
     *
     * @return the health report
     * @throws io.nothingdns.sdk.NothingDnsException 401 or 403 when the caller
     *                                                is below operator
     */
    public Upstreams list() {
        return model(transport.get("/api/v1/upstreams"), Upstreams.class);
    }

    /**
     * Add one upstream server (admin).
     *
     * @param server the server address, e.g. {@code 1.1.1.1:53}
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 409 when the server is already
     *                                                configured
     */
    public String add(String server) {
        return change("add", server);
    }

    /**
     * Remove one upstream server (admin).
     *
     * @param server the server address
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 404 when the server is not
     *                                                configured
     */
    public String remove(String server) {
        return change("remove", server);
    }

    private String change(String action, String server) {
        Map<String, Object> payload = body();
        payload.put("action", action);
        payload.put("server", server);
        return message(transport.put("/api/v1/upstreams", payload));
    }
}
