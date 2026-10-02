package io.nothingdns.sdk.resources;

import io.nothingdns.sdk.NothingDnsTransport;
import io.nothingdns.sdk.model.BlocklistSource;
import io.nothingdns.sdk.model.BlocklistStats;

import java.util.List;
import java.util.Map;

/**
 * Blocklist sources and filtering ({@code /api/v1/blocklists}).
 *
 * <p>Obtained from {@code client.blocklists()}. A source is either a local
 * hosts-style file or a URL fetched over HTTP(S). Reads need operator; adding,
 * removing and toggling need admin.</p>
 */
public final class BlocklistsResource extends ApiResource {

    /**
     * Create the blocklists namespace.
     *
     * @param transport the shared transport
     */
    public BlocklistsResource(NothingDnsTransport transport) {
        super(transport);
    }

    /**
     * Read blocklist engine statistics (operator+).
     *
     * @return the statistics
     */
    public BlocklistStats stats() {
        return model(transport.get("/api/v1/blocklists"), BlocklistStats.class);
    }

    /**
     * List the configured blocklist sources (operator+).
     *
     * @return the sources
     */
    public List<BlocklistSource> sources() {
        return list(transport.get("/api/v1/blocklists/sources"), null, BlocklistSource.class);
    }

    /**
     * Add a blocklist source (admin).
     *
     * <p>Give exactly one of {@code file} (a path on the server) or
     * {@code url} (a remote list the server fetches).</p>
     *
     * @param file a local hosts-format file path, or {@code null}
     * @param url  a remote list URL, or {@code null}
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 400 when neither or both are given
     */
    public String add(String file, String url) {
        Map<String, Object> payload = body();
        put(payload, "file", file);
        put(payload, "url", url);
        return message(transport.post("/api/v1/blocklists", payload));
    }

    /**
     * Add a URL-based blocklist source (admin).
     *
     * @param url the remote list URL
     * @return the server's confirmation message
     */
    public String addUrl(String url) {
        return add(null, url);
    }

    /**
     * Add a file-based blocklist source (admin).
     *
     * @param file the local hosts-format file path
     * @return the server's confirmation message
     */
    public String addFile(String file) {
        return add(file, null);
    }

    /**
     * Toggle blocklist filtering on or off for the whole engine (admin).
     *
     * @return the server's confirmation message
     */
    public String toggle() {
        return message(transport.post("/api/v1/blocklists/toggle", null));
    }

    /**
     * Remove a blocklist source (admin).
     *
     * @param source the source id, as reported by {@link #sources()}
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 400 when the id is unknown
     */
    public String remove(String source) {
        return message(transport.delete("/api/v1/blocklists/" + escape(source)));
    }

    /**
     * Enable or disable a single blocklist source (admin).
     *
     * @param source the source id
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 404 when the id is unknown
     */
    public String toggleSource(String source) {
        return message(transport.post("/api/v1/blocklists/" + escape(source) + "/toggle", null));
    }
}
