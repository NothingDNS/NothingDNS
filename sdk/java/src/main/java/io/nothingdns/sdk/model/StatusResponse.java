package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Server status, version, cache and cluster summary.
 *
 * <p>Returned by {@code GET /api/v1/status}. Any authenticated user may call
 * it; the {@code cache} block is only present for operators and admins.</p>
 */
public final class StatusResponse {

    private String status;
    private String timestamp;
    private String version;
    private CacheStats cache;
    private ClusterSummary cluster;

    private StatusResponse() {
    }

    /**
     * Decode a status response.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the status, never {@code null}
     */
    public static StatusResponse from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        StatusResponse s = new StatusResponse();
        s.status = Json.str(o, "status");
        s.timestamp = Json.str(o, "timestamp");
        s.version = Json.str(o, "version");
        s.cache = CacheStats.from(o.get("cache"), gson);
        s.cluster = ClusterSummary.from(o.get("cluster"), gson);
        return s;
    }

    /**
     * @return the server status, e.g. {@code running}
     */
    public String getStatus() {
        return status;
    }

    /**
     * @return when the status was captured, as an ISO-8601 timestamp
     */
    public String getTimestamp() {
        return timestamp;
    }

    /**
     * @return the running server version
     */
    public String getVersion() {
        return version;
    }

    /**
     * @return the cache summary, never {@code null}
     */
    public CacheStats getCache() {
        return cache;
    }

    /**
     * @return the cluster summary, never {@code null}
     */
    public ClusterSummary getCluster() {
        return cluster;
    }

    @Override
    public String toString() {
        return "StatusResponse{status='" + status + "', version='" + version + "'}";
    }
}
