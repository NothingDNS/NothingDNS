package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Health / readiness / liveness probe response.
 *
 * <p>Returned by {@code GET /health}, {@code GET /readyz} and
 * {@code GET /livez}.</p>
 */
public final class HealthResponse {

    private String status;
    private String timestamp;

    private HealthResponse() {
    }

    /**
     * Build a probe response.
     *
     * @param status    the reported status, one of {@code healthy},
     *                  {@code ready}, {@code unhealthy} or {@code alive}
     * @param timestamp when the probe ran
     * @return the response
     */
    public static HealthResponse of(String status, String timestamp) {
        HealthResponse r = new HealthResponse();
        r.status = status;
        r.timestamp = timestamp;
        return r;
    }

    /**
     * Decode a probe response.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the response, never {@code null}
     */
    public static HealthResponse from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        HealthResponse r = new HealthResponse();
        r.status = Json.str(o, "status");
        r.timestamp = Json.str(o, "timestamp");
        return r;
    }

    /**
     * @return the reported status, e.g. {@code healthy}
     */
    public String getStatus() {
        return status;
    }

    /**
     * @return when the probe ran, as an ISO-8601 timestamp
     */
    public String getTimestamp() {
        return timestamp;
    }

    @Override
    public String toString() {
        return "HealthResponse{status='" + status + "', timestamp='" + timestamp + "'}";
    }
}
