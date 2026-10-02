package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * One live query event from the dashboard's live stream.
 *
 * <p>Returned in the array of {@code GET /api/dashboard/queries} (operator+),
 * which serves the last 100 events. The wire format is camelCase
 * ({@code clientIp}, {@code queryType}, {@code responseCode}), so the Java field
 * names match the wire directly.</p>
 */
public final class QueryEvent {

    private String timestamp;
    private String clientIp;
    private String countryCode;
    private String domain;
    private String queryType;
    private String responseCode;
    private List<String> answers;
    private int duration;
    private boolean cached;
    private boolean blocked;
    private String protocol;

    private QueryEvent() {
        this.answers = new ArrayList<>();
    }

    /**
     * Decode a query event.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the event, never {@code null}
     */
    public static QueryEvent from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        QueryEvent e = new QueryEvent();
        e.timestamp = Json.str(o, "timestamp");
        e.clientIp = Json.str(o, "clientIp");
        e.countryCode = Json.str(o, "countryCode");
        e.domain = Json.str(o, "domain");
        e.queryType = Json.str(o, "queryType");
        e.responseCode = Json.str(o, "responseCode");
        e.answers = Json.stringList(o, "answers");
        e.duration = Json.integer(o, "duration");
        e.cached = Json.bool(o, "cached");
        e.blocked = Json.bool(o, "blocked");
        e.protocol = Json.str(o, "protocol");
        return e;
    }

    /**
     * @return when the query was answered, as an ISO-8601 timestamp
     */
    public String getTimestamp() {
        return timestamp;
    }

    /**
     * @return the client's IP address
     */
    public String getClientIp() {
        return clientIp;
    }

    /**
     * @return the client's country code, when GeoIP is enabled
     */
    public String getCountryCode() {
        return countryCode;
    }

    /**
     * @return the queried domain
     */
    public String getDomain() {
        return domain;
    }

    /**
     * @return the queried record type
     */
    public String getQueryType() {
        return queryType;
    }

    /**
     * @return the DNS response code, e.g. {@code NOERROR}
     */
    public String getResponseCode() {
        return responseCode;
    }

    /**
     * @return the answer records, never {@code null}
     */
    public List<String> getAnswers() {
        return answers;
    }

    /**
     * @return the handling time, in milliseconds
     */
    public int getDuration() {
        return duration;
    }

    /**
     * @return whether the answer came from cache
     */
    public boolean isCached() {
        return cached;
    }

    /**
     * @return whether the query was blocked by filtering
     */
    public boolean isBlocked() {
        return blocked;
    }

    /**
     * @return the transport the query arrived on, e.g. {@code udp}
     */
    public String getProtocol() {
        return protocol;
    }

    @Override
    public String toString() {
        return "QueryEvent{domain='" + domain + "', type='" + queryType
                + "', rcode='" + responseCode + "', blocked=" + blocked + "}";
    }
}
