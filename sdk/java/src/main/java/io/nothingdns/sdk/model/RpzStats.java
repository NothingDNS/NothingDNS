package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

/**
 * Response Policy Zone (RPZ) engine statistics.
 *
 * <p>Returned by {@code GET /api/v1/rpz} (operator+).</p>
 */
public final class RpzStats {

    private boolean enabled;
    @SerializedName("total_rules")
    private long totalRules;
    @SerializedName("qname_rules")
    private long qnameRules;
    @SerializedName("client_ip_rules")
    private long clientIpRules;
    @SerializedName("resp_ip_rules")
    private long respIpRules;
    @SerializedName("files_count")
    private int filesCount;
    @SerializedName("total_matches")
    private long totalMatches;
    @SerializedName("total_lookups")
    private long totalLookups;
    @SerializedName("last_reload")
    private String lastReload;

    private RpzStats() {
    }

    /**
     * Decode RPZ statistics.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the statistics, never {@code null}
     */
    public static RpzStats from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        RpzStats r = new RpzStats();
        r.enabled = Json.bool(o, "enabled");
        r.totalRules = Json.integer(o, "total_rules");
        r.qnameRules = Json.integer(o, "qname_rules");
        r.clientIpRules = Json.integer(o, "client_ip_rules");
        r.respIpRules = Json.integer(o, "resp_ip_rules");
        r.filesCount = Json.integer(o, "files_count");
        r.totalMatches = Json.integer(o, "total_matches");
        r.totalLookups = Json.integer(o, "total_lookups");
        r.lastReload = Json.str(o, "last_reload");
        return r;
    }

    /**
     * @return whether RPZ filtering is on
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * @return the total number of loaded rules
     */
    public long getTotalRules() {
        return totalRules;
    }

    /**
     * @return the number of QNAME rules
     */
    public long getQnameRules() {
        return qnameRules;
    }

    /**
     * @return the number of client-IP rules
     */
    public long getClientIpRules() {
        return clientIpRules;
    }

    /**
     * @return the number of response-IP rules
     */
    public long getRespIpRules() {
        return respIpRules;
    }

    /**
     * @return the number of loaded RPZ files
     */
    public int getFilesCount() {
        return filesCount;
    }

    /**
     * @return how many queries an RPZ rule has matched
     */
    public long getTotalMatches() {
        return totalMatches;
    }

    /**
     * @return how many queries were checked against the RPZ
     */
    public long getTotalLookups() {
        return totalLookups;
    }

    /**
     * @return when the rules were last reloaded, as an ISO-8601 timestamp
     */
    public String getLastReload() {
        return lastReload;
    }

    @Override
    public String toString() {
        return "RpzStats{enabled=" + enabled + ", totalRules=" + totalRules
                + ", totalMatches=" + totalMatches + "}";
    }
}
