package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

/**
 * GeoDNS (GeoIP) statistics.
 *
 * <p>Returned by {@code GET /api/v1/geoip/stats} (operator+).</p>
 */
public final class GeoIpStats {

    private boolean enabled;
    private long rules;
    @SerializedName("mmdb_loaded")
    private boolean mmdbLoaded;
    private long lookups;
    private long hits;
    private long misses;

    private GeoIpStats() {
    }

    /**
     * Decode GeoDNS statistics.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the statistics, never {@code null}
     */
    public static GeoIpStats from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        GeoIpStats g = new GeoIpStats();
        g.enabled = Json.bool(o, "enabled");
        g.rules = Json.integer(o, "rules");
        g.mmdbLoaded = Json.bool(o, "mmdb_loaded");
        g.lookups = Json.integer(o, "lookups");
        g.hits = Json.integer(o, "hits");
        g.misses = Json.integer(o, "misses");
        return g;
    }

    /**
     * @return whether GeoDNS is on
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * @return the number of configured geo rules
     */
    public long getRules() {
        return rules;
    }

    /**
     * @return whether a MaxMind database is loaded
     */
    public boolean isMmdbLoaded() {
        return mmdbLoaded;
    }

    /**
     * @return the number of geo lookups performed
     */
    public long getLookups() {
        return lookups;
    }

    /**
     * @return the number of lookups that matched a rule
     */
    public long getHits() {
        return hits;
    }

    /**
     * @return the number of lookups that matched no rule
     */
    public long getMisses() {
        return misses;
    }

    @Override
    public String toString() {
        return "GeoIpStats{enabled=" + enabled + ", rules=" + rules
                + ", mmdbLoaded=" + mmdbLoaded + ", hits=" + hits + "}";
    }
}
