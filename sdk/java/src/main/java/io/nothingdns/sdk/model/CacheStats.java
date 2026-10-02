package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

/**
 * DNS response cache statistics.
 *
 * <p>Returned by {@code GET /api/v1/cache/stats} and embedded in the
 * {@code cache} block of {@code GET /api/v1/status}.</p>
 */
public final class CacheStats {

    private int size;
    private int capacity;
    private long hits;
    private long misses;
    @SerializedName("hit_ratio")
    private double hitRatio;

    private CacheStats() {
    }

    /**
     * Decode cache statistics.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the statistics, never {@code null}
     */
    public static CacheStats from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        CacheStats c = new CacheStats();
        c.size = Json.integer(o, "size");
        c.capacity = Json.integer(o, "capacity");
        c.hits = Json.integer(o, "hits");
        c.misses = Json.integer(o, "misses");
        c.hitRatio = Json.dbl(o, "hit_ratio");
        return c;
    }

    /**
     * @return the number of entries currently cached
     */
    public int getSize() {
        return size;
    }

    /**
     * @return the maximum number of entries the cache holds
     */
    public int getCapacity() {
        return capacity;
    }

    /**
     * @return the number of cache hits
     */
    public long getHits() {
        return hits;
    }

    /**
     * @return the number of cache misses
     */
    public long getMisses() {
        return misses;
    }

    /**
     * @return hits divided by total lookups, {@code 0} when there were none
     */
    public double getHitRatio() {
        return hitRatio;
    }

    @Override
    public String toString() {
        return "CacheStats{size=" + size + ", capacity=" + capacity
                + ", hits=" + hits + ", misses=" + misses
                + ", hitRatio=" + hitRatio + "}";
    }
}
