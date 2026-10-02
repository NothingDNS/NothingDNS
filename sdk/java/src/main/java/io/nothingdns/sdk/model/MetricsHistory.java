package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

import java.util.ArrayList;
import java.util.List;

/**
 * The metrics history ring buffer.
 *
 * <p>Returned by {@code GET /api/v1/metrics/history} (operator+). The arrays
 * are parallel: index <em>i</em> of each describes the same sample.</p>
 */
public final class MetricsHistory {

    private List<Long> timestamps;
    private List<Long> queries;
    @SerializedName("cache_hits")
    private List<Long> cacheHits;
    @SerializedName("cache_misses")
    private List<Long> cacheMisses;
    @SerializedName("latency_ms")
    private List<Long> latencyMs;
    private int count;

    private MetricsHistory() {
        this.timestamps = new ArrayList<>();
        this.queries = new ArrayList<>();
        this.cacheHits = new ArrayList<>();
        this.cacheMisses = new ArrayList<>();
        this.latencyMs = new ArrayList<>();
    }

    /**
     * Decode the metrics history.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the history, never {@code null}
     */
    public static MetricsHistory from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        MetricsHistory m = new MetricsHistory();
        m.timestamps = longList(o.get("timestamps"));
        m.queries = longList(o.get("queries"));
        m.cacheHits = longList(o.get("cache_hits"));
        m.cacheMisses = longList(o.get("cache_misses"));
        m.latencyMs = longList(o.get("latency_ms"));
        m.count = Json.integer(o, "count");
        return m;
    }

    private static List<Long> longList(JsonElement element) {
        List<Long> out = new ArrayList<>();
        for (JsonElement item : Json.arr(element)) {
            if (item != null && item.isJsonPrimitive()) {
                try {
                    out.add(item.getAsLong());
                } catch (RuntimeException ignored) {
                    out.add(0L);
                }
            } else {
                out.add(0L);
            }
        }
        return out;
    }

    /**
     * @return the sample timestamps (Unix seconds), never {@code null}
     */
    public List<Long> getTimestamps() {
        return timestamps;
    }

    /**
     * @return the query count per sample, never {@code null}
     */
    public List<Long> getQueries() {
        return queries;
    }

    /**
     * @return the cache-hit count per sample, never {@code null}
     */
    public List<Long> getCacheHits() {
        return cacheHits;
    }

    /**
     * @return the cache-miss count per sample, never {@code null}
     */
    public List<Long> getCacheMisses() {
        return cacheMisses;
    }

    /**
     * @return the query latency per sample, in milliseconds, never {@code null}
     */
    public List<Long> getLatencyMs() {
        return latencyMs;
    }

    /**
     * @return the number of samples in the ring buffer
     */
    public int getCount() {
        return count;
    }

    @Override
    public String toString() {
        return "MetricsHistory{count=" + count + "}";
    }
}
