package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Counters shown on the dashboard landing page.
 *
 * <p>Returned by {@code GET /api/dashboard/stats} (operator+). The wire format
 * for the dashboard group is camelCase, so the Java field names match the wire
 * directly.</p>
 */
public final class DashboardStats {

    private long uptime;
    private int queriesTotal;
    private double queriesPerSec;
    private double cacheHitRate;
    private int blockedQueries;
    private int activeClients;
    private int zoneCount;
    private int upstreamLatency;

    private DashboardStats() {
    }

    /**
     * Decode dashboard counters.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the counters, never {@code null}
     */
    public static DashboardStats from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        DashboardStats d = new DashboardStats();
        d.uptime = Json.integer(o, "uptime");
        d.queriesTotal = Json.integer(o, "queriesTotal");
        d.queriesPerSec = Json.dbl(o, "queriesPerSec");
        d.cacheHitRate = Json.dbl(o, "cacheHitRate");
        d.blockedQueries = Json.integer(o, "blockedQueries");
        d.activeClients = Json.integer(o, "activeClients");
        d.zoneCount = Json.integer(o, "zoneCount");
        d.upstreamLatency = Json.integer(o, "upstreamLatency");
        return d;
    }

    /**
     * @return the server uptime, in seconds
     */
    public long getUptime() {
        return uptime;
    }

    /**
     * @return the number of queries served since start
     */
    public int getQueriesTotal() {
        return queriesTotal;
    }

    /**
     * @return the current query rate, per second
     */
    public double getQueriesPerSec() {
        return queriesPerSec;
    }

    /**
     * @return the cache hit rate, {@code 0}–{@code 1}
     */
    public double getCacheHitRate() {
        return cacheHitRate;
    }

    /**
     * @return the number of queries blocked by filtering
     */
    public int getBlockedQueries() {
        return blockedQueries;
    }

    /**
     * @return the number of distinct active clients
     */
    public int getActiveClients() {
        return activeClients;
    }

    /**
     * @return the number of zones served
     */
    public int getZoneCount() {
        return zoneCount;
    }

    /**
     * @return the upstream latency, in milliseconds
     */
    public int getUpstreamLatency() {
        return upstreamLatency;
    }

    @Override
    public String toString() {
        return "DashboardStats{uptime=" + uptime + ", queriesTotal=" + queriesTotal
                + ", blockedQueries=" + blockedQueries + ", zoneCount=" + zoneCount + "}";
    }
}
