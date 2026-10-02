package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

import java.util.ArrayList;
import java.util.List;

/**
 * Upstream pool health and counters.
 *
 * <p>Returned by {@code GET /api/v1/upstreams} (operator+). It reports two
 * related views: the configured pool ({@code upstreams}, with per-upstream
 * query counters) and the measured server list ({@code servers}, with health
 * and latency).</p>
 */
public final class Upstreams {

    private List<UpstreamHealth> upstreams;
    private List<UpstreamServer> servers;

    private Upstreams() {
        this.upstreams = new ArrayList<>();
        this.servers = new ArrayList<>();
    }

    /**
     * Decode upstream health.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the health report, never {@code null}
     */
    public static Upstreams from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        Upstreams u = new Upstreams();
        u.upstreams = Json.list(o.get("upstreams"), null, UpstreamHealth.class, gson);
        u.servers = Json.list(o.get("servers"), null, UpstreamServer.class, gson);
        return u;
    }

    /**
     * @return per-upstream counters, never {@code null}
     */
    public List<UpstreamHealth> getUpstreams() {
        return upstreams;
    }

    /**
     * @return per-server health and latency, never {@code null}
     */
    public List<UpstreamServer> getServers() {
        return servers;
    }

    @Override
    public String toString() {
        return "Upstreams{upstreams=" + upstreams.size()
                + ", servers=" + servers.size() + "}";
    }

    /** Per-upstream counters inside the pool. */
    public static final class UpstreamHealth {
        private String address;
        private boolean healthy;
        private long queries;
        private long failed;
        private long failovers;

        private UpstreamHealth() {
        }

        /**
         * Decode one upstream's counters.
         *
         * @param element the decoded body, may be {@code null}
         * @param gson    the codec
         * @return the counters, never {@code null}
         */
        public static UpstreamHealth from(JsonElement element, Gson gson) {
            JsonObject o = Json.obj(element);
            UpstreamHealth u = new UpstreamHealth();
            u.address = Json.str(o, "address");
            u.healthy = Json.bool(o, "healthy");
            u.queries = Json.integer(o, "queries");
            u.failed = Json.integer(o, "failed");
            u.failovers = Json.integer(o, "failovers");
            return u;
        }

        /**
         * @return the upstream address, e.g. {@code 1.1.1.1:53}
         */
        public String getAddress() {
            return address;
        }

        /**
         * @return whether the upstream is considered healthy
         */
        public boolean isHealthy() {
            return healthy;
        }

        /**
         * @return the number of queries sent to this upstream
         */
        public long getQueries() {
            return queries;
        }

        /**
         * @return the number of failed queries
         */
        public long getFailed() {
            return failed;
        }

        /**
         * @return the number of times traffic failed over to another upstream
         */
        public long getFailovers() {
            return failovers;
        }

        @Override
        public String toString() {
            return "UpstreamHealth{address='" + address + "', healthy=" + healthy
                    + ", queries=" + queries + ", failed=" + failed + "}";
        }
    }

    /** Measured health and latency of one upstream server. */
    public static final class UpstreamServer {
        private String address;
        private boolean healthy;
        @SerializedName("latency_ms")
        private double latencyMs;

        private UpstreamServer() {
        }

        /**
         * Decode one server's health.
         *
         * @param element the decoded body, may be {@code null}
         * @param gson    the codec
         * @return the server, never {@code null}
         */
        public static UpstreamServer from(JsonElement element, Gson gson) {
            JsonObject o = Json.obj(element);
            UpstreamServer s = new UpstreamServer();
            s.address = Json.str(o, "address");
            s.healthy = Json.bool(o, "healthy");
            s.latencyMs = Json.dbl(o, "latency_ms");
            return s;
        }

        /**
         * @return the server address
         */
        public String getAddress() {
            return address;
        }

        /**
         * @return whether the server is considered healthy
         */
        public boolean isHealthy() {
            return healthy;
        }

        /**
         * @return the measured latency, in milliseconds
         */
        public double getLatencyMs() {
            return latencyMs;
        }

        @Override
        public String toString() {
            return "UpstreamServer{address='" + address + "', healthy=" + healthy
                    + ", latencyMs=" + latencyMs + "}";
        }
    }
}
