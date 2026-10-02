package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

/**
 * Cluster status: membership, consensus state and per-node metrics.
 *
 * <p>Returned by {@code GET /api/v1/cluster/status} (operator+). The three
 * sub-blocks — gossip, raft and metrics — are nested objects on the wire.</p>
 */
public final class ClusterStatus {

    private String nodeId;
    private String consensus;
    private int nodeCount;
    private int aliveCount;
    private boolean healthy;
    private GossipStats gossip;
    private RaftStats raft;
    private ClusterMetrics metrics;

    private ClusterStatus() {
    }

    /**
     * Decode a cluster status.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the status, never {@code null}
     */
    public static ClusterStatus from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        ClusterStatus c = new ClusterStatus();
        c.nodeId = Json.str(o, "node_id");
        c.consensus = Json.str(o, "consensus");
        c.nodeCount = Json.integer(o, "node_count");
        c.aliveCount = Json.integer(o, "alive_count");
        c.healthy = Json.bool(o, "healthy");
        c.gossip = GossipStats.from(o.get("gossip"), gson);
        c.raft = RaftStats.from(o.get("raft"), gson);
        c.metrics = ClusterMetrics.from(o.get("metrics"), gson);
        return c;
    }

    /**
     * @return this node's identifier
     */
    public String getNodeId() {
        return nodeId;
    }

    /**
     * @return the consensus backend in use, e.g. {@code raft}
     */
    public String getConsensus() {
        return consensus;
    }

    /**
     * @return the total number of known nodes
     */
    public int getNodeCount() {
        return nodeCount;
    }

    /**
     * @return the number of nodes currently alive
     */
    public int getAliveCount() {
        return aliveCount;
    }

    /**
     * @return whether the cluster reports itself healthy
     */
    public boolean isHealthy() {
        return healthy;
    }

    /**
     * @return gossip membership counters, never {@code null}
     */
    public GossipStats getGossip() {
        return gossip;
    }

    /**
     * @return raft consensus state, never {@code null}
     */
    public RaftStats getRaft() {
        return raft;
    }

    /**
     * @return this node's metrics, never {@code null}
     */
    public ClusterMetrics getMetrics() {
        return metrics;
    }

    @Override
    public String toString() {
        return "ClusterStatus{nodeId='" + nodeId + "', consensus='" + consensus
                + "', nodeCount=" + nodeCount + ", aliveCount=" + aliveCount
                + ", healthy=" + healthy + "}";
    }

    /** Gossip membership counters. */
    public static final class GossipStats {
        @SerializedName("messages_sent")
        private long messagesSent;
        @SerializedName("messages_received")
        private long messagesReceived;
        @SerializedName("ping_sent")
        private long pingSent;
        @SerializedName("ping_received")
        private long pingReceived;

        private GossipStats() {
        }

        /**
         * Decode gossip counters.
         *
         * @param element the decoded body, may be {@code null}
         * @param gson    the codec
         * @return the counters, never {@code null}
         */
        public static GossipStats from(JsonElement element, Gson gson) {
            JsonObject o = Json.obj(element);
            GossipStats g = new GossipStats();
            g.messagesSent = Json.integer(o, "messages_sent");
            g.messagesReceived = Json.integer(o, "messages_received");
            g.pingSent = Json.integer(o, "ping_sent");
            g.pingReceived = Json.integer(o, "ping_received");
            return g;
        }

        /**
         * @return the number of gossip messages sent
         */
        public long getMessagesSent() {
            return messagesSent;
        }

        /**
         * @return the number of gossip messages received
         */
        public long getMessagesReceived() {
            return messagesReceived;
        }

        /**
         * @return the number of SWIM pings sent
         */
        public long getPingSent() {
            return pingSent;
        }

        /**
         * @return the number of SWIM pings received
         */
        public long getPingReceived() {
            return pingReceived;
        }

        @Override
        public String toString() {
            return "GossipStats{sent=" + messagesSent + ", received=" + messagesReceived + "}";
        }
    }

    /** Raft consensus state. */
    public static final class RaftStats {
        private String state;
        private long term;
        @SerializedName("commit_index")
        private long commitIndex;
        @SerializedName("applied_index")
        private long appliedIndex;
        @SerializedName("is_leader")
        private boolean isLeader;
        @SerializedName("leader_id")
        private String leaderId;

        private RaftStats() {
        }

        /**
         * Decode raft state.
         *
         * @param element the decoded body, may be {@code null}
         * @param gson    the codec
         * @return the raft state, never {@code null}
         */
        public static RaftStats from(JsonElement element, Gson gson) {
            JsonObject o = Json.obj(element);
            RaftStats r = new RaftStats();
            r.state = Json.str(o, "state");
            r.term = Json.integer(o, "term");
            r.commitIndex = Json.integer(o, "commit_index");
            r.appliedIndex = Json.integer(o, "applied_index");
            r.isLeader = Json.bool(o, "is_leader");
            r.leaderId = Json.str(o, "leader_id");
            return r;
        }

        /**
         * @return the raft state, e.g. {@code leader} or {@code follower}
         */
        public String getState() {
            return state;
        }

        /**
         * @return the current raft term
         */
        public long getTerm() {
            return term;
        }

        /**
         * @return the highest committed log index
         */
        public long getCommitIndex() {
            return commitIndex;
        }

        /**
         * @return the highest applied log index
         */
        public long getAppliedIndex() {
            return appliedIndex;
        }

        /**
         * @return whether this node is the raft leader
         */
        public boolean isLeader() {
            return isLeader;
        }

        /**
         * @return the current leader's identifier
         */
        public String getLeaderId() {
            return leaderId;
        }

        @Override
        public String toString() {
            return "RaftStats{state='" + state + "', term=" + term
                    + ", isLeader=" + isLeader + "}";
        }
    }

    /** This node's query and latency metrics. */
    public static final class ClusterMetrics {
        @SerializedName("queries_total")
        private long queriesTotal;
        @SerializedName("queries_per_sec")
        private double queriesPerSec;
        @SerializedName("cache_hits")
        private long cacheHits;
        @SerializedName("cache_misses")
        private long cacheMisses;
        @SerializedName("cache_hit_rate")
        private double cacheHitRate;
        @SerializedName("latency_avg_ms")
        private double latencyAvgMs;
        @SerializedName("latency_p99_ms")
        private double latencyP99Ms;

        private ClusterMetrics() {
        }

        /**
         * Decode this node's metrics.
         *
         * @param element the decoded body, may be {@code null}
         * @param gson    the codec
         * @return the metrics, never {@code null}
         */
        public static ClusterMetrics from(JsonElement element, Gson gson) {
            JsonObject o = Json.obj(element);
            ClusterMetrics m = new ClusterMetrics();
            m.queriesTotal = Json.integer(o, "queries_total");
            m.queriesPerSec = Json.dbl(o, "queries_per_sec");
            m.cacheHits = Json.integer(o, "cache_hits");
            m.cacheMisses = Json.integer(o, "cache_misses");
            m.cacheHitRate = Json.dbl(o, "cache_hit_rate");
            m.latencyAvgMs = Json.dbl(o, "latency_avg_ms");
            m.latencyP99Ms = Json.dbl(o, "latency_p99_ms");
            return m;
        }

        /**
         * @return the number of queries served since start
         */
        public long getQueriesTotal() {
            return queriesTotal;
        }

        /**
         * @return the current query rate, per second
         */
        public double getQueriesPerSec() {
            return queriesPerSec;
        }

        /**
         * @return the number of cache hits
         */
        public long getCacheHits() {
            return cacheHits;
        }

        /**
         * @return the number of cache misses
         */
        public long getCacheMisses() {
            return cacheMisses;
        }

        /**
         * @return the cache hit rate, {@code 0}–{@code 1}
         */
        public double getCacheHitRate() {
            return cacheHitRate;
        }

        /**
         * @return the average query latency, in milliseconds
         */
        public double getLatencyAvgMs() {
            return latencyAvgMs;
        }

        /**
         * @return the 99th-percentile query latency, in milliseconds
         */
        public double getLatencyP99Ms() {
            return latencyP99Ms;
        }

        @Override
        public String toString() {
            return "ClusterMetrics{queriesTotal=" + queriesTotal
                    + ", cacheHitRate=" + cacheHitRate + "}";
        }
    }
}
